"""dagflow 漏洞挖掘: 三阶段编排 (图还原 → 判断 → 报告)。

Phase 1: chain_reconstructor — 从有向图还原完整调用链 (纯脚本, 无 LLM)
Phase 2: vuln_judger — LLM 判断是否存在真实漏洞 (输出 candidates)
Phase 3: report_generator — LLM 生成完整报告 (复用 V2 SKILL)

无候选时不调 Phase 3, 省 LLM 调用。
"""
from __future__ import annotations
import logging, time
from pathlib import Path
from typing import Any

from . import chain_reconstructor, dag_tools
from .dag_store import DagflowStore
from .vuln_judger import VulnJudger
from .report_generator import ReportGenerator
from .session_naming import session_path

logger = logging.getLogger("dvs.dagflow.mining_agent")


class MiningAgent:
    """三阶段挖掘编排: 图还原 → 判断 → 报告 → 落库。"""

    def __init__(self, *, config: Any, store: DagflowStore, sessions_dir: Path,
                 vuln_store: Any, run_id: str, func_lookup: Any,
                 on_event: Any = None, task_id: str = "",
                 graph_recorder: Any = None,
                 vuln_root: Path | None = None,
                 source_root: str = "") -> None:
        self.config = config
        self.store = store
        self.sessions_dir = Path(sessions_dir)
        self.vuln_store = vuln_store
        self.run_id = run_id
        self.func_lookup = func_lookup
        self.on_event = on_event
        self.task_id = task_id
        self.graph_recorder = graph_recorder
        self.vuln_root = Path(vuln_root) if vuln_root else self.sessions_dir.parent / "vulnerabilities"
        self.source_root = source_root or getattr(config, "cwd", "") or getattr(config, "source_root", "")
        self.cancel_event = None
        # Phase 模块
        self.judger = VulnJudger(
            config=config, sessions_dir=sessions_dir,
            on_event=on_event, task_id=task_id, source_root=self.source_root)
        self.generator = ReportGenerator(
            config=config, sessions_dir=sessions_dir,
            on_event=on_event, task_id=task_id, source_root=self.source_root)

    def mine(self, func, taint_sig: str) -> list:
        """挖 (func, taint) → findings (落库)。"""
        _t0 = time.time()
        # ── Phase 1: 从有向图还原完整调用链 (纯脚本) ──
        dag = self.store.load_dag(func.func_id, taint_sig)
        if dag is None:
            return []
        chain = chain_reconstructor.reconstruct(
            self.store, dag, self.func_lookup, max_depth=8)
        source = dag_tools.get_func_source(self.source_root, func)
        sp = str(session_path(self.sessions_dir, func.name, taint_sig, kind="vuln"))
        self.vuln_root.mkdir(parents=True, exist_ok=True)

        logger.info("[dagflow-mine] Phase1 chain reconstructed func=%s taint=%s steps=%d",
                    func.name, taint_sig, len(chain.get("steps", [])))

        # ── Phase 2: 漏洞判断 (LLM Step 1, 只输出候选) ──
        self.judger.cancel_event = self.cancel_event
        candidates = self.judger.judge(chain, func, source, session_path=sp)
        if not candidates:
            logger.info("[dagflow-mine] no candidate func=%s taint=%s duration=%.1fs (skip Phase3)",
                        func.name, taint_sig, time.time() - _t0)
            self._emit_mined(func, taint_sig, 0)
            return []

        logger.info("[dagflow-mine] Phase2 judged %d candidates func=%s taint=%s",
                    len(candidates), func.name, taint_sig)

        # ── Phase 3: 报告生成 (LLM Step 2, 用 SKILL, 只对确认候选) ──
        self.generator.cancel_event = self.cancel_event
        findings = self.generator.generate(candidates, chain, func, source, session_path=sp)

        # ── 落库 (复用 V2 persist_finding) ──
        from ..dataflow_v2.finding_store import persist_finding
        context_text = self._build_taint_context(func, taint_sig, chain, source)
        for f in findings:
            item = {
                "vuln_type": f.vuln_type, "severity": f.severity, "title": f.title,
                "summary": f.summary, "entry_point": f.entry_point, "trigger_path": f.trigger_path,
                "evidence": f.evidence,
                "source_file": f.source_file or func.file,
                "function_name": f.function_name or func.name,
                "line": f.line or f.location_line,
                "code_snippet": f.code_snippet,
                "code_explanation": f.code_explanation,
                "fix_suggestion": f.fix_suggestion,
                "poc": f.poc,
                "exploitability": f.exploitability,
                "confidence": f.confidence,
                "dimensions": {k: v.to_dict() for k, v in f.dimensions.items()},
            }
            try:
                persist_finding(
                    graph_store=self.vuln_store, run_id=self.run_id, task_id=self.task_id,
                    source_root=self.source_root, vuln_root=self.vuln_root,
                    func_file=func.file, func_name=func.name, func_description="",
                    item=item, context_text=context_text, context_session_path=sp,
                    cfg_project_id=getattr(self.config, "project_id", ""),
                    cfg_task_name=getattr(self.config, "task_name", ""),
                    cfg_parent_task_name=getattr(self.config, "parent_task_name", ""),
                    cfg_parent_task_id=getattr(self.config, "parent_task_id", ""),
                    cfg_parent_task_type=getattr(self.config, "parent_task_type", ""),
                    cfg_task_origin_type=getattr(self.config, "task_origin_type", ""),
                    on_event=self.on_event,
                )
            except Exception as e:
                logger.exception("persist_finding failed for %s/%s: %s", func.name, taint_sig, e)

        logger.info("[dagflow-mine] DONE func=%s taint=%s duration=%.1fs findings=%d",
                    func.name, taint_sig, time.time() - _t0, len(findings))

        # 记录挖掘会话
        if self.graph_recorder:
            self.graph_recorder.record_session(
                session_path=sp, node_id=self.graph_recorder._node_id(func.func_id),
                session_role="vuln", session_kind="mine",
                status="done" if findings else "no_finding")
        self._emit_mined(func, taint_sig, len(findings))
        return findings

    def _build_taint_context(self, func, taint_sig: str, chain: dict, source: str) -> str:
        import json as _json
        return (
            f"## 完整跨函数调用链 (从入口到 sink)\n"
            f"```json\n{_json.dumps(chain, ensure_ascii=False, indent=2)[:20000]}\n```\n\n"
            f"## 本函数完整源码\n```c\n{source}\n```"
        )

    def _emit_mined(self, func, taint_sig: str, findings_count: int) -> None:
        if self.on_event:
            try:
                self.on_event("v2_dagflow_mined", function=func.name, taint=taint_sig,
                              findings=findings_count, task_id=self.task_id)
            except Exception:
                pass
