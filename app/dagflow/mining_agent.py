"""dagflow 挖掘 agent: 正向建链 + 四维度判定 + findings。

设计: docs/design-vuln-mining.md §1.2/§3/§6 (正向建链读 callee 效应; D1-D4; 独立会话; 提供完整源码)。
独立会话 (func-taint), 不继承 taint 会话。建链由 chain_builder (代码) 拼装喂给 LLM (P6 务实版;
LLM 直接调 dag_* 工具留后续精化)。复用 run_agent + _extract_json_object。
"""
from __future__ import annotations
import json, logging
from pathlib import Path
from typing import Any
from .models import Finding, Dimension, TaintDAG
from . import chain_builder, dag_tools
from .dag_store import DagflowStore
from . import finding_store

logger = logging.getLogger("dvs.dagflow.mining_agent")

_PROMPT_PATH = Path(__file__).resolve().parent.parent.parent / "prompts" / "dagflow" / "vuln-mining.md"
_PROMPT_CACHE: str | None = None


def _task_pi_dir(config: Any, role: str) -> str:
    resolver = getattr(config, "role_pi_dir", None)
    if callable(resolver):
        return str(resolver(role) or "")
    return ""


def _system_prompt() -> str:
    global _PROMPT_CACHE
    if _PROMPT_CACHE is None:
        _PROMPT_CACHE = _PROMPT_PATH.read_text(encoding="utf-8")
    return _PROMPT_CACHE


class MiningAgent:
    """单 (func, taint) 挖掘: 建链 -> LLM 判 D1-D4 -> findings。"""

    def __init__(self, *, config: Any, store: DagflowStore, sessions_dir: Path,
                 vuln_store: Any, run_id: str, func_lookup: Any,
                 on_event: Any = None, task_id: str = "") -> None:
        self.config = config
        self.store = store
        self.sessions_dir = Path(sessions_dir)
        self.vuln_store = vuln_store
        self.run_id = run_id
        self.func_lookup = func_lookup
        self.on_event = on_event
        self.task_id = task_id
        self.source_root = getattr(config, "cwd", "") or getattr(config, "source_root", "")
        self._acfg = (config.workers.agents[0] if config.workers.agents else None)
        self._default_tools = getattr(config.workers, "default_tools", None)

    def mine(self, func, taint_sig: str) -> list[Finding]:
        """挖 (func, taint) -> findings (落库)。"""
        if self._acfg is None:
            return []
        import time as _time
        _t0 = _time.time()
        dag = self.store.load_dag(func.func_id, taint_sig)
        if dag is None:
            return []
        chain = chain_builder.build_chain(self.store, dag, self.source_root, self.func_lookup)
        source = dag_tools.get_func_source(self.source_root, func)
        prompt = self._build_prompt(func, taint_sig, chain, source)
        sp = str(self._session_path(func, taint_sig))
        from ..runner import run_agent
        from ..parsers import _extract_json_object
        v2_env = {"DVS_SOURCE_ROOT": str(self.source_root),
                  "DVS_V2_DB_DIR": str(self.sessions_dir.parent / "dataflow-v2")}
        logger.info("[dagflow-mine] CALLING run_agent func=%s taint=%s session=%s",
                    func.name, taint_sig, sp[-60:])
        output = run_agent(
            prompt=prompt, model=self._acfg.model,
            tools=self._acfg.tools or self._default_tools or [],
            cwd=str(self.source_root), env=v2_env, session_file=sp,
            system_prompt=_system_prompt(),
            cancel_event=getattr(self, "cancel_event", None),
            # Only v2 vuln mining keeps reasoning enabled; legacy dagflow mining stays explicitly off.
            thinking_level="off",
            run_timeout_seconds=getattr(self.config, "agent_run_timeout_seconds", 900),
            timeout_retry_enabled=getattr(self.config, "agent_timeout_retry_enabled", True),
            timeout_max_retries=getattr(self.config, "agent_timeout_max_retries", 20),
            pi_max_retries=getattr(self.config, "pi_max_retries", 3),
            pi_retry_delay=getattr(self.config, "pi_retry_delay", 10.0),
            task_context={"task_id": self.task_id,
                          "task_root": str(self.sessions_dir.parent.parent.parent),
                          "task_run_root": str(self.sessions_dir.parent),
                          "task_pi_dir": _task_pi_dir(self.config, "workers"),
                          "agent_role": "workers", "fork_purpose": "vuln_mining"},
        )
        text = output.output or ""
        parsed = _extract_json_object(text, "findings") or self._greedy_json(text) or {"findings": []}
        findings = self._parse_findings(parsed)
        node_id = f"{func.file}::{func.name}"
        finding_store.save_findings(self.vuln_store, findings, run_id=self.run_id,
                                    node_id=node_id, func=func)
        logger.info("[dagflow-mine] DONE func=%s taint=%s duration=%.1fs findings=%d error=%s",
                    func.name, taint_sig, _time.time() - _t0, len(findings), (output.error or "")[:100])
        if self.on_event:
            try:
                self.on_event("v2_dagflow_mined", function=func.name, taint=taint_sig,
                              findings=len(findings), task_id=self.task_id)
            except Exception:
                pass
        return findings

    def _build_prompt(self, func, taint_sig, chain, source) -> str:
        import json as _json
        return (
            f"# 阶段: dagflow 漏洞挖掘\n\n"
            f"目标函数: `{func.file}::{func.name}` (行 {func.start_line}-{func.end_line})\n"
            f"挖掘污点: {taint_sig}\n\n"
            f"## 正向数据流链 (入口 → callee 效应序列 → sink)\n"
            f"```json\n{_json.dumps(chain, ensure_ascii=False, indent=2)[:20000]}\n```\n\n"
            f"## 本函数完整源码\n```c\n{source}\n```\n\n"
            f"按系统提示词四维度 (D1-D4) 判定, 默认非漏洞找反证, 输出 findings JSON。"
        )

    def _session_path(self, func, taint_sig):
        from .session_naming import session_path
        return session_path(self.sessions_dir, func.name, taint_sig, kind="vuln")

    def _parse_findings(self, parsed: dict) -> list[Finding]:
        out: list[Finding] = []
        for item in (parsed.get("findings") or []):
            if not isinstance(item, dict):
                continue
            loc = item.get("location") or {}
            dims_raw = item.get("dimensions") or {}
            dims = {k: Dimension(pass_=bool(v.get("pass", False)) if isinstance(v, dict) else False,
                                 reason=str(v.get("reason", "")) if isinstance(v, dict) else str(v))
                    for k, v in dims_raw.items()}
            out.append(Finding(
                vuln_type=str(item.get("vuln_type", "unknown")),
                severity=str(item.get("severity", "unknown")),
                title=str(item.get("title", "")),
                summary=str(item.get("summary", "")),
                entry_point=str(item.get("entry_point", "")),
                trigger_path=str(item.get("trigger_path", "")),
                evidence=str(item.get("evidence", "")),
                location_func=str(loc.get("function", "")),
                location_line=str(loc.get("line", "")),
                dag_path=list(item.get("dag_path") or []),
                exploitability=item.get("exploitability") or {},
                dimensions=dims,
                confidence=float(item.get("confidence", 0) or 0)))
        return out

    def _greedy_json(self, text: str) -> dict | None:
        import re
        for blk in reversed(re.findall(r"```json\s*(.*?)```", text, re.S)):
            try: return json.loads(blk.strip())
            except Exception: continue
        s, e = text.find("{"), text.rfind("}")
        if s >= 0 and e > s:
            try: return json.loads(text[s:e + 1])
            except Exception: return None
        return None
