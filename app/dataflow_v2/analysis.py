"""dataflow-v2 分析回调的具体实现。

TaintAnalysisCallbacks.analyze_function:
  1. (确保) tree-sitter 索引本函数所在文件 → 拿到函数体 (run/functions/)
  2. 在前置 session 基础上 fork 会话, run_agent 跑 taint-analysis 提示词
  3. 解析 LLM 输出 JSON → 建 TaintRecord / PropagationRecord
  4. clang 标注每条 propagation 的调用点分支上下文 (branch_group/arm/path)
     + 幽灵 callee 丢弃 (target_function 不在 caller 函数体 CallExpr → 删该 propagation)
  5. 返回 AnalysisResult (含 self_contained)

resolve_external_propagation / mine_vulns 暂为 TODO stub (下一阶段)。
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Callable

from ..agent_runtime_events import emit_agent_runtime_events
from ..clang_analyzer import analyze_function_callsites
from ..copy_utils import safe_copyfile
from ..models import TaskConfig
from ..parsers import _extract_json_object
from ..runner import run_agent
from ..vuln_intake_reporter import report_finding_to_intake
from ..vuln_store import VulnFindingRecord, VulnScanStore
from ..vuln_workflow import (_EMBEDDED_VULN_MINING_SKILL, _format_vuln_report_md,
                             _read_prompt, _safe_name)
from .function_extractor import ensure_file_indexed
from .models import (
    FunctionRecord, PropagationRecord, TaintParamInfo, TaintRecord, Validation,
)
from .orchestrator import AnalysisResult, AnalysisCallbacks, PathContext
from .store import DataflowStore

logger = logging.getLogger("dvs.dataflow_v2")

_TAINT_ANALYSIS_PROMPT = _read_prompt("prompts/v2/taint-analysis.md")


class TaintAnalysisCallbacks(AnalysisCallbacks):
    """注入编排器的具体 LLM + clang 实现。"""

    def __init__(self, *, cfg: TaskConfig, source_root: str, run_dir: Path,
                 sessions_dir: Path, graph_db_path: Path, vuln_root: Path,
                 run_id: str, task_id: str, cancel_event: Any = None,
                 on_event: Callable[..., None] | None = None) -> None:
        self.cfg = cfg
        self.source_root = source_root
        self.run_dir = Path(run_dir)
        self.sessions_dir = Path(sessions_dir)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "clang-cache").mkdir(parents=True, exist_ok=True)
        self.vuln_root = Path(vuln_root)
        self.vuln_root.mkdir(parents=True, exist_ok=True)
        self.graph_store = VulnScanStore(graph_db_path)
        self.run_id = run_id
        self.task_id = task_id
        self.cancel_event = cancel_event
        self.on_event = on_event or (lambda *a, **k: None)
        self._vuln_miner_prompt = _read_prompt("prompts/vuln-miners/default.md")
        self._tracking_prompt = _read_prompt("prompts/v2/external-tracking.md")

    # ── 主入口 ─────────────────────────────────────────────────────────────
    def analyze_function(self, store: DataflowStore, func: FunctionRecord,
                         taint_params: TaintParamInfo, pre_validations: list[Validation],
                         base_session: str, ctx: PathContext) -> AnalysisResult:
        # 1) 确保文件已索引 (函数体在 run/functions/)
        ensure_file_indexed(self.source_root, func.file, store)
        body = self._read_body(func)

        # 2) fork session
        fork_session = self.sessions_dir / f"{_safe_name(func.name)}-taint.jsonl"
        try:
            if base_session and Path(base_session).exists():
                safe_copyfile(base_session, str(fork_session))
        except OSError:
            pass

        # 3) 构造 prompt
        prompt = self._build_prompt(func, body, taint_params, pre_validations)
        acfg = self.cfg.workers.agents[0] if self.cfg.workers.agents else None
        if acfg is None:
            return AnalysisResult(description="no agent configured", self_contained=False)

        # 4) run_agent
        output = run_agent(
            prompt=prompt, model=acfg.model, tools=acfg.tools or self.cfg.workers.default_tools,
            cwd=str(self.run_dir), session_file=str(fork_session),
            system_prompt=_TAINT_ANALYSIS_PROMPT, cancel_event=self.cancel_event,
            run_timeout_seconds=self.cfg.agent_run_timeout_seconds,
            timeout_retry_enabled=self.cfg.agent_timeout_retry_enabled,
            timeout_max_retries=self.cfg.agent_timeout_max_retries,
            pi_max_retries=self.cfg.pi_max_retries, pi_retry_delay=self.cfg.pi_retry_delay,
            task_context={"task_id": getattr(ctx, "path_id", ""), "task_root": str(self.run_dir.parent),
                          "task_run_root": str(self.run_dir), "task_pi_dir": self.cfg.role_pi_dir("workers"),
                          "agent_role": "workers"},
        )
        if self.on_event:
            emit_agent_runtime_events(self.on_event, result=output, stage="taint_analysis_v2",
                                      role="workers", model=acfg.model,
                                      extra={"function": func.name, "fork_purpose": "taint_analysis"})

        # 5) 解析 JSON
        parsed = _extract_json_object(output.output, "propagations") or {}
        return self._build_result(store, func, taint_params, parsed, fork_session)

    # ── 结果构造 + clang 标注 ───────────────────────────────────────────────
    def _build_result(self, store: DataflowStore, func: FunctionRecord,
                      taint_params: TaintParamInfo, parsed: dict,
                      fork_session: Path) -> AnalysisResult:
        description = str(parsed.get("description") or "")
        self_contained = bool(parsed.get("self_contained", False))

        # taints
        taints: list[TaintRecord] = []
        for t in parsed.get("taints") or []:
            if not isinstance(t, dict):
                continue
            taints.append(TaintRecord(
                func_id=func.func_id, name=str(t.get("name") or ""),
                signature=str(t.get("signature") or ""), file=func.file, function=func.name,
                description=str(t.get("description") or "")))

        # propagations (先建裸记录, 再 clang 标注)
        raw_props: list[PropagationRecord] = []
        callee_names: list[str] = []
        for p in parsed.get("propagations") or []:
            if not isinstance(p, dict):
                continue
            target_fn = str(p.get("target_function") or "").strip()
            is_ext = bool(p.get("is_external", False))
            if target_fn:
                callee_names.append(target_fn)
            raw_props.append(PropagationRecord(
                source_func_id=func.func_id,
                source_taint_name=str(p.get("source_taint") or ""),
                source_taint_signature=str(p.get("source_signature") or ""),
                target_taint_name=str(p.get("target_taint") or ""),
                target_taint_signature=str(p.get("target_signature") or ""),
                target_function=target_fn,
                target_file=str(p.get("target_file") or ""),
                call_line=int(p.get("call_line") or 0),
                condition=str(p.get("condition") or "always"),
                is_external=is_ext,
                validations=[Validation(str(v.get("condition") or ""), str(v.get("content") or ""))
                             for v in (p.get("validations") or []) if isinstance(v, dict)],
                description=str(p.get("description") or ""),
            ))

        # clang 标注: 校验调用点 + 分支上下文; 幽灵 callee (不在 caller 函数体) 丢弃
        # 但 clang 解析失败 (缺 include 等) 时 NOT 丢弃 — 区分 "解析失败"(保留, 仅缺分支标注)
        # 与 "解析成功但 callee 不在体"(真幽灵 → 丢), 避免过度丢弃。
        validated_props: list[PropagationRecord] = []
        parse_ok = clang_parse_ok(self.source_root, func.file, func.name) if callee_names else False
        if parse_ok:
            callsites = analyze_function_callsites(
                self.source_root, func.file, func.name, callee_names,
                self.run_dir / "clang-cache")
        else:
            callsites = {}
        for prop in raw_props:
            if prop.is_external or not prop.target_function:
                # 外部变量传播: 无调用点, 不经 clang; 由 resolve_external_propagation 处理
                validated_props.append(prop)
                continue
            if not parse_ok:
                # clang 解析失败 → 无法校验, 保留传播 (无分支标注, 下游按顺序链处理)
                prop.target_func_id = self._resolve_target_func_id(store, prop)
                validated_props.append(prop)
                continue
            ci = callsites.get(prop.target_function)
            if ci is None:
                # 幽灵 callee: caller 函数体根本没调用它 → 丢弃 (修 v1 Gap-1)
                logger.info("drop phantom callee %s in %s (not in body)", prop.target_function, func.name)
                self._emit("v2_phantom_callee_dropped", function=prop.target_function,
                           caller=func.name, claimed_line=prop.call_line)
                continue
            prop.callsite_validated = True
            prop.call_line = int(ci.get("call_line") or prop.call_line)
            prop.branch_path = ci.get("branch_path") or []
            prop.branch_group_id = str(ci.get("branch_group_id") or "")
            prop.branch_arm_id = str(ci.get("branch_arm_id") or "")
            prop.mutex_siblings = ci.get("mutex_siblings") or []
            prop.actual_args = ci.get("actual_args") or []
            # 解析 target_func_id (索引 callee 文件)
            prop.target_func_id = self._resolve_target_func_id(store, prop)
            validated_props.append(prop)

        return AnalysisResult(taints=taints, propagations=validated_props,
                              self_contained=self_contained, description=description)

    def _resolve_target_func_id(self, store: DataflowStore, prop: PropagationRecord) -> str:
        """从函数库解析 callee 的 func_id; 未索引则 tree-sitter 提取 callee 文件。"""
        if not prop.target_function:
            return ""
        rec = store.find_function(prop.target_function, prop.target_file) \
            or store.find_function(prop.target_function)
        if rec is None and prop.target_file:
            ensure_file_indexed(self.source_root, prop.target_file, store)
            rec = store.find_function(prop.target_function, prop.target_file) \
                or store.find_function(prop.target_function)
        return rec.func_id if rec else ""

    # ── prompt 构造 ─────────────────────────────────────────────────────────
    def _build_prompt(self, func: FunctionRecord, body: str,
                      taint_params: TaintParamInfo, pre_validations: list[Validation]) -> str:
        taint_desc = (f"位置 {taint_params.positions} 签名 {taint_params.signature} "
                      f"名字 {taint_params.names}") if taint_params.positions else "所有参数"
        pre_val_text = "\n".join(f"- {v.condition}: {v.content}" for v in pre_validations) or "(无)"
        return (
            f"# 阶段：单函数污点传播分析 Fork\n\n"
            f"目标函数: `{func.file}::{func.name}` (行 {func.start_line}-{func.end_line})\n"
            f"入口污点: {taint_desc}\n\n"
            f"## 前置校验链 (从根到本函数已累积)\n{pre_val_text}\n\n"
            f"## 函数体\n```c\n{body}\n```\n\n"
            f"按系统提示词要求输出 JSON (description/self_contained/taints/propagations)。"
        )

    def _read_body(self, func: FunctionRecord) -> str:
        if func.body_path and Path(func.body_path).is_file():
            try:
                return Path(func.body_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        return f"// body_path 不可读: {func.body_path}\n// 行 {func.start_line}-{func.end_line}"

    # ── 外部变量跟踪 (item 1) ────────────────────────────────────────────────
    def resolve_external_propagation(self, store: DataflowStore, func: FunctionRecord,
                                     taint: TaintRecord, ctx: PathContext) -> list[tuple[FunctionRecord, TaintParamInfo]]:
        """污点写入外部变量 → fork 跟踪 LLM 在源码树搜读取该变量的跟入函数, 分叉路径。"""
        fork_session = self.sessions_dir / f"{_safe_name(func.name)}-track-{_safe_name(taint.name)}.jsonl"
        prompt = (
            f"# 阶段：外部变量污点跟踪\n\n"
            f"写入函数: `{func.file}::{func.name}`\n"
            f"外部变量: `{taint.name}` (签名 {taint.signature})\n"
            f"说明: {taint.description or '(无)'}\n\n"
            f"在源码树 (cwd={self.source_root}) 搜索读取 `{taint.name}` 的函数, "
            f"按系统提示词输出 JSON {{\"follow_ins\":[...]}}。"
        )
        acfg = self.cfg.workers.agents[0] if self.cfg.workers.agents else None
        if acfg is None:
            return []
        output = run_agent(
            prompt=prompt, model=acfg.model, tools=acfg.tools or self.cfg.workers.default_tools,
            cwd=self.source_root, session_file=str(fork_session),
            system_prompt=self._tracking_prompt, cancel_event=self.cancel_event,
            run_timeout_seconds=min(self.cfg.agent_run_timeout_seconds, 1800),
            timeout_retry_enabled=self.cfg.agent_timeout_retry_enabled,
            timeout_max_retries=self.cfg.agent_timeout_max_retries,
            pi_max_retries=self.cfg.pi_max_retries, pi_retry_delay=self.cfg.pi_retry_delay,
            task_context={"task_id": self.task_id, "task_root": str(self.run_dir.parent),
                          "task_run_root": str(self.run_dir), "task_pi_dir": self.cfg.role_pi_dir("workers"),
                          "agent_role": "workers"},
        )
        if self.on_event:
            emit_agent_runtime_events(self.on_event, result=output, stage="external_tracking_v2",
                                      role="workers", model=acfg.model,
                                      extra={"function": func.name, "var": taint.name})
        parsed = _extract_json_object(output.output, "follow_ins") or {}
        out: list[tuple[FunctionRecord, TaintParamInfo]] = []
        for item in parsed.get("follow_ins") or []:
            if not isinstance(item, dict):
                continue
            fn = str(item.get("function") or "").strip()
            if not fn:
                continue
            # 索引跟入函数所在文件, 拿 FunctionRecord
            rec = store.find_function(fn) or store.find_function(fn, str(item.get("file") or ""))
            if rec is None and item.get("file"):
                ensure_file_indexed(self.source_root, str(item.get("file")), store)
                rec = store.find_function(fn) or store.find_function(fn, str(item.get("file") or ""))
            if rec is None:
                continue
            tp = TaintParamInfo(positions=[], signature=taint.signature,
                                names=[str(item.get("param_name") or taint.name)])
            out.append((rec, tp))
        return out

    # ── 漏洞挖掘 (item 2) ────────────────────────────────────────────────────
    def mine_vulns(self, store: DataflowStore, func: FunctionRecord,
                   taint_params: TaintParamInfo, ctx: PathContext) -> int:
        """fork 漏洞挖掘会话 (复用 vuln-miners/default.md), 存 finding + 上报 intake。"""
        acfg = self.cfg.workers.agents[0] if self.cfg.workers.agents else None
        if acfg is None:
            return 0
        fork_session = self.sessions_dir / f"{_safe_name(func.name)}-vuln.jsonl"
        # 构造本函数污点分析上下文文本 (taints + propagations + 前置校验链)
        taints = store.list_taints_in_function(func.func_id)
        props = store.list_propagations_from(func.func_id)
        dataflow_text = self._format_taint_context(func, taint_params, ctx, taints, props)
        prompt = (
            f"# 阶段：漏洞挖掘 Fork\n\n目标函数: `{func.file}::{func.name}`\n"
            f"污点: 位置 {taint_params.positions} 签名 {taint_params.signature} 名字 {taint_params.names}\n\n"
            "基于下面的单函数污点传播结果, 判断是否存在漏洞。输出 JSON: {\"findings\":[]}。\n\n"
            f"```markdown\n{dataflow_text[:30000]}\n```"
        )
        miner_system = ("# 内嵌技能：mine-dataflow-vulnerability\n"
                        "禁止再读取 skills/mine-dataflow-vulnerability/SKILL.md。\n\n"
                        f"{_EMBEDDED_VULN_MINING_SKILL}\n\n{self._vuln_miner_prompt}")
        output = run_agent(
            prompt=prompt, model=acfg.model, tools=acfg.tools or self.cfg.workers.default_tools,
            cwd=str(self.vuln_root.parent), session_file=str(fork_session),
            system_prompt=miner_system, cancel_event=self.cancel_event,
            run_timeout_seconds=self.cfg.agent_run_timeout_seconds,
            timeout_retry_enabled=self.cfg.agent_timeout_retry_enabled,
            timeout_max_retries=self.cfg.agent_timeout_max_retries,
            pi_max_retries=self.cfg.pi_max_retries, pi_retry_delay=self.cfg.pi_retry_delay,
            task_context={"task_id": self.task_id, "task_root": str(self.run_dir.parent),
                          "task_run_root": str(self.run_dir), "task_pi_dir": self.cfg.role_pi_dir("workers"),
                          "agent_role": "workers"},
        )
        if self.on_event:
            emit_agent_runtime_events(self.on_event, result=output, stage="vuln_mining_v2",
                                      role="workers", model=acfg.model, extra={"function": func.name})
        from ..parsers import _extract_json_object as _ej
        parsed = _ej(output.output, "findings") or {"findings": []}
        node = f"{func.file}::{func.name}"
        n = 0
        for idx, item in enumerate(parsed.get("findings") or []):
            if not isinstance(item, dict):
                continue
            finding_id = f"vuln_{hashlib.sha1((self.run_id+str(idx)+json.dumps(item, ensure_ascii=False)).encode()).hexdigest()[:16]}"
            fdir = self.vuln_root / finding_id; fdir.mkdir(parents=True, exist_ok=True)
            fsrc = str(item.get("source_file") or func.file)
            ffn = str(item.get("function_name") or func.name)
            fline = str(item.get("line") or "")
            (fdir / "vulnerability-report.md").write_text(
                _format_vuln_report_md(item, finding_id, fsrc, ffn, fline), encoding="utf-8")
            (fdir / "taint-path-report.md").write_text(dataflow_text, encoding="utf-8")
            try:
                safe_copyfile(str(fork_session), str(fdir / "context.jsonl"))
            except OSError:
                (fdir / "context.jsonl").write_text("", encoding="utf-8")
            _exploit = item.get("exploitability")
            expl_str = json.dumps(_exploit, ensure_ascii=False) if isinstance(_exploit, (dict, list)) else str(_exploit or "")
            rec = VulnFindingRecord(
                finding_id=finding_id, run_id=self.run_id, node_id=node,
                source_file=fsrc, function_name=ffn, line=fline,
                vuln_type=str(item.get("vuln_type") or "unknown"),
                severity=str(item.get("severity") or "unknown"),
                title=str(item.get("title") or finding_id),
                summary=str(item.get("summary") or ""),
                evidence=str(item.get("evidence") or ""),
                exploitability=expl_str,
                confidence=float(item.get("confidence") or 0),
                output_dir=str(fdir))
            self.graph_store.add_finding(rec)
            n += 1
            # 上报 vuln-platform intake
            try:
                report_finding_to_intake(
                    project_id=self.cfg.project_id, task_id=self.task_id,
                    task_name=self.cfg.task_name, parent_task_name=self.cfg.parent_task_name,
                    parent_task_id=self.cfg.parent_task_id, finding=rec,
                    source_root=self.source_root,
                    report_path=str(fdir / "vulnerability-report.md"),
                    taint_path_report_path=str(fdir / "taint-path-report.md"))
            except Exception as exc:
                logger.warning("v2 intake report failed for %s: %s", finding_id, exc, exc_info=True)
        return n

    def _format_taint_context(self, func: FunctionRecord, tp: TaintParamInfo,
                              ctx: PathContext, taints: list[TaintRecord],
                              props: list[PropagationRecord]) -> str:
        pre_val = "\n".join(f"- {v.condition}: {v.content}" for v in ctx.pre_validations) or "(无)"
        lines = [f"## 函数: {func.file}::{func.name} (行 {func.start_line}-{func.end_line})",
                 f"功能: {func.description or '(待分析)'}",
                 f"入口污点: 位置 {tp.positions} 签名 {tp.signature} 名字 {tp.names}",
                 f"前置校验链:\n{pre_val}", "", "## 污点变量:"]
        for t in taints:
            lines.append(f"- {t.name} ({t.signature}): {t.description}")
        lines.append("\n## 传播路径:")
        for p in props:
            tgt = p.target_function or "(外部变量)" if p.is_external else p.target_function
            lines.append(f"- {p.source_taint_name} → {tgt}({p.target_taint_name}) @L{p.call_line} "
                         f"[{p.condition}] {p.description}")
        return "\n".join(lines)
