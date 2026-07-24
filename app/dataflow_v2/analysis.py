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
import os
import time
from pathlib import Path
from typing import Any, Callable

from ..agent_runtime_events import emit_agent_runtime_events
from ..clang_analyzer import analyze_function_callsites, clang_parse_ok
from ..copy_utils import safe_copyfile
from ..models import TaskConfig
from ..parsers import _extract_json_object
from ..runner import run_agent
from ..llm_retry import run_agent_with_design_retry
from ..vuln_intake_reporter import report_finding_to_intake
from ..vuln_report_utils import (EMBEDDED_VULN_MINING_SKILL as _EMBEDDED_VULN_MINING_SKILL,
                                  build_v2_system_prompt as _build_v2_system_prompt,
                                  format_vuln_report_md as _format_vuln_report_md,
                                  read_prompt as _read_prompt, safe_name as _safe_name)
from ..vuln_store import (
    TaskGraphNodeRecord,
    TaskGraphSessionRecord,
    VulnFindingRecord,
    VulnScanStore,
)
from ..service.task_vuln_stats import refresh_task_vuln_snapshot_by_task_id
from .function_extractor import ensure_file_indexed
from .finding_store import persist_finding
from .models import (
    FunctionRecord, PropagationRecord, TaintParamInfo, TaintRecord, Validation,
)
from .orchestrator import AnalysisResult, AnalysisCallbacks, PathContext, _session_path
from .store import DataflowStore

logger = logging.getLogger("dvs.dataflow_v2")

_TAINT_ANALYSIS_PROMPT = _read_prompt("prompts/v2/taint-analysis.md")

import re as _re


def _short_list_preview(items: list[str], *, limit: int = 8) -> list[str]:
    preview = [str(item) for item in items[:limit]]
    if len(items) > limit:
        preview.append(f"...(+{len(items) - limit} more)")
    return preview


def _try_extract_truncated_json(text: str) -> dict | None:
    """尝试从被 stopReason=length 截断的文本中提取部分 JSON。

    LLM 输出被截断时, text 可能包含不完整的 ```json {... ``` 块。
    尝试找到 JSON 开头, 补全缺失的括号/引号, 解析。
    """
    import json
    # 找 json 代码块开头
    idx = text.find('{')
    if idx < 0:
        return None
    fragment = text[idx:]
    # 去掉末尾不完整的部分 (最后一个完整字段后截断)
    # 尝试直接解析
    try:
        return json.loads(fragment)
    except json.JSONDecodeError:
        pass
    # 尝试补全: 找最后一个完整的 key-value 对, 截断后面的
    last_comma = fragment.rfind(',')
    last_brace = fragment.rfind('}')
    last_bracket = fragment.rfind(']')
    # 尝试在最后一个逗号/括号后截断并补全
    for cut_pos in [last_bracket, last_brace, last_comma]:
        if cut_pos <= 0:
            continue
        partial = fragment[:cut_pos + 1]
        # 补全缺失的闭合符号
        opens_braces = partial.count('{') - partial.count('}')
        opens_brackets = partial.count('[') - partial.count(']')
        # 去掉末尾可能的逗号
        partial = partial.rstrip().rstrip(',')
        candidate = partial + ('}' * max(0, opens_braces)) + (']' * max(0, opens_brackets))
        try:
            result = json.loads(candidate)
            if isinstance(result, dict) and ('propagations' in result or 'taints' in result or 'description' in result):
                # 确保有 propagations 字段
                if 'propagations' not in result:
                    result['propagations'] = []
                if not isinstance(result.get('propagations'), list):
                    result['propagations'] = []
                return result
        except json.JSONDecodeError:
            continue
    return None


def _extract_params(func: FunctionRecord) -> set[str]:
    """从函数签名提取参数名集合。"""
    scope: set[str] = set()
    sig = func.signature or ""
    paren = sig.find("(")
    if paren >= 0:
        end = sig.rfind(")") if ")" in sig else len(sig)
        params_str = sig[paren+1:end]
        for param in params_str.split(","):
            param = param.strip()
            if not param or param == "void":
                continue
            ids = _re.findall(r'\b\w+\b', param)
            if ids:
                scope.add(ids[-1])
    return scope


def _extract_local_vars(body: str) -> set[str]:
    """从函数体提取局部变量名集合 (不含参数)。"""
    scope: set[str] = set()
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue
        if stripped.startswith(("if", "for", "while", "switch", "return", "else", "case", "break", "continue", "goto")):
            continue
        m = _re.match(r'(?:^\s*)(?:static\s+)?(?:const\s+)?[\w\s\*]+?\s+\*?(\w+)\s*[;=,]', stripped)
        if m:
            name = m.group(1)
            if name not in ("int", "char", "void", "unsigned", "signed", "struct", "enum", "union", "static", "const", "size_t", "return"):
                scope.add(name)
    return scope


def _extract_local_scope(func: FunctionRecord, body: str) -> set[str]:
    """参数 + 局部变量的并集 (用于规则 4 简单名校验)。"""
    return _extract_params(func) | _extract_local_vars(body)


def _validate_is_external(target_taint: str, target_function: str,
                          local_scope: set[str],
                          params: set[str] | None = None,
                          locals_: set[str] | None = None,
                          *, escape_kind: str = "") -> tuple[bool, str]:
    """轻量结构一致性校验 (不覆盖 LLM 的逃逸语义判定)。

    设计原则: 逃逸语义 (是否逃逸到外部可达对象) 由 LLM 判断, 脚本不做语义覆盖。
    这里只做纯结构一致性归位:
      1. escape_kind 非空 (LLM 显式报了 container/global/field_alias) → 一定保留 true
      2. target_function 非空且非逃逸 → false (callee 参数传播)
      3. target_taint 含返回值语义 → false (走 return_taints)
    历史上 "base 在 locals_ → false" / "简单名在局部作用域 → false" 的规则已删除:
    它们会误杀 "局部 alloc 载体经容器插入逃逸" 这类真实逃逸 (carrier 是局部变量,
    但其字段随载体挂入入参容器而逃逸)。逃逸判定交还 LLM, 由 tracker 复核读者。
    """
    if escape_kind:
        return True, f"LLM 报 escape_kind={escape_kind}, 尊重判定, 交 tracker 复核读者"
    if target_function:
        return False, "target_function 非空, 是 callee 参数传播不是外部变量"
    if target_taint and any(kw in target_taint.lower() for kw in ("返回", "return", "retval")):
        return False, "target_taint 含返回值语义, 不是外部变量"
    return bool(target_taint), ""


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

    def _cancel_requested(self) -> bool:
        return bool(self.cancel_event is not None and self.cancel_event.is_set())

    def _graph_store_ready(self) -> bool:
        store = getattr(self, "graph_store", None)
        if store is None:
            return False
        return hasattr(store, "upsert_task_graph_node") and hasattr(store, "upsert_task_graph_session")

    def _graph_terminal_status(self, *, failed_status: str = "failed", success_status: str = "done") -> str:
        if self._cancel_requested():
            return "cancelled"
        return failed_status if failed_status == "failed" and success_status != "done" else success_status

    @property
    def graph_epoch(self) -> str:
        parts = self.run_dir.parts
        if "epochs" in parts:
            idx = parts.index("epochs")
            if idx + 1 < len(parts):
                return parts[idx + 1]
        return "run"

    def graph_node_id(self, func: FunctionRecord) -> str:
        return f"node::{self.task_id}::{self.graph_epoch}::{func.func_id}"

    def graph_session_relpath(self, session_path: str | Path) -> str:
        session = Path(session_path)
        try:
            return str(session.resolve().relative_to(self.run_dir.parent.resolve())).replace("\\", "/")
        except Exception:
            try:
                return str(session.relative_to(self.run_dir.parent)).replace("\\", "/")
            except Exception:
                return str(session).replace("\\", "/")

    def record_graph_node(self, func: FunctionRecord, *, depth: int, status: str, analysis_status: str) -> str:
        node_id = self.graph_node_id(func)
        if not self._graph_store_ready():
            return node_id
        self.graph_store.upsert_task_graph_node(TaskGraphNodeRecord(
            node_id=node_id,
            task_id=self.task_id,
            epoch=self.graph_epoch,
            func_id=func.func_id,
            function_name_resolved=func.name,
            function_name_raw=func.name,
            source_file=func.file,
            depth=depth,
            status=status,
            analysis_status=analysis_status,
            started_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            session_group_key=f"d{depth:02d}::{func.name}",
        ))
        return node_id

    def record_graph_session(
        self,
        *,
        session_path: str | Path,
        node_id: str = "",
        edge_id: str = "",
        session_role: str,
        session_kind: str,
        status: str,
    ) -> str:
        relpath = self.graph_session_relpath(session_path)
        if not self._graph_store_ready():
            return relpath
        self.graph_store.upsert_task_graph_session(TaskGraphSessionRecord(
            session_relpath=relpath,
            task_id=self.task_id,
            epoch=self.graph_epoch,
            node_id=node_id,
            edge_id=edge_id,
            session_role=session_role,
            session_kind=session_kind,
            display_name=Path(session_path).stem,
            status=status,
            started_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        ))
        return relpath

    # ── 主入口 ─────────────────────────────────────────────────────────────
    def analyze_function(self, store: DataflowStore, func: FunctionRecord,
                         taint_params: TaintParamInfo, pre_validations: list[Validation],
                         base_session: str, ctx: PathContext) -> AnalysisResult:
        _t0 = time.time()
        logger.info("[V2-taint] START func=%s::%s taint=%s depth=%d",
                    func.file, func.name, taint_params.signature, getattr(ctx, "depth", 0))
        # 1) 确保文件已索引 (函数体在 run/functions/)
        ensure_file_indexed(self.source_root, func.file, store)
        body = self._read_body(func)

        # 2) fork session (v1 模型: copy base_session → 累积链上下文 A→A+B→A+B+C)
        fork_session = _session_path(self.sessions_dir, ctx.depth, func.name,
                                       taint_params.names[0] if taint_params.names and taint_params.names != ["auto"] else "")
        try:
            if base_session and Path(base_session).exists():
                safe_copyfile(base_session, str(fork_session))
        except OSError:
            pass
        node_id = self.record_graph_node(
            func,
            depth=getattr(ctx, "depth", 0),
            status="running",
            analysis_status="running",
        )
        session_relpath = self.record_graph_session(
            session_path=fork_session,
            node_id=node_id,
            session_role="worker",
            session_kind="taint",
            status="running",
        )
        if self._graph_store_ready():
            self.graph_store.update_task_graph_node(node_id, primary_session_relpath=session_relpath)

        # 3) 构造 prompt
        prompt = self._build_prompt(func, body, taint_params, pre_validations)
        acfg = self.cfg.workers.agents[0] if self.cfg.workers.agents else None
        if acfg is None:
            return AnalysisResult(description="no agent configured", self_contained=False)

        # 4) run_agent (注入 v2 DB 技能 + 定制技能, 设环境变量)
        v2_system = _build_v2_system_prompt(custom="taint-analysis")
        _taint_prompt = _read_prompt("prompts/v2/taint-analysis.md")
        system_prompt = f"{v2_system}\n\n{_taint_prompt}" if v2_system else _taint_prompt
        v2_env = {"DVS_V2_DB_DIR": str(self.vuln_root.parent / "dataflow-v2"),
                  "DVS_SOURCE_ROOT": self.source_root,
                  "DVS_TASK_ID": self.task_id,
                  "DVS_PROJECT_ID": getattr(self.cfg, "project_id", "") or "",
                  "DVS_MYSQL_URL": "mysql+pymysql://root:Huawei12%23$@secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local:3306"}

        # 4) run_agent + 设计重试 (①②③④, 三模式共享例程 app.llm_retry)
        #    parse_check 由本模式提供 (key="propagations"); 例程负责 length/error 回退 +
        #    Error-xx 会话 + 3 次后 compact。内层 run_agent(delegate_api_retry=True)
        #    不再抢先重试 stop_reason=error, 把结果交回本例程统一处理。
        def _parse_and_check(result, all_texts):
            text = getattr(result, "output", "") or ""
            p = _extract_json_object(text, "propagations")
            if not p:
                p = _try_extract_truncated_json(text)
            if not p and all_texts:
                for prev_text in all_texts:
                    p = _extract_json_object(prev_text, "propagations")
                    if p: break
                    p = _try_extract_truncated_json(prev_text)
                    if p: break
            if not p:
                return None, "missing taint-analysis JSON (no object containing 'propagations')"
            if not isinstance(p.get("propagations"), list):
                return p, "propagations must be a list"
            return p, ""

        def _on_result(stage, res, extra):
            if self.on_event:
                _stage_map = {"llm_call": "taint_analysis_v2",
                              "llm_retry": "taint_analysis_v2_retry",
                              "llm_continue": "taint_analysis_v2_length_continue"}
                emit_agent_runtime_events(self.on_event, result=res,
                                          stage=_stage_map.get(stage, stage),
                                          role="workers", model=acfg.model,
                                          extra={"function": func.name,
                                                 "fork_purpose": "taint_analysis",
                                                 **(extra or {})})

        def _v2_on_event(etype, **payload):
            # 共享例程的通用事件映射回 v2 既有事件名, 保持前端/观测兼容
            _name_map = {"llm_retry_json": "v2_taint_retry_json",
                         "llm_rollback": "v2_rollback_before_retry",
                         "llm_length_continue": "v2_length_continue",
                         "llm_compact_retry": "v2_compact_retry",
                         "llm_retry_failed": "v2_taint_analysis_failed"}
            payload["function"] = payload.pop("label", func.name)
            self.on_event(_name_map.get(etype, etype), **payload)

        output, parsed, parse_warn = run_agent_with_design_retry(
            prompt,
            model=acfg.model, tools=acfg.tools or self.cfg.workers.default_tools,
            system_prompt=system_prompt, cwd=str(self.run_dir), env=v2_env,
            thinking_level="off", session_file=str(fork_session),
            cancel_event=self.cancel_event,
            run_timeout_seconds=self.cfg.agent_run_timeout_seconds,
            timeout_retry_enabled=self.cfg.agent_timeout_retry_enabled,
            timeout_max_retries=self.cfg.agent_timeout_max_retries,
            pi_max_retries=self.cfg.pi_max_retries, pi_retry_delay=self.cfg.pi_retry_delay,
            task_context={"task_id": getattr(ctx, "path_id", ""), "task_root": str(self.run_dir.parent),
                          "task_run_root": str(self.run_dir), "task_pi_dir": self.cfg.role_pi_dir("workers"),
                          "agent_role": "workers", "fork_purpose": "taint_analysis"},
            parse_check=_parse_and_check,
            rollback_session=base_session,
            error_session_fn=lambda n: str(_session_path(self.sessions_dir, ctx.depth, func.name, f"error{n}")),
            on_event=_v2_on_event if self.on_event else None,
            on_result=_on_result,
            label=func.name, retry_max=3,
        )
        if parse_warn:
            parsed = parsed or {}

        # taint 分析失败时跳过后续 mining — 无污点分析结果, 挖掘无意义
        taint_failed = bool(parse_warn)
        logger.info("[V2-taint] DONE func=%s::%s duration=%.1fs taint_failed=%s self_contained=%s propagations=%d",
                    func.file, func.name, time.time() - _t0, taint_failed, parsed.get("self_contained", False),
                    len(parsed.get("propagations") or []))
        terminal_status = "cancelled" if self._cancel_requested() else ("done" if not taint_failed else "failed")
        terminal_analysis_status = "cancelled" if self._cancel_requested() else ("done" if not taint_failed else "failed")
        if self._graph_store_ready():
            self.graph_store.update_task_graph_node(
                node_id,
                status=terminal_status,
                analysis_status=terminal_analysis_status,
                finished_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                primary_session_relpath=session_relpath,
            )
            self.graph_store.update_task_graph_session(
                session_relpath,
                node_id=node_id,
                status=terminal_status,
                ended_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            )
        return self._build_result(store, func, taint_params, parsed, fork_session, body, taint_failed=taint_failed)

    # ── 结果构造 + clang 标注 ───────────────────────────────────────────────
    def _build_result(self, store: DataflowStore, func: FunctionRecord,
                      taint_params: TaintParamInfo, parsed: dict,
                      fork_session: Path, body: str = "",
                      taint_failed: bool = False) -> AnalysisResult:
        description = str(parsed.get("description") or "")
        self_contained = bool(parsed.get("self_contained", False))

        # taints
        taints: list[TaintRecord] = []
        for t in parsed.get("taints") or []:
            if not isinstance(t, dict):
                continue
            _tname = str(t.get("name") or "")
            taints.append(TaintRecord(
                func_id=func.func_id, name=_tname,
                signature=_tname, file=func.file, function=func.name,
                description=str(t.get("description") or "")))

        # propagations: LLM 只输出语义字段; 结构字段 (call_line/condition/is_indirect/signature)
        # 由 clang/脚本提供。is_indirect_call 由 target_function 表达式模式检测 (脚本)。
        # 脚本不覆盖逃逸语义: is_external 尊重 LLM 判定 (container/global/field_alias)
        local_scope = _extract_local_scope(func, body)
        params_set = _extract_params(func)
        locals_set = _extract_local_vars(body)
        # C++ 方法: this 是隐式参数
        if "::" in func.name:
            params_set.add("this")
            local_scope.add("this")
        raw_props: list[PropagationRecord] = []
        callee_names: list[str] = []
        for p in parsed.get("propagations") or []:
            if not isinstance(p, dict):
                continue
            target_fn = str(p.get("target_function") or "").strip()
            is_ext = bool(p.get("is_external", False))
            target_taint = str(p.get("target_taint") or "")
            escape_kind = str(p.get("escape_kind") or "").strip()
            carrier = str(p.get("carrier") or "").strip()
            escape_via = str(p.get("escape_via") or "").strip()
            # 轻量一致性校验 (escape_kind 一定保留 true; 其余只做结构归位)
            llm_said_external = is_ext
            if is_ext:
                is_ext, override_reason = _validate_is_external(
                    target_taint, target_fn, local_scope, params_set, locals_set,
                    escape_kind=escape_kind)
                if override_reason:
                    self.on_event("v2_is_external_overridden",
                                  function=func.name,
                                  target_taint=target_taint,
                                  target_function=target_fn,
                                  reason=override_reason)
            # 系统检测间接调用: target_function 是函数指针表达式 (含 -> / (* / [)
            is_indirect = bool(target_fn) and ("->" in target_fn or target_fn.startswith("*") or "[" in target_fn)
            dispatch_kind = "function_pointer_field" if is_indirect else ""
            if target_fn and not is_ext and not is_indirect:
                callee_names.append(target_fn)  # 直接调用: clang 按名定位 CallExpr
            raw_props.append(PropagationRecord(
                source_func_id=func.func_id,
                source_taint_name=str(p.get("source_taint") or ""),
                source_taint_signature=str(p.get("source_taint") or ""),
                target_taint_name=str(p.get("target_taint") or ""),
                target_taint_signature=str(p.get("target_taint") or ""),
                target_function=target_fn,
                target_file="",  # 系统按名从全局函数库解析
                call_line=0,  # clang 标注时填 (直接调用)
                condition="",  # clang 标注时填分支
                is_external=is_ext,
                is_indirect_call=is_indirect,
                dispatch_kind=dispatch_kind,
                escape_kind=escape_kind,
                carrier=carrier,
                escape_via=escape_via,
                _llm_said_external=llm_said_external,
                validations=[Validation(
                                 left=str(v.get("left") or v.get("condition") or ""),
                                 op=str(v.get("op") or ""),
                                 right=str(v.get("right") or v.get("content") or ""),
                                 line=int(v.get("line") or 0))
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
            if (prop.is_external or prop.is_indirect_call) or not prop.target_function:
                # 外部变量 / 函数指针间接调用 / 无 callee: 不经 clang (由各自 tracker 处理)
                validated_props.append(prop)
                continue
            if not parse_ok:
                # clang 解析失败 → 无法校验, 保留传播
                # 但如果 LLM 原标 external + target 不是真实函数 → 可能是函数指针, 标 indirect
                if getattr(prop, '_llm_said_external', False) and prop.target_function:
                    if not store.find_function(prop.target_function):
                        prop.is_indirect_call = True
                        prop.dispatch_kind = "function_pointer_field"
                        self.on_event("v2_parse_fail_to_indirect",
                                      function=prop.target_function, caller=func.name,
                                      reason="clang parse failed + LLM external + not real function → indirect")
                prop.target_func_id = self._resolve_target_func_id(store, prop)
                validated_props.append(prop)
                continue
            ci = callsites.get(prop.target_function)
            if ci is None:
                # 幽灵 callee: caller 函数体没直接调用它
                # 但如果 LLM 原来标了 is_external=true, 说明 LLM 认为这是间接调用
                # (如 writecallback 是函数指针字段, LLM 没写完整表达式)
                # → 不丢弃, 重新标为 indirect call 走 tracker
                if getattr(prop, '_llm_said_external', False):
                    prop.is_indirect_call = True
                    prop.dispatch_kind = "function_pointer_field"
                    self.on_event("v2_phantom_to_indirect",
                                  function=prop.target_function,
                                  caller=func.name,
                                  reason="LLM marked external + clang phantom → indirect call")
                    validated_props.append(prop)
                    continue
                # 如果 callee 在全局函数库中存在, 不丢弃 (clang 可能因 macro/include 漏检)
                if prop.target_function and store.find_function(prop.target_function):
                    prop.target_func_id = self._resolve_target_func_id(store, prop)
                    validated_props.append(prop)
                    self.on_event("v2_phantom_callee_kept", function=prop.target_function,
                               caller=func.name, claimed_line=prop.call_line,
                               reason="exists in function DB, clang may have missed callsite (macro/include)")
                    continue
                # callee 不在 DB 也不在 clang 体: 保留为未校验传播 (不丢弃)
                # 之前丢弃导致 _prop_count=0 → “未产出传播边” 误报
                prop.target_func_id = self._resolve_target_func_id(store, prop)
                validated_props.append(prop)
                logger.info("keep unvalidated callee %s in %s (not in DB, not in clang body)",
                            prop.target_function, func.name)
                self.on_event("v2_phantom_callee_kept", function=prop.target_function,
                           caller=func.name, claimed_line=prop.call_line,
                           reason="not in function DB and not in clang body; kept as unvalidated")
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

        # parse return_taints
        return_taints: list[TaintRecord] = []
        for rt in parsed.get("return_taints") or []:
            if not isinstance(rt, dict):
                continue
            _rtname = str(rt.get("name") or "")
            return_taints.append(TaintRecord(
                func_id=func.func_id, name=_rtname,
                signature=_rtname, file=func.file, function=func.name,
                description=str(rt.get("description") or "")))

        # 外部 callee 语义推断: 批量 LLM 调用
        external_props = [p for p in validated_props
                          if p.is_external_callee and p.target_function]
        if external_props:
            inferred = self._infer_external_callees(external_props, func, str(fork_session))
            for prop in external_props:
                inf = inferred.get(prop.target_function)
                if inf and inf.get("inferable"):
                    prop.is_external_callee = False
                    # return_taint: 外部函数返回值携带污点
                    if inf.get("return_taint"):
                        rt_name = str(inf["return_taint"])
                        return_taints.append(TaintRecord(
                            func_id=func.func_id, name=rt_name,
                            signature=rt_name, file=func.file, function=func.name,
                            description=f"外部函数 {prop.target_function} 返回值携带污点 (LLM推断)"))
                    # propagation: 参数间传播 (如 memcpy src→dst)
                    if inf.get("propagation"):
                        prop.is_external_callee = False
                    # validation: 校验描述 (外部函数推断, 弱信号; op 留空, 不入去重签名)
                    if inf.get("validation"):
                        prop.validations.append(
                            Validation(left=prop.source_taint_name, op="", right=str(inf.get("validation"))))
                    self.on_event("v2_external_callee_inferred",
                                  function=prop.target_function,
                                  caller=func.name,
                                  return_taint=inf.get("return_taint"),
                                  propagation=inf.get("propagation"),
                                  validation=inf.get("validation"))
                # else: inferable=false → 保持 is_external_callee=True (视为不存在)

        return AnalysisResult(taints=taints, propagations=validated_props,
                              self_contained=self_contained, description=description,
                              session_path=str(fork_session),
                              return_taints=return_taints,
                              taint_failed=taint_failed)

    def _within_source_root(self, file: str) -> bool:
        """文件是否在源码目录内 (目录内=合理可分析, 目录外=不分析; 不按文件名过滤,
        因为被分析的函数本身可能就是 fuzz 工具)。防 ../ 逃逸与绝对路径越界。"""
        if not file:
            return False
        try:
            root = os.path.realpath(self.source_root)
            # 相对路径 → 拼到 source_root 下; 绝对路径 → 原样
            p = file if os.path.isabs(file) else os.path.join(self.source_root, file)
            rp = os.path.realpath(p)
            return rp == root or rp.startswith(root + os.sep)
        except Exception:
            return False

    def _search_callee_files(self, callee_name: str) -> list[str]:
        """按需搜索: callee 不在已索引文件时, grep 源码树找其**所有**出现文件。

        grep -l 既匹配调用点也匹配定义点, 故返回的文件列表里可能混有仅含调用点的
        文件; 调用方需对每个文件 ensure_file_indexed (tree-sitter 建库) 后再
        find_function, 命中即为定义所在。返回相对 source_root 的路径列表。
        """
        import subprocess
        started_at = time.time()
        short = callee_name.rsplit("::", 1)[-1]
        logger.info(
            "[V2-resolve] search_callee_files START callee=%s short=%s source_root=%s",
            callee_name,
            short,
            self.source_root,
        )
        try:
            r = subprocess.run(
                ["grep", "-rlE", "--include=*.c", "--include=*.cpp", "--include=*.cc",
                 f"{short}[[:space:]]*\\(", self.source_root],
                capture_output=True, text=True, timeout=30)
        except Exception:
            logger.warning(
                "[V2-resolve] search_callee_files FAILED callee=%s short=%s duration=%.1fs",
                callee_name,
                short,
                time.time() - started_at,
                exc_info=True,
            )
            return []
        out: list[str] = []
        for f in (r.stdout or "").split("\n"):
            f = f.strip()
            if not f:
                continue
            try:
                rel = str(Path(f).relative_to(self.source_root).as_posix())
            except ValueError:
                continue  # 不在 source_root 内 (grep wrapper 已限制, 正常不会到这)
            if rel not in out:
                out.append(rel)
        logger.info(
            "[V2-resolve] search_callee_files DONE callee=%s short=%s duration=%.1fs returncode=%s candidates=%d preview=%s stderr=%s",
            callee_name,
            short,
            time.time() - started_at,
            r.returncode,
            len(out),
            _short_list_preview(out),
            (r.stderr or "").strip()[:300],
        )
        return out

    def _resolve_target_func_id(self, store: DataflowStore, prop: PropagationRecord) -> str:
        """按 callee 名解析 func_id。

        先查全局函数库; 未命中则 grep 源码树找该名字出现的**所有**文件, 逐个
        ensure_file_indexed (tree-sitter 建库) 后再 find_function — grep 既匹配
        调用点也匹配定义点, 故可能要索引多个文件 (含仅含调用点的文件) 才能命中
        真正的定义。全部候选文件建库后仍查不到, 才判定为外部符号
        (is_external_callee, 不跟入, 不走 tracker)。
        """
        if not prop.target_function:
            return ""
        started_at = time.time()
        logger.info(
            "[V2-resolve] target_func_id START callee=%s caller_func_id=%s source_taint=%s target_taint=%s call_line=%s dispatch_kind=%s is_external=%s is_indirect=%s",
            prop.target_function,
            prop.source_func_id,
            prop.source_taint_name,
            prop.target_taint_name,
            prop.call_line,
            prop.dispatch_kind,
            prop.is_external,
            prop.is_indirect_call,
        )
        rec = store.find_function(prop.target_function)
        if rec is not None:
            logger.info(
                "[V2-resolve] target_func_id HIT callee=%s func_id=%s file=%s duration=%.1fs source=indexed_store",
                prop.target_function,
                rec.func_id,
                rec.file,
                time.time() - started_at,
            )
        if rec is None:
            candidates = self._search_callee_files(prop.target_function)
            logger.info(
                "[V2-resolve] target_func_id INDEX_CANDIDATES callee=%s candidate_count=%d preview=%s",
                prop.target_function,
                len(candidates),
                _short_list_preview(candidates),
            )
            for fpath in candidates:
                if not self._within_source_root(fpath):
                    logger.info(
                        "[V2-resolve] target_func_id SKIP_OUT_OF_SCOPE callee=%s candidate=%s",
                        prop.target_function,
                        fpath,
                    )
                    continue
                file_started_at = time.time()
                try:
                    ensure_file_indexed(self.source_root, fpath, store)
                    logger.info(
                        "[V2-resolve] target_func_id INDEXED callee=%s candidate=%s duration=%.1fs",
                        prop.target_function,
                        fpath,
                        time.time() - file_started_at,
                    )
                except Exception:
                    logger.debug("v2 ensure_file_indexed failed for %s", fpath, exc_info=True)
                    logger.warning(
                        "[V2-resolve] target_func_id INDEX_FAILED callee=%s candidate=%s duration=%.1fs",
                        prop.target_function,
                        fpath,
                        time.time() - file_started_at,
                        exc_info=True,
                    )
                    continue
            # 全部候选建库后再查 (定义可能在任一文件里, 上面已全部索引)
            rec = store.find_function(prop.target_function)
            if rec is not None:
                logger.info(
                    "[V2-resolve] target_func_id RESOLVED_AFTER_INDEX callee=%s func_id=%s file=%s duration=%.1fs",
                    prop.target_function,
                    rec.func_id,
                    rec.file,
                    time.time() - started_at,
                )
        if rec is None:
            # 定义不在源码树 (外部库/系统 API) — 记录传播但不跟入
            # 不设 is_external (那是外部变量传播, 走 tracker)
            # 设 is_external_callee (callee 实现不可达, 不跟入不走 tracker)
            prop.is_external_callee = True
            logger.info(
                "[V2-resolve] target_func_id UNRESOLVED callee=%s caller_func_id=%s duration=%.1fs reason=definition_not_found_in_source_tree",
                prop.target_function,
                prop.source_func_id,
                time.time() - started_at,
            )
            self.on_event("v2_callee_external_unresolved",
                          function=prop.target_function, caller=prop.source_func_id,
                          reason="definition not found in source tree")
            return ""
        if rec.file and not self._within_source_root(rec.file):
            logger.info(
                "[V2-resolve] target_func_id OUT_OF_SCOPE callee=%s func_id=%s file=%s duration=%.1fs",
                prop.target_function,
                rec.func_id,
                rec.file,
                time.time() - started_at,
            )
            self.on_event("v2_out_of_scope_skipped", function=prop.target_function,
                       file=rec.file, reason="outside_source_root")
            return ""
        logger.info(
            "[V2-resolve] target_func_id DONE callee=%s func_id=%s file=%s duration=%.1fs",
            prop.target_function,
            rec.func_id,
            rec.file,
            time.time() - started_at,
        )
        return rec.func_id

    # ── prompt 构造 ─────────────────────────────────────────────────────────
    def _infer_external_callees(self, external_props: list, func: FunctionRecord,
                                base_session: str = "") -> dict:
        """批量 LLM 推断外部函数语义 (一次调用)。

        返回 {function_name: {inferable, return_taint, propagation, validation}}
        """
        _t0 = time.time()
        _names = [p.target_function for p in external_props]
        logger.info(
            "[V2-infer-ext] START func=%s file=%s callees=%s count=%d base_session=%s",
            func.name,
            func.file,
            _names,
            len(_names),
            str(base_session or "")[-120:],
        )
        acfg = self.cfg.workers.agents[0] if self.cfg.workers.agents else None
        if acfg is None:
            return {}
        # 构造批量推断 prompt
        lines = []
        for i, p in enumerate(external_props, 1):
            lines.append(f"{i}. 函数: {p.target_function}, 污点参数: {p.source_taint_name} → {p.target_taint_name}")
        logger.info(
            "[V2-infer-ext] INPUTS func=%s entries=%s",
            func.name,
            [
                {
                    "target_function": str(p.target_function or ""),
                    "source_taint": str(p.source_taint_name or ""),
                    "target_taint": str(p.target_taint_name or ""),
                    "call_line": int(getattr(p, "call_line", 0) or 0),
                    "source_func_id": str(getattr(p, "source_func_id", "") or ""),
                }
                for p in external_props
            ],
        )
        prompt = (
            "以下外部函数被污点参数调用, 定义不在源码中。\n"
            "请根据函数名和调用上下文, 逐个判断能否推断其污点行为。\n\n"
            + "\n".join(lines) + "\n\n"
            "对每个函数输出 JSON (在一个 JSON 数组中):\n"
            '- 能推断: {"function": "open", "inferable": true, '
            '"return_taint": "fd", "propagation": null, "validation": null}\n'
            '  * return_taint: 返回值携带污点的变量名 (如 open → fd)\n'
            '  * propagation: 参数间传播 "dst<-src" (如 memcpy: src→dst)\n'
            '  * validation: 校验描述 (如 "strncpy 限制拷贝长度")\n'
            '- 不能推断: {"function": "MSG_Proc", "inferable": false}\n\n'
            '输出格式: ```json\n[{"function": "...", ...}, ...]\n```'
        )
        session_key = "_".join(_safe_name(p.target_function or "external") for p in external_props[:3]) or "external"
        if len(external_props) > 3:
            session_key = f"{session_key}_plus{len(external_props) - 3}"
        fork_session = _session_path(self.sessions_dir, -1, func.name, session_key[:80], kind="infer-ext")
        try:
            if base_session and Path(base_session).exists():
                safe_copyfile(base_session, str(fork_session))
        except OSError:
            pass
        logger.info(
            "[V2-infer-ext] CALLING run_agent (session=%s timeout=%ss)",
            str(fork_session)[-80:],
            self.cfg.agent_run_timeout_seconds,
        )
        result = run_agent(
            prompt=prompt, model=acfg.model,
            tools=acfg.tools or self.cfg.workers.default_tools,
            cwd=str(self.run_dir), session_file=str(fork_session),
            system_prompt="你是 C/C++ 安全分析专家。根据函数名推断外部函数的污点行为。",
            cancel_event=self.cancel_event,
            env={"DVS_V2_DB_DIR": str(self.vuln_root.parent / "dataflow-v2"),
                 "DVS_SOURCE_ROOT": self.source_root,
                 "DVS_TASK_ID": self.task_id,
                  "DVS_PROJECT_ID": getattr(self.cfg, "project_id", "") or "",
                  "DVS_MYSQL_URL": "mysql+pymysql://root:Huawei12%23$@secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local:3306"},
            thinking_level="off",
            run_timeout_seconds=self.cfg.agent_run_timeout_seconds,
            timeout_retry_enabled=self.cfg.agent_timeout_retry_enabled,
            timeout_max_retries=self.cfg.agent_timeout_max_retries,
            pi_max_retries=self.cfg.pi_max_retries, pi_retry_delay=self.cfg.pi_retry_delay,
        )
        logger.info("[V2-infer-ext] DONE func=%s duration=%.1fs error=%s output_len=%d",
                    func.name, time.time() - _t0, (result.error or "")[:100], len(result.output or ""))
        # 解析 JSON 数组
        from ..parsers import _extract_json_object
        text = result.output or ""
        import json as _json
        # 尝试解析 JSON 数组
        import re as _re
        m = _re.search(r'\[.*?\]', text, _re.DOTALL)
        if not m:
            return {}
        try:
            arr = _json.loads(m.group())
        except Exception:
            return {}
        inferred = {}
        for item in arr:
            if isinstance(item, dict):
                fn = str(item.get("function") or "")
                if fn:
                    inferred[fn] = item
        logger.info(
            "[V2-infer-ext] PARSED func=%s inferred=%s",
            func.name,
            inferred,
        )
        return inferred

    def _build_prompt(self, func: FunctionRecord, body: str,
                      taint_params: TaintParamInfo, pre_validations: list[Validation]) -> str:
        if taint_params.names == ["auto"] or taint_params.signature == "auto":
            taint_desc = ("自行分析（EA 未指定具体污点参数）。\n"
                          "请识别本函数中所有外部输入来源，包括但不限于：\n"
                          "- 入参中携带外部输入的变量\n"
                          "- 函数内部通过调用外部接口获取的数据\n"
                          "将识别到的所有污点源填入 taints[]，并跟踪其传播路径。\n"
                          "注意：只标注和跟踪外部攻击者可能控制的内容，不要标注攻击者无法控制的内部常量、编译期常量、静态配置、进程内部状态、纯内部派生值等其他外部攻击者无法控制的内容，所有污点中，那些不太可能造成安全危险的污点也不要标记和跟踪。")
        else:
            taint_desc = (f"位置 {taint_params.positions} 签名 {taint_params.signature} "
                          f"名字 {taint_params.names}\n"
                          "注意：即使上游已经传入了污点参数，也必须在当前函数内重新判断这些参数是否真的属于外部攻击者可控制的输入；"
                          "只对可被外部攻击者控制的内容继续标注和跟踪，不能默认所有传入参数都要作为污点，所有外部攻击者无法控制的内容都不要标注和跟踪，所有污点中，那些不太可能造成安全危险的污点也不要标记和跟踪。")
        pre_val_text = "\n".join(f"- {v.left} {v.op} {v.right} (行 {v.line})" for v in pre_validations if v.left and v.op) or "(无)"
        return (
            f"# 阶段：单函数污点传播分析 Fork\n\n"
            f"**重要**: 本 session 继承了父函数的分析历史。你只分析 **当前函数体** "
            f"(行 {func.start_line}-{func.end_line}) 内的传播，不要重述父函数已报告的传播。\n\n"
            f"目标函数: `{func.file}::{func.name}` (行 {func.start_line}-{func.end_line})\n\n"
            f"源码绝对根目录: `{self.source_root}`。`{func.file}` 是相对该根目录的源码路径；如果需要使用 read/find 读取源码，请基于这个绝对根目录定位文件，不要基于当前工作目录拼接路径。\n\n"
            f"攻击面复核要求: 无论上游是否已传入污点参数，都要根据函数的功能，传递的参数值的含义，先判断当前函数里哪些输入/变量真实属于外部攻击者可控制的内容,以及攻击者可控的内容能够造成安全危害；"
            f"对攻击者不可控的常量、编译期固定值、静态配置、进程内部状态、纯内部派生值以及其他无法控制的内容，以及不太可能造成安全危害的污点,如简单的类型或者已经经过足够多校验的污点，一律不要作为污点继续跟踪，也不要输出到最终结果，可根据经验进行判断是否属于攻击者可控内容。\n\n"
            f"如果目标函数和传入的污点，不太可能造成安全问题，或者目标函数功能是没有危险的，也不需要跟踪，也不要输出到最终结果,只有值得接下来分析的污点和目标函数，才需要输出到最终结果中。\n\n"
            f"入口污点: {taint_desc}\n\n"
            f"## 前置校验链 (从根到本函数已累积)\n{pre_val_text}\n\n"
            f"## 函数体\n```c\n{body}\n```\n\n"
            f"按系统提示词要求输出 JSON (description/self_contained/taints/propagations)。"
        )

    def _read_body(self, func: FunctionRecord) -> str:
        from .function_extractor import read_function_body
        return read_function_body(self.source_root, func, max_lines=500)

    # ── 函数指针间接调用跟踪 (复用 V1 function_pointer tracker) ──────────────
    def resolve_indirect_call(self, store: DataflowStore, func: FunctionRecord,
                              prop: PropagationRecord, ctx: PathContext,
                              base_session: str = "") -> list[tuple[FunctionRecord, TaintParamInfo]]:
        """函数指针注册点追踪: 前后缀匹配缩小候选 + LLM 判断 (fork-from-parent session)"""
        from .trackers import resolve_indirect
        return resolve_indirect(self.cfg, self.source_root, self.sessions_dir, store,
                               func, prop, self.cancel_event, self.on_event, ctx.depth,
                               base_session)

    # ── 外部变量跟踪 (item 1) ────────────────────────────────────────────────
    def resolve_external_propagation(self, store: DataflowStore, func: FunctionRecord,
                                     prop: PropagationRecord, ctx: PathContext,
                                     base_session: str = "") -> list[tuple[FunctionRecord, TaintParamInfo]]:
        """外部逃逸下游追踪: LLM fork 用 v2_db 按逃逸语义查读者 (fork-from-parent session)"""
        from .trackers import resolve_external
        return resolve_external(self.cfg, self.source_root, self.sessions_dir, store,
                               func, prop, self.cancel_event, self.on_event, ctx.depth,
                               base_session)

    # ── 漏洞挖掘 (item 2) ────────────────────────────────────────────────────
    def mine_vulns(self, store: DataflowStore, func: FunctionRecord,
                   taint_params: TaintParamInfo, ctx: PathContext,
                   base_session: str = "") -> int:
        """fork 漏洞挖掘会话: 继承链 session (base_session, v1 模型 fork-from-parent),
        再提示分析本函数内的漏洞。存 finding + 上报 intake。"""
        _t0 = time.time()
        logger.info("[V2-mine] START func=%s::%s taint=%s thinking=%s",
                    func.file, func.name, taint_params.signature,
                    getattr(self.cfg, "vuln_mining_thinking_level", "high"))
        acfg = self.cfg.workers.agents[0] if self.cfg.workers.agents else None
        if acfg is None:
            return 0
        fork_session = _session_path(self.sessions_dir, ctx.depth, func.name, "", kind="vuln")
        try:
            if base_session and Path(base_session).exists():
                safe_copyfile(base_session, str(fork_session))
        except OSError:
            pass
        node_id = self.graph_node_id(func)
        session_relpath = self.record_graph_session(
            session_path=fork_session,
            node_id=node_id,
            session_role="worker",
            session_kind="vuln",
            status="running",
        )
        taints = store.list_taints_in_function(func.func_id)
        props = store.list_propagations_from(func.func_id)
        dataflow_text = self._format_taint_context(func, taint_params, ctx, taints, props, store)
        prompt = (
            f"# 阶段：漏洞挖掘 Fork\n\n以上是整条调用链的污点分析历史 (从根函数到本函数)。\n"
            f"现在请基于全链上下文, 判断**本函数** `{func.file}::{func.name}` 内是否存在漏洞。\n"
            f"目标函数: `{func.file}::{func.name}` (行 {func.start_line}-{func.end_line})\n"
            f"源码绝对根目录: `{self.source_root}`。`{func.file}` 是相对该根目录的源码路径；如果需要使用 read/find 读取源码，请基于这个绝对根目录定位文件，不要基于当前工作目录拼接路径。\n"
            f"污点: 位置 {taint_params.positions} 签名 {taint_params.signature} 名字 {taint_params.names}\n\n"
            "## 本函数污点分析摘要\n"
            f"```markdown\n{dataflow_text[:30000]}\n```\n\n"
            "结合链上 callee 的行为 (如返回借用指针/分配/不释放等), 判断本函数是否存在漏洞。输出 JSON: {\"findings\":[]}。"
        )
        miner_system = (_build_v2_system_prompt(custom="vuln-mining")
                         + "\n\n# 内嵌技能：mine-dataflow-vulnerability\n"
                           "禁止再读取 skills/mine-dataflow-vulnerability/SKILL.md。\n\n"
                         f"{_EMBEDDED_VULN_MINING_SKILL}\n\n{self._vuln_miner_prompt}")
        v2_env = {"DVS_V2_DB_DIR": str(self.vuln_root.parent / "dataflow-v2"),
                  "DVS_SOURCE_ROOT": self.source_root,
                  "DVS_TASK_ID": self.task_id,
                  "DVS_PROJECT_ID": getattr(self.cfg, "project_id", "") or "",
                  "DVS_MYSQL_URL": "mysql+pymysql://root:Huawei12%23$@secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local:3306"}
        logger.info("[V2-mine] CALLING run_agent (session=%s thinking=%s)",
                    str(fork_session)[-60:], getattr(self.cfg, "vuln_mining_thinking_level", "high"))
        output = run_agent(
            prompt=prompt, model=acfg.model, tools=acfg.tools or self.cfg.workers.default_tools,
            cwd=str(self.vuln_root.parent), session_file=str(fork_session),
            system_prompt=miner_system, cancel_event=self.cancel_event,
            env=v2_env,
            thinking_level=getattr(self.cfg, "vuln_mining_thinking_level", "high"),
            run_timeout_seconds=self.cfg.agent_run_timeout_seconds,
            timeout_retry_enabled=self.cfg.agent_timeout_retry_enabled,
            timeout_max_retries=self.cfg.agent_timeout_max_retries,
            pi_max_retries=self.cfg.pi_max_retries, pi_retry_delay=self.cfg.pi_retry_delay,
            task_context={"task_id": self.task_id, "task_root": str(self.run_dir.parent),
                          "task_run_root": str(self.run_dir), "task_pi_dir": self.cfg.role_pi_dir("workers"),
                          "agent_role": "workers", "fork_purpose": "vuln_mining"},
        )
        logger.info("[V2-mine] DONE func=%s::%s duration=%.1fs error=%s output_len=%d",
                    func.file, func.name, time.time() - _t0, (output.error or "")[:100], len(output.output or ""))
        if self.on_event:
            emit_agent_runtime_events(self.on_event, result=output, stage="vuln_mining_v2",
                                      role="workers", model=acfg.model, extra={"function": func.name})
        from ..parsers import _extract_json_object as _ej
        parsed = _ej(output.output, "findings") or {"findings": []}
        node = f"{func.file}::{func.name}"
        persisted_count = 0
        for idx, item in enumerate(parsed.get("findings") or []):
            if not isinstance(item, dict):
                continue
            fid = persist_finding(
                graph_store=self.graph_store, run_id=self.run_id, task_id=self.task_id,
                source_root=self.source_root, vuln_root=self.vuln_root,
                func_file=func.file, func_name=func.name, func_description=func.description or "",
                item=item, context_text=dataflow_text, context_session_path=str(fork_session),
                cfg_project_id=self.cfg.project_id, cfg_task_name=self.cfg.task_name,
                cfg_parent_task_name=self.cfg.parent_task_name,
                cfg_parent_task_id=self.cfg.parent_task_id,
                cfg_parent_task_type=self.cfg.parent_task_type,
                cfg_task_origin_type=self.cfg.task_origin_type, on_event=self.on_event)
            if fid:
                persisted_count += 1
        # 实时同步任务快照计数: authoritative source = vuln-scan.sqlite
        if self._graph_store_ready():
            try:
                refresh_task_vuln_snapshot_by_task_id(self.task_id, prefer_live=True)
            except Exception:
                pass
            authoritative_count = persisted_count
            try:
                with self.graph_store.connect() as conn:
                    row = conn.execute(
                        "SELECT COUNT(*) FROM vulnerability_findings WHERE node_id=?",
                        (node,),
                    ).fetchone()
                authoritative_count = int(row[0] or 0) if row else 0
            except Exception:
                authoritative_count = persisted_count
            self.graph_store.update_task_graph_node(
                node_id,
                findings_count=authoritative_count,
                primary_session_relpath=session_relpath,
            )
        session_status = "cancelled" if self._cancel_requested() else "done"
        if self._graph_store_ready():
            self.graph_store.update_task_graph_session(
                session_relpath,
                node_id=node_id,
                status=session_status,
                ended_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            )
        return persisted_count

    def _report_finding_to_intake(self, finding_id: str, rec: VulnFindingRecord,
                                  fdir: Path) -> None:
        """上报 finding 到 vuln-platform intake, 失败不影响任务。

        退避策略: 先用 parent_task_id (编排器任务) 上报; 若被 vuln-platform 以
        task_id 不存在拒绝 (父任务已删/不可挂载), 退避用 DVS 自身 task_id 重试;
        自身仍失败才记为真正失败。全程永不 raise, mine_vulns 不受影响。
        """
        # attempt 1: 父任务 (编排器) task_id
        res = self._do_intake(finding_id, rec, fdir, use_self=False)
        if str(res.get("status") or "") == "reported":
            self._record_intake_result(finding_id, rec, res)
            return
        # 退避: 父任务被 task_id 校验拒绝 → 用自身 task_id 重试
        if self._is_task_id_rejection(res):
            logger.warning("v2 intake parent task rejected for %s, retry with self task_id: %s",
                           finding_id, str(res.get("error") or "")[:300])
            self.on_event("vuln_intake_fallback_self", finding_id=finding_id,
                          function=rec.function_name,
                          parent_error=str(res.get("error") or "")[:300])
            res = self._do_intake(finding_id, rec, fdir, use_self=True)
            if str(res.get("status") or "") == "reported":
                self._record_intake_result(finding_id, rec, res)
                return
        # 真正失败 (父+自身都失败, 或非 task_id 类错误不退避)
        self._record_intake_result(finding_id, rec, res)

    def _do_intake(self, finding_id: str, rec: VulnFindingRecord,
                   fdir: Path, *, use_self: bool) -> dict:
        """单次 intake 调用 (永不 raise, 异常转成 failed dict)。"""
        try:
            return report_finding_to_intake(
                project_id=self.cfg.project_id, task_id=self.task_id,
                task_name=self.cfg.task_name, parent_task_name=self.cfg.parent_task_name,
                parent_task_id=self.cfg.parent_task_id,
                parent_task_type=self.cfg.parent_task_type,
                task_origin_type=self.cfg.task_origin_type,
                finding=rec,
                source_root=self.source_root,
                report_path=str(fdir / "vulnerability-report.md"),
                taint_path_report_path=str(fdir / "taint-path-report.md"),
                use_self_task_id=use_self)
        except Exception as exc:  # 双保险: report_finding_to_intake 不应 raise, 但防意外
            logger.warning("v2 intake report failed for %s: %s", finding_id, exc, exc_info=True)
            return {"status": "failed", "error": str(exc)}

    @staticmethod
    def _is_task_id_rejection(res: dict) -> bool:
        """是否 vuln-platform 因 task_id 不存在而拒绝 (可退避用自身 task_id 重试)。"""
        if str(res.get("status") or "") != "failed":
            return False
        err = str(res.get("error") or "")
        low = err.lower()
        return ("不存在" in err) or ("does not exist" in low) \
            or ("not exist" in low) or ("not found" in low and "task" in low)

    def _record_intake_result(self, finding_id: str, rec: VulnFindingRecord,
                              res: dict) -> None:
        """回写 report_status/case_id + 发事件 + 记日志。"""
        status = str(res.get("status") or "")
        case_id = str(res.get("case_id") or res.get("report_id") or "")
        if self._graph_store_ready():
            try:
                self.graph_store.update_finding_report_status(
                    finding_id,
                    status=status,
                    case_id=case_id,
                    task_id=str(self.task_id or ""),
                )
            except Exception:
                logger.debug("v2 update_finding_report_status failed for %s", finding_id, exc_info=True)
        if status == "reported":
            logger.info("v2 intake reported finding %s (case_id=%s)", finding_id, case_id)
            self.on_event("vuln_intake_reported", finding_id=finding_id,
                          function=rec.function_name, case_id=case_id,
                          duplicate=bool(res.get("duplicate")))
        else:
            err = str(res.get("error") or status or "")
            logger.warning("v2 intake report failed for %s: status=%s error=%s url=%s",
                           finding_id, status, err, res.get("url", ""))
            self.on_event("vuln_intake_report_failed", finding_id=finding_id,
                          function=rec.function_name, status=status, error=err)

    def _format_taint_context(self, func: FunctionRecord, tp: TaintParamInfo,
                              ctx: PathContext, taints: list[TaintRecord],
                              props: list[PropagationRecord],
                              store: DataflowStore | None = None) -> str:
        from .function_extractor import read_function_body
        pre_val = "\n".join(f"- {v.left} {v.op} {v.right} (行 {v.line})" for v in ctx.pre_validations if v.left and v.op) or "(无)"
        func_body = read_function_body(self.source_root, func, max_lines=500)
        lines = [f"## 函数: {func.file}::{func.name} (行 {func.start_line}-{func.end_line})",
                 f"功能: {func.description or '(待分析)'}",
                 f"入口污点: 位置 {tp.positions} 签名 {tp.signature} 名字 {tp.names}",
                 f"前置校验链:\n{pre_val}", "",
                 "## 函数体源码:",
                 f"```c\n{func_body}\n```", "",
                 "## 污点变量:"]
        for t in taints:
            lines.append(f"- {t.name} ({t.signature}): {t.description}")
        lines.append("\n## 传播路径:")
        for p in props:
            tgt = p.target_function or "(外部变量)" if p.is_external else p.target_function
            lines.append(f"- {p.source_taint_name} → {tgt}({p.target_taint_name}) @L{p.call_line} "
                         f"[{p.condition}] {p.description}")
        # callee 分析结果 (后序 mining 时, callee 已完成分析)
        if store is not None:
            for p in props:
                if not p.target_function or not p.target_func_id:
                    continue
                callee_taints = store.list_taints_in_function(p.target_func_id)
                callee_props = store.list_propagations_from(p.target_func_id)
                if callee_taints or callee_props:
                    lines.append(f"\n## callee {p.target_function} 的分析结果:")
                    for ct in callee_taints:
                        lines.append(f"  污点: {ct.name} - {ct.description}")
                    for cp in callee_props:
                        target = cp.target_function or "(sink/系统调用)"
                        lines.append(f"  传播: {cp.source_taint_name} → {target}({cp.target_taint_name})")
                        lines.append(f"    {cp.description}")
        return "\n".join(lines)
