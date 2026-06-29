"""Single-worker dataflow taint tracking + vulnerability mining workflow."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from sqlalchemy import func

from .copy_utils import safe_copy2, safe_copyfile
from .agent_runtime_events import emit_agent_runtime_events
from .config import load_system_prompts, resolve_system_prompt
from .models import AgentInstanceConfig, RoundResult, SwarmEvent, TaskConfig, TaskResult, TaskStatus, TokenUsage, WorkerResult
from .runner import run_agent
from .taint_workflow import _extract_function_body, _prepend_upstream_hint_section, _build_upstream_entry_metadata, _build_taint_hint_summary
from .vuln_graph_validator import normalize_taint_graph, validate_taint_graph
from .validation_state import normalize_validation_state
from .vuln_store import FollowupRecord, TaintEdgeRecord, TaintSourceRecord, VulnFindingRecord, VulnScanStore

logger = logging.getLogger("dvs.vuln_workflow")


@dataclass
class TaintInput:
    symbol: str
    kind: str = "param"
    line: str = ""
    call_expr: str = ""
    description: str = ""


_CONTEXT_TAINT_EXCLUDES = {
    "a1",
    "a3",
    "context",
    "ctx",
    "runtime",
    "params",
    "param",
    "state",
}


def _is_likely_external_taint_symbol(symbol: str) -> bool:
    normalized = str(symbol or "").strip()
    if not normalized:
        return False
    if normalized in _CONTEXT_TAINT_EXCLUDES:
        return False
    if normalized.startswith("&"):
        return False
    if normalized.startswith("v") and normalized[1:].isdigit():
        return False
    return True


def _safe_name(value: str, *, max_len: int = 96) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-") or "item"
    if len(safe) <= max_len:
        return safe
    return f"{safe[:max_len - 9]}-{hashlib.sha1(value.encode()).hexdigest()[:8]}"


def _node_id(source_file: str, function_name: str, symbol: str, depth: int) -> str:
    raw = f"{source_file}::{function_name}::{symbol}::{depth}"
    return "node_" + hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def _edge_id(run_id: str, function_name: str, src: str, dst: str, line: str) -> str:
    raw = f"{run_id}::{function_name}::{src}->{dst}@{line}::{uuid.uuid4().hex[:6]}"
    return "edge_" + hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:18]


def parse_taint_inputs(cfg: TaskConfig, fallback: Iterable[str] | None = None) -> list[TaintInput]:
    items: list[TaintInput] = []
    for detail in cfg.taint_details or []:
        if not isinstance(detail, dict):
            continue
        symbol = str(detail.get("name") or detail.get("taint") or detail.get("param") or detail.get("symbol") or "").strip()
        if not symbol:
            continue
        if not _is_likely_external_taint_symbol(symbol):
            continue
        items.append(TaintInput(
            symbol=symbol,
            kind=str(detail.get("source_kind") or detail.get("kind") or "param").strip() or "param",
            line=str(detail.get("line") or detail.get("line_hint") or "").strip(),
            call_expr=str(detail.get("call_expr") or detail.get("call") or "").strip(),
            description=str(detail.get("description") or detail.get("reason") or "").strip(),
        ))
    for param in cfg.taint_params or []:
        symbol = str(param).strip()
        if symbol and _is_likely_external_taint_symbol(symbol) and all(x.symbol != symbol for x in items):
            items.append(TaintInput(symbol=symbol, kind="param"))
    for param in fallback or []:
        symbol = str(param).strip()
        if symbol and _is_likely_external_taint_symbol(symbol) and all(x.symbol != symbol for x in items):
            items.append(TaintInput(symbol=symbol, kind="param"))
    return items or [TaintInput(symbol="all", kind="unknown")]


def _format_exploitability_md(value: Any) -> str:
    """Render the exploitability field as Markdown.

    Accepts either a structured object ({preconditions, trigger_complexity,
    worst_case_impact}) — as produced by the four-dimension vuln-miners prompt —
    or a legacy free-text string.
    """
    if not value:
        return "未知"
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        pre = str(value.get("preconditions") or value.get("precondition") or "").strip()
        tc = str(value.get("trigger_complexity") or "").strip()
        wci = str(value.get("worst_case_impact") or value.get("impact") or "").strip()
        parts: list[str] = []
        if pre:
            parts.append(f"- **前置条件**: {pre}")
        if tc:
            parts.append(f"- **触发难度**: {tc}")
        if wci:
            parts.append(f"- **最坏后果**: {wci}")
        return "\n".join(parts) if parts else json.dumps(value, ensure_ascii=False, indent=2)
    return json.dumps(value, ensure_ascii=False, indent=2)


_DIM_LABEL = {
    "code_accurate": "代码准确性",
    "path_reachable": "路径可达性",
    "unmitigated": "防御可绕过",
    "security_impact": "实质安全影响",
}


def _format_dimensions_md(value: Any) -> str:
    """Render the four-dimension self-check (code_accurate/path_reachable/
    unmitigated/security_impact) as Markdown. Returns "" when absent
    (legacy findings / miner did not emit it)."""
    if not isinstance(value, dict) or not value:
        return ""
    lines: list[str] = ["## 四维度自检", ""]
    rows = []
    for key, label in _DIM_LABEL.items():
        entry = value.get(key)
        if isinstance(entry, dict):
            passed = entry.get("passed")
            if passed is True:
                status = "PASS"
            elif passed is False:
                status = "FAIL"
            else:
                status = "N/A"
            reason = str(entry.get("reason") or entry.get("detail") or "").strip()
        else:
            status = "➖ 未判定"
            reason = str(entry or "").strip()
        rows.append(f"| {label} | {status} | {reason} |")
    if rows:
        lines.append("| 维度 | 结论 | 理由 |")
        lines.append("|------|------|------|")
        lines.extend(rows)
        lines.append("")
        return "\n".join(lines)
    return ""


def _format_vuln_report_md(item: dict, finding_id: str, source_file: str, function_name: str, line: str) -> str:
    """Build the vulnerability-report.md body with 9 standardized sections.

    Sections (in order):
      1. 漏洞最初入口    — entry_point
      2. 漏洞所在文件    — source_file
      3. 漏洞所在函数    — function_name
      4. 漏洞所在行号    — line
      5. 漏洞概述        — summary
      6. 漏洞判断依据    — evidence (renamed from 漏洞证据)
      7. 漏洞触发路径    — trigger_path
      8. 漏洞危害        — exploitability
      9. 四维度判断指标  — dimensions
    """
    title = str(item.get("title") or finding_id)
    summary = str(item.get("summary") or "")
    entry_point = str(item.get("entry_point") or "")
    trigger_path = str(item.get("trigger_path") or "")
    evidence = str(item.get("evidence") or "")
    vuln_type = str(item.get("vuln_type") or "unknown")
    severity = str(item.get("severity") or "unknown")
    confidence = item.get("confidence")
    sections = [
        f"# {title}",
        "",
        "## 漏洞最初入口",
        entry_point or "（未提供）",
        "",
        "## 漏洞所在文件",
        f"`{source_file}`",
        "",
        "## 漏洞所在函数",
        f"`{function_name}`",
        "",
        "## 漏洞所在行号",
        f"`{line or 'unknown'}`",
        "",
        "## 漏洞概述",
        summary,
        "",
        "## 漏洞判断依据",
        evidence,
        "",
        "## 漏洞触发路径",
        trigger_path or "（未提供）",
        "",
        "## 漏洞危害",
        _format_exploitability_md(item.get("exploitability")),
        "",
        "## 漏洞基本信息",
        f"- **漏洞类型**: `{vuln_type}`",
        f"- **严重程度**: `{severity}`",
        f"- **置信度**: `{confidence}`",
    ]
    dim_md = _format_dimensions_md(item.get("dimensions"))
    if dim_md:
        sections.append("")
        sections.append("## 四维度判断指标")
        dim_body = dim_md.replace("## 四维度自检", "", 1).strip()
        sections.append(dim_body)
    return "\n".join(sections) + "\n"


def _vuln_intake_min_confidence() -> float:
    """Minimum confidence for a finding to be submitted to vuln-platform intake.

    Findings below this threshold are still archived locally (SQLite + report.md)
    for observability and tuning, but are not pushed downstream — this is the
    primary lever for reducing false-positive leakage into verification.
    """
    raw = os.environ.get("DVS_VULN_INTAKE_MIN_CONFIDENCE", "0.5").strip()
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = 0.5
    return max(0.0, min(1.0, value))


def _check_finding_dimensions(dims: dict) -> bool:
    """Validate the four-dimension self-check emitted by the vuln-miners prompt.

    Returns True only when all four dimensions are present and explicitly
    passed. Findings missing the self-check (legacy/partial output) are
    treated as eligible by default to avoid silently dropping everything —
    the confidence gate is the hard filter in that case.
    """
    if not isinstance(dims, dict) or not dims:
        return True
    required = ("code_accurate", "path_reachable", "unmitigated", "security_impact")
    present = {k: v for k, v in dims.items() if k in required}
    if not present:
        return True
    for key in required:
        entry = present.get(key)
        if isinstance(entry, dict):
            if entry.get("passed") is False:
                return False
        # Missing or non-dict entries do not by themselves disqualify; the
        # confidence gate remains in effect.
    return True


def _extract_json_from_text(text: str, key: str | None = None) -> Any:
    candidates: list[str] = []
    for m in re.finditer(r"```(?:json)?\s*\n(.*?)\n\s*```", text, re.S):
        candidates.append(m.group(1))
    candidates.append(text)
    for raw in candidates:
        raw = raw.strip()
        for start_char, end_char in [("{", "}"), ("[", "]")]:
            start = raw.find(start_char)
            end = raw.rfind(end_char)
            if start >= 0 and end > start:
                try:
                    obj = json.loads(raw[start:end+1])
                    if key is None or (isinstance(obj, dict) and key in obj):
                        return obj
                except Exception as _e:
                    logger.warning("unexpected error in vuln_workflow.py: %s", _e, exc_info=True)
    return None


def _read_prompt(path: str) -> str:
    try:
        return (Path(__file__).resolve().parents[1] / path).read_text(encoding="utf-8")
    except OSError:
        return ""


_EMBEDDED_TAINT_GRAPH_SKILL = _read_prompt("skills/write-taint-graph/SKILL.md")
_EMBEDDED_VULN_MINING_SKILL = _read_prompt("skills/mine-dataflow-vulnerability/SKILL.md")


class DataflowVulnWorkflow:
    def __init__(
        self,
        *,
        cfg: TaskConfig,
        func_name: str,
        src_file: str,
        line_hint: str,
        taint_params: list[str],
        taint_ctx: str,
        task_id: str,
        out_dir: Path,
        dep: int,
        max_depth: int,
        graph_db_path: Path | None = None,
        vuln_output_root: Path | None = None,
        on_event: Callable[[SwarmEvent], None] | None = None,
        cancel_event: threading.Event | None = None,
        # session 继承相关参数
        parent_session_file: str | None = None,       # 父函数完成后的 worker session（fork 源）
        sessions_archive_dir: Path | None = None,     # 全局归档目录 run/sessions/
        session_label: str = "",                     # 该函数的 session 文件前缀
    ):
        self.cfg = cfg
        self.func_name = func_name
        self.src_file = src_file
        self.line_hint = line_hint
        self.taint_inputs = parse_taint_inputs(cfg, taint_params)
        self.taint_params = [x.symbol for x in self.taint_inputs]
        self.taint_ctx = taint_ctx
        self.task_id = task_id
        self.out_dir = Path(out_dir)
        self.dep = dep
        self.max_depth = max_depth
        self.on_event = on_event or (lambda e: None)
        self.cancel_event = cancel_event
        self.parent_session_file = parent_session_file
        self.sessions_archive_dir = Path(sessions_archive_dir) if sessions_archive_dir else None
        self.session_label = session_label or _safe_name(func_name)
        self.run_id = f"{task_id}:{hashlib.sha1((src_file+'::'+func_name).encode()).hexdigest()[:12]}"
        self.project_id = str(getattr(cfg, "project_id", "") or "").strip()
        self.task_name = str(getattr(cfg, "task_name", "") or "").strip()
        self.parent_task_name = str(getattr(cfg, "parent_task_name", "") or "").strip()
        self.parent_task_id = str(getattr(cfg, "parent_task_id", "") or "").strip()
        self.store = VulnScanStore(graph_db_path or (self.out_dir / "vuln-scan.sqlite"))
        self.vuln_root = Path(vuln_output_root) if vuln_output_root is not None else (self.out_dir.parent / "output" / "vulnerabilities")
        self.vuln_root.mkdir(parents=True, exist_ok=True)
        self.ws = self.out_dir / "workspace-worker-0"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.sessions = self.out_dir / "sessions"

    def _emit(self, etype: str, **data: Any) -> None:
        try:
            self.on_event(SwarmEvent(type=etype, task_id=self.task_id, data=data))
        except Exception as _e:
            logger.warning("unexpected error in vuln_workflow.py: %s", _e, exc_info=True)

    def _cancelled(self) -> bool:
        return bool(self.cancel_event and self.cancel_event.is_set())

    def _agent_cfg(self) -> AgentInstanceConfig:
        return self.cfg.workers.agents[0]

    def _seed_nodes(self) -> list[str]:
        node_ids: list[str] = []
        for item in self.taint_inputs:
            nid = _node_id(self.src_file, self.func_name, item.symbol, self.dep)
            node_ids.append(nid)
            self.store.upsert_taint_node(TaintSourceRecord(
                node_id=nid, source_file=self.src_file, function_name=self.func_name,
                taint_kind=item.kind, symbol=item.symbol, line=item.line,
                call_expr=item.call_expr, description=item.description, depth=self.dep,
            ))
        return node_ids

    def _write_design_doc(self) -> None:
        doc = self.out_dir / "vuln-scan-architecture.md"
        if not doc.exists():
            doc.write_text(_read_prompt("docs/architecture-vuln-scan.md") or "# 数据流漏洞挖掘架构\n", encoding="utf-8")

    def _link_source_tree(self) -> None:
        target_dir = Path(self.cfg.cwd).resolve()
        if not target_dir.is_dir():
            return
        # 不能把源码目录整体 symlink 到 workspace：历史任务曾把 dataflow/taint 产物写入源码根，
        # 整目录 symlink 会让模型在 src/... 下写文件时直接污染源码目录。这里改为镜像目录结构，
        # 仅把真实源码文件逐个 symlink 进 workspace；新产物只能落在 workspace 自身。
        artifact_names = {"tainted.list", "taintvars.json", "taint-graph.json", "vuln-scan.sqlite", "artifact-manifest.json"}
        artifact_prefixes = ("dataflow-", "taint-flow-")
        # 只跳过 target_dir 根层级下的产物目录，避免误伤源码树中同名的子目录
        # （例如逆向还原的源码常有 2/output/librmonlib-ppc_rtos.c 这样的路径）
        skip_top_dirs = {".git", ".svn", ".hg", "run", "output", "sessions",
                         "workspace-worker-0", "workspace-worker-1", "__pycache__"}
        def _skip(path: Path) -> bool:
            parts = path.relative_to(target_dir).parts
            if parts and parts[:-1]:
                top = parts[0]
                if top in skip_top_dirs or top.startswith("workspace-worker-"):
                    return True
            name = path.name
            return name in artifact_names or any(name.startswith(prefix) for prefix in artifact_prefixes) or name.endswith((".jsonl", ".lock", ".backup"))
        for src in target_dir.rglob("*"):
            try:
                rel = src.relative_to(target_dir)
            except ValueError:
                continue
            if _skip(src):
                continue
            dst = self.ws / rel
            if src.is_dir():
                dst.mkdir(parents=True, exist_ok=True)
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists() or dst.is_symlink():
                continue
            try:
                safe_copy2(src, dst)
            except OSError:
                pass

    def _build_single_worker_prompt(self, func_body: str) -> str:
        taints = [t.__dict__ for t in self.taint_inputs]
        upstream = f"\n\n# 调用者传入的脏数据\n{self.taint_ctx}" if self.taint_ctx else ""
        return (
            "# 数据流污点跟踪 + 漏洞挖掘\n\n"
            f"目标函数: `{self.src_file}::{self.func_name}`\n"
            f"当前深度: {self.dep}/{self.max_depth}\n"
            f"污点输入(JSON，仅作为本次输入描述，不需要写入输出目录):\n```json\n{json.dumps(taints, ensure_ascii=False, indent=2)}\n```\n"
            f"{upstream}\n\n"
            "## 函数源码（带绝对行号）\n```cpp\n"
            f"{func_body}\n```\n\n"
            "请一个 Worker 在当前函数内同时分析所有污点，不要按污点拆分 worker。\n"
            "不要写任何中间产物文件；禁止创建 `taint-graph.json`、`tainted.list`、`taintvars.json`、`dataflow-*.md` 或 `taint-flow-*.md`。\n"
            "请在最终回复中直接输出一个 JSON 对象，包含 function/source_file/taints/edges/followups/termination。\n"
            "**所有文本字段必须使用简体中文**：description、reason、evidence、sanitizer_effect（值为中文如 `完整清洗`/`部分清洗`/`未清洗`/`未知`）、termination_reason 等全部用中文书写。\n"
            "JSON key 保持英文，`taints[].kind` 等枚举值保持英文。\n"
            "`followups` 是唯一跟入点输出，每个元素必须包含 file/function/line/tainted_params/reason/dispatch_kind/tainted_nonlocal/validations；服务端会直接写入 SQLite。\n"
            "`dispatch_kind` 用于说明调用机制：direct_call/function_pointer/vtable_dispatch/hook_callback/macro/inline/unknown。\n"
            "如果污点写入全局变量、静态变量或类成员变量，必须在相关 followup 的 `tainted_nonlocal` 中记录 symbol/kind/evidence，供后续 tracker 追踪使用点。\n"
            "每条 edge 都必须有 line/evidence/sanitizer_effect；终止边必须有 termination_reason。\n"
            "同时在报告中判断当前函数内是否存在漏洞候选，漏洞判断会由后续 fork 上下文复核。\n"
        )

    def _run_single_worker(self) -> tuple[TaskResult, str, str]:
        self._link_source_tree()
        func_body = _extract_function_body(
            self.ws,
            self.src_file,
            self.func_name,
            self.line_hint,
            funcdb_path=getattr(self.cfg, "funcdb_path", ""),
            func_hash=getattr(self.cfg, "func_hash", ""),
        )
        if not func_body.strip():
            return self._make_result("# 数据流漏洞挖掘受限\n\n未提取到有效函数体。\n", None, False, "function_body_missing"), "", ""
        acfg = self._agent_cfg()
        worker_prompts = load_system_prompts(self.cfg.workers.system_prompt_dir, 1)
        system_prompt = resolve_system_prompt(0, acfg, worker_prompts)
        graph_prompt = _read_prompt("prompts/taint-graph/default.md")
        follow_prompt = _read_prompt("prompts/followups/default.md") if self.dep > 0 else ""
        embedded_skill = (
            "# 内嵌技能：write-taint-graph\n"
            "以下技能内容已经完整嵌入系统提示词。禁止再通过 read/bash/cat/sed 等方式读取 skills/write-taint-graph/SKILL.md；"
            "也不要调用 /skill 触发二次加载。\n\n"
            f"{_EMBEDDED_TAINT_GRAPH_SKILL}"
        )
        system_prompt = "\n\n".join(x for x in [system_prompt, graph_prompt, follow_prompt, embedded_skill] if x)
        # 优先使用全局归档目录，否则退回本地 sessions/
        if self.sessions_archive_dir:
            self.sessions_archive_dir.mkdir(parents=True, exist_ok=True)
            session_file = str(self.sessions_archive_dir / f"{self.session_label}-worker.jsonl")
        else:
            session_file = str(self.sessions / "worker-0.jsonl")
        # 继承父函数 session（fork：以父函数完整分析记忆作为本轮起点）
        if (
            self.parent_session_file
            and Path(self.parent_session_file).exists()
            and self.parent_session_file != session_file
        ):
            try:
                safe_copyfile(self.parent_session_file, session_file)
                self._emit(
                    "session_forked",
                    parent_session=self.parent_session_file,
                    child_session=session_file,
                    function=self.func_name,
                    depth=self.dep,
                )
            except OSError as _fork_err:
                self._emit(
                    "session_fork_error",
                    error=str(_fork_err),
                    function=self.func_name,
                )
        prompt = self._build_single_worker_prompt(func_body)
        self._emit("worker_start", worker_id="worker-0", model=acfg.model, function=self.func_name, depth=self.dep)
        started = time.time()
        res = run_agent(
            prompt=prompt, model=acfg.model, tools=acfg.tools or self.cfg.workers.default_tools,
            cwd=str(self.ws), session_file=session_file, system_prompt=system_prompt,
            cancel_event=self.cancel_event, run_timeout_seconds=self.cfg.agent_run_timeout_seconds,
            timeout_retry_enabled=self.cfg.agent_timeout_retry_enabled, timeout_max_retries=self.cfg.agent_timeout_max_retries,
            pi_max_retries=self.cfg.pi_max_retries, pi_retry_delay=self.cfg.pi_retry_delay,
            task_context={
                "task_id": self.task_id,
                "task_root": str(self.out_dir.parent),
                "task_run_root": str(self.out_dir),
                "task_pi_dir": self.cfg.role_pi_dir("workers"),
                "agent_role": "workers",
            },
        )
        if getattr(res, "rate_limit_event_due", False):
            self._emit(
                "task_rate_limited_retrying",
                stage="vuln_worker",
                function=self.func_name,
                http_status=429,
                retry_delay_seconds=int(getattr(res, "retry_delay_seconds", 30) or 30),
                consecutive_rate_limit_count=int(getattr(res, "consecutive_rate_limit_count", 0) or 0),
                model=acfg.model,
            )
        if getattr(res, "api_retry_event_due", False):
            self._emit(
                "task_api_retrying",
                stage="vuln_worker",
                function=self.func_name,
                retry_delay_seconds=int(getattr(res, "retry_delay_seconds", 30) or 30),
                consecutive_api_retry_count=int(getattr(res, "consecutive_api_retry_count", 0) or 0),
                reason=str(getattr(res, "api_retry_reason", "") or ""),
                model=acfg.model,
            )
        emit_agent_runtime_events(
            self._emit,
            result=res,
            stage="vuln_worker",
            role="workers",
            model=acfg.model,
            extra={"function": self.func_name, "depth": self.dep},
        )
        self._emit("worker_done", worker_id="worker-0", output=res.output[:300], tokens_in=res.token_usage.input, tokens_out=res.token_usage.output)
        total_tokens = TokenUsage(); total_tokens += res.token_usage

        # ── 输出校验 + 重试：LLM 未输出 JSON 时，一句话 prompt 让 LLM 补充 ──
        graph = _extract_json_from_text(res.output)
        graph_warnings: list[str] = []
        retry_used = 0
        _JSON_RETRY_MAX = 3
        _JSON_RETRY_PROMPT = (
            "[系统反馈] 上一轮回复缺少符合格式的 taint-graph JSON 对象。"
            "请直接输出完整的 JSON，不要 Markdown 包裹，不要额外文字: "
            '{"function":"...","source_file":"...","taints":[...],"edges":[...],"followups":[...],"termination":{...}}'
        )
        while not isinstance(graph, dict) and retry_used < _JSON_RETRY_MAX:
            if self._cancelled():
                break
            retry_used += 1
            self._emit("worker_retry_json", worker_id="worker-0", attempt=retry_used,
                       function=self.func_name, reason="missing taint graph JSON")
            res = run_agent(
                prompt=_JSON_RETRY_PROMPT, model=acfg.model,
                tools=acfg.tools or self.cfg.workers.default_tools,
                cwd=str(self.ws), session_file=session_file, system_prompt=system_prompt,
                cancel_event=self.cancel_event,
                run_timeout_seconds=min(self.cfg.agent_run_timeout_seconds or 300, 120),
                pi_max_retries=1, pi_retry_delay=2,
                max_retries=1, retry_delay=2,
                task_context={"task_id": self.task_id, "task_root": str(self.out_dir.parent),
                              "task_run_root": str(self.out_dir), "task_pi_dir": self.cfg.role_pi_dir("workers"), "agent_role": "workers"},
            )
            if getattr(res, "rate_limit_event_due", False):
                self._emit(
                    "task_rate_limited_retrying",
                    stage="vuln_worker_json_retry",
                    function=self.func_name,
                    http_status=429,
                    retry_delay_seconds=int(getattr(res, "retry_delay_seconds", 30) or 30),
                    consecutive_rate_limit_count=int(getattr(res, "consecutive_rate_limit_count", 0) or 0),
                    model=acfg.model,
                )
            emit_agent_runtime_events(
                self._emit,
                result=res,
                stage="vuln_worker_json_retry",
                role="workers",
                model=acfg.model,
                extra={"function": self.func_name, "attempt": retry_used},
            )
            total_tokens += res.token_usage
            graph = _extract_json_from_text(res.output)

        if isinstance(graph, dict):
            graph = normalize_taint_graph(graph)
            graph_warnings = validate_taint_graph(graph)
        else:
            graph = None
            graph_warnings = [f"missing taint graph JSON in final response (retried {retry_used}x)"]
        dataflow_file = None
        df_content = res.output
        if graph_warnings:
            (self.out_dir / "taint-graph.validation.json").write_text(json.dumps({"warnings": graph_warnings}, ensure_ascii=False, indent=2), encoding="utf-8")
        passed = not graph_warnings
        final_output = res.output
        rr = RoundResult(
            round=1, function_name=self.func_name, source_path=self.src_file, stage="worker", stage_round=1,
            duration_ms=max(0.0, (time.time() - started) * 1000.0), status="passed" if passed else "failed",
            worker_results=[WorkerResult(worker_id="worker-0", model=acfg.model, output=final_output, dataflow_file=str(dataflow_file or ""), session_file=session_file, token_usage=res.token_usage, df_issues=graph_warnings)],
            judge_results=[], pass_count=1 if passed else 0, total_judges=0, passed=passed, best_worker_id="worker-0",
            module_completed=passed, completion_reason="script_validated" if passed else "script_validation_failed",
        )
        result = self._make_result(final_output, res, passed, "script_validated" if passed else "script_validation_failed", rounds=[rr], total_tokens=total_tokens)
        if isinstance(graph, dict):
            result.upstream_entry_metadata["taint_graph"] = graph
        return result, str(session_file), df_content or res.output

    def _run_vuln_mining_fork(self, base_session: str, dataflow_text: str) -> list[VulnFindingRecord]:
        if self._cancelled() or not self.cfg.workers.agents:
            return []
        acfg = self._agent_cfg()
        # 漏洞挖掘 fork session：归档到 run/sessions/，读取 worker session 作为起点
        if self.sessions_archive_dir:
            self.sessions_archive_dir.mkdir(parents=True, exist_ok=True)
            fork_session = self.sessions_archive_dir / f"{self.session_label}-vuln-mining.jsonl"
        else:
            fork_session = self.sessions / f"vuln-mining-{_safe_name(self.func_name)}.jsonl"
        try:
            if base_session and Path(base_session).exists():
                safe_copyfile(base_session, fork_session)
        except OSError:
            pass
        fork_id = "fork_" + hashlib.sha1((self.run_id + str(fork_session) + "vuln").encode()).hexdigest()[:16]
        node = _node_id(self.src_file, self.func_name, self.taint_params[0] if self.taint_params else "all", self.dep)
        self.store.add_context_fork(fork_id=fork_id, run_id=self.run_id, purpose="vulnerability_mining", session_file=str(fork_session), node_id=node, status="running")
        prompt = (
            f"# 阶段：漏洞挖掘 Fork\n\n目标函数: `{self.src_file}::{self.func_name}`\n污点: {', '.join(self.taint_params)}\n\n"
            "基于下面的单函数污点传播结果，判断是否存在漏洞。必须输出 JSON: {\"findings\":[]}。\n"
            "每个 finding 必须包含以下字段：\n"
            "- `source_file`：漏洞所在文件（相对源码根目录优先）\n"
            "- `function_name`：漏洞所在函数名\n"
            "- `line`：漏洞发生行号，如 L123 或 123\n"
            "- `entry_point`：漏洞最初入口，描述污点最初从哪个外部入口进入系统、经过的关键中间节点\n"
            "- `trigger_path`：漏洞触发路径，分步骤描述从入口到漏洞点的完整调用链（如 步骤1: xxx → 步骤2: xxx → 步骤3: 触发漏洞）\n"
            "- `summary`：漏洞概述（源→sink路径、缺失的防御、为何可绕过、实质后果）\n"
            "- `evidence`：漏洞判断依据（带行号的代码证据，逐行引用证明漏洞存在的关键语句）\n"
            "- `exploitability`：{preconditions, trigger_complexity, worst_case_impact}\n"
            "- `dimensions`：四维度自检{code_accurate, path_reachable, unmitigated, security_impact}\n\n"
            "**所有文本输出必须使用简体中文**。JSON key 保持英文，`title`/`summary`/`evidence`/`entry_point`/`trigger_path`/`exploitability`/`dimensions.reason` 等文本字段的 value 全部用中文书写。\n"
            "`severity` 和 `vuln_type` 使用英文归一化值（如 `heap-buffer-overflow`、`critical`），不做翻译。\n\n"
            f"```markdown\n{dataflow_text[:30000]}\n```"
        )
        miner_system_prompt = (
            "# 内嵌技能：mine-dataflow-vulnerability\n"
            "以下技能内容已经完整嵌入系统提示词。禁止再通过 read/bash/cat/sed 等方式读取 skills/mine-dataflow-vulnerability/SKILL.md；"
            "漏洞报告由服务端写入 output/vulnerabilities 目录；不要自行创建 run/output 或其它 output 目录。\n\n"
            f"{_EMBEDDED_VULN_MINING_SKILL}\n\n"
            f"{_read_prompt('prompts/vuln-miners/default.md')}"
        )
        output = run_agent(
            prompt=prompt, model=acfg.model, tools=acfg.tools or self.cfg.workers.default_tools,
            cwd=str(self.vuln_root.parent), session_file=str(fork_session), system_prompt=miner_system_prompt,
            cancel_event=self.cancel_event, run_timeout_seconds=self.cfg.agent_run_timeout_seconds,
            timeout_retry_enabled=self.cfg.agent_timeout_retry_enabled, timeout_max_retries=self.cfg.agent_timeout_max_retries,
            pi_max_retries=self.cfg.pi_max_retries, pi_retry_delay=self.cfg.pi_retry_delay,
            task_context={
                "task_id": self.task_id,
                "task_root": str(self.out_dir.parent),
                "task_run_root": str(self.out_dir),
                "task_pi_dir": self.cfg.role_pi_dir("workers"),
                "agent_role": "workers",
            },
        )
        emit_agent_runtime_events(
            self._emit,
            result=output,
            stage="vulnerability_mining",
            role="workers",
            model=acfg.model,
            extra={"function": self.func_name, "fork_purpose": "vulnerability_mining"},
        )
        parsed = _extract_json_from_text(output.output, "findings") or {"findings": []}
        self.store.add_context_fork(fork_id=fork_id, run_id=self.run_id, purpose="vulnerability_mining", session_file=str(fork_session), node_id=node, status="completed" if not output.error else "error")
        findings: list[VulnFindingRecord] = []
        for idx, item in enumerate(parsed.get("findings") or []):
            if not isinstance(item, dict):
                continue
            finding_id = f"vuln_{hashlib.sha1((self.run_id+str(idx)+json.dumps(item, ensure_ascii=False)).encode()).hexdigest()[:16]}"
            fdir = self.vuln_root / finding_id; fdir.mkdir(parents=True, exist_ok=True)
            report_path = fdir / "vulnerability-report.md"
            taint_report_path = fdir / "taint-path-report.md"
            finding_source_file = str(item.get('source_file') or item.get('file') or self.src_file)
            finding_function_name = str(item.get('function_name') or item.get('function') or item.get('func') or self.func_name)
            finding_line = str(item.get('line') or item.get('line_hint') or item.get('vuln_line') or '')
            report_path.write_text(_format_vuln_report_md(item, finding_id, finding_source_file, finding_function_name, finding_line), encoding="utf-8")
            taint_report_path.write_text(dataflow_text, encoding="utf-8")
            try:
                if fork_session.exists():
                    safe_copyfile(fork_session, fdir / "context.jsonl")
            except OSError:
                (fdir / "context.jsonl").write_text("", encoding="utf-8")
            _exploit_raw = item.get("exploitability")
            if isinstance(_exploit_raw, (dict, list)):
                exploitability_str = json.dumps(_exploit_raw, ensure_ascii=False)
            else:
                exploitability_str = str(_exploit_raw or "")
            rec = VulnFindingRecord(finding_id=finding_id, run_id=self.run_id, node_id=node, source_file=finding_source_file, function_name=finding_function_name, line=finding_line, vuln_type=str(item.get("vuln_type") or "unknown"), severity=str(item.get("severity") or "unknown"), title=str(item.get("title") or finding_id), summary=str(item.get("summary") or ""), evidence=str(item.get("evidence") or ""), exploitability=exploitability_str, confidence=float(item.get("confidence") or 0), output_dir=str(fdir))
            self.store.add_finding(rec); findings.append(rec)
            # 四维度自检 + 置信度过滤：仅通过自检且达到阈值的 finding 才提交到
            # vuln-platform intake，低置信度/未通过自检的仅本地归档，避免误报外泄。
            _dims = item.get("dimensions") if isinstance(item.get("dimensions"), dict) else {}
            _dim_pass = _check_finding_dimensions(_dims)
            _min_conf = _vuln_intake_min_confidence()
            _submit_eligible = _dim_pass and rec.confidence >= _min_conf
            _verifier_failed = False
            # ── debug: 服务端结构化核验门 (DVS_VULN_VERIFIER_ENABLED, 默认 OFF) ──
            # OFF 时完全不执行, intake 行为与主线一致; ON 时对每条 finding 做行存在/
            # 调用点存在/callee 行为一致性/调用链可达/session 读取审计五项核验, 任一
            # fail 则不提交 intake (本地仍归档), emit vuln_verification_skipped。
            if _submit_eligible:
                try:
                    from .vuln_verifier import is_enabled as _verifier_enabled, verify_finding as _verify_finding
                except Exception:
                    _verifier_enabled = lambda: False
                if _verifier_enabled():
                    try:
                        _vr = _verify_finding(
                            rec, item,
                            str(self.cfg.cwd or ""),
                            str(self.ws / "clang-cache"),
                            str(fork_session),
                        )
                        (fdir / "verification.json").write_text(
                            json.dumps(_vr, ensure_ascii=False, indent=2), encoding="utf-8")
                        if not _vr.get("passed"):
                            _submit_eligible = False
                            _verifier_failed = True
                            self._emit(
                                "vuln_verification_skipped",
                                finding_id=rec.finding_id,
                                reasons=_vr.get("reasons") or [],
                                checks=_vr.get("checks") or {},
                                source_file=rec.source_file,
                                function_name=rec.function_name,
                                line=rec.line,
                            )
                    except Exception as _ve:
                        logger.warning("vuln_verifier error: %s", _ve, exc_info=True)
            if not _submit_eligible and not _verifier_failed:
                self._emit(
                    "vuln_intake_skipped",
                    finding_id=rec.finding_id,
                    reason="low_confidence_or_self_check_failed",
                    confidence=rec.confidence,
                    min_confidence=_min_conf,
                    dimensions_pass=_dim_pass,
                    source_file=rec.source_file,
                    function_name=rec.function_name,
                    line=rec.line,
                )
            self.store.append_artifact_manifest(
                "vulnerability_mining",
                [
                    {"path": str(report_path), "kind": "markdown", "role": "vulnerability_report", "exists": report_path.exists()},
                    {"path": str(taint_report_path), "kind": "markdown", "role": "taint_path_report", "exists": taint_report_path.exists()},
                    {"path": str(fdir / "context.jsonl"), "kind": "jsonl", "role": "fork_session", "exists": (fdir / "context.jsonl").exists()},
                ],
                function_name=self.func_name,
                source_file=self.src_file,
                task_id=self.task_id,
                run_id=self.run_id,
            )
            try:
                if not _submit_eligible:
                    # 本地已归档但未达到提交阈值，跳过 vuln-platform intake。
                    continue
                from .vuln_intake_reporter import report_finding_to_intake
                report_result = report_finding_to_intake(
                    project_id=self.project_id,
                    task_id=self.task_id,
                    task_name=self.task_name,
                    parent_task_name=self.parent_task_name,
                    parent_task_id=self.parent_task_id,
                    finding=rec,
                    source_root=str(self.cfg.cwd or ""),
                    report_path=str(report_path),
                    taint_path_report_path=str(taint_report_path),
                )
                reported_ok = report_result.get("status") == "reported"
                self._emit(
                    "vuln_intake_reported" if reported_ok else "vuln_intake_report_failed",
                    finding_id=rec.finding_id,
                    report_id=report_result.get("report_id"),
                    case_id=report_result.get("case_id"),
                    status=report_result.get("status"),
                    duplicate=report_result.get("duplicate"),
                    error=report_result.get("error"),
                    source_file=rec.source_file,
                    function_name=rec.function_name,
                    line=rec.line,
                )
                if reported_ok:
                    self.store.update_finding_report_status(
                        rec.finding_id,
                        status="reported",
                        case_id=str(report_result.get("case_id") or ""),
                    )
                # 无论上报成败都同步 MySQL 统计
                try:
                    from app.service.task_service import _sync_task_vuln_stats
                    from app.db.models import AppDvsTask
                    from sqlalchemy import create_engine
                    from sqlalchemy.orm import Session
                    from app.config import get_service_yaml
                    engine = create_engine(get_service_yaml().database.url)
                    with Session(engine) as sess:
                        row = sess.query(AppDvsTask).filter(AppDvsTask.task_id == self.task_id).first()
                        if row:
                            _sync_task_vuln_stats(row)
                            sess.commit()
                except Exception:
                    pass
            except Exception as exc:
                self._emit("vuln_intake_report_failed", finding_id=rec.finding_id, status="failed", error=str(exc), source_file=rec.source_file, function_name=rec.function_name, line=rec.line)
        return findings

    def _record_edges_from_result(self, result: TaskResult, node_ids: list[str]) -> None:
        text = result.final_output or ""
        edges: list[TaintEdgeRecord] = []
        followups: list[FollowupRecord] = []
        graph = (result.upstream_entry_metadata or {}).get("taint_graph")
        graph_path = self.ws / "taint-graph.json"
        if not isinstance(graph, dict) and graph_path.exists():
            try: graph = json.loads(graph_path.read_text(encoding="utf-8"))
            except Exception: graph = None
        if isinstance(graph, dict):
            for item in graph.get("edges") or []:
                if not isinstance(item, dict): continue
                src = str(item.get("from") or item.get("from_symbol") or "").strip() or (self.taint_params[0] if self.taint_params else "unknown")
                dst = str(item.get("to") or item.get("to_symbol") or "").strip() or "unknown"
                validation_state = normalize_validation_state(item.get("validations") or item.get("validation"), sanitizer_effect=str(item.get("sanitizer_effect") or "none"), default_target=dst)
                edge_rec = TaintEdgeRecord(edge_id=_edge_id(self.run_id, self.func_name, src, dst, str(item.get("line") or "")), run_id=self.run_id, from_node_id=node_ids[0] if node_ids else "", to_node_id=_node_id(self.src_file, self.func_name, dst, self.dep), source_file=self.src_file, function_name=self.func_name, from_symbol=src, to_symbol=dst, line=str(item.get("line") or ""), operation=str(item.get("operation") or ""), evidence=str(item.get("evidence") or ""), sanitizer=str(item.get("sanitizer") or ""), sanitizer_effect=str(item.get("sanitizer_effect") or "none"), validation=str(item.get("validation") or ""), termination_reason=str(item.get("termination_reason") or ""), confidence=float(item.get("confidence") or 0), validation_facts_json=json.dumps(validation_state.facts, ensure_ascii=False), validation_signature=validation_state.signature, validation_risk_rank=validation_state.risk_rank)
                edges.append(edge_rec)
                self.store.record_constraints(run_id=self.run_id, edge_id=edge_rec.edge_id, source_file=self.src_file, function_name=self.func_name, line=edge_rec.line, facts=validation_state.facts)
            for item in graph.get("followups") or []:
                if not isinstance(item, dict):
                    continue
                fname = str(item.get("function") or item.get("callee_function") or "").strip()
                if not fname:
                    continue
                fline = str(item.get("line") or item.get("callee_line") or "").strip()
                params = item.get("tainted_params") or item.get("params") or []
                if isinstance(params, str):
                    param_list = [x.strip() for x in params.split(",") if x.strip()]
                elif isinstance(params, list):
                    param_list = [str(x).strip() for x in params if str(x).strip()]
                else:
                    param_list = []
                src_symbol = self.taint_params[0] if self.taint_params else "taint"
                dst_symbol = ",".join(param_list) or "*"
                eid = _edge_id(self.run_id, self.func_name, src_symbol, fname, fline)
                validation_state = normalize_validation_state(item.get("validations") or item.get("validation"), default_target=dst_symbol)
                edges.append(TaintEdgeRecord(edge_id=eid, run_id=self.run_id, from_node_id=node_ids[0] if node_ids else "", to_node_id=_node_id(str(item.get("file") or self.src_file), fname, dst_symbol, self.dep + 1), source_file=self.src_file, function_name=self.func_name, from_symbol=src_symbol, to_symbol=dst_symbol, line=fline, operation="call_arg", evidence=str(item.get("reason") or item.get("evidence") or ""), validation=str(item.get("validation") or ""), validation_facts_json=json.dumps(validation_state.facts, ensure_ascii=False), validation_signature=validation_state.signature, validation_risk_rank=validation_state.risk_rank))
                followup_id = "follow_" + hashlib.sha1((eid+fname).encode()).hexdigest()[:16]
                dispatch_kind = str(item.get("dispatch_kind") or item.get("call_kind") or item.get("kind") or "direct_call").strip() or "direct_call"
                tainted_nonlocal = item.get("tainted_nonlocal") or item.get("nonlocal_taints") or []
                if not isinstance(tainted_nonlocal, list):
                    tainted_nonlocal = []
                followups.append(FollowupRecord(followup_id=followup_id, edge_id=eid, parent_node_id=node_ids[0] if node_ids else "", callee_file=str(item.get("file") or self.src_file), callee_function=fname, callee_line=fline, tainted_params_json=json.dumps(param_list, ensure_ascii=False), depth=self.dep + 1, reason=str(item.get("reason") or ""), dispatch_kind=dispatch_kind, tainted_nonlocal_json=json.dumps(tainted_nonlocal, ensure_ascii=False)))
                self.store.record_constraints(run_id=self.run_id, edge_id=eid, followup_id=followup_id, source_file=self.src_file, function_name=self.func_name, line=fline, facts=validation_state.facts)
        # ── Bug B: 容器驻留信号（独立于 followups，仅记入图 + 返回元数据）──
        container_taint_syms: list[dict] = []
        for item in (graph or {}).get("container_taints") or []:
            if not isinstance(item, dict):
                continue
            sym = str(item.get("symbol") or "").strip()
            kind = str(item.get("kind") or "global").strip()
            if not sym:
                continue
            eid = _edge_id(self.run_id, self.func_name, self.taint_params[0] if self.taint_params else "taint", sym, str(item.get("evidence") or "")[:60])
            edges.append(TaintEdgeRecord(
                edge_id=eid, run_id=self.run_id,
                from_node_id=node_ids[0] if node_ids else "",
                to_node_id=_node_id(self.src_file, self.func_name, sym, self.dep),
                source_file=self.src_file, function_name=self.func_name,
                from_symbol=self.taint_params[0] if self.taint_params else "taint",
                to_symbol=sym, line=str(item.get("evidence") or ""),
                operation="container",
                evidence=str(item.get("evidence") or ""),
            ))
            container_taint_syms.append({"symbol": sym, "kind": kind, "evidence": str(item.get("evidence") or "")})
        if container_taint_syms:
            try:
                self.store.record_container_taints(
                    run_id=self.run_id, source_file=self.src_file,
                    function_name=self.func_name, entries=container_taint_syms, depth=self.dep,
                )
            except Exception as _e:
                logger.warning("unexpected error in vuln_workflow.py: %s", _e, exc_info=True)
        callees = []
        for c in callees:
            eid = _edge_id(self.run_id, self.func_name, self.taint_params[0] if self.taint_params else "taint", c.function_name, c.line)
            edges.append(TaintEdgeRecord(edge_id=eid, run_id=self.run_id, from_node_id=node_ids[0] if node_ids else "", to_node_id=_node_id(c.file or self.src_file, c.function_name, c.tainted_params or "*", self.dep + 1), source_file=self.src_file, function_name=self.func_name, from_symbol=self.taint_params[0] if self.taint_params else "taint", to_symbol=c.tainted_params or "*", line=c.line, operation="call_arg", evidence=c.description))
            followups.append(FollowupRecord(followup_id="follow_" + hashlib.sha1((eid+c.function_name).encode()).hexdigest()[:16], edge_id=eid, parent_node_id=node_ids[0] if node_ids else "", callee_file=c.file or self.src_file, callee_function=c.function_name, callee_line=c.line, tainted_params_json=json.dumps([x.strip() for x in (c.tainted_params or "").split(',') if x.strip()], ensure_ascii=False), depth=self.dep + 1))
        self.store.add_taint_edges(edges); self.store.add_followups(followups)
        # 带回 result 元数据，供 Orchestrator 直接利用，避免 SQLite JOIN 查询
        if followups:
            _meta = result.upstream_entry_metadata or {}
            _meta["followup_refs"] = [
                {"followup_id": f.followup_id, "callee_function": f.callee_function, "callee_file": f.callee_file,
                 "callee_line": f.callee_line, "tainted_params_json": f.tainted_params_json, "reason": f.reason,
                 "dispatch_kind": f.dispatch_kind, "tainted_nonlocal_json": f.tainted_nonlocal_json,
                 "validation_signature": next((e.validation_signature for e in edges if e.edge_id == f.edge_id), "none"),
                 "validation_risk_rank": next((e.validation_risk_rank for e in edges if e.edge_id == f.edge_id), 100),
                 "validation_facts_json": next((e.validation_facts_json for e in edges if e.edge_id == f.edge_id), "[]")}
                for f in followups
            ]
            result.upstream_entry_metadata = _meta
        # ── Bug B: 容器驻留符号带回元数据，供 orchestrator Bug A 聚合搜索 ──
        if container_taint_syms:
            _meta2 = result.upstream_entry_metadata or {}
            _meta2["container_taint_syms"] = container_taint_syms
            result.upstream_entry_metadata = _meta2
        self.store.append_artifact_manifest(
            "taint_tracking",
            [
                {"path": "sqlite:taint_nodes/taint_edges/followups", "kind": "sqlite", "role": "taint_graph", "exists": True},
            ],
            function_name=self.func_name,
            source_file=self.src_file,
            task_id=self.task_id,
            run_id=self.run_id,
        )

    def _finalize_taint_result(self, result: TaskResult) -> TaskResult:
        graph_export = self.store.export_json()
        self.store.finish_run(self.run_id, result.status.value if hasattr(result.status, "value") else str(result.status))
        summary = {"runs": len(graph_export.get("analysis_runs") or []), "nodes": len(graph_export.get("taint_nodes") or []), "edges": len(graph_export.get("taint_edges") or []), "followups": len(graph_export.get("followups") or []), "findings": len(graph_export.get("vulnerability_findings") or [])}
        result.vuln_summary = summary
        final_output_root = self.out_dir.parent / "output"
        final_output_root.mkdir(parents=True, exist_ok=True)
        final_sqlite_path = final_output_root / "vuln-scan.sqlite"
        try:
            safe_copyfile(self.store.db_path, final_sqlite_path)
        except OSError:
            pass
        result.upstream_entry_metadata = dict(result.upstream_entry_metadata or {})
        result.upstream_entry_metadata["vuln_scan"] = {
            "sqlite_path": str(final_sqlite_path if final_sqlite_path.exists() else self.store.db_path),
            "epoch_sqlite_path": str(self.store.db_path),
            "vulnerabilities_dir": str(self.vuln_root),
        }
        # 兼容清理：旧版本/异常模型可能仍写文件，中间产物不再保留，SQLite 是唯一图谱来源。
        for _json_path in [self.ws / "taint-graph.json", self.ws / "taintvars.json", self.ws / "tainted.list", self.ws / "vuln-scan-graph.json", self.out_dir / "taint-graph.validation.json", *self.ws.glob("dataflow-*.md"), *self.ws.glob("taint-flow-*.md")]:
            try:
                if _json_path.exists():
                    _json_path.unlink()
            except OSError:
                pass
        return result

    def run_taint_tracking_only(self) -> TaskResult:
        self._write_design_doc()
        self.store.start_run(self.run_id, self.task_id, self.src_file, self.func_name, self.cfg.cwd, self.cfg.model_dump())
        node_ids = self._seed_nodes()
        self._emit("vuln_scan_graph_start", function=self.func_name, source_file=self.src_file, taints=self.taint_params, depth=self.dep)
        result, base_session, dataflow_text = self._run_single_worker()
        # 将 worker session 路径写入元数据，供 Orchestrator 传递给 callee 作为 parent session；
        # 同时保留漏洞挖掘所需的 dataflow 文本，使漏洞挖掘可以与后续 callee 污点分析并行。
        if base_session:
            result.upstream_entry_metadata["worker_session_file"] = base_session
        result.upstream_entry_metadata["vuln_mining_base_session"] = base_session
        result.upstream_entry_metadata["vuln_mining_dataflow_text"] = dataflow_text
        self._record_edges_from_result(result, node_ids)
        return self._finalize_taint_result(result)

    def _run_callee_resolve_fork(
        self,
        base_session: str,
        unresolved_map: dict[str, list],
        call_context_map: dict[str, dict] | None = None,
    ) -> dict[str, str]:
        """Fork worker session and ask LLM to confirm fuzzy callee resolutions.

        Takes a map of {original_name: [FunctionResolution candidates]} and
        returns a map of {original_name: confirmed_resolved_name}.

        Fail-safe: any error keeps all candidates as confirmed.
        """
        if self._cancelled() or not unresolved_map or not self.cfg.workers.agents:
            return {}
        acfg = self._agent_cfg()
        if self.sessions_archive_dir:
            self.sessions_archive_dir.mkdir(parents=True, exist_ok=True)
            fork_session = self.sessions_archive_dir / f"{self.session_label}-callee-resolve.jsonl"
        else:
            fork_session = self.sessions / f"callee-resolve-{_safe_name(self.func_name)}.jsonl"
        try:
            if base_session and Path(base_session).exists():
                safe_copyfile(base_session, fork_session)
        except OSError:
            pass
        lines = [
            f"你在分析函数 `{self.src_file}::{self.func_name}` 时，以下跟入点在 funcdb 中"
            "未精确匹配到函数定义。脚本通过最长前缀/后缀分段匹配找到了候选，"
            "请判断每个候选是否确实是被调用的函数。",
            "",
        ]
        for idx, (original, candidates) in enumerate(unresolved_map.items(), 1):
            ctx = (call_context_map or {}).get(original, {})
            call_line = ctx.get("line", "")
            call_file = ctx.get("file", self.src_file)
            lines.append(f"{idx}. 调用点函数名: {original}")
            lines.append(f"   调用位置: {call_file} {call_line}")
            if not candidates:
                lines.append("   候选: (无)")
                lines.append("")
                continue
            for j, c in enumerate(candidates):
                c_name = getattr(c, "function_name", "") or ""
                c_file = getattr(c, "source_file", "") or ""
                c_line = getattr(c, "line", 0) or ""
                lines.append(f"   候选 {chr(97 + j)}. {c_name} @ {c_file} L{c_line}")
            lines.append("")
        lines.append('输出 JSON: {"results": [{"original": "...", "confirmed": true, "resolved_name": "..."}]}')
        prompt = "\n".join(lines)
        system_prompt = _read_prompt("prompts/callee-resolve/default.md")
        self._emit("callee_resolve_start", function=self.func_name,
                   unresolved_count=len(unresolved_map), depth=self.dep)
        output = run_agent(
            prompt=prompt, model=acfg.model,
            tools=acfg.tools or self.cfg.workers.default_tools,
            cwd=str(self.ws), session_file=str(fork_session),
            system_prompt=system_prompt,
            cancel_event=self.cancel_event,
            run_timeout_seconds=min(self.cfg.agent_run_timeout_seconds or 300, 120),
            pi_max_retries=self.cfg.pi_max_retries, pi_retry_delay=self.cfg.pi_retry_delay,
            task_context={
                "task_id": self.task_id,
                "task_root": str(self.out_dir.parent),
                "task_run_root": str(self.out_dir),
                "task_pi_dir": self.cfg.role_pi_dir("workers"),
                "agent_role": "workers",
            },
        )
        emit_agent_runtime_events(
            self._emit, result=output, stage="callee_resolve",
            role="workers", model=acfg.model,
            extra={"function": self.func_name, "depth": self.dep},
        )
        parsed = _extract_json_from_text(output.output, "results")
        if not isinstance(parsed, dict):
            self._emit("callee_resolve_done", function=self.func_name,
                       total=len(unresolved_map), confirmed=len(unresolved_map),
                       error="json parse failed, keeping all candidates", depth=self.dep)
            # Fail-safe: confirm all candidates
            return {orig: getattr(cands[0], "function_name", "") if cands else ""
                    for orig, cands in unresolved_map.items() if cands}
        results_list = parsed.get("results") or []
        confirmed_map: dict[str, str] = {}
        confirmed_count = 0
        for item in results_list:
            if not isinstance(item, dict):
                continue
            original = str(item.get("original") or "").strip()
            if item.get("confirmed") is True:
                resolved_name = str(item.get("resolved_name") or "").strip()
                if original and resolved_name:
                    confirmed_map[original] = resolved_name
                    confirmed_count += 1
        # Fail-safe: unmentioned originals with candidates default to confirmed
        for orig, cands in unresolved_map.items():
            if orig not in confirmed_map and cands:
                confirmed_map[orig] = getattr(cands[0], "function_name", "")
                confirmed_count += 1
        self._emit("callee_resolve_done", function=self.func_name,
                   total=len(unresolved_map), confirmed=confirmed_count, depth=self.dep)
        return confirmed_map

    def run_vuln_mining_after_taint(self, result: TaskResult) -> list[VulnFindingRecord]:
        base_session = str((result.upstream_entry_metadata or {}).get("vuln_mining_base_session") or "")
        dataflow_text = str((result.upstream_entry_metadata or {}).get("vuln_mining_dataflow_text") or result.final_output or "")
        try:
            findings = self._run_vuln_mining_fork(base_session, dataflow_text)
            self._emit("vuln_scan_findings", function=self.func_name, count=len(findings), depth=self.dep)
            graph_export = self.store.export_json()
            result.vuln_summary = {"runs": len(graph_export.get("analysis_runs") or []), "nodes": len(graph_export.get("taint_nodes") or []), "edges": len(graph_export.get("taint_edges") or []), "followups": len(graph_export.get("followups") or []), "findings": len(graph_export.get("vulnerability_findings") or [])}
            return findings
        except Exception as exc:
            self._emit("vuln_scan_error", function=self.func_name, error=str(exc), depth=self.dep)
            return []

    def run(self) -> TaskResult:
        result = self.run_taint_tracking_only()
        self.run_vuln_mining_after_taint(result)
        return result

    def _make_result(self, final_output: str, agent_result: Any, passed: bool, completion_reason: str, *, rounds: list[RoundResult] | None = None, total_tokens: TokenUsage | None = None) -> TaskResult:
        status = TaskStatus.PASSED if passed else TaskStatus.COMPLETED_LIMITED
        entry_metadata = _build_upstream_entry_metadata(self.cfg)
        taint_hint_summary = _build_taint_hint_summary(self.cfg, self.taint_params)
        output = _prepend_upstream_hint_section(final_output, entry_metadata=entry_metadata, taint_hint_summary=taint_hint_summary)
        return TaskResult(task_id=self.task_id, task=self.cfg.task, status=status, analysis_status=status.value, completion_reason=completion_reason, upstream_entry_metadata=entry_metadata, taint_hint_summary=taint_hint_summary, final_output=output, rounds=rounds or [], total_tokens=total_tokens or TokenUsage(), error=(completion_reason if not passed else None))


def build_function_summary_from_result(
    result: TaskResult,
    tainted_params: list[str],
    func_hash: str,
) -> dict:
    """Script-based summary extraction — no LLM overhead.

    Returns a dict suitable for GlobalCache.put() / FunctionSummary construction.
    Called from orchestrator after Worker analysis completes.
    """
    validations: list[dict] = []
    edges_list: list[dict] = []
    followups_list: list[dict] = []

    # Extract from rounds
    for rnd in (result.rounds or []):
        for worker in (rnd.worker_results or []):
            if worker.df_issues:
                for issue in worker.df_issues:
                    validations.append({
                        "variable": "",
                        "kind": "structure_check",
                        "evidence": issue,
                        "confidence": "high",
                    })

    # Extract from upstream_entry_metadata
    meta = result.upstream_entry_metadata or {}
    followup_refs = meta.get("followup_refs") or []
    for fup in followup_refs:
        followups_list.append({
            "file": fup.get("callee_file", ""),
            "function": fup.get("callee_function", ""),
            "line": fup.get("callee_line", ""),
            "reason": fup.get("reason", ""),
        })
        # If followup has validation facts, collect them
        facts_json = fup.get("validation_facts_json", "[]")
        try:
            facts = json.loads(facts_json) if isinstance(facts_json, str) else facts_json
            for fact in (facts if isinstance(facts, list) else []):
                if isinstance(fact, dict):
                    validations.append({
                        "variable": fact.get("target_symbol", ""),
                        "kind": fact.get("kind", "constraint"),
                        "evidence": fact.get("evidence", ""),
                        "confidence": fact.get("confidence", "medium"),
                    })
        except Exception as _e:
            logger.warning("unexpected error in vuln_workflow.py: %s", _e, exc_info=True)

    # Extract taint edges from taint_graph
    taint_graph = meta.get("taint_graph")
    if isinstance(taint_graph, dict):
        for edge in (taint_graph.get("edges") or []):
            if isinstance(edge, dict):
                edges_list.append({
                    "from": edge.get("from", ""),
                    "to": edge.get("to", ""),
                    "operation": edge.get("operation", ""),
                    "evidence": edge.get("evidence", ""),
                })
                # Validations from edges
                if edge.get("sanitizer_effect") and edge["sanitizer_effect"] != "none":
                    validations.append({
                        "variable": edge.get("to", ""),
                        "kind": edge.get("sanitizer", "sanitizer"),
                        "evidence": edge.get("evidence", ""),
                        "confidence": "high",
                    })

    return {
        "function_name": result.task or "",
        "func_hash": func_hash,
        "validations": validations,
        "edges": edges_list,
        "followups": followups_list,
    }

    def run(self) -> TaskResult:
        result = self.run_taint_tracking_only()
        self.run_vuln_mining_after_taint(result)
        return result

    def _make_result(self, final_output: str, agent_result: Any, passed: bool, completion_reason: str, *, rounds: list[RoundResult] | None = None, total_tokens: TokenUsage | None = None) -> TaskResult:
        status = TaskStatus.PASSED if passed else TaskStatus.COMPLETED_LIMITED
        entry_metadata = _build_upstream_entry_metadata(self.cfg)
        taint_hint_summary = _build_taint_hint_summary(self.cfg, self.taint_params)
        output = _prepend_upstream_hint_section(final_output, entry_metadata=entry_metadata, taint_hint_summary=taint_hint_summary)
        return TaskResult(task_id=self.task_id, task=self.cfg.task, status=status, analysis_status=status.value, completion_reason=completion_reason, upstream_entry_metadata=entry_metadata, taint_hint_summary=taint_hint_summary, final_output=output, rounds=rounds or [], total_tokens=total_tokens or TokenUsage(), error=(completion_reason if not passed else None))
