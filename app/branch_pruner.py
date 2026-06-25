"""Branch pruner — LLM judges whether each callee is worth pursuing.

Called from orchestrator after callee resolution + P0/P1/P2 classification,
before BFS queue dispatch.  Forks the worker session (preserves caller analysis
context) but uses an independent system prompt so the main-line taint-graph
prompt does not contaminate the judgment.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from pathlib import Path
from typing import Any, Callable

from .agent_runtime_events import emit_agent_runtime_events
from .copy_utils import safe_copyfile
from .models import AgentInstanceConfig, CalleeRef, SwarmEvent, TokenUsage
from .runner import run_agent
from .taint_workflow import _extract_function_body

logger = logging.getLogger("dvs.branch_pruner")

_PRUNE_SESSION_SUFFIX = "-branch-pruning.jsonl"


def _read_prompt(rel_path: str) -> str:
    try:
        return (Path(__file__).resolve().parents[1] / rel_path).read_text(encoding="utf-8")
    except OSError:
        return ""


def _safe_name(value: str, *, max_len: int = 96) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-") or "item"
    if len(safe) <= max_len:
        return safe
    return f"{safe[:max_len - 9]}-{hashlib.sha1(value.encode()).hexdigest()[:8]}"


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
                    obj = json.loads(raw[start:end + 1])
                    if key is None or (isinstance(obj, dict) and key in obj):
                        return obj
                except Exception:
                    pass
    return None


def prune_branches(
    *,
    worker_session: str,
    callees: list[CalleeRef],
    caller_func: str,
    caller_file: str,
    source_root: str,
    workspace: Path,
    funcdb_path: str,
    sessions_dir: Path,
    session_label: str,
    agent_cfg: AgentInstanceConfig,
    default_tools: list[str],
    cancel_event: threading.Event | None,
    run_timeout_seconds: int,
    pi_max_retries: int,
    pi_retry_delay: float,
    task_context: dict,
    on_event: Callable[[SwarmEvent], None] | None,
    depth: int,
) -> set[str]:
    """Fork worker session, extract callee function bodies, ask LLM to judge.

    Returns a set of function names that should be PURSUED.
    Fail-safe: any error keeps all callees (returns all names).
    """
    if not callees or (cancel_event and cancel_event.is_set()):
        return {c.function_name for c in callees}

    # ── Fork worker session ──────────────────────────────────────────
    sessions_dir.mkdir(parents=True, exist_ok=True)
    prune_session = sessions_dir / f"{session_label}{_PRUNE_SESSION_SUFFIX}"
    try:
        if worker_session and Path(worker_session).exists():
            safe_copyfile(worker_session, prune_session)
    except OSError:
        pass

    # ── Extract callee function bodies ───────────────────────────────
    lines = [
        f"当前函数 `{caller_file}::{caller_func}` 的污点传播分析识别了以下跟入点。",
        "所有跟入点都有污点数据流入。请根据被调用函数的函数体，判断跟入后是否有较大概率发现有价值漏洞。",
        "",
    ]
    extract_failures: list[str] = []
    for idx, callee in enumerate(callees, 1):
        func_body = ""
        try:
            func_body = _extract_function_body(
                str(workspace),
                callee.file or caller_file,
                callee.function_name,
                callee.line,
                funcdb_path=funcdb_path,
            )
        except Exception:
            pass

        params_str = callee.tainted_params or "(无直接参数)"
        nl_parts: list[str] = []
        for nl in (callee.tainted_nonlocal or []):
            if isinstance(nl, dict):
                sym = str(nl.get("symbol") or "").strip()
                kind = str(nl.get("kind") or "").strip()
                ev = str(nl.get("evidence") or "").strip()
                nl_parts.append(f"{sym} [{kind}]{chr(8212) + ' ' + ev if ev else ''}")

        lines.append(f"## 跟入点 {idx}")
        lines.append(f"函数: {callee.function_name}")
        lines.append(f"调用位置: {callee.file or caller_file} {callee.line}")
        lines.append(f"污点参数: {params_str}")
        if nl_parts:
            lines.append(f"间接污点: {'; '.join(nl_parts)}")
        lines.append(f"跟入原因: {callee.description or ''}")
        if func_body.strip():
            lines.append("")
            lines.append("被调用函数体:")
            lines.append("```c")
            lines.append(func_body)
            lines.append("```")
        else:
            lines.append("")
            lines.append("(无法提取函数体，请根据函数名和污点信息判断)")
            extract_failures.append(callee.function_name)
        lines.append("")

    lines.append('请输出 JSON: {"decisions": [{"function": "...", "pursue": true/false, "reason": "..."}]}')
    prompt = "\n".join(lines)
    system_prompt = _read_prompt("prompts/branch-pruning/default.md")

    def _emit(etype: str, **data: Any) -> None:
        if on_event:
            try:
                on_event(SwarmEvent(type=etype, task_id=task_context.get("task_id", ""), data=data))
            except Exception:
                pass

    _emit("branch_pruning_start", function=caller_func,
          followup_count=len(callees), depth=depth)

    output = run_agent(
        prompt=prompt,
        model=agent_cfg.model,
        tools=agent_cfg.tools or default_tools,
        cwd=str(workspace),
        session_file=str(prune_session),
        system_prompt=system_prompt,
        cancel_event=cancel_event,
        run_timeout_seconds=min(run_timeout_seconds or 300, 120),
        pi_max_retries=pi_max_retries,
        pi_retry_delay=pi_retry_delay,
        task_context=task_context,
    )
    emit_agent_runtime_events(
        _emit, result=output, stage="branch_pruning",
        role="workers", model=agent_cfg.model,
        extra={"function": caller_func, "depth": depth},
    )

    parsed = _extract_json_from_text(output.output, "decisions")
    if not isinstance(parsed, dict):
        _emit("branch_pruning_done", function=caller_func,
              total=len(callees), pursued=len(callees), pruned=0,
              error="json parse failed, keeping all", depth=depth)
        return {c.function_name for c in callees}

    decisions = parsed.get("decisions") or []
    mentioned: set[str] = set()
    pursue: set[str] = set()
    for d in decisions:
        if isinstance(d, dict):
            fname = str(d.get("function") or "").strip()
            if fname:
                mentioned.add(fname)
                if d.get("pursue") is True:
                    pursue.add(fname)

    # Fail-safe: unmentioned callees default to pursue
    all_names = {c.function_name for c in callees}
    for name in all_names:
        if name not in mentioned:
            pursue.add(name)

    pruned_names = all_names - pursue
    _emit("branch_pruning_done", function=caller_func,
          total=len(callees), pursued=len(pursue), pruned=len(pruned_names),
          pruned_functions=list(pruned_names), depth=depth)
    return pursue
