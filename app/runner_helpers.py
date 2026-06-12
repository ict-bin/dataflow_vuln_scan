"""Agent runner helper utilities — token estimation, process management, error classification.

All async/await removed. Uses threading primitives (threading.Event, subprocess.Popen) instead.
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from .agent_process import AgentProcessHandle, find_pi_command, process_group_id
from .models import TokenUsage

logger = logging.getLogger("dvs.runner")

# ─── Configuration constants ──────────────────────────────────────────────────

_MAX_BACKOFF = 300  # 退避上限 5 分钟
_QUERY_ENGINE_401_MAX_RETRIES = 10
_DEFAULT_CONTEXT_WINDOW = 128_000
_SINGLE_INPUT_CONTEXT_RATIO = 0.75
_PROMPT_TOKEN_OVERHEAD = 128
_COMPACTION_TRIGGER_PROMPT = (
    "请立即触发一次当前会话的自动压缩（compaction），"
    "仅保留后续继续执行任务所需的关键结论、约束和待办。"
    "不要继续业务分析，只回复 COMPACTION_OK。"
)
_CONTEXT_WINDOW_BY_MODEL = {
    "gpt-5.4": 128_000,
    "gpt-5.4-mini": 128_000,
    "gpt-5.5": 256_000,
    "gpt-5.3-codex": 128_000,
    "gpt-5.2": 200_000,
    "minimax/minimax-m2.5": 163_804,
    "minimax-m2.5": 163_804,
    "minimax-m2.7": 128_000,
    "glm-5.1": 128_000,
    "zai-org/glm-5": 128_000,
}


# ─── Result / Error classes ───────────────────────────────────────────────────

class AgentResult:
    def __init__(self, output: str = "", error: str | None = None,
                 token_usage: TokenUsage | None = None,
                 fatal: bool = False, retryable: bool = False,
                 session_file: str | None = None, exit_code: int = -1,
                 duration_ms: float = 0.0, pi_version: str = ""):
        self.output = output
        self.error = error
        self.token_usage = token_usage or TokenUsage()
        self.fatal = fatal
        self.retryable = retryable
        self.session_file = session_file
        self.exit_code = exit_code
        self.duration_ms = duration_ms
        self.pi_version = pi_version
        self.messages: list[dict] = []


class _PiProcessError(Exception):
    pass


class PiFatalError(Exception):
    pass


class TaskCancelledError(Exception):
    """Raised when a task is cancelled via threading.Event."""
    pass


# ─── Logging helpers ──────────────────────────────────────────────────────────

def _log_error(msg: str) -> None:
    logger.error(msg)


def _log_warn(msg: str) -> None:
    logger.warning(msg)


def _log_info(msg: str) -> None:
    logger.info(msg)


# ─── Backoff / retry helpers ──────────────────────────────────────────────────

def _backoff(base_delay: float, attempt: int) -> float:
    return min(_MAX_BACKOFF, base_delay * (2 ** max(0, attempt - 1)))


def _fmt_max(n: int) -> str:
    return "∞" if n < 0 else str(n)


def _normalize_timeout_seconds(timeout_seconds: float | int | None) -> float | None:
    if timeout_seconds is None or timeout_seconds < 0:
        return None
    normalized = float(max(1.0, timeout_seconds))
    if normalized >= 86400:
        return None
    return normalized


def _should_retry(
    *,
    attempt: int,
    max_retries: int,
    cancel_event: threading.Event | None = None,
) -> bool:
    if max_retries < 0:
        return True
    return attempt < max_retries


def _sleep_with_cancel(delay: float, cancel_event: threading.Event | None) -> bool:
    """Sleep for `delay` seconds.  Returns True if cancelled, False if timeout elapsed normally."""
    if cancel_event is None:
        time.sleep(delay)
        return False
    cancelled = cancel_event.wait(timeout=delay)
    return cancelled


def _cmd_preview(args: list[str]) -> str:
    return " ".join(args)


# ─── Token estimation ─────────────────────────────────────────────────────────

def _estimate_tokens(text: str) -> int:
    """4-char heuristic for English text; returns ≥ 1."""
    return max(1, len(text) // 4)


def _model_context_window(model: str) -> int:
    key = model.lower()
    return _CONTEXT_WINDOW_BY_MODEL.get(key, _DEFAULT_CONTEXT_WINDOW)


def _single_input_token_estimate(system_prompt: str, prompt: str, post_skill_prompt: str | None = None) -> int:
    combined = system_prompt + "\n\n" + prompt
    if post_skill_prompt:
        combined += "\n\n" + post_skill_prompt
    return _estimate_tokens(combined) + _PROMPT_TOKEN_OVERHEAD


def _single_input_token_limit(context_window: int) -> int:
    return max(4096, int(context_window * _SINGLE_INPUT_CONTEXT_RATIO))


# ─── Context overflow detection ───────────────────────────────────────────────

def _parse_context_overflow_details(error_text: str | None) -> dict[str, int]:
    if not error_text:
        return {}
    details: dict[str, int] = {}
    m = re.search(r"prompt\s+token\s+count.*?(\d[\d,]*)", error_text, re.IGNORECASE)
    if m:
        try:
            details["prompt_tokens"] = int(m.group(1).replace(",", ""))
        except ValueError:
            pass
    m = re.search(r"max.*?(?:context|model).*?(?:length|tokens)[^\d]*(\d[\d,]*)", error_text, re.IGNORECASE)
    if m:
        try:
            details["max_tokens"] = int(m.group(1).replace(",", ""))
        except ValueError:
            pass
    if "too long" in error_text.lower() or "exceed" in error_text.lower():
        m = re.search(r"(\d[\d,]*)\s*(?:tokens?|length)", error_text)
        if m:
            try:
                val = int(m.group(1).replace(",", ""))
                if "prompt_tokens" not in details:
                    details["prompt_tokens"] = val
                if "max_tokens" not in details:
                    details["max_tokens"] = val
            except ValueError:
                pass
    return details


def _is_context_overflow_error(error_text: str | None) -> bool:
    if not error_text:
        return False
    lower = error_text.lower()
    indicators = [
        "context length", "context_length", "context window",
        "maximum context length", "too long", "token limit",
        "max tokens", "reduce the length", "prompt is too long",
        "exceeds model", "context size", "4097",
    ]
    return any(indicator in lower for indicator in indicators)


def _format_context_overflow_failure(
    model: str,
    system_prompt: str,
    prompt: str,
    post_skill_prompt: str | None,
    error_text: str | None,
) -> str:
    details = _parse_context_overflow_details(error_text)
    context_window = _model_context_window(model)
    estimated = _single_input_token_estimate(system_prompt, prompt, post_skill_prompt)
    limit = _single_input_token_limit(context_window)
    limit_info = f"model_limit={context_window}, input_limit={limit}, estimated={estimated}"
    if details:
        detail_str = ", ".join(f"{k}={v}" for k, v in sorted(details.items()))
        limit_info += f", api_reported=({detail_str})"
    return (
        f"Context overflow detected (model={model}, {limit_info}). "
        f"Session compaction triggered to reduce prompt size."
    )


# ─── pi command resolution ────────────────────────────────────────────────────

def _find_pi_command() -> list[str]:
    """Locate the pi CLI command; delegate to agent_process module."""
    from .agent_process import find_pi_command as _fpc
    return _fpc()


def _resolve_pi_model(model: str) -> str:
    return model


# ─── Process tree management (sync, using subprocess.Popen) ───────────────────

def _proc_group_id(proc: subprocess.Popen) -> int | None:
    try:
        return process_group_id(proc.pid)
    except Exception:
        return None


def _terminate_pi_process_tree(
    proc: subprocess.Popen,
    *,
    reason: str = "",
    task_id: str = "",
    timeout: float = 15.0,
) -> None:
    """Synchronously terminate a process tree. Uses subprocess.Popen."""
    pid = proc.pid
    pgid = _proc_group_id(proc)
    logger.info(
        "terminating pi process tree: pid=%s pgid=%s reason=%s task=%s",
        pid, pgid, reason, task_id,
    )
    try:
        if pgid is not None and pgid > 0:
            os.killpg(pgid, signal.SIGTERM)
        else:
            proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.warning(
                "pi process tree did not exit after SIGTERM, sending SIGKILL: pid=%s pgid=%s",
                pid, pgid,
            )
            try:
                if pgid is not None and pgid > 0:
                    os.killpg(pgid, signal.SIGKILL)
                else:
                    proc.kill()
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                logger.error("pi process tree could not be killed: pid=%s", pid)
    except ProcessLookupError:
        pass
    except Exception as exc:
        logger.warning("error terminating pi process tree pid=%s: %s", pid, exc)


# ─── Argument building ────────────────────────────────────────────────────────

def _build_args(
    prompt: str,
    model: str,
    tools: list[str],
    thinking_level: str,
    session_file: str | None,
    *,
    post_skill_prompt: str | None = None,
    max_turns: int | None = None,
    no_session: bool = False,
    task_pi_dir: str | None = None,
    task_context: dict | None = None,
) -> list[str]:
    args = ["-p", prompt, "-m", model]
    for tool in tools:
        args.extend(["--tools", tool])
    args.extend(["--thinking-level", thinking_level])
    if task_pi_dir:
        args.extend(["--agent-dir", task_pi_dir])
    if session_file and not no_session:
        args.extend(["--session", session_file])
    if no_session:
        args.append("--no-session")
    if post_skill_prompt:
        args.extend(["--post-skill-prompt", post_skill_prompt])
    if max_turns is not None and max_turns > 0:
        args.extend(["--max-turns", str(max_turns)])
    if task_context:
        context_json = json.dumps(task_context, ensure_ascii=False)
        args.extend(["--task-context", context_json])
    return args


# ─── Temp file writing ────────────────────────────────────────────────────────

def _write_temp_markdown(
    prompt: str,
    system_prompt: str,
    post_skill_prompt: str | None,
    model: str,
    *,
    task_id: str = "",
) -> str | None:
    try:
        fd, path = tempfile.mkstemp(suffix=".md", prefix=f"dvs-prompt-{task_id[:12]}-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"# System Prompt\n\n{system_prompt}\n\n---\n\n# Prompt\n\n{prompt}")
            if post_skill_prompt:
                f.write(f"\n\n---\n\n# Post-Skill Prompt\n\n{post_skill_prompt}")
        return path
    except OSError as exc:
        logger.warning("failed to write temp markdown for task=%s: %s", task_id, exc)
        return None


# ─── Agent environment building ───────────────────────────────────────────────

def _build_agent_env(
    *,
    cwd: str,
    env: dict[str, str] | None,
    task_pi_dir: str | None = None,
    task_context: dict | None = None,
) -> dict[str, str]:
    merged: dict[str, str] = dict(os.environ)
    if env:
        merged.update(env)
    merged.setdefault("HOME", cwd)
    merged.setdefault("TMPDIR", os.path.join(cwd, "tmp"))
    if task_pi_dir:
        merged["PI_CODING_AGENT_DIR"] = task_pi_dir
    if task_context:
        merged["DVS_TASK_CONTEXT"] = json.dumps(task_context, ensure_ascii=False)
    return merged


# ─── Error classification ─────────────────────────────────────────────────────

def _is_fatal_error(result: AgentResult) -> bool:
    if result.fatal:
        return True
    error_text = (result.error or "").lower()
    fatal_patterns = [
        "model not found", "unauthorized", "invalid api key",
        "module not found", "no such file", "permission denied",
    ]
    return any(pattern in error_text for pattern in fatal_patterns)


def _is_retryable_api_error(result: AgentResult) -> bool:
    if result.fatal:
        return False
    error_text = (result.error or "").lower()
    if not error_text:
        return False
    retryable_patterns = [
        "timeout", "connection", "rate limit", "too many requests",
        "server error", "internal server error", "service unavailable",
        "bad gateway", "gateway timeout", "temporary",
    ]
    return any(pattern in error_text for pattern in retryable_patterns)


def _is_retryable_query_engine_401_error(result: AgentResult) -> bool:
    error_text = (result.error or "").lower()
    return "401" in error_text and "unauthorized" in error_text


def _is_pi_crash(result: AgentResult) -> bool:
    if result.exit_code < 0:
        return True
    error_text = (result.error or "").lower()
    crash_patterns = ["segmentation fault", "traceback", "signal",
                      "aborted", "core dumped"]
    return result.exit_code != 0 and any(p in error_text for p in crash_patterns)
