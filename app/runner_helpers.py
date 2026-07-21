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
from typing import Any, Callable, Optional

from .agent_process import AgentProcessHandle, find_pi_command, process_group_id
from .models import TokenUsage

logger = logging.getLogger("dvs.runner")

# ─── Configuration constants ──────────────────────────────────────────────────

_MAX_BACKOFF = 300  # 退避上限 5 分钟
_QUERY_ENGINE_401_MAX_RETRIES = 3
_DEFAULT_CONTEXT_WINDOW = 128_000
_SINGLE_INPUT_CONTEXT_RATIO = 0.75
_PROMPT_TOKEN_OVERHEAD = 128
# Compaction 不再发 user 消息, 用 RPC compact 命令 (见 runner.py _run_pi_compact)
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
        self.rate_limited: bool = False
        self.consecutive_rate_limit_count: int = 0
        self.retry_delay_seconds: int = 0
        self.rate_limit_event_due: bool = False
        self.api_retry_event_due: bool = False
        self.consecutive_api_retry_count: int = 0
        self.api_retry_reason: str | None = None
        self.fatal_retry_event_due: bool = False
        self.consecutive_fatal_retry_count: int = 0
        self.fatal_retry_reason: str | None = None
        self.agent_role: str | None = None
        self.runtime_dir: str | None = None
        self.context_window: int = 0
        self.proxy_reserved_tokens: int = 0
        # 模型侧 stopReason (pi RPC 透传); "error" = 模型内部错误 (overloaded/internal),
        # 多为瞬时, 源码分析无内容过滤风险 → _is_retryable_api_error 当可重试
        self.stop_reason: str = ""
        self.compaction_requested: bool = False
        self.compaction_completed: bool = False
        self.context_budget_exceeded_preflight: bool = False
        self.context_overflow_retrying: bool = False
        self.context_overflow_failed_after_compaction: bool = False
        self.context_overflow_retry_count: int = 0
        self.context_overflow_retry_event_due: bool = False


class _PiProcessError(Exception):
    pass


class PiFatalError(Exception):
    pass


class TaskCancelledError(Exception):
    """Raised when a task is cancelled via threading.Event."""
    pass


# ─── Logging helpers ──────────────────────────────────────────────────────────

def _log_error(msg: str, *args: Any) -> None:
    logger.error(msg, *args)


def _log_warn(msg: str, *args: Any) -> None:
    logger.warning(msg, *args)


def _log_info(msg: str, *args: Any) -> None:
    logger.info(msg, *args)


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
    waiter = getattr(cancel_event, "wait", None)
    if waiter is None:
        time.sleep(delay)
        return False
    try:
        cancelled = waiter(timeout=delay)
        return bool(cancelled)
    except TypeError:
        deadline = time.monotonic() + max(0.0, float(delay))
        while time.monotonic() < deadline:
            if getattr(cancel_event, "is_set", lambda: False)():
                return True
            time.sleep(0.05)
        return bool(getattr(cancel_event, "is_set", lambda: False)())


def _should_emit_api_retry_event(consecutive_retries: int, delay_seconds: float) -> bool:
    retries = max(0, int(consecutive_retries or 0))
    delay = max(0.0, float(delay_seconds or 0))
    return delay >= 30.0 and retries > 0 and retries % 10 == 0


def _should_emit_infinite_retry_event(streak: int) -> bool:
    streak = max(0, int(streak or 0))
    return streak > 0 and streak % 10 == 0


def _mark_infinite_retry(result: AgentResult, *, kind: str, count: int, reason: str, delay_seconds: float = 30.0) -> None:
    result.fatal = False
    result.retry_delay_seconds = int(delay_seconds)
    if kind == "fatal":
        result.consecutive_fatal_retry_count = int(count)
        result.fatal_retry_reason = reason
        result.fatal_retry_event_due = _should_emit_infinite_retry_event(count)
    else:
        result.context_overflow_retry_count = int(count)
        result.context_overflow_retrying = True
        result.context_overflow_retry_event_due = _should_emit_infinite_retry_event(count)


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


def _effective_context_limit(context_window: int, proxy_reserved_tokens: int = 0) -> int:
    reserve = max(int(proxy_reserved_tokens or 0), 4096)
    response_headroom = 4096
    return max(1, int(context_window) - reserve - response_headroom)


def _preflight_context_token_limit(context_window: int, proxy_reserved_tokens: int = 0) -> int:
    return max(1, int(_effective_context_limit(context_window, proxy_reserved_tokens) * _SINGLE_INPUT_CONTEXT_RATIO))


# ─── Context overflow detection ───────────────────────────────────────────────

def _parse_context_overflow_details(error_text: str | None) -> dict[str, int]:
    text = str(error_text or "")
    details = {
        "input_tokens": 0,
        "actual_input_tokens": 0,
        "requested_output_tokens": 0,
        "context_length": 0,
        "provider_reported_context_length": 0,
        "max_input_tokens": 0,
        "proxy_reserved_tokens": 0,
    }
    if not text:
        return details
    patterns = {
        "input_tokens": r"passed\s+(\d[\d,]*)\s+input tokens",
        "actual_input_tokens": r"input has\s+(\d[\d,]*)\s+tokens",
        "requested_output_tokens": r"requested\s+(\d[\d,]*)\s+output tokens",
        "context_length": r"context length is only\s+(\d[\d,]*)\s+tokens",
        "provider_reported_context_length": r"maximum context length is\s+(\d[\d,]*)\s+tokens",
        "max_input_tokens": r"maximum input length(?: of)?\s+(\d[\d,]*)\s+tokens",
        "proxy_reserved_tokens": r"reserves\s+(\d[\d,]*)\s+safety-buffer tokens",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            continue
        try:
            details[key] = int(match.group(1).replace(",", ""))
        except ValueError:
            continue
    if details["provider_reported_context_length"] and not details["context_length"]:
        details["context_length"] = details["provider_reported_context_length"]
    if details["actual_input_tokens"] and not details["input_tokens"]:
        details["input_tokens"] = details["actual_input_tokens"]
    return details


def _is_context_overflow_error(error_text: str | None) -> bool:
    if not error_text:
        return False
    lower = error_text.lower()
    details = _parse_context_overflow_details(error_text)
    if details.get("context_length", 0) > 0:
        return True
    indicators = [
        "context length", "context_length", "context window",
        "maximum context length", "too long", "token limit",
        "max tokens", "reduce the length", "prompt is too long",
        "exceeds model", "context size", "4097",
        "prefill_context_length_exceeded", "input has", "safety-buffer",
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
    context_window = details.get("context_length") or _model_context_window(model)
    estimated = _single_input_token_estimate(system_prompt, prompt, post_skill_prompt)
    proxy_reserved_tokens = details.get("proxy_reserved_tokens", 0)
    effective_limit = _effective_context_limit(context_window, proxy_reserved_tokens)
    limit = _preflight_context_token_limit(context_window, proxy_reserved_tokens)
    limit_info = (
        f"model_limit={context_window}, effective_limit={effective_limit}, "
        f"preflight_limit={limit}, estimated={estimated}, proxy_reserved_tokens={proxy_reserved_tokens}"
    )
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
    """Return a pi-compatible model name with provider prefix.

    pi requires provider-qualified names. Platform config stores only the
    model id (e.g. MiniMax/MiniMax-M2.5). Look up models.json to find the
    matching provider and qualify the name.
    """
    raw = str(model or "").strip()
    if not raw:
        return raw
    models_path = Path(os.environ.get("PI_MODELS_JSON") or Path.home() / ".pi" / "agent" / "models.json")
    try:
        data = json.loads(models_path.read_text(encoding="utf-8"))
        providers = data.get("providers") if isinstance(data, dict) else None
        if not isinstance(providers, dict):
            return raw
        provider_keys = {str(k) for k in providers.keys()}
        if any(raw == key or raw.startswith(f"{key}/") for key in provider_keys):
            return raw
        matches: list[str] = []
        for provider_key, provider_cfg in providers.items():
            if not isinstance(provider_cfg, dict):
                continue
            for item in provider_cfg.get("models") or []:
                if not isinstance(item, dict):
                    continue
                model_id = str(item.get("id") or item.get("name") or "").strip()
                if model_id == raw:
                    matches.append(f"{provider_key}/{raw}")
        if len(matches) == 1:
            resolved = matches[0]
            _log_info(f"resolved pi model {raw!r} -> {resolved!r}")
            return resolved
    except Exception as exc:
        _log_warn(f"resolve pi model failed for {raw!r}: {exc}")
    return raw


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
    """Synchronously terminate a process tree and close all associated pipes."""
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
    finally:
        # Close all pipe file descriptors to prevent FD leaks.
        # Each subprocess.Popen with stdout/stderr/stdin=PIPE creates 3 pipe FDs
        # that must be explicitly closed after the process exits.
        for pipe_attr in ("stdout", "stderr", "stdin"):
            pipe = getattr(proc, pipe_attr, None)
            if pipe is not None:
                try:
                    pipe.close()
                except Exception:
                    pass


# ─── Argument building ────────────────────────────────────────────────────────

def _build_args(
    pi_cmd: list[str],
    model: str,
    tools: list[str],
    thinking_level: str,
    session_file: str | None,
    *,
    post_skill_prompt: str | None = None,
    max_turns: int | None = None,
    no_session: bool = False,
    task_context: dict | None = None,
    extension: str | None = None,
) -> list[str]:
    """Build pi RPC mode launch arguments."""
    args = [*pi_cmd, "--mode", "rpc"]
    if session_file and not no_session:
        args.extend(["--session", session_file])
    if no_session:
        args.append("--no-session")
    if model:
        args.extend(["--model", model])
    if tools:
        args.extend(["--tools", ",".join(tools)])
    if thinking_level and thinking_level != "off":
        args.extend(["--thinking", thinking_level])
    if post_skill_prompt:
        args.extend(["--post-skill-prompt", post_skill_prompt])
    if max_turns is not None and max_turns > 0:
        args.extend(["--max-turns", str(max_turns)])
    if task_context:
        context_json = json.dumps(task_context, ensure_ascii=False)
        args.extend(["--task-context", context_json])
    # 默认加载 restricted-bash 扩展 (find/grep/cat 限源码目录)
    _ext = extension or "/opt/dataflow_vuln_scan/extensions/restricted-bash.ts"
    if _ext and os.path.exists(_ext):
        args.extend(["--extension", _ext])
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
    task_context: dict | None = None,
) -> dict[str, str]:
    merged: dict[str, str] = dict(os.environ)
    if env:
        merged.update(env)
    merged.setdefault("HOME", cwd)
    merged.setdefault("TMPDIR", os.path.join(cwd, "tmp"))
    if task_context:
        merged["DVS_TASK_CONTEXT"] = json.dumps(task_context, ensure_ascii=False)
    # Prepend venv bin (so python3 resolves to venv with tree-sitter installed)
    # then restricted tool wrappers (find/grep 只能在源码目录内搜索)
    _wrapper_dir = "/opt/dataflow_vuln_scan/bin/restricted"
    _venv_bin = "/opt/venv/bin"
    _prepend = []
    if os.path.isdir(_venv_bin) and _venv_bin not in (merged.get("PATH", "")):
        _prepend.append(_venv_bin)
    if os.path.isdir(_wrapper_dir):
        _prepend.append(_wrapper_dir)
    if _prepend:
        merged["PATH"] = ":".join(_prepend) + ":" + merged.get("PATH", "")
    return merged


# ─── Error classification ─────────────────────────────────────────────────────

def _is_fatal_error(result: AgentResult) -> bool:
    if result.fatal:
        return True
    if _is_context_overflow_error(result.error):
        return False
    error_text = (result.error or "").lower()
    fatal_patterns = [
        "model not found", "invalid model", "unknown model",
        "model does not exist", "unsupported model",
        "unauthorized", "invalid api key", "invalid llm key",
        "module not found", "no such file", "permission denied",
    ]
    return any(pattern in error_text for pattern in fatal_patterns)


def _is_retryable_api_error(result: AgentResult) -> bool:
    if result.fatal:
        return False
    error_text = (result.error or "").lower()
    # 404 / record not found 是永久错误 (模型/会话记录被删除), 重试无意义
    _NON_RETRYABLE_PATTERNS = [
        "404", "record not found", "not found",
        "model not found", "invalid model", "model does not exist",
    ]
    if any(p in error_text for p in _NON_RETRYABLE_PATTERNS):
        return False
    # 模型侧 stopReason=error (overloaded/internal/瞬时 API 错误): 当可重试。
    # 源码污点分析输入是代码, 无内容过滤风险; 瞬时错误退避重试即可恢复。
    if getattr(result, "stop_reason", "") == "error":
        return True
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
    has_401 = "401" in error_text
    has_key_err = any(p in error_text for p in ("unauthorized", "invalid llm key", "invalid api key", "invalid key"))
    return has_401 and has_key_err


def _is_pi_crash(result: AgentResult) -> bool:
    if result.exit_code < 0:
        return True
    error_text = (result.error or "").lower()
    crash_patterns = ["segmentation fault", "traceback", "signal",
                      "aborted", "core dumped"]
    return result.exit_code != 0 and any(p in error_text for p in crash_patterns)
