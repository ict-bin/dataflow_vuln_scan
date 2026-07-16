"""
dataflow_vuln_scan — Agent subprocess executor (sync, thread-based)

No async/await. Uses subprocess.Popen + threading for parallel I/O.
Helper utilities are in runner_helpers.py.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Optional

from .models import TokenUsage

from .runner_helpers import (
    AgentResult,
    PiFatalError,
    TaskCancelledError,
    _PiProcessError,
    _backoff,
    _build_agent_env,
    _build_args,
    _cmd_preview,
    _estimate_tokens,
    _fmt_max,
    _format_context_overflow_failure,
    _is_context_overflow_error,
    _is_fatal_error,
    _is_pi_crash,
    _is_retryable_api_error,
    _is_retryable_query_engine_401_error,
    _log_error,
    _log_info,
    _log_warn,
    _model_context_window,
    _normalize_timeout_seconds,
    _parse_context_overflow_details,
    _preflight_context_token_limit,
    _single_input_token_estimate,
    _sleep_with_cancel,
    _terminate_pi_process_tree,
    _write_temp_markdown,
    _find_pi_command,
    _resolve_pi_model,
    _should_emit_api_retry_event,
    _should_emit_infinite_retry_event,
    _should_retry,
    _mark_infinite_retry,
)

logger = logging.getLogger("dvs.runner")

_MAX_BACKOFF = 300
_QUERY_ENGINE_401_MAX_RETRIES = 3
_DEFAULT_CONTEXT_WINDOW = 128_000
_SINGLE_INPUT_CONTEXT_RATIO = 0.75
_PROMPT_TOKEN_OVERHEAD = 128
# Compaction 不再发 user 消息, 用 RPC compact 命令 (见 _run_pi_compact)

_FATAL_PATTERNS: list[list[str]] = [
    ["model not found"],
    ["unauthorized"],
    ["invalid api key"],
    ["module not found"],
]
_RATE_LIMIT_PATTERNS = ["rate limit", "too many requests", "429"]
_RATE_LIMIT_EXTRA_DELAY = 30.0


def _should_emit_rate_limit_event(streak: int) -> bool:
    streak = max(0, int(streak or 0))
    return streak == 1 or (streak > 0 and streak % 10 == 0)


# ─── Compaction via RPC compact command ─────────────────────────────────────

def _run_pi_compact(
    *,
    args: list[str],
    cwd: str,
    env: dict[str, str] | None,
    cancel_event: threading.Event | None = None,
    timeout_seconds: float | None = None,
) -> bool:
    """用 pi RPC compact 命令压缩 session, 不发 user 消息。

    发送 {"type": "compact"} RPC 命令, 等待 compaction_end 事件。
    返回 True 表示压缩成功。
    """
    from .runner_helpers import _terminate_pi_process_tree
    compact_timeout = min(timeout_seconds or 900, 900)  # 最多 15 分钟
    try:
        proc = subprocess.Popen(
            args, cwd=cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.PIPE, start_new_session=True,
        )
    except OSError as e:
        _log_warn(f"compact: failed to start pi process: {e}")
        return False

    try:
        _log_info(f"started pi compact process pid={proc.pid}")
        # 发 RPC compact 命令
        compact_cmd = json.dumps({"type": "compact"}, ensure_ascii=False) + "\n"
        proc.stdin.write(compact_cmd.encode("utf-8"))
        proc.stdin.flush()

        # 读 stdout 找 compaction_end (用 select 非阻塞读, 保证 deadline 生效)
        import select
        compact_success = False
        deadline = time.monotonic() + compact_timeout
        buf = b""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _log_warn("compact: timeout waiting for compaction_end")
                break
            if cancel_event and cancel_event.is_set():
                _log_warn("compact: cancelled")
                break
            # select 带超时, 避免 readline 永久阻塞 (pi compact 挂起时 deadline 才能生效)
            rlist, _, _ = select.select([proc.stdout], [], [], min(remaining, 1.0))
            if not rlist:
                # 无数据: 检查进程是否已退出
                if proc.poll() is not None:
                    break
                continue
            chunk = proc.stdout.readline(1)
            if not chunk:
                if proc.poll() is not None:
                    break
                continue
            buf += chunk
            if b"\n" not in buf:
                continue
            line, buf = buf.split(b"\n", 1)
            decoded = line.decode("utf-8", errors="replace").strip()
            if not decoded:
                continue
            try:
                evt = json.loads(decoded)
            except json.JSONDecodeError:
                continue
            evt_type = evt.get("type", "")
            if evt_type == "compaction_end":
                aborted = evt.get("aborted", False)
                result_data = evt.get("result")
                compact_success = not aborted and result_data is not None
                if compact_success:
                    after = result_data.get("estimatedTokensAfter", "?") if isinstance(result_data, dict) else result_data
                    _log_info(f"compact: success, estimated tokens after: {after}")
                else:
                    err = evt.get("errorMessage", "unknown")
                    _log_warn(f"compact: failed or aborted: {err}")
                break
            if evt_type == "agent_end":
                break

        # 关 stdin 让 pi 退出
        if proc.stdin and not proc.stdin.closed:
            try:
                proc.stdin.close()
            except Exception:
                pass
        proc.wait(timeout=10)
        return compact_success
    except Exception as e:
        _log_warn(f"compact: exception: {e}")
        return False
    finally:
        _terminate_pi_process_tree(proc, reason="compact_done")


# ─── Context overflow recovery ────────────────────────────────────────────────

def _run_with_context_overflow_recovery(
    *,
    pi_cmd: list[str],
    args: list[str],
    prompt: str,
    system_prompt: str,
    post_skill_prompt: str | None,
    model: str,
    tools: list[str],
    thinking_level: str,
    session_file: str | None,
    cwd: str,
    env: dict[str, str] | None,
    on_stream: Callable[[str], None] | None,
    cancel_event: threading.Event | None,
    max_retries: int,
    retry_delay: float,
    pi_max_retries: int,
    pi_retry_delay: float,
    timeout_seconds: float | None = None,
    agent_role: str | None = None,
    runtime_dir: str | None = None,
    retry_prompt: str | None = None,
) -> AgentResult:
    context_window = _model_context_window(model)
    overflow_attempts = 0
    fatal_attempts = 0
    _MAX_COMPACT_RETRIES = int(os.environ.get("DVS_MAX_COMPACT_RETRIES", "5"))
    while True:
        if overflow_attempts >= _MAX_COMPACT_RETRIES:
            _log_warn(f"compact 重试达上限 {_MAX_COMPACT_RETRIES}, 放弃 (避免死循环)")
            fail_result = AgentResult()
            fail_result.agent_role = agent_role
            fail_result.runtime_dir = runtime_dir
            fail_result.context_window = context_window
            fail_result.context_overflow_failed_after_compaction = True
            fail_result.compaction_requested = True
            fail_result.error = _format_context_overflow_failure(
                model, system_prompt, prompt, post_skill_prompt, "compact_retry_exhausted",
            )
            return fail_result
        preflight_limit = _preflight_context_token_limit(context_window, 0)
        single_input_tokens = _single_input_token_estimate(system_prompt, prompt, post_skill_prompt)
        if single_input_tokens > preflight_limit:
            if not session_file:
                preflight_result = AgentResult()
                preflight_result.agent_role = agent_role
                preflight_result.runtime_dir = runtime_dir
                preflight_result.context_window = context_window
                preflight_result.context_budget_exceeded_preflight = True
                preflight_result.context_overflow_failed_after_compaction = True
                preflight_result.error = _format_context_overflow_failure(
                    model, system_prompt, prompt, post_skill_prompt, "preflight_context_length_exceeded",
                )
                return preflight_result
            compaction_args = _build_args(pi_cmd, model, tools, thinking_level, session_file, no_session=(session_file is None))
            _run_pi_compact(
                args=compaction_args,
                cwd=cwd,
                env=env,
                cancel_event=cancel_event,
                timeout_seconds=timeout_seconds,
            )
            overflow_attempts += 1
            continue
        result = _run_with_pi_retry(
            args=args,
            cwd=cwd,
            env=env,
            prompt=prompt,
            post_skill_prompt=post_skill_prompt,
            cancel_event=cancel_event,
            on_stream=on_stream,
            max_retries=max_retries,
            retry_delay=retry_delay,
            pi_max_retries=pi_max_retries,
            pi_retry_delay=pi_retry_delay,
            timeout_seconds=timeout_seconds,
            retry_prompt=retry_prompt,
        )
        result.agent_role = agent_role
        result.runtime_dir = runtime_dir
        result.context_window = context_window
        if not _is_context_overflow_error(result.error):
            if overflow_attempts > 0:
                result.compaction_requested = True
                result.compaction_completed = True
                result.context_overflow_retrying = True
                result.context_overflow_retry_count = overflow_attempts
                result.context_overflow_retry_event_due = _should_emit_infinite_retry_event(overflow_attempts)
            return result
        overflow = _parse_context_overflow_details(result.error)
        context_window = overflow.get("context_length") or _model_context_window(model)
        proxy_reserved_tokens = overflow.get("proxy_reserved_tokens", 0)
        result.context_window = context_window
        result.proxy_reserved_tokens = proxy_reserved_tokens
        if not session_file:
            result.context_overflow_failed_after_compaction = True
            return result
        overflow_attempts += 1
        result.compaction_requested = True
        result.compaction_completed = True
        result.context_overflow_retrying = True
        result.context_overflow_retry_count = overflow_attempts
        result.context_overflow_retry_event_due = _should_emit_infinite_retry_event(overflow_attempts)
        if result.context_overflow_retry_event_due:
            _log_warn(f"overflow 无限压缩重试 [{overflow_attempts}], 继续重试: {(result.error or '')[:200]}")
        compaction_args = _build_args(pi_cmd, model, tools, thinking_level, session_file, no_session=(session_file is None))
        _run_pi_compact(
            args=compaction_args,
            cwd=cwd,
            env=env,
            cancel_event=cancel_event,
            timeout_seconds=timeout_seconds,
        )
        continue


# ─── Public interface ─────────────────────────────────────────────────────────

def run_agent(
    prompt: str,
    *,
    model: str,
    tools: list[str],
    system_prompt: str = "",
    cwd: str = ".",
    env: dict[str, str] | None = None,
    thinking_level: str = "off",
    session_file: str | None = None,
    on_stream: Callable[[str], None] | None = None,
    cancel_event: threading.Event | None = None,
    post_skill_prompt: str | None = None,
    max_retries: int = 3,
    retry_delay: float = 10.0,
    run_timeout_seconds: float | int = 3600,
    timeout_retry_enabled: bool = True,
    timeout_max_retries: int = 3,
    pi_max_retries: int = -1,
    pi_retry_delay: float = 10.0,
    task_context: dict[str, object] | None = None,
    retry_prompt: str | None = None,
    extension: str | None = None,
) -> AgentResult:
    """Run a single pi Agent subprocess (double-layer retry + fatal error detection).

    retry_prompt: 重试时 (pi 崩溃/idle-timeout) 发的提示, 替代原始 prompt。
    自主模式用 '继续从上次中断处探索' 而非重发 entry (避免 agent 重新从头)。"""
    # DRYRUN mode
    if os.environ.get('DRYRUN') == '1':
        from .dryrun import run_agent_dryrun as _dr
        return _dr(prompt, cwd=cwd, session_file=session_file,
                   post_skill_prompt=post_skill_prompt, on_stream=on_stream)

    task_context = task_context or {}

    if cancel_event and cancel_event.is_set():
        r = AgentResult()
        r.error = "cancelled"
        r.exit_code = -1
        return r

    try:
        pi_cmd = _find_pi_command()
    except FileNotFoundError as e:
        _log_error(f"pi executable not found: {e}")
        r = AgentResult()
        r.error = str(e)
        r.exit_code = -1
        r.fatal = True
        return r

    model = _resolve_pi_model(model)
    args = _build_args(pi_cmd, model, tools, thinking_level, session_file, extension=extension, no_session=(session_file is None))
    cwd = os.path.abspath(cwd)
    env = _build_agent_env(cwd=cwd, env=env, task_context=task_context)

    if system_prompt.strip():
        _sp_path = os.path.join(os.path.abspath(cwd), ".system_prompt.md")
        try:
            Path(_sp_path).write_text(system_prompt, encoding="utf-8")
            args.extend(["--system-prompt", _sp_path])
        except OSError:
            pass

    timeout_seconds = _normalize_timeout_seconds(run_timeout_seconds)
    timeout_failures = 0
    _attempt = 0

    while True:
        _attempt += 1
        # 重试 (attempt>1) 用 retry_prompt 而非原始 prompt (自主模式: 续探而非重发 entry)
        _eff_prompt = (retry_prompt or prompt) if _attempt > 1 else prompt
        try:
            return _run_with_context_overflow_recovery(
                pi_cmd=pi_cmd, args=args, prompt=_eff_prompt,
                system_prompt=system_prompt, post_skill_prompt=post_skill_prompt,
                model=model, tools=tools, thinking_level=thinking_level,
                session_file=session_file, cwd=cwd, env=env,
                cancel_event=cancel_event, on_stream=on_stream,
                max_retries=max_retries, retry_delay=retry_delay,
                pi_max_retries=pi_max_retries, pi_retry_delay=pi_retry_delay,
                timeout_seconds=timeout_seconds,
                agent_role=str(task_context.get("agent_role") or "").strip() or None,
                runtime_dir=str(task_context.get("task_pi_dir") or "").strip() or None,
                retry_prompt=retry_prompt,
            )
        except TimeoutError:
            timeout_failures += 1
            r = AgentResult()
            r.error = (
                f"agent step idle timed out after {timeout_seconds:.0f}s"
                if timeout_seconds else "agent step idle timed out"
            )
            r.exit_code = -1
            can_retry = timeout_retry_enabled and (
                timeout_max_retries < 0 or timeout_failures <= timeout_max_retries
            )
            if not can_retry or (cancel_event and cancel_event.is_set()):
                return r
            delay = _backoff(retry_delay, timeout_failures)
            if on_stream:
                on_stream(
                    f"\n⏱️ Agent idle timeout, retry in {delay:.0f}s "
                    f"({timeout_failures}/{_fmt_max(timeout_max_retries)})...\n"
                )
            if _sleep_with_cancel(delay, cancel_event):
                r.error = "cancelled during timeout backoff"
                return r


# ─── Outer layer: pi process-level retry ──────────────────────────────────────

def _run_with_pi_retry(
    *,
    args: list[str],
    cwd: str,
    env: dict[str, str] | None = None,
    prompt: str,
    post_skill_prompt: str | None = None,
    cancel_event: threading.Event | None,
    on_stream: Callable[[str], None] | None,
    max_retries: int,
    retry_delay: float,
    pi_max_retries: int,
    pi_retry_delay: float,
    timeout_seconds: float | None = None,
    retry_prompt: str | None = None,
) -> AgentResult:
    """Outer loop: handle pi process launch failures, crashes, fatal errors."""
    if not os.path.isdir(cwd):
        _log_error(f"cwd directory does not exist (unretryable): {cwd}")
        r = AgentResult()
        r.error = f"cwd directory does not exist: {cwd}"
        r.exit_code = -1
        r.fatal = True
        return r

    pi_attempt = 0
    fatal_retry_count = 0
    _pi_round = 0

    while True:
        _pi_round += 1
        if cancel_event and cancel_event.is_set():
            r = AgentResult()
            r.error = "cancelled"
            return r

        # 重试 (_pi_round>1) 用 retry_prompt 而非原始 prompt (自主模式续探)
        _eff_prompt = (retry_prompt or prompt) if _pi_round > 1 else prompt
        try:
            result = _run_with_api_retry(
                args=args, cwd=cwd, env=env, prompt=_eff_prompt,
                post_skill_prompt=post_skill_prompt,
                cancel_event=cancel_event, on_stream=on_stream,
                max_retries=max_retries, retry_delay=retry_delay,
                timeout_seconds=timeout_seconds,
            )

            if _is_fatal_error(result) or result.fatal:
                fatal_retry_count += 1
                reason = str(result.error or "").strip() or "fatal error"
                # Key/auth errors (401/unauthorized/invalid key): fail after 3 attempts, don't retry infinitely
                _err_lower = reason.lower()
                _is_key_error = any(p in _err_lower for p in ("unauthorized", "invalid api key", "invalid llm key", "401"))
                if _is_key_error and fatal_retry_count >= 3:
                    result.fatal = True
                    result.error = f"Key/auth error after {fatal_retry_count} attempts: {reason}"
                    _log_error(f"key/auth error exhausted after {fatal_retry_count} attempts, giving up: {reason[:200]}")
                    return result
                _mark_infinite_retry(result, kind="fatal", count=fatal_retry_count, reason=reason)
                _log_warn(f"pi infrastructure error [{fatal_retry_count}/inf], retry in 30s: {reason[:200]}")
                if on_stream:
                    on_stream("\n⚠️ PI infrastructure error, retry in 30s...\n")
                if _sleep_with_cancel(30.0, cancel_event):
                    return result
                continue

            if _is_pi_crash(result):
                raise _PiProcessError(
                    f"exit_code={result.exit_code}: "
                    f"{result.error or '(no error message)'}"
                )

            return result

        except (OSError, FileNotFoundError, PermissionError, _PiProcessError) as exc:
            pi_attempt += 1
            label = f"{pi_attempt}/{_fmt_max(pi_max_retries)}"

            if cancel_event and cancel_event.is_set():
                r = AgentResult()
                r.error = f"cancelled after pi error: {exc}"
                return r

            err_lower = str(exc).lower()
            fatal_handled = False
            for pattern in _FATAL_PATTERNS:
                if all(p in err_lower for p in pattern):
                    fatal_retry_count += 1
                    r = AgentResult()
                    r.error = str(exc)
                    r.exit_code = -1
                    _mark_infinite_retry(r, kind="fatal", count=fatal_retry_count, reason=str(exc))
                    _log_warn(f"pi infrastructure error [{fatal_retry_count}/inf], retry in 30s: {exc}")
                    if on_stream:
                        on_stream("\n⚠️ PI infrastructure error, retry in 30s...\n")
                    if _sleep_with_cancel(30.0, cancel_event):
                        return r
                    fatal_handled = True
                    break
            if fatal_handled:
                continue

            if _should_retry(attempt=pi_attempt, max_retries=pi_max_retries,
                             cancel_event=cancel_event):
                delay = _backoff(pi_retry_delay, pi_attempt)
                _log_warn(
                    f"pi process failed [{label}], retry in {delay:.0f}s: {exc}\n"
                    f"    command: {_cmd_preview(args)}"
                )
                if on_stream:
                    on_stream(
                        f"\n❌ pi process failed, retry in {delay:.0f}s ({label})...\n"
                    )
                if _sleep_with_cancel(delay, cancel_event):
                    r = AgentResult()
                    r.error = f"cancelled during pi retry backoff: {exc}"
                    return r
                continue
            else:
                _log_error(f"pi process retries exhausted [{label}]: {exc}")
                r = AgentResult()
                r.exit_code = -1
                r.error = f"pi process failed after {pi_attempt} retries: {exc}"
                return r


# ─── Inner layer: API-level retry (subprocess I/O with threads) ───────────────


def _run_with_api_retry(
    *,
    args: list[str],
    cwd: str,
    env: dict[str, str] | None = None,
    prompt: str,
    post_skill_prompt: str | None = None,
    cancel_event: threading.Event | None,
    on_stream: Callable[[str], None] | None,
    max_retries: int,
    retry_delay: float,
    timeout_seconds: float | None = None,
) -> AgentResult:
    """Inner loop: launch pi subprocess via subprocess.Popen, threaded stdout/stderr reading."""
    api_attempt = 0
    query_engine_401_failures = 0
    rate_limit_streak = 0
    process_launch_attempt = 0

    while True:
        process_launch_attempt += 1
        process_label = f"launch-{process_launch_attempt}"
        result = AgentResult()

        # Spawn subprocess synchronously
        try:
            proc = subprocess.Popen(
                args,
                cwd=cwd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as e:
            # When Popen fails (e.g. ENFILE/EMFILE "Too many open files"),
            # the OS may have already created pipe FDs before the exec
            # failure.  These orphan FDs leak because no proc object
            # exists to track them.  We cannot recover them here, but we
            # emit a high-visibility log to help diagnose.
            if getattr(e, "errno", None) in (23, 24):  # ENFILE / EMFILE
                _log_error(
                    "pi subprocess failed due to file descriptor exhaustion "
                    "(errno=%s). FD limit may need to be increased. "
                    "Error: %s",
                    e.errno, e,
                )
            raise

        _log_info(
            f"started pi process [{process_label}] pid={proc.pid} cwd={cwd}"
        )

        # Cancel monitor thread
        cancel_stop = threading.Event()
        cancel_thread = None
        if cancel_event:

            def _cancel_monitor():
                cancel_event.wait()
                if not cancel_stop.is_set():
                    _terminate_pi_process_tree(proc, reason="cancel_event")

            cancel_thread = threading.Thread(target=_cancel_monitor, daemon=True)
            cancel_thread.start()

        # Shared state for stdout reading thread
        agent_ended = False
        result_lock = threading.Lock()
        buffer_lock = threading.Lock()
        buffer = b""
        last_activity_at = time.monotonic()
        activity_lock = threading.Lock()

        def _mark_activity():
            nonlocal last_activity_at
            with activity_lock:
                last_activity_at = time.monotonic()

        def _check_timeout():
            if timeout_seconds and (time.monotonic() - last_activity_at) >= timeout_seconds:
                raise TimeoutError("agent idle timeout")

        # Thread: read stdout
        read_error = None

        def _read_stdout():
            nonlocal agent_ended, buffer, read_error
            try:
                assert proc.stdout is not None
                while True:
                    _check_timeout()
                    chunk = proc.stdout.read(4096)
                    if not chunk:
                        break
                    _mark_activity()
                    with buffer_lock:
                        buffer += chunk
                    while True:
                        with buffer_lock:
                            if b"\n" not in buffer:
                                break
                            line, buffer = buffer.split(b"\n", 1)
                        decoded = line.decode("utf-8", errors="replace")
                        ended = _process_line(decoded, result, on_stream, _mark_activity, result_lock)
                        if ended:
                            agent_ended = True
                            return
                        # When LLM completes, close stdin so pi exits and sends agent_end
                        if getattr(result, '_rpc_completed', False):
                            try:
                                if proc.stdin and not proc.stdin.closed:
                                    proc.stdin.close()
                            except Exception:
                                pass
                # Process remaining buffer
                with buffer_lock:
                    remaining = buffer
                    buffer = b""
                if remaining.strip():
                    _process_line(
                        remaining.decode("utf-8", errors="replace"),
                        result, on_stream, _mark_activity, result_lock,
                    )
            except TimeoutError:
                read_error = TimeoutError("agent idle timeout")
            except Exception as e:
                read_error = e

        stdout_thread = threading.Thread(target=_read_stdout, daemon=True, name="dvs-stdout")
        stdout_thread.start()

        try:
            assert proc.stdin is not None

            # Send initial prompt via RPC
            prompt_cmd = json.dumps(
                {"type": "prompt", "message": prompt}, ensure_ascii=False
            ) + "\n"
            proc.stdin.write(prompt_cmd.encode("utf-8"))
            proc.stdin.flush()

            # Wait for stdout reader to finish
            stdout_thread.join(timeout=timeout_seconds or 3600)

            if read_error is not None:
                if isinstance(read_error, TimeoutError):
                    _log_warn("agent stdout read timed out")
                    result.error = str(read_error)
                else:
                    _log_warn(f"agent stdout read error: {read_error}")
                    result.error = f"stdout read error: {read_error}"

            # Post-skill prompt (RPC second turn)
            if agent_ended and post_skill_prompt and proc.stdin and not proc.stdin.closed:
                try:
                    _skill_cmd = json.dumps(
                        {"type": "prompt", "message": post_skill_prompt}, ensure_ascii=False
                    ) + "\n"
                    proc.stdin.write(_skill_cmd.encode("utf-8"))
                    proc.stdin.flush()
                    # Start a second stdout reader thread for the post-skill response
                    _ps_buffer = b""
                    _ps_ended = False

                    def _read_post_skill():
                        nonlocal _ps_buffer, _ps_ended
                        try:
                            assert proc.stdout is not None
                            while True:
                                chunk = proc.stdout.read(4096)
                                if not chunk:
                                    break
                                _ps_buffer += chunk
                                while b"\n" in _ps_buffer:
                                    _l, _ps_buffer = _ps_buffer.split(b"\n", 1)
                                    if _process_line(
                                        _l.decode("utf-8", errors="replace"),
                                        result, on_stream, _mark_activity, result_lock,
                                    ):
                                        _ps_ended = True
                                        return
                                if _ps_ended:
                                    return
                        except Exception as _e:
                            logger.warning("unexpected error in runner.py: %s", _e, exc_info=True)

                    ps_thread = threading.Thread(target=_read_post_skill, daemon=True)
                    ps_thread.start()
                    ps_thread.join(timeout=180.0)
                except Exception as _se:
                    _log_warn(f"post_skill RPC second turn error (ignored): {_se}")

            # Drain remaining stdout
            if agent_ended:
                try:
                    if proc.stdout:
                        proc.stdout.read()
                except Exception as _e:
                    logger.warning("unexpected error in runner.py: %s", _e, exc_info=True)

            # Close stdin
            try:
                proc.stdin.close()
            except Exception as _e:
                logger.warning("unexpected error in runner.py: %s", _e, exc_info=True)

            # Read stderr
            try:
                if proc.stderr:
                    stderr_data = proc.stderr.read()
                    stderr_text = stderr_data.decode("utf-8", errors="replace").strip()
                    if stderr_text and not result.error:
                        result.error = stderr_text
            except Exception as _e:
                logger.warning("unexpected error in runner.py: %s", _e, exc_info=True)

            # Wait for process exit
            try:
                proc.wait(timeout=15.0)
                result.exit_code = proc.returncode or 0
            except subprocess.TimeoutExpired:
                _log_warn("pi process did not exit within 15s, force terminating")
                _terminate_pi_process_tree(proc, reason="exit_timeout")
                result.exit_code = -1

        except Exception as e:
            _log_warn(f"pi process read exception: {e}")
            result.error = f"pi process read error: {e}"
            result.exit_code = -1
            _terminate_pi_process_tree(proc, reason=f"read_exception:{type(e).__name__}")

        finally:
            cancel_stop.set()
            if cancel_thread:
                cancel_thread.join(timeout=2.0)
            _terminate_pi_process_tree(
                proc, reason="finally_cleanup",
            )
            # Belts-and-suspenders: explicitly close all pipes.
            # _terminate_pi_process_tree now also closes them, but double-close
            # is harmless and ensures no FD leaks if terminate throws.
            for _pipe_attr in ("stdout", "stderr", "stdin"):
                _pipe = getattr(proc, _pipe_attr, None)
                if _pipe is not None:
                    try:
                        _pipe.close()
                    except Exception:
                        pass

        # idle-timeout (read_error=TimeoutError) 必须传播到 run_agent 的 except TimeoutError -> 重试。
        # 之前被转成 result.error 返回 -> 重试循环拿不到 -> 不重试 (bug: 可重试错误不重试)。
        # 现在 raise 传播, run_agent 的 timeout_retry_enabled/max_retries 生效。
        if isinstance(read_error, TimeoutError):
            _log_warn(f"agent idle timeout after {timeout_seconds:.0f}s, propagating to run_agent retry loop")
            raise read_error

        # Extract output from messages
        for msg in reversed(result.messages):
            if msg.get("role") == "assistant":
                texts = [
                    c["text"]
                    for c in (msg.get("content") or [])
                    if c.get("type") == "text"
                ]
                result.output = "\n".join(texts)
                break

        if cancel_event and cancel_event.is_set():
            return result

        if _is_pi_crash(result):
            if result.error:
                _log_warn(f"pi process crashed (exit={result.exit_code}): {result.error[:300]}")
            return result

        if _is_fatal_error(result):
            return result

        # Query engine 401
        if _is_retryable_query_engine_401_error(result):
            query_engine_401_failures += 1
            if query_engine_401_failures <= _QUERY_ENGINE_401_MAX_RETRIES:
                delay = _backoff(retry_delay, query_engine_401_failures)
                label = f"{query_engine_401_failures}/{_QUERY_ENGINE_401_MAX_RETRIES}"
                _log_warn(f"query engine 401 [{label}], retry in {delay:.0f}s: {(result.error or '')[:200]}")
                if on_stream:
                    on_stream(f"\n⚠️ Query engine connection invalid, retry in {delay:.0f}s ({label})...\n")
                if _sleep_with_cancel(delay, cancel_event):
                    result.error = (result.error or "") + " [cancelled during query-engine retry backoff]"
                    return result
                continue
            _log_error(f"query engine 401 retries exhausted: {(result.error or '')[:200]}")
            result.error = (result.error or "") + f" [query engine 401 retries exhausted: {query_engine_401_failures} failures]"
            return result
        query_engine_401_failures = 0

        # API retryable error
        if _is_retryable_api_error(result):
            err_lower = (result.error or "").lower()
            is_rate_limit = any(p in err_lower for p in _RATE_LIMIT_PATTERNS)
            if is_rate_limit:
                rate_limit_streak += 1
                delay = _RATE_LIMIT_EXTRA_DELAY
                result.rate_limited = True
                result.consecutive_rate_limit_count = rate_limit_streak
                result.retry_delay_seconds = int(delay)
                result.rate_limit_event_due = _should_emit_rate_limit_event(rate_limit_streak)
                _log_warn(f"Rate limit error [streak={rate_limit_streak}], retry in {delay:.0f}s: {(result.error or '')[:200]}")
                if on_stream:
                    on_stream(f"\n⚠️ Rate limit error, retry in {delay:.0f}s (streak {rate_limit_streak})...\n")
                if _sleep_with_cancel(delay, cancel_event):
                    result.error = (result.error or "") + " [cancelled during api retry backoff]"
                    return result
                continue
            rate_limit_streak = 0
            api_attempt += 1
            can_retry = True
            if can_retry:
                delay = _backoff(retry_delay, api_attempt)
                result.retry_delay_seconds = int(delay)
                result.consecutive_api_retry_count = int(api_attempt)
                result.api_retry_reason = str(result.error or "").strip()[:500] or None
                result.api_retry_event_due = _should_emit_api_retry_event(api_attempt, delay)
                label = f"{api_attempt}/{_fmt_max(max_retries)}"
                _log_warn(f"API error [{label}], retry in {delay:.0f}s: {(result.error or '')[:200]}")
                if on_stream:
                    on_stream(f"\n⚠️ API error, retry in {delay:.0f}s ({label})...\n")
                if _sleep_with_cancel(delay, cancel_event):
                    result.error = (result.error or "") + " [cancelled during api retry backoff]"
                    return result
                continue

        # Non-zero exit with error
        if result.exit_code != 0 and result.error:
            err_lower = (result.error or "").lower()
            if any(p in err_lower for p in ("enobufs", "epipe", "broken pipe")):
                api_attempt += 1
                can_retry = (max_retries == -1) or (api_attempt <= max_retries)
                if can_retry:
                    delay = _backoff(retry_delay, api_attempt)
                    _log_warn(f"pipe error [{api_attempt}/{_fmt_max(max_retries)}], retry in {delay:.0f}s: {(result.error or '')[:200]}")
                    if _sleep_with_cancel(delay, cancel_event):
                        result.error = (result.error or "") + " [cancelled during pipe retry backoff]"
                        return result
                    continue
            _log_warn(f"pi exit code {result.exit_code} (has output, not retrying): {result.error[:200]}")

        return result


# ─── JSON Lines parsing ───────────────────────────────────────────────────────

def _process_line(
    line: str,
    result: AgentResult,
    on_stream: Callable[[str], None] | None,
    on_activity: Callable[[], None] | None = None,
    result_lock: threading.Lock | None = None,
) -> bool:
    """Parse one JSONL line. Returns True if agent_end received (caller should stop reading)."""
    line = line.strip()
    if not line:
        return False
    if on_activity:
        on_activity()
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return False

    etype = event.get("type")

    if etype in (
        "response", "session", "queue_update",
        "compaction_start", "compaction_end",
        "auto_retry_start", "auto_retry_end",
    ):
        return False

    if etype == "agent_end":
        return True

    if etype == "message_update":
        ae = event.get("assistantMessageEvent", {})
        if ae.get("type") == "text_delta" and on_stream:
            on_stream(ae.get("delta", ""))

    if etype == "message_end" and event.get("message"):
        msg = event["message"]

        def _append_msg():
            result.messages.append(msg)

        if result_lock:
            with result_lock:
                _append_msg()
        else:
            _append_msg()

        if msg.get("role") == "assistant":
            usage = msg.get("usage", {})

            def _update_usage():
                result.token_usage.input += usage.get("input", 0)
                result.token_usage.output += usage.get("output", 0)
                result.token_usage.cache_read += usage.get("cacheRead", 0)
                result.token_usage.cache_write += usage.get("cacheWrite", 0)
                cost = usage.get("cost", {})
                if isinstance(cost, dict):
                    result.token_usage.cost += cost.get("total", 0)
                elif isinstance(cost, (int, float)):
                    result.token_usage.cost += cost

            if result_lock:
                with result_lock:
                    _update_usage()
            else:
                _update_usage()

            if msg.get("stopReason") == "error":
                err_msg = msg.get("errorMessage", "Unknown error")
                if result_lock:
                    with result_lock:
                        result.error = err_msg
                        result.stop_reason = "error"
                else:
                    result.error = err_msg
                    result.stop_reason = "error"

            # RPC mode: when LLM completes (stop/end_turn/length/error), signal stdout
            # reader to close stdin so pi detects EOF and sends agent_end.
            stop_reason = msg.get("stopReason", "")
            if stop_reason in ("stop", "end_turn", "error", "length", "max_tokens"):
                result._rpc_completed = True

    return False


# ─── Parallel execution ───────────────────────────────────────────────────────

def run_agents_parallel(
    tasks: list[dict],
    concurrency: int = 4,
) -> list[AgentResult]:
    """Run multiple agents in parallel using ThreadPoolExecutor."""
    results: list[AgentResult | None] = [None] * len(tasks)

    def _run(index: int, kwargs: dict):
        results[index] = run_agent(**kwargs)

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(_run, i, t) for i, t in enumerate(tasks)]
        for future in futures:
            future.result()  # Wait for all to complete

    return results  # type: ignore[return-value]
