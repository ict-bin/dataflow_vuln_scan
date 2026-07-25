"""共享 LLM 重试例程 — 统一实现设计①②③④的三模式重试策略。

设计原则 (三模式 V2/DAG/自主 共用):
  ① 截断输出不全 (stop=length 或 stop=error 带部分输出) → 发"继续工作, 完整输出结论"
  ② 超时等可重试错误 (stop=error 无输出) → 回退到上一个 user 重发, 保留错误会话为 -error{N}
  ③ 不可重试错误 → 由 runner.py 外层 fatal 限界 (3 次) 后退出
  ④ 重试 retry_max 次依旧报错 → 先 compact 会话再重试一轮 (输出不全可能是会话超长导致)

调用契约:
  - 内层 run_agent 传 delegate_api_retry=True, 不再抢先重试 stop_reason=error,
    把结果 (带 stop_reason) 交回本例程统一处理。
  - parse_check 由各模式提供, 签名 (result, all_texts) -> (parsed|None, warn:str);
    warn 非空即视为本轮失败需重试。自主模式可用它检查 checkpoint。
  - error_session_fn(attempt) -> str|None 控制错误会话保存路径 (前端会过滤 -error{N} 不展示)。
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("dvs.llm_retry")


def _collect_all_texts(result: Any) -> list[str]:
    """收集 result.messages 里所有 assistant 文本片段 (output.output 只取最后一条)。"""
    texts: list[str] = []
    for msg in getattr(result, "messages", []) or []:
        if not isinstance(msg, dict) or msg.get("role") != "assistant":
            continue
        for c in (msg.get("content") or []):
            if isinstance(c, dict) and c.get("type") == "text" and (c.get("text") or "").strip():
                texts.append(c["text"])
    return texts


def _last_stop_reason(result: Any) -> str:
    """从 messages 取最后一条 assistant 的 stopReason。"""
    for msg in reversed(getattr(result, "messages", []) or []):
        if isinstance(msg, dict) and msg.get("role") == "assistant":
            return str(msg.get("stopReason", "") or "")
    return ""


def compact_session(
    session_file: str | None,
    *,
    model: str,
    tools: list[str],
    thinking_level: str,
    cwd: str,
    env: dict[str, str] | None,
    cancel_event: threading.Event | None = None,
    timeout_seconds: float | None = None,
) -> bool:
    """对 session 文件做一次 RPC compact (复用 runner._run_pi_compact)。"""
    from .runner import _run_pi_compact
    from .runner_helpers import _build_args, _find_pi_command
    if not session_file:
        return False
    try:
        pi_cmd = _find_pi_command()
        args = _build_args(pi_cmd, model, tools or [], thinking_level,
                           session_file, no_session=False)
        return _run_pi_compact(args=args, cwd=cwd, env=env,
                               cancel_event=cancel_event, timeout_seconds=timeout_seconds)
    except Exception:
        logger.exception("compact_session failed session=%s", session_file)
        return False


# ① 截断继续的提示词
_CONTINUE_PROMPT = (
    "继续你刚才未完成的工作，只输出剩余部分，不要重复已输出内容。"
    "如果你刚才已经输出了 JSON，请重新完整输出该 JSON。"
)

# ①' 空输出重试提示词 (stop=stop 但无文本, 模型只产生了 thinking 没输出正文)
_EMPTY_OUTPUT_PROMPT = (
    "你的上一轮回复没有文本输出。请直接输出 DAG JSON，不要使用思维链。"
    "按系统提示词要求，输出顶层唯一一个 ```json 块。"
)


def run_agent_with_design_retry(
    prompt: str,
    *,
    # ── run_agent 透传 ──
    model: str,
    tools: list[str],
    system_prompt: str = "",
    cwd: str = ".",
    env: dict[str, str] | None = None,
    thinking_level: str = "off",
    session_file: str | None = None,
    cancel_event: threading.Event | None = None,
    on_stream: Callable[[str], None] | None = None,
    post_skill_prompt: str | None = None,
    run_timeout_seconds: float | int = 3600,
    timeout_retry_enabled: bool = True,
    timeout_max_retries: int = 3,
    pi_max_retries: int = -1,
    pi_retry_delay: float = 10.0,
    retry_prompt: str | None = None,
    extension: str | None = None,
    task_context: dict[str, object] | None = None,
    # ── 设计重试参数 ──
    parse_check: Callable[[Any, list[str]], tuple[Any, str]] | None,
    rollback_session: str | None,            # 回退源 (fork 的 base_session); None=unlink 重建
    error_session_fn: Callable[[int], str | None] | None,  # (attempt)->error{N} 路径
    on_event: Callable[..., None] | None = None,           # SwarmEvent 上报
    on_result: Callable[[str, Any, dict], None] | None = None,  # agent-runtime 观测 (stage, result, extra)
    label: str = "",                                        # 事件标签 (函数名等)
    retry_max: int = 3,
    compact_then_retry: bool = True,
) -> tuple[Any, Any]:
    """返回 (result, parsed)。失败时 parsed 可能为 None, 由调用方判 taint_failed/raise。"""
    from .runner import run_agent
    from .copy_utils import safe_copyfile

    def _emit(etype: str, **payload):
        if on_event is not None:
            try:
                on_event(etype, **payload)
            except Exception:
                logger.exception("on_event emit failed type=%s", etype)

    def _emit_runtime(stage: str, result: Any, extra: dict):
        if on_result is not None:
            try:
                on_result(stage, result, extra)
            except Exception:
                logger.exception("on_result emit failed stage=%s", stage)

    attempt = 0
    cycle_fails = 0
    compacted = False
    ever_had_partial = False  # 是否出现过部分输出 (用于判断 compact 是否有意义)
    cur_prompt = prompt
    result = None
    parsed = None
    warn = ""

    while True:
        if cancel_event is not None and cancel_event.is_set():
            break
        result = run_agent(
            prompt=cur_prompt,
            delegate_api_retry=True,
            model=model, tools=tools, system_prompt=system_prompt, cwd=cwd, env=env,
            thinking_level=thinking_level, session_file=session_file,
            cancel_event=cancel_event, on_stream=on_stream,
            post_skill_prompt=post_skill_prompt,
            run_timeout_seconds=run_timeout_seconds,
            timeout_retry_enabled=timeout_retry_enabled,
            timeout_max_retries=timeout_max_retries,
            pi_max_retries=pi_max_retries, pi_retry_delay=pi_retry_delay,
            retry_prompt=retry_prompt, extension=extension, task_context=task_context,
        )
        all_texts = _collect_all_texts(result)
        _emit_runtime(("llm_continue" if cur_prompt is _CONTINUE_PROMPT else
                       ("llm_retry" if attempt > 0 else "llm_call")), result,
                      {"label": label, "attempt": attempt})
        # 设计③: run_agent 内层已对 fatal (model not found / 401 等) 重试 _FATAL_RETRY_MAX
        # 次后返回 result.fatal=True; 此类不可重试错误不再走设计重试烧预算, 直接退出。
        if getattr(result, "fatal", False):
            _emit("llm_fatal_no_retry", label=label, reason=str(result.error or "")[:200])
            break
        if parse_check is not None:
            try:
                parsed, warn = parse_check(result, all_texts)
            except Exception as exc:
                logger.debug("parse_check raised: %s", exc, exc_info=True)
                parsed, warn = None, f"parse_check raised: {exc}"
        else:
            parsed, warn = None, ""
        if not warn:
            break  # 本轮成功 (或无需按 parse 重试)

        attempt += 1
        cycle_fails += 1
        stop_reason = _last_stop_reason(result)
        _emit("llm_retry_json", label=label, attempt=attempt, reason=warn, stop_reason=stop_reason)

        # 保存错误会话 -error{N} (前端过滤不展示); attempt 单调递增避免覆盖
        if error_session_fn is not None and session_file:
            try:
                _err = error_session_fn(attempt)
                if _err:
                    safe_copyfile(session_file, _err)
            except OSError:
                logger.warning(
                    "llm_retry: failed to copy error session label=%s attempt=%s session=%s",
                    label,
                    attempt,
                    session_file,
                    exc_info=True,
                )

        # ④ 本轮 compact 周期重试预算用尽 → compact 一次再开新一轮
        # (仅当出现过部分输出才 compact; 全空输出不是 context overflow, compact 无用)
        if cycle_fails >= retry_max:
            if compact_then_retry and not compacted and ever_had_partial:
                _emit("llm_compact_retry", label=label,
                      reason=f"{retry_max} retries failed, compact then retry once")
                compact_session(session_file, model=model, tools=tools,
                                thinking_level=thinking_level, cwd=cwd, env=env,
                                cancel_event=cancel_event,
                                timeout_seconds=float(run_timeout_seconds or 3600))
                compacted = True
                cycle_fails = 0     # 重置本轮预算 (attempt 不重置, error 会话编号继续递增)
                cur_prompt = prompt  # compact 后重发原始 prompt
                continue
            _emit("llm_retry_failed", label=label,
                  attempt=attempt, reason=warn, compacted=compacted)
            break  # compact 后仍失败 / 不允许 compact → 放弃

        # ① 截断输出不全 (length 或 error 带部分输出) → 继续工作
        has_partial = bool(all_texts)
        if has_partial:
            ever_had_partial = True
        if stop_reason == "length" or (stop_reason == "error" and has_partial):
            _emit("llm_length_continue", label=label, stop_reason=stop_reason, attempt=attempt)
            cur_prompt = _CONTINUE_PROMPT
            continue

        # ①' 空输出 (stop=stop 但无文本, 模型只产生了 thinking 没输出正文)
        # → 不走 compact (不是 context overflow), 用专门提示词重试
        if not has_partial and stop_reason == "stop":
            _emit("llm_empty_output_retry", label=label, stop_reason=stop_reason, attempt=attempt)
            try:
                if session_file:
                    Path(session_file).unlink(missing_ok=True)
            except OSError:
                logger.warning(
                    "llm_retry: failed to remove empty-output session label=%s session=%s",
                    label,
                    session_file,
                    exc_info=True,
                )
            cur_prompt = _EMPTY_OUTPUT_PROMPT
            continue

        # ② 超时/无输出 → 回退到上一个 user, 重发原始 prompt
        _emit("llm_rollback", label=label,
              stop_reason=stop_reason or "(empty)", attempt=attempt,
              rollback_target="original_prompt", resend_user_count=attempt)
        try:
            if rollback_session and Path(rollback_session).exists():
                safe_copyfile(rollback_session, session_file)
            elif session_file:
                Path(session_file).unlink(missing_ok=True)
        except OSError:
            logger.warning(
                "llm_retry: rollback session restore failed label=%s rollback=%s session=%s",
                label,
                rollback_session,
                session_file,
                exc_info=True,
            )
        cur_prompt = prompt

    return result, parsed, warn
