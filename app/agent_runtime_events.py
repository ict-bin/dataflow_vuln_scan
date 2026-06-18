from __future__ import annotations

from typing import Any, Callable


def emit_agent_runtime_events(
    emit: Callable[..., None],
    *,
    result: Any,
    stage: str,
    role: str,
    model: str,
    extra: dict[str, Any] | None = None,
) -> None:
    payload = dict(extra or {})
    payload.update(
        {
            "stage": stage,
            "role": role,
            "runtime_dir": str(getattr(result, "runtime_dir", "") or ""),
            "model": model,
            "context_window": int(getattr(result, "context_window", 0) or 0),
        }
    )
    proxy_reserved_tokens = int(getattr(result, "proxy_reserved_tokens", 0) or 0)
    if getattr(result, "compaction_requested", False):
        emit("task_context_compaction_requested", **payload)
    if getattr(result, "compaction_completed", False):
        emit("task_context_compaction_completed", **payload)
    if getattr(result, "context_budget_exceeded_preflight", False):
        emit(
            "task_context_budget_exceeded_preflight",
            proxy_reserved_tokens=proxy_reserved_tokens,
            error=str(getattr(result, "error", "") or ""),
            **payload,
        )
    if getattr(result, "fatal_retry_event_due", False):
        emit(
            "task_fatal_retrying",
            retry_delay_seconds=int(getattr(result, "retry_delay_seconds", 30) or 30),
            consecutive_fatal_retry_count=int(getattr(result, "consecutive_fatal_retry_count", 0) or 0),
            reason=str(getattr(result, "fatal_retry_reason", "") or ""),
            **payload,
        )
    if getattr(result, "context_overflow_retrying", False) and getattr(result, "context_overflow_retry_event_due", False):
        emit(
            "task_context_overflow_retrying",
            proxy_reserved_tokens=proxy_reserved_tokens,
            context_overflow_retry_count=int(getattr(result, "context_overflow_retry_count", 0) or 0),
            **payload,
        )
    if getattr(result, "context_overflow_failed_after_compaction", False):
        emit(
            "task_context_overflow_failed_after_compaction",
            proxy_reserved_tokens=proxy_reserved_tokens,
            error=str(getattr(result, "error", "") or ""),
            **payload,
        )
