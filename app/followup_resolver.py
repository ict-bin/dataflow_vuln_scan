"""Extensible followup resolution primitives for DVS.

This module keeps followup resolution decisions in small handlers so new
program-specific cases can be added without growing the orchestrator loop.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .models import CalleeRef


@dataclass
class ResolutionContext:
    source_root: str
    funcdb_path: str = ""
    cache_root: str = ""
    graph_db_path: Path | None = None
    caller_func: str = ""
    caller_file: str = ""
    line_hint: str = ""
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass
class ResolutionResult:
    handled: bool = False
    resolved: bool = False
    callee: CalleeRef | None = None
    reason: str = ""
    needs_tracker: bool = False
    tracker_type: str = ""
    tracker_context: dict[str, Any] = field(default_factory=dict)


FollowupHandler = Callable[[CalleeRef, ResolutionContext], ResolutionResult]


class FollowupResolver:
    """Registry-backed followup resolver.

    Handlers run in priority order. A handler returns handled=True when it owns
    the decision; otherwise the next handler gets a chance. Tracker handlers are
    intentionally separate so deterministic resolution remains the first path.
    """

    def __init__(self) -> None:
        self._direct: list[tuple[int, FollowupHandler]] = []
        self._trackers: list[tuple[int, FollowupHandler]] = []

    def register_direct(self, handler: FollowupHandler, *, priority: int = 100) -> None:
        self._direct.append((priority, handler))
        self._direct.sort(key=lambda item: item[0])

    def register_tracker(self, handler: FollowupHandler, *, priority: int = 100) -> None:
        self._trackers.append((priority, handler))
        self._trackers.sort(key=lambda item: item[0])

    def resolve_direct(self, callee: CalleeRef, ctx: ResolutionContext) -> ResolutionResult:
        for _, handler in self._direct:
            result = handler(callee, ctx)
            if result.handled:
                return result
        return ResolutionResult(handled=False, reason="no_direct_handler")

    def resolve_tracker(self, callee: CalleeRef, ctx: ResolutionContext) -> ResolutionResult:
        for _, handler in self._trackers:
            result = handler(callee, ctx)
            if result.handled or result.needs_tracker:
                return result
        return ResolutionResult(handled=False, reason="no_tracker_handler")

    def resolve(self, callee: CalleeRef, ctx: ResolutionContext) -> ResolutionResult:
        direct = self.resolve_direct(callee, ctx)
        if direct.handled:
            return direct
        tracker = self.resolve_tracker(callee, ctx)
        if tracker.handled or tracker.needs_tracker:
            return tracker
        return direct


def classify_tracker_need(callee: CalleeRef, ctx: ResolutionContext) -> ResolutionResult:
    """Default tracker classifier used by the first LLM-tracker integration.

    It only classifies; executing the tracker is handled by tracker.py so future
    tracker types can reuse the same registry contract.
    """
    dispatch = (callee.dispatch_kind or "").strip().lower()
    if dispatch in {"function_pointer", "vtable_dispatch", "hook_callback", "callback", "dynamic_dispatch"}:
        return ResolutionResult(
            handled=True,
            needs_tracker=True,
            tracker_type="function_pointer",
            tracker_context={
                "dispatch_kind": dispatch,
                "callee_function": callee.function_name,
                "callee_file": callee.file,
                "callee_line": callee.line,
                "tainted_params": callee.tainted_params,
                "description": callee.description,
                "caller_func": ctx.caller_func,
                "caller_file": ctx.caller_file,
            },
        )
    if callee.tainted_nonlocal:
        return ResolutionResult(
            handled=True,
            needs_tracker=True,
            tracker_type="nonlocal",
            tracker_context={
                "tainted_nonlocal": callee.tainted_nonlocal,
                "callee_function": callee.function_name,
                "callee_file": callee.file,
                "callee_line": callee.line,
                "tainted_params": callee.tainted_params,
                "description": callee.description,
                "caller_func": ctx.caller_func,
                "caller_file": ctx.caller_file,
            },
        )
    return ResolutionResult()


def default_followup_resolver() -> FollowupResolver:
    resolver = FollowupResolver()
    resolver.register_tracker(classify_tracker_need, priority=100)
    return resolver
