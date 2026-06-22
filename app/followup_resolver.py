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
    # 非局部/容器污点的读取者搜索已从“解析失败分支”解耦（Bug A 修复）：
    # 改由 orchestrator 调用 collect_trackable_nonlocals + 独立触发 nonlocal tracker 统一负责，
    # 不再受“callee 是否解析成功”影响。这里只保留 function_pointer 类（确实依赖“名字解析不出来”才触发）。
    return ResolutionResult()


def default_followup_resolver() -> FollowupResolver:
    resolver = FollowupResolver()
    resolver.register_tracker(classify_tracker_need, priority=100)
    return resolver


_TRACKABLE_NONLOCAL_KINDS = {"global", "field", "static_local"}


def collect_trackable_nonlocals(callees) -> list[dict]:
    """聚合并按符号去重本函数所有 followup 上报的可追踪非局部污点符号。

    与 callee 是否解析无关 —— 用于驱动“常开”的非局部读取者搜索（Bug A 修复）。
    仅保留命名容器类符号（global/field/static_local）。
    """
    seen: dict[str, dict] = {}
    for c in (callees or []):
        for nl in (getattr(c, "tainted_nonlocal", None) or []):
            if not isinstance(nl, dict):
                continue
            sym = str(nl.get("symbol") or "").strip()
            kind = str(nl.get("kind") or "").strip()
            if sym and kind in _TRACKABLE_NONLOCAL_KINDS:
                seen.setdefault(sym, {"symbol": sym, "kind": kind, "evidence": str(nl.get("evidence") or "")})
    return list(seen.values())
