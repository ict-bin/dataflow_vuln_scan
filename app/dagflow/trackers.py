"""dagflow tracker 统一调度 (escape + indirect)。

设计: docs/design-taint-analysis.md §9.3。orchestrator 的 escape_track/indirect_track 项 -> 此调度。
reader_finder / function_resolver 由 pipeline 注入 (生产=LLM+v2_db, 测试=stub)。
"""
from __future__ import annotations
import logging
from typing import Callable, Any
from . import escape_tracker, indirect_tracker
from .dag_store import DagflowStore

logger = logging.getLogger("dvs.dagflow.trackers")


class TrackerDispatcher:
    """escape/indirect tracker 项调度。注入 reader_finder + function_resolver。"""

    def __init__(self, *, store: DagflowStore, func_lookup: Callable[[str], Any],
                 on_enqueue: Callable[[str, str], None], on_event: Any = None,
                 reader_finder: Callable[[dict], list[str]] | None = None,
                 function_resolver: Callable[[str, str], list[str]] | None = None,
                 func_lookup_by_id: Callable[[str], Any] | None = None) -> None:
        self.store = store
        self.func_lookup = func_lookup
        self.func_lookup_by_id = func_lookup_by_id or func_lookup
        self.on_enqueue = on_enqueue
        self.on_event = on_event
        self.reader_finder = reader_finder
        self.function_resolver = function_resolver

    def handle_escape(self, *, origin_func: str, origin_taint: str, origin_node: int,
                      origin_edge: str) -> int:
        return escape_tracker.resolve(
            self.store, origin_func=origin_func, origin_taint=origin_taint,
            origin_node=origin_node, origin_edge=origin_edge,
            reader_finder=self.reader_finder, func_lookup=self.func_lookup,
            func_lookup_by_id=self.func_lookup_by_id,
            on_enqueue=self.on_enqueue, on_event=self.on_event)

    def handle_indirect(self, *, origin_func: str, origin_taint: str, origin_node: int,
                        origin_edge: str) -> int:
        return indirect_tracker.resolve(
            self.store, origin_func=origin_func, origin_taint=origin_taint,
            origin_node=origin_node, origin_edge=origin_edge,
            function_resolver=self.function_resolver, func_lookup=self.func_lookup,
            func_lookup_by_id=self.func_lookup_by_id,
            on_enqueue=self.on_enqueue, on_event=self.on_event)
