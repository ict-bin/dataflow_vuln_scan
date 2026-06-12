"""Slot-based DFS scheduler for sequential followup execution.

When Worker analysis of function F completes, followups are split into two
groups by param_analyzer:

  P0 (needs_sequential):  at least one tainted param is a non-const
                          pointer/reference ── must run sequentially inside
                          the current Slot so validation state accumulates.

  P2 (isolated):          all tainted params are value-type or const-qualified
                          ── dispatched to the global BFS queue for parallel
                          execution.

A Slot accumulates a TaintState as it walks P0 followups depth-first, so
later followups (and the vulnerability-mining fork) see the full validation
context built by previous calls.
"""
from __future__ import annotations

from queue import Queue
import threading
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .global_cache import GlobalCache, TaintValidationItem
from .param_analyzer import FollowupSemantics

logger = logging.getLogger("dvs.scheduler")


# ─── TaintState ───────────────────────────────────────────────────────────────

@dataclass
class TaintEntry:
    """A single validation fact about a tainted variable."""
    variable: str          # e.g. "buf", "buf->len"
    kind: str              # null_check / range / bounds / enum / auth / sanitizer
    evidence: str          # L25: if (buf->len <= 1024)
    confidence: str = "medium"
    dominates: bool = True  # True when the check dominates all downstream calls


@dataclass
class TaintState:
    """Validation facts accumulated along a DFS chain."""

    entries: list[TaintEntry] = field(default_factory=list)

    def merge(self, other: "TaintState") -> None:
        seen: set[tuple[str, str]] = {
            (e.variable, e.evidence) for e in self.entries
        }
        for e in other.entries:
            key = (e.variable, e.evidence)
            if key not in seen:
                self.entries.append(e)
                seen.add(key)

    def summary(self) -> str:
        if not self.entries:
            return "(无)"
        lines = []
        for e in self.entries:
            tag = "✓" if e.dominates else "?"
            lines.append(f"  {tag} {e.variable}: {e.kind} [{e.confidence}] {e.evidence}")
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps(
            [{"variable": e.variable, "kind": e.kind, "evidence": e.evidence,
              "confidence": e.confidence, "dominates": e.dominates}
             for e in self.entries],
            ensure_ascii=False,
        )

    @classmethod
    def from_json(cls, data: str | list | None) -> "TaintState":
        if not data:
            return cls()
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                return cls()
        entries = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    entries.append(TaintEntry(
                        variable=str(item.get("variable", "")),
                        kind=str(item.get("kind", "unknown")),
                        evidence=str(item.get("evidence", "")),
                        confidence=str(item.get("confidence", "medium")),
                        dominates=bool(item.get("dominates", True)),
                    ))
        return cls(entries=entries)


# ─── ValidationCache (placeholder) ────────────────────────────────────────────

@dataclass
class ValidationCacheEntry:
    function_name: str
    source_file: str
    taint_signature: str       # normalized taint params signature
    state: TaintState = field(default_factory=TaintState)

    def cache_key(self) -> str:
        raw = f"{self.function_name}::{self.source_file}::{self.taint_signature}"
        return hashlib.sha1(raw.encode()).hexdigest()[:20]


class ValidationCache:
    """Cross-Slot validation cache (placeholder — redesign planned).

    Currently an in-memory dict with task lifetime.  Future implementation will
    persist to a dedicated SQLite table with versioning and parent-context
    awareness."""

    def __init__(self) -> None:
        self._store: dict[str, ValidationCacheEntry] = {}

    def get(self, function_name: str, source_file: str,
            taint_signature: str) -> TaintState | None:
        key = ValidationCacheEntry(
            function_name=function_name,
            source_file=source_file,
            taint_signature=taint_signature,
        ).cache_key()
        entry = self._store.get(key)
        return entry.state if entry else None

    def put(self, function_name: str, source_file: str,
            taint_signature: str, state: TaintState) -> None:
        entry = ValidationCacheEntry(
            function_name=function_name,
            source_file=source_file,
            taint_signature=taint_signature,
            state=state,
        )
        self._store[entry.cache_key()] = entry

    def __len__(self) -> int:
        return len(self._store)


# ─── Slot ─────────────────────────────────────────────────────────────────────

@dataclass
class SlotContext:
    """Shared context for a Slot's execution."""
    source_root: str
    funcdb_path: str
    cache_root: str
    graph_db_path: Path | None
    sessions_dir: Path
    model: str
    tools: list[str]
    cancel_event: threading.Event | None
    run_timeout_seconds: float | int
    pi_max_retries: int
    pi_retry_delay: float
    task_id: str
    task_root: str
    task_run_root: str
    max_depth: int
    analyzed: set[str]


class Slot:
    """A sequential execution slot.

    P0 followups are executed depth-first inside this slot, accumulating
    TaintState.  P2 followups are dispatched to the external BFS queue.
    """

    def __init__(self, slot_id: int, cache: ValidationCache):
        self.slot_id = slot_id
        self.cache = cache
        self.taint_state = TaintState()

    def inject_validation_context(self, taint_ctx: str) -> str:
        summary = self.taint_state.summary()
        if summary == "(无)":
            return taint_ctx
        return f"{taint_ctx}\n\n# 调用链上已累积的校验\n{summary}"

    def execute_sequential_chain(
        self,
        p0_followups: list,
        ctx: SlotContext,
        executor,  # Callable[[CalleeRef, SlotContext, TaintState], TaintState]
        bfs_queue: Queue,
    ) -> TaintState:
        """Execute P0 followups sequentially, dispatching P2 to BFS queue.

        Returns the accumulated TaintState after all P0 followups complete.
        """
        for fup in p0_followups:
            if ctx.cancel_event and ctx.cancel_event.is_set():
                break

            # Check cache before executing
            taint_sig = _normalize_taint_signature(fup.tainted_params)
            cached = self.cache.get(
                fup.function_name, fup.file, taint_sig,
            )
            if cached:
                self.taint_state.merge(cached)
                logger.debug(
                    "slot %d cache hit for %s (%s)",
                    self.slot_id, fup.function_name, taint_sig,
                )
                continue

            # Inject accumulated validation context
            fup.taint_ctx = self.inject_validation_context(
                getattr(fup, "taint_ctx", "") or ""
            )

            # Execute
            sub_state = executor(fup, ctx)
            self.taint_state.merge(sub_state)

            # Cache the result
            self.cache.put(
                fup.function_name, fup.file, taint_sig, sub_state,
            )

        return self.taint_state


def _normalize_taint_signature(tainted_params: str | list[str]) -> str:
    """Normalize taint params into a stable signature string."""
    if isinstance(tainted_params, list):
        items = [str(x).strip() for x in tainted_params]
    elif isinstance(tainted_params, str):
        items = [x.strip() for x in tainted_params.split(",") if x.strip()]
    else:
        items = []
    return ",".join(sorted(set(
        re.sub(r"\s*\(.*", "", x).strip().lstrip("&")
        for x in items if x
    )))


def _noop_executor(fup: Any, ctx: SlotContext) -> TaintState:
    """Placeholder executor — returns empty state."""
    return TaintState()
