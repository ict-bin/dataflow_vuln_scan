"""Source-root-scoped global function summary cache.

One SQLite database per source root, storing per-function analysis
summaries that are reused across tasks and chains.  When a function
with identical taint signature and source hash is encountered again,
the cached validations / edges / followups are applied directly
without launching a Worker.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = 1

_DEFAULT_GLOBAL_ROOT = Path(
    os.environ.get("FILESERVER_ROOT", "/data/files")
) / "dvs-global"


# ─── data model ──────────────────────────────────────────────────────────────

@dataclass
class TaintValidationItem:
    variable: str          # e.g. "buf", "buf->len"
    kind: str              # null_check | range | bounds | enum | auth | sanitizer
    predicate: str = "{}"  # JSON predicate
    evidence: str = ""
    confidence: str = "medium"


@dataclass
class EdgeItem:
    from_symbol: str
    to_symbol: str
    operation: str = ""
    evidence: str = ""


@dataclass
class FollowupItem:
    file: str = ""
    function: str = ""
    line: str = ""
    reason: str = ""


@dataclass
class FunctionSummary:
    function_name: str = ""
    source_file: str = ""
    taint_sig: str = ""                # normalized positional signature
    func_hash: str = ""                # source body hash
    validations: list[TaintValidationItem] = field(default_factory=list)
    edges: list[EdgeItem] = field(default_factory=list)
    followups: list[FollowupItem] = field(default_factory=list)
    created_at: float = 0.0

    def to_json(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "source_file": self.source_file,
            "taint_sig": self.taint_sig,
            "func_hash": self.func_hash,
            "validations": [
                {"variable": v.variable, "kind": v.kind, "predicate": v.predicate,
                 "evidence": v.evidence, "confidence": v.confidence}
                for v in self.validations
            ],
            "edges": [
                {"from": e.from_symbol, "to": e.to_symbol,
                 "operation": e.operation, "evidence": e.evidence}
                for e in self.edges
            ],
            "followups": [
                {"file": f.file, "function": f.function, "line": f.line, "reason": f.reason}
                for f in self.followups
            ],
            "created_at": self.created_at,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "FunctionSummary":
        return cls(
            function_name=str(data.get("function_name", "")),
            source_file=str(data.get("source_file", "")),
            taint_sig=str(data.get("taint_sig", "")),
            func_hash=str(data.get("func_hash", "")),
            validations=[
                TaintValidationItem(
                    variable=str(v.get("variable", "")),
                    kind=str(v.get("kind", "unknown")),
                    predicate=str(v.get("predicate", "{}")),
                    evidence=str(v.get("evidence", "")),
                    confidence=str(v.get("confidence", "medium")),
                )
                for v in (data.get("validations") or [])
            ],
            edges=[
                EdgeItem(
                    from_symbol=str(e.get("from", "")),
                    to_symbol=str(e.get("to", "")),
                    operation=str(e.get("operation", "")),
                    evidence=str(e.get("evidence", "")),
                )
                for e in (data.get("edges") or [])
            ],
            followups=[
                FollowupItem(
                    file=str(f.get("file", "")),
                    function=str(f.get("function", "")),
                    line=str(f.get("line", "")),
                    reason=str(f.get("reason", "")),
                )
                for f in (data.get("followups") or [])
            ],
            created_at=float(data.get("created_at", 0)),
        )


# ─── global cache ────────────────────────────────────────────────────────────

class GlobalCache:
    """Primary interface for the source-root-wide function summary cache.

    Thread-safe (SQLite in WAL mode).  One instance per source root.
    """

    def __init__(self, source_root: str, *, db_root: str | Path = _DEFAULT_GLOBAL_ROOT):
        self.source_root = str(Path(source_root).resolve())
        self.source_root_hash = hashlib.sha1(
            self.source_root.encode("utf-8", errors="replace")
        ).hexdigest()[:16]
        self._root: Path = Path(db_root)
        self._db_path: Path = self._root / self.source_root_hash / "cache" / "global-analysis.db"
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @property
    def funcdb_root(self) -> Path:
        """Recommended funcdb parent path for this source root."""
        return self._root / self.source_root_hash / "funcdb"

    @contextmanager
    def _connect(self) -> "sqlite3.Connection":
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ── schema ────────────────────────────────────────────────────────────

    SCHEMA_DDL = """
        CREATE TABLE IF NOT EXISTS function_summaries (
            cache_id         TEXT PRIMARY KEY,
            function_name    TEXT NOT NULL,
            source_file      TEXT NOT NULL,
            taint_sig        TEXT NOT NULL,
            func_hash        TEXT NOT NULL,
            summary_json     TEXT NOT NULL,
            model_version    TEXT NOT NULL DEFAULT '',
            created_at       REAL NOT NULL,
            last_hit_at      REAL NOT NULL,
            hit_count        INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS ix_fsum_lookup
            ON function_summaries(function_name, source_file, taint_sig);
        CREATE INDEX IF NOT EXISTS ix_fsum_func_hash
            ON function_summaries(function_name, source_file, func_hash);
    """

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(self.SCHEMA_DDL)

    # ── public API ────────────────────────────────────────────────────────

    def get(
        self,
        function_name: str,
        source_file: str,
        taint_sig: str,
        func_hash: str,
    ) -> FunctionSummary | None:
        cache_id = _make_cache_id(function_name, source_file, taint_sig, func_hash)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT summary_json, func_hash FROM function_summaries WHERE cache_id=?",
                (cache_id,),
            ).fetchone()
        if row is None:
            return None
        # Source change detection
        if row["func_hash"] != func_hash:
            self._evict(cache_id)
            return None
        self._touch_hit(cache_id)
        return FunctionSummary.from_json(json.loads(row["summary_json"]))

    def put(
        self,
        function_name: str,
        source_file: str,
        taint_sig: str,
        func_hash: str,
        summary: FunctionSummary,
        *,
        model_version: str = "",
    ) -> None:
        cache_id = _make_cache_id(function_name, source_file, taint_sig, func_hash)
        summary.function_name = function_name
        summary.source_file = source_file
        summary.taint_sig = taint_sig
        summary.func_hash = func_hash
        summary.created_at = time.time()
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO function_summaries
                   (cache_id, function_name, source_file, taint_sig, func_hash,
                    summary_json, model_version, created_at, last_hit_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cache_id, function_name, source_file, taint_sig, func_hash,
                    json.dumps(summary.to_json(), ensure_ascii=False),
                    model_version, summary.created_at, summary.created_at,
                ),
            )

    def get_validations(
        self,
        function_name: str,
        source_file: str,
        taint_sig: str,
        func_hash: str,
    ) -> list[TaintValidationItem]:
        summary = self.get(function_name, source_file, taint_sig, func_hash)
        if summary is None:
            return []
        return list(summary.validations)

    def get_edges(
        self,
        function_name: str,
        source_file: str,
        taint_sig: str,
        func_hash: str,
    ) -> list[EdgeItem]:
        summary = self.get(function_name, source_file, taint_sig, func_hash)
        if summary is None:
            return []
        return list(summary.edges)

    def get_followups(
        self,
        function_name: str,
        source_file: str,
        taint_sig: str,
        func_hash: str,
    ) -> list[FollowupItem]:
        summary = self.get(function_name, source_file, taint_sig, func_hash)
        if summary is None:
            return []
        return list(summary.followups)

    # ── maintenance ───────────────────────────────────────────────────────

    def _evict(self, cache_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM function_summaries WHERE cache_id=?", (cache_id,))

    def _touch_hit(self, cache_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE function_summaries SET hit_count=hit_count+1, last_hit_at=? WHERE cache_id=?",
                (time.time(), cache_id),
            )


def _make_cache_id(
    function_name: str, source_file: str, taint_sig: str, func_hash: str
) -> str:
    raw = f"{function_name}::{source_file}::{taint_sig}::{func_hash}"
    return hashlib.sha1(raw.encode()).hexdigest()[:32]


# ─── helper: func_hash ──────────────────────────────────────────────────────

def compute_func_hash(source_root: str, source_file: str, func_name: str) -> str:
    """Compute a stable hash of the function body for cache validation."""
    file_path = Path(source_root) / source_file
    if not file_path.exists():
        # Try rg fallback
        try:
            import subprocess
            result = subprocess.run(
                ["rg", "-l", f"\\b{func_name.rsplit('::', 1)[-1]}\\b", str(source_root)],
                capture_output=True, text=True, timeout=10, cwd=str(source_root),
            )
            for line in result.stdout.splitlines():
                p = Path(line.strip())
                if p.exists():
                    file_path = Path(source_root) / p
                    break
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
    if not file_path.exists():
        return ""
    try:
        data = file_path.read_bytes()
        return hashlib.sha1(data).hexdigest()[:20]
    except OSError:
        return ""


# ─── helper: source_root_hash ───────────────────────────────────────────────

def source_root_key(source_root: str) -> str:
    return hashlib.sha1(str(Path(source_root).resolve()).encode()).hexdigest()[:16]
