"""SQLite persistence for dataflow vulnerability mining.

The MySQL tables keep SecFlow task lifecycle.  This module stores the per-task
analysis graph in a task-local SQLite database under output/run so every forked
context can append deterministic taint/vulnerability facts without polluting the
platform database.
"""
from __future__ import annotations

try:
    import fcntl  # type: ignore
except Exception:  # pragma: no cover - Windows local tests
    fcntl = None
import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator, Iterable, Any

SCHEMA_VERSION = 1


@dataclass
class TaintSourceRecord:
    node_id: str
    source_file: str
    function_name: str
    taint_kind: str  # param | return_value | call_argument | global | field | unknown
    symbol: str
    line: str = ""
    call_expr: str = ""
    description: str = ""
    parent_node_id: str = ""
    depth: int = 0
    context_session: str = ""


@dataclass
class TaintEdgeRecord:
    edge_id: str
    run_id: str
    from_node_id: str
    to_node_id: str
    source_file: str
    function_name: str
    from_symbol: str
    to_symbol: str
    line: str = ""
    operation: str = ""  # assignment | call_arg | return | field | container | condition | sink | terminate
    evidence: str = ""
    sanitizer: str = ""
    sanitizer_effect: str = "none"  # none | partial | complete | unknown
    validation: str = ""
    termination_reason: str = ""
    confidence: float = 0.0


@dataclass
class FollowupRecord:
    followup_id: str
    edge_id: str
    parent_node_id: str
    callee_file: str
    callee_function: str
    callee_line: str = ""
    tainted_params_json: str = "[]"
    status: str = "pending"  # pending | queued | running | completed | skipped | cycle | depth_limit
    reason: str = ""
    fork_session: str = ""
    depth: int = 0


@dataclass
class VulnFindingRecord:
    finding_id: str
    run_id: str
    node_id: str
    edge_id: str = ""
    source_file: str = ""
    function_name: str = ""
    line: str = ""
    vuln_type: str = "unknown"
    severity: str = "unknown"
    title: str = ""
    summary: str = ""
    evidence: str = ""
    exploitability: str = ""
    confidence: float = 0.0
    output_dir: str = ""


class VulnScanStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                  key TEXT PRIMARY KEY,
                  value TEXT NOT NULL
                );
                INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', '1');

                CREATE TABLE IF NOT EXISTS analysis_runs (
                  run_id TEXT PRIMARY KEY,
                  task_id TEXT NOT NULL,
                  root_file TEXT NOT NULL,
                  root_function TEXT NOT NULL,
                  source_root TEXT NOT NULL,
                  status TEXT NOT NULL DEFAULT 'running',
                  started_at REAL NOT NULL,
                  finished_at REAL,
                  config_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS taint_nodes (
                  node_id TEXT PRIMARY KEY,
                  source_file TEXT NOT NULL,
                  function_name TEXT NOT NULL,
                  taint_kind TEXT NOT NULL,
                  symbol TEXT NOT NULL,
                  line TEXT NOT NULL DEFAULT '',
                  call_expr TEXT NOT NULL DEFAULT '',
                  description TEXT NOT NULL DEFAULT '',
                  parent_node_id TEXT NOT NULL DEFAULT '',
                  depth INTEGER NOT NULL DEFAULT 0,
                  context_session TEXT NOT NULL DEFAULT '',
                  created_at REAL NOT NULL DEFAULT (strftime('%s','now'))
                );

                CREATE TABLE IF NOT EXISTS taint_edges (
                  edge_id TEXT PRIMARY KEY,
                  run_id TEXT NOT NULL,
                  from_node_id TEXT NOT NULL,
                  to_node_id TEXT NOT NULL,
                  source_file TEXT NOT NULL,
                  function_name TEXT NOT NULL,
                  from_symbol TEXT NOT NULL,
                  to_symbol TEXT NOT NULL,
                  line TEXT NOT NULL DEFAULT '',
                  operation TEXT NOT NULL DEFAULT '',
                  evidence TEXT NOT NULL DEFAULT '',
                  sanitizer TEXT NOT NULL DEFAULT '',
                  sanitizer_effect TEXT NOT NULL DEFAULT 'none',
                  validation TEXT NOT NULL DEFAULT '',
                  termination_reason TEXT NOT NULL DEFAULT '',
                  confidence REAL NOT NULL DEFAULT 0,
                  created_at REAL NOT NULL DEFAULT (strftime('%s','now')),
                  FOREIGN KEY(run_id) REFERENCES analysis_runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS followups (
                  followup_id TEXT PRIMARY KEY,
                  edge_id TEXT NOT NULL,
                  parent_node_id TEXT NOT NULL,
                  callee_file TEXT NOT NULL,
                  callee_function TEXT NOT NULL,
                  callee_line TEXT NOT NULL DEFAULT '',
                  tainted_params_json TEXT NOT NULL DEFAULT '[]',
                  status TEXT NOT NULL DEFAULT 'pending',
                  reason TEXT NOT NULL DEFAULT '',
                  fork_session TEXT NOT NULL DEFAULT '',
                  depth INTEGER NOT NULL DEFAULT 0,
                  created_at REAL NOT NULL DEFAULT (strftime('%s','now'))
                );

                CREATE TABLE IF NOT EXISTS vulnerability_findings (
                  finding_id TEXT PRIMARY KEY,
                  run_id TEXT NOT NULL,
                  node_id TEXT NOT NULL,
                  edge_id TEXT NOT NULL DEFAULT '',
                  source_file TEXT NOT NULL DEFAULT '',
                  function_name TEXT NOT NULL DEFAULT '',
                  line TEXT NOT NULL DEFAULT '',
                  vuln_type TEXT NOT NULL DEFAULT 'unknown',
                  severity TEXT NOT NULL DEFAULT 'unknown',
                  title TEXT NOT NULL DEFAULT '',
                  summary TEXT NOT NULL DEFAULT '',
                  evidence TEXT NOT NULL DEFAULT '',
                  exploitability TEXT NOT NULL DEFAULT '',
                  confidence REAL NOT NULL DEFAULT 0,
                  output_dir TEXT NOT NULL DEFAULT '',
                  created_at REAL NOT NULL DEFAULT (strftime('%s','now')),
                  FOREIGN KEY(run_id) REFERENCES analysis_runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS context_forks (
                  fork_id TEXT PRIMARY KEY,
                  parent_fork_id TEXT NOT NULL DEFAULT '',
                  run_id TEXT NOT NULL,
                  node_id TEXT NOT NULL DEFAULT '',
                  purpose TEXT NOT NULL,
                  session_file TEXT NOT NULL,
                  status TEXT NOT NULL DEFAULT 'created',
                  created_at REAL NOT NULL DEFAULT (strftime('%s','now'))
                );

                CREATE INDEX IF NOT EXISTS ix_taint_edges_run ON taint_edges(run_id);
                CREATE INDEX IF NOT EXISTS ix_taint_edges_function ON taint_edges(source_file, function_name);
                CREATE INDEX IF NOT EXISTS ix_followups_status ON followups(status, depth);
                CREATE INDEX IF NOT EXISTS ix_findings_run ON vulnerability_findings(run_id);
                """
            )
            for column, ddl in [
                ("source_file", "ALTER TABLE vulnerability_findings ADD COLUMN source_file TEXT NOT NULL DEFAULT ''"),
                ("function_name", "ALTER TABLE vulnerability_findings ADD COLUMN function_name TEXT NOT NULL DEFAULT ''"),
                ("line", "ALTER TABLE vulnerability_findings ADD COLUMN line TEXT NOT NULL DEFAULT ''"),
            ]:
                try:
                    conn.execute(ddl)
                except Exception:
                    pass

    def start_run(self, run_id: str, task_id: str, root_file: str, root_function: str, source_root: str, config: dict[str, Any] | None = None) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO analysis_runs
                   (run_id, task_id, root_file, root_function, source_root, status, started_at, config_json)
                   VALUES (?, ?, ?, ?, ?, 'running', ?, ?)""",
                (run_id, task_id, root_file, root_function, source_root, time.time(), json.dumps(config or {}, ensure_ascii=False)),
            )

    def finish_run(self, run_id: str, status: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE analysis_runs SET status=?, finished_at=? WHERE run_id=?", (status, time.time(), run_id))

    def upsert_taint_node(self, rec: TaintSourceRecord) -> None:
        data = asdict(rec)
        cols = list(data)
        with self.connect() as conn:
            conn.execute(
                f"INSERT OR REPLACE INTO taint_nodes ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
                [data[c] for c in cols],
            )

    def add_taint_edges(self, records: Iterable[TaintEdgeRecord]) -> None:
        rows = [asdict(r) for r in records]
        if not rows:
            return
        cols = list(rows[0])
        with self.connect() as conn:
            conn.executemany(
                f"INSERT OR REPLACE INTO taint_edges ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
                [[row[c] for c in cols] for row in rows],
            )

    def add_followups(self, records: Iterable[FollowupRecord]) -> None:
        rows = [asdict(r) for r in records]
        if not rows:
            return
        cols = list(rows[0])
        with self.connect() as conn:
            conn.executemany(
                f"INSERT OR REPLACE INTO followups ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
                [[row[c] for c in cols] for row in rows],
            )

    def add_finding(self, rec: VulnFindingRecord) -> None:
        data = asdict(rec)
        cols = list(data)
        with self.connect() as conn:
            conn.execute(
                f"INSERT OR REPLACE INTO vulnerability_findings ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
                [data[c] for c in cols],
            )

    def list_followups(self, run_id: str | None = None, *, status: str | None = None) -> list[FollowupRecord]:
        where: list[str] = []
        params: list[Any] = []
        if run_id:
            where.append("e.run_id=?")
            params.append(run_id)
        if status:
            where.append("f.status=?")
            params.append(status)
        sql = """SELECT f.* FROM followups f
                 LEFT JOIN taint_edges e ON e.edge_id=f.edge_id"""
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY f.depth ASC, f.callee_function ASC, f.followup_id ASC"
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [FollowupRecord(**dict(row)) for row in rows]

    def append_artifact_manifest(self, stage: str, artifacts: list[dict[str, Any]], *, function_name: str = "", source_file: str = "", task_id: str = "", run_id: str = "") -> None:
        """Append a deterministic artifact inventory entry under the SQLite-adjacent output directory."""
        manifest_path = self.db_path.parent / "artifact-manifest.json"
        entry = {
            "stage": stage,
            "task_id": task_id,
            "run_id": run_id,
            "function": function_name,
            "source_file": source_file,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "artifacts": artifacts,
        }
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with manifest_path.open("a+", encoding="utf-8") as fh:
            if fcntl is not None:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                except OSError:
                    pass
            fh.seek(0)
            try:
                data = json.loads(fh.read() or "[]")
                if not isinstance(data, list):
                    data = []
            except Exception:
                data = []
            data.append(entry)
            fh.seek(0)
            fh.truncate()
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
            if fcntl is not None:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass

    def add_context_fork(
        self,
        *,
        fork_id: str,
        run_id: str,
        purpose: str,
        session_file: str,
        parent_fork_id: str = "",
        node_id: str = "",
        status: str = "created",
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO context_forks
                   (fork_id, parent_fork_id, run_id, node_id, purpose, session_file, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (fork_id, parent_fork_id, run_id, node_id, purpose, session_file, status),
            )

    def has_path_seen(self, source_file: str, function_name: str, symbol: str, *, max_depth_revisit: int = 1) -> bool:
        with self.connect() as conn:
            row = conn.execute(
                """SELECT COUNT(*) AS n FROM taint_nodes
                   WHERE source_file=? AND function_name=? AND symbol=?""",
                (source_file, function_name, symbol),
            ).fetchone()
            return int(row["n"] if row else 0) > max_depth_revisit

    def export_json(self) -> dict[str, Any]:
        with self.connect() as conn:
            result: dict[str, Any] = {}
            for table in ["analysis_runs", "taint_nodes", "taint_edges", "followups", "vulnerability_findings", "context_forks"]:
                result[table] = [dict(r) for r in conn.execute(f"SELECT * FROM {table}").fetchall()]
            return result
