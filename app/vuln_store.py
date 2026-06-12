"""SQLite persistence for dataflow vulnerability mining.

The MySQL tables keep SecFlow task lifecycle.  This module stores the per-task
analysis graph in a task-local SQLite database under output/run so every forked
context can append deterministic taint/vulnerability facts without polluting the
platform database.
"""
from __future__ import annotations
from sqlalchemy import func

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

from .validation_state import normalize_validation_state, validation_covers

SCHEMA_VERSION = 2


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
    validation_facts_json: str = "[]"
    validation_signature: str = "none"
    validation_risk_rank: int = 100


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
    dispatch_kind: str = "direct_call"
    tainted_nonlocal_json: str = "[]"
    tracker_type: str = ""
    tracker_status: str = ""
    tracker_result_json: str = "{}"
    created_at: float = 0.0


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
                  validation_facts_json TEXT NOT NULL DEFAULT '[]',
                  validation_signature TEXT NOT NULL DEFAULT 'none',
                  validation_risk_rank INTEGER NOT NULL DEFAULT 100,
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
                  dispatch_kind TEXT NOT NULL DEFAULT 'direct_call',
                  tainted_nonlocal_json TEXT NOT NULL DEFAULT '[]',
                  tracker_type TEXT NOT NULL DEFAULT '',
                  tracker_status TEXT NOT NULL DEFAULT '',
                  tracker_result_json TEXT NOT NULL DEFAULT '{}',
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

                CREATE TABLE IF NOT EXISTS analysis_contexts (
                  context_id TEXT PRIMARY KEY,
                  function_identity TEXT NOT NULL,
                  source_file TEXT NOT NULL DEFAULT '',
                  function_name TEXT NOT NULL,
                  taint_signature TEXT NOT NULL,
                  validation_signature TEXT NOT NULL DEFAULT 'none',
                  validation_risk_rank INTEGER NOT NULL DEFAULT 100,
                  validation_facts_json TEXT NOT NULL DEFAULT '[]',
                  risk_class TEXT NOT NULL DEFAULT 'no_validation',
                  status TEXT NOT NULL DEFAULT 'created',
                  covered_by_context_id TEXT NOT NULL DEFAULT '',
                  created_from_followup_id TEXT NOT NULL DEFAULT '',
                  merged_followups_json TEXT NOT NULL DEFAULT '[]',
                  created_at REAL NOT NULL DEFAULT (strftime('%s','now'))
                );

                CREATE TABLE IF NOT EXISTS taint_constraints (
                  constraint_id TEXT PRIMARY KEY,
                  run_id TEXT NOT NULL,
                  edge_id TEXT NOT NULL DEFAULT '',
                  followup_id TEXT NOT NULL DEFAULT '',
                  source_file TEXT NOT NULL DEFAULT '',
                  function_name TEXT NOT NULL DEFAULT '',
                  line TEXT NOT NULL DEFAULT '',
                  target_arg_index INTEGER NOT NULL DEFAULT 0,
                  target_symbol TEXT NOT NULL DEFAULT '',
                  access_path_json TEXT NOT NULL DEFAULT '[]',
                  kind TEXT NOT NULL,
                  predicate_json TEXT NOT NULL DEFAULT '{}',
                  effect TEXT NOT NULL DEFAULT 'constrains',
                  confidence TEXT NOT NULL DEFAULT 'medium',
                  dominates_call INTEGER NOT NULL DEFAULT 1,
                  evidence TEXT NOT NULL DEFAULT '',
                  normalized_key TEXT NOT NULL,
                  created_at REAL NOT NULL DEFAULT (strftime('%s','now'))
                );

                CREATE INDEX IF NOT EXISTS ix_taint_edges_run ON taint_edges(run_id);
                CREATE INDEX IF NOT EXISTS ix_taint_edges_function ON taint_edges(source_file, function_name);
                CREATE INDEX IF NOT EXISTS ix_followups_status ON followups(status, depth);
                CREATE INDEX IF NOT EXISTS ix_findings_run ON vulnerability_findings(run_id);
                CREATE INDEX IF NOT EXISTS ix_contexts_lookup ON analysis_contexts(function_identity, taint_signature, validation_signature);
                CREATE INDEX IF NOT EXISTS ix_constraints_run ON taint_constraints(run_id, edge_id, followup_id);
                """
            )
            for table, column, ddl in [
                ("vulnerability_findings", "source_file", "ALTER TABLE vulnerability_findings ADD COLUMN source_file TEXT NOT NULL DEFAULT ''"),
                ("vulnerability_findings", "function_name", "ALTER TABLE vulnerability_findings ADD COLUMN function_name TEXT NOT NULL DEFAULT ''"),
                ("vulnerability_findings", "line", "ALTER TABLE vulnerability_findings ADD COLUMN line TEXT NOT NULL DEFAULT ''"),
                ("taint_edges", "validation_facts_json", "ALTER TABLE taint_edges ADD COLUMN validation_facts_json TEXT NOT NULL DEFAULT '[]'"),
                ("taint_edges", "validation_signature", "ALTER TABLE taint_edges ADD COLUMN validation_signature TEXT NOT NULL DEFAULT 'none'"),
                ("taint_edges", "validation_risk_rank", "ALTER TABLE taint_edges ADD COLUMN validation_risk_rank INTEGER NOT NULL DEFAULT 100"),
                ("analysis_contexts", "validation_facts_json", "ALTER TABLE analysis_contexts ADD COLUMN validation_facts_json TEXT NOT NULL DEFAULT '[]'"),
                ("followups", "dispatch_kind", "ALTER TABLE followups ADD COLUMN dispatch_kind TEXT NOT NULL DEFAULT 'direct_call'"),
                ("followups", "tainted_nonlocal_json", "ALTER TABLE followups ADD COLUMN tainted_nonlocal_json TEXT NOT NULL DEFAULT '[]'"),
                ("followups", "tracker_type", "ALTER TABLE followups ADD COLUMN tracker_type TEXT NOT NULL DEFAULT ''"),
                ("followups", "tracker_status", "ALTER TABLE followups ADD COLUMN tracker_status TEXT NOT NULL DEFAULT ''"),
                ("followups", "tracker_result_json", "ALTER TABLE followups ADD COLUMN tracker_result_json TEXT NOT NULL DEFAULT '{}'"),
                ("analysis_contexts", "validations_json", "ALTER TABLE analysis_contexts ADD COLUMN validations_json TEXT NOT NULL DEFAULT '[]'"),
                ("analysis_contexts", "func_hash", "ALTER TABLE analysis_contexts ADD COLUMN func_hash TEXT NOT NULL DEFAULT ''"),
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

    def update_followup_status(self, followup_id: str, status: str, *, reason: str | None = None) -> None:
        if not followup_id:
            return
        with self.connect() as conn:
            if reason is None:
                conn.execute("UPDATE followups SET status=? WHERE followup_id=?", (status, followup_id))
            else:
                conn.execute("UPDATE followups SET status=?, reason=? WHERE followup_id=?", (status, reason, followup_id))

    def update_followup_tracker(
        self,
        followup_id: str,
        *,
        tracker_type: str,
        tracker_status: str,
        result: dict[str, Any] | None = None,
    ) -> None:
        if not followup_id:
            return
        with self.connect() as conn:
            conn.execute(
                """UPDATE followups
                   SET tracker_type=?, tracker_status=?, tracker_result_json=?
                   WHERE followup_id=?""",
                (tracker_type, tracker_status, json.dumps(result or {}, ensure_ascii=False), followup_id),
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

    def record_constraints(self, *, run_id: str, edge_id: str = "", followup_id: str = "", source_file: str = "", function_name: str = "", line: str = "", facts: list[dict[str, Any]] | None = None) -> None:
        rows = []
        for idx, fact in enumerate(facts or []):
            target = fact.get("target") if isinstance(fact.get("target"), dict) else {}
            predicate = fact.get("predicate") if isinstance(fact.get("predicate"), dict) else {}
            access_path = target.get("access_path") if isinstance(target.get("access_path"), list) else []
            key_obj = {"kind": fact.get("kind"), "target": target, "predicate": predicate}
            normalized_key = json.dumps(key_obj, sort_keys=True, ensure_ascii=False)
            rows.append((
                "constraint_" + str(abs(hash((run_id, edge_id, followup_id, idx, normalized_key)))),
                run_id, edge_id, followup_id, source_file, function_name, line,
                int(target.get("arg_index") or 0), str(target.get("symbol") or ""),
                json.dumps(access_path, ensure_ascii=False), str(fact.get("kind") or "unknown"),
                json.dumps(predicate, ensure_ascii=False), str(fact.get("effect") or "constrains"),
                str(fact.get("confidence") or "medium"),
                1 if (fact.get("scope") or {}).get("dominates_call", True) else 0,
                str(fact.get("evidence") or ""), normalized_key,
            ))
        if not rows:
            return
        with self.connect() as conn:
            conn.executemany(
                """INSERT OR REPLACE INTO taint_constraints
                   (constraint_id, run_id, edge_id, followup_id, source_file, function_name, line,
                    target_arg_index, target_symbol, access_path_json, kind, predicate_json, effect,
                    confidence, dominates_call, evidence, normalized_key)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )

    def find_covering_context(self, *, function_identity: str, taint_signature: str, validation_signature: str, validation_risk_rank: int, validation_facts: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
        with self.connect() as conn:
            rows = [dict(r) for r in conn.execute(
                """SELECT * FROM analysis_contexts
                   WHERE function_identity=? AND taint_signature=? AND status IN ('created','queued','running','analyzed')""",
                (function_identity, taint_signature),
            ).fetchall()]
        rows.sort(key=lambda r: int(r.get("validation_risk_rank") or 0), reverse=True)
        for row in rows:
            try:
                existing_facts = json.loads(row.get("validation_facts_json") or "[]")
                if validation_covers(existing_facts, validation_facts or []):
                    return dict(row)
            except Exception:
                continue
        return None

    def find_running_context(self, function_identity: str, taint_signature: str) -> dict[str, Any] | None:
        """Check if the same (func, taint) is currently being analyzed in another slot."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM analysis_contexts WHERE function_identity=? AND taint_signature=? AND status='running'",
                (function_identity, taint_signature),
            ).fetchone()
            return dict(row) if row else None

    def update_context_validations(self, context_id: str, validations_json: str, func_hash: str = "") -> None:
        """After Worker completes, persist validation facts into analysis_contexts."""
        if not context_id:
            return
        with self.connect() as conn:
            conn.execute(
                """UPDATE analysis_contexts
                   SET validation_facts_json=?, func_hash=?, status='completed'
                   WHERE context_id=?""",
                (validations_json, func_hash, context_id),
            )

    def find_covering_context(self, *, function_identity: str, taint_signature: str, validation_signature: str, validation_risk_rank: int, validation_facts: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
        with self.connect() as conn:
            rows = [dict(r) for r in conn.execute(
                """SELECT * FROM analysis_contexts
                   WHERE function_identity=? AND taint_signature=? AND status IN ('created','queued','running','analyzed')""",
                (function_identity, taint_signature),
            ).fetchall()]
        rows.sort(key=lambda r: int(r.get("validation_risk_rank") or 0), reverse=True)
        for row in rows:
            try:
                existing_facts = json.loads(str(row.get("validation_facts_json") or "[]"))
            except Exception:
                existing_facts = []
            if validation_covers(str(row.get("validation_signature") or "none"), int(row.get("validation_risk_rank") or 100), validation_signature, validation_risk_rank, existing_facts, validation_facts or []):
                return dict(row)
        return None

    def upsert_analysis_context(self, *, context_id: str, function_identity: str, source_file: str, function_name: str, taint_signature: str, validation_signature: str, validation_risk_rank: int, risk_class: str, status: str, created_from_followup_id: str = "", covered_by_context_id: str = "", validation_facts: list[dict[str, Any]] | None = None) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO analysis_contexts
                   (context_id, function_identity, source_file, function_name, taint_signature, validation_signature,
                    validation_risk_rank, validation_facts_json, risk_class, status, covered_by_context_id, created_from_followup_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (context_id, function_identity, source_file, function_name, taint_signature, validation_signature,
                 validation_risk_rank, json.dumps(validation_facts or [], ensure_ascii=False), risk_class, status, covered_by_context_id, created_from_followup_id),
            )

    def update_analysis_context_status(self, context_id: str, status: str) -> None:
        if not context_id:
            return
        with self.connect() as conn:
            conn.execute("UPDATE analysis_contexts SET status=? WHERE context_id=?", (status, context_id))

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
            for table in ["analysis_runs", "taint_nodes", "taint_edges", "followups", "vulnerability_findings", "context_forks", "analysis_contexts", "taint_constraints"]:
                result[table] = [dict(r) for r in conn.execute(f"SELECT * FROM {table}").fetchall()]
            return result
