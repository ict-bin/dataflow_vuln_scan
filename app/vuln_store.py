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
class TaskGraphRunRecord:
    task_id: str
    epoch: str
    run_root: str
    graph_version: int = 1
    root_function: str = ""
    generated_at: float = 0.0


@dataclass
class TaskGraphNodeRecord:
    node_id: str
    task_id: str
    epoch: str
    func_id: str = ""
    function_name_resolved: str = ""
    function_name_raw: str = ""
    source_file: str = ""
    depth: int = 0
    status: str = "discovered"
    analysis_status: str = "pending"
    findings_count: int = 0
    started_at: str | None = None
    finished_at: str | None = None
    primary_session_relpath: str = ""
    session_group_key: str = ""
    visible_in_tree: int = 1
    visible_in_all_propagations: int = 1
    extra_json: str = "{}"


@dataclass
class TaskGraphEdgeRecord:
    edge_id: str
    task_id: str
    epoch: str
    source_node_id: str
    target_node_id: str = ""
    source_func_id: str = ""
    target_func_id: str = ""
    source_function_resolved: str = ""
    target_function_resolved: str = ""
    target_function_raw: str = ""
    source_file: str = ""
    target_file: str = ""
    edge_kind: str = "direct_call"
    status: str = "discovered"
    reason_code: str = ""
    reason_message: str = ""
    reason_source: str = ""
    source_prop_id: str = ""
    source_orchestration_edge_id: str = ""
    call_line: int | None = None
    source_taint_name: str = ""
    target_taint_name: str = ""
    validations_json: str = "[]"
    actual_args_json: str = "[]"
    tracker_type: str = ""
    tracker_result_json: str = "{}"
    display_order: int = 0
    visible_in_tree: int = 1
    visible_in_all_propagations: int = 1
    created_at: str | None = None
    updated_at: str | None = None


@dataclass
class TaskGraphSessionRecord:
    session_relpath: str
    task_id: str
    epoch: str
    node_id: str = ""
    edge_id: str = ""
    session_role: str = ""
    session_kind: str = ""
    display_name: str = ""
    status: str = "unknown"
    started_at: str | None = None
    ended_at: str | None = None
    mtime: float | None = None
    event_count: int = 0
    extra_json: str = "{}"


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
    code_snippet: str = ""
    code_explanation: str = ""
    fix_suggestion: str = ""


class VulnScanStore:
    def __init__(self, db_path: str | Path, mysql_store=None):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._mysql = mysql_store
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
                  report_status TEXT NOT NULL DEFAULT '',
                  report_case_id TEXT NOT NULL DEFAULT '',
                  code_snippet TEXT NOT NULL DEFAULT '',
                  code_explanation TEXT NOT NULL DEFAULT '',
                  fix_suggestion TEXT NOT NULL DEFAULT '',
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

                CREATE TABLE IF NOT EXISTS container_taints (
                  container_taint_id TEXT PRIMARY KEY,
                  run_id TEXT NOT NULL,
                  source_file TEXT NOT NULL DEFAULT '',
                  function_name TEXT NOT NULL DEFAULT '',
                  symbol TEXT NOT NULL,
                  kind TEXT NOT NULL DEFAULT 'global',
                  evidence TEXT NOT NULL DEFAULT '',
                  depth INTEGER NOT NULL DEFAULT 0,
                  created_at REAL NOT NULL DEFAULT (strftime('%s','now'))
                );

                CREATE INDEX IF NOT EXISTS ix_container_taints_run ON container_taints(run_id);

                CREATE TABLE IF NOT EXISTS task_graph_runs (
                  task_id TEXT PRIMARY KEY,
                  epoch TEXT NOT NULL,
                  run_root TEXT NOT NULL,
                  graph_version INTEGER NOT NULL DEFAULT 1,
                  root_function TEXT NOT NULL DEFAULT '',
                  generated_at REAL NOT NULL DEFAULT (strftime('%s','now'))
                );

                CREATE TABLE IF NOT EXISTS task_graph_nodes (
                  node_id TEXT PRIMARY KEY,
                  task_id TEXT NOT NULL,
                  epoch TEXT NOT NULL,
                  func_id TEXT NOT NULL DEFAULT '',
                  function_name_resolved TEXT NOT NULL DEFAULT '',
                  function_name_raw TEXT NOT NULL DEFAULT '',
                  source_file TEXT NOT NULL DEFAULT '',
                  depth INTEGER NOT NULL DEFAULT 0,
                  status TEXT NOT NULL DEFAULT 'discovered',
                  analysis_status TEXT NOT NULL DEFAULT 'pending',
                  findings_count INTEGER NOT NULL DEFAULT 0,
                  started_at TEXT,
                  finished_at TEXT,
                  primary_session_relpath TEXT NOT NULL DEFAULT '',
                  session_group_key TEXT NOT NULL DEFAULT '',
                  visible_in_tree INTEGER NOT NULL DEFAULT 1,
                  visible_in_all_propagations INTEGER NOT NULL DEFAULT 1,
                  extra_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS task_graph_edges (
                  edge_id TEXT PRIMARY KEY,
                  task_id TEXT NOT NULL,
                  epoch TEXT NOT NULL,
                  source_node_id TEXT NOT NULL,
                  target_node_id TEXT NOT NULL DEFAULT '',
                  source_func_id TEXT NOT NULL DEFAULT '',
                  target_func_id TEXT NOT NULL DEFAULT '',
                  source_function_resolved TEXT NOT NULL DEFAULT '',
                  target_function_resolved TEXT NOT NULL DEFAULT '',
                  target_function_raw TEXT NOT NULL DEFAULT '',
                  source_file TEXT NOT NULL DEFAULT '',
                  target_file TEXT NOT NULL DEFAULT '',
                  edge_kind TEXT NOT NULL DEFAULT 'direct_call',
                  status TEXT NOT NULL DEFAULT 'discovered',
                  reason_code TEXT NOT NULL DEFAULT '',
                  reason_message TEXT NOT NULL DEFAULT '',
                  reason_source TEXT NOT NULL DEFAULT '',
                  source_prop_id TEXT NOT NULL DEFAULT '',
                  source_orchestration_edge_id TEXT NOT NULL DEFAULT '',
                  call_line INTEGER,
                  source_taint_name TEXT NOT NULL DEFAULT '',
                  target_taint_name TEXT NOT NULL DEFAULT '',
                  validations_json TEXT NOT NULL DEFAULT '[]',
                  actual_args_json TEXT NOT NULL DEFAULT '[]',
                  tracker_type TEXT NOT NULL DEFAULT '',
                  tracker_result_json TEXT NOT NULL DEFAULT '{}',
                  display_order INTEGER NOT NULL DEFAULT 0,
                  visible_in_tree INTEGER NOT NULL DEFAULT 1,
                  visible_in_all_propagations INTEGER NOT NULL DEFAULT 1,
                  created_at TEXT,
                  updated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS task_graph_sessions (
                  session_relpath TEXT PRIMARY KEY,
                  task_id TEXT NOT NULL,
                  epoch TEXT NOT NULL,
                  node_id TEXT NOT NULL DEFAULT '',
                  edge_id TEXT NOT NULL DEFAULT '',
                  session_role TEXT NOT NULL DEFAULT '',
                  session_kind TEXT NOT NULL DEFAULT '',
                  display_name TEXT NOT NULL DEFAULT '',
                  status TEXT NOT NULL DEFAULT 'unknown',
                  started_at TEXT,
                  ended_at TEXT,
                  mtime REAL,
                  event_count INTEGER NOT NULL DEFAULT 0,
                  extra_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS ix_task_graph_nodes_task ON task_graph_nodes(task_id, depth);
                CREATE INDEX IF NOT EXISTS ix_task_graph_edges_task ON task_graph_edges(task_id, display_order);
                CREATE INDEX IF NOT EXISTS ix_task_graph_sessions_task ON task_graph_sessions(task_id, session_relpath);
                """
            )
            for table, column, ddl in [
                ("vulnerability_findings", "source_file", "ALTER TABLE vulnerability_findings ADD COLUMN source_file TEXT NOT NULL DEFAULT ''"),
                ("vulnerability_findings", "function_name", "ALTER TABLE vulnerability_findings ADD COLUMN function_name TEXT NOT NULL DEFAULT ''"),
                ("vulnerability_findings", "line", "ALTER TABLE vulnerability_findings ADD COLUMN line TEXT NOT NULL DEFAULT ''"),
                ("vulnerability_findings", "report_status", "ALTER TABLE vulnerability_findings ADD COLUMN report_status TEXT NOT NULL DEFAULT ''"),
                ("vulnerability_findings", "report_case_id", "ALTER TABLE vulnerability_findings ADD COLUMN report_case_id TEXT NOT NULL DEFAULT ''"),
                ("vulnerability_findings", "code_snippet", "ALTER TABLE vulnerability_findings ADD COLUMN code_snippet TEXT NOT NULL DEFAULT ''"),
                ("vulnerability_findings", "code_explanation", "ALTER TABLE vulnerability_findings ADD COLUMN code_explanation TEXT NOT NULL DEFAULT ''"),
                ("vulnerability_findings", "fix_suggestion", "ALTER TABLE vulnerability_findings ADD COLUMN fix_suggestion TEXT NOT NULL DEFAULT ''"),
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
                ("taint_nodes", "run_id", "ALTER TABLE taint_nodes ADD COLUMN run_id TEXT NOT NULL DEFAULT ''"),
            ]:
                try:
                    conn.execute(ddl)
                except Exception:
                    pass

    def _upsert_rows(self, table: str, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        cols = list(rows[0])
        with self.connect() as conn:
            conn.executemany(
                f"INSERT OR REPLACE INTO {table} ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
                [[row[c] for c in cols] for row in rows],
            )

    def start_task_graph_run(self, rec: TaskGraphRunRecord) -> None:
        data = asdict(rec)
        if not data.get("generated_at"):
            data["generated_at"] = time.time()
        with self.connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO task_graph_runs
                   (task_id, epoch, run_root, graph_version, root_function, generated_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    data["task_id"], data["epoch"], data["run_root"], data["graph_version"],
                    data["root_function"], data["generated_at"],
                ),
            )
        if self._mysql:
            try:
                self._mysql.start_task_graph_run(rec)
            except Exception:
                logger.warning("mysql start_task_graph_run failed: task_id=%s", rec.task_id, exc_info=True)

    def upsert_task_graph_node(self, rec: TaskGraphNodeRecord) -> None:
        self._upsert_rows("task_graph_nodes", [asdict(rec)])
        if self._mysql:
            try:
                self._mysql.upsert_task_graph_node(rec)
            except Exception:
                logger.warning("mysql upsert_task_graph_node failed: node_id=%s", rec.node_id, exc_info=True)

    def upsert_task_graph_edge(self, rec: TaskGraphEdgeRecord) -> None:
        data = asdict(rec)
        if not data.get("updated_at"):
            data["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        if not data.get("created_at"):
            data["created_at"] = data["updated_at"]
        self._upsert_rows("task_graph_edges", [data])
        if self._mysql:
            try:
                self._mysql.upsert_task_graph_edge(rec)
            except Exception:
                logger.warning("mysql upsert_task_graph_edge failed: edge_id=%s", rec.edge_id, exc_info=True)

    def upsert_task_graph_session(self, rec: TaskGraphSessionRecord) -> None:
        self._upsert_rows("task_graph_sessions", [asdict(rec)])
        if self._mysql:
            try:
                self._mysql.upsert_task_graph_session(rec)
            except Exception:
                logger.warning(
                    "mysql upsert_task_graph_session failed: session_relpath=%s",
                    rec.session_relpath,
                    exc_info=True,
                )

    def update_task_graph_node(
        self,
        node_id: str,
        *,
        status: str | None = None,
        analysis_status: str | None = None,
        findings_count: int | None = None,
        finished_at: str | None = None,
        primary_session_relpath: str | None = None,
    ) -> None:
        if not node_id:
            return
        assigns: list[str] = []
        params: list[Any] = []
        for key, value in [
            ("status", status),
            ("analysis_status", analysis_status),
            ("findings_count", findings_count),
            ("finished_at", finished_at),
            ("primary_session_relpath", primary_session_relpath),
        ]:
            if value is None:
                continue
            assigns.append(f"{key}=?")
            params.append(value)
        if not assigns:
            return
        params.append(node_id)
        with self.connect() as conn:
            conn.execute(f"UPDATE task_graph_nodes SET {', '.join(assigns)} WHERE node_id=?", params)
        if self._mysql:
            try:
                self._mysql.update_task_graph_node(node_id, **{k: v for k, v in [("status", status), ("analysis_status", analysis_status), ("findings_count", findings_count), ("finished_at", finished_at), ("primary_session_relpath", primary_session_relpath)] if v is not None})
            except Exception:
                logger.warning("mysql update_task_graph_node failed: node_id=%s", node_id, exc_info=True)

    def update_task_graph_edge(
        self,
        edge_id: str,
        *,
        edge_kind: str | None = None,
        status: str | None = None,
        target_node_id: str | None = None,
        target_func_id: str | None = None,
        target_function_resolved: str | None = None,
        target_file: str | None = None,
        reason_code: str | None = None,
        reason_message: str | None = None,
        reason_source: str | None = None,
        tracker_type: str | None = None,
        tracker_result_json: str | None = None,
        visible_in_tree: int | None = None,
        visible_in_all_propagations: int | None = None,
    ) -> None:
        if not edge_id:
            return
        assigns: list[str] = ["updated_at=?"]
        params: list[Any] = [time.strftime("%Y-%m-%dT%H:%M:%S%z")]
        for key, value in [
            ("edge_kind", edge_kind),
            ("status", status),
            ("target_node_id", target_node_id),
            ("target_func_id", target_func_id),
            ("target_function_resolved", target_function_resolved),
            ("target_file", target_file),
            ("reason_code", reason_code),
            ("reason_message", reason_message),
            ("reason_source", reason_source),
            ("tracker_type", tracker_type),
            ("tracker_result_json", tracker_result_json),
            ("visible_in_tree", visible_in_tree),
            ("visible_in_all_propagations", visible_in_all_propagations),
        ]:
            if value is None:
                continue
            assigns.append(f"{key}=?")
            params.append(value)
        params.append(edge_id)
        with self.connect() as conn:
            conn.execute(f"UPDATE task_graph_edges SET {', '.join(assigns)} WHERE edge_id=?", params)
        if self._mysql:
            try:
                self._mysql.update_task_graph_edge(edge_id, **{k: v for k, v in [("edge_kind", edge_kind), ("status", status), ("target_node_id", target_node_id), ("target_func_id", target_func_id), ("target_function_resolved", target_function_resolved), ("target_file", target_file), ("reason_code", reason_code), ("reason_message", reason_message), ("reason_source", reason_source), ("tracker_type", tracker_type), ("tracker_result_json", tracker_result_json), ("visible_in_tree", visible_in_tree), ("visible_in_all_propagations", visible_in_all_propagations)] if v is not None})
            except Exception:
                logger.warning("mysql update_task_graph_edge failed: edge_id=%s", edge_id, exc_info=True)

    def update_task_graph_session(
        self,
        session_relpath: str,
        *,
        node_id: str | None = None,
        edge_id: str | None = None,
        status: str | None = None,
        ended_at: str | None = None,
        event_count: int | None = None,
    ) -> None:
        if not session_relpath:
            return
        assigns: list[str] = []
        params: list[Any] = []
        for key, value in [
            ("node_id", node_id),
            ("edge_id", edge_id),
            ("status", status),
            ("ended_at", ended_at),
            ("event_count", event_count),
        ]:
            if value is None:
                continue
            assigns.append(f"{key}=?")
            params.append(value)
        if not assigns:
            return
        params.append(session_relpath)
        with self.connect() as conn:
            conn.execute(f"UPDATE task_graph_sessions SET {', '.join(assigns)} WHERE session_relpath=?", params)
        if self._mysql:
            try:
                self._mysql.update_task_graph_session(session_relpath, **{k: v for k, v in [("node_id", node_id), ("edge_id", edge_id), ("status", status), ("ended_at", ended_at), ("event_count", event_count)] if v is not None})
            except Exception:
                logger.warning(
                    "mysql update_task_graph_session failed: session_relpath=%s",
                    session_relpath,
                    exc_info=True,
                )

    def start_run(self, run_id: str, task_id: str, root_file: str, root_function: str, source_root: str, config: dict[str, Any] | None = None) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO analysis_runs
                   (run_id, task_id, root_file, root_function, source_root, status, started_at, config_json)
                   VALUES (?, ?, ?, ?, ?, 'running', ?, ?)""",
                (run_id, task_id, root_file, root_function, source_root, time.time(), json.dumps(config or {}, ensure_ascii=False)),
            )
        if self._mysql:
            try:
                self._mysql.start_run(run_id, task_id, root_file, root_function, source_root, config or {})
            except Exception:
                logger.warning("mysql start_run failed: run_id=%s task_id=%s", run_id, task_id, exc_info=True)


    def finish_run(self, run_id: str, status: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE analysis_runs SET status=?, finished_at=? WHERE run_id=?", (status, time.time(), run_id))
        if self._mysql:
            try:
                self._mysql.finish_run(run_id, status)
            except Exception:
                logger.warning("mysql finish_run failed: run_id=%s status=%s", run_id, status, exc_info=True)


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

    def update_finding_report_status(
        self,
        finding_id: str,
        *,
        status: str = "reported",
        case_id: str = "",
        task_id: str = "",
    ) -> None:
        if not finding_id:
            return
        with self.connect() as conn:
            conn.execute(
                "UPDATE vulnerability_findings SET report_status=?, report_case_id=? WHERE finding_id=?",
                (status, case_id, finding_id),
            )
        if self._mysql:
            try:
                self._mysql.update_finding_report_status(finding_id, status, case_id, task_id=task_id)
            except Exception:
                logger.warning(
                    "mysql update_finding_report_status failed: finding_id=%s task_id=%s",
                    finding_id,
                    task_id,
                    exc_info=True,
                )

    def add_finding(self, rec: VulnFindingRecord) -> None:
        data = asdict(rec)
        cols = list(data)
        with self.connect() as conn:
            conn.execute(
                f"INSERT OR REPLACE INTO vulnerability_findings ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
                [data[c] for c in cols],
            )
        if self._mysql:
            try:
                self._mysql.insert_finding(**data)
            except Exception:
                logger.warning("mysql insert_finding failed: finding_id=%s", rec.finding_id, exc_info=True)

    def list_task_findings(self, task_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(
                """SELECT vf.*
                   FROM vulnerability_findings vf
                   JOIN analysis_runs ar ON ar.run_id = vf.run_id
                   WHERE ar.task_id = ?
                   ORDER BY vf.created_at, vf.finding_id""",
                (task_id,),
            ).fetchall()]

    def list_all_findings(self, *, conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
        def _query(active_conn: sqlite3.Connection) -> list[dict[str, Any]]:
            return [dict(r) for r in active_conn.execute(
                "SELECT * FROM vulnerability_findings ORDER BY created_at, finding_id"
            ).fetchall()]

        if conn is not None:
            return _query(conn)
        with self.connect() as owned_conn:
            return _query(owned_conn)

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

    def record_container_taints(self, *, run_id: str, source_file: str, function_name: str, entries: list[dict[str, Any]], depth: int) -> None:
        """存储每函数分析后上报的容器驻留污点信息。

        entries 中每一项包含 {symbol, kind, evidence}。
        每条记录写入 container_taints 表。
        """
        import uuid
        import time as _time
        now = _time.time()
        with self.connect() as conn:
            for entry in (entries or []):
                if not isinstance(entry, dict):
                    continue
                sym = str(entry.get("symbol") or "").strip()
                if not sym:
                    continue
                ct_id = "ct_" + str(uuid.uuid4())[:16]
                conn.execute(
                    """INSERT OR REPLACE INTO container_taints
                       (container_taint_id, run_id, source_file, function_name,
                        symbol, kind, evidence, depth, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (ct_id, run_id, source_file, function_name,
                     sym, str(entry.get("kind") or "global"),
                     str(entry.get("evidence") or ""), int(depth), now),
                )

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
            for table in [
                "analysis_runs", "taint_nodes", "taint_edges", "followups",
                "vulnerability_findings", "context_forks", "analysis_contexts",
                "taint_constraints", "task_graph_runs", "task_graph_nodes",
                "task_graph_edges", "task_graph_sessions",
            ]:
                result[table] = [dict(r) for r in conn.execute(f"SELECT * FROM {table}").fetchall()]
            return result

    def export_task_graph_view(self, task_id: str) -> dict[str, Any]:
        with self.connect() as conn:
            run = conn.execute(
                "SELECT * FROM task_graph_runs WHERE task_id=?",
                (task_id,),
            ).fetchone()
            nodes = [dict(r) for r in conn.execute(
                "SELECT * FROM task_graph_nodes WHERE task_id=? ORDER BY depth, function_name_resolved, node_id",
                (task_id,),
            ).fetchall()]
            edges = [dict(r) for r in conn.execute(
                "SELECT * FROM task_graph_edges WHERE task_id=? ORDER BY display_order, source_function_resolved, edge_id",
                (task_id,),
            ).fetchall()]
            sessions = [dict(r) for r in conn.execute(
                "SELECT * FROM task_graph_sessions WHERE task_id=? ORDER BY session_relpath",
                (task_id,),
            ).fetchall()]
            findings = [dict(r) for r in conn.execute(
                """SELECT vf.*
                   FROM vulnerability_findings vf
                   JOIN analysis_runs ar ON ar.run_id = vf.run_id
                   WHERE ar.task_id = ?
                   ORDER BY vf.created_at, vf.finding_id""",
                (task_id,),
            ).fetchall()]
        run_root = Path(str(dict(run).get("run_root") or "")) if run else Path()
        task_root = run_root.parent.parent if run_root.parts and "epochs" in run_root.parts else run_root.parent
        for session in sessions:
            relpath = str(session.get("session_relpath") or "")
            if not relpath:
                continue
            candidates = [
                task_root / relpath,
                run_root / relpath,
                self.db_path.parent / relpath,
            ]
            session_path = next((path for path in candidates if path.exists()), None)
            if session_path is None:
                continue
            try:
                stat = session_path.stat()
                session["mtime"] = float(stat.st_mtime)
                if not int(session.get("event_count") or 0):
                    with session_path.open("r", encoding="utf-8", errors="ignore") as handle:
                        session["event_count"] = sum(1 for _ in handle)
            except Exception:
                continue
        node_by_id = {str(n["node_id"]): n for n in nodes}
        edges_by_source: dict[str, list[dict[str, Any]]] = {}
        for edge in edges:
            if int(edge.get("visible_in_tree") or 0) != 1:
                continue
            edges_by_source.setdefault(str(edge.get("source_node_id") or ""), []).append(edge)
        for edge_list in edges_by_source.values():
            edge_list.sort(key=lambda item: (int(item.get("display_order") or 0), str(item.get("edge_id") or "")))

        def _tree_node(node: dict[str, Any], seen: set[str]) -> dict[str, Any]:
            node_id = str(node.get("node_id") or "")
            if node_id in seen:
                return {
                    "node_id": node_id,
                    "function_name_resolved": node.get("function_name_resolved") or "",
                    "function_name_raw": node.get("function_name_raw") or "",
                    "source_file": node.get("source_file") or "",
                    "depth": int(node.get("depth") or 0),
                    "status": node.get("status") or "done",
                    "children": [],
                    "cycle": True,
                }
            next_seen = set(seen)
            next_seen.add(node_id)
            children: list[dict[str, Any]] = []
            for edge in edges_by_source.get(node_id, []):
                target_node_id = str(edge.get("target_node_id") or "")
                target = node_by_id.get(target_node_id)
                if target is None:
                    children.append({
                        "node_id": target_node_id or f"virtual::{edge.get('edge_id')}",
                        "edge_id": edge.get("edge_id") or "",
                        "function_name_resolved": edge.get("target_function_resolved") or edge.get("target_function_raw") or "",
                        "function_name_raw": edge.get("target_function_raw") or "",
                        "source_file": edge.get("target_file") or "",
                        "depth": int(node.get("depth") or 0) + 1,
                        "status": edge.get("status") or "unresolved",
                        "edge_kind": edge.get("edge_kind") or "",
                        "reason_code": edge.get("reason_code") or "",
                        "reason_message": edge.get("reason_message") or "",
                        "children": [],
                        "placeholder": True,
                    })
                    continue
                child = _tree_node(target, next_seen)
                child["edge_id"] = edge.get("edge_id") or ""
                child["edge_kind"] = edge.get("edge_kind") or ""
                child["reason_code"] = edge.get("reason_code") or ""
                child["reason_message"] = edge.get("reason_message") or ""
                children.append(child)
            return {
                "node_id": node_id,
                "function_name_resolved": node.get("function_name_resolved") or "",
                "function_name_raw": node.get("function_name_raw") or "",
                "source_file": node.get("source_file") or "",
                "depth": int(node.get("depth") or 0),
                "status": node.get("status") or "discovered",
                "analysis_status": node.get("analysis_status") or "pending",
                "findings_count": int(node.get("findings_count") or 0),
                "primary_session_relpath": node.get("primary_session_relpath") or "",
                "children": children,
            }

        root_node = min(nodes, key=lambda item: (int(item.get("depth") or 0), str(item.get("node_id") or ""))) if nodes else None
        summary = {
            "nodes_total": len(nodes),
            "edges_total": len(edges),
            "edges_discovered": sum(1 for item in edges if item.get("status") == "discovered"),
            "edges_scheduled": sum(1 for item in edges if item.get("status") == "scheduled"),
            "edges_done": sum(1 for item in edges if item.get("status") == "done"),
            "edges_running": sum(1 for item in edges if item.get("status") == "running"),
            "edges_failed": sum(1 for item in edges if item.get("status") == "failed"),
            "edges_cancelled": sum(1 for item in edges if item.get("status") == "cancelled"),
            "edges_unresolved": sum(1 for item in edges if item.get("status") == "unresolved"),
            "edges_not_followed": sum(1 for item in edges if item.get("status") == "not_followed"),
            "findings_total": len(findings) if findings else sum(int(item.get("findings_count") or 0) for item in nodes),
        }
        return {
            "task_id": task_id,
            "epoch": (dict(run).get("epoch") if run else ""),
            "available": bool(run or nodes or edges or sessions or findings),
            "summary": summary,
            "nodes": nodes,
            "edges": edges,
            "tree": _tree_node(root_node, set()) if root_node else None,
            "sessions": sessions,
            "findings": findings,
            "generated_at": (dict(run).get("generated_at") if run else None),
            "run_root": str(run_root) if run_root else (dict(run).get("run_root") if run else ""),
        }
