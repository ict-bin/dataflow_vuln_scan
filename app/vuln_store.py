"""SQLite persistence for dataflow vulnerability mining.

The MySQL tables keep SecFlow task lifecycle.  This module stores the per-task
analysis graph in a task-local SQLite database under output/run so every forked
context can append deterministic taint/vulnerability facts without polluting the
platform database.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("dvs.vuln_store")

from sqlalchemy import func

try:
    import fcntl  # type: ignore
except Exception as e:  # pragma: no cover - Windows local tests
    logger.debug("fcntl import failed (non-unix): %s", e)
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
    def __init__(
        self,
        db_path: str | Path,
        mysql_store=None,
        *,
        readonly: bool = False,
        enable_wal: bool = True,
    ):
        self.db_path = Path(db_path)
        self.readonly = bool(readonly)
        self.enable_wal = bool(enable_wal)
        if not self.readonly:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._mysql = mysql_store
        if not self.readonly:
            self.init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        if self.readonly:
            conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=30)
        else:
            conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            if self.enable_wal:
                conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            if self.readonly:
                conn.execute("PRAGMA query_only=ON")
            yield conn
            if not self.readonly:
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

                CREATE INDEX IF NOT EXISTS ix_findings_run ON vulnerability_findings(run_id);

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
                except Exception as e:
                    logger.warning("execute ddl failed: %s", e, exc_info=True)

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
        if self._mysql:
            self._mysql.start_task_graph_run(rec)
        # SQLite 废弃

    def upsert_task_graph_node(self, rec: TaskGraphNodeRecord) -> None:
        if self._mysql:
            self._mysql.upsert_task_graph_node(rec)
        # SQLite 废弃

    def upsert_task_graph_edge(self, rec: TaskGraphEdgeRecord) -> None:
        if self._mysql:
            self._mysql.upsert_task_graph_edge(rec)
        # SQLite 废弃

    def upsert_task_graph_session(self, rec: TaskGraphSessionRecord) -> None:
        if self._mysql:
            self._mysql.upsert_task_graph_session(rec)
        # SQLite 废弃

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
        if self._mysql:
            self._mysql.update_task_graph_node(node_id, **{k: v for k, v in [("status", status), ("analysis_status", analysis_status), ("findings_count", findings_count), ("finished_at", finished_at), ("primary_session_relpath", primary_session_relpath)] if v is not None})
        # SQLite 废弃

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
        if self._mysql:
            self._mysql.update_task_graph_edge(edge_id, **{k: v for k, v in [("edge_kind", edge_kind), ("status", status), ("target_node_id", target_node_id), ("target_func_id", target_func_id), ("target_function_resolved", target_function_resolved), ("target_file", target_file), ("reason_code", reason_code), ("reason_message", reason_message), ("reason_source", reason_source), ("tracker_type", tracker_type), ("tracker_result_json", tracker_result_json), ("visible_in_tree", visible_in_tree), ("visible_in_all_propagations", visible_in_all_propagations)] if v is not None})
        # SQLite 废弃

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
        if self._mysql:
            self._mysql.update_task_graph_session(session_relpath, **{k: v for k, v in [("node_id", node_id), ("edge_id", edge_id), ("status", status), ("ended_at", ended_at), ("event_count", event_count)] if v is not None})
        # SQLite 废弃

    def start_run(self, run_id: str, task_id: str, root_file: str, root_function: str, source_root: str, config: dict[str, Any] | None = None) -> None:
        if self._mysql:
            self._mysql.start_run(run_id, task_id, root_file, root_function, source_root, config or {})
        # SQLite 废弃


    def finish_run(self, run_id: str, status: str) -> None:
        if self._mysql:
            self._mysql.finish_run(run_id, status)
        # SQLite 废弃

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
        if self._mysql:
            self._mysql.update_finding_report_status(finding_id, status, case_id, task_id=task_id)
        # SQLite 废弃

    def add_finding(self, rec: VulnFindingRecord) -> None:
        if self._mysql:
            data = asdict(rec)
            self._mysql.insert_finding(**data)
        # SQLite 废弃: vulnerability_findings 只写 MySQL

    def list_task_findings(self, task_id: str) -> list[dict[str, Any]]:
        if self._mysql:
            return self._mysql.list_task_findings(task_id)
        return []  # SQLite 废弃

    def list_all_findings(self, *, conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
        if self._mysql:
            return self._mysql.list_all_findings()
        return []  # SQLite 废弃

    def export_task_graph_view(self, task_id: str) -> dict[str, Any]:
        if self._mysql:
            return self._mysql.export_task_graph_view(task_id)
        return {"task_id": task_id, "available": False}  # SQLite 废弃

    def upsert_taint_node(self, rec) -> None:
        pass  # v1 遗留: V2 不调用, 表已删

    def add_taint_edges(self, records) -> None:
        pass  # v1 遗留

    def add_followups(self, records) -> None:
        pass  # v1 遗留

    def update_followup_status(self, followup_id: str, status: str, *, reason: str | None = None) -> None:
        pass  # v1 遗留

    def update_followup_tracker(self, followup_id: str, *, tracker_type: str, tracker_status: str, result: dict | None = None) -> None:
        pass  # v1 遗留

    def list_followups(self, run_id: str | None = None, *, status: str | None = None) -> list:
        return []  # v1 遗留

    def record_container_taints(self, **kw) -> None:
        pass  # v1 遗留

    def record_constraints(self, **kw) -> None:
        pass  # v1 遗留

    def find_covering_context(self, **kw) -> dict | None:
        return None  # v1 遗留

    def find_running_context(self, function_identity: str, taint_signature: str) -> dict | None:
        return None  # v1 遗留

    def update_context_validations(self, context_id: str, validations_json: str, func_hash: str = "") -> None:
        pass  # v1 遗留

    def upsert_analysis_context(self, **kw) -> None:
        pass  # v1 遗留

    def update_analysis_context_status(self, context_id: str, status: str) -> None:
        pass  # v1 遗留

    def add_context_fork(self, **kw) -> None:
        pass  # v1 遗留

    def has_path_seen(self, source_file: str, function_name: str, symbol: str, *, max_depth_revisit: int = 1) -> bool:
        return False  # v1 遗留

    def export_json(self) -> dict[str, Any]:
        return {}  # v1 遗留

