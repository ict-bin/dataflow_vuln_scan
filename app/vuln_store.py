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
    """V2 漏洞扫描存储 (MySQL ONLY, 无 SQLite)。

    数据全部存 MySQL (MysqlGraphStore):
      dvs_task_graph_runs / nodes / edges / sessions
      dvs_vuln_findings / dvs_analysis_runs
    """

    def __init__(
        self,
        db_path: str | Path,
        mysql_store=None,
        *,
        readonly: bool = False,
        enable_wal: bool = True,
    ):
        self.db_path = Path(db_path)
        self._mysql = mysql_store  # MysqlGraphStore

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """废弃: V2 数据全部在 MySQL, 不再读写 SQLite。保留空壳兼容旧调用方。"""
        import sqlite3
        conn = sqlite3.connect(":memory:")
        try:
            yield conn
        finally:
            conn.close()

    def init_schema(self) -> None:
        """废弃: V2 数据全部在 MySQL, SQLite 不再建表。"""
        pass

    def _upsert_rows(self, table: str, rows: list[dict[str, Any]]) -> None:
        """废弃: 不再被调用。"""
        pass

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

