from __future__ import annotations

import sqlite3
from types import SimpleNamespace
from pathlib import Path

import app.api.tasks as tasks_module
from app.api.tasks import (
    get_task_result,
    get_task_graph_view,
    get_task_propagations,
    get_task_session_index,
    get_task_vuln_graph,
    list_task_sessions,
    _load_task_graph_view,
    _load_task_vulnerability_findings,
    _project_propagations_from_graph,
    _project_session_index_from_graph,
    _project_session_list_from_graph,
    _project_vuln_graph_summary_from_graph_view,
    _project_vuln_trace_tree_from_graph_view,
)
from app.vuln_store import TaskGraphEdgeRecord, TaskGraphNodeRecord, TaskGraphRunRecord, TaskGraphSessionRecord, VulnFindingRecord, VulnScanStore
from test_legacy_task_propagations_helper import load_task_propagations_legacy


def _exec_sql(db_path: Path, sql: str, params: tuple = ()) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def test_load_task_propagations_includes_followed_and_unfollowed(tmp_path: Path):
    run_root = tmp_path / "run"
    v2_root = run_root / "dataflow-v2"
    v2_root.mkdir(parents=True, exist_ok=True)

    functions_db = v2_root / "functions.db"
    propagations_db = v2_root / "propagations.db"
    orchestration_db = v2_root / "orchestration.db"

    _exec_sql(
        functions_db,
        """
        CREATE TABLE functions (
            func_id TEXT PRIMARY KEY,
            file TEXT,
            name TEXT
        )
        """,
    )
    _exec_sql(
        functions_db,
        "INSERT INTO functions(func_id, file, name) VALUES (?, ?, ?)",
        ("src_fn", "src/a.c", "Source::Entry"),
    )

    _exec_sql(
        propagations_db,
        """
        CREATE TABLE propagations (
            prop_id TEXT PRIMARY KEY,
            source_func_id TEXT,
            source_taint_name TEXT,
            source_taint_signature TEXT,
            target_taint_name TEXT,
            target_taint_signature TEXT,
            target_function TEXT,
            target_func_id TEXT,
            target_file TEXT,
            call_line INTEGER,
            condition TEXT,
            is_external INTEGER DEFAULT 0,
            is_indirect_call INTEGER DEFAULT 0,
            is_external_callee INTEGER DEFAULT 0,
            dispatch_kind TEXT DEFAULT '',
            escape_kind TEXT DEFAULT '',
            carrier TEXT DEFAULT '',
            escape_via TEXT DEFAULT '',
            callsite_validated INTEGER DEFAULT 0,
            branch_group_id TEXT DEFAULT '',
            branch_arm_id TEXT DEFAULT '',
            mutex_siblings TEXT DEFAULT '[]',
            validations TEXT DEFAULT '[]',
            actual_args TEXT DEFAULT '[]',
            description TEXT DEFAULT ''
        )
        """,
    )
    _exec_sql(
        propagations_db,
        """
        INSERT INTO propagations(
            prop_id, source_func_id, source_taint_name, source_taint_signature,
            target_taint_name, target_taint_signature, target_function, target_func_id,
            target_file, call_line, condition, is_external, is_indirect_call,
            is_external_callee, dispatch_kind, escape_kind, carrier, escape_via,
            callsite_validated, branch_group_id, branch_arm_id, mutex_siblings,
            validations, actual_args, description
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "prop_followed",
            "src_fn",
            "request",
            "sig_req",
            "arg0",
            "sig_arg0",
            "Target::Resolved",
            "dst_fn",
            "dst/file.cc",
            88,
            "if (ok)",
            0,
            0,
            0,
            "",
            "",
            "",
            "",
            1,
            "g1",
            "then",
            '["else_fn"]',
            '[{"left":"request","op":"!=","right":"nullptr","line":80}]',
            '["request", "ctx"]',
            "direct call",
        ),
    )
    _exec_sql(
        propagations_db,
        """
        INSERT INTO propagations(
            prop_id, source_func_id, source_taint_name, source_taint_signature,
            target_taint_name, target_taint_signature, target_function, target_func_id,
            target_file, call_line, condition, is_external, is_indirect_call,
            is_external_callee, dispatch_kind, escape_kind, carrier, escape_via,
            callsite_validated, branch_group_id, branch_arm_id, mutex_siblings,
            validations, actual_args, description
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "prop_unfollowed",
            "src_fn",
            "request",
            "sig_req",
            "ret",
            "sig_ret",
            "UnknownDispatch",
            "",
            "",
            99,
            "",
            0,
            1,
            0,
            "callback",
            "",
            "",
            "",
            0,
            "",
            "",
            "[]",
            "[]",
            "[]",
            "indirect call",
        ),
    )

    _exec_sql(
        orchestration_db,
        """
        CREATE TABLE orchestration (
            edge_id TEXT PRIMARY KEY,
            path_id TEXT,
            source_function TEXT,
            source_signature TEXT,
            source_func_id TEXT,
            target_function TEXT,
            target_signature TEXT,
            target_func_id TEXT,
            taint_params TEXT,
            depth INTEGER,
            edge_order INTEGER,
            status TEXT
        )
        """,
    )
    _exec_sql(
        orchestration_db,
        """
        INSERT INTO orchestration(
            edge_id, path_id, source_function, source_signature, source_func_id,
            target_function, target_signature, target_func_id, taint_params,
            depth, edge_order, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "edge1",
            "path1",
            "Source::Entry",
            "sig",
            "src_fn",
            "Target::Resolved",
            "sig_dst",
            "dst_fn",
            "{}",
            1,
            0,
            "done",
        ),
    )

    items = load_task_propagations_legacy(run_root)
    assert len(items) == 2

    followed = next(item for item in items if item["prop_id"] == "prop_followed")
    assert followed["source_function"] == "Source::Entry"
    assert followed["source_file"] == "src/a.c"
    assert followed["propagation_method"] == "直接调用"
    assert followed["orchestration_followed"] is True
    assert followed["orchestration_status"] == "done"
    assert followed["validations"] == [{"left": "request", "op": "!=", "right": "nullptr", "line": 80}]

    unfollowed = next(item for item in items if item["prop_id"] == "prop_unfollowed")
    assert unfollowed["propagation_method"] == "间接调用 / callback"
    assert unfollowed["orchestration_followed"] is False
    assert unfollowed["orchestration_status"] is None


def test_load_task_propagations_supports_name_fallback_and_external_kinds(tmp_path: Path):
    run_root = tmp_path / "run"
    v2_root = run_root / "dataflow-v2"
    v2_root.mkdir(parents=True, exist_ok=True)

    functions_db = v2_root / "functions.db"
    propagations_db = v2_root / "propagations.db"
    orchestration_db = v2_root / "orchestration.db"

    _exec_sql(
        functions_db,
        """
        CREATE TABLE functions (
            func_id TEXT PRIMARY KEY,
            file TEXT,
            name TEXT
        )
        """,
    )
    _exec_sql(
        functions_db,
        "INSERT INTO functions(func_id, file, name) VALUES (?, ?, ?)",
        ("src_fn", "src/mod.c", "Module::Handle"),
    )

    _exec_sql(
        propagations_db,
        """
        CREATE TABLE propagations (
            prop_id TEXT PRIMARY KEY,
            source_func_id TEXT,
            source_taint_name TEXT,
            source_taint_signature TEXT,
            target_taint_name TEXT,
            target_taint_signature TEXT,
            target_function TEXT,
            target_func_id TEXT,
            target_file TEXT,
            call_line INTEGER,
            condition TEXT,
            is_external INTEGER DEFAULT 0,
            is_indirect_call INTEGER DEFAULT 0,
            is_external_callee INTEGER DEFAULT 0,
            dispatch_kind TEXT DEFAULT '',
            escape_kind TEXT DEFAULT '',
            carrier TEXT DEFAULT '',
            escape_via TEXT DEFAULT '',
            callsite_validated INTEGER DEFAULT 0,
            branch_group_id TEXT DEFAULT '',
            branch_arm_id TEXT DEFAULT '',
            mutex_siblings TEXT DEFAULT '[]',
            validations TEXT DEFAULT '[]',
            actual_args TEXT DEFAULT '[]',
            description TEXT DEFAULT ''
        )
        """,
    )
    rows = [
        (
            "prop_name_only", "src_fn", "req", "sig_req", "arg1", "sig_arg1",
            "NamedTarget", "", "", 11, "", 0, 0, 0, "", "", "", "", 0, "", "", "[]", "[]", "[]", "name only"
        ),
        (
            "prop_external", "src_fn", "req", "sig_req", "global_buf", "sig_g",
            "", "", "", 22, "stores into container", 1, 0, 0, "", "container", "list_node", "push_back", 0, "", "", "[]", "[]", "[]", "escape"
        ),
        (
            "prop_external_callee", "src_fn", "req", "sig_req", "ret", "sig_ret",
            "ThirdParty::Sink", "", "", 33, "", 0, 0, 1, "", "", "", "", 0, "", "", "[]", "[]", "[]", "external callee"
        ),
    ]
    for row in rows:
        _exec_sql(
            propagations_db,
            """
            INSERT INTO propagations(
                prop_id, source_func_id, source_taint_name, source_taint_signature,
                target_taint_name, target_taint_signature, target_function, target_func_id,
                target_file, call_line, condition, is_external, is_indirect_call,
                is_external_callee, dispatch_kind, escape_kind, carrier, escape_via,
                callsite_validated, branch_group_id, branch_arm_id, mutex_siblings,
                validations, actual_args, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            row,
        )

    _exec_sql(
        orchestration_db,
        """
        CREATE TABLE orchestration (
            edge_id TEXT PRIMARY KEY,
            path_id TEXT,
            source_function TEXT,
            source_signature TEXT,
            source_func_id TEXT,
            target_function TEXT,
            target_signature TEXT,
            target_func_id TEXT,
            taint_params TEXT,
            depth INTEGER,
            edge_order INTEGER,
            status TEXT
        )
        """,
    )
    _exec_sql(
        orchestration_db,
        """
        INSERT INTO orchestration(
            edge_id, path_id, source_function, source_signature, source_func_id,
            target_function, target_signature, target_func_id, taint_params,
            depth, edge_order, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "edge_name_fallback",
            "path-name",
            "Module::Handle",
            "sig",
            "src_fn",
            "NamedTarget",
            "sig_target",
            "",
            "{}",
            1,
            0,
            "pending",
        ),
    )

    items = load_task_propagations_legacy(run_root)
    by_id = {item["prop_id"]: item for item in items}

    assert by_id["prop_name_only"]["orchestration_followed"] is True
    assert by_id["prop_name_only"]["orchestration_status"] == "pending"
    assert by_id["prop_external"]["propagation_method"] == "外部逃逸 / container"
    assert by_id["prop_external"]["carrier"] == "list_node"
    assert by_id["prop_external"]["escape_via"] == "push_back"
    assert by_id["prop_external_callee"]["propagation_method"] == "外部 callee"


def test_load_task_propagations_tolerates_legacy_db_without_external_callee_column(tmp_path: Path):
    run_root = tmp_path / "run"
    v2_root = run_root / "dataflow-v2"
    v2_root.mkdir(parents=True, exist_ok=True)

    functions_db = v2_root / "functions.db"
    propagations_db = v2_root / "propagations.db"

    _exec_sql(
        functions_db,
        """
        CREATE TABLE functions (
            func_id TEXT PRIMARY KEY,
            file TEXT,
            name TEXT
        )
        """,
    )
    _exec_sql(
        functions_db,
        "INSERT INTO functions(func_id, file, name) VALUES (?, ?, ?)",
        ("src_fn", "src/legacy.c", "Legacy::Entry"),
    )
    _exec_sql(
        propagations_db,
        """
        CREATE TABLE propagations (
            prop_id TEXT PRIMARY KEY,
            source_func_id TEXT,
            source_taint_name TEXT,
            source_taint_signature TEXT,
            target_taint_name TEXT,
            target_taint_signature TEXT,
            target_function TEXT,
            target_func_id TEXT,
            target_file TEXT,
            call_line INTEGER,
            condition TEXT,
            is_external INTEGER DEFAULT 0,
            is_indirect_call INTEGER DEFAULT 0,
            dispatch_kind TEXT DEFAULT '',
            escape_kind TEXT DEFAULT '',
            carrier TEXT DEFAULT '',
            escape_via TEXT DEFAULT '',
            callsite_validated INTEGER DEFAULT 0,
            branch_group_id TEXT DEFAULT '',
            branch_arm_id TEXT DEFAULT '',
            mutex_siblings TEXT DEFAULT '[]',
            validations TEXT DEFAULT '[]',
            actual_args TEXT DEFAULT '[]',
            description TEXT DEFAULT ''
        )
        """,
    )
    _exec_sql(
        propagations_db,
        """
        INSERT INTO propagations(
            prop_id, source_func_id, source_taint_name, source_taint_signature,
            target_taint_name, target_taint_signature, target_function, target_func_id,
            target_file, call_line, condition, is_external, is_indirect_call,
            dispatch_kind, escape_kind, carrier, escape_via, callsite_validated,
            branch_group_id, branch_arm_id, mutex_siblings, validations, actual_args, description
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "legacy_prop",
            "src_fn",
            "req",
            "sig_req",
            "ret",
            "sig_ret",
            "LegacyTarget",
            "",
            "",
            7,
            "",
            0,
            0,
            "",
            "",
            "",
            "",
            0,
            "",
            "",
            "[]",
            "[]",
            "[]",
            "legacy row",
        ),
    )

    items = load_task_propagations_legacy(run_root)
    assert len(items) == 1
    assert items[0]["prop_id"] == "legacy_prop"
    assert items[0]["is_external_callee"] is False
    assert items[0]["propagation_method"] == "直接调用"


def test_load_task_propagations_prefers_followup_reason_for_unfollowed_items(tmp_path: Path):
    run_root = tmp_path / "run"
    v2_root = run_root / "dataflow-v2"
    out_root = run_root.parent / "output"
    v2_root.mkdir(parents=True, exist_ok=True)
    out_root.mkdir(parents=True, exist_ok=True)

    functions_db = v2_root / "functions.db"
    propagations_db = v2_root / "propagations.db"
    vuln_db = out_root / "vuln-scan.sqlite"

    _exec_sql(
        functions_db,
        """
        CREATE TABLE functions (
            func_id TEXT PRIMARY KEY,
            file TEXT,
            name TEXT
        )
        """,
    )
    _exec_sql(
        functions_db,
        "INSERT INTO functions(func_id, file, name) VALUES (?, ?, ?)",
        ("src_fn", "src/followup.c", "Followup::Entry"),
    )
    _exec_sql(
        propagations_db,
        """
        CREATE TABLE propagations (
            prop_id TEXT PRIMARY KEY,
            source_func_id TEXT,
            source_taint_name TEXT,
            source_taint_signature TEXT,
            target_taint_name TEXT,
            target_taint_signature TEXT,
            target_function TEXT,
            target_func_id TEXT,
            target_file TEXT,
            call_line INTEGER,
            condition TEXT,
            is_external INTEGER DEFAULT 0,
            is_indirect_call INTEGER DEFAULT 0,
            is_external_callee INTEGER DEFAULT 0,
            dispatch_kind TEXT DEFAULT '',
            escape_kind TEXT DEFAULT '',
            carrier TEXT DEFAULT '',
            escape_via TEXT DEFAULT '',
            callsite_validated INTEGER DEFAULT 0,
            branch_group_id TEXT DEFAULT '',
            branch_arm_id TEXT DEFAULT '',
            mutex_siblings TEXT DEFAULT '[]',
            validations TEXT DEFAULT '[]',
            actual_args TEXT DEFAULT '[]',
            description TEXT DEFAULT ''
        )
        """,
    )
    _exec_sql(
        propagations_db,
        """
        INSERT INTO propagations(
            prop_id, source_func_id, source_taint_name, source_taint_signature,
            target_taint_name, target_taint_signature, target_function, target_func_id,
            target_file, call_line, condition, is_external, is_indirect_call,
            is_external_callee, dispatch_kind, escape_kind, carrier, escape_via,
            callsite_validated, branch_group_id, branch_arm_id, mutex_siblings,
            validations, actual_args, description
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "prop_with_followup_reason",
            "src_fn",
            "req",
            "sig_req",
            "cb",
            "sig_cb",
            "Callback::Invoke",
            "",
            "",
            44,
            "",
            0,
            1,
            0,
            "callback",
            "",
            "",
            "",
            0,
            "",
            "",
            "[]",
            "[]",
            "[]",
            "with followup reason",
        ),
    )
    _exec_sql(
        vuln_db,
        """
        CREATE TABLE followups (
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
            created_at REAL NOT NULL DEFAULT 0
        )
        """,
    )
    _exec_sql(
        vuln_db,
        """
        INSERT INTO followups(
            followup_id, edge_id, parent_node_id, callee_file, callee_function,
            callee_line, tainted_params_json, status, reason, fork_session, depth,
            dispatch_kind, tainted_nonlocal_json, tracker_type, tracker_status, tracker_result_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "fw_1",
            "prop_with_followup_reason",
            "",
            "",
            "Callback::Invoke",
            "",
            "[]",
            "skipped",
            "tracker_resolved",
            "",
            1,
            "callback",
            "[]",
            "indirect",
            "resolved_without_schedule",
            "{}",
            0,
        ),
    )

    items = load_task_propagations_legacy(run_root)
    assert len(items) == 1
    item = items[0]
    assert item["unfollowed_reason"] == "tracker_resolved"
    assert item["unfollowed_reason_source"] == "followup"
    assert item["followup_status"] == "skipped"
    assert item["followup_reason_raw"] == "tracker_resolved"


def test_load_task_propagations_uses_tracker_status_when_followup_reason_missing(tmp_path: Path):
    run_root = tmp_path / "run"
    v2_root = run_root / "dataflow-v2"
    out_root = run_root.parent / "output"
    v2_root.mkdir(parents=True, exist_ok=True)
    out_root.mkdir(parents=True, exist_ok=True)

    functions_db = v2_root / "functions.db"
    propagations_db = v2_root / "propagations.db"
    vuln_db = out_root / "vuln-scan.sqlite"

    _exec_sql(functions_db, "CREATE TABLE functions (func_id TEXT PRIMARY KEY, file TEXT, name TEXT)")
    _exec_sql(functions_db, "INSERT INTO functions(func_id, file, name) VALUES (?, ?, ?)", ("src_fn", "src/tracker.c", "Tracker::Entry"))
    _exec_sql(
        propagations_db,
        """
        CREATE TABLE propagations (
            prop_id TEXT PRIMARY KEY,
            source_func_id TEXT,
            source_taint_name TEXT,
            source_taint_signature TEXT,
            target_taint_name TEXT,
            target_taint_signature TEXT,
            target_function TEXT,
            target_func_id TEXT,
            target_file TEXT,
            call_line INTEGER,
            condition TEXT,
            is_external INTEGER DEFAULT 0,
            is_indirect_call INTEGER DEFAULT 0,
            is_external_callee INTEGER DEFAULT 0,
            dispatch_kind TEXT DEFAULT '',
            escape_kind TEXT DEFAULT '',
            carrier TEXT DEFAULT '',
            escape_via TEXT DEFAULT '',
            callsite_validated INTEGER DEFAULT 0,
            branch_group_id TEXT DEFAULT '',
            branch_arm_id TEXT DEFAULT '',
            mutex_siblings TEXT DEFAULT '[]',
            validations TEXT DEFAULT '[]',
            actual_args TEXT DEFAULT '[]',
            description TEXT DEFAULT ''
        )
        """,
    )
    _exec_sql(
        propagations_db,
        """
        INSERT INTO propagations(
            prop_id, source_func_id, source_taint_name, source_taint_signature,
            target_taint_name, target_taint_signature, target_function, target_func_id,
            target_file, call_line, condition, is_external, is_indirect_call,
            is_external_callee, dispatch_kind, escape_kind, carrier, escape_via,
            callsite_validated, branch_group_id, branch_arm_id, mutex_siblings,
            validations, actual_args, description
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "prop_tracker_only",
            "src_fn",
            "req",
            "sig_req",
            "dispatch",
            "sig_dispatch",
            "Dispatch::Fire",
            "",
            "",
            55,
            "",
            0,
            1,
            0,
            "function_pointer_field",
            "",
            "",
            "",
            0,
            "",
            "",
            "[]",
            "[]",
            "[]",
            "tracker only",
        ),
    )
    _exec_sql(
        vuln_db,
        """
        CREATE TABLE followups (
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
            created_at REAL NOT NULL DEFAULT 0
        )
        """,
    )
    _exec_sql(
        vuln_db,
        """
        INSERT INTO followups(
            followup_id, edge_id, parent_node_id, callee_file, callee_function,
            callee_line, tainted_params_json, status, reason, fork_session, depth,
            dispatch_kind, tainted_nonlocal_json, tracker_type, tracker_status, tracker_result_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "fw_2",
            "prop_tracker_only",
            "",
            "",
            "Dispatch::Fire",
            "",
            "[]",
            "skipped",
            "",
            "",
            1,
            "function_pointer_field",
            "[]",
            "indirect",
            "resolved_without_schedule",
            "{}",
            0,
        ),
    )

    item = load_task_propagations_legacy(run_root)[0]
    assert item["unfollowed_reason"] == "indirect:resolved_without_schedule"
    assert item["unfollowed_reason_source"] == "followup"
    assert item["followup_status"] == "skipped"


def test_project_propagations_from_graph_preserves_graph_fields():
    view = {
        "edges": [
            {
                "edge_id": "edge-visible",
                "source_prop_id": "prop-visible",
                "edge_kind": "container_reader",
                "status": "running",
                "source_func_id": "src-func",
                "source_function_resolved": "Root::Handle",
                "source_file": "src/root.cpp",
                "source_taint_name": "msg",
                "target_taint_name": "entry",
                "target_func_id": "dst-func",
                "target_function_raw": "Ns::Entry",
                "target_function_resolved": "Entry",
                "target_file": "src/entry.cpp",
                "call_line": 42,
                "validations_json": '[{"left":"msg","op":"!=","right":"nullptr","line":41}]',
                "actual_args_json": '["msg"]',
                "reason_code": "tracker_resolved",
                "reason_message": "resolved by external tracker",
                "reason_source": "tracker",
                "visible_in_all_propagations": 1,
            },
            {
                "edge_id": "edge-hidden",
                "source_prop_id": "prop-hidden",
                "edge_kind": "direct_call",
                "status": "done",
                "visible_in_all_propagations": 0,
            },
        ],
    }

    items = _project_propagations_from_graph(view)
    assert len(items) == 1
    item = items[0]
    assert item["prop_id"] == "prop-visible"
    assert item["edge_id"] == "edge-visible"
    assert item["edge_kind"] == "container_reader"
    assert item["status"] == "running"
    assert item["target_function"] == "Entry"
    assert item["target_function_raw"] == "Ns::Entry"
    assert item["target_function_resolved"] == "Entry"
    assert item["orchestration_followed"] is True
    assert item["reason_code"] == "tracker_resolved"
    assert item["reason_message"] == "resolved by external tracker"


def test_project_propagations_from_graph_preserves_terminal_and_unfollowed_statuses():
    view = {
        "edges": [
            {
                "edge_id": "edge-failed",
                "source_prop_id": "prop-failed",
                "edge_kind": "direct_call",
                "status": "failed",
                "source_function_resolved": "Root",
                "target_function_resolved": "Child",
                "target_function_raw": "Ns::Child",
                "reason_code": "child_process_failed",
                "reason_message": "child process failed",
                "reason_source": "runtime",
                "visible_in_all_propagations": 1,
            },
            {
                "edge_id": "edge-cancelled",
                "source_prop_id": "prop-cancelled",
                "edge_kind": "indirect_call",
                "status": "cancelled",
                "source_function_resolved": "Root",
                "target_function_resolved": "Child2",
                "target_function_raw": "Ns::Child2",
                "reason_code": "owner_cancelled",
                "reason_message": "owner cancelled followup",
                "reason_source": "runtime",
                "visible_in_all_propagations": 1,
            },
            {
                "edge_id": "edge-not-followed",
                "source_prop_id": "prop-not-followed",
                "edge_kind": "external_callee",
                "status": "not_followed",
                "source_function_resolved": "Root",
                "target_function_resolved": "",
                "target_function_raw": "Ext::Call",
                "reason_code": "external_callee",
                "reason_message": "callee definition is outside source tree",
                "reason_source": "analysis",
                "visible_in_all_propagations": 1,
            },
        ],
    }

    items = {item["edge_id"]: item for item in _project_propagations_from_graph(view)}
    assert items["edge-failed"]["orchestration_followed"] is True
    assert items["edge-failed"]["orchestration_status"] == "failed"
    assert items["edge-cancelled"]["orchestration_followed"] is True
    assert items["edge-cancelled"]["orchestration_status"] == "cancelled"
    assert items["edge-not-followed"]["orchestration_followed"] is False
    assert items["edge-not-followed"]["target_function"] == "Ext::Call"
    assert items["edge-not-followed"]["unfollowed_reason"] == "external_callee"
    assert items["edge-not-followed"]["reason_message"] == "callee definition is outside source tree"


def test_project_propagations_from_graph_marks_external_escape_edges_as_external():
    view = {
        "edges": [
            {
                "edge_id": "edge-external",
                "source_prop_id": "prop-external",
                "edge_kind": "unresolved_target",
                "status": "unresolved",
                "source_function_resolved": "Root",
                "target_function_resolved": "Reader",
                "target_function_raw": "Ns::Reader",
                "target_file": "src/reader.cpp",
                "reason_code": "tracker_no_target",
                "reason_message": "external tracker did not resolve target",
                "reason_source": "tracker",
                "visible_in_all_propagations": 1,
            },
        ],
    }

    items = _project_propagations_from_graph(view)
    assert len(items) == 1
    item = items[0]
    assert item["edge_id"] == "edge-external"
    assert item["edge_kind"] == "unresolved_target"
    assert item["is_external"] is False
    assert item["is_indirect_call"] is False
    assert item["is_external_callee"] is False
    assert item["target_function"] == "Reader"
    assert item["target_function_raw"] == "Ns::Reader"
    assert item["orchestration_followed"] is False
    assert item["unfollowed_reason"] == "tracker_no_target"
    assert item["reason_message"] == "external tracker did not resolve target"


def test_project_propagations_from_graph_distinguishes_discovered_and_scheduled_edges():
    view = {
        "edges": [
            {
                "edge_id": "edge-discovered",
                "source_prop_id": "prop-discovered",
                "edge_kind": "direct_call",
                "status": "discovered",
                "source_function_resolved": "Root",
                "target_function_resolved": "Child",
                "target_function_raw": "Ns::Child",
                "visible_in_all_propagations": 1,
            },
            {
                "edge_id": "edge-scheduled",
                "source_prop_id": "prop-scheduled",
                "edge_kind": "container_reader",
                "status": "scheduled",
                "source_function_resolved": "Root",
                "target_function_resolved": "Reader",
                "target_function_raw": "Ns::Reader",
                "visible_in_all_propagations": 1,
            },
        ],
    }

    items = {item["edge_id"]: item for item in _project_propagations_from_graph(view)}
    assert items["edge-discovered"]["orchestration_followed"] is False
    assert items["edge-discovered"]["orchestration_status"] == "discovered"
    assert items["edge-scheduled"]["orchestration_followed"] is True
    assert items["edge-scheduled"]["orchestration_status"] == "scheduled"
    assert items["edge-scheduled"]["edge_kind"] == "container_reader"


def test_project_propagations_from_graph_maps_return_followup_to_human_label():
    view = {
        "edges": [
            {
                "edge_id": "edge-return",
                "source_prop_id": "edge-return",
                "edge_kind": "return_followup",
                "status": "done",
                "source_function_resolved": "Child",
                "target_function_resolved": "Root",
                "target_function_raw": "Root",
                "source_taint_name": "ret_msg",
                "target_taint_name": "ret_msg",
                "visible_in_all_propagations": 1,
            },
        ],
    }

    items = _project_propagations_from_graph(view)
    assert len(items) == 1
    item = items[0]
    assert item["edge_kind"] == "return_followup"
    assert item["propagation_method"] == "返回值回溯"
    assert item["orchestration_followed"] is True
    assert item["orchestration_status"] == "done"


def test_return_followup_projection_stays_visible_in_propagations_but_hidden_from_tree():
    view = {
        "summary": {"nodes_total": 2, "edges_total": 2, "findings_total": 0},
        "nodes": [
            {"node_id": "node-root", "function_name_resolved": "Root", "function_name_raw": "Root"},
            {"node_id": "node-child", "function_name_resolved": "Child", "function_name_raw": "Child"},
        ],
        "edges": [
            {
                "edge_id": "edge-direct",
                "source_prop_id": "prop-direct",
                "source_node_id": "node-root",
                "target_node_id": "node-child",
                "edge_kind": "direct_call",
                "status": "done",
                "visible_in_all_propagations": 1,
                "visible_in_tree": 1,
                "source_function_resolved": "Root",
                "target_function_resolved": "Child",
                "target_function_raw": "Child",
            },
            {
                "edge_id": "edge-return",
                "source_prop_id": "edge-return",
                "source_node_id": "node-child",
                "target_node_id": "node-root",
                "edge_kind": "return_followup",
                "status": "done",
                "visible_in_all_propagations": 1,
                "visible_in_tree": 0,
                "source_function_resolved": "Child",
                "target_function_resolved": "Root",
                "target_function_raw": "Root",
            },
        ],
        "tree": {
            "node_id": "node-root",
            "function_name_resolved": "Root",
            "function_name_raw": "Root",
            "source_file": "src/root.cpp",
            "depth": 0,
            "status": "done",
            "children": [
                {
                    "node_id": "node-child",
                    "edge_id": "edge-direct",
                    "function_name_resolved": "Child",
                    "function_name_raw": "Child",
                    "source_file": "src/child.cpp",
                    "depth": 1,
                    "status": "done",
                    "children": [],
                },
            ],
        },
    }

    propagations = {item["edge_id"]: item for item in _project_propagations_from_graph(view)}
    trace_tree = _project_vuln_trace_tree_from_graph_view(view["tree"])

    assert set(propagations) == {"edge-direct", "edge-return"}
    assert propagations["edge-return"]["propagation_method"] == "返回值回溯"
    assert trace_tree is not None
    assert len(trace_tree["children"]) == 1
    assert trace_tree["children"][0]["function_name"] == "Child"


def test_project_session_views_from_graph_use_session_nodes():
    view = {
        "task_id": "task-1",
        "epoch": "0001",
        "generated_at": 1780000000.0,
        "summary": {"nodes_total": 2},
        "nodes": [
            {"node_id": "node-root", "function_name_resolved": "Root", "function_name_raw": "Root"},
            {"node_id": "node-child", "function_name_resolved": "Child", "function_name_raw": "Ns::Child"},
        ],
        "sessions": [
            {
                "session_relpath": "sessions/root.taint.jsonl",
                "node_id": "node-root",
                "edge_id": "",
                "session_role": "worker",
                "session_kind": "taint",
                "display_name": "root.taint",
                "status": "running",
                "mtime": 123.0,
                "event_count": 7,
            },
            {
                "session_relpath": "sessions/child.taint.jsonl",
                "node_id": "node-child",
                "edge_id": "edge-1",
                "session_role": "worker",
                "session_kind": "taint",
                "display_name": "child.taint",
                "status": "done",
                "mtime": 456.0,
                "event_count": 9,
            },
        ],
        "edges": [
            {
                "edge_id": "edge-1",
                "source_node_id": "node-root",
                "target_node_id": "node-child",
                "edge_kind": "direct_call",
            },
        ],
    }

    items = _project_session_list_from_graph(view)
    assert items[0]["relative_path"] == "sessions/root.taint.jsonl"
    assert items[0]["agent_session"]["function_name"] == "Root"

    index = _project_session_index_from_graph(
        task_id="task-1",
        task_status="running",
        run_root=Path("/tmp/run"),
        view=view,
    )
    assert index["nodes"][0]["node_id"] == "sessions/root.taint.jsonl"
    assert index["edges"][0]["source_node_id"] == "sessions/root.taint.jsonl"
    assert index["edges"][0]["target_node_id"] == "sessions/child.taint.jsonl"
    assert index["groups"][0]["group_id"] == "node-root"


def test_project_session_views_from_graph_allow_empty_sessions_without_fallback_shape():
    view = {
        "task_id": "task-empty",
        "epoch": "0002",
        "generated_at": 1780000001.0,
        "summary": {"nodes_total": 1, "edges_total": 0},
        "nodes": [
            {"node_id": "node-root", "function_name_resolved": "Root", "function_name_raw": "Root"},
        ],
        "sessions": [],
        "edges": [],
    }

    items = _project_session_list_from_graph(view)
    assert items == []

    index = _project_session_index_from_graph(
        task_id="task-empty",
        task_status="done",
        run_root=Path("/tmp/run"),
        view=view,
    )
    assert index["task_id"] == "task-empty"
    assert index["status"] == "done"
    assert index["summary"] == {"nodes_total": 1, "edges_total": 0}
    assert index["nodes"] == []
    assert index["edges"] == []
    assert index["groups"] == []
    assert index["warnings"] == []


def test_load_task_vulnerability_findings_reads_vuln_scan_sqlite(tmp_path: Path):
    run_root = tmp_path / "run"
    run_root.mkdir(parents=True, exist_ok=True)
    store = VulnScanStore(run_root / "vuln-scan.sqlite")

    _exec_sql(
        run_root / "vuln-scan.sqlite",
        """
        INSERT INTO analysis_runs(
            run_id, task_id, root_file, root_function, source_root, status, started_at, config_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("run-1", "task-1", "src/root.cpp", "Root", "/src", "done", 1780000000.0, "{}"),
    )
    _exec_sql(
        run_root / "vuln-scan.sqlite",
        """
        INSERT INTO vulnerability_findings(
            finding_id, run_id, node_id, edge_id, source_file, function_name, line,
            vuln_type, severity, title, summary, evidence, exploitability, confidence,
            output_dir, report_status, report_case_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "finding-1",
            "run-1",
            "node-root",
            "edge-1",
            "src/root.cpp",
            "Root",
            "41",
            "sql_injection",
            "high",
            "Root issue",
            "summary",
            "evidence",
            "exploitability",
            0.8,
            "/tmp/out/finding-1",
            "reported",
            "CASE-1",
        ),
    )

    findings = _load_task_vulnerability_findings(run_root, "task-1")
    assert len(findings) == 1
    assert findings[0]["finding_id"] == "finding-1"
    assert findings[0]["function_name"] == "Root"
    assert findings[0]["report_status"] == "reported"


def test_load_task_vulnerability_findings_does_not_fallback_to_other_tasks(tmp_path: Path):
    run_root = tmp_path / "run"
    run_root.mkdir(parents=True, exist_ok=True)
    VulnScanStore(run_root / "vuln-scan.sqlite")

    _exec_sql(
        run_root / "vuln-scan.sqlite",
        """
        INSERT INTO analysis_runs(
            run_id, task_id, root_file, root_function, source_root, status, started_at, config_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("run-2", "task-other", "src/other.cpp", "Other", "/src", "done", 1780000002.0, "{}"),
    )
    _exec_sql(
        run_root / "vuln-scan.sqlite",
        """
        INSERT INTO vulnerability_findings(
            finding_id, run_id, node_id, edge_id, source_file, function_name, line,
            vuln_type, severity, title, summary, evidence, exploitability, confidence,
            output_dir, report_status, report_case_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "finding-other-1",
            "run-2",
            "node-other",
            "edge-other",
            "src/other.cpp",
            "Other",
            "22",
            "command_injection",
            "medium",
            "Other issue",
            "summary",
            "evidence",
            "exploitability",
            0.5,
            "/tmp/out/finding-other-1",
            "",
            "",
        ),
    )

    findings = _load_task_vulnerability_findings(run_root, "task-missing")

    assert findings == []


def test_load_task_vulnerability_findings_returns_empty_without_authoritative_graph_store(tmp_path: Path):
    run_root = tmp_path / "run"
    v2_root = run_root / "dataflow-v2"
    run_root.mkdir(parents=True, exist_ok=True)
    v2_root.mkdir(parents=True, exist_ok=True)

    _exec_sql(
        v2_root / "functions.db",
        """
        CREATE TABLE functions (
            func_id TEXT PRIMARY KEY,
            file TEXT,
            name TEXT
        )
        """,
    )
    _exec_sql(
        v2_root / "functions.db",
        "INSERT INTO functions(func_id, file, name) VALUES (?, ?, ?)",
        ("root-func", "src/root.cpp", "Root"),
    )

    findings = _load_task_vulnerability_findings(run_root, "task-without-graph")

    assert findings == []


def test_task_graph_view_findings_match_compat_findings_loader(tmp_path: Path):
    run_root = tmp_path / "run"
    run_root.mkdir(parents=True, exist_ok=True)
    store = VulnScanStore(run_root / "vuln-scan.sqlite")
    store.start_task_graph_run(TaskGraphRunRecord(
        task_id="task-graph",
        epoch="1",
        run_root=str(run_root),
        root_function="Root",
    ))

    _exec_sql(
        run_root / "vuln-scan.sqlite",
        """
        INSERT INTO analysis_runs(
            run_id, task_id, root_file, root_function, source_root, status, started_at, config_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("run-graph", "task-graph", "src/root.cpp", "Root", "/src", "done", 1780000001.0, "{}"),
    )
    _exec_sql(
        run_root / "vuln-scan.sqlite",
        """
        INSERT INTO vulnerability_findings(
            finding_id, run_id, node_id, edge_id, source_file, function_name, line,
            vuln_type, severity, title, summary, evidence, exploitability, confidence,
            output_dir, report_status, report_case_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "finding-graph-1",
            "run-graph",
            "node-root",
            "edge-1",
            "src/root.cpp",
            "Root",
            "52",
            "command_injection",
            "critical",
            "Root issue",
            "summary",
            "evidence",
            "exploitability",
            0.9,
            "/tmp/out/finding-graph-1",
            "reported",
            "CASE-9",
        ),
    )

    compat_findings = _load_task_vulnerability_findings(run_root, "task-graph")
    view = _load_task_graph_view(run_root, "task-graph")

    assert [item["finding_id"] for item in compat_findings] == [item["finding_id"] for item in view["findings"]]
    assert view["summary"]["findings_total"] == len(compat_findings) == 1
    assert view["findings"][0]["report_status"] == "reported"


def test_legacy_vuln_graph_projection_stays_consistent_with_graph_view_facts(tmp_path: Path):
    run_root = tmp_path / "run"
    run_root.mkdir(parents=True, exist_ok=True)
    store = VulnScanStore(run_root / "vuln-scan.sqlite")
    store.start_task_graph_run(TaskGraphRunRecord(
        task_id="task-projection",
        epoch="7",
        run_root=str(run_root),
        root_function="Root",
    ))
    store.upsert_task_graph_node(TaskGraphNodeRecord(
        node_id="node-root",
        task_id="task-projection",
        epoch="7",
        func_id="root-func",
        function_name_resolved="Root",
        function_name_raw="Root",
        source_file="src/root.cpp",
        depth=0,
        status="done",
        analysis_status="done",
    ))
    store.upsert_task_graph_edge(TaskGraphEdgeRecord(
        edge_id="edge-child",
        task_id="task-projection",
        epoch="7",
        source_node_id="node-root",
        target_node_id="",
        source_func_id="root-func",
        target_func_id="",
        source_function_resolved="Root",
        target_function_resolved="Child",
        target_function_raw="Ns::Child",
        source_file="src/root.cpp",
        target_file="src/child.cpp",
        edge_kind="direct_call",
        status="unresolved",
        source_prop_id="prop-child",
        reason_code="tracker_no_target",
        reason_message="tracker did not resolve target",
        visible_in_tree=1,
        visible_in_all_propagations=1,
    ))
    store.start_run(run_id="run-projection", task_id="task-projection", root_file="src/root.cpp", root_function="Root", source_root="/src")
    store.add_finding(VulnFindingRecord(
        finding_id="finding-projection-1",
        run_id="run-projection",
        node_id="node-root",
        edge_id="edge-child",
        source_file="src/root.cpp",
        function_name="Root",
        line="61",
        vuln_type="sql_injection",
        severity="medium",
        title="Root issue",
        summary="summary",
        evidence="evidence",
        exploitability="exploitability",
        confidence=0.6,
        output_dir="/tmp/out/finding-projection-1",
    ))

    view = _load_task_graph_view(run_root, "task-projection")
    compat_findings = _load_task_vulnerability_findings(run_root, "task-projection")
    projected_tree = _project_vuln_trace_tree_from_graph_view(view["tree"])
    projected_summary = _project_vuln_graph_summary_from_graph_view(view)

    assert view["available"] is True
    assert [item["finding_id"] for item in view["findings"]] == [item["finding_id"] for item in compat_findings]
    assert projected_tree is not None
    assert projected_tree["run_id"] == "node-root"
    assert projected_tree["children"][0]["run_id"] == "virtual::edge-child"
    assert projected_tree["children"][0]["prune_reason"] == "tracker_no_target"
    assert projected_summary["findings"] == len(view["findings"]) == 1
    assert projected_summary["followups"] == len(view["edges"]) == 1


def test_load_task_graph_view_without_authoritative_store_stays_empty(tmp_path: Path):
    run_root = tmp_path / "run"
    run_root.mkdir(parents=True, exist_ok=True)

    view = _load_task_graph_view(run_root, "task-empty-authoritative")
    session_index = _project_session_index_from_graph(
        task_id="task-empty-authoritative",
        task_status="running",
        run_root=run_root,
        view=view,
    )

    assert view == {
        "task_id": "task-empty-authoritative",
        "epoch": "",
        "available": False,
        "summary": {},
        "nodes": [],
        "edges": [],
        "tree": None,
        "sessions": [],
        "findings": [],
        "generated_at": None,
        "run_root": str(run_root),
    }
    assert session_index["nodes"] == []
    assert session_index["edges"] == []
    assert session_index["groups"] == []
    assert session_index["summary"] == {}


def test_project_session_index_from_graph_marks_graph_view_as_authoritative_source(tmp_path: Path):
    run_root = tmp_path / "run"
    view = {
        "run_root": str(run_root),
        "generated_at": 1780000000.0,
        "summary": {"session_count": 1},
        "nodes": [
            {
                "node_id": "node-root",
                "function_name_resolved": "Root",
                "function_name_raw": "Root",
                "depth": 0,
                "status": "running",
            },
        ],
        "edges": [],
        "sessions": [
            {
                "session_relpath": "sessions/root.jsonl",
                "node_id": "node-root",
                "edge_id": "",
                "session_kind": "taint",
                "session_role": "worker",
                "display_name": "root",
                "status": "running",
                "started_at": "2026-07-19T00:00:00Z",
                "ended_at": None,
                "mtime": 1780000000.0,
                "event_count": 2,
            }
        ],
    }

    session_index = _project_session_index_from_graph(
        task_id="task-graph-authority",
        task_status="running",
        run_root=run_root,
        view=view,
    )

    assert session_index["sessions_root"] == str(run_root / "sessions")
    assert session_index["index_path"] == f"{run_root}/graph-view"
    assert session_index["generated_at"] == "2026-05-28T20:26:40Z"
    assert session_index["nodes"][0]["session_header"]["node_id"] == "node-root"
    assert session_index["edges"] == []


def test_route_level_graph_endpoints_stay_empty_without_authoritative_store(tmp_path: Path, monkeypatch):
    task_id = "task-route-empty-authoritative"
    output_root = tmp_path / "output"
    task_root = output_root / task_id
    run_root = task_root / "run"
    run_root.mkdir(parents=True, exist_ok=True)

    row = SimpleNamespace(
        task_id=task_id,
        output_path=str(output_root),
        result_json={},
        status="running",
    )
    monkeypatch.setattr(tasks_module, "_get_task_row", lambda db, value: row)

    graph_view = get_task_graph_view(task_id, db=None).model_dump()
    vuln_graph = get_task_vuln_graph(task_id, db=None)
    propagations = get_task_propagations(task_id, db=None).model_dump()
    sessions = list_task_sessions(task_id, db=None)
    session_index = get_task_session_index(task_id, db=None)

    assert graph_view == {
        "task_id": task_id,
        "epoch": "",
        "available": False,
        "summary": {},
        "nodes": [],
        "edges": [],
        "tree": None,
        "sessions": [],
        "findings": [],
        "generated_at": None,
        "run_root": str(run_root),
    }
    assert vuln_graph["available"] is False
    assert vuln_graph["summary"] == {
        "runs": 0,
        "nodes": 0,
        "edges": 0,
        "followups": 0,
        "executed_followups": 0,
        "pending_followups": 0,
        "skipped_followups": 0,
        "findings": 0,
    }
    assert vuln_graph["trace_tree"] is None
    assert propagations["items"] == []
    assert sessions["items"] == []
    assert session_index["nodes"] == []
    assert session_index["edges"] == []


def test_get_task_result_summary_uses_authoritative_graph_view_counts(tmp_path: Path, monkeypatch):
    task_id = "task-result-authoritative"
    output_root = tmp_path / "output"
    task_root = output_root / task_id
    run_root = task_root / "run"
    run_root.mkdir(parents=True, exist_ok=True)

    store = VulnScanStore(run_root / "vuln-scan.sqlite")
    store.start_task_graph_run(TaskGraphRunRecord(
        task_id=task_id,
        epoch="9",
        run_root=str(run_root),
        root_function="Root",
    ))
    store.upsert_task_graph_node(TaskGraphNodeRecord(
        node_id="node-root",
        task_id=task_id,
        epoch="9",
        func_id="root-func",
        function_name_resolved="Root",
        function_name_raw="Root",
        source_file="src/root.cpp",
        depth=0,
        status="done",
        analysis_status="done",
    ))
    store.upsert_task_graph_node(TaskGraphNodeRecord(
        node_id="node-child",
        task_id=task_id,
        epoch="9",
        func_id="child-func",
        function_name_resolved="Child",
        function_name_raw="Ns::Child",
        source_file="src/child.cpp",
        depth=1,
        status="done",
        analysis_status="done",
    ))
    store.start_run(run_id="run-result", task_id=task_id, root_file="src/root.cpp", root_function="Root", source_root="/src")
    store.add_finding(VulnFindingRecord(
        finding_id="finding-high",
        run_id="run-result",
        node_id="node-root",
        edge_id="",
        source_file="src/root.cpp",
        function_name="Root",
        line="10",
        vuln_type="command_injection",
        severity="high",
        title="High issue",
        summary="summary",
        evidence="evidence",
        exploitability="exploitability",
        confidence=0.8,
        output_dir="/tmp/out/high",
    ))
    store.add_finding(VulnFindingRecord(
        finding_id="finding-low",
        run_id="run-result",
        node_id="node-child",
        edge_id="",
        source_file="src/child.cpp",
        function_name="Child",
        line="42",
        vuln_type="info_disclosure",
        severity="low",
        title="Low issue",
        summary="summary",
        evidence="evidence",
        exploitability="exploitability",
        confidence=0.5,
        output_dir="/tmp/out/low",
    ))

    row = SimpleNamespace(
        task_id=task_id,
        output_path=str(output_root),
        result_json={},
        status="passed",
    )
    monkeypatch.setattr(tasks_module, "_get_task_row", lambda db, value: row)

    payload = get_task_result(task_id, db=None)

    assert payload["summary"]["function_count"] == 2
    assert payload["summary"]["total_findings"] == 2
    assert payload["summary"]["findings_by_severity"] == {"HIGH": 1, "LOW": 1}


def test_route_level_projections_stay_aligned_on_same_authoritative_graph_view(tmp_path: Path, monkeypatch):
    task_id = "task-route-projection"
    output_root = tmp_path / "output"
    task_root = output_root / task_id
    run_root = task_root / "run"
    run_root.mkdir(parents=True, exist_ok=True)

    store = VulnScanStore(run_root / "vuln-scan.sqlite")
    store.start_task_graph_run(TaskGraphRunRecord(
        task_id=task_id,
        epoch="12",
        run_root=str(run_root),
        root_function="Root",
    ))
    store.upsert_task_graph_node(TaskGraphNodeRecord(
        node_id="node-root",
        task_id=task_id,
        epoch="12",
        func_id="root-func",
        function_name_resolved="Root",
        function_name_raw="Root",
        source_file="src/root.cpp",
        depth=0,
        status="done",
        analysis_status="done",
    ))
    store.upsert_task_graph_node(TaskGraphNodeRecord(
        node_id="node-child",
        task_id=task_id,
        epoch="12",
        func_id="child-func",
        function_name_resolved="Child",
        function_name_raw="Ns::Child",
        source_file="src/child.cpp",
        depth=1,
        status="done",
        analysis_status="done",
    ))
    store.upsert_task_graph_edge(TaskGraphEdgeRecord(
        edge_id="edge-direct",
        task_id=task_id,
        epoch="12",
        source_node_id="node-root",
        target_node_id="node-child",
        source_func_id="root-func",
        target_func_id="child-func",
        source_function_resolved="Root",
        target_function_resolved="Child",
        target_function_raw="Ns::Child",
        source_file="src/root.cpp",
        target_file="src/child.cpp",
        edge_kind="direct_call",
        status="done",
        source_prop_id="prop-direct",
        visible_in_tree=1,
        visible_in_all_propagations=1,
    ))
    store.upsert_task_graph_session(TaskGraphSessionRecord(
        session_relpath="sessions/root.jsonl",
        task_id=task_id,
        epoch="12",
        node_id="node-root",
        edge_id="",
        session_role="worker",
        session_kind="taint",
        display_name="root",
        status="done",
        event_count=2,
    ))
    store.upsert_task_graph_session(TaskGraphSessionRecord(
        session_relpath="sessions/child.jsonl",
        task_id=task_id,
        epoch="12",
        node_id="node-child",
        edge_id="edge-direct",
        session_role="worker",
        session_kind="taint",
        display_name="child",
        status="done",
        event_count=4,
    ))
    store.start_run(run_id="run-route", task_id=task_id, root_file="src/root.cpp", root_function="Root", source_root="/src")
    store.add_finding(VulnFindingRecord(
        finding_id="finding-route-1",
        run_id="run-route",
        node_id="node-child",
        edge_id="edge-direct",
        source_file="src/child.cpp",
        function_name="Child",
        line="52",
        vuln_type="sql_injection",
        severity="medium",
        title="Child issue",
        summary="summary",
        evidence="evidence",
        exploitability="exploitability",
        confidence=0.7,
        output_dir="/tmp/out/route-1",
    ))

    row = SimpleNamespace(
        task_id=task_id,
        output_path=str(output_root),
        result_json={},
        status="passed",
    )
    monkeypatch.setattr(tasks_module, "_get_task_row", lambda db, value: row)

    graph_view = get_task_graph_view(task_id, db=None).model_dump()
    vuln_graph = get_task_vuln_graph(task_id, db=None)
    propagations = get_task_propagations(task_id, db=None).model_dump()
    sessions = list_task_sessions(task_id, db=None)
    session_index = get_task_session_index(task_id, db=None)
    result = get_task_result(task_id, db=None)

    assert graph_view["available"] is True
    assert vuln_graph["available"] is True
    assert len(graph_view["nodes"]) == vuln_graph["summary"]["nodes"] == result["summary"]["function_count"] == 2
    assert len(graph_view["findings"]) == vuln_graph["summary"]["findings"] == result["summary"]["total_findings"] == 1
    assert len(graph_view["edges"]) == vuln_graph["summary"]["edges"] == vuln_graph["summary"]["followups"] == 1
    assert [item["edge_id"] for item in propagations["items"]] == [edge["edge_id"] for edge in graph_view["edges"] if int(edge["visible_in_all_propagations"]) == 1]
    assert {item["relative_path"] for item in sessions["items"]} == {node["node_id"] for node in session_index["nodes"]}
    graph_node_ids = {node["node_id"] for node in graph_view["nodes"]}
    graph_edge_ids = {edge["edge_id"] for edge in graph_view["edges"]}
    for session_node in session_index["nodes"]:
        session_header = session_node["session_header"]
        assert session_header["node_id"] in graph_node_ids
        if session_header["edge_id"]:
            assert session_header["edge_id"] in graph_edge_ids
    assert session_index["edges"] == [
        {
            "edge_id": "edge-direct",
            "source_node_id": "sessions/root.jsonl",
            "target_node_id": "sessions/child.jsonl",
            "kind": "direct_call",
            "label": "direct_call",
        },
    ]
    assert vuln_graph["trace_tree"]["run_id"] == graph_view["tree"]["node_id"]
    assert vuln_graph["trace_tree"]["children"][0]["run_id"] == graph_view["tree"]["children"][0]["node_id"]

    def _collect_graph_tree_node_ids(node: dict) -> list[str]:
        values = [node["node_id"]]
        for child in node.get("children") or []:
            values.extend(_collect_graph_tree_node_ids(child))
        return values

    def _collect_trace_tree_run_ids(node: dict) -> list[str]:
        values = [node["run_id"]]
        for child in node.get("children") or []:
            values.extend(_collect_trace_tree_run_ids(child))
        return values

    assert _collect_trace_tree_run_ids(vuln_graph["trace_tree"]) == _collect_graph_tree_node_ids(graph_view["tree"])
    assert vuln_graph["trace_tree"]["children"][0]["run_id"] == graph_view["tree"]["children"][0]["node_id"]


def test_route_level_projections_preserve_one_to_many_bridge_edges(tmp_path: Path, monkeypatch):
    task_id = "task-route-one-to-many"
    output_root = tmp_path / "output"
    task_root = output_root / task_id
    run_root = task_root / "run"
    run_root.mkdir(parents=True, exist_ok=True)

    store = VulnScanStore(run_root / "vuln-scan.sqlite")
    store.start_task_graph_run(TaskGraphRunRecord(
        task_id=task_id,
        epoch="12m",
        run_root=str(run_root),
        root_function="RootMulti",
        generated_at=1780001111.0,
    ))
    for node_id, func_id, resolved, raw, source_file in [
        ("node-root", "root-func", "RootMulti", "RootMulti", "src/root_multi.cpp"),
        ("node-emit", "emit-func", "Emit", "EventManager::Emit", "src/event_manager.cpp"),
        ("node-emit-uv", "emit-uv-func", "EmitByUvWithoutCheckShared", "EventManager::EmitByUvWithoutCheckShared", "src/event_manager.cpp"),
    ]:
        store.upsert_task_graph_node(TaskGraphNodeRecord(
            node_id=node_id,
            task_id=task_id,
            epoch="12m",
            func_id=func_id,
            function_name_resolved=resolved,
            function_name_raw=raw,
            source_file=source_file,
            depth=0 if node_id == "node-root" else 1,
            status="running" if node_id != "node-root" else "done",
            analysis_status="running" if node_id != "node-root" else "done",
        ))
    for payload in [
        {
            "edge_id": "edge-bridge-emit",
            "source_node_id": "node-root",
            "target_node_id": "node-emit",
            "source_func_id": "root-func",
            "target_func_id": "emit-func",
            "source_function_resolved": "RootMulti",
            "target_function_resolved": "Emit",
            "target_function_raw": "OnSharedManager",
            "source_file": "src/root_multi.cpp",
            "target_file": "src/event_manager.cpp",
            "edge_kind": "container_reader",
            "status": "scheduled",
            "reason_code": "tracker_resolved",
            "reason_message": "resolved by container tracker",
            "reason_source": "tracker",
            "source_prop_id": "prop-shared-manager",
            "source_orchestration_edge_id": "orch-emit",
            "call_line": 12,
            "source_taint_name": "cb",
            "target_taint_name": "emit",
            "actual_args_json": '["cb"]',
            "tracker_type": "container_reader",
            "tracker_result_json": '{"resolved_targets":["Emit","EmitByUvWithoutCheckShared"]}',
            "display_order": 1,
            "visible_in_tree": 1,
            "visible_in_all_propagations": 1,
        },
        {
            "edge_id": "edge-bridge-emit-uv",
            "source_node_id": "node-root",
            "target_node_id": "node-emit-uv",
            "source_func_id": "root-func",
            "target_func_id": "emit-uv-func",
            "source_function_resolved": "RootMulti",
            "target_function_resolved": "EmitByUvWithoutCheckShared",
            "target_function_raw": "OnSharedManager",
            "source_file": "src/root_multi.cpp",
            "target_file": "src/event_manager.cpp",
            "edge_kind": "container_reader",
            "status": "scheduled",
            "reason_code": "tracker_resolved",
            "reason_message": "resolved by container tracker",
            "reason_source": "tracker",
            "source_prop_id": "prop-shared-manager",
            "source_orchestration_edge_id": "orch-emit-uv",
            "call_line": 12,
            "source_taint_name": "cb",
            "target_taint_name": "emit_uv",
            "actual_args_json": '["cb"]',
            "tracker_type": "container_reader",
            "tracker_result_json": '{"resolved_targets":["Emit","EmitByUvWithoutCheckShared"]}',
            "display_order": 2,
            "visible_in_tree": 1,
            "visible_in_all_propagations": 1,
        },
    ]:
        store.upsert_task_graph_edge(TaskGraphEdgeRecord(task_id=task_id, epoch="12m", **payload))
    for relpath, node_id, edge_id, status in [
        ("sessions/root.jsonl", "node-root", "", "done"),
        ("sessions/emit.jsonl", "node-emit", "edge-bridge-emit", "running"),
        ("sessions/emit-uv.jsonl", "node-emit-uv", "edge-bridge-emit-uv", "running"),
    ]:
        store.upsert_task_graph_session(TaskGraphSessionRecord(
            session_relpath=relpath,
            task_id=task_id,
            epoch="12m",
            node_id=node_id,
            edge_id=edge_id,
            session_role="worker",
            session_kind="taint",
            display_name=Path(relpath).stem,
            status=status,
            event_count=2,
        ))

    row = SimpleNamespace(task_id=task_id, output_path=str(output_root), result_json={}, status="running")
    monkeypatch.setattr(tasks_module, "_get_task_row", lambda db, value: row)

    graph_view = get_task_graph_view(task_id, db=None).model_dump()
    vuln_graph = get_task_vuln_graph(task_id, db=None)
    propagations = get_task_propagations(task_id, db=None).model_dump()
    sessions = list_task_sessions(task_id, db=None)
    session_index = get_task_session_index(task_id, db=None)

    assert graph_view["tree"]["node_id"] == "node-root"
    assert [child["node_id"] for child in graph_view["tree"]["children"]] == ["node-emit", "node-emit-uv"]
    assert [child["edge_id"] for child in graph_view["tree"]["children"]] == ["edge-bridge-emit", "edge-bridge-emit-uv"]
    assert [child["function_name_resolved"] for child in graph_view["tree"]["children"]] == ["Emit", "EmitByUvWithoutCheckShared"]
    assert len(graph_view["edges"]) == 2
    assert [item["edge_id"] for item in propagations["items"]] == ["edge-bridge-emit", "edge-bridge-emit-uv"]
    assert [item["target_function_raw"] for item in propagations["items"]] == ["OnSharedManager", "OnSharedManager"]
    assert [item["target_function_resolved"] for item in propagations["items"]] == ["Emit", "EmitByUvWithoutCheckShared"]
    assert len(vuln_graph["trace_tree"]["children"]) == 2
    assert [child["run_id"] for child in vuln_graph["trace_tree"]["children"]] == ["node-emit", "node-emit-uv"]
    assert [child["function_name"] for child in vuln_graph["trace_tree"]["children"]] == ["Emit", "EmitByUvWithoutCheckShared"]
    assert {item["relative_path"] for item in sessions["items"]} == {"sessions/root.jsonl", "sessions/emit.jsonl", "sessions/emit-uv.jsonl"}
    assert {item["relative_path"] for item in sessions["items"]} == {node["node_id"] for node in session_index["nodes"]}
    assert session_index["index_path"] == f"{run_root}/graph-view"
    assert session_index["generated_at"] == "2026-05-28T20:45:11Z"
    assert {node["session_header"]["edge_id"] for node in session_index["nodes"] if node["session_header"]["edge_id"]} == {"edge-bridge-emit", "edge-bridge-emit-uv"}
    assert {edge["edge_id"] for edge in graph_view["edges"]} == {item["edge_id"] for item in propagations["items"]} == {edge["edge_id"] for edge in session_index["edges"]}
    assert [edge["source_node_id"] for edge in session_index["edges"]] == ["sessions/root.jsonl", "sessions/root.jsonl"]
    assert [edge["target_node_id"] for edge in session_index["edges"]] == ["sessions/emit.jsonl", "sessions/emit-uv.jsonl"]
    session_nodes_by_path = {node["relative_path"]: node for node in session_index["nodes"]}
    assert session_nodes_by_path["sessions/root.jsonl"]["module_name"] == "RootMulti"
    assert session_nodes_by_path["sessions/emit.jsonl"]["module_name"] == "Emit"
    assert session_nodes_by_path["sessions/emit-uv.jsonl"]["module_name"] == "EmitByUvWithoutCheckShared"
    assert session_index["edges"] == [
        {
            "edge_id": "edge-bridge-emit",
            "source_node_id": "sessions/root.jsonl",
            "target_node_id": "sessions/emit.jsonl",
            "kind": "container_reader",
            "label": "container_reader",
        },
        {
            "edge_id": "edge-bridge-emit-uv",
            "source_node_id": "sessions/root.jsonl",
            "target_node_id": "sessions/emit-uv.jsonl",
            "kind": "container_reader",
            "label": "container_reader",
        },
    ]


def test_route_level_projections_keep_findings_queryable_when_graph_has_only_findings(tmp_path: Path, monkeypatch):
    task_id = "task-route-findings-only"
    output_root = tmp_path / "output"
    task_root = output_root / task_id
    run_root = task_root / "run"
    run_root.mkdir(parents=True, exist_ok=True)

    store = VulnScanStore(run_root / "vuln-scan.sqlite")
    store.start_task_graph_run(TaskGraphRunRecord(
        task_id=task_id,
        epoch="13",
        run_root=str(run_root),
        root_function="Root",
    ))
    store.start_run(run_id="run-findings-only", task_id=task_id, root_file="src/root.cpp", root_function="Root", source_root="/src")
    store.add_finding(VulnFindingRecord(
        finding_id="finding-only-1",
        run_id="run-findings-only",
        node_id="",
        edge_id="",
        source_file="src/root.cpp",
        function_name="Root",
        line="11",
        vuln_type="command_injection",
        severity="high",
        title="Only issue",
        summary="summary",
        evidence="evidence",
        exploitability="exploitability",
        confidence=0.8,
        output_dir="/tmp/out/findings-only-1",
    ))

    row = SimpleNamespace(
        task_id=task_id,
        output_path=str(output_root),
        result_json={},
        status="passed",
    )
    monkeypatch.setattr(tasks_module, "_get_task_row", lambda db, value: row)

    graph_view = get_task_graph_view(task_id, db=None).model_dump()
    vuln_graph = get_task_vuln_graph(task_id, db=None)
    propagations = get_task_propagations(task_id, db=None).model_dump()
    sessions = list_task_sessions(task_id, db=None)
    session_index = get_task_session_index(task_id, db=None)
    result = get_task_result(task_id, db=None)

    assert graph_view["available"] is True
    assert graph_view["nodes"] == []
    assert graph_view["edges"] == []
    assert graph_view["findings"][0]["finding_id"] == "finding-only-1"
    assert vuln_graph["available"] is True
    assert vuln_graph["summary"]["nodes"] == 0
    assert vuln_graph["summary"]["edges"] == 0
    assert vuln_graph["summary"]["findings"] == 1
    assert propagations["items"] == []
    assert sessions["items"] == []
    assert session_index["nodes"] == []
    assert session_index["edges"] == []
    assert result["summary"]["function_count"] == 0
    assert result["summary"]["total_findings"] == 1
    assert result["summary"]["findings_by_severity"] == {"HIGH": 1}


def test_route_level_session_index_does_not_invent_edges_from_orphan_sessions(tmp_path: Path, monkeypatch):
    task_id = "task-route-orphan-session"
    output_root = tmp_path / "output"
    task_root = output_root / task_id
    run_root = task_root / "run"
    run_root.mkdir(parents=True, exist_ok=True)

    store = VulnScanStore(run_root / "vuln-scan.sqlite")
    store.start_task_graph_run(TaskGraphRunRecord(
        task_id=task_id,
        epoch="14",
        run_root=str(run_root),
        root_function="Root",
    ))
    store.upsert_task_graph_node(TaskGraphNodeRecord(
        node_id="node-root",
        task_id=task_id,
        epoch="14",
        func_id="root-func",
        function_name_resolved="Root",
        function_name_raw="Root",
        source_file="src/root.cpp",
        depth=0,
        status="running",
        analysis_status="running",
    ))
    store.upsert_task_graph_node(TaskGraphNodeRecord(
        node_id="node-child",
        task_id=task_id,
        epoch="14",
        func_id="child-func",
        function_name_resolved="Child",
        function_name_raw="Child",
        source_file="src/child.cpp",
        depth=1,
        status="running",
        analysis_status="running",
    ))
    store.upsert_task_graph_session(TaskGraphSessionRecord(
        session_relpath="sessions/root.jsonl",
        task_id=task_id,
        epoch="14",
        node_id="node-root",
        edge_id="",
        session_role="worker",
        session_kind="taint",
        display_name="root",
        status="running",
        event_count=3,
    ))
    store.upsert_task_graph_session(TaskGraphSessionRecord(
        session_relpath="sessions/child.jsonl",
        task_id=task_id,
        epoch="14",
        node_id="node-child",
        edge_id="edge-direct",
        session_role="worker",
        session_kind="taint",
        display_name="child",
        status="done",
        event_count=2,
    ))
    store.upsert_task_graph_session(TaskGraphSessionRecord(
        session_relpath="sessions/orphan.jsonl",
        task_id=task_id,
        epoch="14",
        node_id="node-orphan",
        edge_id="edge-missing",
        session_role="worker",
        session_kind="taint",
        display_name="orphan",
        status="done",
        event_count=1,
    ))
    store.upsert_task_graph_edge(TaskGraphEdgeRecord(
        edge_id="edge-direct",
        task_id=task_id,
        epoch="14",
        source_node_id="node-root",
        target_node_id="node-child",
        source_func_id="root-func",
        target_func_id="child-func",
        source_function_resolved="Root",
        target_function_resolved="Child",
        target_function_raw="Child",
        source_file="src/root.cpp",
        target_file="src/child.cpp",
        edge_kind="direct_call",
        status="scheduled",
        source_prop_id="prop-direct",
        visible_in_tree=1,
        visible_in_all_propagations=1,
    ))

    row = SimpleNamespace(
        task_id=task_id,
        output_path=str(output_root),
        result_json={},
        status="running",
    )
    monkeypatch.setattr(tasks_module, "_get_task_row", lambda db, value: row)

    session_index = get_task_session_index(task_id, db=None)

    assert {node["session_header"]["edge_id"] for node in session_index["nodes"]} == {"", "edge-direct", "edge-missing"}
    assert session_index["edges"] == [
        {
            "edge_id": "edge-direct",
            "source_node_id": "sessions/root.jsonl",
            "target_node_id": "sessions/child.jsonl",
            "kind": "direct_call",
            "label": "direct_call",
        },
    ]
    assert all(edge["edge_id"] != "edge-missing" for edge in session_index["edges"])
    orphan_node = next(node for node in session_index["nodes"] if node["session_header"]["edge_id"] == "edge-missing")
    assert orphan_node["module_name"] is None
    assert orphan_node["stage_group"] == "node-orphan"


def test_route_level_projections_preserve_terminal_and_hidden_followup_statuses(tmp_path: Path, monkeypatch):
    task_id = "task-route-status-matrix"
    output_root = tmp_path / "output"
    task_root = output_root / task_id
    run_root = task_root / "run"
    run_root.mkdir(parents=True, exist_ok=True)

    store = VulnScanStore(run_root / "vuln-scan.sqlite")
    store.start_task_graph_run(TaskGraphRunRecord(
        task_id=task_id,
        epoch="14",
        run_root=str(run_root),
        root_function="Root",
    ))
    store.upsert_task_graph_node(TaskGraphNodeRecord(
        node_id="node-root",
        task_id=task_id,
        epoch="14",
        func_id="root-func",
        function_name_resolved="Root",
        function_name_raw="Root",
        source_file="src/root.cpp",
        depth=0,
        status="done",
        analysis_status="done",
    ))
    store.upsert_task_graph_node(TaskGraphNodeRecord(
        node_id="node-child-failed",
        task_id=task_id,
        epoch="14",
        func_id="child-failed",
        function_name_resolved="ChildFailed",
        function_name_raw="Ns::ChildFailed",
        source_file="src/failed.cpp",
        depth=1,
        status="failed",
        analysis_status="failed",
    ))
    store.upsert_task_graph_node(TaskGraphNodeRecord(
        node_id="node-child-cancelled",
        task_id=task_id,
        epoch="14",
        func_id="child-cancelled",
        function_name_resolved="ChildCancelled",
        function_name_raw="Ns::ChildCancelled",
        source_file="src/cancelled.cpp",
        depth=1,
        status="cancelled",
        analysis_status="cancelled",
    ))
    store.upsert_task_graph_edge(TaskGraphEdgeRecord(
        edge_id="edge-failed",
        task_id=task_id,
        epoch="14",
        source_node_id="node-root",
        target_node_id="node-child-failed",
        source_func_id="root-func",
        target_func_id="child-failed",
        source_function_resolved="Root",
        target_function_resolved="ChildFailed",
        target_function_raw="Ns::ChildFailed",
        source_file="src/root.cpp",
        target_file="src/failed.cpp",
        edge_kind="direct_call",
        status="failed",
        source_prop_id="prop-failed",
        reason_code="child_process_failed",
        reason_message="child process failed",
        visible_in_tree=1,
        visible_in_all_propagations=1,
    ))
    store.upsert_task_graph_edge(TaskGraphEdgeRecord(
        edge_id="edge-cancelled",
        task_id=task_id,
        epoch="14",
        source_node_id="node-root",
        target_node_id="node-child-cancelled",
        source_func_id="root-func",
        target_func_id="child-cancelled",
        source_function_resolved="Root",
        target_function_resolved="ChildCancelled",
        target_function_raw="Ns::ChildCancelled",
        source_file="src/root.cpp",
        target_file="src/cancelled.cpp",
        edge_kind="indirect_call",
        status="cancelled",
        source_prop_id="prop-cancelled",
        reason_code="owner_cancelled",
        reason_message="owner cancelled followup",
        visible_in_tree=1,
        visible_in_all_propagations=1,
    ))
    store.upsert_task_graph_edge(TaskGraphEdgeRecord(
        edge_id="edge-not-followed",
        task_id=task_id,
        epoch="14",
        source_node_id="node-root",
        target_node_id="",
        source_func_id="root-func",
        target_func_id="",
        source_function_resolved="Root",
        target_function_resolved="ExternalChild",
        target_function_raw="Ns::ExternalChild",
        source_file="src/root.cpp",
        target_file="",
        edge_kind="external_callee",
        status="not_followed",
        source_prop_id="prop-not-followed",
        reason_code="external_callee",
        reason_message="callee definition is outside source tree",
        reason_source="analysis",
        visible_in_tree=1,
        visible_in_all_propagations=1,
    ))
    store.upsert_task_graph_edge(TaskGraphEdgeRecord(
        edge_id="edge-return",
        task_id=task_id,
        epoch="14",
        source_node_id="node-child-failed",
        target_node_id="node-root",
        source_func_id="child-failed",
        target_func_id="root-func",
        source_function_resolved="ChildFailed",
        target_function_resolved="Root",
        target_function_raw="Root",
        source_file="src/failed.cpp",
        target_file="src/root.cpp",
        edge_kind="return_followup",
        status="done",
        source_prop_id="prop-return",
        visible_in_tree=0,
        visible_in_all_propagations=1,
    ))

    row = SimpleNamespace(
        task_id=task_id,
        output_path=str(output_root),
        result_json={},
        status="failed",
    )
    monkeypatch.setattr(tasks_module, "_get_task_row", lambda db, value: row)

    graph_view = get_task_graph_view(task_id, db=None).model_dump()
    vuln_graph = get_task_vuln_graph(task_id, db=None)
    propagations = get_task_propagations(task_id, db=None).model_dump()

    assert graph_view["summary"]["edges_failed"] == 1
    assert graph_view["summary"]["edges_cancelled"] == 1
    assert graph_view["summary"]["edges_not_followed"] == 1
    assert vuln_graph["summary"]["executed_followups"] == 3
    assert vuln_graph["summary"]["skipped_followups"] == 1

    propagation_by_id = {item["edge_id"]: item for item in propagations["items"]}
    assert propagation_by_id["edge-failed"]["status"] == "failed"
    assert propagation_by_id["edge-cancelled"]["status"] == "cancelled"
    assert propagation_by_id["edge-not-followed"]["status"] == "not_followed"
    assert propagation_by_id["edge-return"]["edge_kind"] == "return_followup"
    assert propagation_by_id["edge-failed"]["orchestration_followed"] is True
    assert propagation_by_id["edge-failed"]["orchestration_status"] == "failed"
    assert propagation_by_id["edge-failed"]["reason_code"] == "child_process_failed"
    assert propagation_by_id["edge-failed"]["reason_message"] == "child process failed"
    assert propagation_by_id["edge-cancelled"]["orchestration_followed"] is True
    assert propagation_by_id["edge-cancelled"]["orchestration_status"] == "cancelled"
    assert propagation_by_id["edge-cancelled"]["reason_code"] == "owner_cancelled"
    assert propagation_by_id["edge-cancelled"]["reason_message"] == "owner cancelled followup"
    assert propagation_by_id["edge-not-followed"]["orchestration_followed"] is False
    assert propagation_by_id["edge-not-followed"]["unfollowed_reason"] == "external_callee"
    assert propagation_by_id["edge-not-followed"]["unfollowed_reason_source"] == "analysis"
    assert propagation_by_id["edge-not-followed"]["reason_message"] == "callee definition is outside source tree"

    trace_children = vuln_graph["trace_tree"]["children"]
    trace_edge_ids = {child["followup_reason"]: child["run_id"] for child in trace_children}
    assert "child process failed" in trace_edge_ids
    assert "owner cancelled followup" in trace_edge_ids
    assert "callee definition is outside source tree" in trace_edge_ids
    assert all(child["run_id"] != "node-root" for child in trace_children)


def test_route_level_projections_preserve_unresolved_tracker_observability_fields(tmp_path: Path, monkeypatch):
    task_id = "task-route-unresolved-observability"
    output_root = tmp_path / "output"
    task_root = output_root / task_id
    run_root = task_root / "run"
    run_root.mkdir(parents=True, exist_ok=True)

    store = VulnScanStore(run_root / "vuln-scan.sqlite")
    store.start_task_graph_run(TaskGraphRunRecord(
        task_id=task_id,
        epoch="15",
        run_root=str(run_root),
        root_function="Root",
    ))
    store.upsert_task_graph_node(TaskGraphNodeRecord(
        node_id="node-root",
        task_id=task_id,
        epoch="15",
        func_id="root-func",
        function_name_resolved="Root",
        function_name_raw="Root",
        source_file="src/root.cpp",
        depth=0,
        status="done",
        analysis_status="done",
    ))
    store.upsert_task_graph_edge(TaskGraphEdgeRecord(
        edge_id="edge-unresolved-observe",
        task_id=task_id,
        epoch="15",
        source_node_id="node-root",
        target_node_id="",
        source_func_id="root-func",
        target_func_id="",
        source_function_resolved="Root",
        target_function_resolved="Reader",
        target_function_raw="Ns::Reader",
        source_file="src/root.cpp",
        target_file="",
        edge_kind="unresolved_target",
        status="unresolved",
        source_prop_id="prop-unresolved-observe",
        reason_code="tracker_no_target",
        reason_message="external tracker did not resolve target",
        reason_source="tracker",
        tracker_type="external_escape",
        tracker_result_json='{"resolved_targets":[]}',
        visible_in_tree=1,
        visible_in_all_propagations=1,
    ))

    row = SimpleNamespace(
        task_id=task_id,
        output_path=str(output_root),
        result_json={},
        status="failed",
    )
    monkeypatch.setattr(tasks_module, "_get_task_row", lambda db, value: row)

    graph_view = get_task_graph_view(task_id, db=None).model_dump()
    propagations = get_task_propagations(task_id, db=None).model_dump()
    vuln_graph = get_task_vuln_graph(task_id, db=None)

    edge = graph_view["edges"][0]
    propagation = propagations["items"][0]
    trace_child = vuln_graph["trace_tree"]["children"][0]

    assert edge["reason_source"] == "tracker"
    assert edge["edge_kind"] == "unresolved_target"
    assert edge["tracker_type"] == "external_escape"
    assert edge["tracker_result_json"] == '{"resolved_targets":[]}'
    assert propagation["unfollowed_reason_source"] == "tracker"
    assert propagation["reason_code"] == "tracker_no_target"
    assert propagation["reason_message"] == "external tracker did not resolve target"
    assert trace_child["prune_reason"] == "tracker_no_target"
    assert trace_child["followup_reason"] == "external tracker did not resolve target"


def test_project_vuln_graph_from_graph_view_keeps_legacy_shape():
    tree = {
        "node_id": "node-root",
        "function_name_resolved": "Root",
        "function_name_raw": "Root",
        "source_file": "src/root.cpp",
        "depth": 0,
        "status": "running",
        "findings_count": 1,
        "children": [
            {
                "node_id": "virtual::edge-1",
                "edge_id": "edge-1",
                "function_name_resolved": "Entry",
                "function_name_raw": "Ns::Entry",
                "source_file": "src/entry.cpp",
                "depth": 1,
                "status": "unresolved",
                "reason_code": "tracker_no_target",
                "reason_message": "tracker did not resolve target",
                "placeholder": True,
                "children": [],
            },
        ],
    }
    projected = _project_vuln_trace_tree_from_graph_view(tree)
    assert projected["run_id"] == "node-root"
    assert projected["function_name"] == "Root"
    assert projected["children"][0]["pruned"] is True
    assert projected["children"][0]["prune_reason"] == "tracker_no_target"
    assert projected["children"][0]["followup_reason"] == "tracker did not resolve target"

    summary = _project_vuln_graph_summary_from_graph_view({
        "summary": {"nodes_total": 2, "edges_total": 3, "findings_total": 4},
        "edges": [
            {"status": "done"},
            {"status": "running"},
            {"status": "unresolved"},
        ],
    })
    assert summary["runs"] == 2
    assert summary["followups"] == 3
    assert summary["executed_followups"] == 2
    assert summary["skipped_followups"] == 1
    assert summary["findings"] == 4


def test_project_vuln_graph_summary_counts_failed_cancelled_and_not_followed():
    summary = _project_vuln_graph_summary_from_graph_view({
        "summary": {"nodes_total": 4, "edges_total": 4, "findings_total": 0},
        "edges": [
            {"status": "failed"},
            {"status": "cancelled"},
            {"status": "not_followed"},
            {"status": "discovered"},
        ],
    })
    assert summary["runs"] == 4
    assert summary["followups"] == 4
    assert summary["executed_followups"] == 2
    assert summary["pending_followups"] == 1
    assert summary["skipped_followups"] == 1


def test_project_vuln_graph_summary_counts_discovered_and_scheduled_as_pending():
    summary = _project_vuln_graph_summary_from_graph_view({
        "summary": {"nodes_total": 3, "edges_total": 3, "findings_total": 0},
        "edges": [
            {"status": "discovered"},
            {"status": "scheduled"},
            {"status": "running"},
        ],
    })
    assert summary["runs"] == 3
    assert summary["followups"] == 3
    assert summary["executed_followups"] == 2
    assert summary["pending_followups"] == 3
    assert summary["skipped_followups"] == 0


def test_graph_view_tree_edges_can_be_resolved_from_edge_inventory():
    view = {
        "edges": [
            {
                "edge_id": "edge-1",
                "visible_in_all_propagations": 1,
                "source_prop_id": "prop-1",
                "edge_kind": "direct_call",
                "status": "done",
                "source_function_resolved": "Root",
                "target_function_resolved": "Child",
                "target_function_raw": "Ns::Child",
                "reason_code": "",
                "reason_message": "",
            },
            {
                "edge_id": "edge-2",
                "visible_in_all_propagations": 1,
                "source_prop_id": "prop-2",
                "edge_kind": "indirect_call",
                "status": "unresolved",
                "source_function_resolved": "Child",
                "target_function_resolved": "Leaf",
                "target_function_raw": "Ns::Leaf",
                "reason_code": "tracker_no_target",
                "reason_message": "tracker did not resolve target",
            },
        ],
        "tree": {
            "node_id": "node-root",
            "function_name_resolved": "Root",
            "function_name_raw": "Root",
            "source_file": "src/root.cpp",
            "depth": 0,
            "status": "done",
            "children": [
                {
                    "node_id": "node-child",
                    "edge_id": "edge-1",
                    "function_name_resolved": "Child",
                    "function_name_raw": "Ns::Child",
                    "source_file": "src/child.cpp",
                    "depth": 1,
                    "status": "done",
                    "children": [
                        {
                            "node_id": "virtual::edge-2",
                            "edge_id": "edge-2",
                            "function_name_resolved": "Leaf",
                            "function_name_raw": "Ns::Leaf",
                            "source_file": "src/leaf.cpp",
                            "depth": 2,
                            "status": "unresolved",
                            "reason_code": "tracker_no_target",
                            "reason_message": "tracker did not resolve target",
                            "placeholder": True,
                            "children": [],
                        },
                    ],
                },
            ],
        },
    }

    projected_edges = {item["edge_id"]: item for item in _project_propagations_from_graph(view)}
    projected_tree = _project_vuln_trace_tree_from_graph_view(view["tree"])
    assert projected_tree is not None
    child = projected_tree["children"][0]
    placeholder = child["children"][0]

    assert child["function_name"] == projected_edges["edge-1"]["target_function"]
    assert placeholder["function_name"] == projected_edges["edge-2"]["target_function"]
    assert placeholder["prune_reason"] == projected_edges["edge-2"]["reason_code"]
    assert placeholder["followup_reason"] == projected_edges["edge-2"]["reason_message"]


def test_vuln_graph_trace_tree_run_ids_are_projected_from_authoritative_graph_tree():
    view = {
        "tree": {
            "node_id": "node-root",
            "function_name_resolved": "Root",
            "function_name_raw": "Root",
            "source_file": "src/root.cpp",
            "depth": 0,
            "status": "done",
            "children": [
                {
                    "node_id": "node-child",
                    "edge_id": "edge-direct",
                    "function_name_resolved": "Child",
                    "function_name_raw": "Ns::Child",
                    "source_file": "src/child.cpp",
                    "depth": 1,
                    "status": "running",
                    "children": [
                        {
                            "node_id": "virtual::edge-unresolved",
                            "edge_id": "edge-unresolved",
                            "function_name_resolved": "Leaf",
                            "function_name_raw": "Ns::Leaf",
                            "source_file": "src/leaf.cpp",
                            "depth": 2,
                            "status": "unresolved",
                            "reason_code": "tracker_no_target",
                            "reason_message": "tracker did not resolve target",
                            "placeholder": True,
                            "children": [],
                        },
                    ],
                },
                {
                    "node_id": "virtual::edge-not-followed",
                    "edge_id": "edge-not-followed",
                    "function_name_resolved": "Skipped",
                    "function_name_raw": "Ns::Skipped",
                    "source_file": "src/skipped.cpp",
                    "depth": 1,
                    "status": "not_followed",
                    "reason_code": "external_callee",
                    "reason_message": "callee definition is outside source tree",
                    "placeholder": True,
                    "children": [],
                },
            ],
        },
    }

    projected = _project_vuln_trace_tree_from_graph_view(view["tree"])
    assert projected is not None

    def _collect_tree_node_ids(node: dict) -> list[str]:
        values = [node["node_id"]]
        for child in node.get("children") or []:
            values.extend(_collect_tree_node_ids(child))
        return values

    def _collect_trace_run_ids(node: dict) -> list[str]:
        values = [node["run_id"]]
        for child in node.get("children") or []:
            values.extend(_collect_trace_run_ids(child))
        return values

    assert _collect_trace_run_ids(projected) == _collect_tree_node_ids(view["tree"])
    assert projected["children"][0]["run_id"] == "node-child"
    assert projected["children"][0]["children"][0]["run_id"] == "virtual::edge-unresolved"
    assert projected["children"][1]["run_id"] == "virtual::edge-not-followed"
    assert projected["children"][1]["pruned"] is True


def test_graph_session_references_resolve_within_same_view():
    view = {
        "nodes": [
            {"node_id": "node-root", "function_name_resolved": "Root", "function_name_raw": "Root"},
            {"node_id": "node-child", "function_name_resolved": "Child", "function_name_raw": "Ns::Child"},
        ],
        "edges": [
            {
                "edge_id": "edge-1",
                "source_node_id": "node-root",
                "target_node_id": "node-child",
                "edge_kind": "direct_call",
                "status": "done",
                "visible_in_all_propagations": 1,
                "source_prop_id": "prop-1",
                "source_function_resolved": "Root",
                "target_function_resolved": "Child",
                "target_function_raw": "Ns::Child",
            },
        ],
        "sessions": [
            {
                "session_relpath": "sessions/root.jsonl",
                "node_id": "node-root",
                "edge_id": "",
                "session_role": "worker",
                "session_kind": "taint",
                "display_name": "root",
                "status": "running",
                "event_count": 3,
            },
            {
                "session_relpath": "sessions/child.jsonl",
                "node_id": "node-child",
                "edge_id": "edge-1",
                "session_role": "worker",
                "session_kind": "taint",
                "display_name": "child",
                "status": "done",
                "event_count": 5,
            },
        ],
    }

    node_ids = {node["node_id"] for node in view["nodes"]}
    edge_ids = {edge["edge_id"] for edge in view["edges"]}
    for session in view["sessions"]:
        assert session["node_id"] in node_ids
        if session["edge_id"]:
            assert session["edge_id"] in edge_ids

    session_items = _project_session_list_from_graph(view)
    session_index = _project_session_index_from_graph(
        task_id="task-1",
        task_status="running",
        run_root=Path("/tmp/run"),
        view=view,
    )
    index_node_ids = {node["node_id"] for node in session_index["nodes"]}
    assert {item["relative_path"] for item in session_items} == index_node_ids
    assert session_index["edges"] == [
        {
            "edge_id": "edge-1",
            "source_node_id": "sessions/root.jsonl",
            "target_node_id": "sessions/child.jsonl",
            "kind": "direct_call",
            "label": "direct_call",
        },
    ]


def test_project_session_index_from_graph_returns_empty_projection_without_authoritative_view():
    projected = _project_session_index_from_graph(
        task_id="task-empty",
        task_status="running",
        run_root=Path("/tmp/empty-run"),
        view={
            "summary": {},
            "nodes": [],
            "edges": [],
            "sessions": [],
            "generated_at": None,
        },
    )

    assert projected["task_id"] == "task-empty"
    assert projected["task_status"] == "running"
    assert projected["summary"] == {}
    assert projected["nodes"] == []
    assert projected["edges"] == []
    assert projected["groups"] == []
    assert projected["warnings"] == []


def test_projection_views_stay_consistent_for_same_graph_fact_set():
    view = {
        "summary": {"nodes_total": 2, "edges_total": 2, "findings_total": 1},
        "nodes": [
            {"node_id": "node-root", "function_name_resolved": "Root", "function_name_raw": "Root"},
            {"node_id": "node-child", "function_name_resolved": "Child", "function_name_raw": "Ns::Child"},
        ],
        "edges": [
            {
                "edge_id": "edge-done",
                "source_prop_id": "prop-done",
                "source_node_id": "node-root",
                "target_node_id": "node-child",
                "edge_kind": "direct_call",
                "status": "done",
                "visible_in_all_propagations": 1,
                "source_function_resolved": "Root",
                "target_function_resolved": "Child",
                "target_function_raw": "Ns::Child",
                "reason_code": "",
                "reason_message": "",
            },
            {
                "edge_id": "edge-unresolved",
                "source_prop_id": "prop-unresolved",
                "source_node_id": "node-child",
                "target_node_id": "",
                "edge_kind": "indirect_call",
                "status": "unresolved",
                "visible_in_all_propagations": 1,
                "source_function_resolved": "Child",
                "target_function_resolved": "Leaf",
                "target_function_raw": "Ns::Leaf",
                "reason_code": "tracker_no_target",
                "reason_message": "tracker did not resolve target",
            },
        ],
        "tree": {
            "node_id": "node-root",
            "function_name_resolved": "Root",
            "function_name_raw": "Root",
            "source_file": "src/root.cpp",
            "depth": 0,
            "status": "done",
            "children": [
                {
                    "node_id": "node-child",
                    "edge_id": "edge-done",
                    "function_name_resolved": "Child",
                    "function_name_raw": "Ns::Child",
                    "source_file": "src/child.cpp",
                    "depth": 1,
                    "status": "done",
                    "children": [
                        {
                            "node_id": "virtual::edge-unresolved",
                            "edge_id": "edge-unresolved",
                            "function_name_resolved": "Leaf",
                            "function_name_raw": "Ns::Leaf",
                            "source_file": "src/leaf.cpp",
                            "depth": 2,
                            "status": "unresolved",
                            "reason_code": "tracker_no_target",
                            "reason_message": "tracker did not resolve target",
                            "placeholder": True,
                            "children": [],
                        },
                    ],
                },
            ],
        },
        "sessions": [
            {
                "session_relpath": "sessions/root.jsonl",
                "node_id": "node-root",
                "edge_id": "",
                "session_role": "worker",
                "session_kind": "taint",
                "display_name": "root",
                "status": "done",
                "event_count": 2,
            },
            {
                "session_relpath": "sessions/child.jsonl",
                "node_id": "node-child",
                "edge_id": "edge-done",
                "session_role": "worker",
                "session_kind": "taint",
                "display_name": "child",
                "status": "done",
                "event_count": 4,
            },
        ],
    }

    propagations = {item["edge_id"]: item for item in _project_propagations_from_graph(view)}
    trace_tree = _project_vuln_trace_tree_from_graph_view(view["tree"])
    session_index = _project_session_index_from_graph(
        task_id="task-1",
        task_status="done",
        run_root=Path("/tmp/run"),
        view=view,
    )

    assert trace_tree is not None
    child = trace_tree["children"][0]
    leaf = child["children"][0]
    assert child["run_id"] == "node-child"
    assert child["function_name"] == propagations["edge-done"]["target_function"]
    assert leaf["function_name"] == propagations["edge-unresolved"]["target_function"]
    assert leaf["prune_reason"] == propagations["edge-unresolved"]["reason_code"]
    assert {edge["source_node_id"] for edge in session_index["edges"]} == {"sessions/root.jsonl"}
    assert {edge["target_node_id"] for edge in session_index["edges"]} == {"sessions/child.jsonl"}


def test_projection_views_stay_consistent_for_external_escape_placeholder():
    view = {
        "summary": {"nodes_total": 1, "edges_total": 1, "findings_total": 0},
        "nodes": [
            {"node_id": "node-root", "function_name_resolved": "Root", "function_name_raw": "Root"},
        ],
        "edges": [
            {
                "edge_id": "edge-external",
                "source_prop_id": "prop-external",
                "source_node_id": "node-root",
                "target_node_id": "",
                "edge_kind": "unresolved_target",
                "status": "unresolved",
                "visible_in_all_propagations": 1,
                "source_function_resolved": "Root",
                "target_function_resolved": "Reader",
                "target_function_raw": "Ns::Reader",
                "reason_code": "tracker_no_target",
                "reason_message": "external tracker did not resolve target",
            },
        ],
        "tree": {
            "node_id": "node-root",
            "function_name_resolved": "Root",
            "function_name_raw": "Root",
            "source_file": "src/root.cpp",
            "depth": 0,
            "status": "done",
            "children": [
                {
                    "node_id": "virtual::edge-external",
                    "edge_id": "edge-external",
                    "function_name_resolved": "Reader",
                    "function_name_raw": "Ns::Reader",
                    "source_file": "src/reader.cpp",
                    "depth": 1,
                    "status": "unresolved",
                    "reason_code": "tracker_no_target",
                    "reason_message": "external tracker did not resolve target",
                    "placeholder": True,
                    "children": [],
                },
            ],
        },
        "sessions": [
            {
                "session_relpath": "sessions/root.jsonl",
                "node_id": "node-root",
                "edge_id": "",
                "session_role": "worker",
                "session_kind": "taint",
                "display_name": "root",
                "status": "done",
                "event_count": 1,
            },
        ],
    }

    propagations = {item["edge_id"]: item for item in _project_propagations_from_graph(view)}
    trace_tree = _project_vuln_trace_tree_from_graph_view(view["tree"])
    session_index = _project_session_index_from_graph(
        task_id="task-external",
        task_status="done",
        run_root=Path("/tmp/run"),
        view=view,
    )

    assert trace_tree is not None
    leaf = trace_tree["children"][0]
    assert propagations["edge-external"]["edge_kind"] == "unresolved_target"
    assert leaf["function_name"] == propagations["edge-external"]["target_function"]
    assert leaf["prune_reason"] == propagations["edge-external"]["reason_code"]
    assert leaf["followup_reason"] == propagations["edge-external"]["reason_message"]
    assert session_index["edges"] == []


def test_session_index_edges_and_sessions_resolve_to_same_authoritative_graph_ids():
    view = {
        "nodes": [
            {"node_id": "node-root", "function_name_resolved": "Root", "function_name_raw": "Root"},
            {"node_id": "node-child", "function_name_resolved": "Child", "function_name_raw": "Ns::Child"},
        ],
        "edges": [
            {
                "edge_id": "edge-direct",
                "source_node_id": "node-root",
                "target_node_id": "node-child",
                "edge_kind": "direct_call",
                "status": "done",
                "visible_in_all_propagations": 1,
                "source_prop_id": "prop-direct",
                "source_function_resolved": "Root",
                "target_function_resolved": "Child",
                "target_function_raw": "Ns::Child",
            },
        ],
        "sessions": [
            {
                "session_relpath": "sessions/root.jsonl",
                "node_id": "node-root",
                "edge_id": "",
                "session_role": "worker",
                "session_kind": "taint",
                "display_name": "root",
                "status": "done",
                "event_count": 2,
            },
            {
                "session_relpath": "sessions/child.jsonl",
                "node_id": "node-child",
                "edge_id": "edge-direct",
                "session_role": "worker",
                "session_kind": "taint",
                "display_name": "child",
                "status": "done",
                "event_count": 4,
            },
        ],
    }

    session_items = _project_session_list_from_graph(view)
    session_index = _project_session_index_from_graph(
        task_id="task-graph-session-consistency",
        task_status="done",
        run_root=Path("/tmp/run"),
        view=view,
    )

    graph_node_ids = {node["node_id"] for node in view["nodes"]}
    graph_edge_ids = {edge["edge_id"] for edge in view["edges"]}
    for session in view["sessions"]:
        assert session["node_id"] in graph_node_ids
        if session["edge_id"]:
            assert session["edge_id"] in graph_edge_ids

    index_nodes = {node["node_id"]: node for node in session_index["nodes"]}
    assert set(index_nodes) == {item["relative_path"] for item in session_items}
    assert index_nodes["sessions/root.jsonl"]["session_header"]["node_id"] == "node-root"
    assert index_nodes["sessions/child.jsonl"]["session_header"]["node_id"] == "node-child"
    assert index_nodes["sessions/child.jsonl"]["session_header"]["edge_id"] == "edge-direct"
    assert session_index["edges"] == [
        {
            "edge_id": "edge-direct",
            "source_node_id": "sessions/root.jsonl",
            "target_node_id": "sessions/child.jsonl",
            "kind": "direct_call",
            "label": "direct_call",
        },
    ]


def test_route_level_projections_cover_edge_kind_and_status_matrix(tmp_path: Path, monkeypatch):
    task_id = "task-route-matrix"
    output_root = tmp_path / "output"
    task_root = output_root / task_id
    run_root = task_root / "run"
    run_root.mkdir(parents=True, exist_ok=True)

    store = VulnScanStore(run_root / "vuln-scan.sqlite")
    store.start_task_graph_run(TaskGraphRunRecord(
        task_id=task_id,
        epoch="16",
        run_root=str(run_root),
        root_function="Root",
    ))

    for node_id, func_id, resolved, raw, source_file, depth, status in [
        ("node-root", "root-func", "Root", "Root", "src/root.cpp", 0, "done"),
        ("node-discovered", "disc-func", "DiscoveredChild", "Ns::DiscoveredChild", "src/discovered.cpp", 1, "discovered"),
        ("node-running", "running-func", "RunningChild", "Ns::RunningChild", "src/running.cpp", 1, "running"),
        ("node-scheduled", "scheduled-func", "ScheduledChild", "Ns::ScheduledChild", "src/scheduled.cpp", 1, "discovered"),
        ("node-done", "done-func", "DoneChild", "Ns::DoneChild", "src/done.cpp", 1, "done"),
        ("node-failed", "failed-func", "FailedChild", "Ns::FailedChild", "src/failed.cpp", 1, "failed"),
        ("node-cancelled", "cancelled-func", "CancelledChild", "Ns::CancelledChild", "src/cancelled.cpp", 1, "cancelled"),
    ]:
        store.upsert_task_graph_node(TaskGraphNodeRecord(
            node_id=node_id,
            task_id=task_id,
            epoch="16",
            func_id=func_id,
            function_name_resolved=resolved,
            function_name_raw=raw,
            source_file=source_file,
            depth=depth,
            status=status,
            analysis_status=status,
        ))

    for payload in [
        {
            "edge_id": "edge-external-raw",
            "source_node_id": "node-root",
            "target_node_id": "",
            "source_func_id": "root-func",
            "target_func_id": "",
            "source_function_resolved": "Root",
            "target_function_resolved": "ReaderCandidate",
            "target_function_raw": "Ns::ReaderCandidate",
            "source_file": "src/root.cpp",
            "target_file": "",
            "edge_kind": "external_escape",
            "status": "discovered",
            "source_prop_id": "prop-external-raw",
            "visible_in_tree": 0,
            "visible_in_all_propagations": 1,
        },
        {
            "edge_id": "edge-discovered",
            "source_node_id": "node-root",
            "target_node_id": "node-discovered",
            "source_func_id": "root-func",
            "target_func_id": "disc-func",
            "source_function_resolved": "Root",
            "target_function_resolved": "DiscoveredChild",
            "target_function_raw": "Ns::DiscoveredChild",
            "source_file": "src/root.cpp",
            "target_file": "src/discovered.cpp",
            "edge_kind": "direct_call",
            "status": "discovered",
            "source_prop_id": "prop-discovered",
            "visible_in_tree": 1,
            "visible_in_all_propagations": 1,
        },
        {
            "edge_id": "edge-running",
            "source_node_id": "node-root",
            "target_node_id": "node-running",
            "source_func_id": "root-func",
            "target_func_id": "running-func",
            "source_function_resolved": "Root",
            "target_function_resolved": "RunningChild",
            "target_function_raw": "Ns::RunningChild",
            "source_file": "src/root.cpp",
            "target_file": "src/running.cpp",
            "edge_kind": "indirect_call",
            "status": "running",
            "source_prop_id": "prop-running",
            "visible_in_tree": 1,
            "visible_in_all_propagations": 1,
        },
        {
            "edge_id": "edge-scheduled",
            "source_node_id": "node-root",
            "target_node_id": "node-scheduled",
            "source_func_id": "root-func",
            "target_func_id": "scheduled-func",
            "source_function_resolved": "Root",
            "target_function_resolved": "ScheduledChild",
            "target_function_raw": "Ns::ScheduledChild",
            "source_file": "src/root.cpp",
            "target_file": "src/scheduled.cpp",
            "edge_kind": "container_reader",
            "status": "scheduled",
            "source_prop_id": "prop-scheduled",
            "visible_in_tree": 1,
            "visible_in_all_propagations": 1,
        },
        {
            "edge_id": "edge-done",
            "source_node_id": "node-root",
            "target_node_id": "node-done",
            "source_func_id": "root-func",
            "target_func_id": "done-func",
            "source_function_resolved": "Root",
            "target_function_resolved": "DoneChild",
            "target_function_raw": "Ns::DoneChild",
            "source_file": "src/root.cpp",
            "target_file": "src/done.cpp",
            "edge_kind": "direct_call",
            "status": "done",
            "source_prop_id": "prop-done",
            "visible_in_tree": 1,
            "visible_in_all_propagations": 1,
        },
        {
            "edge_id": "edge-not-followed",
            "source_node_id": "node-root",
            "target_node_id": "",
            "source_func_id": "root-func",
            "target_func_id": "",
            "source_function_resolved": "Root",
            "target_function_resolved": "ExternalChild",
            "target_function_raw": "Ns::ExternalChild",
            "source_file": "src/root.cpp",
            "target_file": "",
            "edge_kind": "external_callee",
            "status": "not_followed",
            "source_prop_id": "prop-not-followed",
            "reason_code": "external_callee",
            "reason_message": "callee definition is outside source tree",
            "reason_source": "analysis",
            "visible_in_tree": 1,
            "visible_in_all_propagations": 1,
        },
        {
            "edge_id": "edge-unresolved",
            "source_node_id": "node-root",
            "target_node_id": "",
            "source_func_id": "root-func",
            "target_func_id": "",
            "source_function_resolved": "Root",
            "target_function_resolved": "UnresolvedChild",
            "target_function_raw": "Ns::UnresolvedChild",
            "source_file": "src/root.cpp",
            "target_file": "",
            "edge_kind": "unresolved_target",
            "status": "unresolved",
            "source_prop_id": "prop-unresolved",
            "reason_code": "tracker_no_target",
            "reason_message": "tracker did not resolve target",
            "reason_source": "tracker",
            "tracker_type": "indirect_call",
            "tracker_result_json": '{"resolved_targets":[]}',
            "visible_in_tree": 1,
            "visible_in_all_propagations": 1,
        },
        {
            "edge_id": "edge-failed",
            "source_node_id": "node-root",
            "target_node_id": "node-failed",
            "source_func_id": "root-func",
            "target_func_id": "failed-func",
            "source_function_resolved": "Root",
            "target_function_resolved": "FailedChild",
            "target_function_raw": "Ns::FailedChild",
            "source_file": "src/root.cpp",
            "target_file": "src/failed.cpp",
            "edge_kind": "direct_call",
            "status": "failed",
            "source_prop_id": "prop-failed",
            "reason_code": "child_process_failed",
            "reason_message": "child process failed",
            "visible_in_tree": 1,
            "visible_in_all_propagations": 1,
        },
        {
            "edge_id": "edge-cancelled",
            "source_node_id": "node-root",
            "target_node_id": "node-cancelled",
            "source_func_id": "root-func",
            "target_func_id": "cancelled-func",
            "source_function_resolved": "Root",
            "target_function_resolved": "CancelledChild",
            "target_function_raw": "Ns::CancelledChild",
            "source_file": "src/root.cpp",
            "target_file": "src/cancelled.cpp",
            "edge_kind": "return_followup",
            "status": "cancelled",
            "source_prop_id": "prop-cancelled",
            "reason_code": "owner_cancelled",
            "reason_message": "owner cancelled return followup",
            "visible_in_tree": 0,
            "visible_in_all_propagations": 1,
        },
    ]:
        store.upsert_task_graph_edge(TaskGraphEdgeRecord(
            task_id=task_id,
            epoch="16",
            **payload,
        ))

    store.upsert_task_graph_session(TaskGraphSessionRecord(
        session_relpath="sessions/root.jsonl",
        task_id=task_id,
        epoch="16",
        node_id="node-root",
        edge_id="",
        session_role="worker",
        session_kind="taint",
        display_name="root",
        status="done",
        event_count=3,
    ))
    for relpath, node_id, edge_id, status in [
        ("sessions/discovered.jsonl", "node-discovered", "edge-discovered", "running"),
        ("sessions/running.jsonl", "node-running", "edge-running", "running"),
        ("sessions/scheduled.jsonl", "node-scheduled", "edge-scheduled", "queued"),
        ("sessions/done.jsonl", "node-done", "edge-done", "done"),
        ("sessions/failed.jsonl", "node-failed", "edge-failed", "failed"),
        ("sessions/cancelled.jsonl", "node-cancelled", "edge-cancelled", "cancelled"),
    ]:
        store.upsert_task_graph_session(TaskGraphSessionRecord(
            session_relpath=relpath,
            task_id=task_id,
            epoch="16",
            node_id=node_id,
            edge_id=edge_id,
            session_role="worker",
            session_kind="taint",
            display_name=Path(relpath).stem,
            status=status,
            event_count=2,
        ))

    row = SimpleNamespace(
        task_id=task_id,
        output_path=str(output_root),
        result_json={},
        status="failed",
    )
    monkeypatch.setattr(tasks_module, "_get_task_row", lambda db, value: row)

    graph_view = get_task_graph_view(task_id, db=None).model_dump()
    propagations = get_task_propagations(task_id, db=None).model_dump()
    vuln_graph = get_task_vuln_graph(task_id, db=None)
    session_index = get_task_session_index(task_id, db=None)

    assert graph_view["summary"]["edges_total"] == 9
    assert graph_view["summary"]["edges_discovered"] == 2
    assert graph_view["summary"]["edges_running"] == 1
    assert graph_view["summary"]["edges_scheduled"] == 1
    assert graph_view["summary"]["edges_done"] == 1
    assert graph_view["summary"]["edges_not_followed"] == 1
    assert graph_view["summary"]["edges_unresolved"] == 1
    assert graph_view["summary"]["edges_failed"] == 1
    assert graph_view["summary"]["edges_cancelled"] == 1

    propagation_by_id = {item["edge_id"]: item for item in propagations["items"]}
    assert set(propagation_by_id) == {
        "edge-external-raw",
        "edge-discovered",
        "edge-running",
        "edge-scheduled",
        "edge-done",
        "edge-not-followed",
        "edge-unresolved",
        "edge-failed",
        "edge-cancelled",
    }
    assert propagation_by_id["edge-external-raw"]["propagation_method"] == "外部逃逸"
    assert propagation_by_id["edge-discovered"]["propagation_method"] == "直接调用"
    assert propagation_by_id["edge-running"]["propagation_method"] == "间接调用"
    assert propagation_by_id["edge-scheduled"]["propagation_method"] == "容器读者跟入"
    assert propagation_by_id["edge-not-followed"]["propagation_method"] == "外部 callee"
    assert propagation_by_id["edge-unresolved"]["propagation_method"] == "未解析目标"
    assert propagation_by_id["edge-cancelled"]["propagation_method"] == "返回值回溯"
    assert propagation_by_id["edge-unresolved"]["unfollowed_reason_source"] == "tracker"
    assert propagation_by_id["edge-not-followed"]["unfollowed_reason_source"] == "analysis"

    assert vuln_graph["summary"]["edges"] == 9
    assert vuln_graph["summary"]["executed_followups"] == 5
    assert vuln_graph["summary"]["pending_followups"] == 4
    assert vuln_graph["summary"]["skipped_followups"] == 2
    assert graph_view["tree"] is not None

    def _collect_graph_tree_node_ids(node: dict) -> list[str]:
        values = [node["node_id"]]
        for child in node.get("children") or []:
            values.extend(_collect_graph_tree_node_ids(child))
        return values

    def _collect_trace_tree_run_ids(node: dict) -> list[str]:
        values = [node["run_id"]]
        for child in node.get("children") or []:
            values.extend(_collect_trace_tree_run_ids(child))
        return values

    assert _collect_trace_tree_run_ids(vuln_graph["trace_tree"]) == _collect_graph_tree_node_ids(graph_view["tree"])
    trace_child_ids = {child["run_id"] for child in vuln_graph["trace_tree"]["children"]}
    assert "node-cancelled" not in trace_child_ids
    assert "node-discovered" in trace_child_ids
    assert "node-running" in trace_child_ids
    assert "node-scheduled" in trace_child_ids
    assert "node-done" in trace_child_ids
    assert "node-failed" in trace_child_ids
    assert "virtual::edge-not-followed" in trace_child_ids
    assert "virtual::edge-unresolved" in trace_child_ids

    session_edge_ids = {node["session_header"]["edge_id"] for node in session_index["nodes"] if node["session_header"]["edge_id"]}
    assert {"edge-discovered", "edge-running", "edge-scheduled", "edge-done", "edge-failed", "edge-cancelled"} <= session_edge_ids
