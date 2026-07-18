from __future__ import annotations

import sqlite3
from pathlib import Path

from app.api.tasks import _load_task_propagations


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

    items = _load_task_propagations(run_root)
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

    items = _load_task_propagations(run_root)
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

    items = _load_task_propagations(run_root)
    assert len(items) == 1
    assert items[0]["prop_id"] == "legacy_prop"
    assert items[0]["is_external_callee"] is False
    assert items[0]["propagation_method"] == "直接调用"
