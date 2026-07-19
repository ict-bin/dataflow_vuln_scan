from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from app.dataflow_v2.graph_export import _find_vuln_sqlite


def _query_sqlite_rows(db_path: Path, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def _sqlite_table_columns(db_path: Path, table_name: str) -> set[str]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {str(row["name"] or "") for row in rows}
    finally:
        conn.close()


def _json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if not value:
        return []
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def _propagation_method(row: sqlite3.Row) -> str:
    if bool(row["is_indirect_call"]):
        dispatch_kind = str(row["dispatch_kind"] or "").strip()
        return f"间接调用 / {dispatch_kind}" if dispatch_kind else "间接调用"
    if bool(row["is_external"]):
        escape_kind = str(row["escape_kind"] or "").strip()
        return f"外部逃逸 / {escape_kind}" if escape_kind else "外部逃逸"
    if bool(row["is_external_callee"]):
        return "外部 callee"
    return "直接调用"


def _derive_unfollowed_reason_from_propagation(row: sqlite3.Row) -> tuple[str, str]:
    if bool(row["is_external"]):
        escape_kind = str(row["escape_kind"] or "").strip()
        if escape_kind:
            return f"external_escape_{escape_kind}", "propagation"
        return "external_escape_not_followed", "propagation"
    if bool(row["is_indirect_call"]):
        dispatch_kind = str(row["dispatch_kind"] or "").strip()
        if dispatch_kind:
            return f"indirect_call_unresolved:{dispatch_kind}", "propagation"
        return "indirect_call_unresolved", "propagation"
    if bool(row["is_external_callee"]):
        return "external_callee_not_followed", "propagation"
    if not str(row["target_func_id"] or "").strip():
        return "target_missing_not_followed", "derived"
    return "not_scheduled_into_orchestration", "derived"


def _load_followup_rows(vuln_sqlite: Path | None) -> list[dict[str, Any]]:
    if vuln_sqlite is None or not vuln_sqlite.exists():
        return []
    try:
        columns = _sqlite_table_columns(vuln_sqlite, "followups")
        if not columns:
            return []
        select_cols = [
            "followup_id",
            "edge_id",
            "callee_function",
            "status",
            "reason",
        ]
        if "tracker_type" in columns:
            select_cols.append("tracker_type")
        else:
            select_cols.append("'' AS tracker_type")
        if "tracker_status" in columns:
            select_cols.append("tracker_status")
        else:
            select_cols.append("'' AS tracker_status")
        if "tracker_result_json" in columns:
            select_cols.append("tracker_result_json")
        else:
            select_cols.append("'{}' AS tracker_result_json")
        return [
            dict(row)
            for row in _query_sqlite_rows(
                vuln_sqlite,
                f"SELECT {', '.join(select_cols)} FROM followups",
            )
        ]
    except Exception:
        return []


def _build_followup_reason_maps(vuln_sqlite: Path | None) -> tuple[dict[str, dict[str, Any]], dict[tuple[str, str], dict[str, Any]]]:
    followups = _load_followup_rows(vuln_sqlite)
    by_edge_id: dict[str, dict[str, Any]] = {}
    by_callee_name: dict[tuple[str, str], dict[str, Any]] = {}
    for row in followups:
        edge_id = str(row.get("edge_id") or "").strip()
        if edge_id and edge_id not in by_edge_id:
            by_edge_id[edge_id] = row
        callee_function = str(row.get("callee_function") or "").strip()
        if edge_id and callee_function and (edge_id, callee_function) not in by_callee_name:
            by_callee_name[(edge_id, callee_function)] = row
    return by_edge_id, by_callee_name


def _derive_unfollowed_reason_from_followup(row: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    followup_status = str(row.get("status") or "").strip() or None
    followup_reason = str(row.get("reason") or "").strip() or None
    tracker_type = str(row.get("tracker_type") or "").strip()
    tracker_status = str(row.get("tracker_status") or "").strip()
    if followup_reason:
        return followup_reason, "followup", followup_status
    if tracker_status:
        if tracker_type:
            return f"{tracker_type}:{tracker_status}", "followup", followup_status
        return tracker_status, "followup", followup_status
    if followup_status and followup_status not in {"done", "completed", "analyzed"}:
        return followup_status, "followup", followup_status
    return None, None, followup_status


def load_task_propagations_legacy(run_root: Path) -> list[dict[str, Any]]:
    v2_root = run_root / "dataflow-v2"
    prop_db = v2_root / "propagations.db"
    fn_db = v2_root / "functions.db"
    orch_db = v2_root / "orchestration.db"
    vuln_sqlite = _find_vuln_sqlite(run_root)
    if not prop_db.exists():
        return []

    func_rows = _query_sqlite_rows(
        fn_db,
        "SELECT func_id, name, file FROM functions",
    ) if fn_db.exists() else []
    func_map = {
        str(row["func_id"]): {
            "name": str(row["name"] or ""),
            "file": str(row["file"] or ""),
        }
        for row in func_rows
    }

    orchestration_rows = _query_sqlite_rows(
        orch_db,
        "SELECT source_func_id, target_func_id, target_function, status FROM orchestration",
    ) if orch_db.exists() else []
    followed_pairs: dict[tuple[str, str], str] = {}
    followed_names: dict[tuple[str, str], str] = {}
    for row in orchestration_rows:
        source_func_id = str(row["source_func_id"] or "")
        target_func_id = str(row["target_func_id"] or "")
        target_function = str(row["target_function"] or "")
        status = str(row["status"] or "")
        if source_func_id and target_func_id:
            followed_pairs[(source_func_id, target_func_id)] = status
        if source_func_id and target_function:
            followed_names[(source_func_id, target_function)] = status
    followup_by_edge, followup_by_edge_and_name = _build_followup_reason_maps(vuln_sqlite)

    prop_columns = _sqlite_table_columns(prop_db, "propagations")
    external_callee_expr = "is_external_callee" if "is_external_callee" in prop_columns else "0 AS is_external_callee"
    prop_rows = _query_sqlite_rows(
        prop_db,
        f"""
        SELECT prop_id, source_func_id, source_taint_name, source_taint_signature,
               target_taint_name, target_taint_signature, target_function, target_func_id,
               target_file, call_line, condition, is_external, is_indirect_call,
               {external_callee_expr}, dispatch_kind, escape_kind, carrier, escape_via,
               callsite_validated, branch_group_id, branch_arm_id, mutex_siblings,
               validations, actual_args, description
          FROM propagations
         ORDER BY source_func_id, call_line, prop_id
        """,
    )
    items: list[dict[str, Any]] = []
    for row in prop_rows:
        source_func_id = str(row["source_func_id"] or "")
        source_meta = func_map.get(source_func_id, {})
        target_func_id = str(row["target_func_id"] or "")
        target_function = str(row["target_function"] or "")
        orchestration_status = None
        if source_func_id and target_func_id:
            orchestration_status = followed_pairs.get((source_func_id, target_func_id))
        if orchestration_status is None and source_func_id and target_function:
            orchestration_status = followed_names.get((source_func_id, target_function))
        followup_row = followup_by_edge.get(str(row["prop_id"] or ""))
        if followup_row is None and target_function:
            followup_row = followup_by_edge_and_name.get((str(row["prop_id"] or ""), target_function))
        followup_reason, followup_reason_source, followup_status = (None, None, None)
        if followup_row is not None:
            followup_reason, followup_reason_source, followup_status = _derive_unfollowed_reason_from_followup(followup_row)
        if not followup_reason and orchestration_status is None:
            followup_reason, followup_reason_source = _derive_unfollowed_reason_from_propagation(row)
        items.append({
            "prop_id": str(row["prop_id"] or ""),
            "source_func_id": source_func_id or None,
            "source_function": source_meta.get("name") or None,
            "source_file": source_meta.get("file") or None,
            "source_taint_name": str(row["source_taint_name"] or ""),
            "source_taint_signature": str(row["source_taint_signature"] or ""),
            "target_taint_name": str(row["target_taint_name"] or ""),
            "target_taint_signature": str(row["target_taint_signature"] or ""),
            "target_func_id": target_func_id or None,
            "target_function": target_function or None,
            "target_file": str(row["target_file"] or "") or None,
            "call_line": int(row["call_line"]) if row["call_line"] is not None else None,
            "condition": str(row["condition"] or "") or None,
            "description": str(row["description"] or "") or None,
            "validations": _json_list(row["validations"]),
            "actual_args": [str(item) for item in _json_list(row["actual_args"])],
            "is_external": bool(row["is_external"]),
            "is_indirect_call": bool(row["is_indirect_call"]),
            "is_external_callee": bool(row["is_external_callee"]),
            "dispatch_kind": str(row["dispatch_kind"] or "") or None,
            "escape_kind": str(row["escape_kind"] or "") or None,
            "carrier": str(row["carrier"] or "") or None,
            "escape_via": str(row["escape_via"] or "") or None,
            "callsite_validated": bool(row["callsite_validated"]),
            "branch_group_id": str(row["branch_group_id"] or "") or None,
            "branch_arm_id": str(row["branch_arm_id"] or "") or None,
            "mutex_siblings": [str(item) for item in _json_list(row["mutex_siblings"])],
            "propagation_method": _propagation_method(row),
            "orchestration_followed": orchestration_status is not None,
            "orchestration_status": orchestration_status,
            "unfollowed_reason": followup_reason,
            "unfollowed_reason_source": followup_reason_source,
            "followup_status": followup_status,
            "followup_reason_raw": str((followup_row or {}).get("reason") or "") or None,
        })
    items.sort(
        key=lambda item: (
            str(item.get("source_function") or ""),
            int(item.get("call_line") or 0),
            str(item.get("prop_id") or ""),
        )
    )
    return items
