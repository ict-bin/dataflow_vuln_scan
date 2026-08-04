"""老版本兼容层: 从 SQLite / DB 读取老版本任务数据。

老版本任务的数据存储方式与新版本不同:
  - findings / task_graph: 存在 SQLite vuln-scan.sqlite (新版本用 MySQL)
  - timeline events: 存在管理库 secflow_app_dvs_task_events 表 (新版本用 events.jsonl)

本模块提供统一的 fallback 读取, 新版本代码调用方在 MySQL / events.jsonl 无数据时
委托本模块读取, 避免在主代码中散布兼容逻辑。
"""
from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

logger = logging.getLogger("dvs.legacy_compat")


# ── SQLite vuln-scan.sqlite 读取 (老版本 finding / task_graph 数据) ───────

def sqlite_list_task_findings(db_path: Path | str, task_id: str) -> list[dict[str, Any]]:
    """从老版本 vuln-scan.sqlite 读取 task 关联的 findings。"""
    try:
        with _open_sqlite_ro(db_path) as conn:
            return [dict(r) for r in conn.execute(
                """SELECT vf.* FROM vulnerability_findings vf
                   JOIN analysis_runs ar ON ar.run_id = vf.run_id
                   WHERE ar.task_id = ?
                   ORDER BY vf.created_at, vf.finding_id""",
                (task_id,)).fetchall()]
    except Exception:
        logger.debug("sqlite_list_task_findings failed: db=%s task=%s", db_path, task_id, exc_info=True)
        return []


def sqlite_list_all_findings(db_path: Path | str, conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    """从老版本 vuln-scan.sqlite 读取全部 findings。"""
    try:
        if conn is not None:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM vulnerability_findings ORDER BY created_at, finding_id").fetchall()]
        with _open_sqlite_ro(db_path) as owned:
            return [dict(r) for r in owned.execute(
                "SELECT * FROM vulnerability_findings ORDER BY created_at, finding_id").fetchall()]
    except Exception:
        logger.debug("sqlite_list_all_findings failed: db=%s", db_path, exc_info=True)
        return []


def sqlite_export_task_graph_view(db_path: Path | str, task_id: str) -> dict[str, Any]:
    """从老版本 vuln-scan.sqlite 读取任务图谱视图。"""
    try:
        with _open_sqlite_ro(db_path) as conn:
            run = conn.execute(
                "SELECT * FROM task_graph_runs WHERE task_id=?", (task_id,)).fetchone()
            nodes = [dict(r) for r in conn.execute(
                "SELECT * FROM task_graph_nodes WHERE task_id=? ORDER BY depth, function_name_resolved, node_id",
                (task_id,)).fetchall()]
            edges = [dict(r) for r in conn.execute(
                "SELECT * FROM task_graph_edges WHERE task_id=? ORDER BY display_order, source_function_resolved, edge_id",
                (task_id,)).fetchall()]
            sessions = [dict(r) for r in conn.execute(
                "SELECT * FROM task_graph_sessions WHERE task_id=? ORDER BY session_relpath",
                (task_id,)).fetchall()]
            findings = [dict(r) for r in conn.execute(
                """SELECT vf.* FROM vulnerability_findings vf
                   JOIN analysis_runs ar ON ar.run_id = vf.run_id
                   WHERE ar.task_id = ?
                   ORDER BY vf.created_at, vf.finding_id""",
                (task_id,)).fetchall()]
        run_d = dict(run) if run else {}
        summary = {
            "nodes_total": len(nodes),
            "edges_total": len(edges),
            "edges_done": sum(1 for e in edges if e.get("status") == "done"),
            "edges_running": sum(1 for e in edges if e.get("status") == "running"),
            "edges_failed": sum(1 for e in edges if e.get("status") == "failed"),
            "findings_total": len(findings),
        }
        return {
            "task_id": task_id,
            "epoch": run_d.get("epoch", ""),
            "available": bool(run or nodes or edges or sessions or findings),
            "summary": summary,
            "nodes": nodes,
            "edges": edges,
            "sessions": sessions,
            "findings": findings,
            "generated_at": run_d.get("generated_at"),
            "run_root": run_d.get("run_root", ""),
        }
    except Exception:
        logger.debug("sqlite_export_task_graph_view failed: db=%s task=%s", db_path, task_id, exc_info=True)
        return {"task_id": task_id, "available": False}


def _open_sqlite_ro(db_path: Path | str) -> sqlite3.Connection:
    """以只读模式打开 SQLite, 不创建 WAL。"""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


# ── DB 事件读取 (老版本 timeline 存在管理库) ──────────────────────────

def db_read_task_events(task_id: str) -> list[dict[str, object]]:
    """从管理库 secflow_app_dvs_task_events 表读取事件 (兼容老版本任务)。

    老版本任务的事件存储在 DB 中 (没有 events.jsonl), 此函数提供 fallback。
    """
    try:
        from app.db import get_db
        from sqlalchemy import text as sa_text
        db = next(get_db())
        try:
            rows = db.execute(sa_text(
                "SELECT * FROM secflow_app_dvs_task_events WHERE task_id=:tid "
                "ORDER BY created_at"
            ), {"tid": task_id}).fetchall()
            events: list[dict[str, object]] = []
            for r in rows:
                d = dict(r._mapping)
                payload = {}
                try:
                    payload = json.loads(d.get("payload_json") or "{}")
                except Exception:
                    pass
                events.append({
                    "id": str(d.get("id") or ""),
                    "task_id": str(d.get("task_id") or ""),
                    "project_id": str(d.get("project_id") or ""),
                    "source": str(d.get("source") or "dvs"),
                    "level": str(d.get("level") or "info"),
                    "event_type": str(d.get("event_type") or ""),
                    "status": d.get("status"),
                    "worker_id": d.get("worker_id"),
                    "execution_owner_id": d.get("execution_owner_id"),
                    "execution_epoch": d.get("execution_epoch"),
                    "control_version": d.get("control_version"),
                    "dispatch_status": d.get("dispatch_status"),
                    "function_name": d.get("function_name"),
                    "source_file": d.get("source_file"),
                    "line_hint": d.get("line_hint"),
                    "parent_task_id": d.get("parent_task_id"),
                    "parent_stage_item_id": d.get("parent_stage_item_id"),
                    "message": str(d.get("message") or ""),
                    "payload": payload,
                    "created_at": d.get("created_at").isoformat() if d.get("created_at") else "",
                })
            if events:
                logger.info("legacy: read %d events from DB for task %s", len(events), task_id)
            return events
        finally:
            db.close()
    except Exception:
        logger.debug("db_read_task_events failed: task_id=%s", task_id, exc_info=True)
        return []
