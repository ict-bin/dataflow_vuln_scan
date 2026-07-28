from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from sqlalchemy.orm.attributes import flag_modified

from app.db import get_db
from app.db.models import AppDvsTask
from .task_paths import _task_root, authoritative_task_vuln_stats

logger = logging.getLogger("dvs.task_vuln_stats")

# 统一按 task_id 经 analysis_runs 关联计数 vulnerability_findings。
# runner 里 run_id == task_id (start_run(tid, tid, ...))，故按 task_id 计数等价于按 run_id。
_FINDINGS_COUNT_SQL = (
    "SELECT count(*) AS total, "
    "sum(CASE WHEN vf.report_status='reported' THEN 1 ELSE 0 END) AS reported "
    "FROM vulnerability_findings vf "
    "JOIN analysis_runs ar ON ar.run_id = vf.run_id "
    "WHERE ar.task_id = ?"
)


def _count_from_conn(conn, task_id: str) -> tuple[int, int, int]:
    row = conn.execute(_FINDINGS_COUNT_SQL, (task_id,)).fetchone()
    total = int(row["total"] or 0) if row is not None else 0
    reported = int(row["reported"] or 0) if row is not None else 0
    return total, reported, max(0, total - reported)


def count_findings_from_local_store(graph_store: Any, task_id: str) -> tuple[int, int, int] | None:
    """Worker 执行期: 直接用手里已有的 local graph_store (pod-local vuln-scan.sqlite)
    计数。不开第二个 sqlite 文件、不碰 NFS、不开 WAL 写连接——复用 writer 自己的
    graph_store.connect()。

    这是 1c211f5 之前 analysis.py / finding_store.py 用的安全写法，被那次 "统一
    authoritative 读取" 重构废弃后引入了 worker 开 NFS sqlite 的问题，现恢复。
    """
    if graph_store is None:
        return None
    try:
        with graph_store.connect() as conn:
            return _count_from_conn(conn, task_id)
    except Exception:
        logger.debug("count_findings_from_local_store failed (task=%s)", task_id, exc_info=True)
        return None


def count_findings_readonly(db_path: Path | str | None, task_id: str) -> tuple[int, int, int] | None:
    """对给定 sqlite 路径以只读、无 WAL 方式计数。

    用于 worker 终态提交: 路径是 pod-local epoch vuln-scan.sqlite (经 workspace
    软链 → /tmp)。只读 + 关 WAL, 避免与周期同步 copy2 同一文件时互相撕裂/
    丢 -wal 页导致 "database disk image is malformed"。
    """
    if not db_path:
        return None
    path = Path(db_path)
    if not path.exists():
        return None
    from app.vuln_store import VulnScanStore
    try:
        store = VulnScanStore(path, readonly=True, enable_wal=False)
        with store.connect() as conn:
            return _count_from_conn(conn, task_id)
    except Exception:
        logger.debug("count_findings_readonly failed (path=%s task=%s)", path, task_id, exc_info=True)
        return None


def _apply_stats_to_row(row: AppDvsTask, stats: tuple[int, int, int]) -> bool:
    total, reported, unreported = stats
    changed = (
        row.vuln_total_count != total
        or row.vuln_reported_count != reported
        or row.vuln_unreported_count != unreported
    )
    if changed:
        row.vuln_total_count = total
        row.vuln_reported_count = reported
        row.vuln_unreported_count = unreported
        try:
            flag_modified(row, "vuln_total_count")
            flag_modified(row, "vuln_reported_count")
            flag_modified(row, "vuln_unreported_count")
        except Exception:
            logger.warning(
                "sync_task_vuln_snapshot_row: flag_modified failed task_id=%s",
                row.task_id or getattr(row, "id", None),
                exc_info=True,
            )
    return changed


def sync_task_vuln_snapshot_row(
    row: AppDvsTask,
    *,
    prefer_live: bool = True,
    local_graph_db_path: Path | str | None = None,
) -> bool:
    """刷新任务行的漏洞计数快照。

    路由 (避免 worker 碰 NFS sqlite —— "database disk image is malformed" 根因):
      * worker 执行期/终态提交传 local_graph_db_path (pod-local epoch
        vuln-scan.sqlite) → 只读计数, 不碰 NFS、不开 WAL 写。
      * worker 手里有 graph_store 时更应直接调
        sync_vuln_count_from_local_store() (更省)。
      * API (不传 local 路径) → authoritative_task_vuln_stats() 只读读跨 pod
        的 NFS 快照 (合法的 API 实时读取需求)。
    """
    task_id = str(row.task_id or "").strip()
    stats: tuple[int, int, int] | None = None
    if local_graph_db_path is not None:
        stats = count_findings_readonly(local_graph_db_path, task_id)
    if stats is None:
        task_root = _task_root(row)
        stats = authoritative_task_vuln_stats(task_root, task_id, prefer_live=prefer_live)
    if stats is None:
        return False
    return _apply_stats_to_row(row, stats)


def sync_vuln_count_from_local_store(graph_store: Any, task_id: str) -> bool:
    """worker 执行期: 用手里 local graph_store 计数并落库。

    取代旧 refresh_task_vuln_snapshot_by_task_id() ——后者经
    open_authoritative_vuln_scan_store() 以 WAL 写模式打开 NFS 上的
    run/vuln-scan.sqlite, 与周期同步 copy2 并发导致库文件损坏。
    """
    stats = count_findings_from_local_store(graph_store, task_id)
    if stats is None:
        return False
    db = next(get_db())
    try:
        row = db.query(AppDvsTask).filter_by(task_id=task_id).first()
        if row is None:
            return False
        changed = _apply_stats_to_row(row, stats)
        if changed:
            db.commit()
        return changed
    finally:
        db.close()


def refresh_task_vuln_snapshot_by_task_id(task_id: str, *, prefer_live: bool = True) -> bool:
    """API 侧刷新: 只读读 authoritative (NFS) sqlite。保留给 API/跨 pod 调用方;
    worker 执行路径必须改用 sync_vuln_count_from_local_store() 或传
    local_graph_db_path。
    """
    normalized_task_id = str(task_id or "").strip()
    if not normalized_task_id:
        return False
    db = next(get_db())
    try:
        row = db.query(AppDvsTask).filter_by(task_id=normalized_task_id).first()
        if row is None:
            return False
        changed = sync_task_vuln_snapshot_row(row, prefer_live=prefer_live)
        if changed:
            db.commit()
        return changed
    finally:
        db.close()
