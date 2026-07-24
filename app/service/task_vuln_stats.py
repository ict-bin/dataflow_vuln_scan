from __future__ import annotations

import logging

from sqlalchemy.orm.attributes import flag_modified

from app.db import get_db
from app.db.models import AppDvsTask
from .task_paths import _task_root, authoritative_task_vuln_stats

logger = logging.getLogger("dvs.task_vuln_stats")


def sync_task_vuln_snapshot_row(row: AppDvsTask, *, prefer_live: bool = True) -> bool:
    task_id = str(row.task_id or "").strip()
    task_root = _task_root(row)
    stats = authoritative_task_vuln_stats(task_root, task_id, prefer_live=prefer_live)
    if stats is None:
        return False
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
                task_id or getattr(row, "id", None),
                exc_info=True,
            )
    return changed


def refresh_task_vuln_snapshot_by_task_id(task_id: str, *, prefer_live: bool = True) -> bool:
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
