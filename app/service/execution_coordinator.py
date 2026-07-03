from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import AppDvsTask
from app.runtime_context import LEASE_TTL_SECONDS
from app.time_utils import now_local

_AUTO_RECOVERY_FLAG_KEYS = {
    "_auto_recovered_pending",
    "_auto_recovered_reason",
    "_auto_recovered_previous_owner_id",
    "_auto_recovered_previous_epoch",
    "_auto_recovered_marked_at",
}


@dataclass
class ClaimedTask:
    task_id: str
    epoch: int
    control_version: int
    dispatch_status: str | None = None


@dataclass
class ExecutionSnapshot:
    task_id: str
    status: str
    execution_owner_id: str | None
    execution_epoch: int
    control_version: int
    dispatch_status: str | None
    execution_lease_until: object | None
    execution_heartbeat_at: object | None


@dataclass(frozen=True)
class RecoveredRunningTask:
    task_id: str
    previous_owner_id: str | None
    previous_dispatch_status: str | None
    previous_lease_until: object | None
    reason: str


def _lease_deadline():
    return now_local() + timedelta(seconds=LEASE_TTL_SECONDS)


def _with_clean_restart_flag(config: Any, *, reason: str, previous_owner_id: str | None, previous_epoch: int | None) -> dict[str, Any]:
    import datetime as _dt
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except Exception:
            config = {}
    cfg = {k: v for k, v in (config or {}).items() if k and not k.startswith("_")} if isinstance(config, dict) else {}
    cfg["_force_clean_restart"] = True
    cfg["_restart_reason"] = reason
    cfg["_restart_previous_owner_id"] = previous_owner_id or ""
    cfg["_restart_previous_epoch"] = int(previous_epoch or 0)
    cfg["_restart_marked_at"] = _dt.datetime.now().isoformat()
    return cfg


def _with_auto_recovery_flag(config: Any, *, reason: str, previous_owner_id: str | None, previous_epoch: int | None) -> dict[str, Any]:
    import datetime as _dt
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except Exception:
            config = {}
    cfg = dict(config) if isinstance(config, dict) else {}
    cfg["_auto_recovered_pending"] = True
    cfg["_auto_recovered_reason"] = str(reason or "").strip()
    cfg["_auto_recovered_previous_owner_id"] = str(previous_owner_id or "").strip()
    cfg["_auto_recovered_previous_epoch"] = int(previous_epoch or 0)
    cfg["_auto_recovered_marked_at"] = _dt.datetime.now().isoformat()
    return cfg


def _clear_auto_recovery_flag(config: Any) -> dict[str, Any]:
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except Exception:
            config = {}
    cfg = dict(config) if isinstance(config, dict) else {}
    for key in _AUTO_RECOVERY_FLAG_KEYS:
        cfg.pop(key, None)
    return cfg


def _auto_recovery_payload(config: Any) -> dict[str, Any] | None:
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except Exception:
            config = {}
    if not isinstance(config, dict):
        return None
    if not bool(config.get("_auto_recovered_pending")):
        return None
    return {
        "pending": True,
        "reason": str(config.get("_auto_recovered_reason") or "").strip(),
        "previous_owner_id": str(config.get("_auto_recovered_previous_owner_id") or "").strip() or None,
        "previous_epoch": int(config.get("_auto_recovered_previous_epoch") or 0),
        "marked_at": str(config.get("_auto_recovered_marked_at") or "").strip() or None,
    }


def is_parent_orchestrated_binary_security_task(row: AppDvsTask | None) -> bool:
    if row is None:
        return False
    if str(getattr(row, "task_origin_type", "") or "").strip() != "binary_security":
        return False
    parent_task_id = str(getattr(row, "parent_task_id", "") or "").strip()
    parent_stage_item_id = str(getattr(row, "parent_stage_item_id", "") or "").strip()
    return bool(parent_task_id and parent_stage_item_id)


def _clean_restart_update_fields(row: AppDvsTask | None, *, reason: str) -> dict:
    """Build SQLAlchemy update dict for a clean restart."""
    import datetime as _dt
    now_iso = _dt.datetime.now().isoformat()
    base_cfg: dict[str, Any] = {}
    if row is not None:
        raw = row.task_config_json
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = {}
        if isinstance(raw, dict):
            base_cfg = {k: v for k, v in raw.items() if k and not k.startswith("_")}
    base_cfg["_force_clean_restart"] = True
    base_cfg["_restart_reason"] = reason
    base_cfg["_restart_previous_owner_id"] = str(row.execution_owner_id or "") if row else ""
    base_cfg["_restart_previous_epoch"] = int(row.execution_epoch or 0) if row else 0
    base_cfg["_restart_marked_at"] = now_iso
    base_cfg = _with_auto_recovery_flag(
        base_cfg,
        reason=reason,
        previous_owner_id=str(row.execution_owner_id or "") if row else "",
        previous_epoch=int(row.execution_epoch or 0) if row else 0,
    )
    return {
        AppDvsTask.task_config_json: base_cfg,
        AppDvsTask.result_json: None,
        AppDvsTask.stages_json: None,
        AppDvsTask.latest_abnormal_reason_json: None,
        AppDvsTask.error: None,
        AppDvsTask.finished_at: None,
        AppDvsTask.started_at: None,
    }


def _mark_row_clean_restart(row: AppDvsTask, *, reason: str, previous_owner_id: str | None = None, previous_epoch: int | None = None) -> None:
    cfg = _with_clean_restart_flag(
        row.task_config_json,
        reason=reason,
        previous_owner_id=previous_owner_id if previous_owner_id is not None else row.execution_owner_id,
        previous_epoch=previous_epoch if previous_epoch is not None else int(row.execution_epoch or 0),
    )
    row.task_config_json = _with_auto_recovery_flag(
        cfg,
        reason=reason,
        previous_owner_id=previous_owner_id if previous_owner_id is not None else row.execution_owner_id,
        previous_epoch=previous_epoch if previous_epoch is not None else int(row.execution_epoch or 0),
    )
    row.result_json = None
    row.stages_json = None
    row.latest_abnormal_reason_json = None
    row.error = None
    row.finished_at = None
    row.started_at = None


def _clean_restart_update_fields(row: AppDvsTask, *, reason: str) -> dict:
    cfg = _with_clean_restart_flag(
        row.task_config_json,
        reason=reason,
        previous_owner_id=row.execution_owner_id,
        previous_epoch=int(row.execution_epoch or 0),
    )
    cfg = _with_auto_recovery_flag(
        cfg,
        reason=reason,
        previous_owner_id=row.execution_owner_id,
        previous_epoch=int(row.execution_epoch or 0),
    )
    return {
        AppDvsTask.task_config_json: cfg,
        AppDvsTask.result_json: None,
        AppDvsTask.stages_json: None,
        AppDvsTask.latest_abnormal_reason_json: None,
        AppDvsTask.error: None,
        AppDvsTask.finished_at: None,
        AppDvsTask.started_at: None,
    }


def claim_one_runnable_task(db: Session, owner_id: str) -> ClaimedTask | None:
    now = now_local()
    candidate = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.is_deleted.is_(False),
            AppDvsTask.status.in_(["pending", "running"]),
            ((AppDvsTask.execution_lease_until.is_(None)) | (AppDvsTask.execution_lease_until < now)),
        )
        .order_by(AppDvsTask.status.asc(), AppDvsTask.created_at.asc(), AppDvsTask.id.asc())
        .first()
    )
    if candidate is None:
        return None

    expected_status = str(candidate.status or "pending")
    new_epoch = int(candidate.execution_epoch or 0) + 1
    update_fields = {
        AppDvsTask.execution_owner_id: owner_id,
        AppDvsTask.execution_lease_until: _lease_deadline(),
        AppDvsTask.execution_heartbeat_at: now,
        AppDvsTask.execution_epoch: new_epoch,
        AppDvsTask.dispatch_status: "leased",
    }
    if expected_status == "running":
        if is_parent_orchestrated_binary_security_task(candidate):
            update_fields[AppDvsTask.status] = "running"
        else:
            # No checkpoint/resume support: a reclaimed running task must be a clean business restart.
            update_fields[AppDvsTask.status] = "pending"
            update_fields.update(_clean_restart_update_fields(candidate, reason="claim_expired_running"))

    updated = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.id == candidate.id,
            AppDvsTask.is_deleted.is_(False),
            AppDvsTask.status == expected_status,
            ((AppDvsTask.execution_lease_until.is_(None)) | (AppDvsTask.execution_lease_until < now)),
        )
        .update(
            update_fields,
            synchronize_session=False,
        )
    )
    db.commit()
    if not updated:
        return None
    # expire_on_commit=False is required for long-running task result materialization, so do not
    # rely on the identity map to reload candidate here: it would return the pre-update epoch and
    # make the executor immediately fail still_owner() with task_not_owner_pre_execute.
    return ClaimedTask(
        task_id=str(candidate.task_id),
        epoch=new_epoch,
        control_version=int(candidate.control_version or 0),
        dispatch_status="leased",
    )


def claim_specific_task(db: Session, owner_id: str, task_id: str) -> ClaimedTask | None:
    """Celery worker 收到 LAUNCH 后按 task_id 认领 (非竞争性)。

    与 claim_one_runnable_task 的区别: 不扫表竞争, 只认领指定 task_id。
    用于 Celery 消费: dispatcher 已把该 task 路由到本 worker, 这里设 owner/epoch/lease。
    只认领 pending (正常) 或 running 但租约过期 (acks_late 重投/孤儿);
    running 且租约新鲜 → 返回 None (别的活 worker 在跑, 本消息作废 ack 掉)。
    """
    now = now_local()
    candidate = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.task_id == task_id,
            AppDvsTask.is_deleted.is_(False),
        )
        .first()
    )
    if candidate is None:
        return None
    status = str(candidate.status or "pending")
    if status == "pending":
        expected_status = "pending"
    elif status == "running" and (
        candidate.execution_lease_until is None or candidate.execution_lease_until < now
    ):
        # 租约过期/孤儿: clean restart 回 pending 再认领
        expected_status = "running"
    else:
        # running 且租约新鲜 / 已终态 → 不认领 (别的 worker 在跑或已结束)
        return None
    new_epoch = int(candidate.execution_epoch or 0) + 1
    update_fields = {
        AppDvsTask.execution_owner_id: owner_id,
        AppDvsTask.execution_lease_until: _lease_deadline(),
        AppDvsTask.execution_heartbeat_at: now,
        AppDvsTask.execution_epoch: new_epoch,
        AppDvsTask.dispatch_status: "leased",
    }
    if expected_status == "running":
        # 孤儿重抢: 回 pending, begin_execution_if_owner 会再设 running
        update_fields[AppDvsTask.status] = "pending"
    updated = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.id == candidate.id,
            AppDvsTask.is_deleted.is_(False),
            AppDvsTask.status == expected_status,
            ((AppDvsTask.execution_lease_until.is_(None)) | (AppDvsTask.execution_lease_until < now))
            if expected_status == "running" else AppDvsTask.status.is_not(None),
        )
        .update(update_fields, synchronize_session=False)
    )
    db.commit()
    if not updated:
        return None
    return ClaimedTask(
        task_id=str(candidate.task_id),
        epoch=new_epoch,
        control_version=int(candidate.control_version or 0),
        dispatch_status="leased",
    )


def renew_lease(db: Session, task_id: str, owner_id: str, epoch: int) -> bool:
    now = now_local()
    updated = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.task_id == task_id,
            AppDvsTask.execution_owner_id == owner_id,
            AppDvsTask.execution_epoch == epoch,
            AppDvsTask.is_deleted.is_(False),
            AppDvsTask.status == "running",
        )
        .update(
            {
                AppDvsTask.execution_lease_until: _lease_deadline(),
                AppDvsTask.execution_heartbeat_at: now,
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return bool(updated)


def release_lease(db: Session, task_id: str, owner_id: str, epoch: int) -> bool:
    updated = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.task_id == task_id,
            AppDvsTask.execution_owner_id == owner_id,
            AppDvsTask.execution_epoch == epoch,
        )
        .update(
            {
                AppDvsTask.execution_owner_id: None,
                AppDvsTask.execution_lease_until: None,
                AppDvsTask.dispatch_status: None,
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return bool(updated)


def recover_running_task_if_owner(
    db: Session,
    task_id: str,
    owner_id: str,
    epoch: int,
    control_version: int,
    *,
    reason: str = "owner_cleanup",
) -> bool:
    current_row = db.query(AppDvsTask).filter_by(task_id=task_id).first()
    if is_parent_orchestrated_binary_security_task(current_row):
        return False
    updated = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.task_id == task_id,
            AppDvsTask.execution_owner_id == owner_id,
            AppDvsTask.execution_epoch == epoch,
            AppDvsTask.control_version == control_version,
            AppDvsTask.is_deleted.is_(False),
            AppDvsTask.status == "running",
        )
        .update(
            {
                AppDvsTask.status: "pending",
                AppDvsTask.error: None,
                AppDvsTask.result_json: None,
                AppDvsTask.finished_at: None,
                AppDvsTask.latest_abnormal_reason_json: None,
                AppDvsTask.execution_owner_id: None,
                AppDvsTask.execution_lease_until: None,
                AppDvsTask.execution_heartbeat_at: None,
                AppDvsTask.dispatch_status: "pending",
                **_clean_restart_update_fields(
                    current_row,  # type: ignore[arg-type]
                    reason=reason,
                ),
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return bool(updated)


def reclaim_orphaned_running_tasks(db: Session, *, limit: int = 100) -> list[RecoveredRunningTask]:
    now = now_local()
    candidates = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.is_deleted.is_(False),
            AppDvsTask.status == "running",
            (
                (AppDvsTask.execution_owner_id.is_(None))
                | (AppDvsTask.execution_lease_until.is_(None))
                | (AppDvsTask.execution_lease_until < now)
            ),
        )
        .order_by(AppDvsTask.updated_at.asc(), AppDvsTask.id.asc())
        .limit(max(1, int(limit or 100)))
        .all()
    )
    recovered: list[RecoveredRunningTask] = []
    for row in candidates:
        if is_parent_orchestrated_binary_security_task(row):
            continue
        if row.execution_owner_id is None:
            reason = "missing_owner"
        elif row.execution_lease_until is None:
            reason = "missing_lease"
        else:
            reason = "expired_lease"
        fields = {
            AppDvsTask.status: "pending",
            AppDvsTask.error: None,
            AppDvsTask.result_json: None,
            AppDvsTask.finished_at: None,
            AppDvsTask.latest_abnormal_reason_json: None,
            AppDvsTask.execution_owner_id: None,
            AppDvsTask.execution_lease_until: None,
            AppDvsTask.execution_heartbeat_at: None,
            AppDvsTask.dispatch_status: "pending",
        }
        fields.update(_clean_restart_update_fields(row, reason=reason))
        updated = (
            db.query(AppDvsTask)
            .filter(
                AppDvsTask.id == row.id,
                AppDvsTask.is_deleted.is_(False),
                AppDvsTask.status == "running",
            )
            .update(
                fields,
                synchronize_session=False,
            )
        )
        if not updated:
            db.rollback()
            continue
        recovered.append(
            RecoveredRunningTask(
                task_id=row.task_id,
                previous_owner_id=row.execution_owner_id,
                previous_dispatch_status=row.dispatch_status,
                previous_lease_until=row.execution_lease_until,
                reason=reason,
            )
        )
    db.commit()
    return recovered


def still_owner(db: Session, task_id: str, owner_id: str, epoch: int, control_version: int) -> bool:
    row = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.task_id == task_id,
            AppDvsTask.is_deleted.is_(False),
        )
        .first()
    )
    if row is None:
        return False
    return (
        row.execution_owner_id == owner_id
        and int(row.execution_epoch or 0) == int(epoch)
        and int(row.control_version or 0) == int(control_version)
        and row.status in {"pending", "running"}
    )


def load_execution_snapshot(db: Session, task_id: str) -> ExecutionSnapshot | None:
    row = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.task_id == task_id,
            AppDvsTask.is_deleted.is_(False),
        )
        .first()
    )
    if row is None:
        return None
    return ExecutionSnapshot(
        task_id=row.task_id,
        status=str(row.status or ""),
        execution_owner_id=row.execution_owner_id,
        execution_epoch=int(row.execution_epoch or 0),
        control_version=int(row.control_version or 0),
        dispatch_status=row.dispatch_status,
        execution_lease_until=row.execution_lease_until,
        execution_heartbeat_at=row.execution_heartbeat_at,
    )


def begin_execution_if_owner(db: Session, task_id: str, owner_id: str, epoch: int, control_version: int, *, started_at) -> bool:
    updated = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.task_id == task_id,
            AppDvsTask.execution_owner_id == owner_id,
            AppDvsTask.execution_epoch == epoch,
            AppDvsTask.control_version == control_version,
            AppDvsTask.is_deleted.is_(False),
            AppDvsTask.status.in_(["pending", "running"]),
        )
        .update(
            {
                AppDvsTask.status: "running",
                AppDvsTask.dispatch_status: "running",
                AppDvsTask.started_at: started_at,
                AppDvsTask.finished_at: None,
                AppDvsTask.error: None,
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return bool(updated)


def commit_terminal_state_if_owner(
    db: Session,
    task_id: str,
    owner_id: str,
    epoch: int,
    control_version: int,
    *,
    status: str,
    finished_at,
    stages_json: dict,
    result_json: dict | None,
    error: str | None,
) -> bool:
    updated = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.task_id == task_id,
            AppDvsTask.execution_owner_id == owner_id,
            AppDvsTask.execution_epoch == epoch,
            AppDvsTask.control_version == control_version,
            AppDvsTask.is_deleted.is_(False),
            AppDvsTask.status == "running",
        )
        .update(
            {
                AppDvsTask.status: status,
                AppDvsTask.finished_at: finished_at,
                AppDvsTask.stages_json: stages_json,
                AppDvsTask.result_json: result_json,
                AppDvsTask.error: error,
                AppDvsTask.execution_owner_id: None,
                AppDvsTask.execution_lease_until: None,
                AppDvsTask.execution_heartbeat_at: None,
                AppDvsTask.dispatch_status: None,
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return bool(updated)
