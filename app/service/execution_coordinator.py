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


def _task_cfg_dict(raw: Any) -> dict[str, Any]:
    return dict(raw) if isinstance(raw, dict) else {}


def _with_clean_restart_flag(
    raw: Any,
    *,
    reason: str,
    previous_owner_id: str | None,
    previous_epoch: int,
) -> dict[str, Any]:
    cfg = _task_cfg_dict(raw)
    cfg["_force_clean_restart"] = True
    cfg["_restart_reason"] = reason
    cfg["_restart_previous_owner_id"] = previous_owner_id
    cfg["_restart_previous_epoch"] = int(previous_epoch or 0)
    cfg["_restart_marked_at"] = now_local().isoformat()
    return cfg


def _with_auto_recovery_flag(
    raw: Any,
    *,
    reason: str,
    previous_owner_id: str | None,
    previous_epoch: int,
) -> dict[str, Any]:
    cfg = _task_cfg_dict(raw)
    cfg["_auto_recovered_pending"] = True
    cfg["_auto_recovered_reason"] = reason
    cfg["_auto_recovered_previous_owner_id"] = previous_owner_id
    cfg["_auto_recovered_previous_epoch"] = int(previous_epoch or 0)
    cfg["_auto_recovered_marked_at"] = now_local().isoformat()
    return cfg


def is_parent_orchestrated_binary_security_task(row: AppDvsTask | None) -> bool:
    if row is None:
        return False
    if str(getattr(row, "task_origin_type", "") or "").strip() != "binary_security":
        return False
    parent_task_id = str(getattr(row, "parent_task_id", "") or "").strip()
    parent_stage_item_id = str(getattr(row, "parent_stage_item_id", "") or "").strip()
    return bool(parent_task_id and parent_stage_item_id)


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


def claim_specific_task(
    db: Session,
    owner_id: str,
    task_id: str,
    *,
    celery_task_id: str | None = None,
    allow_pending: bool = True,
) -> ClaimedTask | None:
    """Celery worker 收到 LAUNCH 后按 task_id 认领 (非竞争性)。

    与 v1 claim (已删) 的区别: 不扫表竞争, 只认领指定 task_id。
    用于 Celery 消费: dispatcher 已把该 task 路由到本 worker, 这里设 owner/epoch/lease。
    当传入 celery_task_id 时，它必须与当前 DB 投递 ID 一致；旧 Redis 消息不能
    认领已经重新投递的任务。没有 Celery ID 的内部兼容调用保持原有语义。
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
    if celery_task_id is not None and candidate.celery_task_id != celery_task_id:
        return None
    status = str(candidate.status or "pending")
    if status == "pending" and allow_pending:
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
        AppDvsTask.started_at: now,  # 每次 claim (含 restart/重投) 重置开始时间
        AppDvsTask.finished_at: None,
        AppDvsTask.error: None,
    }
    if expected_status == "running":
        if is_parent_orchestrated_binary_security_task(candidate):
            update_fields[AppDvsTask.status] = "running"
        else:
            # 孤儿重抢: 回 pending, begin_execution_if_owner 会再设 running
            update_fields[AppDvsTask.status] = "pending"
            update_fields.update(
                _clean_restart_update_fields(candidate, reason="claim_expired_running")
            )
    updated = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.id == candidate.id,
            AppDvsTask.is_deleted.is_(False),
            AppDvsTask.status == expected_status,
            AppDvsTask.celery_task_id == celery_task_id
            if celery_task_id is not None else AppDvsTask.id.is_not(None),
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


def begin_delivery_handoff(
    db: Session,
    owner_id: str,
    task_id: str,
    celery_task_id: str,
) -> bool:
    """Record that a worker received the current dispatch before it claims it.

    This tiny CAS makes the worker-restart handoff window observable. A stale
    ``delivering`` row can be safely re-dispatched without treating normal queue
    wait in ``published`` as an error.
    """
    now = now_local()
    updated = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.task_id == task_id,
            AppDvsTask.status == "pending",
            AppDvsTask.is_deleted.is_(False),
            AppDvsTask.celery_task_id == celery_task_id,
            AppDvsTask.dispatch_status.in_(["publishing", "published"]),
            AppDvsTask.execution_owner_id.is_(None),
            AppDvsTask.execution_lease_until.is_(None),
        )
        .update(
            {
                AppDvsTask.dispatch_status: "delivering",
                AppDvsTask.dispatch_delivery_started_at: now,
                AppDvsTask.dispatch_delivery_worker_id: owner_id,
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return bool(updated)


def claim_one_runnable_task(db: Session, owner_id: str) -> ClaimedTask | None:
    now = now_local()
    candidates = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.is_deleted.is_(False),
            AppDvsTask.status.in_(["pending", "running"]),
        )
        .order_by(AppDvsTask.created_at.asc(), AppDvsTask.id.asc())
        .all()
    )
    for row in candidates:
        status = str(row.status or "pending")
        if status == "pending":
            lease_until = row.execution_lease_until
            if str(row.execution_owner_id or "").strip() and lease_until is not None and lease_until >= now:
                continue
            claimed = claim_specific_task(db, owner_id, str(row.task_id))
            if claimed is not None:
                return claimed
            continue
        lease_until = row.execution_lease_until
        if lease_until is None or lease_until < now:
            claimed = claim_specific_task(db, owner_id, str(row.task_id))
            if claimed is not None:
                return claimed
    return None


def reclaim_orphaned_running_tasks(db: Session) -> list[RecoveredRunningTask]:
    now = now_local()
    rows = (
        db.query(AppDvsTask)
        .filter(
            AppDvsTask.is_deleted.is_(False),
            AppDvsTask.status == "running",
        )
        .all()
    )
    recovered: list[RecoveredRunningTask] = []
    for row in rows:
        if is_parent_orchestrated_binary_security_task(row):
            continue
        reason = ""
        if not str(row.execution_owner_id or "").strip():
            reason = "missing_owner"
        elif row.execution_lease_until is None or row.execution_lease_until < now:
            reason = "expired_lease"
        if not reason:
            continue
        updated = (
            db.query(AppDvsTask)
            .filter(
                AppDvsTask.id == row.id,
                AppDvsTask.is_deleted.is_(False),
                AppDvsTask.status == "running",
            )
            .update(
                {
                    AppDvsTask.status: "pending",
                    AppDvsTask.execution_owner_id: None,
                    AppDvsTask.execution_lease_until: None,
                    AppDvsTask.execution_heartbeat_at: None,
                    AppDvsTask.dispatch_status: "pending",
                    AppDvsTask.celery_task_id: None,
                    AppDvsTask.dispatch_reserved_at: None,
                    AppDvsTask.dispatch_published_at: None,
                    AppDvsTask.dispatch_broker_epoch: None,
                    AppDvsTask.dispatch_delivery_started_at: None,
                    AppDvsTask.dispatch_delivery_worker_id: None,
                    AppDvsTask.last_dispatch_error: None,
                    **_clean_restart_update_fields(row, reason=reason),
                },
                synchronize_session=False,
            )
        )
        if updated:
            recovered.append(
                RecoveredRunningTask(
                    task_id=str(row.task_id),
                    previous_owner_id=row.execution_owner_id,
                    previous_dispatch_status=row.dispatch_status,
                    previous_lease_until=row.execution_lease_until,
                    reason=reason,
                )
            )
    db.commit()
    return recovered


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
                AppDvsTask.celery_task_id: None,
                AppDvsTask.dispatch_reserved_at: None,
                AppDvsTask.dispatch_published_at: None,
                AppDvsTask.dispatch_broker_epoch: None,
                AppDvsTask.dispatch_delivery_started_at: None,
                AppDvsTask.dispatch_delivery_worker_id: None,
                AppDvsTask.last_dispatch_error: None,
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
