"""Worker 集群容量快照 (Celery 驱动, 取代 v1 worker_slot 表)。

v1 的 worker_slot DB 表已废弃; 改用 Celery inspect (ping/active/stats) 获取
活 worker + 在跑任务, 配合 DB 查 pending 队列 + celery_task_id→task 映射。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.time_utils import now_local


@dataclass(frozen=True)
class DfaWorkerActiveJobSnapshot:
    task_id: str
    task_name: str
    status: str
    parent_task_id: str | None
    parent_task_type: str | None
    task_origin_type: str | None
    input_path: str
    started_at: Any
    updated_at: Any
    dispatch_status: str | None
    execution_owner_id: str | None
    execution_lease_until: Any
    execution_heartbeat_at: Any
    mapped: bool = True
    mapping_reason: str = "celery_active"


@dataclass(frozen=True)
class DfaWorkerSnapshot:
    worker_id: str
    host_name: str
    pod_name: str
    pod_ip: str | None
    http_port: int | None
    healthy: bool
    max_concurrent_jobs: int
    running_jobs: int
    available_slots: int
    source: str
    last_heartbeat_at: Any
    pod_created_at: str | None = None
    pod_started_at: str | None = None
    pod_metrics_at: str | None = None
    pod_cpu_usage_millicores: int | None = None
    pod_memory_usage_bytes: int | None = None
    pod_cpu_request_millicores: int | None = None
    pod_memory_request_bytes: int | None = None
    pod_cpu_limit_millicores: int | None = None
    pod_memory_limit_bytes: int | None = None
    active_jobs: list[DfaWorkerActiveJobSnapshot] = field(default_factory=list)
    error: str | None = None


@dataclass(frozen=True)
class DfaClusterCapacitySnapshot:
    worker_count: int
    healthy_workers: int
    stale_workers: int
    total_capacity: int
    running_jobs: int
    queued_jobs: int
    available_slots: int
    updated_at: Any
    workers: list[DfaWorkerSnapshot] = field(default_factory=list)


def build_worker_cluster_snapshot(db, *, project_id: str | None = None):
    """用 Celery inspect 构建集群容量快照。

    db: SQLAlchemy Session (用于查 pending 队列 + celery_task_id→task 映射)
    project_id: 过滤 pending 队列 (worker 活跃任务不过滤, 跨项目)
    """
    from app.celery_app import app as celery_app
    from app.db.models import AppDvsTask

    try:
        inspect = celery_app.control.inspect(timeout=3)
        ping = inspect.ping() or {}
        active = inspect.active() or {}
        stats = inspect.stats() or {}
    except Exception:
        ping, active, stats = {}, {}, {}

    # celery_task_id → task 行映射 (running 任务的 active_jobs 详情)
    active_celery_ids: set[str] = set()
    for _pod, tasks in active.items():
        for t in (tasks or []):
            cid = t.get("id") if isinstance(t, dict) else None
            if cid:
                active_celery_ids.add(cid)
    task_map: dict[str, AppDvsTask] = {}
    if active_celery_ids:
        rows = db.query(AppDvsTask).filter(AppDvsTask.celery_task_id.in_(list(active_celery_ids))).all()
        task_map = {str(r.celery_task_id): r for r in rows if r.celery_task_id}

    # pending 队列 (queued_jobs)
    q = db.query(AppDvsTask).filter(AppDvsTask.status == "pending", AppDvsTask.is_deleted.is_(False))
    if project_id:
        q = q.filter(AppDvsTask.project_id == project_id)
    queued_jobs = int(q.count())

    workers: list[DfaWorkerSnapshot] = []
    total_cap = 0
    running_total = 0
    for worker_name, pong in ping.items():
        healthy = isinstance(pong, dict) and pong.get("ok") == "pong"
        cap = 1
        try:
            cap = int((stats.get(worker_name) or {}).get("pool", {}).get("max-concurrency", 1))
        except Exception:
            cap = 1
        total_cap += cap
        pod_tasks = active.get(worker_name) or []
        running = len(pod_tasks)
        running_total += running
        active_jobs: list[DfaWorkerActiveJobSnapshot] = []
        for t in pod_tasks:
            cid = t.get("id") if isinstance(t, dict) else None
            row = task_map.get(cid) if cid else None
            if row is not None:
                active_jobs.append(DfaWorkerActiveJobSnapshot(
                    task_id=row.task_id, task_name=row.task_name, status=str(row.status or "running"),
                    parent_task_id=row.parent_task_id, parent_task_type=row.parent_task_type,
                    task_origin_type=row.task_origin_type, input_path=row.input_path or "",
                    started_at=row.started_at, updated_at=row.updated_at,
                    dispatch_status=row.dispatch_status, execution_owner_id=row.execution_owner_id,
                    execution_lease_until=row.execution_lease_until,
                    execution_heartbeat_at=row.execution_heartbeat_at,
                ))
        host = str(worker_name).split("@", 1)[-1] if "@" in str(worker_name) else str(worker_name)
        workers.append(DfaWorkerSnapshot(
            worker_id=str(worker_name), host_name=host, pod_name=host, pod_ip=None,
            http_port=8080, healthy=healthy, max_concurrent_jobs=cap, running_jobs=running,
            available_slots=max(0, cap - running), source="celery_inspect",
            last_heartbeat_at=now_local(), active_jobs=active_jobs,
        ))
    workers.sort(key=lambda w: w.worker_id)
    return DfaClusterCapacitySnapshot(
        worker_count=len(workers),
        healthy_workers=sum(1 for w in workers if w.healthy),
        stale_workers=sum(1 for w in workers if not w.healthy),
        total_capacity=total_cap,
        running_jobs=running_total,
        queued_jobs=queued_jobs,
        available_slots=sum(w.available_slots for w in workers),
        updated_at=now_local(),
        workers=workers,
    )


__all__ = [
    "DfaClusterCapacitySnapshot",
    "DfaWorkerActiveJobSnapshot",
    "DfaWorkerSnapshot",
    "build_worker_cluster_snapshot",
]
