"""DVS 调度器侧车: DB→Celery 泵 + stale 扫描。

跑在 scheduler pod (与 Redis 同 pod)。纯 threading, 无 asyncio。
DB 是任务真相, Redis 是临时队列。pump 先在 DB 原子占位再发布，避免重复消息。
worker 死亡由心跳 stale 恢复；已占位但丢失的 pending 消息由独立老化恢复。

入口: python -m app.dispatcher
"""
from __future__ import annotations

import logging
import os
import threading
import time
import json
import uuid
from datetime import timedelta

from sqlalchemy import and_, or_

logger = logging.getLogger("dvs.dispatcher")

PUMP_INTERVAL = float(os.environ.get("DVS_DISPATCHER_PUMP_INTERVAL", "3"))
STALE_INTERVAL = float(os.environ.get("DVS_DISPATCHER_STALE_INTERVAL", "30"))
PUMP_BATCH = int(os.environ.get("DVS_DISPATCHER_PUMP_BATCH", "20"))
STALE_HEARTBEAT_SECONDS = int(os.environ.get("DVS_DISPATCHER_STALE_HEARTBEAT_SECONDS", "60"))  # 60s 无心跳=卡死
PUBLISHING_TIMEOUT_SECONDS = int(os.environ.get("DVS_DISPATCH_PUBLISHING_TIMEOUT_SECONDS", "120"))
DELIVERING_TIMEOUT_SECONDS = int(os.environ.get("DVS_DISPATCH_DELIVERING_TIMEOUT_SECONDS", "120"))
PUBLISHED_RECOVERY_SECONDS = int(os.environ.get("DVS_DISPATCH_PUBLISHED_RECOVERY_SECONDS", "120"))
LEGACY_DISPATCH_RECOVERY_SECONDS = int(os.environ.get("DVS_LEGACY_DISPATCH_RECOVERY_SECONDS", "600"))
DISPATCH_RECOVERY_BATCH = int(os.environ.get("DVS_DISPATCH_RECOVERY_BATCH", "20"))
PUBLISHED_RECOVERY_CONFIRMATIONS = 2
BROKER_EPOCH_KEY = os.environ.get("DVS_BROKER_EPOCH_KEY", "dvs:broker_epoch")
DEBUG_DISPATCH_INTERVAL = float(os.environ.get("DVS_DISPATCHER_DEBUG_INTERVAL", "15"))
DEBUGGER_HOST = os.environ.get("DVS_DEBUGGER_HOST", "secflow-app-dataflow-vuln-scan-debugger")
DEBUGGER_PORT = int(os.environ.get("DVS_DEBUGGER_PORT", "8080"))
# 需调试的终态
_DEBUG_STATUSES = ("failed", "error", "completed_limited")


def _celery_task_ids(messages) -> set[str]:
    """Extract Celery IDs from Kombu Redis message envelopes."""
    task_ids: set[str] = set()
    for raw in messages or ():
        try:
            envelope = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
            message = envelope[0] if isinstance(envelope, list) and envelope else envelope
            if not isinstance(message, dict):
                continue
            headers = message.get("headers") or {}
            properties = message.get("properties") or {}
            task_id = headers.get("id") or properties.get("correlation_id")
            if task_id:
                task_ids.add(str(task_id))
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
    return task_ids


def _current_broker_epoch() -> str:
    """Return the current Redis lifetime marker.

    Redis is colocated with the scheduler and intentionally nonpersistent. Its
    disappearance is therefore authoritative evidence that queued messages
    from the prior epoch were lost.
    """
    import redis

    host = os.environ.get("DVS_SCHEDULER_HOST", "secflow-app-dataflow-vuln-scan-scheduler")
    port = int(os.environ.get("DVS_SCHEDULER_REDIS_PORT", "6379"))
    db = int(os.environ.get("DVS_CELERY_BROKER_DB", "0"))
    client = redis.Redis(
        host=host,
        port=port,
        db=db,
        decode_responses=True,
        socket_connect_timeout=3,
        socket_timeout=3,
    )
    epoch = client.get(BROKER_EPOCH_KEY)
    if epoch:
        return str(epoch)

    candidate = uuid.uuid4().hex
    if client.set(BROKER_EPOCH_KEY, candidate, nx=True):
        logger.warning("initialized DVS broker epoch=%s", candidate)
        return candidate

    epoch = client.get(BROKER_EPOCH_KEY)
    if not epoch:
        raise RuntimeError("could not create or read DVS broker epoch")
    return str(epoch)


class Dispatcher:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._debug_watermark = None  # 已处理终态任务 finished_at 水位线, 之前的不回扫
        self._published_recovery_observations: dict[str, tuple[str, int]] = {}

    def start(self) -> None:
        self._stop.clear()
        self._startup_reset()
        t = threading.Thread(target=self._pump_loop, name="dvs_disp_pump", daemon=True)
        t.start(); self._threads.append(t)
        t = threading.Thread(target=self._stale_loop, name="dvs_disp_stale", daemon=True)
        t.start(); self._threads.append(t)
        # debugger 调度: 扫终态失败任务 → 发给 debugger 分析 (scheduler 职责, 不靠 worker)
        t = threading.Thread(target=self._debug_dispatch_loop, name="dvs_disp_debug", daemon=True)
        t.start(); self._threads.append(t)
        logger.info("Dispatcher started: pump=%ss stale=%ss debug=%ss", PUMP_INTERVAL, STALE_INTERVAL, DEBUG_DISPATCH_INTERVAL)

    def stop(self) -> None:
        self._stop.set()

    # ── 启动恢复: 不无条件清投递标记，避免 rollout 时重新制造重复消息 ──
    def _startup_reset(self) -> None:
        logger.info(
            "dispatcher startup: preserving pending dispatch reservations; "
            "running tasks use heartbeat recovery and lost pending messages use aging recovery"
        )

    # ── 泵: pending(celery_task_id IS NULL) → 发布到 Celery ──
    def _pump_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._pump_once()
            except Exception as exc:
                logger.warning("pump loop error: %s", exc, exc_info=True)
            self._stop.wait(PUMP_INTERVAL)

    def _pump_once(self) -> int:
        from app.db import get_db
        from app.db.models import AppDvsTask
        from app.celery_tasks import run_dvs_task
        from app.time_utils import now_local
        db_gen = get_db()
        db = next(db_gen)
        published = 0
        try:
            broker_epoch = _current_broker_epoch()
            rows = (
                db.query(AppDvsTask.task_id)
                .filter(
                    AppDvsTask.status == "pending",
                    AppDvsTask.is_deleted.is_(False),
                    AppDvsTask.celery_task_id.is_(None),
                )
                .order_by(AppDvsTask.created_at.asc())
                .limit(PUMP_BATCH)
                .all()
            )
            for row in rows:
                tid = row[0] if isinstance(row, tuple) else row.task_id
                dispatch_id = uuid.uuid4().hex
                reserved_at = now_local()
                published_to_broker = False
                try:
                    # A DB compare-and-set, not the preceding SELECT, grants publication rights.
                    # This keeps the behavior safe if a second scheduler is introduced later.
                    reserved = db.query(AppDvsTask).filter(
                        AppDvsTask.task_id == tid,
                        AppDvsTask.status == "pending",
                        AppDvsTask.is_deleted.is_(False),
                        AppDvsTask.celery_task_id.is_(None),
                    ).update(
                        {
                            AppDvsTask.celery_task_id: dispatch_id,
                            AppDvsTask.dispatch_status: "publishing",
                            AppDvsTask.dispatch_reserved_at: reserved_at,
                            AppDvsTask.dispatch_published_at: None,
                            AppDvsTask.dispatch_broker_epoch: broker_epoch,
                            AppDvsTask.dispatch_delivery_started_at: None,
                            AppDvsTask.dispatch_delivery_worker_id: None,
                            AppDvsTask.dispatch_attempts: AppDvsTask.dispatch_attempts + 1,
                            AppDvsTask.last_dispatch_error: None,
                        },
                        synchronize_session=False,
                    )
                    db.commit()
                    if reserved != 1:
                        continue

                    run_dvs_task.apply_async(args=(tid,), task_id=dispatch_id)
                    published_to_broker = True
                    updated = db.query(AppDvsTask).filter(
                        AppDvsTask.task_id == tid,
                        AppDvsTask.celery_task_id == dispatch_id,
                        AppDvsTask.dispatch_status == "publishing",
                    ).update(
                        {
                            AppDvsTask.dispatch_status: "published",
                            AppDvsTask.dispatch_published_at: now_local(),
                            AppDvsTask.last_dispatch_error: None,
                        },
                        synchronize_session=False,
                    )
                    db.commit()
                    published += 1
                    if updated != 1:
                        logger.info(
                            "published task=%s celery_id=%s; task was claimed before publish acknowledgement",
                            tid,
                            dispatch_id,
                        )
                    else:
                        logger.info("published task=%s celery_id=%s", tid, dispatch_id)
                except Exception as exc:
                    db.rollback()
                    if published_to_broker:
                        # Celery may already have accepted the message. Releasing the
                        # DB reservation here would turn an acknowledgement-write
                        # failure into a guaranteed duplicate publication.
                        logger.exception(
                            "publish acknowledgement update failed task=%s celery_id=%s; "
                            "keeping reservation for aging recovery",
                            tid,
                            dispatch_id,
                        )
                        continue
                    # Only release the reservation owned by this publication attempt.
                    try:
                        db.query(AppDvsTask).filter(
                            AppDvsTask.task_id == tid,
                            AppDvsTask.status == "pending",
                            AppDvsTask.celery_task_id == dispatch_id,
                            AppDvsTask.dispatch_status == "publishing",
                        ).update(
                            {
                                AppDvsTask.celery_task_id: None,
                                AppDvsTask.dispatch_status: "pending",
                                AppDvsTask.dispatch_reserved_at: None,
                                AppDvsTask.dispatch_published_at: None,
                                AppDvsTask.dispatch_broker_epoch: None,
                                AppDvsTask.dispatch_delivery_started_at: None,
                                AppDvsTask.dispatch_delivery_worker_id: None,
                                AppDvsTask.last_dispatch_error: str(exc)[:4096],
                            },
                            synchronize_session=False,
                        )
                        db.commit()
                    except Exception:
                        db.rollback()
                        logger.exception(
                            "publish release failed task=%s celery_id=%s; aging recovery will handle it",
                            tid,
                            dispatch_id,
                        )
                    logger.exception(
                        "publish failed task=%s celery_id=%s; reservation released for next pump",
                        tid,
                        dispatch_id,
                    )
                    continue
        finally:
            try:
                next(db_gen)
            except StopIteration:
                logger.debug("dispatcher: pump_once db generator closed")
        return published

    # ── stale 扫描: DB running 但无活 worker 在跑 → 重置 pending 重排 ──
    def _stale_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._stale_once()
            except Exception as exc:
                logger.warning("stale loop error: %s", exc, exc_info=True)
            self._stop.wait(STALE_INTERVAL)

    def _stale_once(self) -> int:
        from app.db import get_db
        from app.db.models import AppDvsTask
        from app.time_utils import now_local
        from app.celery_app import app as celery_app
        from app.service.task_paths import cleanup_task_data
        from app.service.task_events import TaskEventLockTimeout
        # DB lease is the running-worker truth source. Pending-message recovery below
        # uses inspect only to prove whether a published Celery id is still observable.
        # running + 心跳超时(lease 过期) = worker 死了 → revoke 兜底 + 清理 + 回 pending (pump 重发)
        db_gen = get_db()
        db = next(db_gen)
        reset = 0
        try:
            now = now_local()
            rows = db.query(AppDvsTask).filter(
                AppDvsTask.status == "running",
                AppDvsTask.is_deleted.is_(False),
            ).all()
            for row in rows:
                cid = row.celery_task_id
                heartbeat_stale = (
                    row.execution_heartbeat_at is None
                    or (now - row.execution_heartbeat_at).total_seconds() > STALE_HEARTBEAT_SECONDS
                )
                if not heartbeat_stale:
                    continue  # 心跳新鲜 = worker 活着, 不动
                # 心跳陈旧 = worker 死了 (rollout/SIGKILL/崩溃) → revoke 兜底 + 清理 + 回 pending
                if cid:
                    try:
                        celery_app.control.revoke(cid, terminate=True, signal="SIGKILL")
                    except Exception:
                        logger.warning("dispatcher: revoke failed celery_id=%s", cid, exc_info=True)
                # 清理该任务的所有关联数据 (NFS run/+output/, MySQL 任务表, MySQL graph store)
                try:
                    cleanup_task_data(row, reason="stale_reset")
                except TaskEventLockTimeout:
                    logger.exception("stale cleanup_task_data lock timeout; keep task running for next recovery pass: task=%s", row.task_id)
                    continue
                except Exception as exc:
                    logger.warning("stale cleanup_task_data failed: task=%s err=%s", row.task_id, exc)
                row.status = "pending"
                row.celery_task_id = None
                row.execution_owner_id = None
                row.execution_lease_until = None
                row.dispatch_status = None
                row.dispatch_reserved_at = None
                row.dispatch_published_at = None
                row.dispatch_broker_epoch = None
                row.dispatch_delivery_started_at = None
                row.dispatch_delivery_worker_id = None
                reset += 1
                logger.warning("stale reset task=%s celery_id=%s hb_stale=%s (lease expired, worker dead, data cleaned)",
                               row.task_id, cid, heartbeat_stale)
            pending_reset = self._recover_dispatch_handoffs(db, now)
            reset += pending_reset
            if reset:
                db.commit()
        finally:
            try:
                next(db_gen)
            except StopIteration:
                logger.debug("dispatcher: stale_once db generator closed")
        return reset

    def _recover_dispatch_handoffs(self, db, now) -> int:
        """Release only proven-lost dispatch handoffs.

        Published messages normally remain in the broker queue, but a worker
        rollout can move one to Redis ``unacked`` immediately before the worker
        exits. Such a message needs broker evidence plus two stale observations
        before its DB reservation is released.
        """
        from app.db.models import AppDvsTask

        try:
            broker_epoch = _current_broker_epoch()
        except Exception:
            logger.exception("dispatch handoff recovery skipped: broker epoch unavailable")
            return 0

        publishing_cutoff = now - timedelta(seconds=PUBLISHING_TIMEOUT_SECONDS)
        delivering_cutoff = now - timedelta(seconds=DELIVERING_TIMEOUT_SECONDS)
        published_cutoff = now - timedelta(seconds=PUBLISHED_RECOVERY_SECONDS)
        legacy_cutoff = now - timedelta(seconds=LEGACY_DISPATCH_RECOVERY_SECONDS)
        epoch_lost = and_(
            AppDvsTask.dispatch_broker_epoch.is_not(None),
            AppDvsTask.dispatch_broker_epoch != broker_epoch,
        )
        publishing_aged = and_(
            AppDvsTask.dispatch_status == "publishing",
            AppDvsTask.dispatch_reserved_at.is_not(None),
            AppDvsTask.dispatch_reserved_at < publishing_cutoff,
        )
        delivering_aged = and_(
            AppDvsTask.dispatch_status == "delivering",
            AppDvsTask.dispatch_delivery_started_at.is_not(None),
            AppDvsTask.dispatch_delivery_started_at < delivering_cutoff,
        )
        published_aged = and_(
            AppDvsTask.dispatch_status == "published",
            AppDvsTask.dispatch_published_at.is_not(None),
            AppDvsTask.dispatch_published_at < published_cutoff,
        )
        legacy_aged = and_(
            AppDvsTask.dispatch_reserved_at.is_(None),
            AppDvsTask.dispatch_broker_epoch.is_(None),
            AppDvsTask.dispatch_delivery_started_at.is_(None),
            AppDvsTask.updated_at < legacy_cutoff,
        )
        legacy_published_aged = and_(
            AppDvsTask.dispatch_status == "published",
            AppDvsTask.dispatch_broker_epoch.is_(None),
            AppDvsTask.dispatch_published_at.is_not(None),
            AppDvsTask.dispatch_published_at < legacy_cutoff,
        )
        rows = (
            db.query(AppDvsTask)
            .filter(
                AppDvsTask.status == "pending",
                AppDvsTask.is_deleted.is_(False),
                AppDvsTask.celery_task_id.is_not(None),
                AppDvsTask.execution_owner_id.is_(None),
                AppDvsTask.execution_lease_until.is_(None),
                or_(
                    epoch_lost,
                    publishing_aged,
                    delivering_aged,
                    published_aged,
                    legacy_aged,
                    legacy_published_aged,
                ),
            )
            .order_by(
                AppDvsTask.dispatch_reserved_at.asc(),
                AppDvsTask.dispatch_delivery_started_at.asc(),
                AppDvsTask.updated_at.asc(),
            )
            .limit(DISPATCH_RECOVERY_BATCH)
            .all()
        )
        if not rows:
            return 0

        published_dispatch_ids = {
            str(row.celery_task_id)
            for row in rows
            if (
                row.dispatch_status == "published"
                and row.dispatch_published_at is not None
                and row.dispatch_published_at < published_cutoff
                and (row.dispatch_broker_epoch == broker_epoch or row.dispatch_broker_epoch is None)
            )
        }
        published_locations = self._observe_published_dispatches(published_dispatch_ids)
        released = 0
        for row in rows:
            dispatch_id = str(row.celery_task_id or "").strip()
            if not dispatch_id:
                continue
            if row.dispatch_broker_epoch and row.dispatch_broker_epoch != broker_epoch:
                reason = "broker epoch changed; queued message was lost; scheduled for retry"
                state_condition = epoch_lost
            elif (
                row.dispatch_status == "publishing"
                and row.dispatch_reserved_at is not None
                and row.dispatch_reserved_at < publishing_cutoff
            ):
                reason = "publishing handoff timed out; scheduled for retry"
                state_condition = publishing_aged
            elif (
                row.dispatch_status == "delivering"
                and row.dispatch_delivery_started_at is not None
                and row.dispatch_delivery_started_at < delivering_cutoff
            ):
                reason = "delivering handoff timed out; scheduled for retry"
                state_condition = delivering_aged
            elif (
                row.dispatch_status == "published"
                and row.dispatch_published_at is not None
                and row.dispatch_published_at < published_cutoff
            ):
                is_legacy = row.dispatch_broker_epoch is None
                if is_legacy and row.dispatch_published_at >= legacy_cutoff:
                    self._published_recovery_observations.pop(dispatch_id, None)
                    continue
                location = published_locations.get(dispatch_id, "unknown")
                if location in {"queue", "active", "reserved", "unknown"}:
                    self._published_recovery_observations.pop(dispatch_id, None)
                    continue
                if not self._confirm_published_recovery(dispatch_id, location):
                    continue
                reason = f"published handoff stale in broker ({location}); scheduled for retry"
                state_condition = legacy_published_aged if is_legacy else published_aged
            elif (
                row.dispatch_reserved_at is None
                and row.dispatch_broker_epoch is None
                and row.dispatch_delivery_started_at is None
                and row.updated_at < legacy_cutoff
            ):
                reason = "legacy dispatch recovery; scheduled for retry"
                state_condition = legacy_aged
            else:
                continue

            # Match the old token and reason state in the WHERE clause so an
            # overlapping claim/retry can never erase a newer reservation.
            conditions = [
                AppDvsTask.task_id == row.task_id,
                AppDvsTask.status == "pending",
                AppDvsTask.is_deleted.is_(False),
                AppDvsTask.celery_task_id == dispatch_id,
                AppDvsTask.execution_owner_id.is_(None),
                AppDvsTask.execution_lease_until.is_(None),
                state_condition,
            ]
            changed = db.query(AppDvsTask).filter(
                *conditions,
            ).update(
                {
                    AppDvsTask.celery_task_id: None,
                    AppDvsTask.dispatch_status: "pending",
                    AppDvsTask.dispatch_reserved_at: None,
                    AppDvsTask.dispatch_published_at: None,
                    AppDvsTask.dispatch_broker_epoch: None,
                    AppDvsTask.dispatch_delivery_started_at: None,
                    AppDvsTask.dispatch_delivery_worker_id: None,
                    AppDvsTask.last_dispatch_error: reason,
                },
                synchronize_session=False,
            )
            if changed:
                released += 1
                logger.warning(
                    "dispatch handoff recovered task=%s celery_id=%s reason=%s",
                    row.task_id,
                    dispatch_id,
                    reason,
                )
        return released

    def _observe_published_dispatches(self, dispatch_ids: set[str]) -> dict[str, str]:
        """Classify published messages with one read-only broker observation."""
        if not dispatch_ids:
            return {}
        try:
            import redis

            host = os.environ.get("DVS_SCHEDULER_HOST", "secflow-app-dataflow-vuln-scan-scheduler")
            port = int(os.environ.get("DVS_SCHEDULER_REDIS_PORT", "6379"))
            db = int(os.environ.get("DVS_CELERY_BROKER_DB", "0"))
            client = redis.Redis(
                host=host,
                port=port,
                db=db,
                decode_responses=True,
                socket_connect_timeout=3,
                socket_timeout=3,
            )
            ready_ids = _celery_task_ids(client.lrange("dvs", 0, -1))
            unacked_ids = _celery_task_ids(client.hvals("unacked"))

            from app.celery_app import app as celery_app

            inspect = celery_app.control.inspect(timeout=3)
            if not inspect.ping():
                return {dispatch_id: "unknown" for dispatch_id in dispatch_ids}
            active = inspect.active()
            reserved = inspect.reserved()
            if active is None or reserved is None:
                return {dispatch_id: "unknown" for dispatch_id in dispatch_ids}
            active_ids = {
                str(item.get("id"))
                for tasks in active.values()
                for item in (tasks or [])
                if isinstance(item, dict) and item.get("id")
            }
            reserved_ids = {
                str(item.get("id"))
                for tasks in reserved.values()
                for item in (tasks or [])
                if isinstance(item, dict) and item.get("id")
            }
            locations: dict[str, str] = {}
            for dispatch_id in dispatch_ids:
                if dispatch_id in active_ids:
                    locations[dispatch_id] = "active"
                elif dispatch_id in reserved_ids:
                    locations[dispatch_id] = "reserved"
                elif dispatch_id in ready_ids:
                    locations[dispatch_id] = "queue"
                elif dispatch_id in unacked_ids:
                    locations[dispatch_id] = "unacked"
                else:
                    locations[dispatch_id] = "missing"
            return locations
        except Exception:
            logger.warning("published broker observation failed celery_ids=%s", sorted(dispatch_ids), exc_info=True)
            return {dispatch_id: "unknown" for dispatch_id in dispatch_ids}

    def _confirm_published_recovery(self, dispatch_id: str, location: str) -> bool:
        if location not in {"unacked", "missing"}:
            self._published_recovery_observations.pop(dispatch_id, None)
            return False
        previous = self._published_recovery_observations.get(dispatch_id)
        count = (previous[1] + 1) if previous and previous[0] == location else 1
        self._published_recovery_observations[dispatch_id] = (location, count)
        if count < PUBLISHED_RECOVERY_CONFIRMATIONS:
            logger.info(
                "published handoff recovery pending confirmation task_celery_id=%s location=%s confirmation=%s/%s",
                dispatch_id,
                location,
                count,
                PUBLISHED_RECOVERY_CONFIRMATIONS,
            )
            return False
        self._published_recovery_observations.pop(dispatch_id, None)
        return True

    # ── debugger 调度: 扫终态失败任务 → 发给 debugger (scheduler 职责) ──
    def _debug_dispatch_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._debug_dispatch_once()
            except Exception as exc:
                logger.warning("debug dispatch loop error: %s", exc, exc_info=True)
            self._stop.wait(DEBUG_DISPATCH_INTERVAL)

    def _debug_dispatch_once(self) -> int:
        """实时触发: 处理本次轮询新出现的 failed/error/completed_limited 终态任务 → POST 给 debugger。

        用 finished_at 水位线: 只处理 watermark 之后新结束的任务, 不回扫历史错误。
        首次运行设水位线=当前 max(finished_at), 跳过所有历史 (不处理旧错误)。
        debugger 端 /internal/failure-debug 幂等 (已有报告则不重复)。
        """
        import urllib.request
        from app.db import get_db
        from app.db.models import AppDvsTask, AppDvsFailureDebug
        db_gen = get_db()
        db = next(db_gen)
        dispatched = 0
        try:
            # 查 watermark 之后的终态任务 (新结束的)
            q = db.query(AppDvsTask).filter(
                AppDvsTask.status.in_(_DEBUG_STATUSES),
                AppDvsTask.is_deleted.is_(False),
                AppDvsTask.finished_at.is_not(None),
            )
            if self._debug_watermark is not None:
                q = q.filter(AppDvsTask.finished_at > self._debug_watermark)
            rows = q.order_by(AppDvsTask.finished_at.asc()).limit(50).all()
            if not rows:
                return 0
            # 首次运行: 设水位线=本批次 max(finished_at), 不处理历史 (本批次也跳过)
            # 但本批次是新于 None watermark 的, 首次应跳过 → 设水位线后返回
            if self._debug_watermark is None:
                self._debug_watermark = max(r.finished_at for r in rows)
                logger.info("debug dispatch: 首次水位线=%s, 跳过历史终态任务", self._debug_watermark)
                return 0
            # 已有报告的 task_id (仅查本批次, 幂等)
            batch_ids = [r.task_id for r in rows]
            existing = {r.task_id for r in db.query(AppDvsFailureDebug).filter(
                AppDvsFailureDebug.task_id.in_(batch_ids)).all()}
            for row in rows:
                if row.task_id in existing:
                    continue
                url = f"http://{DEBUGGER_HOST}:{DEBUGGER_PORT}/api/app/dataflow-vuln-scan/internal/failure-debug"
                payload = json.dumps({"task_id": row.task_id}).encode()
                try:
                    req = urllib.request.Request(url, data=payload, method="POST",
                                                 headers={"Content-Type": "application/json"})
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        if 200 <= resp.status < 300:
                            dispatched += 1
                            logger.info("debug dispatched task=%s (status=%s)", row.task_id, row.status)
                            existing.add(row.task_id)
                except Exception as exc:
                    logger.warning("debug dispatch failed task=%s: %s", row.task_id, exc)
            # 推进水位线
            self._debug_watermark = max(r.finished_at for r in rows)
        finally:
            try:
                next(db_gen)
            except StopIteration:
                logger.debug("dispatcher: debug_dispatch db generator closed")
        return dispatched


_dispatcher: Dispatcher | None = None


def get_dispatcher() -> Dispatcher:
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = Dispatcher()
    return _dispatcher


def main() -> None:
    import signal as _sig
    from app.logging_utils import configure_container_logging
    configure_container_logging("dvs-dispatcher")
    # 确保 DB 初始化 (celery_app._ensure_db 幂等; 本进程无 runtime_bootstrap)
    from app.celery_app import _ensure_db
    _ensure_db()
    disp = get_dispatcher()
    disp.start()
    def _handle(signum, frame):
        disp.stop()
    _sig.signal(_sig.SIGTERM, _handle)
    _sig.signal(_sig.SIGINT, _handle)
    # keep alive
    while not disp._stop.is_set():
        time.sleep(5)


if __name__ == "__main__":
    main()
