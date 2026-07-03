"""DVS 调度器侧车: DB→Celery 泵 + 启动重置 + stale 扫描。

跑在 scheduler pod (与 Redis 同 pod)。纯 threading, 无 asyncio。
DB 是任务真相, Redis 是临时队列; Redis 丢/重启 → _startup_reset 全 running→pending + 重新发布。
worker 死亡 → _stale_loop 用 inspect.active() 找孤儿 running → 重置重排。

入口: python -m app.dispatcher
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

logger = logging.getLogger("dvs.dispatcher")

PUMP_INTERVAL = float(os.environ.get("DVS_DISPATCHER_PUMP_INTERVAL", "3"))
STALE_INTERVAL = float(os.environ.get("DVS_DISPATCHER_STALE_INTERVAL", "30"))
PUMP_BATCH = int(os.environ.get("DVS_DISPATCHER_PUMP_BATCH", "20"))
STALE_HEARTBEAT_SECONDS = int(os.environ.get("DVS_DISPATCHER_STALE_HEARTBEAT_SECONDS", "600"))  # 10min 无心跳=卡死
INSPECT_TIMEOUT = float(os.environ.get("DVS_DISPATCHER_INSPECT_TIMEOUT", "3"))


class Dispatcher:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        self._stop.clear()
        self._startup_reset()
        t = threading.Thread(target=self._pump_loop, name="dvs_disp_pump", daemon=True)
        t.start(); self._threads.append(t)
        t = threading.Thread(target=self._stale_loop, name="dvs_disp_stale", daemon=True)
        t.start(); self._threads.append(t)
        logger.info("Dispatcher started: pump=%ss stale=%ss", PUMP_INTERVAL, STALE_INTERVAL)

    def stop(self) -> None:
        self._stop.set()

    # ── 启动重置: Redis 丢队列 → running 全回 pending + pending 的 stale celery_id 清掉 (重发) ──
    def _startup_reset(self) -> None:
        from app.db import get_db
        from app.db.models import AppDvsTask
        from app.time_utils import now_local
        db_gen = get_db()
        db = next(db_gen)
        try:
            # running → pending (孤儿任务重排)
            n_running = db.query(AppDvsTask).filter(
                AppDvsTask.status == "running",
                AppDvsTask.is_deleted.is_(False),
            ).update(
                {AppDvsTask.status: "pending",
                 AppDvsTask.celery_task_id: None,
                 AppDvsTask.execution_owner_id: None,
                 AppDvsTask.execution_lease_until: None,
                 AppDvsTask.dispatch_status: None},
                synchronize_session=False,
            )
            # pending 但已有 celery_id (Redis 丢消息) → 清掉让 pump 重发
            n_pending = db.query(AppDvsTask).filter(
                AppDvsTask.status == "pending",
                AppDvsTask.is_deleted.is_(False),
                AppDvsTask.celery_task_id.is_not(None),
            ).update(
                {AppDvsTask.celery_task_id: None,
                 AppDvsTask.execution_owner_id: None,
                 AppDvsTask.execution_lease_until: None,
                 AppDvsTask.dispatch_status: None},
                synchronize_session=False,
            )
            db.commit()
            if n_running or n_pending:
                logger.warning("startup_reset: %d running→pending, %d pending stale celery_id cleared (redis queue rebuilt)",
                               n_running, n_pending)
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass

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
        db_gen = get_db()
        db = next(db_gen)
        published = 0
        try:
            rows = (
                db.query(AppDvsTask)
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
                try:
                    ar = run_dvs_task.delay(row.task_id)
                    row.celery_task_id = ar.id
                    db.commit()
                    published += 1
                    logger.info("published task=%s celery_id=%s", row.task_id, ar.id)
                except Exception as exc:
                    logger.warning("publish failed task=%s: %s (retry next loop)", row.task_id, exc)
                    db.rollback()
                    break  # Redis 不可达, 下轮再试
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass
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
        # 1. 取所有活 worker 在跑的 celery_id
        active_ids: set[str] = set()
        try:
            inspect = celery_app.control.inspect(timeout=INSPECT_TIMEOUT)
            active = inspect.active() or {}
            for _pod, tasks in active.items():
                for t in (tasks or []):
                    cid = t.get("id") if isinstance(t, dict) else None
                    if cid:
                        active_ids.add(cid)
        except Exception as exc:
            logger.warning("inspect.active failed: %s (skip this round)", exc)
            return 0
        # 2. DB running 任务: celery_id 不在 active 且 心跳超时 → 孤儿/卡死
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
                in_active = cid is not None and cid in active_ids
                heartbeat_stale = (
                    row.execution_heartbeat_at is None
                    or (now - row.execution_heartbeat_at).total_seconds() > STALE_HEARTBEAT_SECONDS
                )
                if in_active and not heartbeat_stale:
                    continue  # 正常在跑
                # 孤儿 (不在 active) 或 卡死 (在 active 但无心跳) → 重置
                # 先 revoke 兜底杀残留进程 (best-effort)
                if cid:
                    try:
                        celery_app.control.revoke(cid, terminate=True, signal="SIGKILL")
                    except Exception:
                        pass
                row.status = "pending"
                row.celery_task_id = None
                row.execution_owner_id = None
                row.execution_lease_until = None
                row.dispatch_status = None
                reset += 1
                logger.warning("stale reset task=%s celery_id=%s in_active=%s hb_stale=%s",
                               row.task_id, cid, in_active, heartbeat_stale)
            if reset:
                db.commit()
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass
        return reset


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
