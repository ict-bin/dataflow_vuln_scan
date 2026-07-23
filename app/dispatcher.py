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
import json
from typing import Any

logger = logging.getLogger("dvs.dispatcher")

PUMP_INTERVAL = float(os.environ.get("DVS_DISPATCHER_PUMP_INTERVAL", "3"))
STALE_INTERVAL = float(os.environ.get("DVS_DISPATCHER_STALE_INTERVAL", "30"))
PUMP_BATCH = int(os.environ.get("DVS_DISPATCHER_PUMP_BATCH", "20"))
STALE_HEARTBEAT_SECONDS = int(os.environ.get("DVS_DISPATCHER_STALE_HEARTBEAT_SECONDS", "60"))  # 60s 无心跳=卡死
PENDING_CELERY_STALE_SECONDS = int(os.environ.get("DVS_PENDING_CELERY_STALE_SECONDS", "600"))  # 10min 未消费=重投
INSPECT_TIMEOUT = float(os.environ.get("DVS_DISPATCHER_INSPECT_TIMEOUT", "3"))
DEBUG_DISPATCH_INTERVAL = float(os.environ.get("DVS_DISPATCHER_DEBUG_INTERVAL", "15"))
DEBUGGER_HOST = os.environ.get("DVS_DEBUGGER_HOST", "secflow-app-dataflow-vuln-scan-debugger")
DEBUGGER_PORT = int(os.environ.get("DVS_DEBUGGER_PORT", "8080"))
# 需调试的终态
_DEBUG_STATUSES = ("failed", "error", "completed_limited")


def _collect_known_celery_ids(payload: Any) -> set[str]:
    known_ids: set[str] = set()
    for tasks in (payload or {}).values():
        for task in (tasks or []):
            cid = task.get("id") if isinstance(task, dict) else None
            if cid:
                known_ids.add(str(cid))
    return known_ids


class Dispatcher:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._debug_watermark = None  # 已处理终态任务 finished_at 水位线, 之前的不回扫

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
                db.query(AppDvsTask.task_id)
                .filter(
                    AppDvsTask.status == "pending",
                    AppDvsTask.is_deleted.is_(False),
                )
                .order_by(AppDvsTask.created_at.asc())
                .limit(PUMP_BATCH)
                .all()
            )
            for row in rows:
                tid = row[0] if isinstance(row, tuple) else row.task_id
                try:
                    ar = run_dvs_task.delay(tid)
                    db.query(AppDvsTask).filter(AppDvsTask.task_id == tid).update({"celery_task_id": ar.id})
                    db.commit()
                    published += 1
                    logger.info("published task=%s celery_id=%s", tid, ar.id)
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
        from app.service.task_paths import cleanup_task_data
        # 1. 取所有活 worker 已知的 celery_id
        # DB lease 为死亡判定真相源 (不查 celery inspect, 避免 inspect 超时/worker 不可达误判):
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
                        pass
                # 清理该任务的所有关联数据 (NFS run/+output/, MySQL 任务表, MySQL graph store)
                try:
                    cleanup_task_data(row, reason="stale_reset")
                except Exception as exc:
                    logger.warning("stale cleanup_task_data failed: task=%s err=%s", row.task_id, exc)
                row.status = "pending"
                row.celery_task_id = None
                row.execution_owner_id = None
                row.execution_lease_until = None
                row.dispatch_status = None
                reset += 1
                logger.warning("stale reset task=%s celery_id=%s hb_stale=%s (lease expired, worker dead, data cleaned)",
                               row.task_id, cid, heartbeat_stale)
            # pending 任务: pump 每 3s 重发 (无 celery_id 门), 不需要 stale 恢复
            if reset:
                db.commit()
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass
        return reset

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
                pass
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
