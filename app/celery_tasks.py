"""DVS Celery 任务定义。

run_dvs_task(task_id): Celery worker prefork 子进程执行单个 DVS 任务。
  - os.setsid() 新进程组, 便于 revoke 时 killpg 杀 pi 全树
  - claim_specific_task 设 owner/epoch (防 acks_late 重投双跑)
  - 复用 task_service._execute_task 跑引擎 + 终态提交
  - task_revoked 信号 → killpg 兜底
"""
from __future__ import annotations

import logging
import os
import signal
import threading

from celery import current_task
from celery.signals import task_revoked

from app.celery_app import app
from app.runtime_context import WORKER_ID

logger = logging.getLogger("dvs.celery_tasks")

# celery_task_id → 进程组 id (供 revoke 时 killpg)
_PGID_LOCK = threading.Lock()
_PGID: dict[str, int] = {}


@app.task(bind=True, name="app.celery_tasks.run_dvs_task", acks_late=True)
def run_dvs_task(self, task_id: str) -> dict:
    """执行一个 DVS 任务 (Celery prefork 子进程)。"""
    celery_id = self.request.id
    # 新进程组: pi/node 子进程都进本组, revoke 时 killpg 一锅端
    try:
        os.setsid()
    except OSError as e:
        logger.debug("os.setsid failed (already session leader?): %s", e)
    try:
        pgid = os.getpgid(0)
    except OSError as e:
        logger.debug("os.getpgid(0) failed, fallback self pid: %s", e)
        pgid = os.getpid()
    with _PGID_LOCK:
        _PGID[celery_id] = pgid
    logger.info("run_dvs_task start task=%s celery_id=%s pgid=%s pod=%s", task_id, celery_id, pgid, WORKER_ID)

    from app.db import get_db
    from app.service.execution_coordinator import claim_specific_task
    from app.service.task_service import get_task_service

    db_gen = get_db()
    db = next(db_gen)
    claimed = None
    try:
        claimed = claim_specific_task(db, WORKER_ID, task_id, celery_task_id=celery_id)
    finally:
        try:
            next(db_gen)
        except StopIteration as e:
            logger.debug("db_gen exhausted: %s", e)

    if claimed is None:
        # 已被别的活 worker 认领 (running+新鲜) 或已终态 → 本消息作废 (ack 掉, 不执行)
        logger.info("run_dvs_task skip (not claimable) task=%s", task_id)
        _PGID_LOCK.pop(celery_id, None) if False else None
        with _PGID_LOCK:
            _PGID.pop(celery_id, None)
        return {"task_id": task_id, "status": "skipped"}

    # restart 语义: 清空上一轮产物 (run/output), 保留 input + JSONL 事件时间线, 从头跑
    # 每次 (重投/restart/首次) 都清: 首次无产物=no-op, 重投清掉旧 dataflow-v2/sessions 避免续跑
    _clean_task_artifacts(task_id)

    try:
        svc = get_task_service()
        svc._execute_task(task_id, claimed.epoch, claimed.control_version)
        return {"task_id": task_id, "status": "done"}
    finally:
        with _PGID_LOCK:
            _PGID.pop(celery_id, None)
        _cleanup_pi_processes()


def _cleanup_pi_processes() -> None:
    """任务结束后 best-effort 清理残留 pi/node 进程 (本进程组内)。"""
    try:
        from app.service.task_service import cleanup_worker_runtime_processes
        cleanup_worker_runtime_processes(logger.warning, label="celery_task_done")
    except Exception:
        logger.debug("pi cleanup failed", exc_info=True)


def _clean_task_artifacts(task_id: str) -> None:
    """清空任务 run/output 产物，保留 input 与 output/events.jsonl 审计时间线。

    每次 (重投/restart/首次) 执行前都清: 首次无产物=no-op; 重投时清掉旧
    run/dataflow-v2 (functions.db/sessions) + output + DB stages_json(前端分析日志回放缓冲),
    确保从头跑而非续跑，前端 /logs 也重置。
    """
    import shutil
    from pathlib import Path
    from app.db import get_db
    from app.db.models import AppDvsTask
    from app.config import OUTPUT_DIR
    from app.service.task_events import TaskEventLockTimeout
    try:
        db_gen = get_db()
        db = next(db_gen)
        try:
            row = db.query(AppDvsTask).filter_by(task_id=task_id).first()
            if row is None:
                return
            # 1. 清 DB 回放缓冲 (前端 /logs 读 stages_json), 保留 JSONL 审计时间线
            row.stages_json = None
            row.result_json = None
            row.latest_abnormal_reason_json = None
            # 1b. 重置漏洞计数 (避免旧 run 的计数残留)
            row.vuln_total_count = -1
            row.vuln_reported_count = -1
            row.vuln_unreported_count = -1
            db.commit()
            # 2. 清文件产物 run/output (保留 input 和 output/events.jsonl)
            task_root = Path(row.output_path or OUTPUT_DIR) / task_id
            if task_root.is_dir():
                for child_name in ("run", "output"):
                    child = task_root / child_name
                    if child.exists():
                        try:
                            if child_name == "output":
                                from app.service.task_paths import _remove_output_preserving_task_events
                                _remove_output_preserving_task_events(task_root, child, reason="worker_preflight")
                            else:
                                shutil.rmtree(child)
                                logger.info("cleaned task artifacts: %s/%s", task_id, child_name)
                        except TaskEventLockTimeout:
                            logger.exception("clean task artifact %s lock timeout task=%s", child_name, task_id)
                            raise
                        except Exception as exc:
                            logger.warning("clean task artifact %s failed: %s", child_name, exc)
        finally:
            try:
                next(db_gen)
            except StopIteration as e:
                logger.debug("db_gen exhausted: %s", e)
    except TaskEventLockTimeout:
        logger.exception("_clean_task_artifacts failed after event lock timeout task=%s", task_id)
        raise
    except Exception:
        logger.warning("_clean_task_artifacts failed task=%s", task_id, exc_info=True)


@task_revoked.connect
def _on_revoked(sender, request, **kwargs):
    """cancel/revoke 时杀整组 pi/node (等价 EA _kill_group)。"""
    celery_id = getattr(request, "id", None) if request else None
    if not celery_id:
        return
    with _PGID_LOCK:
        pgid = _PGID.pop(celery_id, None)
    if pgid is None:
        return
    logger.info("task_revoked celery_id=%s pgid=%s → killpg SIGKILL", celery_id, pgid)
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError as e:
            logger.debug("killpg process gone: %s", e)
            return
        except OSError as e:
            logger.debug("killpg OSError: %s", e)
            return
        if sig == signal.SIGTERM:
            import time
            time.sleep(0.5)
