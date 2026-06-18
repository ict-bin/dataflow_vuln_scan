"""Task management service for secflow-app-dataflow-vuln-scan.

Bridges the FastAPI management layer with the Orchestrator engine.
Each task is persisted in MySQL and executed asynchronously.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import threading
import time as _time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from sqlalchemy.orm import Session, load_only
from sqlalchemy import func
from sqlalchemy.orm.attributes import flag_modified

from app.copy_utils import safe_copy2
from app.config import build_task_config
from app.db import is_retryable_db_error
from app.db.models import AppDvsTask, AppDvsTaskEvent
from app.logging_utils import log_event
from app.models import SwarmEvent, TaskStatus
from app.orchestrator import Orchestrator
from app.runtime_context import HEARTBEAT_INTERVAL_SECONDS, WORKER_ID, MAX_LOCAL_RUNNING_TASKS
from app.service.execution_coordinator import (
    _auto_recovery_payload,
    _clear_auto_recovery_flag,
    begin_execution_if_owner,
    claim_one_runnable_task,
    commit_terminal_state_if_owner,
    load_execution_snapshot,
    recover_running_task_if_owner,
    release_lease,
    renew_lease,
    still_owner,
    _mark_row_clean_restart,
)
from app.agent_process import cleanup_orphan_pi_processes, cleanup_task_agent_processes, cleanup_worker_runtime_processes
from app.time_utils import isoformat_local, now_local
from .task_events import _record_task_event, _task_event_dedupe_key, _build_task_event_response
from .task_paths import _task_root, _task_run_root, _task_epoch_run_root, _task_result_path, _latest_epoch_run_root, _epoch_label_from_path
from .task_session import _write_json_atomic, _safe_session_file, _parse_session_file, _build_task_session_catalog
from .task_result import (
    _load_task_result_json, _write_task_result_json, _build_entry_analysis_context,
    _persist_terminal_failure, _input_manifest_path, _path_metadata,
    _validate_fileserver_path, _normalize_source_file_for_root, _write_input_manifest,
    _lightweight_result_json, _token_usage_dict, _merge_usage, _token_total,
    _safe_eval_key, _build_evaluation_payload, _write_task_evaluation_files,
    _origin_payload, _load_svc_config, _load_svc_config_from_db,
    _write_models_json_from_db, generate_prompt_from_path, _flush_stages,
    SERVICE_CONFIG_PATH,
)

logger = logging.getLogger("dvs.task_service")

TASK_EVENT_RENEW_INTERVAL_SECONDS = max(60, HEARTBEAT_INTERVAL_SECONDS * 6)
EXECUTION_SUPERVISOR_INTERVAL_SECONDS = float(os.environ.get("DVS_EXECUTION_SUPERVISOR_INTERVAL_SECONDS", "5"))
EXECUTION_NO_PROGRESS_SECONDS = float(os.environ.get("DVS_EXECUTION_NO_PROGRESS_SECONDS", "1800"))
IDLE_PI_REAPER_ENABLED = os.environ.get("DVS_IDLE_PI_REAPER_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
IDLE_PI_REAPER_INTERVAL_SECONDS = max(5, int(os.environ.get("DVS_IDLE_PI_REAPER_INTERVAL_SECONDS", "30")))
IDLE_PI_REAPER_CONFIRM_ROUNDS = max(1, int(os.environ.get("DVS_IDLE_PI_REAPER_CONFIRM_ROUNDS", "2")))

DB_RETRY_ATTEMPTS = max(3, int(os.environ.get("DVS_DB_RETRY_ATTEMPTS", "3")))
DB_RETRY_BASE_DELAY_SECONDS = float(os.environ.get("DVS_DB_RETRY_BASE_DELAY_SECONDS", "1"))

_RUNNING_TASK_LOCK = threading.RLock()
_running_tasks: dict[str, "_RunningTaskContext"] = {}


def _restart_payload(row: AppDvsTask, *, previous_status: str, previous_error: str | None, previous_epoch: int, reason: str) -> dict[str, Any]:
    return {
        "reason": reason,
        "previous_status": previous_status,
        "previous_error": previous_error,
        "execution_epoch_before": previous_epoch,
        "execution_epoch_after": int(row.execution_epoch or 0),
        "control_version": int(row.control_version or 0),
    }
_PI_RUNTIME_ROLES = ("workers", "judges")
_PI_COMPACTION_SETTINGS = {
    "defaultThinkingLevel": "off",
    "compaction": {
        "enabled": True,
        "reserveTokens": 8192,
        "keepRecentTokens": 50000,
    },
}


def _task_agent_key(task_config_json: dict | None) -> dict | None:
    if not isinstance(task_config_json, dict):
        return None
    payload = task_config_json.get("agent_task_key")
    return payload if isinstance(payload, dict) else None


def _merge_pi_settings(base_settings: dict[str, Any] | None) -> dict[str, Any]:
    payload = dict(base_settings) if isinstance(base_settings, dict) else {}
    payload["defaultThinkingLevel"] = _PI_COMPACTION_SETTINGS["defaultThinkingLevel"]
    compaction = payload.get("compaction")
    merged_compaction = dict(compaction) if isinstance(compaction, dict) else {}
    merged_compaction.update(_PI_COMPACTION_SETTINGS["compaction"])
    payload["compaction"] = merged_compaction
    return payload


def _collect_role_models(role_config: Any) -> set[str]:
    models: set[str] = set()
    default_model = str(getattr(role_config, "default_model", "") or "").strip()
    if default_model:
        models.add(default_model)
    for agent in getattr(role_config, "agents", []) or []:
        model = str(getattr(agent, "model", "") or "").strip()
        if model:
            models.add(model)
    stage_models = getattr(role_config, "stage_models", None)
    if isinstance(stage_models, dict):
        for value in stage_models.values():
            model = str(value or "").strip()
            if model:
                models.add(model)
    return models


def _model_identifier_variants(model_name: str) -> set[str]:
    raw = str(model_name or "").strip()
    lowered = raw.lower()
    variants = {raw, lowered}
    if "/" in raw:
        suffix = raw.split("/", 1)[1].strip()
        variants.update({suffix, suffix.lower()})
    return {item for item in variants if item}


def _build_role_models_json(
    base_models: dict[str, Any] | None,
    *,
    role_config: Any,
    secret: str,
) -> dict[str, Any]:
    payload = json.loads(json.dumps(base_models if isinstance(base_models, dict) else {"providers": {}}))
    providers = payload.get("providers")
    if not isinstance(providers, dict):
        payload["providers"] = {}
        providers = payload["providers"]
    allowed_models = _collect_role_models(role_config)
    allowed_variants: set[str] = set()
    for model_name in allowed_models:
        allowed_variants.update(_model_identifier_variants(model_name))
    filtered_providers: dict[str, Any] = {}
    for provider_key, provider_cfg in providers.items():
        if not isinstance(provider_cfg, dict):
            continue
        provider_copy = dict(provider_cfg)
        models = provider_cfg.get("models")
        if isinstance(models, list):
            kept_models = []
            for item in models:
                if not isinstance(item, dict):
                    continue
                model_id = str(item.get("id") or item.get("name") or "").strip()
                if not model_id:
                    continue
                model_variants = _model_identifier_variants(model_id)
                provider_qualified = {f"{provider_key}/{variant}" for variant in model_variants}
                if allowed_variants.intersection(model_variants.union(provider_qualified)):
                    kept_models.append(dict(item))
            provider_copy["models"] = kept_models
            if not kept_models:
                continue
        if secret:
            provider_copy["apiKey"] = secret
        filtered_providers[provider_key] = provider_copy
    payload["providers"] = filtered_providers
    return payload


def _materialize_task_pi_runtime(*, task_root: str, agent_task_key: dict | None, cfg: Any) -> tuple[dict[str, str], str]:
    task_pi_dirs: dict[str, str] = {}
    if not task_root:
        return task_pi_dirs, "task_scoped"
    secret = str((agent_task_key or {}).get("secret") or "").strip()
    global_pi_dir = Path(os.environ.get("PI_CODING_AGENT_DIR", "/root/.pi/agent"))
    models_src = Path(os.environ.get("PI_MODELS_JSON") or (global_pi_dir / "models.json"))
    settings_src = global_pi_dir / "settings.json"
    base_models = _read_json_file(models_src)
    base_settings = _read_json_file(settings_src)
    merged_settings = _merge_pi_settings(base_settings)
    auth_payload = {
        "agent_task_key_id": str((agent_task_key or {}).get("id") or "").strip() or None,
        "agent_task_key_name": str((agent_task_key or {}).get("name") or "").strip() or None,
        "agent_task_key_prefix": str((agent_task_key or {}).get("prefix") or "").strip() or None,
        "agent_task_key_secret": secret or None,
        "agent_task_key_source": str((agent_task_key or {}).get("source") or "").strip() or "default",
    }
    runtime_root = Path(task_root) / ".pi" / "agents"
    runtime_root.mkdir(parents=True, exist_ok=True)
    for role_name in _PI_RUNTIME_ROLES:
        role_dir = runtime_root / role_name
        role_dir.mkdir(parents=True, exist_ok=True)
        role_config = getattr(cfg, role_name, None)
        role_models = _build_role_models_json(base_models, role_config=role_config, secret=secret)
        (role_dir / "models.json").write_text(
            json.dumps(role_models, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (role_dir / "settings.json").write_text(
            json.dumps(merged_settings, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (role_dir / "auth.json").write_text(
            json.dumps(auth_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        task_pi_dirs[role_name] = str(role_dir)
    return task_pi_dirs, "task_scoped"


def _inject_api_key(models_path: Path, secret: str) -> None:
    """将 models.json 中所有 provider 的 apiKey 替换为任务级密钥。"""
    try:
        data = json.loads(models_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return
    providers = data.get("providers") if isinstance(data, dict) else None
    if not isinstance(providers, dict):
        return
    injected = 0
    for _provider_key, provider_cfg in providers.items():
        if isinstance(provider_cfg, dict):
            provider_cfg["apiKey"] = secret
            injected += 1
    if injected > 0:
        models_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info(
            "injected task-scoped apiKey into %d providers in %s",
            injected, models_path,
        )


def _read_json_file(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        if not path.is_file():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _normalize_agent_auth_snapshot(agent_task_key: dict | None) -> dict[str, Any] | None:
    if not isinstance(agent_task_key, dict):
        return None
    payload = {
        "agent_task_key_id": str(agent_task_key.get("id") or "").strip() or None,
        "agent_task_key_name": str(agent_task_key.get("name") or "").strip() or None,
        "agent_task_key_prefix": str(agent_task_key.get("prefix") or "").strip() or None,
        "agent_task_key_secret": str(agent_task_key.get("secret") or "").strip() or None,
        "agent_task_key_source": str(agent_task_key.get("source") or "").strip() or None,
    }
    return payload if any(payload.values()) else None


def _build_role_runtime_summary(
    role_name: str,
    role_config: Any,
    *,
    models_json: dict[str, Any] | None,
    settings_json: dict[str, Any] | None,
) -> dict[str, Any]:
    agents = []
    for index, agent in enumerate(getattr(role_config, "agents", []) or []):
        if hasattr(agent, "model_dump"):
            payload = agent.model_dump(mode="json")
        elif isinstance(agent, dict):
            payload = dict(agent)
        else:
            payload = {"model": str(getattr(agent, "model", "") or "").strip() or None}
        payload.setdefault("index", index)
        agents.append(payload)
    summary = {
        "role_name": role_name,
        "default_model": str(getattr(role_config, "default_model", "") or "").strip() or None,
        "default_tools": list(getattr(role_config, "default_tools", []) or []),
        "default_thinking_level": str(getattr(role_config, "default_thinking_level", "") or "").strip() or None,
        "system_prompt_dir": str(getattr(role_config, "system_prompt_dir", "") or "").strip() or None,
        "agent_count": len(agents),
        "agents": agents,
        "models_json": models_json,
        "settings_json": settings_json,
    }
    stage_models = getattr(role_config, "stage_models", None)
    if isinstance(stage_models, dict) and stage_models:
        summary["stage_models"] = dict(stage_models)
    return summary


def _build_runtime_config_snapshots(
    *,
    cfg: Any,
    agent_task_key: dict | None,
    task_pi_dirs: dict[str, str] | None,
    agent_runtime_mode: str,
) -> tuple[dict[str, Any] | None, dict[str, Any], dict[str, Any], dict[str, Any]]:
    frozen_at = isoformat_local(now_local()) or datetime.utcnow().isoformat()
    agent_auth_json = _normalize_agent_auth_snapshot(agent_task_key)
    role_config_snapshot = {
        "workers": cfg.workers.model_dump(mode="json"),
        "judges": cfg.judges.model_dump(mode="json"),
    }
    global_pi = Path(os.environ.get("PI_CODING_AGENT_DIR", "/root/.pi/agent"))
    models_json = _read_json_file(global_pi / "models.json")
    settings_json = _read_json_file(global_pi / "settings.json")
    runtime_files = {"models_json": models_json, "settings_json": settings_json}
    provider_runtime_summary: dict[str, Any] = {}
    llm_roles: dict[str, Any] = {}
    for role_name in _PI_RUNTIME_ROLES:
        role_config = getattr(cfg, role_name)
        provider_runtime_summary[role_name] = _build_role_runtime_summary(
            role_name,
            role_config,
            models_json=models_json,
            settings_json=settings_json,
        )
        llm_roles[role_name] = {
            "config": role_config_snapshot.get(role_name),
            "runtime_files": models_json is not None,
        }
    llm_binding_snapshot = {
        "version": 1,
        "frozen_at": frozen_at,
        "agent_runtime_mode": agent_runtime_mode,
        "agent_task_key": {
            "id": str((agent_task_key or {}).get("id") or "").strip() or None,
            "name": str((agent_task_key or {}).get("name") or "").strip() or None,
            "prefix": str((agent_task_key or {}).get("prefix") or "").strip() or None,
            "secret": str((agent_task_key or {}).get("secret") or "").strip() or None,
            "source": str((agent_task_key or {}).get("source") or "").strip() or None,
        } if isinstance(agent_task_key, dict) else None,
        "runtime_files": runtime_files,
        "roles": llm_roles,
    }
    return agent_auth_json, role_config_snapshot, provider_runtime_summary, llm_binding_snapshot


def _task_config_snapshot_payload(task_config_json: dict | None) -> dict[str, object]:
    task_config = task_config_json if isinstance(task_config_json, dict) else {}
    return {
        "agent_auth_json": task_config.get("agent_auth_json") if isinstance(task_config.get("agent_auth_json"), dict) else None,
        "role_config_snapshot": task_config.get("role_config_snapshot") if isinstance(task_config.get("role_config_snapshot"), dict) else None,
        "provider_runtime_summary": task_config.get("provider_runtime_summary") if isinstance(task_config.get("provider_runtime_summary"), dict) else None,
        "llm_binding_snapshot": task_config.get("llm_binding_snapshot") if isinstance(task_config.get("llm_binding_snapshot"), dict) else None,
    }


def _agent_runtime_mode_from_task_config(task_config_json: dict | None) -> str:
    task_config = task_config_json if isinstance(task_config_json, dict) else {}
    llm_binding_snapshot = task_config.get("llm_binding_snapshot")
    if isinstance(llm_binding_snapshot, dict):
        candidate = str(llm_binding_snapshot.get("agent_runtime_mode") or "").strip()
        if candidate:
            return candidate
    return "task_scoped"


def _run_db_write_with_retries(label: str, operation, *, attempts: int | None = None):
    """Run a DB write operation with fresh sessions on transient MySQL disconnects.

    The operation receives a newly-created SQLAlchemy Session and must commit/rollback as needed.
    At least three attempts are made for retryable DBAPI errors (MySQL 2006/2013/etc.).
    """
    from app.db import get_db as _get_db

    max_attempts = max(3, int(attempts or DB_RETRY_ATTEMPTS))
    last_exc: BaseException | None = None
    for attempt in range(1, max_attempts + 1):
        gen = _get_db()
        db: Session = next(gen)
        try:
            return operation(db, attempt)
        except Exception as exc:
            last_exc = exc
            try:
                db.rollback()
            except Exception as _e:
                logger.warning("unexpected error in task_service.py: %s", _e, exc_info=True)
            retryable = is_retryable_db_error(exc)
            logger.warning(
                "%s DB operation failed attempt=%s/%s retryable=%s error=%s",
                label,
                attempt,
                max_attempts,
                retryable,
                exc,
                exc_info=True,
            )
            if not retryable or attempt >= max_attempts:
                raise
            _time.sleep(DB_RETRY_BASE_DELAY_SECONDS * attempt)
        finally:
            try:
                next(gen)
            except StopIteration:
                pass
    if last_exc is not None:
        raise last_exc
    return None


@dataclass
class _RunningTaskContext:
    execution_thread: threading.Thread | None = None
    lease_thread: threading.Thread | None = None
    orch: Orchestrator | None = None
    task_root: str | None = None
    run_root: str | None = None
    epoch: int | None = None
    control_version: int | None = None
    started_at: float = field(default_factory=_time.time)
    last_progress_at: float = field(default_factory=_time.time)
    last_lease_heartbeat_at: float = 0.0
    last_state_sync_at: float = 0.0
    last_lease_error: str | None = None
    termination_reason: str | None = None
    cancel_requested: threading.Event = field(default_factory=threading.Event)
    lease_stop_requested: threading.Event = field(default_factory=threading.Event)

    def execution_alive(self) -> bool:
        return bool(self.execution_thread and self.execution_thread.is_alive())

    def lease_alive(self) -> bool:
        return bool(self.lease_thread and self.lease_thread.is_alive())


_running_task_contexts: dict[str, _RunningTaskContext] = {}

_TASK_LIST_SORT_COLUMNS = {
    "created_at": AppDvsTask.created_at,
    "updated_at": AppDvsTask.updated_at,
    "started_at": AppDvsTask.started_at,
    "finished_at": AppDvsTask.finished_at,
    "status": AppDvsTask.status,
    "task_name": AppDvsTask.task_name,
}


def _active_local_task(task_id: str) -> _RunningTaskContext | None:
    with _RUNNING_TASK_LOCK:
        ctx = _running_tasks.get(task_id)
        if ctx is None:
            return None
        if not ctx.execution_alive():
            return None
        return ctx


def _register_running_task_context(
    task_id: str,
    *,
    execution_thread: threading.Thread | None = None,
    lease_thread: threading.Thread | None = None,
    orch: Orchestrator | None = None,
    task_root: str | None = None,
    run_root: str | None = None,
    epoch: int | None = None,
    control_version: int | None = None,
) -> _RunningTaskContext:
    with _RUNNING_TASK_LOCK:
        ctx = _running_task_contexts.get(task_id) or _RunningTaskContext()
    if execution_thread is not None:
        ctx.execution_thread = execution_thread
    if lease_thread is not None:
        ctx.lease_thread = lease_thread
    if orch is not None:
        ctx.orch = orch
    if task_root is not None:
        ctx.task_root = task_root
    if run_root is not None:
        ctx.run_root = run_root
    if epoch is not None:
        ctx.epoch = epoch
    if control_version is not None:
        ctx.control_version = control_version
    ctx.last_state_sync_at = _time.time()
    with _RUNNING_TASK_LOCK:
        _running_task_contexts[task_id] = ctx
        _running_tasks[task_id] = ctx
    return ctx


def _get_running_task_context(task_id: str) -> _RunningTaskContext | None:
    with _RUNNING_TASK_LOCK:
        return _running_task_contexts.get(task_id)


def _unregister_running_task_context(task_id: str) -> None:
    with _RUNNING_TASK_LOCK:
        _running_task_contexts.pop(task_id, None)
        _running_tasks.pop(task_id, None)


def _mark_task_progress(task_id: str) -> None:
    with _RUNNING_TASK_LOCK:
        ctx = _running_task_contexts.get(task_id)
        if ctx is not None:
            now = _time.time()
            ctx.last_progress_at = now
            ctx.last_state_sync_at = now


def _start_task_lease_heartbeat(
    task_id: str,
    *,
    epoch: int,
    control_version: int,
    on_lease_lost,
) -> threading.Thread:
    def _worker() -> None:
        from app.db import get_db
        from app.metrics import observe_local_event

        last_timeline_renew_at = 0.0
        while True:
            ctx = _get_running_task_context(task_id)
            if ctx is None or ctx.lease_stop_requested.is_set():
                return
            if ctx.cancel_requested.wait(timeout=HEARTBEAT_INTERVAL_SECONDS):
                return
            _hb_gen = get_db()
            _hb_db: Session = next(_hb_gen)
            try:
                ok = renew_lease(_hb_db, task_id, WORKER_ID, epoch)
                current_ts = _time.time()
                if ctx is not None:
                    ctx.last_lease_heartbeat_at = current_ts
                    ctx.last_state_sync_at = current_ts
                    ctx.last_lease_error = None
                if not ok or not still_owner(_hb_db, task_id, WORKER_ID, epoch, control_version):
                    observe_local_event("lease_renew", "failed")
                    if ctx is not None:
                        ctx.last_lease_error = "lease_lost"
                        ctx.termination_reason = "lease_lost"
                    log_event(
                        logger,
                        logging.WARNING,
                        "lease lost during threaded heartbeat, aborting task",
                        event="task_lease_lost",
                        task_id=task_id,
                        owner_id=WORKER_ID,
                        epoch=epoch,
                        control_version=control_version,
                    )
                    lost_row = _hb_db.query(AppDvsTask).filter_by(task_id=task_id).first()
                    if lost_row is not None:
                        _record_task_event(
                            _hb_db,
                            row=lost_row,
                            event_type="task_lease_lost",
                            message="任务心跳续租失败，租约已丢失",
                            level="warning",
                            status=lost_row.status,
                            worker_id=WORKER_ID,
                            execution_owner_id=WORKER_ID,
                            execution_epoch=epoch,
                            control_version=control_version,
                            payload={"owner_id": WORKER_ID, "epoch": epoch, "control_version": control_version},
                        )
                        _hb_db.commit()
                    on_lease_lost()
                    return
                observe_local_event("lease_renew", "success")
                if current_ts - last_timeline_renew_at >= TASK_EVENT_RENEW_INTERVAL_SECONDS:
                    lease_row = _hb_db.query(AppDvsTask).filter_by(task_id=task_id).first()
                    if lease_row is not None:
                        _record_task_event(
                            _hb_db,
                            row=lease_row,
                            event_type="task_lease_renewed",
                            message="任务租约续约成功",
                            status=lease_row.status,
                            worker_id=WORKER_ID,
                            execution_owner_id=WORKER_ID,
                            execution_epoch=epoch,
                            control_version=control_version,
                            payload={
                                "owner_id": WORKER_ID,
                                "epoch": epoch,
                                "control_version": control_version,
                                "lease_until": isoformat_local(lease_row.execution_lease_until),
                            },
                        )
                        _hb_db.commit()
                        last_timeline_renew_at = current_ts
            except Exception as exc:
                observe_local_event("lease_renew", "thread_error")
                if ctx is not None:
                    ctx.last_lease_error = str(exc)
            finally:
                try:
                    next(_hb_gen)
                except StopIteration:
                    pass

    thread = threading.Thread(target=_worker, name=f"dvs_lease_{task_id}", daemon=True)
    thread.start()
    return thread


def _run_execute_task_in_thread(service: "TaskService", task_id: str, epoch: int, control_version: int) -> None:
    service._execute_task(task_id, epoch, control_version)


def _recover_running_task_for_cleanup(
    db: Session,
    *,
    task_id: str,
    owner_id: str,
    epoch: int,
    control_version: int,
    reason: str,
) -> bool:
    recovered = recover_running_task_if_owner(
        db,
        task_id,
        owner_id,
        epoch,
        control_version,
        reason=reason,
    )
    if not recovered:
        return False
    row = db.query(AppDvsTask).filter_by(task_id=task_id).first()
    if row is not None:
        _record_task_event(
            db,
            row=row,
            event_type="task_running_recovered",
            message="任务在 worker 非正常收尾后已回退为 pending 并等待重排",
            level="warning",
            status=row.status,
            worker_id=owner_id,
            execution_owner_id=owner_id,
            execution_epoch=epoch,
            control_version=control_version,
            dispatch_status=row.dispatch_status,
            payload={
                "owner_id": owner_id,
                "epoch": epoch,
                "control_version": control_version,
                "recovery_reason": reason,
            },
        )
        _record_task_event(
            db,
            row=row,
            event_type="task_requeued_after_orphaned_running",
            message="任务已重新进入调度队列",
            level="warning",
            status=row.status,
            worker_id=owner_id,
            execution_owner_id=owner_id,
            execution_epoch=epoch,
            control_version=control_version,
            dispatch_status=row.dispatch_status,
            payload={
                "owner_id": owner_id,
                "epoch": epoch,
                "control_version": control_version,
                "recovery_reason": reason,
            },
        )
        db.commit()
    return True


def _abnormal_evidence(key: str, label: str, value: object) -> dict | None:
    text = str(value or "").strip()
    if not text:
        return None
    return {"key": key, "label": label, "value": text}


def _task_abnormal_reason(row: AppDvsTask) -> dict | None:
    status = str(row.status or "")
    if status not in {"failed", "error", "cancelled"}:
        return None
    if isinstance(row.latest_abnormal_reason_json, dict):
        return dict(row.latest_abnormal_reason_json)
    result_json = _load_task_result_json(row) or {}
    events = (row.stages_json or {}).get("events") if isinstance(row.stages_json, dict) else []
    latest_event = next((event for event in reversed(events or []) if isinstance(event, dict) and (event.get("error") or event.get("event"))), None)
    message = str(
        row.error
        or result_json.get("error")
        or result_json.get("completion_reason")
        or (latest_event or {}).get("error")
        or (latest_event or {}).get("message")
        or ""
    ).strip()
    if status == "cancelled":
        code, category, title = "user_cancelled", "cancel", "任务已取消"
    elif "lease" in message.lower() or "租约" in message:
        code, category, title = "lease_lost", "runtime", "任务租约丢失"
    elif "dispatch" in message.lower() or "调度" in message:
        code, category, title = "dispatch_failed", "runtime", "调度失败"
    elif "timeout" in message.lower() or "dependency" in message.lower():
        code, category, title = "dependency_unavailable", "runtime", "依赖不可用"
    else:
        code, category, title = ("unknown_abnormal" if status == "error" else "orchestration_failed"), "orchestration", "任务异常结束"
    return {
        "is_abnormal": True,
        "category": category,
        "code": code,
        "title": title,
        "message": message or "任务以非正常状态结束。",
        "terminal": True,
        "source_layer": "task",
        "status": status,
        "service": "dataflow-analysis",
        "stage_name": str((latest_event or {}).get("stage") or (latest_event or {}).get("stage_name") or "").strip() or None,
        "item_key": None,
        "downstream_task_id": None,
        "downstream_service": None,
        "first_seen_at": isoformat_local(row.started_at),
        "last_seen_at": isoformat_local(row.finished_at or row.updated_at),
        "evidence": [
            item for item in [
                _abnormal_evidence("status", "状态", row.status),
                _abnormal_evidence("dispatch_status", "调度状态", row.dispatch_status),
                _abnormal_evidence("error", "原始错误", row.error),
            ] if item is not None
        ],
        "recommended_action": "查看 result_json、stages_json 和执行租约状态，确认是调度问题还是运行阶段中断。",
        "related_event_ids": [],
    }


def _abnormal_reason_event(reason: dict, *, event_id: str | None = None) -> dict:
    timestamp = str(reason.get("last_seen_at") or isoformat_local(now_local()) or "")
    return {
        "ts": _time.time(),
        "timestamp": timestamp,
        "event": "abnormal_reason_recorded",
        "type": "abnormal_reason_recorded",
        "event_id": event_id or f"abn-{uuid.uuid4().hex[:12]}",
        "message": str(reason.get("title") or "任务异常结束"),
        "level": "warning" if str(reason.get("status") or "") == "cancelled" else "error",
        "data": {"reason": dict(reason)},
    }


def _abnormal_reason_history(row: AppDvsTask) -> list[dict]:
    stages_json = row.stages_json if isinstance(row.stages_json, dict) else {}
    events = stages_json.get("events") if isinstance(stages_json.get("events"), list) else []
    history: list[dict] = []
    for event in reversed(events):
        if not isinstance(event, dict) or event.get("event") != "abnormal_reason_recorded":
            continue
        payload = event.get("data") if isinstance(event.get("data"), dict) else {}
        reason = payload.get("reason") if isinstance(payload.get("reason"), dict) else None
        if not isinstance(reason, dict):
            continue
        history.append(
            {
                "event_id": event.get("event_id"),
                "created_at": event.get("timestamp") or event.get("ts"),
                "reason": reason,
            }
        )
        if len(history) >= 10:
            break
    return history


def _sync_task_abnormal_reason(row: AppDvsTask) -> tuple[dict | None, bool]:
    reason = _task_abnormal_reason(row)
    next_payload = dict(reason) if isinstance(reason, dict) else None
    changed = row.latest_abnormal_reason_json != next_payload
    if changed:
        row.latest_abnormal_reason_json = next_payload
        flag_modified(row, "latest_abnormal_reason_json")
    return next_payload, changed


def _record_abnormal_reason(row: AppDvsTask, reason: dict | None, *, changed: bool) -> None:
    if not changed or not isinstance(reason, dict):
        return
    payload = row.stages_json if isinstance(row.stages_json, dict) else {}
    events = list(payload.get("events") or [])
    events.append(_abnormal_reason_event(reason))
    row.stages_json = {**payload, "events": events, "final": bool(payload.get("final", False))}
    flag_modified(row, "stages_json")


def _record_abnormal_reason_timeline(db: Session, row: AppDvsTask, reason: dict | None, *, changed: bool) -> None:
    if not changed or not isinstance(reason, dict):
        return
    _record_task_event(
        db,
        row=row,
        event_type="abnormal_reason_recorded",
        message=str(reason.get("title") or "任务异常结束"),
        level="warning" if str(reason.get("status") or "") == "cancelled" else "error",
        status=str(reason.get("status") or row.status or ""),
        payload={"reason": reason},
        dedupe_key=_task_event_dedupe_key(
            row.task_id,
            "abnormal_reason_recorded",
            str(reason.get("status") or row.status or ""),
            str(reason.get("message") or reason.get("title") or ""),
            epoch=int(row.execution_epoch or 0),
        ),
    )




class TaskService:
    def __init__(self) -> None:
        self._supervisor_thread: threading.Thread | None = None
        self._supervisor_stop = threading.Event()
        self._last_supervisor_run_at = 0.0
        self._last_supervisor_error: str | None = None
        self._idle_pi_reaper_thread: threading.Thread | None = None
        self._idle_pi_reaper_stop = threading.Event()
        self._last_idle_pi_reaper_at = 0.0
        self._last_idle_pi_reaper_killed_count = 0
        self._idle_pi_reaper_runs_total = 0
        self._idle_pi_reaper_killed_groups_total = 0
        self._idle_pi_reaper_failures_total = 0
        self._idle_pi_reaper_idle_streak = 0

    def local_running_task_count(self) -> int:
        with _RUNNING_TASK_LOCK:
            return sum(1 for ctx in _running_tasks.values() if ctx.execution_alive())

    def running_task_snapshot(self) -> list[dict[str, object]]:
        with _RUNNING_TASK_LOCK:
            rows = []
            for task_id, ctx in _running_tasks.items():
                rows.append(
                    {
                        "task_id": task_id,
                        "execution_alive": ctx.execution_alive(),
                        "lease_alive": ctx.lease_alive(),
                        "last_progress_at": ctx.last_progress_at,
                        "last_lease_heartbeat_at": ctx.last_lease_heartbeat_at,
                        "last_state_sync_at": ctx.last_state_sync_at,
                        "termination_reason": ctx.termination_reason,
                        "cancel_requested": ctx.cancel_requested.is_set(),
                        "epoch": ctx.epoch,
                        "control_version": ctx.control_version,
                    }
                )
            return rows

    def request_cancel(self, task_id: str, *, reason: str) -> bool:
        ctx = _get_running_task_context(task_id)
        if ctx is None:
            return False
        ctx.termination_reason = reason
        ctx.cancel_requested.set()
        if ctx.orch is not None:
            ctx.orch.abort()
        return True

    def supervisor_status(self) -> dict[str, object]:
        return {
            "thread_alive": bool(self._supervisor_thread and self._supervisor_thread.is_alive()),
            "last_run_at": self._last_supervisor_run_at,
            "last_error": self._last_supervisor_error,
        }

    def idle_pi_reaper_status(self) -> dict[str, object]:
        return {
            "thread_alive": bool(self._idle_pi_reaper_thread and self._idle_pi_reaper_thread.is_alive()),
            "last_idle_pi_reaper_at": self._last_idle_pi_reaper_at or None,
            "last_idle_pi_reaper_killed_count": self._last_idle_pi_reaper_killed_count,
            "idle_pi_reaper_runs_total": self._idle_pi_reaper_runs_total,
            "idle_pi_reaper_killed_groups_total": self._idle_pi_reaper_killed_groups_total,
            "idle_pi_reaper_failures_total": self._idle_pi_reaper_failures_total,
            "idle_pi_reaper_idle_streak": self._idle_pi_reaper_idle_streak,
        }

    def start_supervisor(self) -> None:
        if self._supervisor_thread and self._supervisor_thread.is_alive():
            return
        self._supervisor_stop = threading.Event()
        self._idle_pi_reaper_stop = threading.Event()

        def _worker() -> None:
            from app.db import get_db
            while not self._supervisor_stop.wait(EXECUTION_SUPERVISOR_INTERVAL_SECONDS):
                self._last_supervisor_run_at = _time.time()
                try:
                    with _RUNNING_TASK_LOCK:
                        contexts = list(_running_task_contexts.items())
                    for task_id, ctx in contexts:
                        if ctx.execution_alive():
                            db_gen = get_db()
                            db: Session = next(db_gen)
                            try:
                                snapshot = load_execution_snapshot(db, task_id)
                                if (
                                    snapshot is None
                                    or snapshot.status == "cancelled"
                                    or snapshot.execution_owner_id != WORKER_ID
                                    or int(snapshot.execution_epoch or 0) != int(ctx.epoch or 0)
                                    or int(snapshot.control_version or 0) != int(ctx.control_version or 0)
                                ):
                                    ctx.termination_reason = "control_plane_state_changed"
                                    ctx.cancel_requested.set()
                                    if ctx.orch is not None:
                                        ctx.orch.abort()
                                    continue
                            finally:
                                try:
                                    next(db_gen)
                                except StopIteration:
                                    pass
                            if ctx.cancel_requested.is_set() and ctx.orch is not None:
                                ctx.orch.abort()
                            if EXECUTION_NO_PROGRESS_SECONDS > 0 and (_time.time() - max(ctx.last_progress_at, ctx.started_at)) > EXECUTION_NO_PROGRESS_SECONDS:
                                ctx.termination_reason = "no_progress"
                                ctx.cancel_requested.set()
                                if ctx.orch is not None:
                                    ctx.orch.abort()
                            continue
                        db_gen = get_db()
                        db: Session = next(db_gen)
                        try:
                            snapshot = load_execution_snapshot(db, task_id)
                            if (
                                snapshot is not None
                                and snapshot.status == "running"
                                and snapshot.execution_owner_id == WORKER_ID
                                and int(snapshot.execution_epoch or 0) == int(ctx.epoch or 0)
                                and int(snapshot.control_version or 0) == int(ctx.control_version or 0)
                            ):
                                _recover_running_task_for_cleanup(
                                    db,
                                    task_id=task_id,
                                    owner_id=WORKER_ID,
                                    epoch=int(ctx.epoch or 0),
                                    control_version=int(ctx.control_version or 0),
                                    reason=ctx.termination_reason or "executor_thread_dead",
                                )
                        finally:
                            try:
                                next(db_gen)
                            except StopIteration:
                                pass
                        _unregister_running_task_context(task_id)
                    self._last_supervisor_error = None
                except Exception as exc:
                    self._last_supervisor_error = str(exc)
                    logger.warning("execution supervisor loop failed: %s", exc, exc_info=True)

        self._supervisor_thread = threading.Thread(target=_worker, name="dvs_execution_supervisor", daemon=True)
        self._supervisor_thread.start()
        if IDLE_PI_REAPER_ENABLED and (self._idle_pi_reaper_thread is None or not self._idle_pi_reaper_thread.is_alive()):
            self._idle_pi_reaper_thread = threading.Thread(target=self._idle_pi_reaper_loop, name="dvs_idle_pi_reaper", daemon=True)
            self._idle_pi_reaper_thread.start()

    def stop_supervisor(self) -> None:
        self._supervisor_stop.set()
        self._idle_pi_reaper_stop.set()

    def reconcile_orphaned_running_tasks(self, db: Session, *, limit: int = 100) -> int:
        from app.service.execution_coordinator import reclaim_orphaned_running_tasks

        recovered = reclaim_orphaned_running_tasks(db, limit=limit)
        for item in recovered:
            row = db.query(AppDvsTask).filter_by(task_id=item.task_id).first()
            if row is None:
                continue
            _mark_row_clean_restart(row, reason=item.reason, previous_owner_id=item.previous_owner_id)
            db.add(row)
            payload = {
                "previous_owner_id": item.previous_owner_id,
                "previous_dispatch_status": item.previous_dispatch_status,
                "previous_lease_until": isoformat_local(item.previous_lease_until),
                "recovery_reason": item.reason,
            }
            _record_task_event(
                db,
                row=row,
                event_type="task_running_recovered",
                message="后台巡检发现孤儿 running 任务，已回退为 pending",
                level="warning",
                status=row.status,
                dispatch_status=row.dispatch_status,
                payload=payload,
            )
            _record_task_event(
                db,
                row=row,
                event_type="task_requeued_after_orphaned_running",
                message="孤儿 running 任务已重新排入调度队列",
                level="warning",
                status=row.status,
                dispatch_status=row.dispatch_status,
                payload=payload,
            )
        if recovered:
            db.commit()
        return len(recovered)

    def _cleanup_worker_runtime(self, *, label: str, task_id: str | None = None, reason: str = "") -> int:
        """Best-effort full runtime cleanup for one-slot worker pods."""
        try:
            cleaned = cleanup_worker_runtime_processes(logger.warning, label=label)
            log_event(
                logger,
                logging.INFO,
                "worker runtime cleanup finished",
                event="worker_runtime_cleanup_finished",
                task_id=task_id,
                owner_id=WORKER_ID,
                label=label,
                reason=reason,
                cleaned_groups=cleaned,
            )
            return cleaned
        except Exception as exc:
            logger.warning("worker runtime cleanup failed [%s]: %s", label, exc, exc_info=True)
            return 0

    def _worker_idle_for_pi_reaping(self) -> bool:
        if self.local_running_task_count() != 0:
            self._idle_pi_reaper_idle_streak = 0
            return False
        from app.db import get_db

        db_gen = get_db()
        db: Session = next(db_gen)
        try:
            active_owned = (
                db.query(AppDvsTask)
                .filter(
                    AppDvsTask.is_deleted.is_(False),
                    AppDvsTask.execution_owner_id == WORKER_ID,
                    AppDvsTask.status.in_(("pending", "running")),
                    AppDvsTask.dispatch_status.in_(("leased", "running", "dispatching")),
                )
                .count()
            )
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass
        if int(active_owned or 0) != 0:
            self._idle_pi_reaper_idle_streak = 0
            return False
        self._idle_pi_reaper_idle_streak += 1
        return self._idle_pi_reaper_idle_streak >= IDLE_PI_REAPER_CONFIRM_ROUNDS

    def _worker_has_residual_pi_for_reaping(self) -> bool:
        from app.db import get_db
        from app.service.agent_observability import AgentObservabilityService

        db_gen = get_db()
        db: Session = next(db_gen)
        try:
            snapshot = AgentObservabilityService().build_snapshot(db, project_id=None)
            summary = dict(snapshot.get("summary") or {})
            residual_count = int(
                summary.get("residual_pi_process_count")
                or summary.get("residual_processes")
                or 0
            )
            unknown_count = int(
                summary.get("unknown_pi_process_count")
                or summary.get("unknown_processes")
                or 0
            )
            return (residual_count + unknown_count) > 0
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass

    def _idle_pi_reaper_loop(self) -> None:
        while not self._idle_pi_reaper_stop.wait(IDLE_PI_REAPER_INTERVAL_SECONDS):
            self._idle_pi_reaper_runs_total += 1
            if not self._worker_idle_for_pi_reaping():
                continue
            if not self._worker_has_residual_pi_for_reaping():
                self._idle_pi_reaper_idle_streak = 0
                continue
            logger.info("idle_pi_reaper_scan_started: worker_id=%s", WORKER_ID)
            try:
                cleaned = self._cleanup_worker_runtime(
                    label="idle_pi_reaper",
                    reason="idle_worker_reaper",
                )
                self._last_idle_pi_reaper_at = _time.time()
                self._last_idle_pi_reaper_killed_count = int(cleaned or 0)
                self._idle_pi_reaper_killed_groups_total += int(cleaned or 0)
                self._idle_pi_reaper_idle_streak = 0
                logger.info(
                    "idle_pi_reaper_cleanup_finished: worker_id=%s cleaned_groups=%s",
                    WORKER_ID,
                    cleaned,
                )
            except Exception as exc:
                self._idle_pi_reaper_failures_total += 1
                logger.warning("idle_pi_reaper_cleanup_failed: worker_id=%s error=%s", WORKER_ID, exc)

    def dispatch_once(self) -> str | None:
        if self.local_running_task_count() >= MAX_LOCAL_RUNNING_TASKS:
            from app.metrics import observe_local_event

            observe_local_event("dispatch_capacity_blocked", "skip")
            return None
        pre_dispatch_cleaned = self._cleanup_worker_runtime(label="pre_dispatch", reason="before_claim")
        from app.db import get_db
        db_gen = get_db()
        db: Session = next(db_gen)
        try:
            claimed = claim_one_runnable_task(db, WORKER_ID)
            if claimed is None:
                from app.metrics import observe_local_event

                observe_local_event("dispatch_claim", "empty")
                return None
            if _active_local_task(claimed.task_id) is not None:
                release_lease(db, claimed.task_id, WORKER_ID, claimed.epoch)
                from app.metrics import observe_local_event

                observe_local_event("dispatch_claim", "duplicate_local")
                log_event(
                    logger,
                    logging.WARNING,
                    "claimed task already running locally, released duplicate lease",
                    event="task_lease_released_duplicate_local",
                    task_id=claimed.task_id,
                    owner_id=WORKER_ID,
                    epoch=claimed.epoch,
                    control_version=claimed.control_version,
                )
                return None
            execution_thread = threading.Thread(
                target=_run_execute_task_in_thread,
                args=(self, claimed.task_id, claimed.epoch, claimed.control_version),
                name=f"dvs_task_{claimed.task_id}",
                daemon=True,
            )
            _register_running_task_context(
                claimed.task_id,
                execution_thread=execution_thread,
                epoch=claimed.epoch,
                control_version=claimed.control_version,
            )
            execution_thread.start()
            from app.metrics import observe_local_event

            observe_local_event("dispatch_claim", "success")
            log_event(
                logger,
                logging.INFO,
                "task leased by dispatcher",
                event="task_leased",
                task_id=claimed.task_id,
                owner_id=WORKER_ID,
                epoch=claimed.epoch,
                control_version=claimed.control_version,
            )
            claimed_row = db.query(AppDvsTask).filter_by(task_id=claimed.task_id).first()
            if claimed_row is not None:
                auto_recovery = _auto_recovery_payload(claimed_row.task_config_json)
                _record_task_event(
                    db,
                    row=claimed_row,
                    event_type="task_leased",
                    message="任务已被 worker 领取租约",
                    status=claimed_row.status,
                    execution_epoch=claimed.epoch,
                    control_version=claimed.control_version,
                    dispatch_status=claimed.dispatch_status,
                    worker_id=WORKER_ID,
                    execution_owner_id=WORKER_ID,
                    payload={
                        "owner_id": WORKER_ID,
                        "epoch": claimed.epoch,
                        "control_version": claimed.control_version,
                        "dispatch_status": claimed.dispatch_status,
                        "preflight_cleanup_scope": "pod_all_pi",
                        "preflight_cleaned_groups": pre_dispatch_cleaned,
                    },
                )
                if auto_recovery is not None:
                    _record_task_event(
                        db,
                        row=claimed_row,
                        event_type="task_auto_recovered",
                        message="任务已由系统自动恢复并重新认领执行",
                        level="warning",
                        status=claimed_row.status,
                        execution_epoch=claimed.epoch,
                        control_version=claimed.control_version,
                        dispatch_status=claimed.dispatch_status,
                        worker_id=WORKER_ID,
                        execution_owner_id=WORKER_ID,
                        payload={
                            "reason": auto_recovery.get("reason"),
                            "previous_status": "running",
                            "previous_error": claimed_row.error,
                            "previous_owner_id": auto_recovery.get("previous_owner_id"),
                            "lease_epoch_before": int(auto_recovery.get("previous_epoch") or 0),
                            "lease_epoch_after": int(claimed.epoch or 0),
                            "control_version": int(claimed.control_version or 0),
                        },
                    )
                    claimed_row.task_config_json = _clear_auto_recovery_flag(claimed_row.task_config_json)
                    db.add(claimed_row)
                db.commit()
            return claimed.task_id
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass

    def dispatch_until_full(self) -> int:
        claimed = 0
        while self.local_running_task_count() < MAX_LOCAL_RUNNING_TASKS:
            task_id = self.dispatch_once()
            if not task_id:
                break
            claimed += 1
        return claimed

    def list_task_sessions(self, db: Session, task_id: str) -> list[dict[str, object]]:
        row = self._get_or_404(db, task_id)
        return list(_build_task_session_catalog(row).get("items", []))

    def get_task_session_index(self, db: Session, task_id: str) -> dict[str, object]:
        row = self._get_or_404(db, task_id)
        catalog = _build_task_session_catalog(row)
        return {
            "task_id": catalog.get("task_id") or row.task_id,
            "status": catalog.get("status") or row.status,
            "sessions_root": catalog.get("sessions_root"),
            "index_path": catalog.get("index_path"),
            "generated_at": catalog.get("generated_at"),
            **(catalog.get("index") or {}),
        }

    def get_task_session_file(self, db: Session, task_id: str, relative_path: str) -> dict[str, object]:
        row = self._get_or_404(db, task_id)
        root = _task_root(row)
        if root is None:
            from fastapi import HTTPException
            raise HTTPException(404, "会话目录不存在")
        target = _safe_session_file(root, relative_path)
        parsed = _parse_session_file(target)
        return {
            "path": str(relative_path),
            "session_meta": parsed["session_meta"],
            "events": parsed["events"],
            "warnings": parsed["warnings"],
            "line_count": parsed["line_count"],
        }

    def get_task_evaluation(self, db: Session, task_id: str) -> dict:
        row = self._get_or_404(db, task_id)
        run_root = _latest_epoch_run_root(row)
        warnings: list[str] = []
        if not run_root or not run_root.is_dir():
            return {
                "task_id": row.task_id,
                "status": row.status,
                "current_epoch": None,
                "run_root": None,
                "available": False,
                "summary": None,
                "rounds": [],
                "warnings": warnings,
            }

        summary: dict | None = None
        summary_path = run_root / "evaluation_summary.json"
        if summary_path.exists():
            try:
                loaded = json.loads(summary_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    summary = loaded
                else:
                    warnings.append("evaluation_summary.json 格式不是对象")
            except Exception as exc:
                warnings.append(f"evaluation_summary.json 读取失败: {exc}")

        rounds: list[dict] = []
        for round_dir in sorted(run_root.glob("round_*")):
            if not round_dir.is_dir():
                continue
            for path in sorted(round_dir.glob("*.json")):
                if path.name.endswith(".tmp"):
                    continue
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except Exception as exc:
                    warnings.append(f"{path.relative_to(run_root)} 读取失败: {exc}")
                    continue
                if not isinstance(payload, dict):
                    warnings.append(f"{path.relative_to(run_root)} 格式不是对象")
                    continue
                payload.setdefault("source_path", str(path))
                rounds.append(payload)

        if summary is None and not rounds:
            result_json = _load_task_result_json(row)
            if result_json:
                summary, rounds = _build_evaluation_payload(row.task_id, row.status, result_json)

        rounds.sort(key=lambda item: (
            int(item.get("round") or 0),
            str(item.get("module_name") or ""),
            str(item.get("stage") or ""),
        ))
        return {
            "task_id": row.task_id,
            "status": row.status,
            "current_epoch": _epoch_label_from_path(run_root),
            "run_root": str(run_root),
            "available": bool(summary or rounds),
            "summary": summary,
            "rounds": rounds,
            "warnings": warnings,
        }

    def list_tasks(self, db: Session, *, project_id: str, page: int = 1,
                   per_page: int = 100, status: Optional[str] = None,
                   mode: Optional[str] = None,
                   parent_task_id: Optional[str] = None,
                   parent_stage_item_id: Optional[str] = None,
                   sort_by: str = "created_at",
                   sort_order: str = "desc") -> dict:
        query = db.query(AppDvsTask).filter(
            AppDvsTask.project_id == project_id,
            AppDvsTask.is_deleted.is_(False),
        )
        if status:
            query = query.filter(AppDvsTask.status == status)
        normalized_mode = str(mode or "").strip().lower()
        if normalized_mode == "manual":
            query = query.filter(
                (AppDvsTask.task_origin_type.is_(None)) | (AppDvsTask.task_origin_type != "binary_security")
            )
        elif normalized_mode == "binary":
            query = query.filter(
                AppDvsTask.task_origin_type == "binary_security",
                (AppDvsTask.parent_task_type.is_(None)) | (AppDvsTask.parent_task_type != "source"),
            )
        elif normalized_mode == "source":
            query = query.filter(
                AppDvsTask.task_origin_type == "binary_security",
                AppDvsTask.parent_task_type == "source",
            )
        normalized_parent_task_id = str(parent_task_id or "").strip()
        if normalized_parent_task_id:
            query = query.filter(AppDvsTask.parent_task_id == normalized_parent_task_id)
        normalized_parent_stage_item_id = str(parent_stage_item_id or "").strip()
        if normalized_parent_stage_item_id:
            query = query.filter(AppDvsTask.parent_stage_item_id == normalized_parent_stage_item_id)
        sort_column = _TASK_LIST_SORT_COLUMNS.get(str(sort_by or "").strip(), AppDvsTask.created_at)
        order_expr = sort_column.asc() if str(sort_order or "").lower() == "asc" else sort_column.desc()
        total = query.count()
        rows = (query.options(*self._list_load_options())
                .order_by(order_expr, AppDvsTask.id.desc())
                .offset((page - 1) * per_page).limit(per_page).all())
        return {"items": [self._row_to_dict(r, include_heavy=False) for r in rows],
                "total": total, "page": page, "per_page": per_page}

    def get_task_stats(
        self,
        db: Session,
        *,
        project_id: str,
        status: Optional[str] = None,
        mode: Optional[str] = None,
        parent_task_id: Optional[str] = None,
        parent_stage_item_id: Optional[str] = None,
    ) -> dict:
        query = db.query(AppDvsTask.status, func.count(AppDvsTask.id)).filter(
            AppDvsTask.project_id == project_id,
            AppDvsTask.is_deleted.is_(False),
        )
        if status:
            query = query.filter(AppDvsTask.status == status)
        normalized_mode = str(mode or "").strip().lower()
        if normalized_mode == "manual":
            query = query.filter(
                (AppDvsTask.task_origin_type.is_(None)) | (AppDvsTask.task_origin_type != "binary_security")
            )
        elif normalized_mode == "binary":
            query = query.filter(
                AppDvsTask.task_origin_type == "binary_security",
                (AppDvsTask.parent_task_type.is_(None)) | (AppDvsTask.parent_task_type != "source"),
            )
        elif normalized_mode == "source":
            query = query.filter(
                AppDvsTask.task_origin_type == "binary_security",
                AppDvsTask.parent_task_type == "source",
            )
        normalized_parent_task_id = str(parent_task_id or "").strip()
        if normalized_parent_task_id:
            query = query.filter(AppDvsTask.parent_task_id == normalized_parent_task_id)
        normalized_parent_stage_item_id = str(parent_stage_item_id or "").strip()
        if normalized_parent_stage_item_id:
            query = query.filter(AppDvsTask.parent_stage_item_id == normalized_parent_stage_item_id)
        rows = query.group_by(AppDvsTask.status).all()
        counts = {str(task_status or ""): int(count or 0) for task_status, count in rows}
        return {
            "total": sum(counts.values()),
            "pending": counts.get("pending", 0),
            "running": counts.get("running", 0),
            "passed": counts.get("passed", 0),
            "failed": counts.get("failed", 0),
            "error": counts.get("error", 0),
            "cancelled": counts.get("cancelled", 0),
        }

    def get_task(self, db: Session, task_id: str) -> dict:
        return self._row_to_dict(self._get_or_404(db, task_id))

    def get_task_execution(self, db: Session, task_id: str) -> dict:
        row = self._get_or_404(db, task_id)
        snapshot = load_execution_snapshot(db, task_id)
        return {
            "task_id": row.task_id,
            "project_id": row.project_id,
            "status": row.status,
            "execution": None if snapshot is None else {
                "owner_id": snapshot.execution_owner_id,
                "epoch": snapshot.execution_epoch,
                "control_version": snapshot.control_version,
                "dispatch_status": snapshot.dispatch_status,
                "lease_until": isoformat_local(snapshot.execution_lease_until),
                "heartbeat_at": isoformat_local(snapshot.execution_heartbeat_at),
            },
        }

    def get_task_timeline(self, db: Session, task_id: str) -> dict:
        row = self._get_or_404(db, task_id)
        events = (
            db.query(AppDvsTaskEvent)
            .filter(AppDvsTaskEvent.task_id == row.task_id)
            .order_by(AppDvsTaskEvent.created_at.desc())
            .all()
        )
        return {
            "task_id": row.task_id,
            "events": [_build_task_event_response(event) for event in events],
        }

    def clear_task_timeline(self, db: Session, task_id: str) -> int:
        row = self._get_or_404(db, task_id)
        deleted = (
            db.query(AppDvsTaskEvent)
            .filter(AppDvsTaskEvent.task_id == row.task_id)
            .delete(synchronize_session=False)
        )
        return int(deleted or 0)

    def delete_task_timeline_event(self, db: Session, task_id: str, event_id: str) -> int:
        row = self._get_or_404(db, task_id)
        deleted = (
            db.query(AppDvsTaskEvent)
            .filter(
                AppDvsTaskEvent.task_id == row.task_id,
                AppDvsTaskEvent.id == event_id,
            )
            .delete(synchronize_session=False)
        )
        return int(deleted or 0)

    def create_task(self, db: Session, *, project_id: str, task_name: str,
                    input_path: str, module_input_path: Optional[str] = None,
                    source_root_path: Optional[str] = None, output_path: Optional[str] = None,
                    task_description: Optional[str] = None,
                    prompt_template_id: Optional[str] = None,
                    prompt_content: str, created_by: Optional[str] = None,
                    task_config_json: Optional[dict] = None,
                    task_origin_type: Optional[str] = None,
                    parent_project_id: Optional[str] = None,
                    parent_task_id: Optional[str] = None,
                    parent_task_type: Optional[str] = None,
                    parent_stage_name: Optional[str] = None,
                    parent_stage_item_id: Optional[str] = None,
                    parent_stage_item_key: Optional[str] = None) -> dict:
        task_id = f"dvs_{uuid.uuid4().hex[:16]}"
        _fs_base = os.environ.get("FILESERVER_ROOT", "/data/files")
        effective_module_input_path = module_input_path or input_path
        normalized_module_input_path = _validate_fileserver_path(
            effective_module_input_path,
            fs_root=_fs_base,
            field_name="module_input_path",
            must_exist=True,
            must_be_dir=True,
        )
        normalized_source_root_path = _validate_fileserver_path(
            source_root_path or effective_module_input_path,
            fs_root=_fs_base,
            field_name="source_root_path",
            must_exist=True,
            must_be_dir=True,
        )
        normalized_task_config = dict(task_config_json or {})
        if normalized_task_config.get("source_file"):
            normalized_task_config["source_file"] = _normalize_source_file_for_root(
                normalized_source_root_path,
                str(normalized_task_config.get("source_file") or ""),
            )
        raw_definition_kind = str(normalized_task_config.get("definition_kind") or "").strip().lower()
        if raw_definition_kind:
            if raw_definition_kind not in {"definition", "declaration", "unknown"}:
                from fastapi import HTTPException as _HTTPException

                raise _HTTPException(400, f"definition_kind 非法: {raw_definition_kind}")
            normalized_task_config["definition_kind"] = raw_definition_kind
        effective_output = output_path or f"{_fs_base}/{project_id}/app/secflow-app-dataflow-vuln-scan"
        normalized_output = _validate_fileserver_path(
            effective_output,
            fs_root=_fs_base,
            field_name="output_path",
            must_exist=False,
            must_be_dir=False,
        )
        row = AppDvsTask(
            task_id=task_id, project_id=project_id, task_name=task_name,
            task_description=task_description, input_path=normalized_module_input_path,
            module_input_path=normalized_module_input_path,
            source_root_path=normalized_source_root_path,
            output_path=normalized_output, prompt_template_id=prompt_template_id,
            prompt_content=prompt_content, status="pending", created_by=created_by,
            task_config_json=normalized_task_config or None,
            task_origin_type=str(task_origin_type or "").strip() or "manual",
            parent_project_id=parent_project_id,
            parent_task_id=parent_task_id,
            parent_task_type=parent_task_type,
            parent_stage_name=parent_stage_name,
            parent_stage_item_id=parent_stage_item_id,
            parent_stage_item_key=parent_stage_item_key,
            execution_owner_id=None,
            execution_lease_until=None,
            execution_heartbeat_at=None,
            execution_epoch=0,
            control_version=0,
            dispatch_status="pending",
        )
        db.add(row); db.commit(); db.refresh(row)
        _record_task_event(
            db,
            row=row,
            event_type="task_created",
            message="数据流漏洞挖掘任务已创建",
            status=row.status,
            dispatch_status=row.dispatch_status,
            payload={
                "task_name": row.task_name,
                "input_path": row.input_path,
                "module_input_path": row.module_input_path,
                "source_root_path": row.source_root_path,
                "task_origin_type": row.task_origin_type,
                "parent_task_id": row.parent_task_id,
                "parent_stage_item_id": row.parent_stage_item_id,
            },
        )
        db.commit(); db.refresh(row)
        log_event(logger, logging.INFO, "task created",
                  event="task_created", task_id=task_id, project_id=project_id)
        return self._row_to_dict(row)

    def restart_task(self, db: Session, task_id: str) -> dict:
        """在原任务ID上重置并重新执行（SA 模式：in-place restart）。"""
        row = self._get_or_404(db, task_id)
        previous_status = str(row.status or "")
        previous_error = str(row.error or "").strip() or None
        previous_epoch = int(row.execution_epoch or 0)
        self.request_cancel(task_id, reason="restart_requested")
        restart_cleanup_groups = self._cleanup_worker_runtime(label=f"task_restart:{task_id}", task_id=task_id, reason="restart_requested_before_pending")
        task_root = _task_root(row)
        run_dir_removed = False
        output_dir_removed = False
        cleanup_errors: list[str] = []
        if task_root is not None:
            for child_name in ("run", "output"):
                child = task_root / child_name
                if child.exists():
                    try:
                        shutil.rmtree(child)
                        if child_name == "run":
                            run_dir_removed = True
                        if child_name == "output":
                            output_dir_removed = True
                    except Exception as exc:
                        cleanup_errors.append(f"{child_name}: {exc}")
        deleted_events = int(
            db.query(AppDvsTaskEvent)
            .filter(AppDvsTaskEvent.task_id == row.task_id)
            .delete(synchronize_session=False)
            or 0
        )
        from sqlalchemy.orm.attributes import flag_modified
        clean_config = {k: v for k, v in (row.task_config_json or {}).items()
                        if k not in ("start_stage", "resume_workspace", "resume")} or None
        row.task_config_json = clean_config
        row.status = "pending"
        row.started_at = None
        row.finished_at = None
        row.stages_json = None
        row.result_json = None
        row.error = None
        row.latest_abnormal_reason_json = None
        row.execution_owner_id = None
        row.execution_epoch = int(row.execution_epoch or 0) + 1
        row.execution_lease_until = None
        row.execution_heartbeat_at = None
        row.control_version = int(row.control_version or 0) + 1
        row.dispatch_status = "pending"
        flag_modified(row, "task_config_json")
        flag_modified(row, "latest_abnormal_reason_json")
        db.commit(); db.refresh(row)
        _record_task_event(
            db,
            row=row,
            event_type="task_retried",
            message="任务已原地重置并重新执行",
            status=row.status,
            control_version=int(row.control_version or 0),
            dispatch_status=row.dispatch_status,
            payload={
                **_restart_payload(
                    row,
                    previous_status=previous_status,
                    previous_error=previous_error,
                    previous_epoch=previous_epoch,
                    reason="restart_requested",
                ),
                "deleted_event_count": deleted_events,
                "run_dir_removed": run_dir_removed,
                "output_dir_removed": output_dir_removed,
                "cleanup_errors": cleanup_errors,
                "preflight_cleanup_scope": "pod_all_pi",
                "preflight_cleaned_groups": restart_cleanup_groups,
            },
        )
        db.commit(); db.refresh(row)
        log_event(logger, logging.INFO, "task restarted in-place", event="task_restarted",
                  task_id=task_id, project_id=row.project_id, control_version=row.control_version)
        return self._row_to_dict(row)

    def resume_task(self, db: Session, task_id: str) -> dict:
        """断点续跑暂未实现，重定向到 restart_task。"""
        return self.restart_task(db, task_id)

    def cancel_task(self, db: Session, task_id: str) -> dict:
        row = self._get_or_404(db, task_id)
        cancel_cleanup_groups = self._cleanup_worker_runtime(label=f"task_cancel:{task_id}", task_id=task_id, reason="cancel_requested")
        if row.status in ("passed", "failed", "error", "cancelled"):
            return self._row_to_dict(row)
        ctx = _get_running_task_context(task_id)
        local_task = _active_local_task(task_id)
        if local_task is not None:
            if self.request_cancel(task_id, reason="control_plane_cancel"):
                log_event(
                    logger,
                    logging.INFO,
                    "task cancel signal sent to orchestrator",
                    event="task_cancel_signal_sent",
                    task_id=task_id,
                    project_id=row.project_id,
                    owner_id=WORKER_ID,
                    epoch=ctx.epoch if ctx is not None else None,
                    control_version=ctx.control_version if ctx is not None else None,
                )
        if ctx is not None and (ctx.task_root or ctx.run_root):
            cleaned = cleanup_task_agent_processes(
                logger.warning,
                label=f"task_cancel:{task_id}",
                task_id=task_id,
                task_root=ctx.task_root,
                run_root=ctx.run_root,
                worker_id=WORKER_ID,
            )
            log_event(
                logger,
                logging.INFO,
                "task agent cleanup finished after cancel",
                event="task_agent_cleanup_finished",
                task_id=task_id,
                project_id=row.project_id,
                owner_id=WORKER_ID,
                cleaned_groups=cleaned,
            )
        row.status = "cancelled"
        row.finished_at = now_local()
        row.control_version = int(row.control_version or 0) + 1
        row.execution_owner_id = None
        row.execution_epoch = int(row.execution_epoch or 0) + 1
        row.execution_lease_until = None
        row.execution_heartbeat_at = None
        row.dispatch_status = None
        reason, changed = _sync_task_abnormal_reason(row)
        _record_abnormal_reason(row, reason, changed=changed)
        _record_abnormal_reason_timeline(db, row, reason, changed=changed)
        _record_task_event(
            db,
            row=row,
            event_type="task_cancelled",
            message="任务已被控制面取消",
            level="warning",
            status=row.status,
            control_version=int(row.control_version or 0),
            payload={
                "orchestrator_abort_sent": bool(ctx and ctx.orch is not None),
                "local_task_active": local_task is not None,
                "cleanup_task_root": ctx.task_root if ctx is not None else None,
                "cleanup_run_root": ctx.run_root if ctx is not None else None,
                "control_version": int(row.control_version or 0),
                "terminal_cleanup_scope": "pod_all_pi",
                "terminal_cleaned_groups": cancel_cleanup_groups,
            },
        )
        db.commit(); db.refresh(row)
        _unregister_running_task_context(task_id)
        log_event(logger, logging.INFO, "task cancelled by control plane", event="task_cancel_requested",
                  task_id=task_id, project_id=row.project_id, control_version=row.control_version, status=row.status,
                  local_task_active=local_task is not None)
        return self._row_to_dict(row)

    def delete_task(self, db: Session, task_id: str, *, delete_files: bool = True) -> None:
        """软删除任务记录，并可选删除输出目录下的任务文件。运行中任务不允许删除。"""
        from fastapi import HTTPException
        row = self._get_or_404(db, task_id, include_deleted=True)
        lease_live = bool(row.execution_owner_id and row.execution_lease_until and row.execution_lease_until >= now_local())
        local_task = _active_local_task(task_id)
        if bool(row.is_deleted):
            if delete_files and row.output_path:
                task_dir = os.path.join(row.output_path, task_id)
                if os.path.isdir(task_dir):
                    try:
                        shutil.rmtree(task_dir)
                        logger.info("delete_task: removed task dir %s", task_dir)
                    except FileNotFoundError:
                        logger.info("delete_task: task dir already absent %s", task_dir)
                    except Exception as _e:
                        logger.warning("delete_task: failed to remove %s: %s", task_dir, _e)
            return
        if row.status == "running" or lease_live or local_task is not None:
            detail = "任务仍在本地执行清理中，请稍后再删除" if local_task is not None else "任务正在运行，请先取消后再删除"
            _record_task_event(
                db,
                row=row,
                event_type="task_delete_rejected",
                message=detail,
                level="warning",
                status=row.status,
                control_version=int(row.control_version or 0),
                dispatch_status=row.dispatch_status,
                payload={
                    "delete_files": bool(delete_files),
                    "lease_live": lease_live,
                    "local_task_active": local_task is not None,
                },
            )
            db.commit()
            raise HTTPException(status_code=409, detail=detail)
        task_dir = None
        files_deleted = False
        files_delete_error: str | None = None
        if delete_files and row.output_path:
            task_dir = os.path.join(row.output_path, task_id)
            if os.path.isdir(task_dir):
                try:
                    shutil.rmtree(task_dir)
                    files_deleted = True
                    logger.info("delete_task: removed task dir %s", task_dir)
                except FileNotFoundError:
                    files_deleted = True
                    logger.info("delete_task: task dir already absent %s", task_dir)
                except Exception as _e:
                    files_delete_error = str(_e)
                    logger.warning("delete_task: failed to remove %s: %s", task_dir, _e)
        _record_task_event(
            db,
            row=row,
            event_type="task_deleted",
            message="任务已被软删除",
            level="warning",
            status=row.status,
            control_version=int(row.control_version or 0),
            dispatch_status=row.dispatch_status,
            payload={
                "delete_files": bool(delete_files),
                "files_deleted": files_deleted,
                "files_delete_error": files_delete_error,
                "task_dir": task_dir,
                "control_version": int(row.control_version or 0),
                "status_before_delete": row.status,
            },
        )
        row.is_deleted = True
        db.commit()

    def _execute_task(self, task_id: str, epoch: int, control_version: int) -> None:
        """Run the Orchestrator engine and persist results."""
        from app.db import get_db
        db_gen = get_db()
        db: Session = next(db_gen)
        event_buffer: list[dict] = []
        guard_counter = 0
        orch_holder: dict[str, Orchestrator] = {}
        ctx = None
        task_root_path: str | None = None
        epoch_run_root_path: str | None = None

        # Snapshot any previously-saved events BEFORE execution begins.
        # On resume, row.stages_json already has correct historical events
        # (e.g. root trace_callees from the prior run). Without this baseline,
        # the very first _flush_stages call would overwrite the DB with just
        # [first_new_event], wiping the history and causing the frontend tree
        # to briefly (or permanently, if root is cached) show wrong callees.
        _prev_row_for_baseline = db.query(AppDvsTask).filter_by(task_id=task_id).first()
        _baseline_events: list[dict] = []
        if _prev_row_for_baseline and isinstance(_prev_row_for_baseline.stages_json, dict):
            _baseline_events = list(_prev_row_for_baseline.stages_json.get("events") or [])

        def on_event(event: SwarmEvent) -> None:
            nonlocal guard_counter
            _mark_task_progress(task_id)
            event_buffer.append({"ts": _time.time(), "type": event.type,
                                  "data": dict(event.data)})
            try:
                event_db_gen = get_db()
                event_db: Session = next(event_db_gen)
                try:
                    event_row = event_db.query(AppDvsTask).filter_by(task_id=task_id).first()
                    if event_row is not None:
                        event_data = dict(event.data or {})
                        event_type = str(event.type or "").strip() or "runtime_event"
                        mapped_event_type = {
                            "task_start": "root_analysis_started",
                            "trace_callees": "callee_discovered",
                            "round_start": "round_started",
                            "round_end": "round_finished",
                            "judge_done": "judge_completed",
                            "task_end": "result_materialized",
                            "error": "task_runtime_error",
                            "task_rate_limited_retrying": "task_rate_limited_retrying",
                            "task_api_retrying": "task_api_retrying",
                            "task_fatal_retrying": "task_fatal_retrying",
                            "task_context_compaction_requested": "task_context_compaction_requested",
                            "task_context_compaction_completed": "task_context_compaction_completed",
                            "task_context_budget_exceeded_preflight": "task_context_budget_exceeded_preflight",
                            "task_context_overflow_retrying": "task_context_overflow_retrying",
                            "task_context_overflow_failed_after_compaction": "task_context_overflow_failed_after_compaction",
                        }.get(event_type, event_type)
                        if event_type == "trace_start":
                            depth = int(event_data.get("depth") or 0)
                            max_depth = int((event_row.task_config_json or {}).get("max_trace_depth") or 0)
                            if max_depth > 0 and depth >= max_depth:
                                mapped_event_type = "depth_limit_reached"
                            else:
                                mapped_event_type = "trace_started"
                        message = {
                            "root_analysis_started": "开始执行根函数分析",
                            "trace_started": "开始追踪函数",
                            "callee_discovered": "发现新的调用函数",
                            "round_started": "新一轮分析开始",
                            "round_finished": "分析轮次结束",
                            "judge_completed": "Judge 评估完成",
                            "depth_limit_reached": "追踪达到最大深度限制",
                            "result_materialized": "任务结果已产出",
                            "task_runtime_error": str(event_data.get("error") or "分析过程中出现错误"),
                            "task_rate_limited_retrying": "智能体请求被 429 限流，30 秒后自动重试",
                            "task_api_retrying": "智能体 API 错误，已进入无限重试",
                            "task_fatal_retrying": "智能体基础设施异常，已进入 30 秒固定间隔重试",
                            "task_context_compaction_requested": "智能体上下文超限，已请求会话压缩",
                            "task_context_compaction_completed": "智能体会话压缩已完成",
                            "task_context_budget_exceeded_preflight": "智能体请求在发送前已判定超出上下文预算",
                            "task_context_overflow_retrying": "智能体上下文持续超限，已进入无限压缩重试",
                            "task_context_overflow_failed_after_compaction": "智能体上下文压缩后仍超出预算，请求已终止",
                        }.get(mapped_event_type, f"运行事件: {mapped_event_type}")
                        _record_task_event(
                            event_db,
                            row=event_row,
                            event_type=mapped_event_type,
                            message=message,
                            level="error" if mapped_event_type == "task_runtime_error" else "info",
                            status=event_row.status,
                            worker_id=WORKER_ID,
                            execution_owner_id=WORKER_ID,
                            execution_epoch=epoch,
                            control_version=control_version,
                            function_name=str(event_data.get("function") or event_data.get("task") or ""),
                            source_file=str(event_data.get("source_path") or event_data.get("source_file") or ""),
                            line_hint=str(event_data.get("line") or event_data.get("line_hint") or ""),
                            payload=event_data,
                        )
                        event_db.commit()
                finally:
                    try:
                        next(event_db_gen)
                    except StopIteration:
                        pass
            except Exception:
                logger.debug("failed to persist DVS task runtime event", exc_info=True)
            n = len(event_buffer)
            if n == 1 or n % 3 == 0:
                _flush_stages(task_id, _baseline_events + event_buffer, WORKER_ID, epoch, control_version)
            guard_counter += 1
            if guard_counter % 10 == 0:
                try:
                    from app.db import get_db as _get_db
                    _guard_gen = _get_db()
                    _guard_db: Session = next(_guard_gen)
                    try:
                        if not still_owner(_guard_db, task_id, WORKER_ID, epoch, control_version):
                            log_event(
                                logger,
                                logging.WARNING,
                                "control-plane ownership changed during event streaming",
                                event="task_control_guard_abort",
                                task_id=task_id,
                                owner_id=WORKER_ID,
                                epoch=epoch,
                                control_version=control_version,
                            )
                            guard_row = _guard_db.query(AppDvsTask).filter_by(task_id=task_id).first()
                            if guard_row is not None:
                                _record_task_event(
                                    _guard_db,
                                    row=guard_row,
                                    event_type="task_control_guard_abort",
                                    message="控制面检测到执行权漂移，终止当前任务",
                                    level="warning",
                                    status=guard_row.status,
                                    worker_id=WORKER_ID,
                                    execution_owner_id=WORKER_ID,
                                    execution_epoch=epoch,
                                    control_version=control_version,
                                    payload={"owner_id": WORKER_ID, "epoch": epoch, "control_version": control_version},
                                )
                                _guard_db.commit()
                            ctx = _get_running_task_context(task_id)
                            if ctx is not None:
                                ctx.cancel_requested.set()
                                ctx.termination_reason = "control_guard_abort"
                            orch = orch_holder.get("orch")
                            if orch and orch._cancel_event is not None:
                                orch._cancel_event.set()
                    finally:
                        try:
                            next(_guard_gen)
                        except StopIteration:
                            pass
                except Exception as exc:
                    logger.warning("control guard check failed for %s: %s", task_id, exc, exc_info=True)

        try:
            row = db.query(AppDvsTask).filter_by(task_id=task_id).first()
            if not row or row.status == "cancelled":
                log_event(logger, logging.INFO, "task skipped before execution", event="task_skip_pre_execute",
                          task_id=task_id, owner_id=WORKER_ID, epoch=epoch, control_version=control_version, status=row.status if row else "missing")
                if row is not None:
                    _record_task_event(
                        db,
                        row=row,
                        event_type="task_skip_pre_execute",
                        message="任务在执行前被跳过",
                        level="warning",
                        status=row.status,
                        worker_id=WORKER_ID,
                        execution_owner_id=WORKER_ID,
                        execution_epoch=epoch,
                        control_version=control_version,
                        dispatch_status=row.dispatch_status,
                        payload={"reason": "cancelled_before_execute"},
                    )
                    db.commit()
                return
            if not still_owner(db, task_id, WORKER_ID, epoch, control_version):
                log_event(logger, logging.INFO, "task lost ownership before execution", event="task_not_owner_pre_execute",
                          task_id=task_id, owner_id=WORKER_ID, epoch=epoch, control_version=control_version)
                _record_task_event(
                    db,
                    row=row,
                    event_type="task_not_owner_pre_execute",
                    message="任务在执行前已失去执行权",
                    level="warning",
                    status=row.status,
                    worker_id=WORKER_ID,
                    execution_owner_id=WORKER_ID,
                    execution_epoch=epoch,
                    control_version=control_version,
                    dispatch_status=row.dispatch_status,
                    payload={"owner_id": WORKER_ID, "epoch": epoch, "control_version": control_version},
                )
                db.commit()
                return

            # ── Clean Restart ─────────────────────────────────────────────────────────
            # 没有断点续做能力：只要任务是从 lease 恢复过来的，就必须做一次干净重启，
            # 清理旧 output / SQLite 图谱 / session，新 epoch 从根函数全量重跑。
            tcfg_pre = row.task_config_json or {}
            force_clean_restart = bool(tcfg_pre.pop("_force_clean_restart", False))
            restart_reason = str(tcfg_pre.pop("_restart_reason", "") or "")
            restart_prev_owner = str(tcfg_pre.pop("_restart_previous_owner_id", "") or "")
            restart_prev_epoch = int(tcfg_pre.pop("_restart_previous_epoch", 0) or 0)
            tcfg_pre.pop("_restart_marked_at", None)
            if force_clean_restart:
                row.task_config_json = tcfg_pre
                db.add(row)
                db.commit()
                task_root = _task_root(row)
                _cleaned: list[str] = []
                if task_root:
                    # 完全清除整个 run 目录（包括所有 epoch、session、workspace、SQLite 图谱）
                    run_root = task_root / "run"
                    if run_root.exists():
                        try:
                            shutil.rmtree(run_root)
                            _cleaned.append(str(run_root))
                        except OSError as exc:
                            logger.warning("clean restart: failed to remove run root %s: %s", run_root, exc)
                    run_root.mkdir(parents=True, exist_ok=True)
                    # 完全清除 output/（图谱、漏洞、报告、flag 全部清除）
                    output_root = task_root / "output"
                    if output_root.exists():
                        try:
                            shutil.rmtree(output_root)
                            _cleaned.append(str(output_root))
                        except OSError as exc:
                            logger.warning("clean restart: failed to remove output root %s: %s", output_root, exc)
                    output_root.mkdir(parents=True, exist_ok=True)
                log_event(logger, logging.INFO, "clean restart applied for recovered task",
                          event="task_clean_restart", task_id=task_id, owner_id=WORKER_ID, epoch=epoch,
                          restart_reason=restart_reason, prev_owner=restart_prev_owner, prev_epoch=restart_prev_epoch,
                          cleaned_count=len(_cleaned))
                db.expire(row)
                db.refresh(row)
                _record_task_event(
                    db, row=row, event_type="task_clean_restart",
                    message=f"任务因 lease 恢复触发干净重启（无断点续做能力）：{restart_reason}",
                    level="warning", status=row.status,
                    worker_id=WORKER_ID, execution_owner_id=WORKER_ID,
                    execution_epoch=epoch, control_version=control_version,
                    dispatch_status=row.dispatch_status,
                    payload={
                        "restart_reason": restart_reason, "previous_owner_id": restart_prev_owner,
                        "previous_epoch": restart_prev_epoch, "new_epoch": epoch,
                        "cleaned": _cleaned,
                    },
                )
                db.commit()

            started_at = now_local() if force_clean_restart else (row.started_at or now_local())
            if not begin_execution_if_owner(db, task_id, WORKER_ID, epoch, control_version, started_at=started_at):
                from app.metrics import observe_local_event

                observe_local_event("task_started", "rejected")
                log_event(logger, logging.INFO, "failed to enter running state as owner", event="task_begin_execution_rejected",
                          task_id=task_id, owner_id=WORKER_ID, epoch=epoch, control_version=control_version)
                rejected_row = db.query(AppDvsTask).filter_by(task_id=task_id).first()
                if rejected_row is not None:
                    _record_task_event(
                        db,
                        row=rejected_row,
                        event_type="task_begin_execution_rejected",
                        message="任务获取执行态失败，未能进入 running",
                        level="warning",
                        status=rejected_row.status,
                        worker_id=WORKER_ID,
                        execution_owner_id=WORKER_ID,
                        execution_epoch=epoch,
                        control_version=control_version,
                        dispatch_status=rejected_row.dispatch_status,
                        payload={"owner_id": WORKER_ID, "epoch": epoch, "control_version": control_version},
                    )
                    db.commit()
                return
            from app.metrics import observe_local_event
            started_row = db.query(AppDvsTask).filter_by(task_id=task_id).first()
            if started_row is not None:
                _record_task_event(
                    db,
                    row=started_row,
                    event_type="task_started",
                    message="任务已开始执行",
                    status=started_row.status,
                    worker_id=WORKER_ID,
                    execution_owner_id=WORKER_ID,
                    execution_epoch=epoch,
                    control_version=control_version,
                    dispatch_status=started_row.dispatch_status,
                    payload={
                        "owner_id": WORKER_ID,
                        "epoch": epoch,
                        "control_version": control_version,
                        "started_at": isoformat_local(started_at),
                    },
                )
                db.commit()

            observe_local_event("task_started", "success")
            log_event(logger, logging.INFO, "task execution started", event="task_execution_started",
                      task_id=task_id, project_id=row.project_id, owner_id=WORKER_ID, epoch=epoch, control_version=control_version, status="running")
            db.expire(row)
            db.refresh(row)
            if row.status == "cancelled" or not still_owner(db, task_id, WORKER_ID, epoch, control_version):
                log_event(logger, logging.INFO, "task lost ownership before llm sync", event="task_not_owner_pre_llm_sync",
                          task_id=task_id, owner_id=WORKER_ID, epoch=epoch, control_version=control_version, status=row.status)
                _record_task_event(
                    db,
                    row=row,
                    event_type="task_not_owner_pre_llm_sync",
                    message="任务在模型执行前失去执行权",
                    level="warning",
                    status=row.status,
                    worker_id=WORKER_ID,
                    execution_owner_id=WORKER_ID,
                    execution_epoch=epoch,
                    control_version=control_version,
                    dispatch_status=row.dispatch_status,
                    payload={"owner_id": WORKER_ID, "epoch": epoch, "control_version": control_version},
                )
                db.commit()
                return
            _write_input_manifest(row)

            _write_models_json_from_db(db)
            svc = _load_svc_config_from_db(db, row.project_id)

            # Apply per-task config overrides
            tcfg = row.task_config_json or {}
            if tcfg.get("start_stage"):
                svc.start_stage = tcfg["start_stage"]

            # When output_path is unset (EA-created or clean-restarted tasks),
            # persist the fileserver output base so _task_root() & the sessions
            # API can discover session files without guessing paths.
            if not row.output_path or not Path(row.output_path).is_dir():
                _fs_root = os.environ.get("FILESERVER_ROOT", "/data/files")
                row.output_path = str(Path(_fs_root) / row.project_id / "app" / "secflow-app-dataflow-vuln-scan")
                db.add(row)
                db.commit()
                db.refresh(row)
            svc.output_dir = row.output_path
            svc.archive_dir = row.output_path
            svc.result_dir = row.output_path

            epoch_run_root = _task_epoch_run_root(row, epoch)
            root_output_dir = (_task_root(row) / "output") if _task_root(row) else None
            task_root_path = str(_task_root(row)) if _task_root(row) else None
            epoch_run_root_path = str(epoch_run_root) if epoch_run_root is not None else None
            if epoch_run_root is not None:
                if epoch_run_root.exists():
                    try:
                        shutil.rmtree(epoch_run_root)
                    except OSError as exc:
                        logger.warning("failed to clean epoch run root %s: %s", epoch_run_root, exc)
                epoch_run_root.mkdir(parents=True, exist_ok=True)

            cfg = build_task_config(svc, row.prompt_content, cwd=row.source_root_path or row.input_path)
            agent_task_key = _task_agent_key(tcfg)
            secret = str((agent_task_key or {}).get("secret") or "").strip()
            from app.service.pi_runtime import materialize_pi_runtime
            materialize_pi_runtime(secret=secret)
            agent_runtime_mode = "task_scoped" if secret else "global"
            (
                agent_auth_json,
                role_config_snapshot,
                provider_runtime_summary,
                llm_binding_snapshot,
            ) = _build_runtime_config_snapshots(
                cfg=cfg,
                agent_task_key=agent_task_key,
                task_pi_dirs={},
                agent_runtime_mode=agent_runtime_mode,
            )
            row.task_config_json = {
                **tcfg,
                "agent_auth_json": agent_auth_json,
                "role_config_snapshot": role_config_snapshot,
                "provider_runtime_summary": provider_runtime_summary,
                "llm_binding_snapshot": llm_binding_snapshot,
            }
            db.add(row)
            db.commit()
            db.refresh(row)
            tcfg = row.task_config_json or {}
            cfg.project_id = str(row.project_id or "")
            cfg.task_name = str(row.task_name or "")
            if tcfg.get("source_file"):
                cfg.source_file = str(tcfg["source_file"])
            if tcfg.get("function_name"):
                cfg.function_name = str(tcfg["function_name"])
            if tcfg.get("line_hint"):
                cfg.line_hint = str(tcfg["line_hint"])
            if tcfg.get("funcdb_path"):
                cfg.funcdb_path = str(tcfg["funcdb_path"]).strip()
            if tcfg.get("func_hash"):
                cfg.func_hash = str(tcfg["func_hash"]).strip()
            if "deep_trace_enabled" in tcfg:
                cfg.deep_trace_enabled = bool(tcfg.get("deep_trace_enabled"))
            if tcfg.get("max_trace_depth"):
                try:
                    cfg.max_trace_depth = int(tcfg.get("max_trace_depth") or cfg.max_trace_depth)
                except (TypeError, ValueError):
                    pass
            if isinstance(tcfg.get("taint_params"), list):
                cfg.taint_params = [str(value).strip() for value in tcfg["taint_params"] if str(value).strip()]
            if tcfg.get("function_description"):
                cfg.function_description = str(tcfg["function_description"]).strip()
            if tcfg.get("function_description_source"):
                cfg.function_description_source = str(tcfg["function_description_source"]).strip()
            if tcfg.get("entry_reason"):
                cfg.entry_reason = str(tcfg["entry_reason"]).strip()
            if tcfg.get("entry_reason_source"):
                cfg.entry_reason_source = str(tcfg["entry_reason_source"]).strip()
            if isinstance(tcfg.get("taint_details"), list):
                cfg.taint_details = [
                    {
                        "name": str(item.get("name") or "").strip(),
                        "description": str(item.get("description") or "").strip(),
                        **({"description_source": str(item.get("description_source")).strip()} if str(item.get("description_source") or "").strip() else {}),
                        **({"source_kind": str(item.get("source_kind")).strip()} if str(item.get("source_kind") or "").strip() else {}),
                    }
                    for item in tcfg["taint_details"]
                    if isinstance(item, dict) and str(item.get("name") or "").strip()
                ]
            entry_context = _build_entry_analysis_context(tcfg)
            if entry_context:
                cfg.context = ((cfg.context or "").rstrip() + "\n\n" + entry_context).strip()
            orch = Orchestrator(config=cfg, on_event=on_event)
            orch_holder["orch"] = orch
            ctx = _register_running_task_context(
                task_id,
                orch=orch,
                task_root=task_root_path,
                run_root=epoch_run_root_path,
                epoch=epoch,
                control_version=control_version,
            )
            _record_task_event(
                db,
                row=row,
                event_type="task_agent_runtime_materialized",
                message="已生成任务级角色 PI runtime",
                status=row.status,
                dispatch_status=row.dispatch_status,
                payload={
                    "agent_task_key_id": str((agent_task_key or {}).get("id") or "").strip() or None,
                    "agent_task_key_prefix": str((agent_task_key or {}).get("prefix") or "").strip() or None,
                    "agent_task_key_source": str((agent_task_key or {}).get("source") or "").strip() or None,
                    "agent_runtime_mode": agent_runtime_mode,
                },
            )
            db.commit()
            if not ctx.lease_alive():
                ctx.lease_stop_requested.clear()
                ctx.lease_thread = _start_task_lease_heartbeat(
                    task_id,
                    epoch=epoch,
                    control_version=control_version,
                    on_lease_lost=lambda: self.request_cancel(task_id, reason="lease_lost"),
                )
            result = orch.execute_recursive(
                task_id,
                _root_out_dir=epoch_run_root,
                _root_output_dir=root_output_dir,
            )
            if ctx is not None:
                ctx.lease_stop_requested.set()

            if ctx is not None and ctx.termination_reason == "lease_lost":
                recovered = _recover_running_task_for_cleanup(
                    db,
                    task_id=task_id,
                    owner_id=WORKER_ID,
                    epoch=epoch,
                    control_version=control_version,
                    reason="lease_lost",
                )
                log_event(
                    logger,
                    logging.WARNING,
                    "task lease lost; requeued instead of terminal error",
                    event="task_requeued_after_lease_lost",
                    task_id=task_id,
                    owner_id=WORKER_ID,
                    epoch=epoch,
                    control_version=control_version,
                    recovered=recovered,
                )
                return

            _flush_stages(task_id, _baseline_events + event_buffer, WORKER_ID, epoch, control_version)

            def _pre_terminal_check(_db: Session, _attempt: int):
                _row = _db.query(AppDvsTask).filter_by(task_id=task_id).first()
                if _row is None:
                    return "missing"
                if _row.status == "cancelled":
                    return "cancelled"
                owned = (
                    _row.execution_owner_id == WORKER_ID
                    and int(_row.execution_epoch or 0) == int(epoch)
                    and int(_row.control_version or 0) == int(control_version)
                    and _row.status in {"pending", "running"}
                )
                if not owned:
                    _record_task_event(
                        _db,
                        row=_row,
                        event_type="task_not_owner_pre_commit",
                        message="任务在写入终态前失去执行权",
                        level="warning",
                        status=_row.status,
                        worker_id=WORKER_ID,
                        execution_owner_id=WORKER_ID,
                        execution_epoch=epoch,
                        control_version=control_version,
                        dispatch_status=_row.dispatch_status,
                        payload={"owner_id": WORKER_ID, "epoch": epoch, "control_version": control_version},
                    )
                    _db.commit()
                    return "lost"
                return "ok"

            _pre_state = _run_db_write_with_retries("pre_terminal_check", _pre_terminal_check)
            if _pre_state == "cancelled":
                log_event(logger, logging.INFO, "task stopped after control-plane cancel", event="task_cancelled_during_execution",
                          task_id=task_id, owner_id=WORKER_ID, epoch=epoch, control_version=control_version, status="cancelled")
                return
            if _pre_state != "ok":
                log_event(logger, logging.INFO, "task lost ownership before terminal commit", event="task_not_owner_pre_commit",
                          task_id=task_id, owner_id=WORKER_ID, epoch=epoch, control_version=control_version, pre_state=_pre_state)
                return

            finished_at = now_local()
            stages_json = {"events": _baseline_events + event_buffer, "final": True}
            lightweight_result = None
            terminal_error = None
            if result:
                result_payload = result.model_dump(mode="json")
                result_file = _write_task_result_json(row, result_payload)
                _write_task_evaluation_files(row, result_payload)
                lightweight_result = _lightweight_result_json(row, result_payload, result_file)
                if result.error:
                    terminal_error = result.error
            def _commit_terminal(_db: Session, _attempt: int):
                return commit_terminal_state_if_owner(
                    _db,
                    task_id,
                    WORKER_ID,
                    epoch,
                    control_version,
                    status=result.status.value if result else "error",
                    finished_at=finished_at,
                    stages_json=stages_json,
                    result_json=lightweight_result,
                    error=terminal_error,
                )

            if not _run_db_write_with_retries("commit_terminal_state", _commit_terminal):
                from app.metrics import observe_local_event

                observe_local_event("task_finished", "commit_rejected")
                log_event(logger, logging.WARNING, "terminal commit rejected for stale owner", event="task_terminal_commit_rejected",
                          task_id=task_id, owner_id=WORKER_ID, epoch=epoch, control_version=control_version)
                def _record_rejected(_db: Session, _attempt: int):
                    rejected_row = _db.query(AppDvsTask).filter_by(task_id=task_id).first()
                    if rejected_row is not None:
                        _record_task_event(
                            _db,
                            row=rejected_row,
                            event_type="task_terminal_commit_rejected",
                            message="任务终态提交被拒绝，执行权已过期",
                            level="warning",
                            status=rejected_row.status,
                            worker_id=WORKER_ID,
                            execution_owner_id=WORKER_ID,
                            execution_epoch=epoch,
                            control_version=control_version,
                            dispatch_status=rejected_row.dispatch_status,
                            payload={"owner_id": WORKER_ID, "epoch": epoch, "control_version": control_version},
                        )
                        _db.commit()
                    return None
                _run_db_write_with_retries("record_terminal_rejected", _record_rejected)
                return
            def _record_terminal_event(_db: Session, _attempt: int):
                refreshed = _db.query(AppDvsTask).filter_by(task_id=task_id).first()
                if refreshed is not None:
                    reason, changed = _sync_task_abnormal_reason(refreshed)
                    _record_abnormal_reason(refreshed, reason, changed=changed)
                    _record_abnormal_reason_timeline(_db, refreshed, reason, changed=changed)
                    terminal_status = result.status.value if result else "error"
                    _record_task_event(
                        _db,
                        row=refreshed,
                        event_type={
                            "passed": "task_passed",
                            "failed": "task_failed",
                            "error": "task_error",
                            "completed_limited": "task_completed_limited",
                            "cancelled": "task_cancelled",
                        }.get(terminal_status, "task_finished"),
                        message=f"任务执行结束，状态={terminal_status}",
                        level="error" if terminal_status in {"failed", "error"} else "info",
                        status=terminal_status,
                        worker_id=WORKER_ID,
                        execution_owner_id=WORKER_ID,
                        execution_epoch=epoch,
                        control_version=control_version,
                        payload={
                            "completion_reason": result.completion_reason if result else None,
                            "round_count": len(result.rounds) if result else 0,
                            "error": result.error if result else None,
                        },
                    )
                    _db.commit()
                return None
            _run_db_write_with_retries("record_terminal_event", _record_terminal_event)
            from app.metrics import observe_local_event

            terminal_status = result.status.value if result else "error"
            observe_local_event("task_finished", terminal_status)
            log_event(logger, logging.INFO, "terminal state committed", event="task_terminal_committed",
                      task_id=task_id, owner_id=WORKER_ID, epoch=epoch, control_version=control_version,
                      status=terminal_status)
            terminal_cleaned_groups = self._cleanup_worker_runtime(label=f"task_terminal:{task_id}", task_id=task_id, reason="task_terminal_committed")
            def _record_terminal_cleanup(_db: Session, _attempt: int):
                refreshed = _db.query(AppDvsTask).filter_by(task_id=task_id).first()
                if refreshed is not None:
                    _record_task_event(
                        _db,
                        row=refreshed,
                        event_type="task_terminal_pi_cleanup_finished",
                        message="任务终态前已执行全量 PI 清理",
                        level="warning" if terminal_cleaned_groups else "info",
                        status=refreshed.status,
                        worker_id=WORKER_ID,
                        execution_owner_id=WORKER_ID,
                        execution_epoch=epoch,
                        control_version=control_version,
                        payload={
                            "cleanup_scope": "pod_all_pi",
                            "terminal_status": refreshed.status,
                            "cleaned_groups": terminal_cleaned_groups,
                        },
                    )
                    _db.commit()
                return None
            _run_db_write_with_retries("record_terminal_cleanup", _record_terminal_cleanup)

        except Exception as exc:
            from app.metrics import observe_local_event

            observe_local_event("task_finished", "exception")
            log_event(logger, logging.ERROR, "task execution failed",
                      event="task_error", task_id=task_id, owner_id=WORKER_ID, epoch=epoch, control_version=control_version, error=str(exc))
            try:
                ctx_for_error = _get_running_task_context(task_id)
                if ctx_for_error is not None and ctx_for_error.termination_reason == "lease_lost":
                    recovered = _recover_running_task_for_cleanup(
                        db,
                        task_id=task_id,
                        owner_id=WORKER_ID,
                        epoch=epoch,
                        control_version=control_version,
                        reason="lease_lost_exception",
                    )
                    log_event(logger, logging.WARNING, "exception after lease loss requeued instead of terminal error",
                              event="task_requeued_after_lease_lost", task_id=task_id,
                              owner_id=WORKER_ID, epoch=epoch, control_version=control_version,
                              recovered=recovered, error=str(exc))
                    return

                def _commit_error_terminal(_db: Session, _attempt: int):
                    r = _db.query(AppDvsTask).filter_by(task_id=task_id).first()
                    owned = bool(
                        r
                        and r.status == "running"
                        and r.execution_owner_id == WORKER_ID
                        and int(r.execution_epoch or 0) == int(epoch)
                        and int(r.control_version or 0) == int(control_version)
                    )
                    if not owned or r is None:
                        return False
                    _persist_terminal_failure(r, str(exc), status="error")
                    result_json = r.result_json
                    ok = commit_terminal_state_if_owner(
                        _db,
                        task_id,
                        WORKER_ID,
                        epoch,
                        control_version,
                        status="error",
                        finished_at=now_local(),
                        stages_json={"events": _baseline_events + event_buffer, "final": True},
                        result_json=result_json,
                        error=str(exc),
                    )
                    if not ok:
                        return False
                    refreshed = _db.query(AppDvsTask).filter_by(task_id=task_id).first()
                    if refreshed is not None:
                        reason, changed = _sync_task_abnormal_reason(refreshed)
                        _record_abnormal_reason(refreshed, reason, changed=changed)
                        _record_abnormal_reason_timeline(_db, refreshed, reason, changed=changed)
                        _record_task_event(
                            _db,
                            row=refreshed,
                            event_type="task_error",
                            message="任务因异常退出并已写入错误终态",
                            level="error",
                            status="error",
                            worker_id=WORKER_ID,
                            execution_owner_id=WORKER_ID,
                            execution_epoch=epoch,
                            control_version=control_version,
                            payload={"error": str(exc)},
                        )
                        _db.commit()
                    return True

                if _run_db_write_with_retries("commit_error_terminal", _commit_error_terminal):
                    log_event(logger, logging.ERROR, "error terminal state committed", event="task_error_committed",
                              task_id=task_id, owner_id=WORKER_ID, epoch=epoch, control_version=control_version, status="error")
            except Exception:
                logger.warning("failed to commit error terminal state after retries", exc_info=True)
        finally:
            ctx = _get_running_task_context(task_id)
            if ctx is not None:
                ctx.lease_stop_requested.set()
                ctx.cancel_requested.set()
            orch = orch_holder.get("orch")
            if orch is not None:
                orch.abort()
            targeted_cleaned = 0
            if task_root_path or epoch_run_root_path:
                log_event(
                    logger,
                    logging.INFO,
                    "task agent cleanup started",
                    event="task_agent_cleanup_started",
                    task_id=task_id,
                    owner_id=WORKER_ID,
                    epoch=epoch,
                    control_version=control_version,
                )
                targeted_cleaned = cleanup_task_agent_processes(
                    logger.warning,
                    label=f"task_finally:{task_id}",
                    task_id=task_id,
                    task_root=task_root_path,
                    run_root=epoch_run_root_path,
                    worker_id=WORKER_ID,
                )
            try:
                orphan_cleaned = cleanup_orphan_pi_processes(logger.warning, label=f"task_finally:{task_id}")
                full_cleaned = self._cleanup_worker_runtime(label=f"task_finally_full:{task_id}", task_id=task_id, reason="task_finally")
                log_event(
                    logger,
                    logging.INFO,
                    "task agent cleanup finished",
                    event="task_agent_cleanup_finished",
                    task_id=task_id,
                    owner_id=WORKER_ID,
                    epoch=epoch,
                    control_version=control_version,
                    cleaned_groups=targeted_cleaned,
                    orphan_cleaned_groups=orphan_cleaned,
                    full_runtime_cleaned_groups=full_cleaned,
                )
            except Exception:
                logger.warning("failed to cleanup orphan pi processes for %s", task_id, exc_info=True)
            try:
                snapshot = load_execution_snapshot(db, task_id)
                if (
                    snapshot is not None
                    and snapshot.status == "running"
                    and snapshot.execution_owner_id == WORKER_ID
                    and int(snapshot.execution_epoch or 0) == int(epoch)
                    and int(snapshot.control_version or 0) == int(control_version)
                ):
                    recovered = _recover_running_task_for_cleanup(
                        db,
                        task_id=task_id,
                        owner_id=WORKER_ID,
                        epoch=epoch,
                        control_version=control_version,
                        reason="worker_finally_without_terminal_state",
                    )
                    if recovered:
                        from app.metrics import observe_local_event

                        observe_local_event("task_running_recovered", "cleanup")
                        log_event(
                            logger,
                            logging.WARNING,
                            "running task recovered to pending during worker cleanup",
                            event="task_running_recovered",
                            task_id=task_id,
                            owner_id=WORKER_ID,
                            epoch=epoch,
                            control_version=control_version,
                        )
                released = release_lease(db, task_id, WORKER_ID, epoch)
                if released:
                    from app.metrics import observe_local_event

                    observe_local_event("lease_release", "success")
                    log_event(logger, logging.INFO, "lease released", event="task_lease_released",
                              task_id=task_id, owner_id=WORKER_ID, epoch=epoch, control_version=control_version)
                    released_row = db.query(AppDvsTask).filter_by(task_id=task_id).first()
                    if released_row is not None:
                        _record_task_event(
                            db,
                            row=released_row,
                            event_type="task_lease_released",
                            message="任务租约已释放",
                            status=released_row.status,
                            worker_id=WORKER_ID,
                            execution_owner_id=WORKER_ID,
                            execution_epoch=epoch,
                            control_version=control_version,
                            payload={"owner_id": WORKER_ID, "epoch": epoch, "control_version": control_version},
                        )
                        db.commit()
                else:
                    from app.metrics import observe_local_event

                    observe_local_event("lease_release", "noop")
            except Exception:
                from app.metrics import observe_local_event

                observe_local_event("lease_release", "failed")
                db.rollback()
            _unregister_running_task_context(task_id)
            try:
                next(db_gen)
            except StopIteration:
                pass

    def _get_or_404(self, db: Session, task_id: str, *, include_deleted: bool = False) -> AppDvsTask:
        query = db.query(AppDvsTask).filter(AppDvsTask.task_id == task_id)
        if not include_deleted:
            query = query.filter(AppDvsTask.is_deleted.is_(False))
        row = query.first()
        if not row:
            from fastapi import HTTPException
            raise HTTPException(404, f"任务不存在: {task_id}")
        return row

    @staticmethod
    def _list_load_options():
        return (
            load_only(
                AppDvsTask.id,
                AppDvsTask.task_id,
                AppDvsTask.project_id,
                AppDvsTask.task_origin_type,
                AppDvsTask.parent_project_id,
                AppDvsTask.parent_task_id,
                AppDvsTask.parent_task_type,
                AppDvsTask.parent_stage_name,
                AppDvsTask.parent_stage_item_id,
                AppDvsTask.parent_stage_item_key,
                AppDvsTask.task_name,
                AppDvsTask.task_description,
                AppDvsTask.input_path,
                AppDvsTask.module_input_path,
                AppDvsTask.source_root_path,
                AppDvsTask.output_path,
                AppDvsTask.prompt_template_id,
                AppDvsTask.status,
                AppDvsTask.error,
                AppDvsTask.created_by,
                AppDvsTask.created_at,
                AppDvsTask.updated_at,
                AppDvsTask.started_at,
                AppDvsTask.finished_at,
                AppDvsTask.execution_owner_id,
                AppDvsTask.execution_lease_until,
                AppDvsTask.execution_heartbeat_at,
                AppDvsTask.execution_epoch,
                AppDvsTask.control_version,
                AppDvsTask.dispatch_status,
            ),
        )

    @staticmethod
    def _row_to_dict(row: AppDvsTask, *, include_heavy: bool = True) -> dict:
        def fmt(dt: datetime | None) -> str | None:
            return isoformat_local(dt)
        abnormal_reason = _task_abnormal_reason(row)
        task_root = str(Path(row.output_path) / row.task_id) if row.output_path else None
        run_root = str(Path(task_root) / "run") if task_root else None
        workspace_root = str(Path(run_root) / "epochs") if run_root else None
        result_payload = _lightweight_result_json(row, row.result_json) if include_heavy else None
        execution_duration_ms: float | None = None
        if row.result_json and isinstance(row.result_json, dict):
            _total = row.result_json.get("total_duration_ms")
            if _total is not None:
                try:
                    execution_duration_ms = float(_total)
                except (TypeError, ValueError):
                    pass
        if execution_duration_ms is None and row.started_at and row.finished_at:
            try:
                execution_duration_ms = (row.finished_at - row.started_at).total_seconds() * 1000
            except Exception as _e:
                logger.warning("unexpected error in task_service.py: %s", _e, exc_info=True)
        return {
            **_origin_payload(row),
            "task_id": row.task_id, "project_id": row.project_id,
            "task_name": row.task_name, "task_description": row.task_description,
            "input_path": row.input_path,
            "module_input_path": row.module_input_path or row.input_path,
            "source_root_path": row.source_root_path or row.input_path,
            "output_path": row.output_path,
            "task_root": task_root,
            "run_root": run_root,
            "workspace_root": workspace_root,
            "input_summary": {
                "module_input_path": row.module_input_path or row.input_path,
                "source_root_path": row.source_root_path or row.input_path,
            } if include_heavy else None,
            "output_summary": {
                "latest_workspace_root": workspace_root,
                "result_path": str(Path(run_root) / "result.json") if run_root else None,
                "dataflow_output_path": str(Path(task_root) / "output" / "dataflow") if task_root else None,
            } if include_heavy else None,
            "definition_kind": str((row.task_config_json or {}).get("definition_kind") or ""),
            "prompt_template_id": row.prompt_template_id,
            "prompt_content": row.prompt_content if include_heavy else None, "status": row.status,
            "error": row.error,
            "result_json": result_payload,
            "stages_json": row.stages_json if include_heavy else None,
            "task_config_json": row.task_config_json if include_heavy else None,
            "created_by": row.created_by,
            "created_at": fmt(row.created_at), "updated_at": fmt(row.updated_at),
            "started_at": fmt(row.started_at), "finished_at": fmt(row.finished_at),
            "latest_started_at": fmt(row.started_at),
            "execution_duration_ms": execution_duration_ms,
            "execution_owner_id": row.execution_owner_id,
            "execution_lease_until": fmt(row.execution_lease_until),
            "execution_heartbeat_at": fmt(row.execution_heartbeat_at),
            "execution_epoch": int(row.execution_epoch or 0),
            "control_version": int(row.control_version or 0),
            "dispatch_status": row.dispatch_status,
            "abnormal_reason": abnormal_reason,
            "abnormal_reason_history": _abnormal_reason_history(row) if include_heavy else [],
            "abnormal_reason_title": (abnormal_reason or {}).get("title"),
            "abnormal_reason_code": (abnormal_reason or {}).get("code"),
            "abnormal_reason_category": (abnormal_reason or {}).get("category"),
            "has_agent_task_key": bool(str((((row.task_config_json or {}).get("agent_task_key") or {}).get("secret") or "")).strip()),
            "agent_task_key_id": str((((row.task_config_json or {}).get("agent_task_key") or {}).get("id") or "")).strip() or None,
            "agent_task_key_prefix": str((((row.task_config_json or {}).get("agent_task_key") or {}).get("prefix") or "")).strip() or None,
            "agent_runtime_mode": _agent_runtime_mode_from_task_config(row.task_config_json),
            **_task_config_snapshot_payload(row.task_config_json),
        }


_task_service: TaskService | None = None


def get_task_service() -> TaskService:
    global _task_service
    if _task_service is None:
        _task_service = TaskService()
    return _task_service
