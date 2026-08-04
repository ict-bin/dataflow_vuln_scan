"""Task event recording and JSONL timeline helpers."""

from __future__ import annotations

import fcntl
import json
import logging
import os
import socket
import time
import uuid
from collections import deque
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.config import OUTPUT_DIR
from app.db.models import AppDvsTask
from app.time_utils import isoformat_local, now_local

logger = logging.getLogger("dvs.task_events")

TASK_EVENT_SOURCE_DVS = "dvs"
TASK_EVENTS_JSONL_NAME = "events.jsonl"
TASK_EVENTS_LOCK_DIR_NAME = ".locks"
TASK_EVENTS_LOCK_NAME = "events.lock"
TASK_EVENTS_LOCK_TIMEOUT_SECONDS = max(0.1, float(os.environ.get("DVS_TASK_EVENTS_LOCK_TIMEOUT_SECONDS", "5")))
TASK_EVENTS_LOCK_RETRIES = max(0, int(os.environ.get("DVS_TASK_EVENTS_LOCK_RETRIES", "1")))
TASK_EVENTS_LOCK_POLL_SECONDS = max(0.01, float(os.environ.get("DVS_TASK_EVENTS_LOCK_POLL_SECONDS", "0.1")))
TASK_EVENTS_TAIL_SCAN_BYTES = max(1024 * 1024, int(os.environ.get("DVS_TASK_EVENTS_TAIL_SCAN_BYTES", str(8 * 1024 * 1024))))
POD_NAME = (
    os.environ.get("DVS_POD_NAME")
    or os.environ.get("POD_NAME")
    or os.environ.get("HOSTNAME")
    or "dvs-pod"
)
POD_IP = (
    os.environ.get("DVS_POD_IP")
    or os.environ.get("MY_POD_IP")
    or os.environ.get("POD_IP")
    or ""
)
NODE_NAME = (
    os.environ.get("DVS_NODE_NAME")
    or os.environ.get("NODE_NAME")
    or ""
)


class TaskEventLockTimeout(TimeoutError):
    """Raised when the task event file lock cannot be acquired in bounded time."""


def _task_event_runtime_role() -> str:
    role = str(os.environ.get("DVS_ROLE") or "").strip().lower()
    if role in {"api", "worker", "scheduler", "runner"}:
        return role
    return "api"


def _task_event_instance_id(
    *,
    payload: dict[str, object] | None = None,
    worker_id: str | None = None,
    execution_owner_id: str | None = None,
) -> str | None:
    data = payload if isinstance(payload, dict) else {}
    candidates = (
        os.environ.get("DVS_INSTANCE_ID"),
        os.environ.get("WORKER_INSTANCE_ID"),
        os.environ.get("DVS_WORKER_ID"),
        worker_id,
        execution_owner_id,
        str(data.get("worker_id") or "").strip() or None,
        str(data.get("execution_owner_id") or "").strip() or None,
        str(data.get("pod_name") or "").strip() or None,
        POD_NAME,
    )
    for value in candidates:
        text = str(value or "").strip()
        if text:
            return text
    return None


def _build_task_event_recorder_metadata(
    *,
    payload: dict[str, object] | None = None,
    role: str | None = None,
    worker_id: str | None = None,
    execution_owner_id: str | None = None,
) -> dict[str, object]:
    resolved_role = str(role or _task_event_runtime_role()).strip().lower() or "api"
    hostname = str(os.environ.get("HOSTNAME") or "").strip() or socket.gethostname()
    pod_name = str(os.environ.get("DVS_POD_NAME") or os.environ.get("POD_NAME") or hostname).strip() or hostname
    pod_ip = str(os.environ.get("DVS_POD_IP") or os.environ.get("MY_POD_IP") or os.environ.get("POD_IP") or "").strip() or None
    node_name = str(os.environ.get("DVS_NODE_NAME") or os.environ.get("NODE_NAME") or "").strip() or None
    return {
        "service": "dataflow-vuln-scan",
        "role": resolved_role,
        "instance_id": _task_event_instance_id(
            payload=payload,
            worker_id=worker_id,
            execution_owner_id=execution_owner_id,
        ),
        "hostname": hostname or None,
        "pod_name": pod_name or None,
        "node_name": node_name,
        "pod_ip": pod_ip,
    }


def _merge_task_event_recorder_payload(
    payload: dict[str, object] | None,
    *,
    role: str | None = None,
    origin: dict[str, object] | None = None,
    worker_id: str | None = None,
    execution_owner_id: str | None = None,
) -> dict[str, object]:
    merged = dict(payload) if isinstance(payload, dict) else {}
    merged["recorder"] = _build_task_event_recorder_metadata(
        payload=merged,
        role=role,
        worker_id=worker_id,
        execution_owner_id=execution_owner_id,
    )
    if isinstance(origin, dict) and origin:
        merged["event_origin"] = dict(origin)
    return merged


def _timeline_party_from_payload(payload: dict[str, object] | None, key: str) -> dict[str, object] | None:
    if not isinstance(payload, dict):
        return None
    party = payload.get(key)
    if not isinstance(party, dict):
        return None
    return party


_REVERSE_EVENT_TYPE_MAP = {
    "trace_started": "trace_start",
    "callee_discovered": "trace_callees",
    "root_analysis_started": "task_start",
    "round_started": "round_start",
    "round_finished": "round_end",
    "judge_completed": "judge_done",
    "result_materialized": "task_end",
    "depth_limit_reached": "trace_start",
    "task_runtime_error": "error",
}


def _task_root(row: AppDvsTask) -> Path:
    output_path = str(row.output_path or "").strip()
    if output_path:
        task_root = Path(output_path).expanduser() / row.task_id
    else:
        project_id = str(getattr(row, "project_id", "") or "").strip()
        if project_id:
            task_root = Path(os.environ.get("FILESERVER_ROOT", "/data/files")) / project_id / "app" / "secflow-app-dataflow-vuln-scan" / row.task_id
        else:
            task_root = Path(OUTPUT_DIR) / row.task_id
    return task_root


def _task_events_path(row: AppDvsTask) -> Path:
    return _task_root(row) / "output" / TASK_EVENTS_JSONL_NAME


def task_events_lock_path(task_root: Path) -> Path:
    """Return the stable task-level lock path outside resettable output/."""
    return task_root / TASK_EVENTS_LOCK_DIR_NAME / TASK_EVENTS_LOCK_NAME


@contextmanager
def task_events_file_lock(task_root: Path):
    lock_path = task_events_lock_path(task_root)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.touch(exist_ok=True)
    with lock_path.open("r+", encoding="utf-8") as lock_file:
        acquired = False
        total_attempts = TASK_EVENTS_LOCK_RETRIES + 1
        for attempt in range(1, total_attempts + 1):
            deadline = time.monotonic() + TASK_EVENTS_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(min(TASK_EVENTS_LOCK_POLL_SECONDS, max(0.0, deadline - time.monotonic())))
            if acquired:
                break
            if attempt < total_attempts:
                logger.warning(
                    "task event lock acquisition timed out; retrying: lock_path=%s attempt=%s/%s timeout_seconds=%s",
                    lock_path,
                    attempt,
                    total_attempts,
                    TASK_EVENTS_LOCK_TIMEOUT_SECONDS,
                )
        if not acquired:
            raise TaskEventLockTimeout(
                f"task event lock acquisition timed out: lock_path={lock_path} "
                f"attempts={total_attempts} timeout_seconds={TASK_EVENTS_LOCK_TIMEOUT_SECONDS}"
            )
        try:
            yield lock_path
        finally:
            if acquired:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _json_safe(value: Any, _seen: set[int] | None = None) -> Any:
    try:
        json.dumps(value, ensure_ascii=False)
        return value
    except Exception:
        logger.exception("task event value is not JSON serializable; stringifying value type=%s", type(value).__name__)
    seen = _seen if _seen is not None else set()
    value_id = id(value)
    if value_id in seen:
        return "<recursive value>"
    seen.add(value_id)
    if isinstance(value, dict):
        converted = {str(k): _json_safe(v, seen) for k, v in value.items()}
        seen.discard(value_id)
        return converted
    if isinstance(value, (list, tuple, set)):
        converted = [_json_safe(item, seen) for item in value]
        seen.discard(value_id)
        return converted
    converted = str(value)
    seen.discard(value_id)
    return converted


def _event_sort_key(event: dict[str, object]) -> str:
    return str(event.get("created_at") or event.get("ts") or "")


def _build_task_event_response(event: dict[str, object]) -> dict[str, object]:
    payload = event.get("payload")
    if not isinstance(payload, dict):
        payload = {}
    recorder = _timeline_party_from_payload(payload, "recorder") or {}
    origin = _timeline_party_from_payload(payload, "event_origin") or {}
    # 前端 buildDfaTree 用 evt.type + evt.data, 需要 reverse-map event_type + payload
    event_type = str(event.get("event_type") or "")
    original_type = _REVERSE_EVENT_TYPE_MAP.get(event_type, event_type)
    data = dict(payload)
    # 补充直接字段到 data (前端读 d.function, d.callees 等)
    if "function" not in data and event.get("function_name"):
        data["function"] = event.get("function_name")
    if "source_file" not in data and event.get("source_file"):
        data["source_file"] = event.get("source_file")
    return {
        "id": str(event.get("id") or ""),
        "task_id": str(event.get("task_id") or ""),
        "project_id": str(event.get("project_id") or ""),
        "source": str(event.get("source") or TASK_EVENT_SOURCE_DVS),
        "level": str(event.get("level") or "info"),
        "event_type": event_type,
        "status": event.get("status"),
        "worker_id": event.get("worker_id"),
        "execution_owner_id": event.get("execution_owner_id"),
        "execution_epoch": event.get("execution_epoch"),
        "control_version": event.get("control_version"),
        "dispatch_status": event.get("dispatch_status"),
        "function_name": event.get("function_name"),
        "source_file": event.get("source_file"),
        "line_hint": event.get("line_hint"),
        "parent_task_id": event.get("parent_task_id"),
        "parent_stage_item_id": event.get("parent_stage_item_id"),
        "message": str(event.get("message") or ""),
        "payload": payload,
        "recorder_instance_id": recorder.get("instance_id"),
        "recorder_hostname": recorder.get("hostname"),
        "recorder_pod_name": recorder.get("pod_name"),
        "recorder_node_name": recorder.get("node_name"),
        "recorder_pod_ip": recorder.get("pod_ip"),
        "recorder_role": recorder.get("role"),
        "origin_instance_id": origin.get("instance_id"),
        "origin_hostname": origin.get("hostname"),
        "origin_pod_name": origin.get("pod_name"),
        "origin_node_name": origin.get("node_name"),
        "origin_pod_ip": origin.get("pod_ip"),
        "origin_role": origin.get("role"),
        "created_at": str(event.get("created_at") or ""),
        "type": original_type,
        "data": data,
    }


def append_task_event(row: AppDvsTask, event: dict[str, object]) -> Path:
    events_path = _task_events_path(row)
    events_path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(_json_safe(event), ensure_ascii=False, separators=(",", ":")) + "\n"
    try:
        with task_events_file_lock(_task_root(row)):
            with events_path.open("a", encoding="utf-8") as event_file:
                event_file.write(line)
                event_file.flush()
                os.fsync(event_file.fileno())
    except TaskEventLockTimeout:
        logger.exception("append task event skipped after lock timeout: task_id=%s path=%s", row.task_id, events_path)
    return events_path


def read_task_events(row: AppDvsTask, *, newest_first: bool = True) -> list[dict[str, object]]:
    events_path = _task_events_path(row)
    if events_path.exists():
        events: list[dict[str, object]] = []
        try:
            with events_path.open("r", encoding="utf-8") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        loaded = json.loads(line)
                        if isinstance(loaded, dict):
                            events.append(loaded)
                        else:
                            logger.warning("task event JSONL line is not object: path=%s line=%s", events_path, line_number)
                    except Exception:
                        logger.exception("parse task event JSONL line failed: path=%s line=%s", events_path, line_number)
        except Exception:
            logger.exception("read task events failed: task_id=%s path=%s", row.task_id, events_path)
            return []
        if events:
            events.sort(key=_event_sort_key, reverse=newest_first)
            return events
    # fallback: 从管理库 secflow_app_dvs_task_events 表读取 (老版本任务)
    db_events = _read_task_events_from_db(row)
    if db_events:
        db_events.sort(key=_event_sort_key, reverse=newest_first)
    return db_events


def _read_task_events_from_db(row: AppDvsTask) -> list[dict[str, object]]:
    """从管理库 secflow_app_dvs_task_events 表读取事件 (兼容老版本任务)。

    老版本任务的事件存储在 DB 中 (没有 events.jsonl), 此函数提供 fallback。
    """
    try:
        from app.db import get_db
        from sqlalchemy import text as sa_text
        db = next(get_db())
        try:
            rows = db.execute(sa_text(
                "SELECT * FROM secflow_app_dvs_task_events WHERE task_id=:tid "
                "ORDER BY created_at"
            ), {"tid": row.task_id}).fetchall()
            events: list[dict[str, object]] = []
            for r in rows:
                d = dict(r._mapping)
                payload = {}
                try:
                    payload = json.loads(d.get("payload_json") or "{}")
                except Exception:
                    pass
                events.append({
                    "id": str(d.get("id") or ""),
                    "task_id": str(d.get("task_id") or ""),
                    "project_id": str(d.get("project_id") or ""),
                    "source": str(d.get("source") or "dvs"),
                    "level": str(d.get("level") or "info"),
                    "event_type": str(d.get("event_type") or ""),
                    "status": d.get("status"),
                    "worker_id": d.get("worker_id"),
                    "execution_owner_id": d.get("execution_owner_id"),
                    "execution_epoch": d.get("execution_epoch"),
                    "control_version": d.get("control_version"),
                    "dispatch_status": d.get("dispatch_status"),
                    "function_name": d.get("function_name"),
                    "source_file": d.get("source_file"),
                    "line_hint": d.get("line_hint"),
                    "parent_task_id": d.get("parent_task_id"),
                    "parent_stage_item_id": d.get("parent_stage_item_id"),
                    "message": str(d.get("message") or ""),
                    "payload": payload,
                    "created_at": d.get("created_at").isoformat() if d.get("created_at") else "",
                })
            logger.info("read %d events from DB for task %s (events.jsonl fallback)", len(events), row.task_id)
            return events
        finally:
            db.close()
    except Exception:
        logger.debug("read_task_events_from_db failed: task_id=%s", row.task_id, exc_info=True)
        return []


def read_task_event_responses(row: AppDvsTask, *, newest_first: bool = True) -> list[dict[str, object]]:
    return [_build_task_event_response(event) for event in read_task_events(row, newest_first=newest_first)]


def read_task_events_tail(row: AppDvsTask, limit: int) -> list[dict[str, object]]:
    normalized_limit = max(0, int(limit or 0))
    if normalized_limit <= 0:
        return []
    events_path = _task_events_path(row)
    if not events_path.exists():
        return []
    try:
        file_size = events_path.stat().st_size
        start = max(0, file_size - TASK_EVENTS_TAIL_SCAN_BYTES)
        with events_path.open("rb") as handle:
            handle.seek(start)
            if start:
                handle.readline()
            raw_lines = list(handle)
    except Exception:
        logger.exception("read task events tail failed: task_id=%s path=%s", row.task_id, events_path)
        return []
    out: deque[dict[str, object]] = deque(maxlen=normalized_limit)
    for index, raw_line in enumerate(raw_lines, start=1):
        line = raw_line.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        try:
            loaded = json.loads(line)
            if isinstance(loaded, dict):
                out.append(loaded)
        except Exception:
            logger.exception("parse task event tail JSONL failed: path=%s tail_line=%s", events_path, index)
    sorted_out = sorted(out, key=_event_sort_key)
    return sorted_out[-normalized_limit:]


def clear_task_events(row: AppDvsTask) -> int:
    events_path = _task_events_path(row)
    if not events_path.exists():
        return 0
    with task_events_file_lock(_task_root(row)):
        current_count = 0
        with events_path.open("r", encoding="utf-8") as source:
            current_count = sum(1 for line in source if line.strip())
        with events_path.open("w", encoding="utf-8") as event_file:
            event_file.truncate(0)
            event_file.flush()
            os.fsync(event_file.fileno())
    return current_count


def delete_task_event(row: AppDvsTask, event_id: str) -> int:
    normalized_event_id = str(event_id or "").strip()
    if not normalized_event_id:
        return 0
    events_path = _task_events_path(row)
    if not events_path.exists():
        return 0
    deleted = 0
    with task_events_file_lock(_task_root(row)):
        events: list[dict[str, object]] = []
        with events_path.open("r", encoding="utf-8") as source:
            for line_number, raw_line in enumerate(source, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    loaded = json.loads(line)
                    if isinstance(loaded, dict):
                        events.append(loaded)
                except Exception:
                    logger.exception("parse task event JSONL during delete failed: path=%s line=%s", events_path, line_number)
        kept: list[dict[str, object]] = []
        for event in events:
            if str(event.get("id") or "") == normalized_event_id:
                deleted += 1
                continue
            kept.append(event)
        if deleted <= 0:
            return 0
        tmp_path = events_path.with_suffix(events_path.suffix + f".{uuid.uuid4().hex}.tmp")
        with tmp_path.open("w", encoding="utf-8") as tmp_file:
            for event in kept:
                tmp_file.write(json.dumps(_json_safe(event), ensure_ascii=False, separators=(",", ":")) + "\n")
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_path, events_path)
    return deleted


def _record_task_event(
    db: Session,
    *,
    row: AppDvsTask,
    event_type: str,
    message: str,
    source: str = TASK_EVENT_SOURCE_DVS,
    level: str = "info",
    status: str | None = None,
    payload: dict[str, object] | None = None,
    worker_id: str | None = None,
    execution_owner_id: str | None = None,
    execution_epoch: int | None = None,
    control_version: int | None = None,
    dispatch_status: str | None = None,
    function_name: str | None = None,
    source_file: str | None = None,
    line_hint: str | None = None,
    origin: dict[str, object] | None = None,
) -> dict[str, object] | None:
    normalized_message = str(message or "").strip()
    normalized_status = str(status or row.status or "").strip() or None
    normalized_worker_id = str(worker_id or row.execution_owner_id or "").strip() or None
    normalized_owner_id = str(execution_owner_id or row.execution_owner_id or "").strip() or None
    normalized_dispatch_status = str(dispatch_status or row.dispatch_status or "").strip() or None
    normalized_function_name = str(function_name or (row.task_config_json or {}).get("function_name") or "").strip() or None
    normalized_source_file = str(source_file or (row.task_config_json or {}).get("source_file") or "").strip() or None
    normalized_line_hint = str(line_hint or (row.task_config_json or {}).get("line_hint") or "").strip() or None
    created_at = now_local()
    event: dict[str, object] = {
        "id": uuid.uuid4().hex[:32],
        "task_id": row.task_id,
        "project_id": row.project_id,
        "source": source,
        "level": level,
        "event_type": event_type,
        "status": normalized_status,
        "worker_id": normalized_worker_id,
        "execution_owner_id": normalized_owner_id,
        "execution_epoch": int(execution_epoch) if execution_epoch is not None else int(row.execution_epoch or 0),
        "control_version": int(control_version) if control_version is not None else int(row.control_version or 0),
        "dispatch_status": normalized_dispatch_status,
        "function_name": normalized_function_name,
        "source_file": normalized_source_file,
        "line_hint": normalized_line_hint,
        "parent_task_id": row.parent_task_id,
        "parent_stage_item_id": row.parent_stage_item_id,
        "message": normalized_message,
        "payload": _json_safe(_merge_task_event_recorder_payload(
            payload,
            origin=origin,
            worker_id=normalized_worker_id,
            execution_owner_id=normalized_owner_id,
        )),
        "created_at": isoformat_local(created_at),
    }
    try:
        append_task_event(row, event)
    except Exception:
        logger.exception("append task event failed: task_id=%s event_type=%s path=%s", row.task_id, event_type, _task_events_path(row))
        return None
    return event
