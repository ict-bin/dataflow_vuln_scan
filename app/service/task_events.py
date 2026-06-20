"""Task event recording, deduplication, and serialization helpers."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import AppDvsTask, AppDvsTaskEvent
from app.time_utils import isoformat_local

logger = logging.getLogger("dvs.task_events")

TASK_EVENT_SOURCE_DVS = "dvs"
DB_TIMELINE_EVENT_LIMIT = 10_000
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


def _fit_event_message(raw: object, *, limit: int = 400) -> str:
    text = str(raw or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[: limit - 1]}…"


def _event_payload_preview_value(value: object, *, limit: int = 240) -> object:
    if isinstance(value, str):
        return value if len(value) <= limit else f"{value[: limit - 1]}…"
    if isinstance(value, list):
        return [_event_payload_preview_value(item, limit=80) for item in value[:10]]
    if isinstance(value, dict):
        compact: dict[str, object] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 12:
                break
            compact[str(key)] = _event_payload_preview_value(item, limit=120)
        return compact
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _fit_event_message(value, limit=limit)


def _compact_event_payload(payload: dict[str, object] | None) -> dict[str, object]:
    compact: dict[str, object] = {}
    for key, value in (payload or {}).items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            compact[key] = _event_payload_preview_value(value)
        elif isinstance(value, list):
            compact[f"{key}_count"] = len(value)
            compact[key] = _event_payload_preview_value(value)
        elif isinstance(value, dict):
            compact[key] = _event_payload_preview_value(value)
        else:
            compact[key] = _fit_event_message(value)
    return compact


def _task_event_dedupe_key(
    task_id: str,
    event_type: str,
    status: str | None,
    message: str,
    *,
    epoch: int | None = None,
    function_name: str | None = None,
    dispatch_status: str | None = None,
    line_hint: str | None = None,
) -> str:
    parts = [
        task_id,
        event_type,
        str(status or ""),
        str(epoch or ""),
        str(function_name or ""),
        str(dispatch_status or ""),
        str(line_hint or ""),
        hashlib.sha1(message.encode("utf-8")).hexdigest()[:12],
    ]
    return "::".join(parts)[:255]


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


def _build_task_event_response(event: AppDvsTaskEvent) -> dict[str, object]:
    recorder = _timeline_party_from_payload(event.payload, "recorder") or {}
    origin = _timeline_party_from_payload(event.payload, "event_origin") or {}
    return {
        "id": event.id,
        "task_id": event.task_id,
        "project_id": event.project_id,
        "source": event.source,
        "level": event.level,
        "event_type": event.event_type,
        "status": event.status,
        "worker_id": event.worker_id,
        "execution_owner_id": event.execution_owner_id,
        "execution_epoch": event.execution_epoch,
        "control_version": event.control_version,
        "dispatch_status": event.dispatch_status,
        "function_name": event.function_name,
        "source_file": event.source_file,
        "line_hint": event.line_hint,
        "parent_task_id": event.parent_task_id,
        "parent_stage_item_id": event.parent_stage_item_id,
        "message": event.message,
        "payload": event.payload,
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
        "created_at": isoformat_local(event.created_at),
    }


def _trim_task_timeline_events(db: Session, task_id: str, *, limit: int | None = None) -> int:
    normalized_limit = max(0, int(DB_TIMELINE_EVENT_LIMIT if limit is None else limit))
    if normalized_limit <= 0:
        return 0
    total = int(
        db.query(AppDvsTaskEvent)
        .filter(AppDvsTaskEvent.task_id == task_id)
        .count()
        or 0
    )
    trim_count = max(0, total - normalized_limit)
    if trim_count <= 0:
        return 0
    old_event_ids = [
        row.id
        for row in (
            db.query(AppDvsTaskEvent.id)
            .filter(AppDvsTaskEvent.task_id == task_id)
            .order_by(AppDvsTaskEvent.created_at.asc(), AppDvsTaskEvent.id.asc())
            .limit(trim_count)
            .all()
        )
    ]
    if not old_event_ids:
        return 0
    deleted = (
        db.query(AppDvsTaskEvent)
        .filter(AppDvsTaskEvent.id.in_(old_event_ids))
        .delete(synchronize_session=False)
    )
    return int(deleted or 0)


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
    dedupe_key: str | None = None,
) -> AppDvsTaskEvent | None:
    normalized_message = _fit_event_message(message, limit=1000)
    normalized_status = str(status or row.status or "").strip() or None
    normalized_worker_id = str(worker_id or row.execution_owner_id or "").strip() or None
    normalized_owner_id = str(execution_owner_id or row.execution_owner_id or "").strip() or None
    normalized_dispatch_status = str(dispatch_status or row.dispatch_status or "").strip() or None
    normalized_function_name = str(function_name or (row.task_config_json or {}).get("function_name") or "").strip() or None
    normalized_source_file = str(source_file or (row.task_config_json or {}).get("source_file") or "").strip() or None
    normalized_line_hint = str(line_hint or (row.task_config_json or {}).get("line_hint") or "").strip() or None
    event_dedupe_key = dedupe_key or _task_event_dedupe_key(
        row.task_id,
        event_type,
        normalized_status,
        normalized_message,
        epoch=execution_epoch or int(row.execution_epoch or 0),
        function_name=normalized_function_name,
        dispatch_status=normalized_dispatch_status,
        line_hint=normalized_line_hint,
    )
    existing = db.query(AppDvsTaskEvent).filter(AppDvsTaskEvent.dedupe_key == event_dedupe_key).first()
    if existing is not None:
        return existing
    event = AppDvsTaskEvent(
        id=uuid.uuid4().hex[:32],
        task_id=row.task_id,
        project_id=row.project_id,
        source=source,
        level=level,
        event_type=event_type,
        status=normalized_status,
        worker_id=normalized_worker_id,
        execution_owner_id=normalized_owner_id,
        execution_epoch=int(execution_epoch) if execution_epoch is not None else int(row.execution_epoch or 0),
        control_version=int(control_version) if control_version is not None else int(row.control_version or 0),
        dispatch_status=normalized_dispatch_status,
        function_name=normalized_function_name,
        source_file=normalized_source_file,
        line_hint=normalized_line_hint,
        parent_task_id=row.parent_task_id,
        parent_stage_item_id=row.parent_stage_item_id,
        message=normalized_message,
        dedupe_key=event_dedupe_key,
    )
    event.payload = _compact_event_payload(
        _merge_task_event_recorder_payload(
            payload,
            origin=origin,
            worker_id=normalized_worker_id,
            execution_owner_id=normalized_owner_id,
        )
    )
    db.add(event)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        logger.warning(
            "dvs task event dedupe conflict ignored: task_id=%s event_type=%s dedupe_key=%s",
            row.task_id,
            event_type,
            event_dedupe_key,
        )
        return db.query(AppDvsTaskEvent).filter(AppDvsTaskEvent.dedupe_key == event_dedupe_key).first()
    _trim_task_timeline_events(db, row.task_id)
    return event
