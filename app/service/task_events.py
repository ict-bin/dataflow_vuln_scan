"""Task event recording, deduplication, and serialization helpers."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import AppDvsTask, AppDvsTaskEvent
from app.time_utils import isoformat_local

logger = logging.getLogger("dvs.task_events")

TASK_EVENT_SOURCE_DVS = "dvs"


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


def _build_task_event_response(event: AppDvsTaskEvent) -> dict[str, object]:
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
        "created_at": isoformat_local(event.created_at),
    }


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
    event.payload = _compact_event_payload(payload or {})
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
    return event
