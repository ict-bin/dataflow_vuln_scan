from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from .file_access_logging import read_json_logged, read_text_logged, stat_logged

logger = logging.getLogger("dvs.session_lineage_index")

_INDEX_FILENAME = "session-index.json"
_INDEX_VERSION = 2
_LOCK = threading.RLock()


def lineage_index_path(run_root: Path) -> Path:
    return Path(run_root) / _INDEX_FILENAME


def normalize_relative_path(path: str) -> str:
    return str(path or "").replace("\\", "/").strip().lstrip("/")


def session_relpath_for_run_root(run_root: Path, session_path: str | Path) -> str:
    session = Path(session_path)
    try:
        return normalize_relative_path(str(session.resolve().relative_to(Path(run_root).resolve())))
    except Exception:
        try:
            return normalize_relative_path(str(session.relative_to(Path(run_root))))
        except Exception:
            return normalize_relative_path(str(session))


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2))
            handle.flush()
            os.fsync(handle.fileno())
        Path(tmp_name).replace(path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def _default_payload(*, task_id: str, run_root: Path) -> dict[str, Any]:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {
        "version": _INDEX_VERSION,
        "generated_at": now,
        "task_id": str(task_id or "").strip(),
        "run_root": str(run_root),
        "sessions_root": str(Path(run_root) / "sessions"),
        "items": [],
    }


def load_lineage_index(run_root: Path, *, task_id: str = "") -> dict[str, Any]:
    path = lineage_index_path(run_root)
    if not path.exists():
        return _default_payload(task_id=task_id, run_root=run_root)
    try:
        payload = read_json_logged(path, logger=logger, purpose="session_lineage_index.load")
    except Exception as exc:
        logger.warning("failed to read lineage index %s: %s", str(path), exc, exc_info=True)
        return _default_payload(task_id=task_id, run_root=run_root)
    if not isinstance(payload, dict):
        return _default_payload(task_id=task_id, run_root=run_root)
    payload.setdefault("version", _INDEX_VERSION)
    payload.setdefault("generated_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    payload.setdefault("task_id", str(task_id or payload.get("task_id") or "").strip())
    payload.setdefault("run_root", str(run_root))
    payload.setdefault("sessions_root", str(Path(run_root) / "sessions"))
    items = payload.get("items")
    if not isinstance(items, list):
        payload["items"] = []
    return payload


def _session_file_stats(run_root: Path, session_relpath: str) -> tuple[float | None, int | None]:
    normalized = normalize_relative_path(session_relpath)
    if not normalized:
        return None, None
    target = Path(run_root) / normalized
    if not target.exists():
        logger.debug(
            "session_lineage_index session file not ready yet: run_root=%s session_relpath=%s",
            str(run_root),
            normalized,
        )
        return None, None
    try:
        stat = stat_logged(target, logger=logger, purpose="session_lineage_index.session_stat")
        line_count = len(read_text_logged(target, logger=logger, purpose="session_lineage_index.session_read", encoding="utf-8", errors="replace").splitlines())
        return float(stat.st_mtime), int(line_count)
    except Exception:
        return None, None


def normalize_session_index_item(item: dict[str, Any]) -> dict[str, Any]:
    relative_path = normalize_relative_path(str(item.get("session_relpath") or item.get("relative_path") or ""))
    relation_kind = str(item.get("relation_kind") or "").strip()
    parent_relative_path = normalize_relative_path(str(item.get("parent_session_relpath") or item.get("parent_relative_path") or ""))
    display_name = str(item.get("display_name") or item.get("session_name") or Path(relative_path or "session").stem).strip()
    status = str(item.get("status") or "unknown").strip()
    event_count = int(item.get("event_count") or 0)
    line_count = int(item.get("line_count") or event_count)
    findings_count = int(item.get("findings_count") or 0)
    mtime = float(item.get("mtime") or 0.0)
    role_name = str(item.get("role_name") or item.get("session_role") or item.get("session_kind") or "worker").strip()
    stage_group = str(item.get("stage_group") or item.get("node_id") or "root").strip()
    normalized = dict(item)
    normalized.update({
        "session_id": str(item.get("session_id") or relative_path).strip(),
        "session_name": str(item.get("session_name") or display_name).strip(),
        "session_relpath": relative_path,
        "relative_path": relative_path,
        "stage_group": stage_group,
        "role_name": role_name,
        "size": int(item.get("size") or 0),
        "mtime": mtime,
        "started_at": item.get("started_at"),
        "ended_at": item.get("ended_at"),
        "event_count": event_count,
        "line_count": line_count,
        "findings_count": findings_count,
        "is_active": bool(item.get("is_active")) if "is_active" in item else status == "running",
        "display_name": display_name,
        "warnings": list(item.get("warnings") or []),
        "status": status,
        "parent_session_relpath": parent_relative_path,
        "parent_relative_path": parent_relative_path or None,
        "relation_kind": relation_kind or None,
    })
    return normalized


def upsert_session_index_item(
    *,
    run_root: Path,
    task_id: str,
    session_relpath: str,
    parent_session_relpath: str = "",
    relation_kind: str = "",
    node_id: str = "",
    edge_id: str = "",
    session_role: str = "",
    session_kind: str = "",
    display_name: str = "",
    status: str = "unknown",
    started_at: str | None = None,
    ended_at: str | None = None,
) -> str:
    normalized_relpath = normalize_relative_path(session_relpath)
    normalized_parent = normalize_relative_path(parent_session_relpath)
    with _LOCK:
        payload = load_lineage_index(run_root, task_id=task_id)
        items = payload.setdefault("items", [])
        by_path = {
            normalize_relative_path(str(item.get("session_relpath") or "")): item
            for item in items
            if isinstance(item, dict)
        }
        item = by_path.get(normalized_relpath, {})
        mtime, event_count = _session_file_stats(run_root, normalized_relpath)
        item.update(normalize_session_index_item({
            "session_relpath": normalized_relpath,
            "parent_session_relpath": normalized_parent,
            "relation_kind": str(relation_kind or item.get("relation_kind") or "").strip(),
            "node_id": str(node_id or item.get("node_id") or "").strip(),
            "edge_id": str(edge_id or item.get("edge_id") or "").strip(),
            "session_role": str(session_role or item.get("session_role") or "").strip(),
            "session_kind": str(session_kind or item.get("session_kind") or "").strip(),
            "display_name": str(display_name or item.get("display_name") or Path(normalized_relpath).stem).strip(),
            "status": str(status or item.get("status") or "unknown").strip(),
            "started_at": started_at or item.get("started_at"),
            "ended_at": ended_at or item.get("ended_at"),
            "mtime": mtime if mtime is not None else item.get("mtime"),
            "event_count": event_count if event_count is not None else item.get("event_count", 0),
            "line_count": event_count if event_count is not None else item.get("line_count", item.get("event_count", 0)),
            "size": int(item.get("size") or 0),
            "warnings": item.get("warnings") or [],
        }))
        by_path[normalized_relpath] = item
        payload["task_id"] = str(task_id or payload.get("task_id") or "").strip()
        payload["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload["items"] = sorted(by_path.values(), key=lambda current: str(current.get("session_relpath") or ""))
        _write_json_atomic(lineage_index_path(run_root), payload)
    return normalized_relpath


def update_session_index_item(
    *,
    run_root: Path,
    task_id: str,
    session_relpath: str,
    status: str | None = None,
    ended_at: str | None = None,
    mtime: float | None = None,
    event_count: int | None = None,
    findings_count: int | None = None,
) -> str:
    normalized_relpath = normalize_relative_path(session_relpath)
    with _LOCK:
        payload = load_lineage_index(run_root, task_id=task_id)
        items = payload.setdefault("items", [])
        by_path = {
            normalize_relative_path(str(item.get("session_relpath") or "")): item
            for item in items
            if isinstance(item, dict)
        }
        item = by_path.get(normalized_relpath, {"session_relpath": normalized_relpath})
        fs_mtime, fs_event_count = _session_file_stats(run_root, normalized_relpath)
        if status is not None:
            item["status"] = str(status)
        if ended_at is not None:
            item["ended_at"] = ended_at
        item["mtime"] = mtime if mtime is not None else (fs_mtime if fs_mtime is not None else item.get("mtime"))
        item["event_count"] = event_count if event_count is not None else (fs_event_count if fs_event_count is not None else item.get("event_count", 0))
        item["line_count"] = item["event_count"]
        if findings_count is not None:
            item["findings_count"] = int(findings_count)
        item["is_active"] = str(item.get("status") or "") == "running"
        item = normalize_session_index_item(item)
        by_path[normalized_relpath] = item
        payload["task_id"] = str(task_id or payload.get("task_id") or "").strip()
        payload["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload["items"] = sorted(by_path.values(), key=lambda current: str(current.get("session_relpath") or ""))
        _write_json_atomic(lineage_index_path(run_root), payload)
    return normalized_relpath
