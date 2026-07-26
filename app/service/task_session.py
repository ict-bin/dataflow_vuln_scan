"""Task session file parsing, catalog building, and atomic write helpers."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path

from app.db.models import AppDvsTask
from .file_access_logging import path_exists_logged, path_is_file_logged, read_text_logged, resolve_path_logged

logger = logging.getLogger("dvs.task_session")


def _write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2))
            handle.flush()
            os.fsync(handle.fileno())
        Path(tmp_name).replace(path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError as e:
            logger.debug("unlink tmp already gone: %s", e)
        raise


def _safe_session_file(root: Path, relative_path: str) -> Path:
    rel = Path(relative_path)
    if rel.is_absolute() or ".." in rel.parts:
        from fastapi import HTTPException
        raise HTTPException(400, "非法会话路径")
    output_root = resolve_path_logged(root / "output", logger=logger, purpose="task_session.output_root")
    target = resolve_path_logged(output_root / rel, logger=logger, purpose="task_session.target_path")
    try:
        target.relative_to(output_root)
    except ValueError:
        from fastapi import HTTPException
        raise HTTPException(400, "非法会话路径")
    if target.suffix != ".jsonl":
        from fastapi import HTTPException
        raise HTTPException(400, "仅支持 jsonl 会话文件")
    return target


def _path_accessible(path: Path) -> bool:
    try:
        return path.exists()
    except OSError as e:
        logger.debug("session path.exists check failed: %s", e)
        return False


def _parse_session_file(path: Path) -> dict[str, object]:
    events: list[dict[str, object]] = []
    warnings: list[str] = []
    session_meta: dict[str, object] | None = None
    if not path_exists_logged(path, logger=logger, purpose="task_session.parse.exists") or not path_is_file_logged(path, logger=logger, purpose="task_session.parse.is_file"):
        from fastapi import HTTPException
        raise HTTPException(404, "会话文件不存在")
    try:
        lines = read_text_logged(path, logger=logger, purpose="task_session.parse.read", encoding="utf-8", errors="replace").splitlines()
    except Exception as exc:
        logger.warning("failed to read session file: path=%s error=%s", str(path), exc, exc_info=True)
        from fastapi import HTTPException
        raise HTTPException(500, "读取会话文件失败")
    for index, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception as e:
            logger.debug("parse session line json failed (line %d): %s", index, e)
            warnings.append(f"第 {index} 行 JSON 解析失败")
            events.append({"type": "raw", "event_index": index, "line": index, "raw_line": line[:500], "summary": line[:200]})
            continue
        if isinstance(obj, dict) and obj.get("type") == "session":
            session_meta = obj
            continue
        if not isinstance(obj, dict):
            warnings.append(f"第 {index} 行不是 JSON 对象")
            continue
        obj.setdefault("event_index", index)
        obj.setdefault("line", index)
        obj.setdefault("raw_line", line)
        events.append(obj)
    return {
        "events": events,
        "warnings": warnings,
        "session_meta": session_meta,
        "line_count": len(lines),
    }


def _build_task_session_catalog(row: AppDvsTask) -> dict[str, object]:
    from .session_lineage_index import lineage_index_path, load_lineage_index, normalize_relative_path, normalize_session_index_item
    from .task_paths import _latest_epoch_run_root, _resolve_run_path, _task_output_sessions_root, _task_root
    from .task_result import _load_task_result_json
    from .session_index import build_session_catalog

    run_root = _resolve_run_path(row) or _latest_epoch_run_root(row)
    if run_root is not None:
        authority_index_path = lineage_index_path(run_root)
        if path_exists_logged(authority_index_path, logger=logger, purpose="task_session.authority_index.exists"):
            lineage = load_lineage_index(run_root, task_id=row.task_id)
            items = lineage.get("items") if isinstance(lineage, dict) else []
            normalized_items = [normalize_session_index_item(item) for item in items if isinstance(item, dict)]
            session_items: list[dict[str, object]] = []
            nodes: list[dict[str, object]] = []
            edges: list[dict[str, object]] = []
            warnings: list[str] = []
            session_count = 0
            active_count = 0
            relation_count = 0
            seen_edge_ids: set[str] = set()
            for item in normalized_items:
                relative_path = normalize_relative_path(str(item.get("session_relpath") or ""))
                if not relative_path:
                    continue
                session_count += 1
                status = str(item.get("status") or "unknown")
                is_active = status == "running"
                if is_active:
                    active_count += 1
                relation_kind = str(item.get("relation_kind") or "").strip()
                parent_relative_path = normalize_relative_path(str(item.get("parent_session_relpath") or item.get("parent_relative_path") or ""))
                display_name = str(item.get("display_name") or Path(relative_path).stem)
                session_name = str(item.get("session_name") or display_name)
                stage_group = str(item.get("stage_group") or item.get("node_id") or "root")
                session_items.append({
                    "session_id": str(item.get("session_id") or relative_path),
                    "session_name": session_name,
                    "relative_path": relative_path,
                    "stage_group": stage_group,
                    "role_name": str(item.get("role_name") or item.get("session_role") or item.get("session_kind") or "worker"),
                    "size": int(item.get("size") or 0),
                    "mtime": float(item.get("mtime") or 0.0),
                    "started_at": item.get("started_at"),
                    "ended_at": item.get("ended_at"),
                    "event_count": int(item.get("event_count") or 0),
                    "line_count": int(item.get("line_count") or item.get("event_count") or 0),
                    "findings_count": int(item.get("findings_count") or 0),
                    "is_active": bool(item.get("is_active")) if "is_active" in item else is_active,
                    "display_name": display_name,
                    "warnings": list(item.get("warnings") or []),
                    "status": status,
                    "parent_relative_path": parent_relative_path or None,
                    "relation_kind": relation_kind or None,
                })
                node = {
                    "node_id": relative_path,
                    "relative_path": relative_path,
                    "session_name": session_name,
                    "display_name": display_name,
                    "role": str(item.get("session_kind") or item.get("session_role") or "worker"),
                    "role_label": str(item.get("session_role") or item.get("session_kind") or "worker"),
                    "status": status,
                    "is_active": is_active,
                    "stage_key": "worker",
                    "stage_label": "数据流漏洞挖掘",
                    "stage_order": 10,
                    "stage_group": stage_group,
                    "module_name": None,
                    "parent_relative_path": parent_relative_path or None,
                    "relation_kind": relation_kind or None,
                    "flow_kind": "lineage",
                    "started_at": item.get("started_at"),
                    "ended_at": item.get("ended_at"),
                    "started_ts": None,
                    "last_event_at": item.get("ended_at") or item.get("started_at"),
                    "last_event_ts": None,
                    "mtime": float(item.get("mtime") or 0.0),
                    "size": 0,
                    "event_count": int(item.get("event_count") or 0),
                    "line_count": int(item.get("event_count") or 0),
                    "findings_count": int(item.get("findings_count") or 0),
                    "warnings": [],
                    "session_header": {
                        "node_id": item.get("node_id") or "",
                        "edge_id": item.get("edge_id") or "",
                        "session_kind": item.get("session_kind") or "",
                        "relation_kind": relation_kind or "",
                    },
                    "round_refs": [],
                    "attempts_seen": [],
                }
                nodes.append(node)
                if parent_relative_path:
                    edge_id = f"{relation_kind or 'fork'}:{parent_relative_path}->{relative_path}"
                    if edge_id not in seen_edge_ids:
                        seen_edge_ids.add(edge_id)
                        edges.append({
                            "edge_id": edge_id,
                            "source_node_id": parent_relative_path,
                            "target_node_id": relative_path,
                            "kind": relation_kind or "fork",
                            "label": relation_kind or "fork",
                        })
                        relation_count += 1
            return {
                "task_id": row.task_id,
                "status": row.status,
                "sessions_root": str(run_root / "sessions"),
                "index_path": str(authority_index_path),
                "generated_at": lineage.get("generated_at"),
                "items": session_items,
                "index": {
                    "version": lineage.get("version") or 2,
                    "generated_at": lineage.get("generated_at"),
                    "task_id": row.task_id,
                    "task_status": row.status,
                    "sessions_root": str(run_root / "sessions"),
                    "summary": {
                        "session_count": session_count,
                        "active_session_count": active_count,
                        "edge_count": relation_count,
                    },
                    "nodes": nodes,
                    "edges": edges,
                    "groups": [],
                    "warnings": warnings,
                },
            }
        logger.info(
            "authoritative session lineage index missing, fallback to legacy catalog: task_id=%s path=%s",
            row.task_id,
            str(authority_index_path),
        )

    root = _task_root(row)
    sessions_root = _task_output_sessions_root(row) or (root / "output" / "sessions" if root else Path())
    if not sessions_root.exists():
        return {
            "task_id": row.task_id,
            "status": row.status,
            "sessions_root": str(sessions_root),
            "index_path": str(sessions_root / "index.json"),
            "generated_at": None,
            "items": [],
            "index": {
                "version": 1,
                "generated_at": None,
                "task_id": row.task_id,
                "task_status": row.status,
                "sessions_root": str(sessions_root),
                "summary": {},
                "nodes": [],
                "edges": [],
                "groups": [],
                "warnings": [],
            },
        }
    result_json = _load_task_result_json(row)
    return build_session_catalog(
        task_id=row.task_id,
        row_status=row.status,
        sessions_root=sessions_root,
        result_json=result_json,
        write_json_atomic=_write_json_atomic,
    )
