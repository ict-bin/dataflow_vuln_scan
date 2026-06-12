"""Task session file parsing, catalog building, and atomic write helpers."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path

from app.db.models import AppDvsTask

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
        except FileNotFoundError:
            pass
        raise


def _safe_session_file(root: Path, relative_path: str) -> Path:
    rel = Path(relative_path)
    if rel.is_absolute() or ".." in rel.parts:
        from fastapi import HTTPException
        raise HTTPException(400, "非法会话路径")
    run_root = (root / "run").resolve()
    target = (run_root / rel).resolve()
    try:
        target.relative_to(run_root)
    except ValueError:
        from fastapi import HTTPException
        raise HTTPException(400, "非法会话路径")
    if target.suffix != ".jsonl":
        from fastapi import HTTPException
        raise HTTPException(400, "仅支持 jsonl 会话文件")
    return target


def _parse_session_file(path: Path) -> dict[str, object]:
    events: list[dict[str, object]] = []
    warnings: list[str] = []
    session_meta: dict[str, object] | None = None
    if not path.exists() or not path.is_file():
        from fastapi import HTTPException
        raise HTTPException(404, "会话文件不存在")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for index, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
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
    from .task_paths import _task_root
    from .task_result import _load_task_result_json
    from .session_index import build_session_catalog

    root = _task_root(row)
    run_root = root / "run" if str(root) else Path()
    if not run_root.exists():
        return {
            "task_id": row.task_id,
            "status": row.status,
            "sessions_root": str(run_root / "sessions"),
            "index_path": str(run_root / "sessions" / "index.json"),
            "generated_at": None,
            "items": [],
            "index": {
                "version": 1,
                "generated_at": None,
                "task_id": row.task_id,
                "task_status": row.status,
                "sessions_root": str(run_root / "sessions"),
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
        run_root=run_root,
        result_json=result_json,
        write_json_atomic=_write_json_atomic,
    )
