"""Task directory structure helpers — compute run/epoch/output paths from a DB row."""

from __future__ import annotations

from pathlib import Path

from app.db.models import AppDvsTask


def _task_root(row: AppDvsTask) -> Path | None:
    if not row.output_path:
        return None
    return Path(row.output_path) / row.task_id


def _task_run_root(row: AppDvsTask) -> Path | None:
    root = _task_root(row)
    return root / "run" if root else None


def _task_epoch_run_root(row: AppDvsTask, epoch: int) -> Path | None:
    root = _task_run_root(row)
    if root is None:
        return None
    return root / "epochs" / f"{int(epoch):04d}"


def _task_result_path(row: AppDvsTask) -> Path | None:
    run_root = _task_run_root(row)
    return run_root / "result.json" if run_root else None


def _latest_epoch_run_root(row: AppDvsTask) -> Path | None:
    run_root = _task_run_root(row)
    if run_root is None:
        return None
    epochs_root = run_root / "epochs"
    if not epochs_root.is_dir():
        return run_root
    candidates = sorted([path for path in epochs_root.iterdir() if path.is_dir()], key=lambda path: path.name)
    return candidates[-1] if candidates else run_root


def _epoch_label_from_path(path: Path | None) -> str | None:
    if path is None:
        return None
    parts = path.parts
    if "epochs" in parts:
        idx = parts.index("epochs")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None
