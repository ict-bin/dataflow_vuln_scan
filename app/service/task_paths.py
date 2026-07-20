"""Task directory structure helpers — compute run/epoch/output paths from a DB row.

Also provides NFS-safe path resolution for API pods that need to read
session files while a Worker pod has replaced the NFS run/ directory with
a symlink to local storage (DVS_LOCAL_WORKSPACE_ENABLED).
"""

from __future__ import annotations

import logging
from pathlib import Path

from app.db.models import AppDvsTask

logger = logging.getLogger("dvs.task_paths")

# NFS mirror directory name used by WorkspaceManager periodic sync
_NFS_MIRROR_DIR = ".run_nfs"


def _task_root(row: AppDvsTask) -> Path | None:
    if not row.output_path:
        return None
    return Path(row.output_path) / row.task_id


def _task_source_root(row: AppDvsTask) -> str:
    """任务的源码根目录 (用于 MySQL 共享存储 source_dir_id)。"""
    return str(row.source_root_path or row.input_path or "")


def _task_run_root(row: AppDvsTask) -> Path | None:
    root = _task_root(row)
    return root / "run" if root else None


def _task_output_root(row: AppDvsTask) -> Path | None:
    root = _task_root(row)
    return root / "output" if root else None


def _task_output_sessions_root(row: AppDvsTask) -> Path | None:
    output_root = _task_output_root(row)
    return output_root / "sessions" if output_root else None


def _resolve_run_path(row: AppDvsTask, relative: str = "") -> Path | None:
    """Resolve a path under run/ with NFS sync mirror fallback.

    When DVS_LOCAL_WORKSPACE_ENABLED is active on a Worker pod, the
    NFS run/epochs/NNNN/ directory is a symlink to local /tmp/.
    On API pods (different node), this symlink is broken.

    This function first checks if the primary path is accessible.
    If the primary run/ directory exists but its epochs/ subdirectory
    contains broken symlinks (indicating active workspace redirection),
    it falls back to the .run_nfs/ mirror.
    """
    root = _task_root(row)
    if root is None:
        return None

    primary = _task_run_root(row)
    if primary is None:
        return None

    target = primary / relative if relative else primary
    fallback = root / _NFS_MIRROR_DIR / relative if relative else root / _NFS_MIRROR_DIR

    # Check if epochs/ contains broken symlinks -> workspace is redirected
    epochs_dir = primary / "epochs"
    has_broken_epoch_symlinks = False
    if epochs_dir.exists():
        for entry in epochs_dir.iterdir():
            if entry.is_symlink() and not _path_readable(entry):
                has_broken_epoch_symlinks = True
                break

    # Use primary path only if it's readable AND epochs are not broken
    if _path_readable(target) and not has_broken_epoch_symlinks:
        return target

    # Fall back to .run_nfs mirror
    if fallback.exists():
        logger.debug(
            "_resolve_run_path: primary %s has broken epoch symlinks, "
            "falling back to %s",
            str(target), str(fallback),
        )
        return fallback

    # Neither works — return primary (caller gets a clean error)
    return target


def _path_readable(path: Path) -> bool:
    """Check if a path exists and is readable, handling broken symlinks.

    Path.exists() returns False for broken symlinks. This is sufficient
    because a symlink to local /tmp on a different pod IS broken.
    """
    try:
        return path.exists()
    except OSError:
        return False


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
