"""Task directory structure helpers — compute run/epoch/output paths from a DB row.

Also provides NFS-safe path resolution for API pods that need to read
session files while a Worker pod has replaced the NFS run/ directory with
a symlink to local storage (DVS_LOCAL_WORKSPACE_ENABLED).
"""

from __future__ import annotations

import hashlib, logging, shutil
from pathlib import Path

from app.db.models import AppDvsTask

logger = logging.getLogger("dvs.task_paths")

# MySQL URL (固定, 与 restart_task 一致)
_MYSQL_URL = "mysql+pymysql://root:Huawei12%23$@secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local:3306"

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


# ── 任务级清理: 清除该任务的所有关联数据 (restart/stale/运行前 都调) ──

def cleanup_task_data(row: AppDvsTask, *, reason: str = "cleanup") -> None:
    """清除该任务的所有任务关联数据 (公用表 functions 等不清)。

    清理范围:
    1. NFS run/ + output/ 目录 (SQLite dagflow.db, vuln-scan.sqlite, sessions)
    2. MySQL 共享存储: 所有 mode 的任务表 (V2 + DAG)
    3. MySQL graph store: task_graph_* + findings
    """
    task_id = str(row.task_id or "")
    source_root = _task_source_root(row)
    project_id = str(row.project_id or "")

    # 1. 删 NFS run/ + output/ 目录
    task_root = _task_root(row)
    if task_root is not None:
        try:
            from app.service.workspace_manager import WorkspaceManager
            WorkspaceManager.cleanup_temp_for_task(task_id)
        except Exception:
            pass
        for child_name in ("run", "output"):
            child = task_root / child_name
            if child.exists():
                try:
                    shutil.rmtree(child)
                    logger.info("cleanup_task_data: removed %s/ (%s)", child_name, reason)
                except Exception as exc:
                    logger.warning("cleanup_task_data: remove %s/ failed: %s", child_name, exc)

    # 2. MySQL 共享存储: 所有 mode 的任务表
    if source_root:
        try:
            from app.db.shared_mysql import create_shared_store
            for mode in ("complete", "autonomous", "dagflow"):
                ms = create_shared_store(_MYSQL_URL, mode, source_root, task_id, project_id=project_id)
                if ms:
                    ms.clear_task_analysis()
        except Exception as e:
            logger.warning("cleanup_task_data: MySQL shared store cleanup failed: %s", e)

    # 3. MySQL graph store: task_graph_* + findings
    try:
        from app.db.mysql_graph_store import create_mysql_graph_store
        _sid = hashlib.sha1(source_root.encode("utf-8")).hexdigest()[:16] if source_root else ""
        mgs = create_mysql_graph_store(_MYSQL_URL, project_id=project_id,
                                       source_dir_id=_sid, source_root=source_root)
        if mgs:
            mgs.clear_task(task_id)
    except Exception as e:
        logger.warning("cleanup_task_data: MySQL graph store cleanup failed: %s", e)

    logger.info("cleanup_task_data: task=%s reason=%s (run/+output/ removed, MySQL cleared)", task_id, reason)
