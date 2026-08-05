"""Task directory structure helpers — compute run/epoch/output paths from a DB row.

Also provides NFS-safe path resolution for API pods that need to read
runtime files while a Worker pod has replaced an epoch-local run directory
with a symlink to local storage (DVS_LOCAL_WORKSPACE_ENABLED).
"""

from __future__ import annotations

import hashlib, logging, os, shutil, sqlite3
from pathlib import Path

from app.db.models import AppDvsTask
from .file_access_logging import path_exists_logged, resolve_path_logged

logger = logging.getLogger("dvs.task_paths")

# MySQL URL (固定, 与 restart_task 一致)
_MYSQL_URL = "mysql+pymysql://root:Huawei12%23$@secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local:3306"

# NFS mirror directory name used by WorkspaceManager periodic sync
_NFS_MIRROR_DIR = ".run_nfs"


def _remove_output_preserving_task_events(task_root: Path, output_root: Path, *, reason: str) -> None:
    """Reset output artifacts while retaining the file-backed task timeline."""
    from app.service.task_events import task_events_file_lock

    events_path = output_root / "events.jsonl"
    preserved: list[tuple[Path, Path]] = []
    with task_events_file_lock(task_root):
        try:
            if events_path.exists():
                target = task_root / f".{events_path.name}.{os.getpid()}.preserve"
                shutil.move(str(events_path), str(target))
                preserved.append((target, events_path))
            shutil.rmtree(output_root)
            output_root.mkdir(parents=True, exist_ok=True)
        finally:
            for source, target in preserved:
                if source.exists():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(source), str(target))
    logger.info("task output reset with events.jsonl retained: root=%s reason=%s", task_root, reason)


def _task_root(row: AppDvsTask) -> Path | None:
    output_path = str(row.output_path or "").strip()
    if output_path:
        return resolve_path_logged(Path(output_path).expanduser(), logger=logger, purpose="task_paths.task_root.output_path") / row.task_id
    project_id = str(getattr(row, "project_id", "") or "").strip()
    if project_id:
        fileserver_root = os.environ.get("FILESERVER_ROOT", "/data/files")
        return Path(fileserver_root) / project_id / "app" / "secflow-app-dataflow-vuln-scan" / row.task_id
    return None


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


def resolve_live_vuln_scan_sqlite(task_root: Path | None) -> Path | None:
    if task_root is None:
        return None
    path = task_root / "run" / "vuln-scan.sqlite"
    return path if path_exists_logged(path, logger=logger, purpose="task_paths.live_vuln_sqlite") else None


def resolve_archived_vuln_scan_sqlite(task_root: Path | None) -> Path | None:
    if task_root is None:
        return None
    path = task_root / "output" / "vuln-scan.sqlite"
    return path if path_exists_logged(path, logger=logger, purpose="task_paths.archived_vuln_sqlite") else None


def resolve_authoritative_vuln_scan_sqlite(task_root: Path | None, *, prefer_live: bool = True) -> Path | None:
    primary = resolve_live_vuln_scan_sqlite(task_root) if prefer_live else resolve_archived_vuln_scan_sqlite(task_root)
    if primary is not None:
        return primary
    return resolve_archived_vuln_scan_sqlite(task_root) if prefer_live else resolve_live_vuln_scan_sqlite(task_root)


def open_authoritative_vuln_scan_store(
    task_root: Path | None,
    *,
    prefer_live: bool = True,
    # 默认只读、无 WAL: 这是读 helper, 谁都不应以写模式开 authoritative sqlite
    # (worker 以 WAL 写模式开 NFS run/vuln-scan.sqlite 曾导致
    # "database disk image is malformed"). 需要写的调用方自行用本地路径
    # 直接 new VulnScanStore(local_path).
    readonly: bool = True,
    enable_wal: bool = False,
):
    db_path = resolve_authoritative_vuln_scan_sqlite(task_root, prefer_live=prefer_live)
    if db_path is None:
        return None
    from app.vuln_store import VulnScanStore

    return VulnScanStore(
        db_path,
        readonly=readonly,
        enable_wal=enable_wal,
    )


def authoritative_task_vuln_stats(task_root: Path | None, task_id: str, *, prefer_live: bool = True) -> tuple[int, int, int] | None:
    normalized_task_id = str(task_id or "").strip()
    if not normalized_task_id:
        return None
    store = open_authoritative_vuln_scan_store(task_root, prefer_live=prefer_live)
    if store is None:
        return None
    try:
        findings = list(store.list_task_findings(normalized_task_id))
    except sqlite3.OperationalError as exc:
        logger.warning(
            "authoritative_task_vuln_stats skipped: sqlite unavailable during read task_id=%s task_root=%s error=%s",
            normalized_task_id,
            task_root,
            exc,
        )
        return None
    total = len(findings)
    reported = sum(1 for item in findings if str(item.get("report_status") or "") == "reported")
    return total, reported, max(0, total - reported)


def _resolve_run_path(row: AppDvsTask, relative: str = "") -> Path | None:
    """Resolve a path under run/ with NFS sync mirror fallback.

    When DVS_LOCAL_WORKSPACE_ENABLED is active on a Worker pod, the
    NFS run/epochs/NNNN/ directory is a symlink to local /tmp/.
    On API pods (different node), this symlink is broken.

    This function first checks if the primary path is accessible.
    If the requested target itself is unreadable and run/epochs contains
    broken symlinks (indicating active workspace redirection), it falls
    back to the .run_nfs/ mirror. Root-level compatibility files already
    synced back into run/ should keep using the primary path even if some
    epoch directories are broken symlinks.
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
    if path_exists_logged(epochs_dir, logger=logger, purpose="task_paths.epochs_dir_exists"):
        for entry in epochs_dir.iterdir():
            if entry.is_symlink() and not _path_readable(entry):
                has_broken_epoch_symlinks = True
                break

    # Root-level compatibility files in run/ stay authoritative once they are
    # synced back to NFS, even if some epoch dirs are broken symlinks.
    target_uses_epoch_subtree = "epochs" in target.parts

    if _path_readable(target) and (not has_broken_epoch_symlinks or not target_uses_epoch_subtree):
        return target

    # Fall back to .run_nfs mirror only when the requested target itself is not
    # readable. This keeps synced compatibility files on the primary run/
    # path and limits mirror use to genuinely unavailable epoch-local paths.
    if not _path_readable(target) and path_exists_logged(fallback, logger=logger, purpose="task_paths.fallback_exists"):
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
        return path_exists_logged(path, logger=logger, purpose="task_paths.path_readable")
    except OSError as e:
        logger.debug("path.exists check failed (broken symlink?): %s", e)
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


def latest_epoch_run_root_from_task_root(task_root: Path | None) -> Path | None:
    if task_root is None:
        return None
    run_root = task_root / "run"
    epochs_root = run_root / "epochs"
    if not path_exists_logged(epochs_root, logger=logger, purpose="task_paths.latest_epoch.exists"):
        return run_root
    candidates = [path for path in epochs_root.iterdir() if path.is_dir() and path.name.isdigit()]
    if not candidates:
        return run_root
    return sorted(candidates, key=lambda path: int(path.name))[-1]


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

    preserve_task_events = reason in {"restart", "stale_reset"}

    # 1. 删 NFS run/ + output/ 目录。restart/stale_reset 保留
    # output/events.jsonl 审计时间线，任务物理删除仍由上层删除整个任务目录。
    task_root = _task_root(row)
    if task_root is not None:
        try:
            from app.workspace_manager import WorkspaceManager
            WorkspaceManager.cleanup_temp_for_task(task_id)
        except Exception as e:
            logger.warning("workspace cleanup_temp_for_task failed (task=%s): %s", task_id, e, exc_info=True)
        for child_name in ("run", "output"):
            child = task_root / child_name
            if child.exists():
                try:
                    if child_name == "output" and preserve_task_events:
                        _remove_output_preserving_task_events(task_root, child, reason=reason)
                    else:
                        shutil.rmtree(child)
                        logger.info("cleanup_task_data: removed %s/ (%s)", child_name, reason)
                except Exception as exc:
                    logger.warning("cleanup_task_data: remove %s/ failed: %s", child_name, exc)

    # 2. MySQL 共享存储: 所有 mode 的任务表
    if source_root:
        try:
            from app.db.shared_mysql import create_shared_store
            for mode in ("complete", "autonomous", "dagflow"):
                ms = create_shared_store(
                    _MYSQL_URL, mode, source_root, task_id,
                    project_id=project_id,
                    parent_task_id=str(row.parent_task_id or ""),
                )
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

    logger.info("cleanup_task_data: task=%s reason=%s (run/output reset, MySQL cleared)", task_id, reason)
