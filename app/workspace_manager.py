"""
Pod-local workspace manager for NFS IO timeout mitigation.

Strategy (minimal code change):
  1. On task start: create a pod-local temp workspace under
     DVS_LOCAL_WORKSPACE_ROOT (default /tmp/dvs_workspace/{task_id})
  2. Replace the NFS target directory with a symlink pointing to local storage,
     so the orchestrator writes all hot-path files (sessions, SQLite, temp) locally.
  3. On task completion/cancel/error: sync files back to NFS, replace symlink
     with the real directory containing the synced files.
  4. On task restart/cleanup: clear the local temp directory to prevent
     cross-task contamination.

Environment variables:
  DVS_LOCAL_WORKSPACE_ENABLED  "true" (default) / "false" — toggle entirely
  DVS_LOCAL_WORKSPACE_ROOT     "/tmp/dvs_workspace" (default) — base directory
  DVS_LOCAL_WORKSPACE_SYNC_INTERVAL  60 (default seconds) — periodic sync interval

Thread safety: one task per worker pod → no concurrent access to same temp dir.
"""

from __future__ import annotations

import logging
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Callable

logger = logging.getLogger("dvs.workspace_manager")


def _is_enabled() -> bool:
    raw = str(os.environ.get("DVS_LOCAL_WORKSPACE_ENABLED", "true")).strip().lower()
    return raw not in {"0", "false", "no", "off", "disabled"}


def _local_root() -> Path:
    return Path(os.environ.get("DVS_LOCAL_WORKSPACE_ROOT", "/tmp/dvs_workspace"))


def _sync_interval() -> float:
    try:
        return max(5.0, float(os.environ.get("DVS_LOCAL_WORKSPACE_SYNC_INTERVAL", "60")))
    except (TypeError, ValueError):
        return 60.0


class WorkspaceManager:
    """Manages a single task's local workspace lifecycle."""

    def __init__(self) -> None:
        self._task_id: str = ""
        self._epoch: int = 0
        self._nfs_run_root: Path | None = None   # Original NFS path (e.g. {output}/{task_id}/run/)
        self._local_run_root: Path | None = None  # Local temp copy
        self._stop_event = threading.Event()
        self._sync_thread: threading.Thread | None = None
        self._on_event: Callable | None = None
        self._enabled = _is_enabled()

    # ── public API ──────────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def task_id(self) -> str:
        return self._task_id

    @property
    def local_run_root(self) -> Path | None:
        return self._local_run_root

    def setup(
        self,
        *,
        task_id: str,
        epoch: int,
        nfs_run_root: Path,
        on_event: Callable | None = None,
    ) -> Path:
        """Prepare pod-local workspace and replace NFS path with a symlink.

        Returns the actual run root path to use (local if enabled, NFS otherwise).
        """
        self._task_id = task_id
        self._epoch = epoch
        self._nfs_run_root = Path(nfs_run_root)
        self._on_event = on_event

        if not self._enabled:
            logger.info(
                "workspace_manager: local workspace disabled, using NFS directly "
                "run_root=%s", str(self._nfs_run_root),
            )
            self._nfs_run_root.mkdir(parents=True, exist_ok=True)
            return self._nfs_run_root

        _local_root().mkdir(parents=True, exist_ok=True)
        self._local_run_root = _local_root() / f"{task_id}_epoch{epoch}"
        self._local_run_root.mkdir(parents=True, exist_ok=True)

        # If NFS path already exists and is a symlink (stale from previous crash),
        # remove it. If it's a real directory (first run), archive contents to
        # local first, then replace with symlink.
        if self._nfs_run_root.is_symlink():
            logger.warning(
                "workspace_manager: stale symlink detected at %s, removing",
                str(self._nfs_run_root),
            )
            self._nfs_run_root.unlink()
        elif self._nfs_run_root.is_dir():
            # Move any existing content to local, then remove the empty dir
            if any(self._nfs_run_root.iterdir()):
                logger.info(
                    "workspace_manager: moving existing content from %s to %s",
                    str(self._nfs_run_root), str(self._local_run_root),
                )
                _move_contents(self._nfs_run_root, self._local_run_root)
            # Remove the NFS directory so we can create the symlink
            try:
                self._nfs_run_root.rmdir()
            except OSError:
                shutil.rmtree(str(self._nfs_run_root), ignore_errors=True)

        # Create the symlink: NFS path → local path
        try:
            self._nfs_run_root.symlink_to(
                str(self._local_run_root), target_is_directory=True,
            )
            logger.info(
                "workspace_manager: symlink created %s → %s",
                str(self._nfs_run_root), str(self._local_run_root),
            )
        except OSError as exc:
            logger.error(
                "workspace_manager: symlink failed %s → %s: %s, falling back to NFS",
                str(self._nfs_run_root), str(self._local_run_root), exc,
            )
            self._enabled = False
            self._nfs_run_root.mkdir(parents=True, exist_ok=True)
            return self._nfs_run_root

        if self._on_event:
            self._on_event("workspace_localized", task_id=task_id,
                           nfs_path=str(self._nfs_run_root),
                           local_path=str(self._local_run_root))

        return self._local_run_root

    def start_periodic_sync(self) -> None:
        """Start a background thread that periodically syncs session files
        to NFS so the API pods (which read from NFS) can serve them to the
        frontend during task execution.

        Sessions now sync directly to {task_root}/output/sessions so the
        frontend and terminal-state readers use the same authoritative path.
        The legacy run/sessions mirror remains best-effort temporary state and
        is cleaned on task completion.
        """
        if not self._enabled or self._local_run_root is None or self._nfs_run_root is None:
            return
        self._stop_event.clear()
        self._sync_thread = threading.Thread(
            target=self._periodic_sync_loop,
            name=f"dvs_ws_sync_{self._task_id}",
            daemon=True,
        )
        self._sync_thread.start()

    def stop_periodic_sync(self) -> None:
        self._stop_event.set()
        if self._sync_thread and self._sync_thread.is_alive():
            self._sync_thread.join(timeout=10.0)

    def sync_back_and_cleanup(
        self,
        *,
        status: str = "completed",
        archive: bool = True,
    ) -> None:
        """Sync all files back to NFS, replace symlink with real directory,
        and remove the pod-local temp workspace.

        Called in the finally block of _execute_task.
        """
        self.stop_periodic_sync()

        if not self._enabled or self._local_run_root is None or self._nfs_run_root is None:
            logger.info(
                "workspace_manager: skip sync_back (enabled=%s local=%s nfs=%s)",
                self._enabled,
                str(self._local_run_root) if self._local_run_root else None,
                str(self._nfs_run_root) if self._nfs_run_root else None,
            )
            # Clean up .run_nfs staging directory even if we skip
            _mirror = self._nfs_run_root.parent / ".run_nfs" if self._nfs_run_root else None
            if _mirror and _mirror.exists():
                shutil.rmtree(str(_mirror), ignore_errors=True)
            return

        try:
            if not self._local_run_root.exists():
                logger.warning(
                    "workspace_manager: local run root missing: %s",
                    str(self._local_run_root),
                )
                # Try to restore
                if self._nfs_run_root.is_symlink():
                    self._nfs_run_root.unlink(missing_ok=True)
                self._nfs_run_root.mkdir(parents=True, exist_ok=True)
                return

            # Do a final sync (rsync-style copy)
            self._sync_to_nfs(self._local_run_root, self._nfs_run_root)

            # Clean up .run_nfs staging directory (periodic sync leftover)
            _mirror = self._nfs_run_root.parent / ".run_nfs"
            if _mirror.exists():
                shutil.rmtree(str(_mirror), ignore_errors=True)
                logger.info("workspace_manager: cleaned staging dir %s", str(_mirror))
            # Clean up the NFS run/sessions/ temp copies (periodic sync wrote here)
            _nfs_sessions = self._nfs_run_root.parent.parent / "sessions"
            if _nfs_sessions.exists() and _nfs_sessions.is_dir():
                shutil.rmtree(str(_nfs_sessions), ignore_errors=True)
                logger.info("workspace_manager: cleaned run/sessions temp copies %s", str(_nfs_sessions))

            # Clean up old epoch directories on NFS (only keep current epoch)
            _epochs_dir = self._nfs_run_root.parent  # epochs/
            if _epochs_dir.is_dir():
                _current_epoch_name = self._nfs_run_root.name  # e.g. 0006
                for _entry in _epochs_dir.iterdir():
                    if _entry.name != _current_epoch_name and _entry.is_dir():
                        shutil.rmtree(str(_entry), ignore_errors=True)
                        logger.info(
                            "workspace_manager: cleaned old epoch dir %s",
                            str(_entry),
                        )

            logger.info(
                "workspace_manager: final sync completed %s status=%s",
                str(self._nfs_run_root), status,
            )

            if self._on_event:
                self._on_event(
                    "workspace_synced",
                    task_id=self._task_id,
                    nfs_path=str(self._nfs_run_root),
                    local_path=str(self._local_run_root),
                    status=status,
                )
        except Exception as exc:
            logger.error(
                "workspace_manager: sync_back failed: %s", exc, exc_info=True,
            )
        finally:
            # Clean up the local temp directory (with retries)
            if self._local_run_root and self._local_run_root.exists():
                _cleanup_local_temp(self._local_run_root)
            # Also clean up any other /tmp workspace for this task (all epochs)
            # in case previous runs left leftovers
            try:
                _local_root_path = _local_root()
                for _pattern in [f"{self._task_id}_epoch*", self._task_id]:
                    for _path in list(_local_root_path.glob(_pattern)):
                        if _path.is_dir() and not _path.is_symlink():
                            if str(_path) != str(self._local_run_root):
                                shutil.rmtree(str(_path), ignore_errors=True)
                                logger.info(
                                    "workspace_manager: cleaned leftover local %s",
                                    str(_path),
                                )
            except Exception:
                pass

    @staticmethod
    def cleanup_temp_for_task(task_id: str) -> None:
        """Remove any leftover local workspace for a task_id.
        Called before starting a new task to prevent cross-task contamination.
        """
        if not _is_enabled():
            return
        root = _local_root()
        for pattern in [f"{task_id}_epoch*", f"{task_id}"]:
            for path in list(root.glob(pattern)):
                if path.is_dir() and not path.is_symlink():
                    _cleanup_local_temp(path)
                elif path.is_symlink():
                    try:
                        path.unlink()
                    except OSError:
                        pass

    @staticmethod
    def resolve_broken_symlinks(base_path: str | Path) -> int:
        """Check for and fix any stale symlinks left from previous crashes.

        Returns the number of fixed entries.
        """
        base = Path(base_path)
        if not base.is_dir():
            return 0
        fixed = 0
        for entry in list(base.iterdir()):
            if entry.is_symlink() and not entry.exists():
                logger.warning(
                    "workspace_manager: broken symlink %s → removing",
                    str(entry),
                )
                try:
                    entry.unlink()
                    fixed += 1
                except OSError:
                    pass
            elif entry.is_symlink():
                # Valid symlink pointing to local temp — clean it up
                try:
                    target = Path(os.readlink(str(entry)))
                    if str(target).startswith(str(_local_root())):
                        logger.info(
                            "workspace_manager: removing stale symlink %s → %s",
                            str(entry), str(target),
                        )
                        entry.unlink()
                        fixed += 1
                except (OSError, RuntimeError):
                    pass
        return fixed

    # ── internal ─────────────────────────────────────────────────────────────

    def _sync_to_nfs(self, local_dir: Path, nfs_dir: Path) -> None:
        """Copy all files from local to NFS using a safe replace strategy:
        1. Copy to a temp directory on NFS {nfs_dir}.tmp/
        2. Remove old symlink at nfs_dir
        3. Rename temp to final position
        """
        if not local_dir.exists():
            return

        tmp_path = Path(str(nfs_dir) + ".tmp")
        # Remove stale tmp
        if tmp_path.exists():
            shutil.rmtree(str(tmp_path), ignore_errors=True)
        tmp_path.mkdir(parents=True, exist_ok=True)

        # Copy all content from local to tmp
        _copy_tree(str(local_dir), str(tmp_path))

        # Remove the symlink
        if nfs_dir.is_symlink():
            nfs_dir.unlink()
        elif nfs_dir.exists():
            # Shouldn't happen normally, but handle gracefully
            shutil.rmtree(str(nfs_dir), ignore_errors=True)

        # Rename tmp → final
        try:
            tmp_path.rename(nfs_dir)
            logger.info(
                "workspace_manager: moved %s → %s",
                str(tmp_path), str(nfs_dir),
            )
        except OSError:
            # Cross-filesystem rename may fail; fall back to copy
            logger.warning(
                "workspace_manager: rename failed %s → %s, falling back to copy",
                str(tmp_path), str(nfs_dir),
            )
            nfs_dir.mkdir(parents=True, exist_ok=True)
            _copy_tree(str(tmp_path), str(nfs_dir))
            shutil.rmtree(str(tmp_path), ignore_errors=True)

    def _periodic_sync_loop(self) -> None:
        """Background thread: periodically sync the runtime minimum set to NFS.

        Sessions sync directly to output/sessions/ on NFS so runtime and
        terminal reads use the same path. The only other runtime artifact we
        keep incrementally visible is run/vuln-scan.sqlite.

        Large runtime trees such as output/, vulnerabilities/ and dataflow-v2/
        stay local during execution and are published by the terminal archive.
        """
        interval = _sync_interval()
        while not self._stop_event.wait(interval):
            if self._local_run_root is None or self._nfs_run_root is None:
                continue
            if not self._local_run_root.exists():
                continue
            # self._nfs_run_root = {task_root}/run/epochs/{epoch:04d}/
            # Keep run/ compatibility artifacts under {task_root}/run/,
            # but real-time session visibility now lives under {task_root}/output/sessions.
            task_root = self._nfs_run_root.parent.parent.parent
            nfs_run_parent = task_root / "run"
            try:
                nfs_run_parent.mkdir(parents=True, exist_ok=True)

                # Sync sessions/ to output/sessions/ on NFS (authoritative read path)
                local_sessions = self._local_run_root / "sessions"
                if local_sessions.exists():
                    nfs_output = task_root / "output"
                    nfs_output.mkdir(parents=True, exist_ok=True)
                    nfs_sessions = nfs_output / "sessions"
                    nfs_sessions.mkdir(parents=True, exist_ok=True)
                    self._sync_sessions_incremental(local_sessions, nfs_sessions)

                # Sync vuln-scan.sqlite
                local_db = self._local_run_root / "vuln-scan.sqlite"
                if local_db.exists():
                    nfs_db = nfs_run_parent / "vuln-scan.sqlite"
                    _safe_copyfile(str(local_db), str(nfs_db))
            except Exception as exc:
                logger.debug(
                    "workspace_manager: periodic sync failed: %s", exc,
                )

    def _sync_sessions_incremental(self, local_sessions: Path, nfs_sessions: Path) -> None:
        """Copy session files to NFS — only copy files that changed (mtime/size).

        Avoids full-copy every 60s cycle for large session files.
        """
        nfs_sessions.mkdir(parents=True, exist_ok=True)
        for src in local_sessions.iterdir():
            if not src.is_file():
                continue
            dst = nfs_sessions / src.name
            if _needs_copy(src, dst):
                _safe_copyfile(str(src), str(dst))


# ── helpers ──────────────────────────────────────────────────────────────────

def _move_contents(src: Path, dst: Path) -> None:
    """Move all contents from src to dst (src and dst are both directories)."""
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        target = dst / item.name
        if item.is_dir() and not item.is_symlink():
            if target.exists():
                _move_contents(item, target)
            else:
                try:
                    item.rename(target)
                except OSError:
                    shutil.copytree(str(item), str(target))
                    shutil.rmtree(str(item), ignore_errors=True)
        else:
            try:
                if target.exists():
                    target.unlink()
                item.rename(target)
            except OSError:
                shutil.copy2(str(item), str(target))
                try:
                    item.unlink()
                except OSError:
                    pass


def _copy_tree(src: str, dst: str) -> None:
    """Robust recursive copy, skipping broken symlinks."""
    os.makedirs(dst, exist_ok=True)
    for entry in os.listdir(src):
        s = os.path.join(src, entry)
        d = os.path.join(dst, entry)
        try:
            if os.path.islink(s):
                linkto = os.readlink(s)
                if os.path.exists(d):
                    os.unlink(d)
                os.symlink(linkto, d)
            elif os.path.isdir(s):
                _copy_tree(s, d)
            else:
                shutil.copy2(s, d)
        except (OSError, shutil.Error) as exc:
            logger.debug("_copy_tree: skip %s: %s", s, exc)


def _safe_copyfile(src: str, dst: str) -> bool:
    """Copy a single file atomically (write to tmp then rename)."""
    try:
        tmp = dst + ".tmp"
        shutil.copy2(src, tmp)
        os.replace(tmp, dst)
        return True
    except OSError as exc:
        logger.debug("_safe_copyfile: %s → %s failed: %s", src, dst, exc)
        return False


def _cleanup_local_temp(local_path: Path) -> None:
    """Remove local temp directory with retries and forced cleanup."""
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            if not local_path.exists():
                logger.info("workspace_manager: local temp already gone %s", str(local_path))
                return
            shutil.rmtree(str(local_path))
            logger.info("workspace_manager: cleaned local %s", str(local_path))
            return
        except OSError as exc:
            if attempt < max_attempts:
                time.sleep(1.0 * attempt)
                logger.debug(
                    "workspace_manager: cleanup retry %d/%d for %s: %s",
                    attempt, max_attempts, str(local_path), exc,
                )
            else:
                # Final attempt: force cleanup
                logger.warning(
                    "workspace_manager: forced cleanup %s after %d attempts",
                    str(local_path), max_attempts,
                )
                shutil.rmtree(str(local_path), ignore_errors=True)
                if local_path.exists():
                    logger.error(
                        "workspace_manager: CRITICAL - failed to clean local %s",
                        str(local_path),
                    )


def _needs_copy(src: Path, dst: Path) -> bool:
    """Return True if src needs to be copied to dst (missing or stale)."""
    try:
        if not dst.exists():
            return True
        src_stat = src.stat()
        dst_stat = dst.stat()
        return (src_stat.st_mtime != dst_stat.st_mtime
                or src_stat.st_size != dst_stat.st_size)
    except OSError:
        return True
