from __future__ import annotations

import contextlib
import logging
import os
import pathlib
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Callable

logger = logging.getLogger("dvs.agent_process")


def find_pi_command() -> list[str]:
    pi_bin = os.environ.get("PI_BIN")
    if pi_bin and os.path.isfile(pi_bin):
        return [pi_bin]
    pi_path = shutil.which("pi")
    if pi_path:
        return [pi_path]
    npx = shutil.which("npx")
    if npx:
        return [npx, "pi"]
    raise FileNotFoundError(
        "找不到 'pi'。请安装: npm install -g @mariozechner/pi-coding-agent"
    )


def process_group_id(pid: int) -> int | None:
    try:
        return os.getpgid(pid)
    except ProcessLookupError as e:
        logger.debug("getpgid process gone (pid=%s): %s", pid, e)
        return None
    except Exception:
        logger.warning("agent_process: getpgid failed pid=%s", pid, exc_info=True)
        return None


def process_group_exists(pgid: int | None) -> bool:
    if pgid is None:
        return False
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError as e:
        logger.debug("killpg(0) group gone: %s", e)
        return False
    except PermissionError as e:
        logger.debug("killpg(0) PermissionError -> alive: %s", e)
        return True
    except Exception:
        logger.warning("agent_process: process_group_exists failed pgid=%s", pgid, exc_info=True)
        return False
    return True


def _read_proc_name(pid: int, field: str) -> str:
    try:
        return (pathlib.Path("/proc") / str(pid) / field).read_text(
            encoding="utf-8",
            errors="replace",
        ).strip()
    except Exception:
        logger.warning(
            "agent_process: failed to read proc field pid=%s field=%s",
            pid,
            field,
            exc_info=True,
        )
        return ""


def _safe_readlink(path: pathlib.Path) -> str:
    try:
        return os.readlink(path)
    except Exception:
        logger.warning("agent_process: readlink failed path=%s", path, exc_info=True)
        return ""


def _read_proc_environ(pid: int) -> dict[str, str]:
    try:
        raw = (pathlib.Path("/proc") / str(pid) / "environ").read_bytes()
    except Exception:
        logger.warning("agent_process: failed to read environ pid=%s", pid, exc_info=True)
        return {}
    payload: dict[str, str] = {}
    for item in raw.split(b"\0"):
        if not item or b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        try:
            payload[key.decode("utf-8", errors="replace")] = value.decode("utf-8", errors="replace")
        except Exception:
            logger.warning("agent_process: failed to decode environ pid=%s", pid, exc_info=True)
            continue
    return payload


def _read_proc_cmdline(pid: int) -> str:
    try:
        raw = (pathlib.Path("/proc") / str(pid) / "cmdline").read_bytes()
    except Exception:
        logger.warning("agent_process: failed to read cmdline pid=%s", pid, exc_info=True)
        return ""
    return raw.replace(b"\0", b" ").decode("utf-8", errors="replace").strip()


def _read_ppid(status_text: str) -> int | None:
    for line in status_text.splitlines():
        if line.startswith("PPid:"):
            try:
                return int(line.split(":", 1)[1].strip())
            except ValueError:
                logger.warning("agent_process: invalid PPid line=%r", line, exc_info=True)
                return None
    return None


def _read_pgid(pid: int) -> int | None:
    try:
        return int(
            subprocess.check_output(
                ["sh", "-lc", f"awk '{{print $5}}' /proc/{pid}/stat"],
                text=True,
            ).strip()
        )
    except Exception:
        logger.warning("agent_process: failed to read pgid pid=%s", pid, exc_info=True)
        return None


def _proc_exists(pid: int) -> bool:
    """检查进程是否还在 /proc 中 (包括 zombie)."""
    return os.path.exists(f"/proc/{pid}")


def _normalize_path(path_value: str | None) -> str:
    raw = str(path_value or "").strip()
    if not raw:
        return ""
    try:
        return os.path.realpath(os.path.abspath(raw))
    except Exception:
        logger.warning("agent_process: failed to normalize path=%r", path_value, exc_info=True)
        return raw


def _path_within(path_value: str | None, root_value: str | None) -> bool:
    path = _normalize_path(path_value)
    root = _normalize_path(root_value)
    if not path or not root:
        return False
    return path == root or path.startswith(root + os.sep)


@dataclass(frozen=True)
class AgentCleanupTarget:
    task_id: str | None = None
    task_root: str | None = None
    run_root: str | None = None
    worker_id: str | None = None
    execution_epoch: int | None = None


@dataclass(frozen=True)
class AgentProcessInfo:
    pid: int
    ppid: int | None
    pgid: int | None
    comm: str
    exe: str
    cwd: str
    cmdline: str
    environ: dict[str, str]
    started_at: float | None = None


def _is_runtime_process(info: AgentProcessInfo) -> bool:
    comm = (info.comm or "").lower()
    exe = (info.exe or "").lower()
    cmdline = (info.cmdline or "").lower()
    if comm == "pi" or exe in {"node", "pi", "npm", "npx"}:
        return True
    if comm.startswith("python") or exe.startswith("python"):
        return True
    # pi may be launched through npx/node; keep this conservative but catch common wrappers.
    return "pi-coding-agent" in cmdline or " npx pi" in cmdline or cmdline.startswith("npx pi")


def _iter_runtime_processes() -> list[AgentProcessInfo]:
    candidates: list[AgentProcessInfo] = []
    proc_root = pathlib.Path("/proc")
    for proc_dir in proc_root.iterdir():
        if not proc_dir.name.isdigit():
            continue
        pid = int(proc_dir.name)
        try:
            status = (proc_dir / "status").read_text(encoding="utf-8", errors="replace")
            if "\nState:\tZ" in status or "\nState: Z" in status:
                continue
            comm = (proc_dir / "comm").read_text(encoding="utf-8", errors="replace").strip()
            exe = os.path.basename(_safe_readlink(proc_dir / "exe"))
        except Exception:
            logger.warning("agent_process: failed to inspect proc entry=%s", proc_dir, exc_info=True)
            continue
        try:
            started_at = os.stat(proc_dir).st_ctime
        except Exception:
            logger.warning("agent_process: failed to stat proc entry=%s", proc_dir, exc_info=True)
            started_at = None
        info = AgentProcessInfo(
            pid=pid,
            ppid=_read_ppid(status),
            pgid=_read_pgid(pid),
            comm=comm,
            exe=exe,
            cwd=_safe_readlink(proc_dir / "cwd"),
            cmdline=_read_proc_cmdline(pid),
            environ=_read_proc_environ(pid),
            started_at=started_at,
        )
        if _is_runtime_process(info):
            candidates.append(info)
    return candidates


def _iter_agent_processes() -> list[AgentProcessInfo]:
    candidates: list[AgentProcessInfo] = []
    for info in _iter_runtime_processes():
        comm = (info.comm or "").lower()
        exe = (info.exe or "").lower()
        if comm == "pi" or exe == "node" or "pi-coding-agent" in (info.cmdline or "").lower():
            candidates.append(info)
    return candidates


def _matches_target(info: AgentProcessInfo, target: AgentCleanupTarget | None) -> bool:
    task_id = str(info.environ.get("DVS_TASK_ID") or "").strip()
    task_root = str(info.environ.get("DVS_TASK_ROOT") or "").strip()
    run_root = str(info.environ.get("DVS_TASK_RUN_ROOT") or "").strip()
    worker_id = str(info.environ.get("DVS_WORKER_ID") or "").strip()
    if target is None:
        return bool(task_id or task_root or run_root or "DVS_TASK_ID=" in info.cmdline)
    if target.task_id and task_id == target.task_id:
        return True
    if target.worker_id and worker_id and worker_id == target.worker_id:
        if target.task_id:
            return task_id == target.task_id
        return True
    if target.run_root and (_path_within(info.cwd, target.run_root) or _path_within(run_root, target.run_root)):
        return True
    if target.task_root and (
        _path_within(info.cwd, target.task_root)
        or _path_within(task_root, target.task_root)
        or _path_within(run_root, target.task_root)
    ):
        return True
    return False


def _kill_process_group(
    logger: Callable[[str], None],
    *,
    label: str,
    info: AgentProcessInfo,
    reason: str,
) -> bool:
    logger(
        f"cleaning agent process [{label}] pid={info.pid} pgid={info.pgid if info.pgid is not None else 'unknown'} "
        f"task_id={info.environ.get('DVS_TASK_ID') or '-'} cwd={info.cwd or '-'} reason={reason}"
    )
    try:
        if info.pgid is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(info.pgid, signal.SIGTERM)
            time.sleep(1.0)
            with contextlib.suppress(ProcessLookupError):
                os.killpg(info.pgid, signal.SIGKILL)
        else:
            with contextlib.suppress(ProcessLookupError):
                os.kill(info.pid, signal.SIGTERM)
            time.sleep(1.0)
            with contextlib.suppress(ProcessLookupError):
                os.kill(info.pid, signal.SIGKILL)
        # 等待进程真正退出 (最多 5s), 避免残留进程影响下一个任务
        _deadline = time.monotonic() + 5.0
        while time.monotonic() < _deadline:
            if not _proc_exists(info.pid):
                break
            time.sleep(0.2)
        return True
    except Exception:
        logger.warning(
            "agent_process: failed to kill process group pid=%s pgid=%s label=%s",
            info.pid,
            info.pgid,
            label,
            exc_info=True,
        )
        return False


def cleanup_task_agent_processes(
    logger: Callable[[str], None],
    *,
    label: str,
    task_id: str | None = None,
    task_root: str | None = None,
    run_root: str | None = None,
    worker_id: str | None = None,
) -> int:
    target = AgentCleanupTarget(
        task_id=task_id or None,
        task_root=task_root or None,
        run_root=run_root or None,
        worker_id=worker_id or None,
    )
    killed = 0
    seen_pgids: set[tuple[str, int]] = set()
    for info in _iter_agent_processes():
        if not _matches_target(info, target):
            continue
        key = ("pg", info.pgid) if info.pgid is not None else ("pid", info.pid)
        if key in seen_pgids:
            continue
        seen_pgids.add(key)
        if _kill_process_group(logger, label=label, info=info, reason="task_targeted_cleanup"):
            killed += 1
    return killed


def cleanup_orphan_pi_processes(
    logger: Callable[[str], None],
    *,
    label: str,
) -> int:
    killed = 0
    seen_pgids: set[tuple[str, int]] = set()
    try:
        grace_seconds = max(0, int(os.environ.get("DVS_ORPHAN_PI_GRACE_SECONDS", "900")))
    except ValueError as e:
        logger.debug("parse DVS_ORPHAN_PI_GRACE_SECONDS failed, default 900: %s", e)
        grace_seconds = 900
    now = time.time()
    for info in _iter_agent_processes():
        if not _matches_target(info, None):
            continue
        # ── 孤儿判断：父进程是否真实存活 ─────────────────────────────────
        # 原始 ppid==1 检测在容器环境下完全失效：
        #   entrypoint.sh 使用 `exec "$@"` → python3 main.py 成为 PID 1
        #   → 所有 pi 子进程的 ppid 都是 1（python3 本身，并非 init）
        #   → 900s 宽限期后所有活跃 pi 进程都会被误杀
        # 正确方法：用 os.kill(ppid, 0) 探测父进程是否仍在进程表中
        #   ProcessLookupError → 父进程已消失 → 进程真正成为孤儿
        #   成功 / PermissionError → 父进程存活 → 不是孤儿，跳过
        ppid = info.ppid
        if ppid is not None and ppid > 0:
            try:
                os.kill(ppid, 0)
                continue  # 父进程存活 → 非孤儿，跳过
            except ProcessLookupError as e:
                logger.debug("parent process gone (orphan): %s", e)
                pass  # 父进程已消失 → 真正的孤儿，继续判断
            except PermissionError as e:
                logger.debug("parent exists but no permission -> not orphan: %s", e)
                continue  # 父进程存在但无权发信号 → 非孤儿，跳过
            except Exception:
                globals()["logger"].warning(
                    "agent_process: orphan probe failed pid=%s ppid=%s",
                    info.pid,
                    ppid,
                    exc_info=True,
                )
                continue  # 其他异常保守处理，不杀
        # 宽限期：只清理启动超过 grace_seconds 的孤儿（避免误杀刚启动的进程）
        if info.started_at is not None and grace_seconds > 0 and (now - info.started_at) < grace_seconds:
            continue
        key = ("pg", info.pgid) if info.pgid is not None else ("pid", info.pid)
        if key in seen_pgids:
            continue
        seen_pgids.add(key)
        if _kill_process_group(logger, label=label, info=info, reason="orphan_cleanup"):
            killed += 1
    return killed


def cleanup_worker_runtime_processes(
    logger: Callable[[str], None],
    *,
    label: str,
) -> int:
    """Clean all agent runtime helper processes owned by this worker container.

    This service is deployed with one task slot per worker.  Before taking a new
    task and after every terminal/cancel path, it is safer to remove any stale
    agent/runtime processes.  The current service process, PID 1, and the current
    process group are always excluded so the worker itself is not killed.
    """
    current_pid = os.getpid()
    current_pgid = _read_pgid(current_pid)
    protected_pids = {0, 1, current_pid, os.getppid()}
    killed = 0
    seen_pgids: set[tuple[str, int]] = set()
    for info in _iter_agent_processes():
        if info.pid in protected_pids:
            continue
        if info.pgid is not None and current_pgid is not None and info.pgid == current_pgid:
            continue
        key = ("pg", info.pgid) if info.pgid is not None else ("pid", info.pid)
        if key in seen_pgids:
            continue
        seen_pgids.add(key)
        if _kill_process_group(logger, label=label, info=info, reason="worker_full_runtime_cleanup"):
            killed += 1
    return killed


@dataclass
class AgentProcessHandle:
    proc: subprocess.Popen
    label: str
    logger: Callable[[str], None]
    pgid: int | None

    @classmethod
    def spawn(
        cls,
        *args: str,
        cwd: str,
        env: dict[str, str] | None,
        stdout,
        stderr,
        stdin,
        logger: Callable[[str], None],
        label: str,
    ) -> "AgentProcessHandle":
        proc = subprocess.Popen(
            args,
            cwd=cwd,
            env=env,
            stdout=stdout,
            stderr=stderr,
            stdin=stdin,
            start_new_session=True,
        )
        return cls(proc=proc, label=label, logger=logger, pgid=process_group_id(proc.pid))

    def terminate_tree(
        self,
        *,
        reason: str,
        term_timeout: float = 5.0,
        kill_timeout: float = 5.0,
        force_if_group_still_exists: bool = True,
    ) -> None:
        if self.proc.poll() is not None:
            if force_if_group_still_exists and process_group_exists(self.pgid):
                self.logger(
                    f"cleaning leaked pi process group [{self.label}] "
                    f"reason={reason} pid={self.proc.pid} pgid={self.pgid}"
                )
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(self.pgid, signal.SIGKILL)
            with contextlib.suppress(Exception):
                self.proc.wait(timeout=1.0)
            return

        if self.pgid is not None:
            self.logger(
                f"terminating pi process group [{self.label}] "
                f"reason={reason} pid={self.proc.pid} pgid={self.pgid}"
            )
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.pgid, signal.SIGTERM)
        else:
            self.logger(
                f"terminating pi process [{self.label}] "
                f"reason={reason} pid={self.proc.pid} pgid=unavailable"
            )
            self.proc.terminate()

        try:
            self.proc.wait(timeout=term_timeout)
        except subprocess.TimeoutExpired as e:
            self.logger(
                f"terminate_tree wait timeout [{self.label}] reason={reason} "
                f"pid={self.proc.pid} pgid={self.pgid}"
            )
            logger.warning("terminate_tree wait timeout [%s] pid=%s pgid=%s: %s",
                           self.label, self.proc.pid, self.pgid, e, exc_info=True)
        except ProcessLookupError as e:
            logger.debug("proc.wait process gone: %s", e)
            return
        else:
            if not force_if_group_still_exists or not process_group_exists(self.pgid):
                return

        if self.pgid is not None:
            self.logger(
                f"force killing pi process group [{self.label}] "
                f"reason={reason} pid={self.proc.pid} pgid={self.pgid}"
            )
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.pgid, signal.SIGKILL)
        else:
            self.logger(
                f"force killing pi process [{self.label}] "
                f"reason={reason} pid={self.proc.pid} pgid=unavailable"
            )
            self.proc.kill()

        with contextlib.suppress(Exception):
            self.proc.wait(timeout=kill_timeout)
