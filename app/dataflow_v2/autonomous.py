"""自主模式 runner (feature_flags["autonomous_mode"])。

LLM 作为一个长程 agent 自主从入口探索。微服务只负责:
  - 记录探索路径 (read_function 脚本写 path.log, 流式)
  - 上报漏洞 (report_finding 脚本即写即包, 同完整模式格式)
  - 帮索引函数 (read_function 增量建库)
  - 续探循环 (checkpoint.continue → 新 session 注入 path+pending)

不动完整模式 (V2 DFS orchestrator)。runner.py 按 feature_flags 分派。
"""
from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Callable

from ..models import SwarmEvent, TaskConfig
from ..runner import run_agent
from ..vuln_report_utils import build_v2_system_prompt
from .function_extractor import ensure_file_indexed, find_func_in_source
from .store import DataflowStore

logger = logging.getLogger("dvs.dataflow_v2.autonomous")


class AutonomousRunner:
    """自主模式执行器, 对外接口与 DataflowV2Runner 兼容 (execute_recursive)。"""

    def __init__(self, config: TaskConfig, on_event: Callable[..., None] | None = None,
                 task_id: str = "") -> None:
        self.cfg = config
        self._raw_on_event = on_event
        self.task_id = task_id
        self._cancel_event: threading.Event | None = threading.Event()

    def _emit(self, etype: str, **data: Any) -> None:
        try:
            if self._raw_on_event is not None:
                self._raw_on_event(SwarmEvent(type=etype, task_id=self.task_id, data=data))
        except Exception:
            logger.debug("autonomous _emit %s failed", etype, exc_info=True)

    def abort(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()

    def cancel(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()

    # ── 兼容接口 ──────────────────────────────────────────────────────────
    def execute_recursive(self, task_id: str | None = None, depth: int = 0,
                          tainted_context: str = "",
                          _analyzed: set[str] | None = None,
                          _root_out_dir: Path | None = None,
                          _root_output_dir: Path | None = None) -> Any:
        from ..models import TaskStatus, TaskResult
        tid = task_id or self.task_id
        cfg = self.cfg
        if _root_out_dir is not None:
            root_out_dir = Path(_root_out_dir)
            shared_run_dir = root_out_dir.parent.parent if ("epochs" in root_out_dir.parts and "run" in root_out_dir.parts) else root_out_dir
        else:
            root_out_dir = Path(cfg.output_dir) / tid / "run"
            shared_run_dir = root_out_dir
        root_out_dir.mkdir(parents=True, exist_ok=True)
        shared_run_dir.mkdir(parents=True, exist_ok=True)
        root_output_path = Path(_root_output_dir) if _root_output_dir is not None else (shared_run_dir.parent / "output")
        root_output_path.mkdir(parents=True, exist_ok=True)
        v2_run_dir = shared_run_dir / "dataflow-v2"
        sessions_dir = root_out_dir / "sessions"
        graph_db_path = shared_run_dir / "vuln-scan.sqlite"
        vuln_root = shared_run_dir / "vulnerabilities"
        source_root = cfg.cwd
        v2_run_dir.mkdir(parents=True, exist_ok=True)
        sessions_dir.mkdir(parents=True, exist_ok=True)
        vuln_root.mkdir(parents=True, exist_ok=True)

        status = TaskStatus.PASSED
        err_msg = ""
        try:
            if not cfg.source_file:
                return TaskResult(task_id=tid, status=TaskStatus.INVALID_INPUT, task=cfg.task,
                                  error="autonomous: source_file 未指定")
            store = DataflowStore(v2_run_dir)
            self._emit("v2_indexing_source_tree")
            ensure_file_indexed(source_root, cfg.source_file, store)
            root_func = store.find_function(cfg.function_name, cfg.source_file) \
                or store.find_function(cfg.function_name)
            if root_func is None:
                found = find_func_in_source(cfg.function_name, Path(source_root))
                if found:
                    ensure_file_indexed(source_root, found[0], store)
                    root_func = store.find_function(cfg.function_name, found[0]) \
                        or store.find_function(cfg.function_name)
            if root_func is None:
                return TaskResult(task_id=tid, status=TaskStatus.INVALID_INPUT, task=cfg.task,
                                  error=f"autonomous: 入口函数 {cfg.function_name} 未找到")
            self._emit("v2_indexed", functions=len(store.list_functions()))

            # 服务工具脚本路径 (agent 经 bash 调)
            script_dir = Path("/opt/dataflow_vuln_scan/scripts/autonomous")
            # 环境变量: 让脚本能找到 run_dir/v2_db/source_root + intake 元数据
            base_env = {
                "DVS_RUN_DIR": str(shared_run_dir),
                "DVS_V2_DB_DIR": str(v2_run_dir),
                "DVS_SOURCE_ROOT": str(source_root),
                "DVS_TASK_ID": tid,
                "DVS_RUN_ID": tid,
                "DVS_PROJECT_ID": cfg.project_id,
                "DVS_TASK_NAME": cfg.task_name,
                "DVS_PARENT_TASK_ID": cfg.parent_task_id,
                "DVS_PARENT_TASK_NAME": cfg.parent_task_name,
                "DVS_PARENT_TASK_TYPE": cfg.parent_task_type,
                "DVS_TASK_ORIGIN_TYPE": cfg.task_origin_type,
                "PATH": os.environ.get("PATH", "") + os.pathsep + str(script_dir) + os.pathsep + "/opt/venv/bin",
            }

            acfg = cfg.workers.agents[0] if cfg.workers.agents else None
            if acfg is None:
                return TaskResult(task_id=tid, status=TaskStatus.ERROR, task=cfg.task,
                                  error="autonomous: 无 worker agent 配置")
            system_prompt = (build_v2_system_prompt(custom="autonomous") or "")
            sp_path = Path(__file__).parent.parent.parent / "prompts" / "v2" / "autonomous-explore.md"
            try:
                system_prompt = system_prompt + "\n\n" + sp_path.read_text(encoding="utf-8")
            except Exception:
                system_prompt = sp_path.read_text(encoding="utf-8") if sp_path.exists() else system_prompt

            # 入口提示 (用解析到的 root_func.name, 不靠 cfg.function_name)
            taint_desc = ",".join(cfg.taint_params) if cfg.taint_params else "(自行识别入口污点源)"
            _desc = ("来源说明: " + cfg.function_description) if cfg.function_description else ""
            entry_prompt = (
                f"## 入口\n目标函数: `{root_func.file}::{root_func.name}` (行 {root_func.start_line}-{root_func.end_line})\n"
                f"签名: {root_func.signature}\n"
                f"入口污点: {taint_desc}\n"
                f"{_desc}\n\n"
                f"开始自主探索。先 `read_function {root_func.name}` 读入口, 再跟踪污点、挖漏洞。")

            # 续探循环: 每轮一个 agent session, 结束读 checkpoint
            max_rounds = max(1, int(getattr(cfg, "max_rounds", 3) or 3))
            for rnd in range(1, max_rounds + 1):
                if self._cancel_event is not None and self._cancel_event.is_set():
                    status, err_msg = TaskStatus.FAILED, "autonomous: cancelled"
                    break
                round_session = sessions_dir / f"autonomous-r{rnd:02d}.jsonl"
                prompt = entry_prompt if rnd == 1 else self._resume_prompt(shared_run_dir, rnd)
                if not prompt:
                    break  # 无可续探
                self._emit("v2_autonomous_round", round=rnd, session=str(round_session))
                # 本轮 context session 路径 (report_finding 用)
                base_env["DVS_CONTEXT_SESSION"] = str(round_session)
                result = run_agent(
                    prompt=prompt, model=acfg.model, tools=acfg.tools or cfg.workers.default_tools,
                    cwd=source_root, session_file=str(round_session), system_prompt=system_prompt,
                    cancel_event=self._cancel_event, env=base_env,
                    run_timeout_seconds=cfg.agent_run_timeout_seconds,
                    timeout_retry_enabled=cfg.agent_timeout_retry_enabled,
                    timeout_max_retries=cfg.agent_timeout_max_retries,
                    pi_max_retries=cfg.pi_max_retries, pi_retry_delay=cfg.pi_retry_delay,
                    task_context={"task_id": tid, "task_root": str(shared_run_dir.parent),
                                  "task_run_root": str(shared_run_dir),
                                  "task_pi_dir": cfg.role_pi_dir("workers"), "agent_role": "workers"})
                if self._cancel_event is not None and self._cancel_event.is_set():
                    status, err_msg = TaskStatus.FAILED, "autonomous: cancelled"
                    break
                # 读 checkpoint
                ck = self._read_checkpoint(shared_run_dir)
                self._emit("v2_autonomous_checkpoint", round=rnd, checkpoint=ck)
                if not ck or not ck.get("continue"):
                    break  # LLM 决定不再继续 / 无 checkpoint
            # 任务完成: 输出探索路径 + 剩余 pending
            self._emit("v2_autonomous_done", round=rnd if 'rnd' in dir() else 0,
                        path_steps=self._count_path(shared_run_dir))
        except Exception as exc:
            logger.exception("autonomous runner failed")
            status, err_msg = TaskStatus.ERROR, str(exc)

        # 最终报告 (markdown: 探索路径 + pending)
        self._write_final_report(shared_run_dir, root_output_path)
        return self._build_result(tid, status, err_msg)

    # ── 辅助 ──────────────────────────────────────────────────────────────
    def _read_checkpoint(self, run_dir: Path) -> dict:
        p = run_dir / "checkpoint.json"
        try:
            return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        except Exception:
            return {}

    def _count_path(self, run_dir: Path) -> int:
        p = run_dir / "path.log"
        try:
            return sum(1 for _ in p.read_text(encoding="utf-8").splitlines() if _.strip()) if p.exists() else 0
        except Exception:
            return 0

    def _resume_prompt(self, run_dir: Path, rnd: int) -> str:
        """构造续探 prompt: 注入已探索路径 + pending_branches。"""
        ck = self._read_checkpoint(run_dir)
        pending = ck.get("pending_branches") or []
        if not pending:
            return ""
        path_lines = self._read_path_render(run_dir, limit=60)
        pend_text = "\n".join(
            f"- 在 `{b.get('at_func','')}` 处: 跟入 `{b.get('target','')}` (污点 {b.get('taint','')}) — {b.get('reason','')}"
            for b in pending if isinstance(b, dict))
        return (
            f"## 续探 (第 {rnd} 轮)\n上一轮你已探索的路径:\n{path_lines}\n\n"
            f"## 未探索的可疑分支 (从这些继续)\n{pend_text}\n\n"
            f"继续自主探索。用 `read_function` 读这些 target, 跟污点、挖漏洞; 结束时再 `checkpoint`。")

    def _read_path_render(self, run_dir: Path, limit: int = 60) -> str:
        p = run_dir / "path.log"
        if not p.exists():
            return "(无)"
        try:
            lines = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
            lines = lines[-limit:]
            return "\n".join(f"- {s.get('func','')} ({s.get('file','')} 行 {s.get('start_line','')})" for s in lines)
        except Exception:
            return "(无)"

    def _write_final_report(self, run_dir: Path, out_dir: Path) -> None:
        try:
            ck = self._read_checkpoint(run_dir)
            path_lines = self._read_path_render(run_dir, limit=10000)
            pending = ck.get("pending_branches") or []
            pend_text = "\n".join(
                f"- `{b.get('at_func','')}` → `{b.get('target','')}` (污点 {b.get('taint','')}): {b.get('reason','')}"
                for b in pending if isinstance(b, dict)) or "(已充分探索)"
            md = ["# 自主模式探索报告", "",
                  "## 已探索路径", path_lines, "",
                  "## 未探索分支 (可继续)", pend_text, "",
                  f"轮次: {ck.get('round','?')}  stop_reason: {ck.get('stop_reason','?')}"]
            (out_dir / "autonomous_report.md").write_text("\n".join(md), encoding="utf-8")
        except Exception:
            logger.debug("autonomous final report failed", exc_info=True)

    def _build_result(self, tid, status, err_msg):
        from ..models import TaskResult
        r = TaskResult(task_id=tid, status=status, task=self.cfg.task, error=err_msg)
        return r
