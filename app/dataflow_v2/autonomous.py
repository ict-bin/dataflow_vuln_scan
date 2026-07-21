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


class _PiKilledExternally(Exception):
    """pi 被外部杀 (SIGTERM=143 等) — raise 让 celery 失败, 任务留 running, stale-reset 回 pending 重派。"""
    pass


class AutonomousRunner:
    """自主模式执行器, 对外接口与 DataflowV2Runner 兼容 (execute_recursive)。"""

    def __init__(self, config: TaskConfig, on_event: Callable[..., None] | None = None,
                 task_id: str = "") -> None:
        self.cfg = config
        self._raw_on_event = on_event
        self.task_id = task_id
        self._cancel_event: threading.Event | None = threading.Event()

    def _create_mysql_store(self, mode: str):
        """创建 SharedMysqlStore (双写, 失败返回 None)。"""
        try:
            from ..db.shared_mysql import create_shared_store
            db_cfg = getattr(self.cfg, "db", None)
            url = db_cfg.url if db_cfg else \
                "mysql+pymysql://root:Huawei12%23$@secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local:3306"
            return create_shared_store(url, mode, self.cfg.cwd, self.task_id,
                                      project_id=getattr(self.cfg, "project_id", "") or "")
        except Exception as e:
            logger.warning("create mysql store failed: %s", e)
            return None

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
            store = DataflowStore(v2_run_dir, mysql_store=self._create_mysql_store("autonomous"))
            self._emit("v2_indexing_source_tree")
            ensure_file_indexed(source_root, cfg.source_file, store)
            root_func = store.find_function(cfg.function_name, cfg.source_file) \
                or store.find_function(cfg.function_name)
            if root_func is None:
                found = find_func_in_source(cfg.function_name, Path(source_root))
                if found:
                    for rel_file, _ in found:
                        ensure_file_indexed(source_root, rel_file, store)
                    root_func = store.find_function(cfg.function_name, found[0]) \
                        or store.find_function(cfg.function_name)
            if root_func is None:
                return TaskResult(task_id=tid, status=TaskStatus.INVALID_INPUT, task=cfg.task,
                                  error=f"autonomous: 入口函数 {cfg.function_name} 未找到")
            self._emit("v2_indexed", functions=store.count_functions())

            # 服务工具脚本路径 (agent 经 bash 调)
            script_dir = Path("/opt/dataflow_vuln_scan/scripts/autonomous")
            wrapper_dir = "/opt/dataflow_vuln_scan/bin/restricted"  # find/grep/cat 限源码目录
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
                # 显式把 restricted wrapper 放 PATH 最前 (find/grep/cat 只能在 source_root 内),
                # 双保险 (_build_agent_env 也会 prepend, 这里再保一次防 pi bash 工具 env 差异)
                "PATH": wrapper_dir + os.pathsep + os.environ.get("PATH", "") + os.pathsep + str(script_dir) + os.pathsep + "/opt/venv/bin",
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
            # max_rounds: -1 = 无限轮 (服务配置语义), 映射为 999; 0/None=3 默认
            _mr = int(getattr(cfg, "max_rounds", 3) or 3)
            max_rounds = 999 if _mr < 0 else max(1, _mr)
            for rnd in range(1, max_rounds + 1):
                if self._cancel_event is not None and self._cancel_event.is_set():
                    status, err_msg = TaskStatus.FAILED, "autonomous: cancelled"
                    break
                round_session = sessions_dir / f"autonomous-r{rnd:02d}.jsonl"
                prompt = entry_prompt if rnd == 1 else self._resume_prompt(shared_run_dir, rnd)
                if not prompt:
                    break  # 无可续探
                self._emit("v2_autonomous_round", round=rnd, session=str(round_session))
                logger.info("[AUTO] round=%d START session=%s", rnd, str(round_session)[-60:])
                # 本轮 context session 路径 (report_finding 用)
                base_env["DVS_CONTEXT_SESSION"] = str(round_session)
                result = run_agent(
                    prompt=prompt, model=acfg.model, tools=acfg.tools or cfg.workers.default_tools,
                    cwd=str(shared_run_dir), session_file=str(round_session), system_prompt=system_prompt,
                    cancel_event=self._cancel_event, env=base_env,
                    thinking_level="off",
                    run_timeout_seconds=cfg.agent_run_timeout_seconds,
                    timeout_retry_enabled=cfg.agent_timeout_retry_enabled,
                    timeout_max_retries=cfg.agent_timeout_max_retries,
                    pi_max_retries=cfg.pi_max_retries, pi_retry_delay=cfg.pi_retry_delay,
                    task_context={"task_id": tid, "task_root": str(shared_run_dir.parent),
                                  "task_run_root": str(shared_run_dir),
                                  "task_pi_dir": cfg.role_pi_dir("workers"), "agent_role": "workers",
                                  "fork_purpose": "autonomous_round"},
                    retry_prompt=("## 续探 (重试)\n刚才你的探索因 pi 崩溃/超时中断。session 历史仍在。"
                                  "请**从上次中断处继续**探索, 不要从头重来。回顾你已读的函数 + 正在追的污点路径,"
                                  "继续往深挖 + 发现漏洞即 report_finding。结束时 checkpoint。"),
                    extension="/opt/dataflow_vuln_scan/extensions/restricted-bash.ts")
                # 诊断日志: 记录每轮 run_agent 结果 (error/exit/timeout) 供后续判断
                _err = getattr(result, "error", "") or ""
                logger.info("[AUTO] round=%d DONE exit=%s error=%s output_len=%d",
                            rnd, getattr(result, "exit_code", None), _err[:100], len(getattr(result, "output", "") or ""))
                _ec = getattr(result, "exit_code", None)
                _co = getattr(result, "context_overflow_failed_after_compaction", False)
                _outlen = len(getattr(result, "output", "") or "")
                self._emit("v2_autonomous_round_result", round=rnd,
                           error=str(_err)[:200], exit_code=_ec,
                           context_overflow=_co, output_len=_outlen,
                           has_output=_outlen > 0)
                if self._cancel_event is not None and self._cancel_event.is_set():
                    status, err_msg = TaskStatus.FAILED, "autonomous: cancelled"
                    break
                # 检测 pi 异常退出 (SIGTERM=143 被 pod rollout/worker 重启杀, 非零=崩溃)
                # 不当正常完成 pass — raise 让 celery 失败 → 任务留 running → stale-reset → pending → 重派
                if _ec is not None and _ec not in (0, 1) and not _co:
                    self._emit("v2_autonomous_pi_killed", round=rnd, exit_code=_ec, error=str(_err)[:200])
                    raise _PiKilledExternally(f"pi exited abnormally (exit_code={_ec}), likely pod rollout/worker restart")
                # 读 checkpoint
                ck = self._read_checkpoint(shared_run_dir)
                self._emit("v2_autonomous_checkpoint", round=rnd, checkpoint=ck)
                # Q2 诊断: checkpoint 决策日志
                _cont = ck.get("continue")
                _pend = len(ck.get("pending_branches") or [])
                _will_break = (not _cont) and (_pend == 0)
                self._emit("v2_autonomous_q2_decision", round=rnd,
                           continue_val=str(_cont), pending_count=_pend,
                           will_break=_will_break)
                import sys as _sys2
                _sys2.stderr.write(f"Q2DBG round={rnd} continue={_cont} pending={_pend} will_break={_will_break}\n")
                _sys2.stderr.flush()
                if not ck:
                    break  # 无 checkpoint (异常)
                # Q2: agent 说不继续 BUT 有 pending_branches -> 仍续探 (不盲从 continue=false)
                if not ck.get("continue") and not ck.get("pending_branches"):
                    break  # 真完成: 不继续 + 无未探索分支
            # 任务完成: 输出探索路径 + 剩余 pending
            self._emit("v2_autonomous_done", round=rnd if 'rnd' in dir() else 0,
                        path_steps=self._count_path(shared_run_dir))
        except _PiKilledExternally:
            raise  # re-raise: 让 celery 失败 → 任务留 running → stale-reset → pending → 重派
        except Exception as exc:
            logger.exception("autonomous runner failed")
            status, err_msg = TaskStatus.ERROR, str(exc)

        # Q3: 从 path.log 提取调用边写入 orchestration.db 供前端展示
        self._build_call_tree_from_path(shared_run_dir, store, root_func)
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

    def _build_call_tree_from_path(self, run_dir: Path, store, root_func) -> None:
        """Q3: 从 path.log 提取调用边写入 orchestration.db 供前端展示调用树。

        path.log 是扁平轨迹, 两类条目构成调用树:
        - read_function / v2_db_lookup: agent 读了函数体 (A→B 连续读 = A 调 B 的边)
        - grep_function: agent 搜到的函数 (matched_funcs 从上一个读过的函数分叉)
        """
        from .models import OrchestrationEdge, TaintParamInfo
        p = run_dir / "path.log"
        if not p.exists():
            return
        # 解析全部条目, 保留顺序
        all_entries = []
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            all_entries.append(d)
        if not all_entries:
            return
        path_id = "autonomous"
        edge_count = 0
        # 上一个读过的函数 (read_function/v2_db_lookup 的 func), 作为 grep 分叉的父
        last_read_func = None
        last_read_entry = None
        depth = 0
        for d in all_entries:
            via = d.get("via", "")
            if via in ("read_function", "v2_db_lookup") and d.get("func"):
                func = d["func"]
                if last_read_entry and last_read_entry["func"] != func:
                    # 连续读 A→B = 调用边
                    src_rec = store.find_function(last_read_entry["func"], last_read_entry.get("file", ""))
                    tgt_rec = store.find_function(func, d.get("file", ""))
                    edge = OrchestrationEdge(
                        path_id=path_id,
                        source_function=last_read_entry["func"],
                        source_signature=last_read_entry.get("signature", ""),
                        source_func_id=src_rec.func_id if src_rec else "",
                        target_function=func,
                        target_signature=d.get("signature", ""),
                        target_func_id=tgt_rec.func_id if tgt_rec else "",
                        taint_params=TaintParamInfo(),
                        depth=depth, edge_order=depth, status="done")
                    try:
                        store.upsert_edge(edge)
                        edge_count += 1
                    except Exception:
                        logger.debug("upsert_edge failed for %s->%s", last_read_entry["func"], func, exc_info=True)
                    depth += 1
                last_read_func = func
                last_read_entry = d
            elif via == "grep_function" and last_read_entry:
                # grep 的 matched_funcs 从上一个读过的函数分叉
                for mf in (d.get("matched_funcs") or []):
                    if not isinstance(mf, str) or mf.startswith("<global:"):
                        continue  # 跳过非函数 (全局代码)
                    if mf == last_read_entry["func"]:
                        continue  # 跳过自引用
                    tgt_rec = store.find_function(mf, "")
                    edge = OrchestrationEdge(
                        path_id=path_id,
                        source_function=last_read_entry["func"],
                        source_signature=last_read_entry.get("signature", ""),
                        source_func_id=store.find_function(last_read_entry["func"], last_read_entry.get("file", "")).func_id if store.find_function(last_read_entry["func"], last_read_entry.get("file", "")) else "",
                        target_function=mf,
                        target_signature=tgt_rec.signature if tgt_rec else "",
                        target_func_id=tgt_rec.func_id if tgt_rec else "",
                        taint_params=TaintParamInfo(),
                        depth=depth, edge_order=depth, status="pending")
                    try:
                        store.upsert_edge(edge)
                        edge_count += 1
                    except Exception:
                        logger.debug("upsert_edge failed for grep %s->%s", last_read_entry["func"], mf, exc_info=True)
                    depth += 1
        self._emit("v2_autonomous_call_tree", edges=edge_count)

    def _resume_prompt(self, run_dir: Path, rnd: int) -> str:
        """构造续探 prompt: 注入已探索路径 + pending_branches。"""
        ck = self._read_checkpoint(run_dir)
        pending = ck.get("pending_branches") or []
        if not pending:
            self._emit("v2_autonomous_resume_empty", round=rnd, reason="no pending_branches", ck_keys=list(ck.keys()))
            import sys as _sys3
            _sys3.stderr.write(f"RESUMEDBG round={rnd} empty: ck_keys={list(ck.keys())}\n")
            _sys3.stderr.flush()
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
