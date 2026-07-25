"""failure_debug.py — 任务失败时 LLM 自动调试，生成故障定位报告。

独立角色 `debugger`（单独 Pod），不影响 api/worker。被动接收任务终态下发
（worker 在任务 failed/error/completed_limited 时 POST /internal/failure-debug），
用内存队列 + worker 线程串行处理。启动时扫一次 pending/stale-running 行
（处理重启前已下发但未处理的任务）。

对每个尚无报告的失败任务启动一次 pi Agent 调试，输出：
问题现象 / 问题根因 / 解决方法 / 代码现场 / 补丁代码。

报告存放：NFS {output_path}/{task_id}/output/failure_debug_report.{md,json}
索引：DB 表 secflow_app_dvs_failure_debug（供前端列表/详情/下载）。

约束：纯 threading + time.sleep，无 asyncio。
"""

from __future__ import annotations

import json
import logging
import os
import queue
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from app.config import OUTPUT_DIR
import app.db as _dbmod
from app.db.models import AppDvsFailureDebug, AppDvsTask, AppDvsTaskEvent

logger = logging.getLogger("dvs.failure_debug")

POLL_INTERVAL = float(os.environ.get("DVS_FAILURE_DEBUG_POLL_INTERVAL", "30"))
MAX_EVENT_CONTEXT = int(os.environ.get("DVS_FAILURE_DEBUG_MAX_EVENTS", "60"))


def _timeout_env(name: str) -> float | None:
    """超时 env: 未设/<=0 → None (不限制 LLM 时间)。"""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        v = float(raw)
        return v if v > 0 else None
    except ValueError as e:
        logger.debug("parse float raw failed: %s", e)
        return None


# debugger 的 LLM 调试默认不限制时间 (run_agent 传 None = 无超时)
RUN_TIMEOUT = _timeout_env("DVS_FAILURE_DEBUG_TIMEOUT")
SEGMENT_TIMEOUT = _timeout_env("DVS_FAILURE_DEBUG_SEGMENT_TIMEOUT")
DEBUG_MODEL = os.environ.get("DVS_FAILURE_DEBUG_MODEL", "").strip()
SOURCE_ROOT = os.environ.get("DVS_FAILURE_DEBUG_SOURCE_ROOT", "/app")
PI_DIR = os.environ.get("PI_CODING_AGENT_DIR", "/root/.pi/agent")

# 需调试的终态：failed/error 是明确失败；completed_limited 是"部分完成但有函数失败"
_DEBUG_STATUSES = ("failed", "error", "completed_limited")

_instance: "FailureDebugService | None" = None
_lock = threading.Lock()


class FailureDebugService:
    """单例：被动接收下发的调试任务（不主动轮询任务表）。

    worker 在任务终态后 POST /internal/failure-debug {task_id} → submit()。
    本服务用内存队列 + worker 线程串行处理。启动时扫一次 pending/
    stale-running 行（处理重启前已下发但未处理的任务）。
    """

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._queue: "queue.Queue[str]" = queue.Queue()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._reset_stale_running_on_startup()
        self._enqueue_pending_rows()
        self._thread = threading.Thread(
            target=self._worker_loop, name="dvs_failure_debug", daemon=True
        )
        self._thread.start()
        logger.info("FailureDebugService started (notify-driven, model=%s)", DEBUG_MODEL or "auto")

    def stop(self) -> None:
        self._stop_event.set()
        try:
            self._queue.put_nowait("")
        except Exception as e:
            logger.debug("put_nowait keepalive failed (queue full?): %s", e)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        self._thread = None

    def submit(self, task_id: str) -> None:
        """worker 下发：入队一个调试任务。"""
        if not task_id:
            return
        self._queue.put(task_id)
        logger.info("failure-debug task submitted: %s", task_id)

    def _reset_stale_running_on_startup(self) -> None:
        try:
            if _dbmod._SessionLocal is None:
                return
            db = _dbmod._SessionLocal()
            try:
                n = db.query(AppDvsFailureDebug).filter(
                    AppDvsFailureDebug.status == "running"
                ).update(
                    {AppDvsFailureDebug.status: "error",
                     AppDvsFailureDebug.debug_error: "startup_reset: stale running"},
                    synchronize_session=False,
                )
                db.commit()
                if n:
                    logger.info("startup: reset %d stale running failure_debug rows to error", n)
            finally:
                db.close()
        except Exception:
            logger.exception("startup stale running reset failed")

    def _enqueue_pending_rows(self) -> None:
        """启动扫描：把已下发(pending)/重试(error)的行入队处理。"""
        try:
            if _dbmod._SessionLocal is None:
                return
            db = _dbmod._SessionLocal()
            try:
                rows = db.query(AppDvsFailureDebug).filter(
                    AppDvsFailureDebug.status.in_(("pending", "error"))
                ).all()
                for r in rows:
                    self._queue.put(r.task_id)
                if rows:
                    logger.info("startup: enqueued %d pending/error failure_debug rows", len(rows))
            finally:
                db.close()
        except Exception:
            logger.exception("startup pending enqueue failed")

    # ── worker 循环（被动消费队列，不轮询任务表）────────────────────────────
    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                task_id = self._queue.get(timeout=5.0)
            except queue.Empty as e:
                logger.debug("failure_debug queue empty: %s", e)
                continue
            if not task_id:
                continue
            try:
                self._debug_one_by_id(task_id)
            except Exception:
                logger.exception("debug failed for task %s", task_id)
            try:
                self._queue.task_done()
            except Exception as e:
                logger.debug("task_done failed (queue closed?): %s", e)

    def _debug_one_by_id(self, task_id: str) -> None:
        """从 DB 加载任务并调试。"""
        if _dbmod._SessionLocal is None:
            logger.warning("DB not ready, skip debug for %s", task_id)
            return
        db = _dbmod._SessionLocal()
        try:
            task = db.query(AppDvsTask).filter(AppDvsTask.task_id == task_id).first()
            if task is None:
                logger.warning("task %s not found in DB, skip debug", task_id)
                return
            self._debug_one(db, task)
        finally:
            db.close()

    # ── 单任务调试 ────────────────────────────────────────────────────────
    def _debug_one(self, db, task: AppDvsTask) -> None:
        # 创建/获取报告行
        row = db.query(AppDvsFailureDebug).filter(AppDvsFailureDebug.task_id == task.task_id).first()
        if row is None:
            row = AppDvsFailureDebug(
                task_id=task.task_id,
                project_id=task.project_id,
                task_name=task.task_name,
                status="running",
            )
            db.add(row)
        else:
            row.status = "running"
            row.debug_error = None
        db.commit()
        db.refresh(row)
        report_id = row.id

        try:
            context = self._collect_context(db, task)
            # 外部/基础设施错误（非本微服务代码问题）→ 跳过，不跑 LLM
            ext = self._external_error_reason(context.get("error_msg") or "")
            if ext:
                row.status = "skipped"
                row.error_kind = context.get("error_kind")
                row.failing_stage = context.get("failing_stage")
                row.summary = f"[已跳过] {ext}"
                row.debug_error = f"external_error_skipped: {ext}"
                db.commit()
                logger.info("failure debug skipped for task %s (external: %s)", task.task_id, ext)
                return
            report = self._run_llm_debug(task, context)
            self._save_report(task, report)
            row.status = "done"
            row.error_kind = context.get("error_kind")
            row.failing_stage = context.get("failing_stage")
            row.summary = (report.get("phenomenon") or "")[:500]
            row.report_path = self._report_md_path(task)
            row.report_json = report
            row.debug_error = None
            db.commit()
            logger.info("failure debug done for task %s (report_id=%s)", task.task_id, report_id)
        except Exception as exc:
            db.rollback()
            # 重新取行（rollback 后可能 expired）
            row = db.query(AppDvsFailureDebug).filter(AppDvsFailureDebug.task_id == task.task_id).first()
            if row:
                row.status = "error"
                row.debug_error = str(exc)[:2000]
                db.commit()
            logger.exception("failure debug error for task %s: %s", task.task_id, exc)

    # ── 收集错误上下文 ────────────────────────────────────────────────────
    def _collect_context(self, db, task: AppDvsTask) -> dict[str, Any]:
        # DVS 事件存 DB（secflow_app_dvs_task_events），不是 events.jsonl
        events = self._load_events_tail(db, task.task_id, MAX_EVENT_CONTEXT)

        # 推断失败阶段 + error_kind
        failing_stage = None
        error_kind = None
        for ev in reversed(events):
            etype = str(ev.get("event_type") or "")
            level = str(ev.get("level") or "")
            stage = ev.get("stage") or ev.get("stage_name")
            func = ev.get("function_name")
            if level in ("error", "warn") or "error" in etype or "fail" in etype or etype == "stage_error":
                failing_stage = failing_stage or (str(stage) if stage else (str(func) if func else None))
                if not error_kind:
                    error_kind = etype or level
                break
            if stage and not failing_stage:
                failing_stage = str(stage)
            if func and not failing_stage:
                failing_stage = str(func)

        # 异常原因 JSON
        abnormal = task.latest_abnormal_reason_json or {}
        if not isinstance(abnormal, dict):
            abnormal = {}
        err_msg = task.error or ""
        # 兜底：从错误信息模式匹配 error_kind
        if not error_kind:
            error_kind = self._classify_error_kind(err_msg) or (abnormal.get("error_kind") if isinstance(abnormal, dict) else None)
        if not failing_stage:
            failing_stage = (abnormal.get("stage") if isinstance(abnormal, dict) else None) or self._guess_stage_from_error(err_msg)

        return {
            "task_id": task.task_id,
            "task_name": task.task_name,
            "project_id": task.project_id,
            "status": task.status,
            "error_msg": err_msg,
            "error_kind": error_kind,
            "failing_stage": failing_stage,
            "abnormal_reason": json.dumps(abnormal, ensure_ascii=False) if abnormal else "",
            "events_tail": events,
            "events_total": len(events),
        }

    def _load_events_tail(self, db, task_id: str, limit: int) -> list[dict]:
        """从 DB 读取任务时间线事件（最后 limit 条）。"""
        try:
            rows = (
                db.query(AppDvsTaskEvent)
                .filter(AppDvsTaskEvent.task_id == task_id)
                .order_by(AppDvsTaskEvent.created_at.desc())
                .limit(limit)
                .all()
            )
            rows = list(reversed(rows))  # 恢复时间正序
            out: list[dict] = []
            for r in rows:
                payload = {}
                if r.payload_json:
                    try:
                        loaded = json.loads(r.payload_json)
                        if isinstance(loaded, dict):
                            payload = loaded
                    except Exception as e:
                        logger.warning("parse failure_debug payload json failed: %s", e, exc_info=True)
                out.append({
                    "ts": r.created_at.isoformat() if r.created_at else "",
                    "event_type": r.event_type,
                    "level": r.level,
                    "stage": payload.get("stage") or payload.get("stage_name"),
                    "function_name": r.function_name,
                    "message": r.message,
                    "payload": payload,
                })
            return out
        except Exception:
            logger.exception("load events tail failed for %s", task_id)
            return []

    # ── 错误分类（从错误消息模式匹配）────────────────────────────────────
    def _external_error_reason(self, err_msg: str) -> str | None:
        """识别非本微服务的外部/基础设施错误，返回原因（需跳过 LLM 分析）；None=本服务错误。"""
        if not err_msg:
            return None
        e = err_msg.lower()
        # 1. 任务源文件丢失
        if "no such file" in e or "not a directory" in e or "源文件" in err_msg or "input_path" in e \
                or "does not exist" in e or "找不到" in err_msg or "文件不存在" in err_msg \
                or "invalid_input" in e:
            return "任务源文件/输入丢失"
        # 2. 模型选择错误
        if "model" in e and ("not found" in e or "不可用" in e or "no model" in e or "无可用" in err_msg) \
                or ('model "' in e and 'not found' in e):
            return "模型选择错误"
        # 3. key 错误
        if "401" in e or "unauthorized" in e or "invalid api key" in e or "key authentication" in e \
                or ("api key" in e and ("invalid" in e or "无效" in err_msg)) or "认证失败" in err_msg:
            return "API key 错误"
        # 4. 模型超时 / 不可达
        if "timed out" in e or "timeout" in e or "http 000" in e \
                or "connection refused" in e or "connection reset" in e \
                or "unreachable" in e or "couldn't connect" in e or "connection error" in e:
            return "模型超时/不可达"
        return None

    def _classify_error_kind(self, err_msg: str) -> str | None:
        """从 task.error 文本推断错误类型。"""
        if not err_msg:
            return None
        e = err_msg.lower()
        if "script_validation_failed" in e:
            return "ScriptValidationFailed"
        if "foreign key constraint failed" in e:
            return "ForeignKeyConstraint"
        if "root function analysis failed" in e:
            return "RootFunctionAnalysisFailed"
        if "name '" in e and "is not defined" in e:
            return "NameError"
        if "[errno 17]" in e or "file exists" in e:
            return "FileExistsError"
        if "[errno 39]" in e or "directory not empty" in e:
            return "DirectoryNotEmptyError"
        if "[errno" in e:
            return "OSError"
        if "context length" in e or "input tokens" in e:
            return "ContextOverflow"
        if "key authentication" in e or "401" in e:
            return "AuthError"
        if "no model" in e or ("model" in e and "not found" in e):
            return "NoModelError"
        if "timeout" in e or "timed out" in e:
            return "TimeoutError"
        if "connection" in e and ("refused" in e or "reset" in e or "unreachable" in e):
            return "ConnectionError"
        return None

    def _guess_stage_from_error(self, err_msg: str) -> str | None:
        """从错误消息猜失败阶段。"""
        if not err_msg:
            return None
        e = err_msg.lower()
        if "worker" in e or "taint" in e:
            return "worker"
        if "round" in e:
            return "round"
        if "trace" in e:
            return "trace"
        if "vuln" in e or "mining" in e:
            return "vuln_mining"
        if "orchestrat" in e:
            return "orchestrator"
        if "dispatch" in e or "lease" in e:
            return "dispatch"
        return None

    # ── 运行 LLM 调试（分段多轮会话）───────────────────────────────
    def _run_llm_debug(self, task: AppDvsTask, context: dict[str, Any]) -> dict[str, Any]:
        from app.runner import run_agent  # 延迟导入避免循环

        model = self._resolve_debug_model()
        if not model:
            raise RuntimeError("无可用 LLM 模型（models.json 为空或未配置 DVS_FAILURE_DEBUG_MODEL）")

        events_text = self._format_events(context.get("events_tail") or [])
        tmp_dir = tempfile.mkdtemp(prefix="dvs_fdebug_")
        session_file = str(Path(tmp_dir) / "debug_session.jsonl")
        try:
            task_context = {
                "task_id": task.task_id,
                "task_root": str(Path(task.output_path or OUTPUT_DIR) / task.task_id),
                "task_run_root": str(Path(task.output_path or OUTPUT_DIR) / task.task_id / "run"),
                "task_pi_dir": PI_DIR,
                "agent_role": "failure_debugger",
            }
            common = dict(
                model=model,
                tools=["read", "bash", "find"],
                system_prompt=self._system_prompt(),
                cwd=SOURCE_ROOT,
                env=None,
                thinking_level="off",
                max_retries=2,
                retry_delay=10.0,
                timeout_retry_enabled=False,
                pi_max_retries=1,
                pi_retry_delay=2.0,
                task_context=task_context,
            )
            # Turn 0: 上下文 + 检查源码（本轮不产出报告，只建立会话上下文）
            ar = run_agent(
                prompt=self._build_intro_prompt(context, events_text),
                session_file=session_file,
                run_timeout_seconds=RUN_TIMEOUT,
                **common,
            )
            self._check_agent_error(ar, "intro")
            # 分段产出：每段一个 user 消息，格式不对则 user 指出重做
            sections = [
                ("phenomenon", "问题现象", "结合错误信息和事件时间线，描述观察到的失败现象"),
                ("root_cause", "问题根因", "分析为什么会发生此失败，涉及哪个组件/代码逻辑"),
                ("solution", "解决方法", "给出清晰的修复步骤"),
                ("code_scene", "代码现场", "定位文件路径:行号，给出相关代码片段（用```包裹）"),
                ("patch_code", "补丁代码", "给出建议修复补丁（diff 或完整函数代码，用```包裹）"),
            ]
            report: dict[str, Any] = {}
            for key, title, instruction in sections:
                report[key] = self._produce_segment(run_agent, session_file, common, title, instruction)
            report["_model"] = model
            return report
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _produce_segment(
        self, run_agent, session_file: str, common: dict, title: str, instruction: str,
    ) -> str:
        """一轮产出一段；格式问题用 user 指出后重做一次。"""
        prompt = (
            f"现在请输出【{title}】：{instruction}\n"
            f"只输出本段内容，不要重复其他段，不要额外说明。"
        )
        ar = run_agent(prompt=prompt, session_file=session_file, run_timeout_seconds=SEGMENT_TIMEOUT, **common)
        self._check_agent_error(ar, title)
        text = self._clean_segment((ar.output or "").strip())
        issue = self._validate_segment(title, text)
        if not issue:
            return text
        # 格式问题 → user 指出，重做
        redo = (
            f"你上一段【{title}】输出有问题：{issue}。"
            f"请重新输出【{title}】，只输出本段内容。"
        )
        logger.info("segment %s redo (issue=%s)", title, issue)
        ar = run_agent(prompt=redo, session_file=session_file, run_timeout_seconds=SEGMENT_TIMEOUT, **common)
        self._check_agent_error(ar, title + " redo")
        text = self._clean_segment((ar.output or "").strip())
        return text

    def _check_agent_error(self, ar, label: str) -> None:
        if ar.fatal:
            raise RuntimeError(f"pi 致命错误[{label}]: {ar.error or (ar.output or '')[:200]}")
        if not (ar.output or "").strip() and ar.error:
            raise RuntimeError(f"pi 无输出[{label}]: {ar.error}")

    def _clean_segment(self, text: str) -> str:
        """去掉 LLM 可能加的首尾占位文字（如 '好的：'），保留正文。"""
        text = text.strip()
        for prefix in ("好的。", "好的：", "好的,", "以下是", "好的，"):
            if text.startswith(prefix):
                text = text[len(prefix):].lstrip()
        return text.strip()

    def _validate_segment(self, title: str, text: str) -> str | None:
        """返回问题描述（None=合格）。"""
        if not text or len(text) < 20:
            return "内容过短或为空"
        return None

    def _pick_default_model(self) -> str:
        """从 models.json 选第一个可用模型 id。"""
        try:
            models_path = Path(PI_DIR) / "models.json"
            if not models_path.is_file():
                return ""
            data = json.loads(models_path.read_text(encoding="utf-8"))
            for _key, prov in (data.get("providers") or {}).items():
                for m in prov.get("models") or []:
                    mid = m.get("id")
                    if mid:
                        return str(mid)
        except Exception:
            logger.exception("pick_default_model failed")
        return ""

    def _resolve_debug_model(self) -> str:
        """调试模型优先级：DB 配置 > 环境变量 DVS_FAILURE_DEBUG_MODEL > models.json 第一个。"""
        # 1. DB 配置
        try:
            if _dbmod._SessionLocal is not None:
                from app.service.config_service import get_config_service
                db = _dbmod._SessionLocal()
                try:
                    cfg = get_config_service().get_failure_debug_config(db)
                    m = (cfg or {}).get("model")
                    if m:
                        return str(m)
                finally:
                    db.close()
        except Exception:
            logger.exception("resolve_debug_model DB read failed")
        # 2. 环境变量
        if DEBUG_MODEL:
            return DEBUG_MODEL
        # 3. models.json 第一个
        return self._pick_default_model()

    @staticmethod
    def list_available_models() -> list[dict]:
        """从 models.json 列出全部可用模型（provider/model_id 格式，供前端下拉）。"""
        out: list[dict] = []
        try:
            models_path = Path(PI_DIR) / "models.json"
            if not models_path.is_file():
                return out
            data = json.loads(models_path.read_text(encoding="utf-8"))
            for pk, prov in (data.get("providers") or {}).items():
                for m in prov.get("models") or []:
                    mid = m.get("id")
                    if mid:
                        full = f"{pk}/{mid}"
                        out.append({"value": full, "label": full})
        except Exception:
            logger.exception("list_available_models failed")
        return out

    # ── prompt 构建 ───────────────────────────────────────────────────────
    def _system_prompt(self) -> str:
        return (
            "你是数据流漏洞挖掘服务（secflow-app-dataflow-vuln-scan）的故障调试专家。\n"
            "你可以使用 read/bash/find 工具检查 /app 下的服务源码（Python）。\n"
            "关键代码：app/orchestrator.py（v1 BFS 编排）、app/vuln_workflow.py（v1 单函数 Worker+脚本校验）、"
            "app/dataflow_v2/（v2 路径敏感 DFS：orchestrator.py/analysis.py/store.py）、"
            "app/runner.py（pi 子进程调用）、app/service/task_service.py（任务执行/终态提交）、"
            "app/vuln_graph_validator.py（taint-graph JSON 校验）。\n"
            "本次调试分多轮进行：先检查源码理解失败，随后按用户要求逐段产出报告各部分。\n"
            "每轮只输出当轮要求的那一段，不要输出其他段，不要输出多余说明。\n"
        )

    def _build_intro_prompt(self, ctx: dict[str, Any], events_text: str) -> str:
        """Turn 0：给上下文 + 要求检查源码（不产出报告）。"""
        return (
            f"# 任务失败调试\n\n"
            f"## 任务信息\n"
            f"- task_id: {ctx.get('task_id')}\n"
            f"- task_name: {ctx.get('task_name')}\n"
            f"- 任务状态: {ctx.get('status')}\n"
            f"- 失败阶段: {ctx.get('failing_stage') or '未知'}\n"
            f"- 错误类型: {ctx.get('error_kind') or '未知'}\n\n"
            f"## 错误信息\n`````\n{ctx.get('error_msg') or '(无)'}\n`````\n\n"
            f"## 异常原因(JSON)\n`````\n{ctx.get('abnormal_reason') or '(无)'}\n`````\n\n"
            f"## 事件时间线(最后{len(ctx.get('events_tail') or [])}条，共{ctx.get('events_total',0)}条)\n"
            f"{events_text}\n\n"
            f"## 本轮任务\n"
            f"服务源码位于 /app。请用 read/bash/find 工具检查相关源码，定位导致失败的具体代码位置，"
            f"在脑中形成完整理解。**本轮不要输出报告**，只需简短确认你已定位到问题代码"
            f"（给出文件:行号即可）。后续我会逐段让你输出报告。\n"
        )

    def _format_events(self, events: list[dict]) -> str:
        if not events:
            return "(无事件)"
        lines = []
        for ev in events:
            ts = ev.get("ts") or ""
            etype = ev.get("event_type") or ""
            level = ev.get("level") or "info"
            stage = ev.get("stage") or ""
            func = ev.get("function_name") or ""
            msg = ev.get("message") or ""
            if isinstance(msg, (dict, list)):
                msg = json.dumps(msg, ensure_ascii=False)
            loc = f"{stage}/{func}" if stage or func else stage or func
            lines.append(f"[{ts}] [{level}] {loc} {etype}: {msg}")
        return "\n".join(lines)

    # ── 报告存储 ──────────────────────────────────────────────────────────
    def _report_md_path(self, task: AppDvsTask) -> str:
        output_path = task.output_path or OUTPUT_DIR
        return str(Path(output_path) / task.task_id / "output" / "failure_debug_report.md")

    def _save_report(self, task: AppDvsTask, report: dict[str, Any]) -> None:
        output_path = task.output_path or OUTPUT_DIR
        out_dir = Path(output_path) / task.task_id / "output"
        out_dir.mkdir(parents=True, exist_ok=True)
        # JSON
        json_path = out_dir / "failure_debug_report.json"
        json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        # Markdown
        md_path = out_dir / "failure_debug_report.md"
        md_path.write_text(self._render_md(task, report), encoding="utf-8")

    def _render_md(self, task: AppDvsTask, report: dict[str, Any]) -> str:
        lines = [
            f"# 任务失败调试报告",
            "",
            f"- **任务ID**: {task.task_id}",
            f"- **任务名称**: {task.task_name}",
            f"- **项目**: {task.project_id}",
            f"- **状态**: {task.status}",
            f"- **模型**: {report.get('_model', '未知')}",
            "",
            "## 问题现象",
            "",
            report.get("phenomenon") or "(无)",
            "",
            "## 问题根因",
            "",
            report.get("root_cause") or "(无)",
            "",
            "## 解决方法",
            "",
            report.get("solution") or "(无)",
            "",
            "## 代码现场",
            "",
            report.get("code_scene") or "(无)",
            "",
            "## 补丁代码",
            "",
            report.get("patch_code") or "(无)",
            "",
        ]
        return "\n".join(lines)


def get_failure_debug_service() -> FailureDebugService:
    global _instance
    with _lock:
        if _instance is None:
            _instance = FailureDebugService()
        return _instance
