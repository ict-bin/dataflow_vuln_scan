"""
orchestrator.py — 核心编排引擎

Orchestrator: 管理单函数分析的 Worker+Judge 轮次循环
execute_recursive: BFS 队列 + Worker Pool 递归分析调用链
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import shutil
import time
import hashlib
from collections import Counter
from pathlib import Path
from typing import Callable

from .config import load_system_prompts, resolve_system_prompt
from .models import (
    AgentInstanceConfig,
    JudgeRoundResult,
    JudgeSummary,
    RoundResult,
    SwarmEvent,
    TaskConfig,
    TaskResult,
    TaskStatus,
    TokenUsage,
    TraceNode,
    WorkerEvaluation,
    WorkerResult,
    CalleeRef,
    make_id,
    normalize_max_rounds_exceeded_review_strategy,
)
from .runner import run_agent, run_agents_parallel
from .vuln_workflow import DataflowVulnWorkflow
from .vuln_store import VulnScanStore, FollowupRecord
from .function_resolver import FunctionResolver, normalize_taint_params
from .callsite_analysis import analyze_callsite, map_taint_signature
from .validation_state import normalize_validation_state
from .followup_resolver import ResolutionContext, ResolutionResult, default_followup_resolver
from .tracker import run_tracker
from .param_analyzer import analyze as analyze_param_semantics
from .scheduler import TaintState, TaintEntry, ValidationCache, _normalize_taint_signature
from .global_cache import GlobalCache, compute_func_hash
from .vuln_workflow import build_function_summary_from_result

logger = logging.getLogger("dvs.orchestrator")
from .judge_runner import JudgeMixin
from .parsers import (
    _extract_result,
    _find_dataflow_file,
    _read_tainted_list,
    _parse_callees,
    _parse_eval_md,
    _parse_summary_md,
    _STDLIB_SKIP,
    _get_best_output,
)
from .cpp_resolver import _function_has_definition, _resolve_cpp_name, _get_definition_line, _find_function_file, _resolve_virtual_override_if_stub, _find_virtual_override_candidates_if_stub
from .prompt_builder import (
    _build_worker_prompt,
    _build_eval_prompt,
    _build_summary_prompt,
    _build_feedback_md,
    _report,
    _format_final_output,
    _make_result_filename,
)

def _is_external_followup(callee: CalleeRef) -> bool:
    text = f"{callee.file} {callee.description} {callee.function_name}".lower()
    # External classification is definition-driven; this helper only detects explicit markers.
    return any(mark in text for mark in ["dlsym", "external symbol", "extern symbol", "system library", "third-party", "外部库", "外部符号"])

def _normalize_followup_taint_params(raw: str | None) -> list[str]:
    text = str(raw or "").strip()
    if not text:
        return []
    normalized: list[str] = []
    for item in text.split(","):
        symbol = item.strip()
        if not symbol or symbol == "*":
            continue
        symbol = symbol.lstrip("&").strip()
        if symbol.startswith("v") and symbol[1:].isdigit():
            continue
        normalized.append(symbol)
    return normalized


def _resolve_function_pointer_followup(target_dir: str, callee: CalleeRef, caller_func: str) -> tuple[str, str]:
    """Best-effort resolver for function-pointer/dlsym followups such as engine_create_op -> lcr_create."""
    raw = callee.function_name.strip()
    hay = " ".join([raw, callee.file, callee.description])
    m = re.search(r"(?:dlsym|→|->|=>)\s*([A-Za-z_]\w*)", hay)
    if m:
        candidate = m.group(1)
    elif raw.startswith("engine_") and raw.endswith("_op"):
        candidate = raw[len("engine_"):-len("_op")]
        candidate = f"lcr_{candidate}" if not candidate.startswith("lcr_") else candidate
    else:
        candidate = raw
    if candidate and candidate != raw and _function_has_definition(target_dir, candidate):
        rel_file = _find_function_file(target_dir, candidate) or ""
        if rel_file:
            full = os.path.realpath(os.path.join(target_dir, rel_file))
            root = os.path.realpath(target_dir)
            if not (full == root or full.startswith(root + os.sep)):
                return raw, ""
        return candidate, rel_file
    return raw, ""


def _sanitize_callee_name(raw: str) -> list[str]:
    """Generate progressively cleaned candidate names from LLM-produced callee names.

    LLM workers sometimes embed qualifiers inside the function name rather than putting
    them in the reason/description field.  This helper strips common qualifier patterns
    so the FunctionResolver gets a plain C/C++ identifier it can match.
    """
    raw = raw.strip().strip("`")
    candidates: list[str] = [raw]

    # 1.  Strip trailing parenthesised qualifier (only when there is content before it):
    #    "px_find_combo (通过 ...)" -> "px_find_combo"
    #    "next_client_auth_hook (函数指针)" -> "next_client_auth_hook"
    #    Avoid matching the entire string when it IS the wrapping paren.
    cleaned = re.sub(r"^(.+)\s*[\(（][^)）]*[\)）]\s*$", r"\1", raw)
    if cleaned != raw:
        candidates.append(cleaned.strip())

    # 2.  Strip wrapping parentheses:
    #    "(next_ProcessUtility_hook)" -> "next_ProcessUtility_hook"
    m = re.match(r"^[\(（]([^)）]+)[\)）]$", cleaned.strip())
    if m:
        inner = m.group(1).strip()
        if inner != cleaned:
            candidates.append(inner)

    # 3.  Pointer-through-member patterns (virtual dispatch):
    #    "pf->op->pull (function pointer)"  ->  "pull"
    #    "mp->op->push (函数指针)"         ->  "push"
    if "->" in cleaned:
        method = cleaned.rsplit("->", 1)[-1].strip()
        if method and method != cleaned:
            candidates.append(method)

    # 4.  Slash-separated alternatives (LLM suggests multiple):
    #    "ossl_aes_cbc_decrypt / ossl_aes_ecb_decrypt / aes_cbc_decrypt"
    if "/" in cleaned:
        for part in cleaned.split("/"):
            part = part.strip()
            if part and part != cleaned:
                candidates.append(part)

    # 5.  Drop placeholder middle scope:
    #    "ZmqSocket::sock_::RecvMsg" -> "ZmqSocket::RecvMsg"
    if "::" in cleaned and cleaned.count("::") >= 2:
        parts = cleaned.split("::")
        # If the second-to-last part looks like a placeholder (short, lowercase,
        # ends with underscore), try the name without it.
        middle = parts[-2]
        if len(middle) <= 6 and re.match(r"^[a-z_]+", middle):
            candidates.append("::".join(parts[:-2] + parts[-1:]))

    return [c for c in candidates if c.strip()]

    return f"round_{round_num:03d}"


def _safe_dir_name(value: str, *, max_len: int = 120) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-")
    if not safe:
        safe = "item"
    if len(safe) <= max_len:
        return safe
    digest = hashlib.sha1(value.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"{safe[:max_len - 11]}-{digest}"


def _nested_function_run_dir(root_out_dir: Path, tid: str, dep: int, func_name: str) -> Path:
    if dep <= 0:
        return root_out_dir
    logical = f"{tid}-{func_name}"
    return root_out_dir / "subtasks" / f"depth_{dep:02d}" / _safe_dir_name(logical)


def _relativize_round_artifacts(result: TaskResult, round_root: Path, root_out_dir: Path) -> None:
    for rnd in result.rounds or []:
        for worker in rnd.worker_results or []:
            if getattr(worker, "session_file", None):
                try:
                    worker.session_file = str((round_root / worker.session_file).resolve().relative_to(root_out_dir.resolve())).replace("\\", "/")
                except Exception:
                    try:
                        worker.session_file = str(Path(worker.session_file).resolve().relative_to(root_out_dir.resolve())).replace("\\", "/")
                    except Exception:
                        pass
        for judge in rnd.judge_results or []:
            if getattr(judge, "session_file", None):
                try:
                    judge.session_file = str((round_root / judge.session_file).resolve().relative_to(root_out_dir.resolve())).replace("\\", "/")
                except Exception:
                    try:
                        judge.session_file = str(Path(judge.session_file).resolve().relative_to(root_out_dir.resolve())).replace("\\", "/")
                    except Exception:
                        pass

class Orchestrator(JudgeMixin):

    def __init__(
        self,
        config: TaskConfig,
        on_event: Callable[[SwarmEvent], None] | None = None,
        session_dir: str = "./sessions",
    ):
        self.cfg = config
        self.on_event = on_event or (lambda e: None)
        self.session_dir = os.path.abspath(session_dir)
        self._cancel_event: asyncio.Event | None = None

    def _emit(self, etype: str, task_id: str, **data):
        try:
            self.on_event(SwarmEvent(type=etype, task_id=task_id, data=data))
        except Exception:
            pass

    def _is_cancelled(self) -> bool:
        return bool(self._cancel_event and self._cancel_event.is_set())

    def _raise_if_cancelled(self) -> None:
        if self._is_cancelled():
            raise asyncio.CancelledError("orchestrator cancelled")

    async def execute(
        self,
        task_id: str | None = None,
        *,
        archive: bool = True,
        depth: int = 0,
        max_depth: int = 0,
        run_dir: Path | None = None,
    ) -> TaskResult:
        cfg = self.cfg
        task_id = task_id or make_id()
        start = time.time()
        target_dir = os.path.abspath(cfg.cwd)  # /data/target(只读,源文件在这里)
        threshold = cfg.pass_threshold if cfg.pass_threshold is not None else math.ceil(cfg.judge_count / 2)
        self._cancel_event = asyncio.Event()
        max_rounds_strategy = normalize_max_rounds_exceeded_review_strategy(
            getattr(cfg, "max_rounds_exceeded_review_strategy", None)
        )

        # 任务目录结构: output_dir/task_id/input|run|output。递归函数子任务只在根 run/subtasks 下建中间目录。
        if run_dir is not None:
            out_dir = run_dir
            task_base = out_dir.parent
        else:
            task_base = Path(os.path.abspath(cfg.output_dir)) / task_id
            out_dir = task_base / "run"
        out_dir.mkdir(parents=True, exist_ok=True)

        # 归档模式且非子任务:立即写 flag=0 到 output/ 目录
        if archive:
            output_path = task_base / "output"
            output_path.mkdir(parents=True, exist_ok=True)
            (output_path / "flag").write_text("0", encoding="utf-8")

        sess_dir = out_dir / "sessions"
        sess_dir.mkdir(exist_ok=True)

        # 每个 Worker 独立可写工作目录(包含 target 文件的符号链接 + chroot 式环境隔离)
        worker_cwds: list[str] = []
        worker_envs: list[dict] = []
        for i in range(cfg.worker_count):
            wdir = out_dir / f"workspace-worker-{i}"
            wdir.mkdir(exist_ok=True)
            # tmp 子目录隔离临时文件
            wtmp = wdir / "tmp"
            wtmp.mkdir(exist_ok=True)
            # 将 target 目录下的文件链接到 worker 工作目录
            if os.path.isdir(target_dir):
                for item in os.listdir(target_dir):
                    src = os.path.join(target_dir, item)
                    dst = str(wdir / item)
                    if not os.path.exists(dst):
                        try:
                            os.symlink(src, dst)
                        except OSError:
                            pass
            worker_cwds.append(str(wdir))
            worker_envs.append({**os.environ, "HOME": str(wdir), "TMPDIR": str(wtmp)})


        worker_dir_prompts = load_system_prompts(cfg.workers.system_prompt_dir, cfg.worker_count)
        judge_dir_prompts = load_system_prompts(cfg.judges.system_prompt_dir, cfg.judge_count)

        # Worker session 文件(跨轮保持)
        worker_sessions = [str(sess_dir / f"worker-{i}.jsonl") for i in range(cfg.worker_count)]

        result = TaskResult(task_id=task_id, status=TaskStatus.RUNNING,
                            task=cfg.task, config_snapshot=cfg.model_dump())

        agents_desc = ([f"worker-{i}={a.model}" for i, a in enumerate(cfg.workers.agents)]
                       + [f"judge-{i}={a.model}" for i, a in enumerate(cfg.judges.agents)])
        self._emit("task_start", task_id, task=cfg.task, agents=agents_desc,
                   function=cfg.function_name, depth=depth)

        # 将 depth/max_depth 注入 context,Worker 据此决定是否需要追踪 callee
        # max_depth=0 时不注入(外部调用者未指定深度)
        if max_depth > 0:
            _depth_note = f"\n\n# 当前追踪深度: {depth}/{max_depth}" + (
                "(已达最大深度,callee 表格仍需填写但系统不会递归)"
                if depth >= max_depth else ""
            )
            cfg.context = (cfg.context or "").rstrip() + _depth_note

        try:
            feedback_for_workers = ""

            for rnd_num in (range(1, cfg.max_rounds + 1) if cfg.max_rounds >= 0 else __import__('itertools').count(1)):
                if self._is_cancelled():
                    break

                self._emit("round_start", task_id, round=rnd_num,
                           function=cfg.function_name, depth=depth)
                rnd_dir = out_dir / _round_dir_name(rnd_num)
                rnd_workers_dir = rnd_dir / "workers"
                rnd_judges_dir = rnd_dir / "judges"
                rnd_workers_dir.mkdir(parents=True, exist_ok=True)
                rnd_judges_dir.mkdir(parents=True, exist_ok=True)

                # ═══════════════════════════════════════════════════════
                # 1. Workers 并行执行
                # ═══════════════════════════════════════════════════════

                worker_prompt = _build_worker_prompt(
                    cfg.task, cfg.context, rnd_num, feedback_for_workers,
                    function_name=cfg.function_name,
                    source_file=cfg.source_file,
                    function_description=cfg.function_description,
                    function_description_source=cfg.function_description_source,
                    entry_reason=cfg.entry_reason,
                    entry_reason_source=cfg.entry_reason_source,
                    taint_details=cfg.taint_details,
                )

                w_tasks = []
                # write-dataflow skill 已安装到 ~/.pi/agent/skills/（支持该机制的模型可自动发现）
                # GLM-5 不支持 /skill: 命令，阶段4指令已直接内嵌入 Worker system prompt
                for i, acfg in enumerate(cfg.workers.agents):
                    self._raise_if_cancelled()
                    wid = f"worker-{i}"
                    self._emit("worker_start", task_id, worker_id=wid,
                               model=acfg.model, round=rnd_num,
                               function=cfg.function_name)
                    w_tasks.append({
                        "prompt": worker_prompt,
                        "model": acfg.model,
                        "tools": acfg.tools or cfg.workers.default_tools,
                        "system_prompt": resolve_system_prompt(i, acfg, worker_dir_prompts),
                        "cwd": worker_cwds[i],
                        "env": worker_envs[i],
                        "thinking_level": acfg.thinking_level or cfg.workers.default_thinking_level,
                        "session_file": worker_sessions[i],
                        # RPC 第二轮：分析完成后强制写入 tainted.list
                        "post_skill_prompt": (
                            "Based on your taint analysis above, now write the tainted.list file.\n\n"
                            "Use the **write** tool to create `tainted.list` in the current directory.\n"
                            "Format — one line per callee function that receives tainted parameters:\n\n"
                            "```\n"
                            "file_path###Class::FuncName###L_line###param1,param2\n"
                            "```\n\n"
                            "Rules:\n"
                            "- Only functions where tainted data flows IN as arguments\n"
                            "- NO getters, condition checks, logging, or stdlib functions\n"
                            "- file_path: path relative to workspace root (e.g. src-vul/openthread/...)\n"
                            "- Class::FuncName: fully qualified name\n"
                            "- params: the CALLEE's formal parameter names (not caller's variable names)\n"
                            "- Unknown field: use `-` for path/line, `*` for params\n\n"
                            "If no functions need follow-up (leaf function), write:\n"
                            "`# no callees`\n\n"
                            "Write ONLY tainted.list — do not rewrite the dataflow file."
                        ),
                        "cancel_event": self._cancel_event,
                        "max_retries": cfg.agent_max_retries,
                        "retry_delay": cfg.agent_retry_delay,
                        "run_timeout_seconds": cfg.agent_run_timeout_seconds,
                        "timeout_retry_enabled": cfg.agent_timeout_retry_enabled,
                        "timeout_max_retries": cfg.agent_timeout_max_retries,
                        "pi_max_retries": cfg.pi_max_retries,
                        "pi_retry_delay": cfg.pi_retry_delay,
                        "on_stream": lambda d, wid=wid: self._emit(
                            "worker_stream", task_id, worker_id=wid, delta=d),
                    })

                self._raise_if_cancelled()
                w_raw = await run_agents_parallel(w_tasks, concurrency=cfg.worker_count)
                self._raise_if_cancelled()

                round_workers: list[WorkerResult] = []
                for i, wr in enumerate(w_raw):
                    self._raise_if_cancelled()
                    wid = f"worker-{i}"
                    output = _extract_result(wr.output)
                    result.total_tokens += wr.token_usage

                    # 从 Worker 工作目录搜索 dataflow-*.md 文件
                    df_file = _find_dataflow_file(worker_cwds[i], cfg.function_name)
                    df_content = ""
                    if df_file:
                        try:
                            df_content = Path(df_file).read_text(encoding="utf-8")
                        except OSError:
                            pass

                            pass
                    # 后置校验:检查 dataflow 文件结构完整性
                    df_issues: list[str] = []
                    if not df_file or len(df_content.strip()) < 100:
                        df_issues.append(
                            f"[F1] {wid} 未将分析结果写入 dataflow-*.md 文件(或文件为空)\n"
                            f"     请使用 write 工具将完整分析写入 dataflow-{cfg.function_name}.md"
                        )
                    else:
                        # 检查是否包含目标函数名
                        func_short = cfg.function_name.split("::")[-1]
                        if func_short not in df_content and cfg.function_name not in df_content:
                            df_issues.append(
                                f"[F2] dataflow 文件内容不包含目标函数名 '{cfg.function_name}',"
                                f"可能分析了错误的函数\n     请确认分析的是 {cfg.source_file} 中的 {cfg.function_name}"
                            )
                    self._emit("worker_done", task_id, worker_id=wid,
                               output=output[:500],
                               dataflow_found=bool(df_file) and not df_issues,
                               df_issues=df_issues,
                               function=cfg.function_name)
                    round_workers.append(WorkerResult(
                        worker_id=wid, model=cfg.workers.agents[i].model,
                        output=output, dataflow_file=df_file or "",
                        token_usage=wr.token_usage, error=wr.error,
                        df_issues=df_issues))


                    # 每轮结束归档 session(不管成败都保留,供调试和下轮继续利用)
                    _sess_src = Path(worker_sessions[i])
                    if _sess_src.exists():
                        try:
                            import shutil as _shu
                            _shu.copy2(str(_sess_src), str(rnd_workers_dir / f"{wid}-session.jsonl"))
                        except OSError:
                            pass

                    # 归档 worker 摘要输出
                    (rnd_workers_dir / f"{wid}-output.md").write_text(output, encoding="utf-8")
                    # 归档 dataflow 文件(如果存在)
                    if df_content:
                        (rnd_workers_dir / f"{wid}-dataflow.md").write_text(df_content, encoding="utf-8")

                # ═══════════════════════════════════════════════════════
                # 2. Judges 逐个评判(每个 Judge 内多轮对话)
                # ═══════════════════════════════════════════════════════

                # Judge 之间并行,每个 Judge 内部串行(逐个评 Worker → 总结)
                for j_idx, j_acfg in enumerate(cfg.judges.agents):
                    self._emit("judge_start", task_id, judge_id=f"judge-{j_idx}",
                               model=j_acfg.model, round=rnd_num,
                               function=cfg.function_name)

                async def _run_one_judge(j_idx: int, j_acfg: AgentInstanceConfig) -> JudgeRoundResult:
                    return await self._run_judge_evaluation(
                        judge_idx=j_idx,
                        judge_cfg=j_acfg,
                        judge_sys_prompt=resolve_system_prompt(j_idx, j_acfg, judge_dir_prompts),
                        round_workers=round_workers,
                        task_id=task_id,
                        rnd_num=rnd_num,
                        cwd=target_dir,
                        sess_dir=sess_dir,
                        rnd_judges_dir=rnd_judges_dir,
                    )

                judge_tasks_async = [
                    _run_one_judge(j_idx, j_acfg)
                    for j_idx, j_acfg in enumerate(cfg.judges.agents)
                ]
                self._raise_if_cancelled()
                round_judges: list[JudgeRoundResult] = list(await asyncio.gather(*judge_tasks_async))
                self._raise_if_cancelled()

                # 汇总事件 + token
                for j_idx, j_result in enumerate(round_judges):
                    jid = f"judge-{j_idx}"
                    result.total_tokens += j_result.token_usage
                    for ev in j_result.evaluations:
                        self._emit("judge_eval", task_id, judge_id=jid,
                                   worker_id=ev.worker_id, passed=ev.passed,
                                   score=ev.score, feedback=ev.feedback[:200])
                    if j_result.summary:
                        self._emit("judge_summary", task_id, judge_id=jid,
                                   best=j_result.summary.best_worker_id,
                                   overall_passed=j_result.summary.overall_passed,
                                   reasoning=j_result.summary.reasoning[:200])

                # ═══════════════════════════════════════════════════════
                # 3. 汇总投票
                # ═══════════════════════════════════════════════════════

                pass_count = sum(1 for j in round_judges
                                 if j.summary and j.summary.overall_passed)
                # 对于单 worker 场景,用每个 judge 对该 worker 的 passed
                if cfg.worker_count == 1:
                    pass_count = sum(
                        1 for j in round_judges
                        if j.evaluations and j.evaluations[0].passed)

                is_passed = pass_count >= threshold

                # 找出最佳 worker(多数票)
                best_votes: Counter[str] = Counter()
                for j in round_judges:
                    if j.summary and j.summary.best_worker_id:
                        best_votes[j.summary.best_worker_id] += 1
                best_wid = best_votes.most_common(1)[0][0] if best_votes else round_workers[0].worker_id

                # 生成 feedback.md
                feedback_md = _build_feedback_md(
                    round_workers, round_judges, best_wid, rnd_num)
                (rnd_dir / "feedback.md").write_text(feedback_md, encoding="utf-8")

                rnd = RoundResult(
                    round=rnd_num,
                    worker_results=round_workers,
                    judge_results=round_judges,
                    pass_count=pass_count,
                    total_judges=cfg.judge_count,
                    passed=is_passed,
                    status="passed" if is_passed else "failed",
                    best_worker_id=best_wid,
                    feedback_to_workers=feedback_md,
                    completion_reason="passed" if is_passed else "",
                )
                result.rounds.append(rnd)

                self._emit("round_end", task_id, round=rnd_num,
                           passed=is_passed, pass_count=pass_count,
                           total_judges=cfg.judge_count, best_worker=best_wid,
                           function=cfg.function_name)

                if is_passed and rnd_num >= cfg.min_rounds:
                    result.status = TaskStatus.PASSED
                    best_w = next((w for w in round_workers if w.worker_id == best_wid), round_workers[0])
                    result.final_output = _get_best_output(best_w)
                    break

                if is_passed and rnd_num < cfg.min_rounds:
                    self._emit("round_reflection", task_id, round=rnd_num,
                               message=f"Round {rnd_num} passed but min_rounds={cfg.min_rounds}, forcing reflection")

                # 下一轮的反馈
                feedback_for_workers = feedback_md
                if cfg.max_rounds >= 0 and rnd_num == cfg.max_rounds:
                    best_w = next((w for w in round_workers if w.worker_id == best_wid), round_workers[0])
                    result.final_output = _get_best_output(best_w)
                    if max_rounds_strategy == "treat_as_passed":
                        result.status = TaskStatus.PASSED
                        rnd.status = "passed_with_max_rounds_policy"
                        rnd.module_completed = True
                        rnd.completion_reason = "max_rounds_exceeded_treated_as_passed"
                        result.completion_reason = "max_rounds_exceeded_treated_as_passed"
                    else:
                        result.status = TaskStatus.FAILED
                        rnd.completion_reason = "max_rounds_exceeded"
                        result.completion_reason = "max_rounds_exceeded"
                    break

        except asyncio.CancelledError:
            result.status = TaskStatus.ERROR
            result.error = "cancelled"
            self._emit("error", task_id, error="cancelled")
        except Exception as e:
            result.status = TaskStatus.ERROR
            result.error = str(e)
            self._emit("error", task_id, error=str(e))

        result.total_duration_ms = (time.time() - start) * 1000

        # ═══════════════════════════════════════════════════════════════
        # 最终处理:归档 + 格式化输出 + 压缩 + 清理
        # ═══════════════════════════════════════════════════════════════

        # 1) 写入报告到工作目录 (run/)
        (out_dir / "report.md").write_text(_report(result, cfg), encoding="utf-8")
        (out_dir / "result.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")

        if not archive:
            # 子任务模式:不写 output/，由根任务统一处理
            # ★ 关键:将 dataflow 文件内容写入 final_output 供 callee 解析
            _df_path = _find_dataflow_file(out_dir, cfg.function_name)
            if _df_path:
                try:
                    _df_text = Path(_df_path).read_text(encoding="utf-8")
                    if len(_df_text.strip()) > len((result.final_output or "").strip()):
                        result.final_output = _df_text
                except OSError:
                    pass
            self._cancel_event = None
            return result

        # 2) 格式化最终输出 → 写到 task_id/output/ 目录
        output_path = task_base / "output"
        output_path.mkdir(parents=True, exist_ok=True)
        cleaned_output = _format_final_output(result)
        result_filename = "final_report.md"
        (output_path / result_filename).write_text(cleaned_output, encoding="utf-8")
        result.final_output = cleaned_output

        # 3) 写 flag 文件(仅 PASSED 覆盖为 1,其他保持入口处写的 0)
        if result.status == TaskStatus.PASSED:
            (output_path / "flag").write_text("1", encoding="utf-8")

        self._emit("task_end", task_id,
                    status=result.status.value,
                    run_dir=str(out_dir),
                    result_file=str(output_path / result_filename))
        self._cancel_event = None
        return result

    def abort(self):
        if self._cancel_event:
            self._cancel_event.set()





    # ═══════════════════════════════════════════════════════════════════════
    # 递归分析入口
    # ═══════════════════════════════════════════════════════════════════════

    async def execute_recursive(
        self,
        task_id: str | None = None,
        depth: int = 0,
        tainted_context: str = "",
        _analyzed: set[str] | None = None,
        _root_out_dir: Path | None = None,
        _root_output_dir: Path | None = None,
    ) -> TaskResult:
        """BFS 队列 + 工作池架构:
        A 进入队列 → Worker 执行 W+J 分析 → 解析 callee B,C,D → 加入队列 → Worker 执行 B,C,D...
        并发数 = callee_concurrency(worker 数量),无 Semaphore 死锁问题。
        """
        cfg = self.cfg
        is_root = (depth == 0)
        if self._cancel_event is None:
            self._cancel_event = asyncio.Event()

        # ── 非根任务:直接执行 W+J 并返回,由根任务的工作池调度 ──────────────
        if not is_root:
            logical_task_id = task_id or make_id()
            out_dir = (
                _nested_function_run_dir(_root_out_dir, logical_task_id, depth, cfg.function_name)
                if _root_out_dir is not None
                else Path(os.path.abspath(cfg.output_dir)) / logical_task_id / "run"
            )
            result = await self.execute(
                logical_task_id,
                archive=False,
                depth=depth,
                max_depth=cfg.max_trace_depth,
                run_dir=out_dir,
            )
            df_path = _find_dataflow_file(out_dir, cfg.function_name)
            if df_path:
                try:
                    df_text = Path(df_path).read_text(encoding="utf-8")
                    if len(df_text.strip()) > len((result.final_output or "").strip()):
                        result.final_output = df_text
                except OSError:
                    pass
            return result

        # ── 根任务:BFS 队列 + 工作池 ────────────────────────────────────────
        max_depth = 10**9 if getattr(cfg, "deep_trace_enabled", False) else cfg.max_trace_depth
        # BFS 并发度：直接使用 callee_concurrency（1-64，1=串行，-1=自动）
        # 控制同时进行 W+J 分析的 BFS 工作池大小，与 taint 内部并行正交
        # callee_concurrency=-1 表示自动（默认 4）
        n_workers = max(1, cfg.callee_concurrency) if cfg.callee_concurrency > 0 else 4
        analyzed: set[str] = _analyzed if _analyzed is not None else set()
        validation_cache = ValidationCache()
        target_dir = os.path.abspath(cfg.cwd)
        global_cache = GlobalCache(target_dir)
        taint_state_stack: list[TaintState] = []  # DFS 调用链上的累积校验

        # 初始化根目录
        root_task_id = task_id or make_id()
        if _root_out_dir is not None:
            # 已经是 run/epochs/<epoch>/ 子目录；共享 run 工作区是其父父目录（run/）
            root_out_dir = _root_out_dir
            shared_run_dir = root_out_dir.parent.parent  # run/epochs/../.. = run/
        else:
            root_out_dir = Path(os.path.abspath(cfg.output_dir)) / root_task_id / "run"
            shared_run_dir = root_out_dir  # 旧路径模式，run/ 本身
        root_out_dir.mkdir(parents=True, exist_ok=True)
        shared_run_dir.mkdir(parents=True, exist_ok=True)

        # 正确的 output/ 路径：由调用方（task_service）传入，或根据任务根目录计算
        root_output_path = Path(_root_output_dir) if _root_output_dir is not None else (shared_run_dir.parent / "output")
        root_output_path.mkdir(parents=True, exist_ok=True)
        (root_output_path / "flag").write_text("0", encoding="utf-8")

        # 执行期间：图谱数据库和漏洞报告放在共享 run/ 工作区，最终归档时复制到 output/
        graph_db_path = shared_run_dir / "vuln-scan.sqlite"
        vuln_output_root = shared_run_dir / "vulnerabilities"
        vuln_output_root.mkdir(parents=True, exist_ok=True)

        # 所有 session 统一归档目录：run/sessions/
        root_sessions_dir = root_out_dir / "sessions"
        root_sessions_dir.mkdir(exist_ok=True)

        queue: asyncio.Queue = asyncio.Queue()
        all_results: dict[str, TaskResult] = {}   # func_key -> TaskResult
        sub_dataflow_files: list[tuple[str, str]] = []

        # 注册根函数（用 : 分隔符保持与后续 c_key 一致）
        root_key = cfg.source_file + ":" + cfg.function_name
        analyzed.add(root_key)

        self._emit("task_start", root_task_id, task=cfg.task,
                   agents=f"W={cfg.worker_count} J={cfg.judge_count}",
                   function=cfg.function_name, source_file=cfg.source_file)
        self._emit("trace_start", root_task_id,
                   function=cfg.function_name, source_file=cfg.source_file,
                   depth=0, max_depth=max_depth)

        # 根任务入队
        await queue.put((cfg.function_name, cfg.source_file, cfg.line_hint,
                         cfg.model_copy(deep=True), root_task_id, 0, tainted_context, None, "", ""))

        async def process_item(item: tuple) -> None:
            self._raise_if_cancelled()
            func_name, src_file, line_hint, task_cfg, tid, dep, taint_ctx, parent_session_file, followup_id, context_id = item
            try:
                _override_candidates = _find_virtual_override_candidates_if_stub(os.path.abspath(task_cfg.cwd), func_name, src_file, line_hint)
            except Exception:
                _override_candidates = []
            if len(_override_candidates) > 1:
                self._emit("trace_redirect", tid, function=func_name, source_file=src_file,
                           reason="base stub has multiple concrete overrides; fork all candidates",
                           depth=dep, candidate_count=len(_override_candidates),
                           candidates=[{"function": f, "source_file": s, "line": l} for f, s, l in _override_candidates])
                if followup_id:
                    try:
                        VulnScanStore(graph_db_path).update_followup_status(followup_id, "forked", reason="multiple concrete overrides")
                    except Exception:
                        pass
                for index, (_rf, _rs, _rl) in enumerate(_override_candidates):
                    _sub_cfg = task_cfg.model_copy(deep=True)
                    _sub_cfg.function_name = _rf
                    _sub_cfg.source_file = _rs
                    _sub_cfg.line_hint = _rl
                    _sub_tid = tid + f"-override{index}-{_rf[:25]}"
                    await queue.put((_rf, _rs, _rl, _sub_cfg, _sub_tid, dep, taint_ctx, parent_session_file, "", ""))
                return
            try:
                _rf, _rs, _rl, _rr = _resolve_virtual_override_if_stub(os.path.abspath(task_cfg.cwd), func_name, src_file, line_hint)
            except Exception:
                _rf, _rs, _rl, _rr = func_name, src_file, line_hint, ""
            if _rr:
                self._emit("trace_redirect", tid, function=func_name, source_file=src_file,
                           redirected_function=_rf, redirected_source_file=_rs,
                           redirected_line=_rl, reason=_rr, depth=dep)
                func_name, src_file, line_hint = _rf, _rs, _rl
                task_cfg.function_name = _rf
                task_cfg.source_file = _rs
                task_cfg.line_hint = _rl
            if followup_id:
                try:
                    VulnScanStore(graph_db_path).update_followup_status(followup_id, "running")
                    if context_id:
                        VulnScanStore(graph_db_path).update_analysis_context_status(context_id, "running")
                except Exception:
                    pass

            # 通知 CLI: 新函数开始
            self._emit("trace_start", tid,
                       function=func_name, source_file=src_file,
                       depth=dep, max_depth=max_depth)

            # 注入 tainted_context
            if taint_ctx and dep > 0:
                ctx_base = task_cfg.context or ""
                if "# 调用者传入的脏数据" in ctx_base:
                    ctx_base = ctx_base.split("# 调用者传入的脏数据")[0].strip()
                task_cfg.context = ctx_base + "\n\n# 调用者传入的脏数据\n" + taint_ctx

            # dataflow 输出目录
            df_dir = root_out_dir / "dataflow"
            df_dir.mkdir(exist_ok=True)
            safe_func = re.sub(r'[^A-Za-z0-9_:.-]', '_', func_name)
            out_dir = _nested_function_run_dir(root_out_dir, tid, dep, func_name)
            out_dir.mkdir(parents=True, exist_ok=True)

            # session 归档标签（用于 run/sessions/ 统一路径命名）
            _slabel = re.sub(r'[^A-Za-z0-9_.-]+', '_', func_name).strip('._-') or 'func'
            if len(_slabel) > 55:
                _slabel = f"{_slabel[:46]}-{hashlib.sha1(func_name.encode()).hexdigest()[:8]}"
            session_label = f"d{dep:02d}-{_slabel}"

            result: TaskResult | None = None
            completed_session_file: str = ""  # 完成后 worker session 路径，传递给 callee
            workflow: DataflowVulnWorkflow | None = None

            if result is None:
                self._raise_if_cancelled()
                _taint_match = re.search(r'外部输入参数.*?为[:：]\s*([^\n]+)', task_cfg.task or "")
                _taint_list: list[str] = []
                if _taint_match:
                    raw_taints = _taint_match.group(1)
                    _taint_list = [re.sub(r'[。，,（(].*', '', t).strip().strip('`')
                                   for t in raw_taints.split(',') if t.strip()]
                    _taint_list = [t for t in _taint_list if t and re.match(r'^[A-Za-z_]', t)]
                if not _taint_list:
                    _tc_m = re.search(r'污染参数[:\uff1a]\s*([^\n]+)', taint_ctx or "")
                    if _tc_m:
                        _taint_list = [t.strip().strip('`') for t in _tc_m.group(1).split(',') if t.strip()]
                if not _taint_list:
                    _taint_list = ["all"]
                # 执行：数据流污点跟踪 + 漏洞挖掘架构化工作流
                workflow = DataflowVulnWorkflow(
                    cfg=task_cfg,
                    func_name=func_name,
                    src_file=src_file,
                    line_hint=line_hint,
                    taint_params=(task_cfg.taint_params or _taint_list),
                    taint_ctx=taint_ctx or "",
                    task_id=tid,
                    out_dir=out_dir,
                    dep=dep,
                    max_depth=max_depth,
                    graph_db_path=graph_db_path,
                    vuln_output_root=vuln_output_root,
                    on_event=self.on_event,
                    cancel_event=self._cancel_event,
                    parent_session_file=parent_session_file,
                    sessions_archive_dir=root_sessions_dir,
                    session_label=session_label,
                )
                result = await workflow.run_taint_tracking_only()
                self._raise_if_cancelled()
                # 取完成后的 worker session 路径，用作各 callee 继承的 parent session
                completed_session_file = str(
                    result.upstream_entry_metadata.get("worker_session_file") or ""
                )
                # 将当前函数加入去重集合，防止后续 followup / tracker 回环到此函数
                _item_tc_m = re.search(r'污染参数[:\uff1a]\s*([^\n]+)', taint_ctx or "")
                _item_taints = task_cfg.taint_params or ([t.strip() for t in _item_tc_m.group(1).split(',')] if _item_tc_m else []) or ["all"]
                _item_identity = f"{src_file}:{func_name}"
                _item_taint_sig = normalize_taint_params(_item_taints)[1]
                analyzed.add(f"{_item_identity}:{_item_taint_sig}:none")
                try:
                    _item_ctx_id = "ctx_" + hashlib.sha1(f"{_item_identity}:{_item_taint_sig}".encode()).hexdigest()[:16]
                    VulnScanStore(graph_db_path).upsert_analysis_context(
                        context_id=_item_ctx_id,
                        function_identity=_item_identity,
                        source_file=src_file,
                        function_name=func_name,
                        taint_signature=_item_taint_sig,
                        validation_signature="none",
                        validation_risk_rank=100,
                        risk_class="no_validation",
                        status="analyzed",
                    )
                except Exception:
                    pass

                # ── 写全局缓存：脚本提取函数摘要 ──────────────────────────
                try:
                    _local_target_dir = os.path.abspath(task_cfg.cwd)
                    _item_taint_sig = _normalize_taint_signature(task_cfg.taint_params or _item_taints)
                    _item_func_h = compute_func_hash(_local_target_dir, src_file, func_name) or "0"
                    _summary_data = build_function_summary_from_result(
                        result, task_cfg.taint_params or _item_taints, _item_func_h
                    )
                    from .global_cache import FunctionSummary
                    _summary = FunctionSummary.from_json(_summary_data)
                    global_cache.put(
                        func_name, src_file, _item_taint_sig, _item_func_h, _summary,
                    )
                except Exception as _cache_exc:
                    logger.warning("global cache write failed for %s: %s", func_name, _cache_exc)

            _relativize_round_artifacts(result, out_dir, root_out_dir)

            # 通知 CLI: 函数分析完成
            self._emit("round_end", tid,
                       passed=(result.status.value == "passed"),
                       function=func_name, depth=dep)
            if followup_id:
                try:
                    VulnScanStore(graph_db_path).update_followup_status(
                        followup_id,
                        "analyzed" if result.status.value == "passed" else "error",
                    )
                    if context_id:
                        VulnScanStore(graph_db_path).update_analysis_context_status(context_id, "analyzed" if result.status.value == "passed" else "error")
                except Exception:
                    pass
            df_path = _find_dataflow_file(out_dir, func_name)
            if df_path:
                try:
                    df_text = Path(df_path).read_text(encoding="utf-8")
                    if len(df_text.strip()) > len((result.final_output or "").strip()):
                        result.final_output = df_text
                except OSError:
                    pass

            # 编排器从 SQLite 图谱 followups 表读取结构化跟入点；不再生成/依赖 tainted.list 或 Markdown 中间文件。

            # 保存 dataflow/funcname.md(供 callee 解析 + merge)
            if result.final_output:
                dest = df_dir / f"{safe_func}.md"
                try:
                    dest.write_text(result.final_output, encoding="utf-8")
                    sub_dataflow_files.append((func_name, str(dest)))
                except OSError:
                    pass

            func_key = src_file + ":" + func_name
            all_results[func_key] = result

            vuln_mining_task: asyncio.Task | None = None
            if workflow is not None and result is not None:
                # 漏洞挖掘只依赖当前函数污点跟踪结果；与后续 callee 污点分析互不依赖，
                # 因此先 fork 后台任务，让漏洞挖掘与 BFS 后续跟入点并行运行。
                vuln_mining_task = asyncio.create_task(workflow.run_vuln_mining_after_taint(result))

            # ── 解析 callee 并加入队列 ─────
            if dep < max_depth and result.final_output:
                local_td = os.path.abspath(task_cfg.cwd)
                funcdb_cache_root = str(global_cache.funcdb_root / "dvs-fallback")
                resolver = FunctionResolver(local_td, funcdb_path=getattr(task_cfg, "funcdb_path", ""), cache_root=funcdb_cache_root)
                # 优先从 result 元数据直接获取 followup，避免 SQLite JOIN 复杂性
                _fup_refs: list[dict] = (result.upstream_entry_metadata or {}).get("followup_refs") or []
                fup_meta: dict[str, dict] = {str(f.get("followup_id") or ""): f for f in _fup_refs if f.get("followup_id")}
                if _fup_refs:
                    callees: list[CalleeRef] = [
                        CalleeRef(
                            function_name=str(f.get("callee_function") or ""),
                            file=str(f.get("callee_file") or ""),
                            line=str(f.get("callee_line") or ""),
                            tainted_params=",".join(json.loads(f.get("tainted_params_json") or "[]")) if f.get("tainted_params_json") else "",
                            description=str(f.get("reason") or ""),
                            followup_id=str(f.get("followup_id") or ""),
                            dispatch_kind=str(f.get("dispatch_kind") or "direct_call"),
                            tainted_nonlocal=json.loads(f.get("tainted_nonlocal_json") or "[]") if f.get("tainted_nonlocal_json") else [],
                        )
                        for f in _fup_refs if f.get("callee_function")
                    ]
                else:
                    try:
                        _store = VulnScanStore(graph_db_path)
                        _db_fups = _store.list_followups(run_id=getattr(workflow, "run_id", "") if workflow is not None else None, status="pending")
                        callees = [
                            CalleeRef(
                                function_name=f.callee_function, file=f.callee_file, line=f.callee_line,
                                tainted_params=",".join(json.loads(f.tainted_params_json or "[]")) if f.tainted_params_json else "",
                                description=f.reason,
                                followup_id=f.followup_id,
                                dispatch_kind=f.dispatch_kind,
                                tainted_nonlocal=json.loads(f.tainted_nonlocal_json or "[]") if f.tainted_nonlocal_json else [],
                            )
                            for f in _db_fups
                        ]
                    except Exception as _store_exc:
                        logger.warning("followup store read failed: %s", _store_exc)
                        callees = []
                if not callees:
                    self._emit("trace_skip", tid, function=func_name, reason="no followups")
                valid: list[CalleeRef] = []
                context_by_callee: dict[str, str] = {}
                facts_by_callee: dict[str, list[dict]] = {}
                callsite_line_by_callee: dict[str, str] = {}
                followup_resolver = default_followup_resolver()
                def _callee_key(c: CalleeRef) -> str:
                    return c.followup_id or f"{c.function_name}|{c.file}|{c.line}|{c.tainted_params}"
                for callee in callees:
                    resolved_name, resolved_file = _resolve_function_pointer_followup(target_dir, callee, func_name)
                    if resolved_name != callee.function_name:
                        callee = CalleeRef(function_name=resolved_name, file=resolved_file or callee.file, line=callee.line, tainted_params=callee.tainted_params, description=callee.description, followup_id=callee.followup_id, dispatch_kind=callee.dispatch_kind, tainted_nonlocal=callee.tainted_nonlocal)
                    callsite_line = callee.line
                    # Try to resolve the callee.  When the raw LLM-produced name fails,
                    # attempt progressively cleaned variants (strip qualifiers, pointer
                    # dereference chains, slash-separated alternatives).
                    resolved = None
                    for cname in _sanitize_callee_name(callee.function_name):
                        resolved = resolver.resolve(cname, source_file_hint=callee.file or src_file, line_hint=callee.line)
                        if resolved.resolved:
                            if cname != callee.function_name:
                                callee = CalleeRef(function_name=resolved.function_name, file=resolved.source_file or callee.file, line=(f"L{resolved.line}" if resolved.line else callee.line), tainted_params=callee.tainted_params, description=callee.description, followup_id=callee.followup_id, dispatch_kind=callee.dispatch_kind, tainted_nonlocal=callee.tainted_nonlocal)
                            break
                    if not resolved or not resolved.resolved:
                        reason = "external followup" if _is_external_followup(callee) else (resolved.reason if resolved else "not_in_source_root_funcdb") or "not_in_source_root_funcdb"
                        tracker_ctx = ResolutionContext(
                            source_root=local_td,
                            funcdb_path=getattr(task_cfg, "funcdb_path", ""),
                            cache_root=funcdb_cache_root,
                            graph_db_path=graph_db_path,
                            caller_func=func_name,
                            caller_file=src_file,
                            line_hint=callsite_line,
                        )
                        tracker_decision = followup_resolver.resolve_tracker(callee, tracker_ctx)
                        tracked_callees: list[CalleeRef] = []
                        if tracker_decision.needs_tracker and workflow is not None:
                            tracker_type = tracker_decision.tracker_type
                            tracker_session = root_sessions_dir / f"{session_label}-tracker-{tracker_type}-{(callee.followup_id or 'item')[-8:]}.jsonl"
                            try:
                                VulnScanStore(graph_db_path).update_followup_tracker(
                                    callee.followup_id,
                                    tracker_type=tracker_type,
                                    tracker_status="running",
                                )
                                self._emit("tracker_start", tid, function=callee.function_name, tracker_type=tracker_type, depth=dep)
                                acfg = workflow._agent_cfg()
                                tracked = await run_tracker(
                                    tracker_type,
                                    tracker_decision.tracker_context,
                                    workspace=workflow.ws,
                                    model=acfg.model,
                                    tools=acfg.tools or task_cfg.workers.default_tools,
                                    session_file=str(tracker_session),
                                    cancel_event=self._cancel_event,
                                    run_timeout_seconds=min(float(task_cfg.agent_run_timeout_seconds or 300), 600),
                                    pi_max_retries=task_cfg.pi_max_retries,
                                    pi_retry_delay=task_cfg.pi_retry_delay,
                                    task_context={"task_id": tid, "task_root": str(root_output_path.parent), "task_run_root": str(root_out_dir)},
                                )
                                for item in tracked.functions:
                                    fname = str(item.get("function") or item.get("function_name") or "").strip()
                                    if not fname:
                                        continue
                                    params = item.get("tainted_params") or []
                                    if isinstance(params, list):
                                        param_text = ",".join(str(x).strip() for x in params if str(x).strip())
                                    else:
                                        param_text = str(params or "")
                                    tracked_callees.append(CalleeRef(
                                        function_name=fname,
                                        file=str(item.get("file") or callee.file or ""),
                                        line=str(item.get("line") or callee.line or ""),
                                        tainted_params=param_text or callee.tainted_params,
                                        description=str(item.get("reason") or f"{tracker_type} tracker resolved target"),
                                        followup_id=callee.followup_id,
                                        dispatch_kind="direct_call",
                                        tainted_nonlocal=[],
                                    ))
                                tracker_payload = {"functions": [c.model_dump() for c in tracked_callees], "error": tracked.error}
                                VulnScanStore(graph_db_path).update_followup_tracker(
                                    callee.followup_id,
                                    tracker_type=tracker_type,
                                    tracker_status="resolved" if tracked_callees else "unresolved",
                                    result=tracker_payload,
                                )
                                self._emit("tracker_done", tid, function=callee.function_name, tracker_type=tracker_type, targets=[c.function_name for c in tracked_callees], error=tracked.error, depth=dep)
                            except asyncio.CancelledError:
                                raise
                            except Exception as tracker_exc:
                                logger.exception("tracker failed function=%s type=%s", callee.function_name, tracker_type)
                                try:
                                    VulnScanStore(graph_db_path).update_followup_tracker(
                                        callee.followup_id,
                                        tracker_type=tracker_type,
                                        tracker_status="error",
                                        result={"error": str(tracker_exc)},
                                    )
                                except Exception:
                                    pass
                        if tracked_callees:
                            # Re-run deterministic resolution on tracker targets; this keeps
                            # all normal funcdb, dedup and validation logic in one path.
                            callees.extend(tracked_callees)
                            if callee.followup_id:
                                try:
                                    VulnScanStore(graph_db_path).update_followup_status(callee.followup_id, "tracker_resolved", reason=callee.description or "tracker resolved targets")
                                except Exception:
                                    pass
                            continue
                        self._emit("trace_skip", tid, function=callee.function_name,
                                   reason=reason)
                        if callee.followup_id:
                            try:
                                VulnScanStore(graph_db_path).update_followup_status(callee.followup_id, "skipped", reason=reason)
                            except Exception:
                                pass
                        continue
                    callee = CalleeRef(function_name=resolved.function_name, file=resolved.source_file or callee.file, line=(f"L{resolved.line}" if resolved.line else callee.line), tainted_params=callee.tainted_params, description=callee.description, followup_id=callee.followup_id, dispatch_kind=callee.dispatch_kind, tainted_nonlocal=callee.tainted_nonlocal)
                    raw_params = [x.strip() for x in (callee.tainted_params or "").split(",") if x.strip()]
                    callsite = analyze_callsite(local_td, callee.file or src_file, callsite_line, callee.function_name)
                    norm_params, taint_sig = map_taint_signature(raw_params, callsite.actual_args) if callsite.actual_args else normalize_taint_params(callee.tainted_params)
                    meta = fup_meta.get(callee.followup_id, {})
                    try:
                        validation_facts = json.loads(str(meta.get("validation_facts_json") or "[]"))
                    except Exception:
                        validation_facts = []
                    validation_facts = list(validation_facts or []) + list(callsite.derived_validations or [])
                    validation_state = normalize_validation_state(validation_facts)
                    # Recompute from combined model + callsite facts. Do not let stale
                    # followup metadata override validations inferred from exact callsite.
                    function_identity = resolved.func_hash or f"{resolved.source_file}:{resolved.function_name}:L{resolved.line}" if resolved.line else f"{resolved.source_file}:{resolved.function_name}"
                    c_key = f"{function_identity}:{taint_sig}:{validation_state.signature}"
                    if callee.function_name == func_name and taint_sig == normalize_taint_params(task_cfg.taint_params)[1]:
                        continue
                    if callee.function_name.split("::")[-1] == func_name.split("::")[-1] and taint_sig == normalize_taint_params(task_cfg.taint_params)[1]:
                        continue
                    _store_for_context = VulnScanStore(graph_db_path)
                    covering = _store_for_context.find_covering_context(
                        function_identity=function_identity,
                        taint_signature=taint_sig,
                        validation_signature=validation_state.signature,
                        validation_risk_rank=validation_state.risk_rank,
                        validation_facts=validation_state.facts,
                    )
                    if covering:
                        self._emit("trace_skip", tid, function=callee.function_name,
                                   reason="merged_equivalent_taint_validation", covered_by=covering.get("context_id"))
                        if callee.followup_id:
                            try:
                                VulnScanStore(graph_db_path).update_followup_status(callee.followup_id, "skipped", reason="merged_equivalent_taint_validation")
                            except Exception:
                                pass
                        continue
                    if c_key in analyzed:
                        # 全局缓存查重：命中时注入缓存的校验事实
                        taint_sig_cache = _normalize_taint_signature(callee.tainted_params)
                        func_h = compute_func_hash(target_dir, callee.file or src_file, callee.function_name) or "0"
                        cached_vals = global_cache.get_validations(
                            callee.function_name, callee.file or src_file, taint_sig_cache, func_h)
                        if cached_vals:
                            for v in cached_vals:
                                current_taint_state.entries.append(TaintEntry(
                                    variable=v.variable, kind=v.kind, evidence=v.evidence,
                                    confidence=v.confidence))
                        self._emit("trace_skip", tid, function=callee.function_name,
                                   reason="already analyzed (cache validations applied)" if cached_vals else "already analyzed")
                        if callee.followup_id:
                            try:
                                VulnScanStore(graph_db_path).update_followup_status(callee.followup_id, "skipped", reason="already analyzed")
                            except Exception:
                                pass
                        continue
                    if callee.function_name in _STDLIB_SKIP:
                        if callee.followup_id:
                            try:
                                VulnScanStore(graph_db_path).update_followup_status(callee.followup_id, "skipped", reason="stdlib skip")
                            except Exception:
                                pass
                        continue
                    analyzed.add(c_key)
                    context_id = "ctx_" + hashlib.sha1(c_key.encode()).hexdigest()[:16]
                    try:
                        _store_ctx = VulnScanStore(graph_db_path)
                        _store_ctx.upsert_analysis_context(
                            context_id=context_id,
                            function_identity=function_identity,
                            source_file=callee.file,
                            function_name=callee.function_name,
                            taint_signature=taint_sig,
                            validation_signature=validation_state.signature,
                            validation_risk_rank=validation_state.risk_rank,
                            risk_class=validation_state.risk_class,
                            status="queued",
                            created_from_followup_id=callee.followup_id,
                            validation_facts=validation_state.facts,
                        )
                        _store_ctx.record_constraints(
                            run_id=getattr(workflow, "run_id", "") if workflow is not None else tid,
                            followup_id=callee.followup_id,
                            source_file=src_file,
                            function_name=func_name,
                            line=callsite_line or callee.line,
                            facts=validation_state.facts,
                        )
                    except Exception:
                        pass
                    context_by_callee[_callee_key(callee)] = context_id
                    facts_by_callee[_callee_key(callee)] = validation_state.facts
                    callsite_line_by_callee[_callee_key(callee)] = callsite_line
                    if callee.followup_id:
                        try:
                            VulnScanStore(graph_db_path).update_followup_status(callee.followup_id, "queued")
                        except Exception:
                            pass
                    valid.append(callee)

                if valid:
                    self._emit("trace_callees", tid, function=func_name,
                               callees=[c.function_name for c in valid], depth=dep)

                # ── 参数语义分析 + P0/P1/P2 分流 ────────────────────────
                p0_followups: list[CalleeRef] = []
                p1_followups: list[CalleeRef] = []
                p2_followups: list[CalleeRef] = []
                for callee in valid:
                    _callsite_line = callsite_line_by_callee.get(_callee_key(callee), callee.line)
                    callsite = analyze_callsite(target_dir, callee.file or src_file, _callsite_line, callee.function_name)
                    taint_list = [x.strip() for x in (callee.tainted_params or "").split(",") if x.strip()]
                    sem = analyze_param_semantics(
                        callee.function_name, callee.file or src_file,
                        tainted_params=taint_list,
                        callsite_args=callsite.actual_args or taint_list,
                        source_root=target_dir,
                    )
                    pri = sem.highest_priority
                    if pri <= 0:
                        p0_followups.append(callee)
                    elif pri == 1:
                        p1_followups.append(callee)
                    else:
                        p2_followups.append(callee)
                    self._emit("trace_priority", tid, function=callee.function_name,
                               priority=pri, reason=sem.reason[:120], depth=dep)

                # ── P0: 顺序依赖，当前 Slot 内 DFS ────────────────────────
                current_taint_state = TaintState()
                for callee in p0_followups:
                    self._raise_if_cancelled()
                    sub_file = callee.file or src_file
                    sub_cfg = task_cfg.model_copy(deep=True)
                    sub_cfg.function_name = callee.function_name
                    sub_cfg.source_file = sub_file
                    sub_cfg.task = (
                        f"对 {sub_file} 的 {callee.function_name} 函数进行静态污点分析,"
                        f"外部输入参数(已污染)为:{callee.tainted_params or '所有参数'}"
                    )
                    ctx_base = task_cfg.context or ""
                    if "# 调用者传入的脏数据" in ctx_base:
                        ctx_base = ctx_base.split("# 调用者传入的脏数据")[0].strip()
                    sub_cfg.context = ctx_base
                    _callee_callsite_line = callsite_line_by_callee.get(_callee_key(callee), callee.line)
                    _callsite_for_params = analyze_callsite(target_dir, callee.file or src_file, _callee_callsite_line, callee.function_name)
                    _callee_params = map_taint_signature([x.strip() for x in (callee.tainted_params or "").split(",") if x.strip()], _callsite_for_params.actual_args)[0] or normalize_taint_params(callee.tainted_params)[0] or [x.strip() for x in (callee.tainted_params or "").split(",") if x.strip()]
                    sub_cfg.taint_params = _callee_params or ["all"]
                    sub_cfg.taint_details = [
                        {"name": p, "description": f"由 {func_name} 在 {_callee_callsite_line or callee.line or 'unknown'} 调用传入", "source_kind": "call_argument"}
                        for p in sub_cfg.taint_params
                    ]
                    validation_context = current_taint_state.summary()
                    tainted_ctx_str = (
                        f"函数 {callee.function_name} 被 {func_name} 在 {_callee_callsite_line or callee.line} 调用。\n"
                        f"污染参数: {callee.tainted_params}\n说明: {callee.description}"
                    )
                    if validation_context != "(无)":
                        tainted_ctx_str += f"\n\n# 调用链上已累积的校验\n{validation_context}"
                    sub_line_hint = _get_definition_line(target_dir, callee.function_name, sub_file) or callee.line
                    sub_tid = tid + f"-d{dep + 1}-{callee.function_name[:25]}-{(callee.followup_id or hashlib.sha1((callee.function_name + callee.tainted_params + callee.line).encode()).hexdigest())[-6:]}"
                    self._emit("sequence_call", tid,
                               parent_function=func_name, callee_function=callee.function_name,
                               depth=dep + 1, reason="sequential P0: modifies param")
                    await queue.put((callee.function_name, sub_file, sub_line_hint, sub_cfg,
                                     sub_tid, dep + 1, tainted_ctx_str,
                                     completed_session_file or None, callee.followup_id,
                                     context_by_callee.get(_callee_key(callee), "")))

                # ── P1: 不修改参数但产出校验 ────────────────────────────
                for callee in p1_followups:
                    self._raise_if_cancelled()
                    taint_sig = _normalize_taint_signature(callee.tainted_params)
                    func_h = compute_func_hash(target_dir, callee.file or src_file, callee.function_name) or "0"

                    # 查全局缓存
                    cached = global_cache.get_validations(
                        callee.function_name, callee.file or src_file, taint_sig, func_h)
                    if cached:
                        # 命中：注入校验，不启动 Worker
                        for v in cached:
                            current_taint_state.entries.append(TaintEntry(
                                variable=v.variable, kind=v.kind, evidence=v.evidence,
                                confidence=v.confidence))
                        # 还要处理缓存的 followups（check 内部调用的子函数）
                        cached_fups = global_cache.get_followups(
                            callee.function_name, callee.file or src_file, taint_sig, func_h)
                        for fup in cached_fups:
                            if fup.function:
                                cf = CalleeRef(
                                    function_name=fup.function, file=fup.file or callee.file or "",
                                    line=fup.line or "", tainted_params=callee.tainted_params,
                                    description=fup.reason or "cached followup from P1",
                                    dispatch_kind="direct_call")
                                valid.append(cf)
                        if callee.followup_id:
                            try:
                                VulnScanStore(graph_db_path).update_followup_status(
                                    callee.followup_id, "skipped", reason="cache hit (validations applied)")
                            except Exception:
                                pass
                        self._emit("trace_cache_hit", tid, function=callee.function_name,
                                   taint_sig=taint_sig, depth=dep)
                        continue

                    # 未命中缓存 → 正常入队，Worker 分析后写缓存
                    sub_file = callee.file or src_file
                    sub_cfg = task_cfg.model_copy(deep=True)
                    sub_cfg.function_name = callee.function_name
                    sub_cfg.source_file = sub_file
                    sub_cfg.task = (
                        f"对 {sub_file} 的 {callee.function_name} 函数进行静态污点分析,"
                        f"外部输入参数(已污染)为:{callee.tainted_params or '所有参数'}"
                    )
                    ctx_base = task_cfg.context or ""
                    if "# 调用者传入的脏数据" in ctx_base:
                        ctx_base = ctx_base.split("# 调用者传入的脏数据")[0].strip()
                    sub_cfg.context = ctx_base
                    _callee_callsite_line = callsite_line_by_callee.get(_callee_key(callee), callee.line)
                    _callsite_for_params = analyze_callsite(target_dir, callee.file or src_file, _callee_callsite_line, callee.function_name)
                    _callee_params = map_taint_signature([x.strip() for x in (callee.tainted_params or "").split(",") if x.strip()], _callsite_for_params.actual_args)[0] or normalize_taint_params(callee.tainted_params)[0] or [x.strip() for x in (callee.tainted_params or "").split(",") if x.strip()]
                    sub_cfg.taint_params = _callee_params or ["all"]
                    sub_cfg.taint_details = [
                        {"name": p, "description": f"由 {func_name} 在 {_callee_callsite_line or callee.line or 'unknown'} 调用传入", "source_kind": "call_argument"}
                        for p in sub_cfg.taint_params
                    ]
                    validation_context = current_taint_state.summary()
                    tainted_ctx_str = (
                        f"函数 {callee.function_name} 被 {func_name} 在 {_callee_callsite_line or callee.line} 调用。\n"
                        f"污染参数: {callee.tainted_params}\n说明: {callee.description}"
                    )
                    if validation_context != "(无)":
                        tainted_ctx_str += f"\n\n# 调用链上已累积的校验\n{validation_context}"
                    sub_line_hint = _get_definition_line(target_dir, callee.function_name, sub_file) or callee.line
                    sub_tid = tid + f"-d{dep + 1}-{callee.function_name[:25]}-{(callee.followup_id or hashlib.sha1((callee.function_name + callee.tainted_params + callee.line).encode()).hexdigest())[-6:]}"
                    self._emit("sequence_call", tid,
                               parent_function=func_name, callee_function=callee.function_name,
                               depth=dep + 1, reason="sequential P1: validates/reads-only")
                    await queue.put((callee.function_name, sub_file, sub_line_hint, sub_cfg,
                                     sub_tid, dep + 1, tainted_ctx_str,
                                     completed_session_file or None, callee.followup_id,
                                     context_by_callee.get(_callee_key(callee), "")))

                # ── P2: 参数隔离，全局 BFS 并行 ───────────────────────────
                for index, callee in enumerate(p2_followups):
                    self._raise_if_cancelled()
                    sub_file = callee.file or src_file
                    sub_cfg = task_cfg.model_copy(deep=True)
                    sub_cfg.function_name = callee.function_name
                    sub_cfg.source_file = sub_file
                    sub_cfg.task = (
                        f"对 {sub_file} 的 {callee.function_name} 函数进行静态污点分析,"
                        f"外部输入参数(已污染)为:{callee.tainted_params or '所有参数'}"
                    )
                    ctx_base = task_cfg.context or ""
                    if "# 调用者传入的脏数据" in ctx_base:
                        ctx_base = ctx_base.split("# 调用者传入的脏数据")[0].strip()
                    sub_cfg.context = ctx_base
                    _callee_callsite_line = callsite_line_by_callee.get(_callee_key(callee), callee.line)
                    _callsite_for_params = analyze_callsite(target_dir, callee.file or src_file, _callee_callsite_line, callee.function_name)
                    _callee_params = map_taint_signature([x.strip() for x in (callee.tainted_params or "").split(",") if x.strip()], _callsite_for_params.actual_args)[0] or normalize_taint_params(callee.tainted_params)[0] or [x.strip() for x in (callee.tainted_params or "").split(",") if x.strip()]
                    sub_cfg.taint_params = _callee_params or ["all"]
                    sub_cfg.taint_details = [
                        {"name": p, "description": f"由 {func_name} 在 {_callee_callsite_line or callee.line or 'unknown'} 调用传入", "source_kind": "call_argument"}
                        for p in sub_cfg.taint_params
                    ]
                    tainted_ctx_str = (
                        f"函数 {callee.function_name} 被 {func_name} 在 {_callee_callsite_line or callee.line} 调用。\n"
                        f"污染参数: {callee.tainted_params}\n说明: {callee.description}"
                    )
                    suffix = (callee.followup_id or hashlib.sha1((callee.function_name + callee.tainted_params + callee.line).encode()).hexdigest())[-6:]
                    sub_tid = tid + f"-d{dep + 1}-{callee.function_name[:25]}-{suffix}"
                    sub_line_hint = _get_definition_line(target_dir, callee.function_name, sub_file)
                    if not sub_line_hint:
                        sub_line_hint = callee.line if callee.line.startswith("L") else (
                            "L" + callee.line.lstrip("L") if callee.line else "")
                    if index > 0:
                        self._emit("context_fork", tid,
                                   parent_function=func_name,
                                   callee_function=callee.function_name,
                                   fork_index=index, depth=dep + 1,
                                   reason="multiple followup callees")
                    if self._is_cancelled():
                        break
                    await queue.put((callee.function_name, sub_file, sub_line_hint, sub_cfg,
                                     sub_tid, dep + 1, tainted_ctx_str,
                                     completed_session_file or None, callee.followup_id,
                                     context_by_callee.get(_callee_key(callee), "")))

            if vuln_mining_task is not None:
                try:
                    await vuln_mining_task
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self._emit("vuln_scan_error", tid, function=func_name, error=str(exc), depth=dep)

        async def worker(wid: int) -> None:
            while True:
                if self._is_cancelled() and queue.empty():
                    break
                item = await queue.get()
                if item is None:      # sentinel → 退出
                    queue.task_done()
                    break
                try:
                    await process_item(item)
                except asyncio.CancelledError:
                    return
                except Exception as e:
                    # item layout: (func_name, src_file, line_hint, task_cfg, tid, dep, ..., followup_id, context_id)
                    err_tid = item[4] if len(item) > 4 else "?"
                    err_followup_id = item[8] if len(item) > 8 else ""
                    err_context_id = item[9] if len(item) > 9 else ""
                    if err_followup_id:
                        try:
                            VulnScanStore(graph_db_path).update_followup_status(err_followup_id, "error", reason=str(e))
                            if err_context_id:
                                VulnScanStore(graph_db_path).update_analysis_context_status(err_context_id, "error")
                        except Exception:
                            pass
                    logger.exception("recursive process_item failed task_id=%s function=%s", err_tid, item[0] if item else "?")
                    self._emit("error", err_tid, error=str(e), function=item[0] if item else "?")
                finally:
                    queue.task_done()

        # 启动工作池(n_workers 个并发 Worker+Judge 会话)
        workers = [asyncio.create_task(worker(i)) for i in range(n_workers)]

        try:
            # 等待所有任务处理完毕
            await queue.join()
            if self._is_cancelled():
                for task in workers:
                    task.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
                raise asyncio.CancelledError("recursive orchestration cancelled")

            # 发送终止 sentinel
            for _ in range(n_workers):
                await queue.put(None)
            await asyncio.gather(*workers)

            # ── 根函数结果 ────────────────────────────────────────────────────────
            root_result = all_results.get(root_key)
            if root_result is None:
                # cfg.source_file/function_name may be parsed/normalized late by task_config_json.
                # If the literal root_key misses, fall back to the first depth-0 result instead of
                # overwriting a valid root worker result as "root function analysis failed".
                root_result = next((r for r in all_results.values() if str(r.task_id) == str(root_task_id)), None)
            if root_result is None:
                root_result = next(iter(all_results.values()), None)
            if root_result is None:
                root_result = TaskResult(task_id=root_task_id, task=cfg.task,
                                         status=TaskStatus.ERROR,
                                         error="root function analysis failed")
            combined_rounds = []
            combined_tokens = TokenUsage()
            total_duration_ms = 0.0
            for item in all_results.values():
                combined_rounds.extend(item.rounds or [])
                combined_tokens += item.total_tokens
                total_duration_ms += float(item.total_duration_ms or 0.0)
            root_result.rounds = combined_rounds
            root_result.total_tokens = combined_tokens
            if total_duration_ms > 0:
                root_result.total_duration_ms = total_duration_ms

            # 最终报告只展示漏洞简报列表；完整污点图谱/边/跟入点以 output/vuln-scan.sqlite 为准。
            root_result.final_output = self._build_vulnerability_brief_report(root_result, graph_db_path)

            # ── 最终归档 ──────────────────────────────────────────────────────────
            self._do_final_archive(root_result, root_out_dir, _root_output_dir)
            return root_result
        finally:
            self._cancel_event = None

    def _build_vulnerability_brief_report(self, result: TaskResult, graph_db_path: Path) -> str:
        """构建最终报告：只展示漏洞简报列表，不内嵌数据流全文。"""
        graph = {}
        if graph_db_path.exists():
            try:
                graph = VulnScanStore(graph_db_path).export_json()
            except Exception:
                graph = {}
        findings = graph.get("vulnerability_findings") or []
        lines = [
            f"# 数据流漏洞挖掘简报: {self.cfg.function_name}",
            "",
            "## 结果概览",
            "",
            f"- 任务ID: `{result.task_id}`",
            f"- 状态: `{result.status.value}`",
            f"- 漏洞数量: {len(findings)}",
            f"- 文件/函数/行号来源: `{ 'funcdb' if (getattr(self.cfg, 'funcdb_path', '') or getattr(self.cfg, 'func_hash', '')) else 'source-extractor' }`",
            f"- 图谱数据库: `output/vuln-scan.sqlite`",
            f"- 漏洞报告目录: `output/vulnerabilities/`",
            "",
            "## 漏洞简报列表",
            "",
        ]
        if not findings:
            lines.append("未确认漏洞发现。")
        else:
            for idx, item in enumerate(findings, 1):
                rel_dir = str(item.get("output_dir") or "").split("/output/", 1)[-1]
                if rel_dir and not rel_dir.startswith("output/"):
                    rel_dir = "output/" + rel_dir
                lines += [
                    f"### {idx}. {item.get('title') or item.get('finding_id')}",
                    "",
                    f"- ID: `{item.get('finding_id')}`",
                    f"- 类型: `{item.get('vuln_type') or 'unknown'}`",
                    f"- 严重性: `{item.get('severity') or 'unknown'}`",
                    f"- 位置: `{item.get('source_file') or ''}` / `{item.get('function_name') or ''}` / `{item.get('line') or 'unknown'}`",
                    f"- 置信度: `{item.get('confidence')}`",
                    f"- 摘要: {item.get('summary') or ''}",
                    f"- 报告目录: `{rel_dir or item.get('output_dir') or ''}`",
                    "",
                ]
        return "\n".join(lines).strip() + "\n"

    def _do_final_archive(self, result: TaskResult, root_out_dir: Path | None, root_output_dir: Path | None = None):
        """统一归档:写报告 + 输出结果文件到 output/ 目录 + 写 flag。不创建压缩包,不清理工作目录。"""
        cfg = self.cfg
        if not root_out_dir or not root_out_dir.exists():
            return

        # 写报告到 run/ 目录
        (root_out_dir / "report.md").write_text(_report(result, cfg), encoding="utf-8")
        (root_out_dir / "result.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")

        # output/ 目录存放最终输出
        output_path = root_output_dir or (root_out_dir.parent / "output")
        output_path.mkdir(parents=True, exist_ok=True)

        # 格式化最终输出 → output/
        cleaned_output = _format_final_output(result)
        result_filename = "final_report.md"
        (output_path / result_filename).write_text(cleaned_output, encoding="utf-8")
        result.final_output = cleaned_output

        # 将执行期间生成的 SQLite 图谱和漏洞报告从 run/ 工作区复制到 output/
        # shared_run_dir = run/，或旧路径下的 root_out_dir
        _shared = root_out_dir.parent.parent if ("epochs" in root_out_dir.parts and "run" in root_out_dir.parts) else root_out_dir
        _run_sqlite = _shared / "vuln-scan.sqlite"
        _out_sqlite = output_path / "vuln-scan.sqlite"
        if _run_sqlite.exists() and _run_sqlite != _out_sqlite:
            try:
                shutil.copy2(_run_sqlite, _out_sqlite)
            except OSError as _e:
                logger.warning("archive: failed to copy vuln-scan.sqlite: %s", _e)
        _run_vulns = _shared / "vulnerabilities"
        _out_vulns = output_path / "vulnerabilities"
        if _run_vulns.exists() and _run_vulns != _out_vulns:
            try:
                if _out_vulns.exists():
                    shutil.rmtree(_out_vulns)
                shutil.copytree(_run_vulns, _out_vulns)
            except OSError as _e:
                logger.warning("archive: failed to copy vulnerabilities: %s", _e)
        _run_manifest = _shared / "artifact-manifest.json"
        _out_manifest = output_path / "artifact-manifest.json"
        if _run_manifest.exists() and _run_manifest != _out_manifest:
            try:
                shutil.copy2(_run_manifest, _out_manifest)
            except OSError:
                pass

        # 写 flag 文件(仅 PASSED 为 1,其他保持 0)
        if result.status == TaskStatus.PASSED:
            (output_path / "flag").write_text("1", encoding="utf-8")

        self._emit("task_end", result.task_id,
                    status=result.status.value,
                    run_dir=str(root_out_dir),
                    result_file=str(output_path / result_filename))
