"""dataflow-v2 分析回调的具体实现。

TaintAnalysisCallbacks.analyze_function:
  1. (确保) tree-sitter 索引本函数所在文件 → 拿到函数体 (run/functions/)
  2. 在前置 session 基础上 fork 会话, run_agent 跑 taint-analysis 提示词
  3. 解析 LLM 输出 JSON → 建 TaintRecord / PropagationRecord
  4. clang 标注每条 propagation 的调用点分支上下文 (branch_group/arm/path)
     + 幽灵 callee 丢弃 (target_function 不在 caller 函数体 CallExpr → 删该 propagation)
  5. 返回 AnalysisResult (含 self_contained)

resolve_external_propagation / mine_vulns 暂为 TODO stub (下一阶段)。
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Callable

from ..agent_runtime_events import emit_agent_runtime_events
from ..clang_analyzer import analyze_function_callsites, clang_parse_ok
from ..copy_utils import safe_copyfile
from ..models import TaskConfig
from ..parsers import _extract_json_object
from ..runner import run_agent
from ..vuln_intake_reporter import report_finding_to_intake
from ..vuln_report_utils import (EMBEDDED_VULN_MINING_SKILL as _EMBEDDED_VULN_MINING_SKILL,
                                  format_vuln_report_md as _format_vuln_report_md,
                                  read_prompt as _read_prompt, safe_name as _safe_name)
from ..vuln_store import VulnFindingRecord, VulnScanStore
from .function_extractor import ensure_file_indexed
from .models import (
    FunctionRecord, PropagationRecord, TaintParamInfo, TaintRecord, Validation,
)
from .orchestrator import AnalysisResult, AnalysisCallbacks, PathContext
from .store import DataflowStore

logger = logging.getLogger("dvs.dataflow_v2")

_TAINT_ANALYSIS_PROMPT = _read_prompt("prompts/v2/taint-analysis.md")


class TaintAnalysisCallbacks(AnalysisCallbacks):
    """注入编排器的具体 LLM + clang 实现。"""

    def __init__(self, *, cfg: TaskConfig, source_root: str, run_dir: Path,
                 sessions_dir: Path, graph_db_path: Path, vuln_root: Path,
                 run_id: str, task_id: str, cancel_event: Any = None,
                 on_event: Callable[..., None] | None = None) -> None:
        self.cfg = cfg
        self.source_root = source_root
        self.run_dir = Path(run_dir)
        self.sessions_dir = Path(sessions_dir)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "clang-cache").mkdir(parents=True, exist_ok=True)
        self.vuln_root = Path(vuln_root)
        self.vuln_root.mkdir(parents=True, exist_ok=True)
        self.graph_store = VulnScanStore(graph_db_path)
        self.run_id = run_id
        self.task_id = task_id
        self.cancel_event = cancel_event
        self.on_event = on_event or (lambda *a, **k: None)
        self._vuln_miner_prompt = _read_prompt("prompts/vuln-miners/default.md")
        self._tracking_prompt = _read_prompt("prompts/v2/external-tracking.md")

    # ── 主入口 ─────────────────────────────────────────────────────────────
    def analyze_function(self, store: DataflowStore, func: FunctionRecord,
                         taint_params: TaintParamInfo, pre_validations: list[Validation],
                         base_session: str, ctx: PathContext) -> AnalysisResult:
        # 1) 确保文件已索引 (函数体在 run/functions/)
        ensure_file_indexed(self.source_root, func.file, store)
        body = self._read_body(func)

        # 2) fork session (v1 模型: copy base_session → 累积链上下文 A→A+B→A+B+C)
        fork_session = self.sessions_dir / f"d{ctx.depth:02d}-{_safe_name(func.name)}-taint.jsonl"
        try:
            if base_session and Path(base_session).exists():
                safe_copyfile(base_session, str(fork_session))
        except OSError:
            pass

        # 3) 构造 prompt
        prompt = self._build_prompt(func, body, taint_params, pre_validations)
        acfg = self.cfg.workers.agents[0] if self.cfg.workers.agents else None
        if acfg is None:
            return AnalysisResult(description="no agent configured", self_contained=False)

        # 4) run_agent
        output = run_agent(
            prompt=prompt, model=acfg.model, tools=acfg.tools or self.cfg.workers.default_tools,
            cwd=str(self.run_dir), session_file=str(fork_session),
            system_prompt=_TAINT_ANALYSIS_PROMPT, cancel_event=self.cancel_event,
            run_timeout_seconds=self.cfg.agent_run_timeout_seconds,
            timeout_retry_enabled=self.cfg.agent_timeout_retry_enabled,
            timeout_max_retries=self.cfg.agent_timeout_max_retries,
            pi_max_retries=self.cfg.pi_max_retries, pi_retry_delay=self.cfg.pi_retry_delay,
            task_context={"task_id": getattr(ctx, "path_id", ""), "task_root": str(self.run_dir.parent),
                          "task_run_root": str(self.run_dir), "task_pi_dir": self.cfg.role_pi_dir("workers"),
                          "agent_role": "workers"},
        )
        if self.on_event:
            emit_agent_runtime_events(self.on_event, result=output, stage="taint_analysis_v2",
                                      role="workers", model=acfg.model,
                                      extra={"function": func.name, "fork_purpose": "taint_analysis"})

        # 5) 解析 JSON
        parsed = _extract_json_object(output.output, "propagations") or {}
        return self._build_result(store, func, taint_params, parsed, fork_session)

    # ── 结果构造 + clang 标注 ───────────────────────────────────────────────
    def _build_result(self, store: DataflowStore, func: FunctionRecord,
                      taint_params: TaintParamInfo, parsed: dict,
                      fork_session: Path) -> AnalysisResult:
        description = str(parsed.get("description") or "")
        self_contained = bool(parsed.get("self_contained", False))

        # taints
        taints: list[TaintRecord] = []
        for t in parsed.get("taints") or []:
            if not isinstance(t, dict):
                continue
            taints.append(TaintRecord(
                func_id=func.func_id, name=str(t.get("name") or ""),
                signature="", file=func.file, function=func.name,
                description=str(t.get("description") or "")))

        # propagations: LLM 只输出语义字段; 结构字段 (call_line/condition/is_indirect/signature)
        # 由 clang/脚本提供。is_indirect_call 由 target_function 表达式模式检测 (脚本)。
        raw_props: list[PropagationRecord] = []
        callee_names: list[str] = []
        for p in parsed.get("propagations") or []:
            if not isinstance(p, dict):
                continue
            target_fn = str(p.get("target_function") or "").strip()
            is_ext = bool(p.get("is_external", False))
            # 系统检测间接调用: target_function 是函数指针表达式 (含 -> / (* / [)
            is_indirect = bool(target_fn) and ("->" in target_fn or target_fn.startswith("*") or "[" in target_fn)
            dispatch_kind = "function_pointer_field" if is_indirect else ""
            if target_fn and not is_ext and not is_indirect:
                callee_names.append(target_fn)  # 直接调用: clang 按名定位 CallExpr
            raw_props.append(PropagationRecord(
                source_func_id=func.func_id,
                source_taint_name=str(p.get("source_taint") or ""),
                source_taint_signature="",  # 签名由 AST/funcdb 提供
                target_taint_name=str(p.get("target_taint") or ""),
                target_taint_signature="",
                target_function=target_fn,
                target_file="",  # 系统按名从全局函数库解析
                call_line=0,  # clang 标注时填 (直接调用)
                condition="",  # clang 标注时填分支
                is_external=is_ext,
                is_indirect_call=is_indirect,
                dispatch_kind=dispatch_kind,
                validations=[Validation(str(v.get("condition") or ""), str(v.get("content") or ""))
                             for v in (p.get("validations") or []) if isinstance(v, dict)],
                description=str(p.get("description") or ""),
            ))

        # clang 标注: 校验调用点 + 分支上下文; 幽灵 callee (不在 caller 函数体) 丢弃
        # 但 clang 解析失败 (缺 include 等) 时 NOT 丢弃 — 区分 "解析失败"(保留, 仅缺分支标注)
        # 与 "解析成功但 callee 不在体"(真幽灵 → 丢), 避免过度丢弃。
        validated_props: list[PropagationRecord] = []
        parse_ok = clang_parse_ok(self.source_root, func.file, func.name) if callee_names else False
        if parse_ok:
            callsites = analyze_function_callsites(
                self.source_root, func.file, func.name, callee_names,
                self.run_dir / "clang-cache")
        else:
            callsites = {}
        for prop in raw_props:
            if (prop.is_external or prop.is_indirect_call) or not prop.target_function:
                # 外部变量 / 函数指针间接调用 / 无 callee: 不经 clang (由各自 tracker 处理)
                validated_props.append(prop)
                continue
            if not parse_ok:
                # clang 解析失败 → 无法校验, 保留传播 (无分支标注, 下游按顺序链处理)
                prop.target_func_id = self._resolve_target_func_id(store, prop)
                validated_props.append(prop)
                continue
            ci = callsites.get(prop.target_function)
            if ci is None:
                # 幽灵 callee: caller 函数体根本没调用它 → 丢弃 (修 v1 Gap-1)
                logger.info("drop phantom callee %s in %s (not in body)", prop.target_function, func.name)
                self.on_event("v2_phantom_callee_dropped", function=prop.target_function,
                           caller=func.name, claimed_line=prop.call_line)
                continue
            prop.callsite_validated = True
            prop.call_line = int(ci.get("call_line") or prop.call_line)
            prop.branch_path = ci.get("branch_path") or []
            prop.branch_group_id = str(ci.get("branch_group_id") or "")
            prop.branch_arm_id = str(ci.get("branch_arm_id") or "")
            prop.mutex_siblings = ci.get("mutex_siblings") or []
            prop.actual_args = ci.get("actual_args") or []
            # 解析 target_func_id (索引 callee 文件)
            prop.target_func_id = self._resolve_target_func_id(store, prop)
            validated_props.append(prop)

        return AnalysisResult(taints=taints, propagations=validated_props,
                              self_contained=self_contained, description=description,
                              session_path=str(fork_session))

    def _within_source_root(self, file: str) -> bool:
        """文件是否在源码目录内 (目录内=合理可分析, 目录外=不分析; 不按文件名过滤,
        因为被分析的函数本身可能就是 fuzz 工具)。防 ../ 逃逸与绝对路径越界。"""
        if not file:
            return False
        try:
            root = os.path.realpath(self.source_root)
            # 相对路径 → 拼到 source_root 下; 绝对路径 → 原样
            p = file if os.path.isabs(file) else os.path.join(self.source_root, file)
            rp = os.path.realpath(p)
            return rp == root or rp.startswith(root + os.sep)
        except Exception:
            return False

    def _search_callee_file(self, callee_name: str) -> str:
        """按需搜索: callee 不在已索引文件时, grep 源码树找其定义文件。"""
        import subprocess
        short = callee_name.rsplit("::", 1)[-1]
        try:
            r = subprocess.run(
                ["grep", "-rl", "--include=*.c", "--include=*.cpp", "--include=*.cc",
                 f"\\b{short}\\s*\\(", self.source_root],
                capture_output=True, text=True, timeout=30)
            files = [f for f in r.stdout.strip().split("\n") if f]
            if not files:
                return ""
            # 取第一个匹配, 转相对路径
            for f in files:
                try:
                    return str(Path(f).relative_to(self.source_root).as_posix())
                except ValueError:
                    continue
            return ""
        except Exception:
            return ""

    def _resolve_target_func_id(self, store: DataflowStore, prop: PropagationRecord) -> str:
        """按 callee 名解析 func_id (系统解析, 不依赖 LLM target_file)。
        先查已索引库, 找不到则 grep 源码树按需索引其文件。"""
        if not prop.target_function:
            return ""
        rec = store.find_function(prop.target_function)
        if rec is None:
            # 按需: grep 源码树找 callee 定义文件 → 索引 → 重试
            fpath = self._search_callee_file(prop.target_function)
            if fpath and self._within_source_root(fpath):
                ensure_file_indexed(self.source_root, fpath, store)
                rec = store.find_function(prop.target_function)
        if rec is None:
            return ""  # 全局库+源码树均找不到 (外部库/系统 API), 不递归
        if rec.file and not self._within_source_root(rec.file):
            self.on_event("v2_out_of_scope_skipped", function=prop.target_function,
                       file=rec.file, reason="outside_source_root")
            return ""
        return rec.func_id

    # ── prompt 构造 ─────────────────────────────────────────────────────────
    def _build_prompt(self, func: FunctionRecord, body: str,
                      taint_params: TaintParamInfo, pre_validations: list[Validation]) -> str:
        taint_desc = (f"位置 {taint_params.positions} 签名 {taint_params.signature} "
                      f"名字 {taint_params.names}") if taint_params.positions else "所有参数"
        pre_val_text = "\n".join(f"- {v.condition}: {v.content}" for v in pre_validations) or "(无)"
        return (
            f"# 阶段：单函数污点传播分析 Fork\n\n"
            f"目标函数: `{func.file}::{func.name}` (行 {func.start_line}-{func.end_line})\n"
            f"入口污点: {taint_desc}\n\n"
            f"## 前置校验链 (从根到本函数已累积)\n{pre_val_text}\n\n"
            f"## 函数体\n```c\n{body}\n```\n\n"
            f"按系统提示词要求输出 JSON (description/self_contained/taints/propagations)。"
        )

    def _read_body(self, func: FunctionRecord) -> str:
        if func.body_path and Path(func.body_path).is_file():
            try:
                return Path(func.body_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        return f"// body_path 不可读: {func.body_path}\n// 行 {func.start_line}-{func.end_line}"

    # ── 函数指针间接调用跟踪 (复用 V1 function_pointer tracker) ──────────────
    def resolve_indirect_call(self, store: DataflowStore, func: FunctionRecord,
                              prop: PropagationRecord, ctx: PathContext) -> list[tuple[FunctionRecord, TaintParamInfo]]:
        """函数指针注册点追踪: 前后缀匹配缩小候选 + LLM 判断 (fresh session)"""
        from .trackers import resolve_indirect
        return resolve_indirect(self.cfg, self.source_root, self.sessions_dir, store,
                               func, prop, self.cancel_event, self.on_event, ctx.depth)

    # ── 外部变量跟踪 (item 1) ────────────────────────────────────────────────
    def resolve_external_propagation(self, store: DataflowStore, func: FunctionRecord,
                                     taint: TaintRecord, ctx: PathContext) -> list[tuple[FunctionRecord, TaintParamInfo]]:
        """外部变量下游追踪: 脚本 grep + LLM 语义判断 (fresh session, 一个函数一个 user)"""
        from .trackers import resolve_external
        return resolve_external(self.cfg, self.source_root, self.sessions_dir, store,
                               func, taint.name, taint.description or "",
                               self.cancel_event, self.on_event, ctx.depth)

    # ── 漏洞挖掘 (item 2) ────────────────────────────────────────────────────
    def mine_vulns(self, store: DataflowStore, func: FunctionRecord,
                   taint_params: TaintParamInfo, ctx: PathContext,
                   base_session: str = "") -> int:
        """fork 漏洞挖掘会话: 继承链 session (base_session, v1 模型 fork-from-parent),
        再提示分析本函数内的漏洞。存 finding + 上报 intake。"""
        acfg = self.cfg.workers.agents[0] if self.cfg.workers.agents else None
        if acfg is None:
            return 0
        fork_session = self.sessions_dir / f"d{ctx.depth:02d}-{_safe_name(func.name)}-vuln.jsonl"
        try:
            if base_session and Path(base_session).exists():
                safe_copyfile(base_session, str(fork_session))
        except OSError:
            pass
        taints = store.list_taints_in_function(func.func_id)
        props = store.list_propagations_from(func.func_id)
        dataflow_text = self._format_taint_context(func, taint_params, ctx, taints, props)
        prompt = (
            f"# 阶段：漏洞挖掘 Fork\n\n以上是整条调用链的污点分析历史 (从根函数到本函数)。\n"
            f"现在请基于全链上下文, 判断**本函数** `{func.file}::{func.name}` 内是否存在漏洞。\n"
            f"目标函数: `{func.file}::{func.name}` (行 {func.start_line}-{func.end_line})\n"
            f"污点: 位置 {taint_params.positions} 签名 {taint_params.signature} 名字 {taint_params.names}\n\n"
            "## 本函数污点分析摘要\n"
            f"```markdown\n{dataflow_text[:30000]}\n```\n\n"
            "结合链上 callee 的行为 (如返回借用指针/分配/不释放等), 判断本函数是否存在漏洞。输出 JSON: {\"findings\":[]}。"
        )
        miner_system = ("# 内嵌技能：mine-dataflow-vulnerability\n"
                        "禁止再读取 skills/mine-dataflow-vulnerability/SKILL.md。\n\n"
                        f"{_EMBEDDED_VULN_MINING_SKILL}\n\n{self._vuln_miner_prompt}")
        output = run_agent(
            prompt=prompt, model=acfg.model, tools=acfg.tools or self.cfg.workers.default_tools,
            cwd=str(self.vuln_root.parent), session_file=str(fork_session),
            system_prompt=miner_system, cancel_event=self.cancel_event,
            run_timeout_seconds=self.cfg.agent_run_timeout_seconds,
            timeout_retry_enabled=self.cfg.agent_timeout_retry_enabled,
            timeout_max_retries=self.cfg.agent_timeout_max_retries,
            pi_max_retries=self.cfg.pi_max_retries, pi_retry_delay=self.cfg.pi_retry_delay,
            task_context={"task_id": self.task_id, "task_root": str(self.run_dir.parent),
                          "task_run_root": str(self.run_dir), "task_pi_dir": self.cfg.role_pi_dir("workers"),
                          "agent_role": "workers"},
        )
        if self.on_event:
            emit_agent_runtime_events(self.on_event, result=output, stage="vuln_mining_v2",
                                      role="workers", model=acfg.model, extra={"function": func.name})
        from ..parsers import _extract_json_object as _ej
        parsed = _ej(output.output, "findings") or {"findings": []}
        node = f"{func.file}::{func.name}"
        n = 0
        for idx, item in enumerate(parsed.get("findings") or []):
            if not isinstance(item, dict):
                continue
            finding_id = f"vuln_{hashlib.sha1((self.run_id+str(idx)+json.dumps(item, ensure_ascii=False)).encode()).hexdigest()[:16]}"
            fdir = self.vuln_root / finding_id; fdir.mkdir(parents=True, exist_ok=True)
            fsrc = str(item.get("source_file") or func.file)
            ffn = str(item.get("function_name") or func.name)
            fline = str(item.get("line") or "")
            (fdir / "vulnerability-report.md").write_text(
                _format_vuln_report_md(item, finding_id, fsrc, ffn, fline), encoding="utf-8")
            (fdir / "taint-path-report.md").write_text(dataflow_text, encoding="utf-8")
            try:
                safe_copyfile(str(fork_session), str(fdir / "context.jsonl"))
            except OSError:
                (fdir / "context.jsonl").write_text("", encoding="utf-8")
            _exploit = item.get("exploitability")
            expl_str = json.dumps(_exploit, ensure_ascii=False) if isinstance(_exploit, (dict, list)) else str(_exploit or "")
            rec = VulnFindingRecord(
                finding_id=finding_id, run_id=self.run_id, node_id=node,
                source_file=fsrc, function_name=ffn, line=fline,
                vuln_type=str(item.get("vuln_type") or "unknown"),
                severity=str(item.get("severity") or "unknown"),
                title=str(item.get("title") or finding_id),
                summary=str(item.get("summary") or ""),
                evidence=str(item.get("evidence") or ""),
                exploitability=expl_str,
                confidence=float(item.get("confidence") or 0),
                output_dir=str(fdir))
            # 确保 FK 满足 + 插入 finding (同一 connection, 避免 FK 跨连接不可见)
            try:
                data = {'finding_id':finding_id,'run_id':self.run_id,'node_id':node,
                        'source_file':fsrc,'function_name':ffn,'line':fline,
                        'vuln_type':str(item.get('vuln_type') or 'unknown'),
                        'severity':str(item.get('severity') or 'unknown'),
                        'title':str(item.get('title') or finding_id),
                        'summary':str(item.get('summary') or ''),
                        'evidence':str(item.get('evidence') or ''),
                        'exploitability':expl_str,
                        'confidence':float(item.get('confidence') or 0),
                        'output_dir':str(fdir)}
                cols = list(data)
                with self.graph_store.connect() as conn:
                    conn.execute("INSERT OR IGNORE INTO analysis_runs (run_id,task_id,root_file,root_function,source_root,status) VALUES (?,?,?,?,?,?)",
                                 (self.run_id, self.task_id, func.file, func.name, self.source_root, "completed"))
                    conn.execute("INSERT OR IGNORE INTO taint_nodes (node_id,source_file,function_name,taint_kind,symbol,line,call_expr,description,parent_node_id,depth,context_session,run_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                                 (node, func.file, func.name, "vuln_site", ffline, str(fline), "", func.description or "", "", 0, "", self.run_id))
                    conn.execute(f"INSERT OR REPLACE INTO vulnerability_findings ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
                                 [data[c] for c in cols])
            except Exception as _fe:
                logger.warning("v2 add_finding FK+insert failed: %s", _fe, exc_info=True)
            n += 1
            # 上报 vuln-platform intake
            try:
                report_finding_to_intake(
                    project_id=self.cfg.project_id, task_id=self.task_id,
                    task_name=self.cfg.task_name, parent_task_name=self.cfg.parent_task_name,
                    parent_task_id=self.cfg.parent_task_id, finding=rec,
                    source_root=self.source_root,
                    report_path=str(fdir / "vulnerability-report.md"),
                    taint_path_report_path=str(fdir / "taint-path-report.md"))
            except Exception as exc:
                logger.warning("v2 intake report failed for %s: %s", finding_id, exc, exc_info=True)
        return n

    def _format_taint_context(self, func: FunctionRecord, tp: TaintParamInfo,
                              ctx: PathContext, taints: list[TaintRecord],
                              props: list[PropagationRecord]) -> str:
        pre_val = "\n".join(f"- {v.condition}: {v.content}" for v in ctx.pre_validations) or "(无)"
        lines = [f"## 函数: {func.file}::{func.name} (行 {func.start_line}-{func.end_line})",
                 f"功能: {func.description or '(待分析)'}",
                 f"入口污点: 位置 {tp.positions} 签名 {tp.signature} 名字 {tp.names}",
                 f"前置校验链:\n{pre_val}", "", "## 污点变量:"]
        for t in taints:
            lines.append(f"- {t.name} ({t.signature}): {t.description}")
        lines.append("\n## 传播路径:")
        for p in props:
            tgt = p.target_function or "(外部变量)" if p.is_external else p.target_function
            lines.append(f"- {p.source_taint_name} → {tgt}({p.target_taint_name}) @L{p.call_line} "
                         f"[{p.condition}] {p.description}")
        return "\n".join(lines)
