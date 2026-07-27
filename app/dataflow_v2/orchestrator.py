"""dataflow-v2 编排器 (深度优先, 路径敏感)。

路径模型 (用户示例):
  A(msg){ B; C(msg); if(x) D(msg); else E(msg); F(msg); }
  → 两条独立路径: A->C->D->F ; A->C->E->F

  D(msg){ G(msg); }            → D 内联展开: A->C->D->G->F
  E(msg){ g_msg=msg; }         → 外部变量传播, 跟踪 LLM 找到 H/I:
                                → A->C->E->H->F ; A->C->E->I->F

漏洞挖掘时机 (后序):
  - 叶子函数 (无出传播) 污点分析完成后立刻 fork 漏洞挖掘会话。
  - 非叶子函数 (如 A/D/E) 等其全部子路径完成后再挖 (才能知道 msg 在该函数
    的完整处理方式)。

去重 (三重): 到达某函数时, 若 (函数签名, 污点参数, 前置校验) 已在
processed_taints 命中 → 跳过重复分析。

本文件为骨架: DB + 路径数据结构 + 调度循环就绪; LLM fork / clang 分支判定 /
漏洞挖掘 fork 的具体接入留 TODO (下一阶段)。
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .models import (
    FunctionRecord, OrchestrationEdge, ProcessedTaint, PropagationRecord,
    TaintParamInfo, TaintRecord, Validation,
)
from .store import DataflowStore
from ..service.session_lineage_index import session_relpath_for_run_root, upsert_session_index_item
from ..vuln_report_utils import safe_name as _safe_name
from ..vuln_store import TaskGraphEdgeRecord

logger = logging.getLogger("dvs.dataflow_v2.orchestrator")


@dataclass
class AnalysisResult:
    """LLM 污点分析的产出。self_contained 由 LLM 判断 (设计点 #2):
    True  = 该函数对污点的处理自洽 (sink/漏洞判定仅靠函数自身即可) → 立即挖;
    False = 需下游子路径信息才能判定 → 后序挖 (等全部子路径完成)。
    """
    taints: list[TaintRecord] = field(default_factory=list)
    propagations: list[PropagationRecord] = field(default_factory=list)
    self_contained: bool = False
    description: str = ""        # 函数功能说明 (回写函数库)
    session_path: str = ""      # 本函数 taint 分析 fork session 路径 (供子函数/mining 继承链)
    return_taints: list[TaintRecord] = field(default_factory=list)  # 本函数 return 语句返回的污点
    taint_failed: bool = False  # taint 分析全失败 (retry 用尽), 跳过 mining
    # 专注模式: LLM 合并传播+挖掘后, 标记的“最可能产生漏洞的兴趣点”
    #   [{target_function, taint_param, reason, line}] — 编排器只跟入这些点 (往深挖),
    #   不做全 callee BFS。完整模式下为空。
    interest_points: list[dict] = field(default_factory=list)


class PathContext:
    """一条 DFS 路径的累积上下文 (前置校验链 + 已走边)。"""

    def __init__(self, path_id: str) -> None:
        self.path_id = path_id
        self.pre_validations: list[Validation] = []   # 从根到当前的前置校验链
        self.edges: list[OrchestrationEdge] = []
        self.depth: int = 0

    def validation_signature(self) -> str:
        return "|".join(t for t in (_canon_validation(v) for v in self.pre_validations) if t)

    def fork(self, new_path_id: str) -> "PathContext":
        c = PathContext(new_path_id)
        c.pre_validations = list(self.pre_validations)
        c.edges = list(self.edges)
        c.depth = self.depth
        return c


# ── 回调接口 (由上层注入 LLM/clang 实现) ─────────────────────────────────────
class AnalysisCallbacks:
    """注入点: 实际的 LLM 污点分析 / clang 分支判定 / 漏洞挖掘 fork。"""

    def analyze_function(self, store: DataflowStore, func: FunctionRecord,
                         taint_params: TaintParamInfo, pre_validations: list[Validation],
                         base_session: str, ctx: PathContext) -> AnalysisResult:
        """fork 会话用 LLM 分析函数功能 + 污点传播; 返回 AnalysisResult
        (taints/propagations/self_contained/description)。

        self_contained 由 LLM 判断: 该函数对污点的处理是否自洽 (仅靠自身即可
        判定 sink/漏洞), 决定漏洞挖掘时机 (立即 vs 后序)。TODO: 接入 run_agent
        + prompts/v2/taint-analysis.md; 用 clang 标注每条 propagation 的调用点
        分支上下文 (互斥 arm → 独立路径)。
        """
        return AnalysisResult()

    def resolve_external_propagation(self, store: DataflowStore, func: FunctionRecord,
                                     prop: PropagationRecord, ctx: PathContext,
                                     base_session: str = "") -> list[tuple[FunctionRecord, TaintParamInfo]]:
        """taint 传播到外部变量 (如 ctx->buf) 时, 跟踪查找读取该变量的跟入函数。

        返回 [(目标函数, 该路径上的污点参数信息)] 用于分叉路径。
        """
        return []

    def resolve_indirect_call(self, store: DataflowStore, func: FunctionRecord,
                              prop: PropagationRecord, ctx: PathContext,
                              base_session: str = "") -> list[tuple[FunctionRecord, TaintParamInfo]]:
        """函数指针/回调/dispatch 间接调用 → function_pointer tracker 搜注册点 → 处理函数。

        返回 [(处理函数, 污点参数)] 用于分叉路径。TODO: 接入。
        """
        return []

    def mine_vulns(self, store: DataflowStore, func: FunctionRecord,
                   taint_params: TaintParamInfo, ctx: PathContext,
                   base_session: str = "") -> int:
        """fork 漏洞挖掘会话 (复用 vuln-miners/default.md), 存 finding + 上报 intake。
        继承整条链 taint 分析 session (base_session), 再提示分析当前函数内的漏洞。"""
        return 0

    def analyze_and_mine_focus(self, store: DataflowStore, func: FunctionRecord,
                               taint_params: TaintParamInfo, pre_validations: list[Validation],
                               base_session: str, ctx: PathContext) -> AnalysisResult:
        """专注模式: 单函数合并污点传播 + 漏洞挖掘。

        一次 LLM 调用完成传播 (propagations/taints/return_taints) + 挖掘 (findings) +
        输出“兴趣点” (interest_points: 最可能产生漏洞、值得往深跟的 callee/sink)。
        编排器只跟入兴趣点 (目标深挖), 不做全 callee BFS。返回 AnalysisResult (含 interest_points)。"""
        return AnalysisResult()


class ChainStep:
    """路径链上一步: 待分析的 callee + 其污点参数 + 截至该步累积的校验。"""
    __slots__ = ("func", "taint_params", "validations", "call_line", "prop_id",
                "branch_group_id", "branch_arm_id")

    def __init__(self, func: FunctionRecord, taint_params: TaintParamInfo,
                validations: list[Validation], call_line: int = 0, prop_id: str = "",
                branch_group_id: str = "", branch_arm_id: str = "") -> None:
        self.func = func
        self.taint_params = taint_params
        self.validations = validations
        self.call_line = call_line
        self.prop_id = prop_id
        self.branch_group_id = branch_group_id
        self.branch_arm_id = branch_arm_id


class DfsOrchestrator:
    """深度优先编排器 (路径敏感, 同步递归)。

    核心语义 (设计点确认):
    - 有序链: 一个函数的 propagations 按 call_line 排序, 构成有序链 (非独立兄弟)。
    - 互斥分叉: 同 branch_group_id 不同 arm → 在该处分叉成 N 条子链; 非互斥继续同链。
    - 外部变量分叉: is_external 的 propagation → resolve_external_propagation 找跟入函数,
      每个跟入函数 fork 一条子链。
    - 校验链回传: 子函数分析产出的 validations 回传, 追加进链 pre_validations, 供下一步
      callee 上下文使用 (D 看到 C 的校验, F 看到 C+D 的)。
    - 漏洞挖掘时机: self_contained=True → 分析后立即挖 (不论是否有子链); False → 全部子链
      完成后挖 (后序)。

    当前为同步递归实现 (正确性优先); 并发 (路径状态机+线程池) 为后续优化。
    """

    def __init__(self, store: DataflowStore, cbs: AnalysisCallbacks,
                 n_workers: int = 4, concurrent: bool = False,
                 max_concurrent_llm: int = 8, max_depth: int = 10,
                 focus_mode: bool = False) -> None:
        self.store = store
        self.cbs = cbs
        self.n_workers = n_workers
        self.concurrent = concurrent
        self.max_depth = max_depth
        self.focus_mode = focus_mode
        self._llm_sem = threading.Semaphore(max_concurrent_llm) if concurrent else None
        # 根函数(depth=0) taint 分析是否解析失败 (parse_warn), 供 runner 区分
        # "LLM 主动判定无可跟踪污点(合法空)" vs "解析失败/格式错误"。
        # 仅在 _process depth==0 时写入; BFS 去重保证根只分析一次, 无并发竞争。
        self.root_taint_failed = False
        # 根函数(depth=0) 是否真正跑了 LLM 分析 (区别于"被 processed_taints 跳过")
        self.root_analyzed = False
        # 根函数 LLM 判定的 self_contained (合法空结果时区分"存根/终态无流" vs "可疑漏报")
        self.root_self_contained = False

    def _run_llm(self, fn: Callable, *args: Any, **kw: Any) -> Any:
        """LLM 调用限流: 信号量 cap 并发 analyze/mine/track 调用, 避免打爆配额。
        父函数在 join 子路径前已释放信号量, 故不会与子调用死锁。"""
        if self._llm_sem is not None:
            self._llm_sem.acquire()
        try:
            return fn(*args, **kw)
        finally:
            if self._llm_sem is not None:
                self._llm_sem.release()

    def _graph_store(self):
        return getattr(self.cbs, "graph_store", None)

    def _cancel_requested(self) -> bool:
        cancel_event = getattr(self.cbs, "cancel_event", None)
        return bool(cancel_event is not None and cancel_event.is_set())

    def _graph_node_id(self, func: FunctionRecord) -> str:
        graph_node_id = getattr(self.cbs, "graph_node_id", None)
        if callable(graph_node_id):
            return str(graph_node_id(func) or "")
        return ""

    def _graph_task_id(self) -> str:
        return str(getattr(self.cbs, "task_id", "") or "")

    def _graph_epoch(self) -> str:
        return str(getattr(self.cbs, "graph_epoch", "run") or "run")

    def _session_lineage_run_root(self) -> Path | None:
        run_root = getattr(self.cbs, "session_lineage_run_root", None)
        if isinstance(run_root, Path):
            return run_root
        sessions_dir = getattr(self.cbs, "sessions_dir", None)
        if isinstance(sessions_dir, Path):
            return sessions_dir.parent
        return None

    def _register_created_base_session(
        self,
        *,
        session_path: str | Path,
        parent_session_path: str | Path = "",
        relation_kind: str = "fork",
        session_kind: str = "taint",
    ) -> None:
        run_root = self._session_lineage_run_root()
        task_id = self._graph_task_id()
        if run_root is None or not task_id or not str(session_path or "").strip():
            return
        session_file = Path(session_path)
        if not session_file.exists():
            return
        upsert_session_index_item(
            run_root=run_root,
            task_id=task_id,
            session_relpath=session_relpath_for_run_root(run_root, session_file),
            parent_session_relpath=(
                session_relpath_for_run_root(run_root, parent_session_path)
                if str(parent_session_path or "").strip()
                else ""
            ),
            relation_kind=relation_kind,
            node_id="",
            edge_id="",
            session_role="worker",
            session_kind=session_kind,
            display_name=session_file.stem,
            status="done",
            started_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            ended_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        )

    def _return_followup_edge_id(
        self,
        *,
        source_func: FunctionRecord,
        target_func: FunctionRecord,
        taint_signature: str,
        path_id: str,
        call_line: int,
    ) -> str:
        key = f"return|{path_id}|{call_line}|{source_func.func_id}|{target_func.func_id}|{taint_signature}"
        return f"return::{hashlib.sha1(key.encode()).hexdigest()[:24]}"

    def _upsert_return_followup_edge(
        self,
        *,
        source_func: FunctionRecord,
        target_func: FunctionRecord,
        taint_name: str,
        taint_signature: str,
        path_id: str,
        call_line: int,
        status: str,
        reason_code: str = "",
        reason_message: str = "",
        reason_source: str = "",
    ) -> str:
        graph_store = self._graph_store()
        if graph_store is None:
            return ""
        edge_id = self._return_followup_edge_id(
            source_func=source_func,
            target_func=target_func,
            taint_signature=taint_signature,
            path_id=path_id,
            call_line=call_line,
        )
        graph_store.upsert_task_graph_edge(TaskGraphEdgeRecord(
            edge_id=edge_id,
            task_id=self._graph_task_id(),
            epoch=self._graph_epoch(),
            source_node_id=self._graph_node_id(source_func),
            target_node_id=self._graph_node_id(target_func),
            source_func_id=source_func.func_id,
            target_func_id=target_func.func_id,
            source_function_resolved=source_func.name,
            target_function_resolved=target_func.name,
            target_function_raw=target_func.name,
            source_file=source_func.file,
            target_file=target_func.file,
            edge_kind="return_followup",
            status=status,
            reason_code=reason_code,
            reason_message=reason_message,
            reason_source=reason_source,
            source_prop_id=edge_id,
            call_line=call_line or None,
            source_taint_name=taint_name,
            target_taint_name=taint_name,
            display_order=max(0, call_line),
            visible_in_tree=0,
            visible_in_all_propagations=1,
        ))
        return edge_id

    def run(self, root_func: FunctionRecord, root_taint: TaintParamInfo,
            base_session: str = "") -> None:
        """从根函数出发 DFS。"""
        ctx = PathContext(path_id=_path_id(root_func.func_id, root_taint.signature, "0"))
        _, root_return_taints = self._process(root_func, root_taint, ctx.pre_validations, base_session, ctx, 0)

        # 向上回溯: 根函数返回了污点 → 查找调用者, 在 depth -1 分析
        # 场景: A(入口) { msg=recv(); return msg; } → B(调用者) { msg=A(); handle(msg); }
        # B 才是真正处理数据的地方
        if root_return_taints:
            self._analyze_callers(root_func, root_return_taints, base_session, ctx)

    def _analyze_callers(self, func: FunctionRecord, return_taints: list,
                         base_session: str, ctx: Any) -> None:
        """查找 func 的调用者, 用 return_taints 在 depth -1 分析。"""
        from .function_extractor import read_function_body
        callers: list[FunctionRecord] = []
        fname = func.name
        for f in self.store.list_functions():
            if f.func_id == func.func_id:
                continue
            # 快速过滤: 函数体包含 fname(
            try:
                body = read_function_body(self.cbs.source_root, f, max_lines=4000)
                if body and (fname + "(" in body or fname + " (" in body):
                    callers.append(f)
            except Exception as e:
                logger.warning("read caller function body failed, skip caller (func=%s): %s", f, e)
                continue
        if callers:
            self.cbs.on_event("v2_caller_tracked", function=func.name,
                              caller_count=len(callers),
                              return_taints=[rt.name for rt in return_taints])
        for caller in callers:
            for rt in return_taints:
                rt_sig = _norm_taint_sig(rt.signature or rt.name)
                if self.store.find_processed_taint(caller.func_id, rt_sig, _validation_sig([])):
                    continue
                new_tp = TaintParamInfo(positions=[], signature=rt_sig, names=[rt.name])
                new_session = str(_session_path(self.cbs.sessions_dir, -1, caller.name, rt.name, kind="taint")) if base_session else ""
                if base_session:
                    from ..copy_utils import safe_copyfile
                    try:
                        safe_copyfile(base_session, new_session)
                        self._register_created_base_session(
                            session_path=new_session,
                            parent_session_path=base_session,
                            relation_kind="fork",
                            session_kind="taint",
                        )
                    except OSError as e:
                        logger.debug("copy base_session for return-followup failed (base=%s): %s", base_session, e)
                caller_ctx = ctx.fork(_path_id(caller.func_id, rt_sig, "-1"))
                self._upsert_return_followup_edge(
                    source_func=func,
                    target_func=caller,
                    taint_name=rt.name,
                    taint_signature=rt_sig,
                    path_id=caller_ctx.path_id,
                    call_line=int(getattr(rt, "entry_line", 0) or 0),
                    status="running",
                )
                try:
                    self._process(caller, new_tp, [], new_session, caller_ctx, -1)
                except BaseException:
                    cancelled = self._cancel_requested()
                    self._upsert_return_followup_edge(
                        source_func=func,
                        target_func=caller,
                        taint_name=rt.name,
                        taint_signature=rt_sig,
                        path_id=caller_ctx.path_id,
                        call_line=int(getattr(rt, "entry_line", 0) or 0),
                        status="cancelled" if cancelled else "failed",
                        reason_code="task_cancelled" if cancelled else "return_followup_failed",
                        reason_message="task cancellation interrupted return followup" if cancelled else "return followup caller analysis failed",
                        reason_source="cancel" if cancelled else "orchestrator",
                    )
                    raise
                cancelled = self._cancel_requested()
                self._upsert_return_followup_edge(
                    source_func=func,
                    target_func=caller,
                    taint_name=rt.name,
                    taint_signature=rt_sig,
                    path_id=caller_ctx.path_id,
                    call_line=int(getattr(rt, "entry_line", 0) or 0),
                    status="cancelled" if cancelled else "done",
                    reason_code="task_cancelled" if cancelled else "",
                    reason_message="task cancellation interrupted return followup" if cancelled else "",
                    reason_source="cancel" if cancelled else "",
                )

    # ── 核心: 处理一个函数 (返回 my_discovered + return_taints) ──────────────
    def _process(self, func: FunctionRecord, taint_params: TaintParamInfo,
                 pre_validations: list[Validation], base_session: str,
                 ctx: PathContext, depth: int) -> tuple[list[Validation], list[TaintRecord]]:
        # 1) 三重去重 (子集匹配: 已有更完整 pre_val 的记录 → 当前视为已覆盖, 跳过)
        pre_val_sig = _validation_sig(pre_validations)
        _nts = _norm_taint_sig(taint_params.signature)
        if self.store.find_processed_taint(func.func_id, _nts, pre_val_sig):
            return [], []  # 已分析过, 跳过
        # 1b) 双检锁: analyze 前先占位 (INSERT OR IGNORE), 防并发 N 路径同 (func,taint,pre_val)
        #     同时 find-None → 全跑 LLM → N 份冗余分析。占位成功→本线程分析; 占位失败→并发 peer 在分析→跳过。
        _reserve = ProcessedTaint(
            taint_params=taint_params.names, taint_signature=_nts,
            pre_validations=[v.to_dict() for v in pre_validations],
            pre_validation_signature=pre_val_sig, sessions_path=base_session)
        if not self.store.try_reserve_processed_taint(func.func_id, _reserve):
            return [], []  # 并发 peer 已占位, 跳过

        self.cbs.on_event("trace_start", function=func.name, source_file=func.file,
                          depth=depth, max_depth=self.max_depth)
        logger.info("[V2-orch] _process START func=%s depth=%d taint=%s", func.name, depth, taint_params.signature)

        # 2) LLM 污点分析 (fork 会话); 失败时删占位 (让后续可重试)
        ctx.depth = depth
        try:
            result = self._run_llm(
                self.cbs.analyze_function, self.store, func, taint_params, pre_validations, base_session, ctx)
        except BaseException:
            self.store.delete_processed_taint(func.func_id, _nts)
            raise
        if depth == 0:
            # 供 runner 在 0 边 0 传播时区分 "合法空" vs "解析失败" vs "被跳过"
            self.root_taint_failed = bool(getattr(result, "taint_failed", False))
            self.root_analyzed = True
            self.root_self_contained = bool(getattr(result, "self_contained", False))
        for t in result.taints:
            self.store.upsert_taint(t)
        for p in result.propagations:
            self.store.upsert_propagation(p)
            self._record_propagation_edge(func, p, depth)
        if result.description:
            func.description = result.description
            self.store.upsert_function(func)

        # 第一次 trace_callees: 只含直接调用 (非间接/非外部)
        # 间接调用的 target_function 是原始表达式 (如 ctxt->sax->cdataBlock),
        # 等 _build_paths 解析后再发第二次 trace_callees 带解析后的真实函数名
        direct_callees = [p.target_function for p in result.propagations
                          if p.target_function and not p.is_indirect_call and not p.is_external]
        self.cbs.on_event("trace_callees", function=func.name, callees=direct_callees, depth=depth)

        self_contained = result.self_contained
        chain_session = result.session_path

        # 3) 占位已在 1b 完成 (双检锁); 此处无需再 add

        my_discovered = _dedup_validations(
            [v for p in result.propagations for v in p.validations])

        # 4) self_contained=true → 立即 mine (无 callee, 不用等)
        #    taint 分析失败时跳过 mining — 无污点分析结果, 挖掘无意义
        if self_contained and not result.taint_failed:
            self._run_llm(self.cbs.mine_vulns, self.store, func, taint_params, ctx, chain_session)

        # 5) 构造有序路径 + 跟入 callee
        if depth < self.max_depth:
            # 用 LLM 报的 taints[] + 入口污点过滤
            # taints[] 包含入口污点 + 本地派生污点 (如 a=x 的 a)
            # 不含 callee 返回值 (如 a=A(x) 的 a — LLM 不确定是否被污染)
            # 返回值派生的 propagation 在 return_taints 重分析轮自然拾起
            taint_names = set(taint_params.names) | {t.name for t in result.taints}
            paths = self._build_paths(result.propagations, func, ctx, depth,
                                      list(taint_names), chain_session)
        else:
            paths = []

        # 5b) 发 trace_callees_resolved: 仅发真正被解析并继续跟入的目标集合。
        # 原始 callee 名称由第一次 trace_callees 保留; resolved 事件避免把原始名和
        # 规范化后的真实函数名混在一起。
        resolved_callees: list[str] = []
        resolved_seen: set[str] = set()
        for path_steps in paths:
            if not path_steps or not path_steps[0].func:
                continue
            rec = path_steps[0].func
            if rec.func_id in resolved_seen:
                continue
            resolved_seen.add(rec.func_id)
            resolved_callees.append(rec.name)
            self._mark_path_step_scheduled(func, path_steps[0], ctx, depth)
        if resolved_callees:
            self.cbs.on_event("trace_callees", function=func.name,
                              callees=resolved_callees, depth=depth,
                              resolved=True)

        base_accumulated = list(pre_validations) + list(my_discovered)
        all_callee_return_taints: list[TaintRecord] = []
        if self.concurrent and len(paths) > 1:
            threads: list[threading.Thread] = []
            results_lock = threading.Lock()
            errs: list[BaseException] = []
            for path_steps in paths:
                def _run_one(ps=path_steps):
                    try:
                        fb, rts = self._run_path(ps, base_accumulated, func, chain_session, ctx, depth)
                        with results_lock:
                            all_callee_return_taints.extend(rts)
                    except BaseException as exc:
                        logger.warning("_run_path sub-thread failed (func=%s target=%s): %s", func.name, getattr(ps, "target_function", "?"), exc, exc_info=not isinstance(exc, KeyboardInterrupt))
                        with results_lock:
                            errs.append(exc)
                t = threading.Thread(target=_run_one, daemon=True,
                                     name=f"dvs2-path-{func.name}-{len(threads)}")
                threads.append(t); t.start()
            for t in threads:
                t.join()
            if errs:
                raise errs[0]
        else:
            for path_steps in paths:
                _, rts = self._run_path(path_steps, base_accumulated, func, chain_session, ctx, depth)
                all_callee_return_taints.extend(rts)

        # 6) self_contained=false → 后序 mine (callee 已完成, 含 callee 分析结果)
        #    taint 分析失败时跳过 mining
        if not self_contained and not result.taint_failed:
            self._run_llm(self.cbs.mine_vulns, self.store, func, taint_params, ctx, chain_session)

        # 7) return_taints 回传: 对每个 callee 返回的新污点, 在当前函数启动新分析分支
        # #11: return_taint 带 entry_line (callee 调用点行); 若该污点本函数已持有 (escape 源头)
        #    则不回传重分析 — 否则形成冗余循环 (源头早有该污点, reader 回传=重复)
        # #13: taint_sig 归一 (去 this->/尾 ()) 让 proxyBindAddr_ / this->proxyBindAddr_ 去重命中
        my_taint_sigs = {_norm_taint_sig(t.name) for t in result.taints} | {_norm_taint_sig(n) for n in taint_params.names}
        for rt in all_callee_return_taints:
            rt_sig = _norm_taint_sig(rt.signature or rt.name)
            if self.store.find_processed_taint(func.func_id, rt_sig, pre_val_sig):
                continue  # 已分析过此污点, 跳过
            try:
                self.cbs.on_event("v2_step7_find_miss_debug",
                    function=func.name, func_id=func.func_id[:10],
                    rt_name=rt.name, rt_sig=rt_sig, rt_raw_sig=rt.signature,
                    pre_val_sig=pre_val_sig[:60] if pre_val_sig else "(empty)",
                    n_return_taints=len(all_callee_return_taints))
            except Exception as e:
                logger.info("emit v2_step7_find_miss_debug failed (func=%s): %s", func.name, e)
            if rt_sig in my_taint_sigs:
                # 本函数已持有该污点 (escape 源头场景): reader 回传=冗余, 跳过, 终止循环
                self.cbs.on_event("v2_return_taint_skipped_redundant",
                                  function=func.name, taint=rt.name, entry_line=rt.entry_line,
                                  reason="func already holds this taint (escape source)")
                continue
            # 新 fork session (从父链重新 fork, taint 不同); #10: 不覆盖, NN 自增
            new_session = str(_session_path(self.cbs.sessions_dir, depth, func.name, rt.name)) if chain_session else ""
            if chain_session:
                from ..copy_utils import safe_copyfile
                try:
                    safe_copyfile(chain_session, new_session)
                    self._register_created_base_session(
                        session_path=new_session,
                        parent_session_path=chain_session,
                        relation_kind="fork",
                        session_kind="taint",
                    )
                except OSError as e:
                    logger.debug("copy chain_session failed (base=%s): %s", chain_session, e)
            new_tp = TaintParamInfo(positions=[], signature=rt_sig, names=[rt.name])
            source_func = getattr(rt, "_graph_return_source_func", func)
            self._upsert_return_followup_edge(
                source_func=source_func,
                target_func=func,
                taint_name=rt.name,
                taint_signature=rt_sig,
                path_id=ctx.path_id,
                call_line=int(getattr(rt, "entry_line", 0) or 0),
                status="running",
            )
            try:
                self._process(func, new_tp, list(pre_validations), new_session, ctx, depth)
            except BaseException:
                cancelled = self._cancel_requested()
                self._upsert_return_followup_edge(
                    source_func=source_func,
                    target_func=func,
                    taint_name=rt.name,
                    taint_signature=rt_sig,
                    path_id=ctx.path_id,
                    call_line=int(getattr(rt, "entry_line", 0) or 0),
                    status="cancelled" if cancelled else "failed",
                    reason_code="task_cancelled" if cancelled else "return_followup_failed",
                    reason_message="task cancellation interrupted return followup" if cancelled else "return followup re-analysis failed",
                    reason_source="cancel" if cancelled else "orchestrator",
                )
                raise
            cancelled = self._cancel_requested()
            self._upsert_return_followup_edge(
                source_func=source_func,
                target_func=func,
                taint_name=rt.name,
                taint_signature=rt_sig,
                path_id=ctx.path_id,
                call_line=int(getattr(rt, "entry_line", 0) or 0),
                status="cancelled" if cancelled else "done",
                reason_code="task_cancelled" if cancelled else "",
                reason_message="task cancellation interrupted return followup" if cancelled else "",
                reason_source="cancel" if cancelled else "",
            )

        # 8) 返回 (本函数校验, 本函数的 return_taints)
        logger.info("[V2-orch] _process DONE func=%s depth=%d paths=%d return_taints=%d",
                    func.name, depth, len(paths) if "paths" in dir() else 0, len(all_callee_return_taints))
        return my_discovered, result.return_taints

    def _run_path(self, steps: list[ChainStep], base_accumulated: list[Validation],
                  func: FunctionRecord, base_session: str, ctx: PathContext,
                  depth: int) -> tuple[list[Validation], list[TaintRecord]]:
        """运行一条有序链: 链内严格顺序, 校验链累加 + 子回传 + 收集 return_taints。"""
        accumulated = list(base_accumulated)
        all_return_taints: list[TaintRecord] = []
        for step in steps:
            incoming = list(accumulated) + list(step.validations)
            orch_edge = OrchestrationEdge(
                path_id=ctx.path_id, source_function=func.name,
                source_signature=func.signature, source_func_id=func.func_id,
                target_function=step.func.name, target_signature=step.func.signature,
                target_func_id=step.func.func_id, taint_params=step.taint_params,
                depth=depth + 1, edge_order=step.call_line, status="done")
            self.store.upsert_edge(orch_edge)
            bridge_edge_id = step.prop_id if step.prop_id.startswith("bridge::") else ""
            graph_store = self._graph_store()
            if graph_store is not None:
                graph_store.update_task_graph_edge(
                step.prop_id,
                status="running",
                target_node_id=self._graph_node_id(step.func),
                target_func_id=step.func.func_id,
                target_function_resolved=step.func.name,
                target_file=step.func.file,
                reason_code="",
                reason_message="",
                reason_source="",
                )
                graph_store.update_task_graph_node(
                    self._graph_node_id(step.func),
                    status="running",
                    analysis_status="running",
                )
            sub_ctx = ctx.fork(_path_id(step.func.func_id, step.taint_params.signature, str(depth + 1)))
            sub_ctx.pre_validations = list(incoming)
            try:
                child_fb, child_rts = self._process(step.func, step.taint_params, incoming,
                                                    base_session, sub_ctx, depth + 1)
            except BaseException:
                if graph_store is not None:
                    cancelled = self._cancel_requested()
                    graph_store.update_task_graph_edge(
                        step.prop_id,
                        status="cancelled" if cancelled else "failed",
                        reason_code="task_cancelled" if cancelled else "child_process_failed",
                        reason_message="task cancellation interrupted child process" if cancelled else f"{step.func.name} child process failed",
                        reason_source="cancel" if cancelled else "orchestrator",
                    )
                    graph_store.update_task_graph_node(
                        self._graph_node_id(step.func),
                        status="cancelled" if cancelled else "failed",
                        analysis_status="cancelled" if cancelled else "failed",
                        finished_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    )
                raise
            accumulated.extend(child_fb)
            for _rt in child_rts:
                _rt.entry_line = step.call_line  # #11: return_taint 进入 caller 的行 (callee 调用点)
                setattr(_rt, "_graph_return_source_func", step.func)
            all_return_taints.extend(child_rts)
            if graph_store is not None:
                cancelled = self._cancel_requested()
                graph_store.update_task_graph_edge(
                    step.prop_id,
                    status="cancelled" if cancelled else "done",
                    target_node_id=self._graph_node_id(step.func),
                    target_func_id=step.func.func_id,
                    target_function_resolved=step.func.name,
                    target_file=step.func.file,
                    reason_code="task_cancelled" if cancelled else "",
                    reason_message="task cancellation interrupted child completion" if cancelled else "",
                    reason_source="cancel" if cancelled else "",
                )
                graph_store.update_task_graph_node(
                    self._graph_node_id(step.func),
                    status="cancelled" if cancelled else "done",
                    analysis_status="cancelled" if cancelled else "done",
                    finished_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                )
        return accumulated, all_return_taints

    # ── 路径构造: 有序链 + 互斥分叉 + 外部分叉 ───────────────────────────────
    def _build_paths(self, props: list[PropagationRecord], func: FunctionRecord,
                     ctx: PathContext, depth: int,
                     taint_names: list[str], chain_session: str = "") -> list[list[ChainStep]]:
        if not props:
            return []
        # 只跟入 source 有"已确认污点"支撑的 propagation (防爆炸 + 不跟未确认的 callee 返回值派生)
        # - callee 传播: source_taint 必须 ∈ taint_set (严格, 防 callee 返回值未确认就跟入)
        # - escape 传播 (is_external+escape_kind): 语义匹配 — carrier 整体逃逸或 carrier->field
        #   字段访问都算, 只要背后有已确认污点 (carrier 持有 taints[] 字段, 或 field ∈ taint_set),
        #   不强求 LLM 把 source_taint 改写成 taints[] 成员 (carrier/字段访问是 LLM 合理表达)
        taint_set = set(taint_names)
        props_sorted = sorted(
            [p for p in props if _prop_backed_by_taint(p, taint_set)],
            key=lambda p: p.call_line)
        if not props_sorted:
            return []
        # 预分组互斥 arm: group_id -> {arm -> [props]}
        groups: dict[str, dict[str, list[PropagationRecord]]] = {}
        for p in props_sorted:
            if p.branch_group_id:
                groups.setdefault(p.branch_group_id, {}).setdefault(p.branch_arm_id, []).append(p)
        mutex_groups = {gid for gid, arms in groups.items() if len(arms) > 1}

        paths: list[list[ChainStep]] = [[]]
        consumed: set[str] = set()
        for p in props_sorted:
            gid = p.branch_group_id
            if gid in mutex_groups:
                if gid in consumed:
                    continue  # 该 group 的 arm 已整体放置
                consumed.add(gid)
                arms = groups[gid]
                new_paths: list[list[ChainStep]] = []
                for base in paths:
                    for arm, arm_props in arms.items():
                        steps = [s for ap in arm_props for s in self._prop_to_steps(ap)]
                        if steps:
                            new_paths.append(base + steps)
                if new_paths:
                    paths = new_paths
            elif p.is_external:
                # 外部变量传播 → 跟踪 LLM 找跟入函数, 每个跟入 fork 一条子链
                targets = self._run_llm(
                    self.cbs.resolve_external_propagation, self.store, func, p, ctx, chain_session)
                if not targets:
                    graph_store = self._graph_store()
                    if graph_store is not None:
                        graph_store.update_task_graph_edge(
                            p.prop_id,
                            edge_kind="unresolved_target",
                            status="unresolved",
                            reason_code="tracker_no_target",
                            reason_message="external tracker did not resolve target",
                            reason_source="tracker",
                            tracker_type="external_escape",
                            tracker_result_json=json.dumps({"resolved_targets": []}, ensure_ascii=False),
                        )
                    continue  # TODO stub 未接: 不 fork
                new_paths = []
                for base in paths:
                    for tgt_func, tp in targets:
                        bridge_edge_id = self._graph_bridge_edge_id(
                            "container_reader", ctx.path_id, p.call_line, tgt_func.func_id, p.prop_id)
                        self._record_bridge_edge(
                            func,
                            p,
                            tgt_func,
                            ctx,
                            depth,
                            edge_kind="container_reader",
                            tracker_type="external_escape",
                            bridge_edge_id=bridge_edge_id,
                            tracker_result={"resolved_targets": [tgt_func.name for tgt_func, _ in targets]},
                        )
                        new_paths.append(base + [ChainStep(tgt_func, tp, list(p.validations),
                                                           p.call_line, bridge_edge_id)])
                paths = new_paths
            elif p.is_indirect_call:
                # 函数指针/回调间接调用 → function_pointer tracker 搜注册点 → 处理函数
                targets = self._run_llm(self.cbs.resolve_indirect_call, self.store, func, p, ctx, chain_session)
                if not targets:
                    graph_store = self._graph_store()
                    if graph_store is not None:
                        graph_store.update_task_graph_edge(
                            p.prop_id,
                            edge_kind="unresolved_target",
                            status="unresolved",
                            reason_code="tracker_no_target",
                            reason_message="indirect-call tracker did not resolve target",
                            reason_source="tracker",
                            tracker_type="indirect_call",
                            tracker_result_json=json.dumps({"resolved_targets": []}, ensure_ascii=False),
                        )
                    continue  # 无法静态解析注册点, 不 fork
                new_paths = []
                for base in paths:
                    for tgt_func, tp in targets:
                        bridge_edge_id = self._graph_bridge_edge_id(
                            "indirect_call", ctx.path_id, p.call_line, tgt_func.func_id, p.prop_id)
                        self._record_bridge_edge(
                            func,
                            p,
                            tgt_func,
                            ctx,
                            depth,
                            edge_kind="indirect_call",
                            tracker_type="indirect_call",
                            bridge_edge_id=bridge_edge_id,
                            tracker_result={"resolved_targets": [tgt_func.name for tgt_func, _ in targets]},
                        )
                        new_paths.append(base + [ChainStep(tgt_func, tp, list(p.validations),
                                                           p.call_line, bridge_edge_id)])
                paths = new_paths
            else:
                # 直接调用
                if p.is_external_callee:
                    # callee 定义不在源码树 — 记录传播但不跟入, 不走 tracker
                    # propagation 已存 DB, 调用树显示但不可展开
                    continue
                steps = self._prop_to_steps(p)
                if not steps:
                    graph_store = self._graph_store()
                    if graph_store is not None:
                        graph_store.update_task_graph_edge(
                            p.prop_id,
                            edge_kind="unresolved_target",
                            status="unresolved",
                            reason_code="callee_not_resolved",
                            reason_message="direct callee could not be resolved",
                            reason_source="orchestrator",
                        )
                    continue  # callee 解析失败, 跳过
                if len(steps) > 1:
                    new_paths = []
                    for base in paths:
                        for step in steps:
                            bridge_edge_id = self._graph_bridge_edge_id(
                                "direct_call", ctx.path_id, p.call_line, step.func.func_id, p.prop_id)
                            self._record_bridge_edge(
                                func,
                                p,
                                step.func,
                                ctx,
                                depth,
                                edge_kind="direct_call",
                                tracker_type="direct_resolution",
                                bridge_edge_id=bridge_edge_id,
                                tracker_result={"resolved_targets": [item.func.name for item in steps]},
                            )
                            new_paths.append(base + [ChainStep(
                                step.func,
                                step.taint_params,
                                list(step.validations),
                                step.call_line,
                                bridge_edge_id,
                                step.branch_group_id,
                                step.branch_arm_id,
                            )])
                    paths = new_paths
                    continue
                new_paths = []
                for base in paths:
                    for step in steps:
                        new_paths.append(base + [step])
                if new_paths:
                    paths = new_paths
        return [p for p in paths if p]  # 剔除空链

    def _record_propagation_edge(self, func: FunctionRecord, prop: PropagationRecord, depth: int) -> None:
        graph_store = self._graph_store()
        if graph_store is None:
            return
        source_node_id = self._graph_node_id(func)
        target_rec = self.store.get_function(prop.target_func_id) if prop.target_func_id else None
        edge_kind = "external_escape" if prop.is_external else (
            "indirect_call" if prop.is_indirect_call else (
                "external_callee" if prop.is_external_callee else "direct_call"
            )
        )
        graph_store.upsert_task_graph_edge(TaskGraphEdgeRecord(
            edge_id=prop.prop_id,
            task_id=getattr(self.cbs, "task_id", ""),
            epoch=getattr(self.cbs, "graph_epoch", "run"),
            source_node_id=source_node_id,
            target_node_id=self._graph_node_id(target_rec) if target_rec is not None else "",
            source_func_id=func.func_id,
            target_func_id=prop.target_func_id,
            source_function_resolved=func.name,
            target_function_resolved=target_rec.name if target_rec is not None else prop.target_function,
            target_function_raw=prop.target_function,
            source_file=func.file,
            target_file=target_rec.file if target_rec is not None else prop.target_file,
            edge_kind=edge_kind,
            status="not_followed" if prop.is_external_callee else "discovered",
            reason_code="external_callee" if prop.is_external_callee else "",
            reason_message="callee definition is outside source tree" if prop.is_external_callee else "",
            reason_source="analysis" if prop.is_external_callee else "",
            source_prop_id=prop.prop_id,
            call_line=prop.call_line or None,
            source_taint_name=prop.source_taint_name,
            target_taint_name=prop.target_taint_name,
            validations_json=json.dumps([v.to_dict() for v in prop.validations], ensure_ascii=False),
            actual_args_json=json.dumps(prop.actual_args or [], ensure_ascii=False),
            display_order=max(depth, 0) * 1000 + int(prop.call_line or 0),
        ))

    def _graph_bridge_edge_id(
        self,
        edge_kind: str,
        path_id: str,
        call_line: int,
        target_func_id: str,
        source_prop_id: str,
    ) -> str:
        key = f"{edge_kind}|{path_id}|{call_line}|{target_func_id}|{source_prop_id}"
        return f"bridge::{hashlib.sha1(key.encode()).hexdigest()[:24]}"

    def _record_bridge_edge(
        self,
        func: FunctionRecord,
        prop: PropagationRecord,
        tgt_func: FunctionRecord,
        ctx: PathContext,
        depth: int,
        *,
        edge_kind: str,
        tracker_type: str,
        bridge_edge_id: str,
        tracker_result: dict[str, Any] | None = None,
    ) -> None:
        graph_store = self._graph_store()
        if graph_store is None:
            return
        graph_store.upsert_task_graph_edge(TaskGraphEdgeRecord(
            edge_id=bridge_edge_id,
            task_id=getattr(self.cbs, "task_id", ""),
            epoch=getattr(self.cbs, "graph_epoch", "run"),
            source_node_id=self._graph_node_id(func),
            target_node_id=self._graph_node_id(tgt_func),
            source_func_id=func.func_id,
            target_func_id=tgt_func.func_id,
            source_function_resolved=func.name,
            target_function_resolved=tgt_func.name,
            target_function_raw=prop.target_function,
            source_file=func.file,
            target_file=tgt_func.file,
            edge_kind=edge_kind,
            status="scheduled",
            source_prop_id=prop.prop_id,
            call_line=prop.call_line or None,
            source_taint_name=prop.source_taint_name,
            target_taint_name=prop.target_taint_name,
            validations_json=json.dumps([v.to_dict() for v in prop.validations], ensure_ascii=False),
            actual_args_json=json.dumps(prop.actual_args or [], ensure_ascii=False),
            tracker_type=tracker_type,
            tracker_result_json=json.dumps(tracker_result or {}, ensure_ascii=False),
            display_order=max(depth, 0) * 1000 + int(prop.call_line or 0),
        ))
        graph_store.update_task_graph_edge(
            prop.prop_id,
            visible_in_tree=0,
            tracker_type=tracker_type,
            tracker_result_json=json.dumps(tracker_result or {}, ensure_ascii=False),
        )

    def _mark_path_step_scheduled(self, func: FunctionRecord, step: ChainStep, ctx: PathContext, depth: int) -> None:
        graph_store = self._graph_store()
        if graph_store is None:
            return
        edge_id = step.prop_id
        if edge_id.startswith("bridge::"):
            graph_store.update_task_graph_edge(
                edge_id,
                status="scheduled",
                target_node_id=self._graph_node_id(step.func),
                target_func_id=step.func.func_id,
                target_function_resolved=step.func.name,
                target_file=step.func.file,
            )
            return
        graph_store.update_task_graph_edge(
            edge_id,
            status="scheduled",
            target_node_id=self._graph_node_id(step.func),
            target_func_id=step.func.func_id,
            target_function_resolved=step.func.name,
            target_file=step.func.file,
        )

    def _prop_to_steps(self, p: PropagationRecord) -> list[ChainStep]:
        """callee 传播 → ChainStep 列表 (唯一命中或多候选 fan-out)。

        三级回退解析 callee 定义, 让 DFS 能跟入跨 TU 的 callee:
          1) target_func_id 直查 (最快)
          2) 按名+后缀(::method) 回查 (修 LLM 未填 func_id 但函数已索引)
          3) on-demand: find_func_in_source 在源码树定位定义文件 → ensure_file_indexed
             增量索引 → 再查 (修跨 TU 未索引, 根因 1)
        若回退层返回多个候选, 为避免漏跟, 每个候选都 fork 一条子链。
        仍找不到 → [] (真外部/libc, 如 recv/BIO_*)。
        """
        recs: list[FunctionRecord] = []
        if p.target_func_id:
            rec = self.store.get_function(p.target_func_id)
            if rec is not None:
                recs = [rec]
        if not recs and p.target_function:
            # 按名 (+ Class::method 后缀) 回查 — 覆盖 func_id 未填但已索引的情况
            recs = self.store.find_functions(p.target_function)
        if not recs and p.target_function:
            # on-demand: 在源码树定位 callee 定义文件并增量索引
            try:
                from .function_extractor import find_func_in_source, ensure_file_indexed
                src_root = getattr(self.cbs, "source_root", "") or getattr(self.cbs.cfg, "source_root", "")
                if src_root:
                    found = find_func_in_source(p.target_function, src_root)
                    if found:
                        for rel_file, _ in found:
                            ensure_file_indexed(src_root, rel_file, self.store)
                        recs = self.store.find_functions(p.target_function)
                        if recs:
                            self.cbs.on_event("v2_callee_indexed_ondemand",
                                              function=p.target_function,
                                              callee=p.target_function,
                                              indexed_file=found[0])
            except Exception as e:
                logger.warning("lazy import function_extractor / ensure indexed failed (target=%s): %s", getattr(p, "target_function", "?"), e)
        if not recs:
            return []
        unique_recs: list[FunctionRecord] = []
        seen: set[str] = set()
        for rec in recs:
            if rec.func_id in seen:
                continue
            seen.add(rec.func_id)
            unique_recs.append(rec)
        positions = _derive_positions(p.actual_args, p.target_taint_name, p.source_taint_name)
        tp = TaintParamInfo(positions=positions,
                            signature=p.target_taint_signature, names=[p.target_taint_name])
        return [
            ChainStep(rec, tp, list(p.validations), p.call_line, p.prop_id,
                      p.branch_group_id, p.branch_arm_id)
            for rec in unique_recs
        ]


def _derive_positions(actual_args: list[str], target_taint_name: str,
                      source_taint_name: str) -> list[int]:
    """由 clang 调用点实参表达式推导污点参数位置 (0-based)。

    匹配策略: 实参文本含 target_taint_name 或 source_taint_name 的位置即为污点参数。
    匹配不到时返回空 (下游按签名去重, 不依赖位置)。
    """
    if not actual_args:
        return []
    names = {n for n in (target_taint_name, source_taint_name) if n}
    out = [i for i, a in enumerate(actual_args) if any(n and n in a for n in names)]
    return out


# ── helpers ──────────────────────────────────────────────────────────────────

def _prop_backed_by_taint(prop: PropagationRecord, taint_set: set) -> bool:
    """propagation 的 source 是否有已确认污点支撑。

    callee 传播: source_taint 必须 ∈ taint_set (严格, 防 callee 返回值未确认就跟入)。
      但接受结构体前缀匹配: source="request" 匹配 taint="request->domain"
      (LLM 在 taint 识别时用字段级, 在 propagation 中可能用结构体级)。
    escape 传播 (is_external + escape_kind): 语义匹配, 接受 carrier 整体逃逸 /
      carrier->field 字段访问, 只要背后有已确认污点 (carrier 持有 taints[] 字段, 或
      field ∈ taint_set)。非 blind 放行 — 仍要求确认污点支撑, 只是匹配更准。
    """
    src = prop.source_taint_name
    if src in taint_set:
        return True
    # callee 传播: 结构体前缀匹配 (source="request" 匹配 taint="request->domain")
    if not (prop.is_external and prop.escape_kind):
        if src and len(src) >= 2:
            for t in taint_set:
                if t.startswith(src + "->") or t.startswith(src + "."):
                    return True
        return False
    carrier = prop.carrier
    # carrier 整体逃逸: src == carrier, carrier 是否持有已确认污点字段
    if carrier and src == carrier:
        for t in taint_set:
            if t.startswith(carrier + "->") or t.startswith(carrier + "."):
                return True
        return False
    # 字段访问路径: src == carrier->field / carrier.field, field 是否已确认污点
    if carrier and (src.startswith(carrier + "->") or src.startswith(carrier + ".")):
        field = src.rsplit("->", 1)[-1].rsplit(".", 1)[-1].strip("()")
        if field and len(field) >= 2 and field in taint_set:
            return True
    return False


def _path_id(func_id: str, taint_sig: str, depth: str) -> str:
    return hashlib.sha1(f"{func_id}\x1f{taint_sig}\x1f{depth}".encode()).hexdigest()[:16]


def _session_path(sessions_dir: Path, depth: int, func_name: str, taint_name: str,
                  kind: str = "taint") -> Path:
    """会话文件路径: d{depth}-{func}-{kind}-{taint}-{NN}.jsonl, NN 自增不撞名 (#10)。

    含污点名; 同 (深度,函数,污点) 的重分析取 -01/-02... 不覆盖, 便于回溯。
    """
    base = f"d{depth:02d}-{_safe_name(func_name)}-{kind}"
    if taint_name:
        base += f"-{_safe_name(taint_name)}"
    p = sessions_dir / f"{base}-00.jsonl"
    n = 0
    while p.exists():
        n += 1
        p = sessions_dir / f"{base}-{n:02d}.jsonl"
    return p


def _validation_sig(validations: list[Validation]) -> str:
    """前置校验签名: 规范化为 (left|op|right) token 集合。

    校验由 LLM 据代码行输出 (left=污点, op=运算符, right=代码字面量), 脚本核对后入链。
    同一校验逐轮稳定 (值来自代码字面量, 不再漂移)。非合规 (运算符非法/右值非字面量) 丢弃。
    """
    toks = sorted(set(t for t in (_canon_validation(v) for v in validations) if t))
    return "|".join(toks)


_VALID_OPS = {"==", "!=", "<=", ">=", "<", ">"}


def _canon_validation(v: Validation) -> str | None:
    """Validation -> (left|op|right) 规范 token; 非合规 (运算符非法/左值或右值非字面量) 丢弃。

    left/right 取代码标识符 token (允许 :: / . / -> / 下划线/数字), 丢弃中文/游离描述。
    nullptr/null 统一为 NULL。
    """
    op = (v.op or "").strip()
    if op not in _VALID_OPS:
        return None
    left = _norm_ident(v.left)
    right = _norm_ident(v.right)
    if not left or not right:
        return None
    return f"({left}|{op}|{right})"


_IDENT_RE = re.compile(r"^[A-Za-z_][\w:.<>\[\]*]*$")


def _norm_ident(s: str) -> str:
    """标识符 token 归一: 去首尾空白/括号, 校验为合法代码字面量 (宏/枚举/nullptr/数值/常量, 可带 :: . ->)。"""
    if s is None:
        return ""
    t = str(s).strip().strip("()")
    # 取第一个连续 token (遇空格/中文即截)
    m = re.match(r"[A-Za-z_][\w:.<>\[\]*]*", t)
    if m:
        t = m.group(0)
    elif re.match(r"^-?\d+(\.\d+)?$", t):
        pass  # 数值字面量
    else:
        return ""
    if not _IDENT_RE.match(t) and not re.match(r"^-?\d+(\.\d+)?$", t):
        return ""
    low = t.lower()
    if low in ("nullptr", "null"):
        return "NULL"
    return t


def _norm_taint_sig(name: str) -> str:
    """污点签名归一 (#13): 去隐式 this->/self-> 限定 + 尾部 (), 让 proxyBindAddr_ / this->proxyBindAddr_
    归一为同一污点 (方法上下文隐式 this), 供 find_processed_taint 去重命中, 终止 return_taint 循环。"""
    if not name:
        return ""
    t = str(name).strip()
    for prefix in ("this->", "this.", "self->", "self."):
        if t.startswith(prefix):
            t = t[len(prefix):]
            break
    t = t.rstrip("()")
    return t


def _dedup_validations(validations: list[Validation]) -> list[Validation]:
    seen: set[str] = set()
    out: list[Validation] = []
    for v in validations:
        k = _canon_validation(v) or f"{v.left}::{v.op}::{v.right}::{v.line}"
        if k not in seen:
            seen.add(k)
            out.append(v)
    return out


def _prop_source_taint(store: DataflowStore, prop: PropagationRecord) -> TaintRecord:
    """从传播记录反查源污点 (用于外部变量跟踪的上下文)。"""
    taints = store.list_taints_in_function(prop.source_func_id)
    for t in taints:
        if t.name == prop.source_taint_name:
            return t
    return TaintRecord(func_id=prop.source_func_id, name=prop.source_taint_name,
                       signature=prop.source_taint_signature)
