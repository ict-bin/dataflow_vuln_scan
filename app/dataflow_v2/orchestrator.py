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
import threading
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .models import (
    FunctionRecord, OrchestrationEdge, ProcessedTaint, PropagationRecord,
    TaintParamInfo, TaintRecord, Validation,
)
from .store import DataflowStore


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


class PathContext:
    """一条 DFS 路径的累积上下文 (前置校验链 + 已走边)。"""

    def __init__(self, path_id: str) -> None:
        self.path_id = path_id
        self.pre_validations: list[Validation] = []   # 从根到当前的前置校验链
        self.edges: list[OrchestrationEdge] = []
        self.depth: int = 0

    def validation_signature(self) -> str:
        return "|".join(f"{v.condition}::{v.content}" for v in self.pre_validations)

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
                                     taint: TaintRecord, ctx: PathContext) -> list[tuple[FunctionRecord, TaintParamInfo]]:
        """taint 传播到外部变量 (如 g_msg=msg) 时, 跟踪 LLM 查找跟入函数。

        返回 [(目标函数, 该路径上的污点参数信息)] 用于分叉路径。TODO: 接入。
        """
        return []

    def mine_vulns(self, store: DataflowStore, func: FunctionRecord,
                   taint_params: TaintParamInfo, ctx: PathContext) -> int:
        """fork 漏洞挖掘会话; 返回 finding 数。TODO: 接入 vuln_workflow fork。"""
        return 0


class DfsOrchestrator:
    """深度优先编排器。线程安全队列驱动 (与现有 orchestrator 同风格: 线程+queue)。"""

    def __init__(self, store: DataflowStore, cbs: AnalysisCallbacks,
                 n_workers: int = 4) -> None:
        self.store = store
        self.cbs = cbs
        self.n_workers = n_workers
        self._queue: deque[tuple[FunctionRecord, TaintParamInfo, PathContext, str]] = deque()
        self._lock = threading.Lock()
        # 待 vuln mining 的函数: 等其全部子路径完成后再挖
        # key=(func_id, taint_sig, pre_val_sig) -> remaining 子任务计数
        self._pending_mine: dict[str, dict] = {}

    def run(self, root_func: FunctionRecord, root_taint: TaintParamInfo,
            base_session: str = "") -> None:
        """从根函数出发 DFS。"""
        ctx = PathContext(path_id=_path_id(root_func.func_id, root_taint.signature, "0"))
        self._enqueue(root_func, root_taint, ctx, base_session)
        # 简化: 单线程驱动骨架; TODO: 线程池并发
        self._drain_sync()

    # ── 核心: 处理一个函数 ──────────────────────────────────────────────────
    def _process(self, func: FunctionRecord, taint_params: TaintParamInfo,
                 ctx: PathContext, base_session: str) -> None:
        # 1) 三重去重
        if self.store.find_processed_taint(func.func_id, taint_params.signature,
                                           ctx.validation_signature()):
            return  # 已分析过, 跳过

        # 2) LLM 污点分析 (fork 会话)
        result = self.cbs.analyze_function(
            self.store, func, taint_params, ctx.pre_validations, base_session, ctx)
        for t in result.taints:
            self.store.upsert_taint(t)
        for p in result.propagations:
            self.store.upsert_propagation(p)
        if result.description:
            func.description = result.description
            self.store.upsert_function(func)
        self_contained = result.self_contained

        # 3) 记录 processed_taint (去重锚点)
        self.store.add_processed_taint(func.func_id, ProcessedTaint(
            taint_params=taint_params.names, taint_signature=taint_params.signature,
            pre_validations=[v.to_dict() for v in ctx.pre_validations],
            pre_validation_signature=ctx.validation_signature(),
            sessions_path=base_session))

        # 4) 展开 propagations → 子路径
        child_edges: list[tuple[FunctionRecord, TaintParamInfo, list[Validation]]] = []
        for prop in result.propagations:
            # 传播过程校验累积进子路径的前置校验链
            child_vals = list(prop.validations)
            if not prop.target_func_id:
                # 传播到外部变量 → 跟踪 LLM 找跟入函数 (分叉)
                ext = self.cbs.resolve_external_propagation(
                    self.store, func, _prop_source_taint(self.store, prop), ctx)
                for tgt_func, tp in ext:
                    child_edges.append((tgt_func, tp, child_vals))
            else:
                tgt = self.store.get_function(prop.target_func_id)
                if tgt is not None:
                    tp = TaintParamInfo(
                        positions=[0],  # TODO: 由 propagation.target_taint_signature 推位置
                        signature=prop.target_taint_signature,
                        names=[prop.target_taint_name])
                    child_edges.append((tgt, tp, child_vals))

        # 5) 入队子函数 (DFS, 每个互斥 arm 分叉独立 path_id)
        for tgt, tp, vals in child_edges:
            sub_ctx = ctx.fork(_path_id(tgt.func_id, tp.signature, str(ctx.depth + 1)))
            sub_ctx.pre_validations.extend(vals)
            sub_ctx.depth = ctx.depth + 1
            # 编排库记录边
            self.store.upsert_edge(OrchestrationEdge(
                path_id=sub_ctx.path_id, source_function=func.name,
                source_signature=func.signature, source_func_id=func.func_id,
                target_function=tgt.name, target_signature=tgt.signature,
                target_func_id=tgt.func_id, taint_params=tp,
                depth=sub_ctx.depth, edge_order=len(sub_ctx.edges), status="pending"))
            sub_ctx.edges = list(ctx.edges)
            self._enqueue(tgt, tp, sub_ctx, base_session)

        # 6) 漏洞挖掘时机 (设计点 #2: LLM 判自洽):
        #    self_contained=True        → 立即挖 (不论是否有子路径)
        #    self_contained=False 且有子 → 后序 (等全部子路径完成)
        #    self_contained=False 无子  → 无下游可等, 立即挖
        if self_contained or not child_edges:
            self.cbs.mine_vulns(self.store, func, taint_params, ctx)
        else:
            self._register_pending_mine(func, taint_params, ctx, len(child_edges))

    # ── pending mining 计数 ─────────────────────────────────────────────────
    def _register_pending_mine(self, func: FunctionRecord, tp: TaintParamInfo,
                               ctx: PathContext, n_children: int) -> None:
        key = _mine_key(func.func_id, tp.signature, ctx.validation_signature())
        with self._lock:
            self._pending_mine[key] = {
                "func": func, "taint_params": tp, "ctx": ctx, "remaining": n_children,
            }

    def _on_child_done(self, parent_key: str) -> None:
        """子任务完成时调用; remaining 归零后触发父函数 vuln mining。"""
        with self._lock:
            entry = self._pending_mine.get(parent_key)
            if entry is None:
                return
            entry["remaining"] -= 1
            if entry["remaining"] <= 0:
                self._pending_mine.pop(parent_key, None)
            else:
                return
        # 全部子路径完成 → 后序挖掘
        self.cbs.mine_vulns(self.store, entry["func"], entry["taint_params"], entry["ctx"])

    # ── 队列 ────────────────────────────────────────────────────────────────
    def _enqueue(self, func: FunctionRecord, tp: TaintParamInfo,
                 ctx: PathContext, base_session: str) -> None:
        with self._lock:
            self._queue.append((func, tp, ctx, base_session))

    def _drain_sync(self) -> None:
        """同步排空队列 (骨架用; TODO: 改线程池)。"""
        while True:
            with self._lock:
                if not self._queue:
                    break
                func, tp, ctx, sess = self._queue.popleft()
            self._process(func, tp, ctx, sess)
            # TODO: 子任务完成回调 _on_child_done (需记录 parent_key)


# ── helpers ──────────────────────────────────────────────────────────────────
def _path_id(func_id: str, taint_sig: str, depth: str) -> str:
    return hashlib.sha1(f"{func_id}\x1f{taint_sig}\x1f{depth}".encode()).hexdigest()[:16]


def _mine_key(func_id: str, taint_sig: str, pre_val_sig: str) -> str:
    return hashlib.sha1(f"{func_id}\x1f{taint_sig}\x1f{pre_val_sig}".encode()).hexdigest()[:16]


def _prop_source_taint(store: DataflowStore, prop: PropagationRecord) -> TaintRecord:
    """从传播记录反查源污点 (用于外部变量跟踪的上下文)。"""
    taints = store.list_taints_in_function(prop.source_func_id)
    for t in taints:
        if t.name == prop.source_taint_name:
            return t
    return TaintRecord(func_id=prop.source_func_id, name=prop.source_taint_name,
                       signature=prop.source_taint_signature)
