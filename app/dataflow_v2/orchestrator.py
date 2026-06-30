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
        """fork 漏洞挖掘会话; 返回 finding 数。TODO: 由回调实现接入。"""
        return 0


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
                 max_concurrent_llm: int = 8, max_depth: int = 10) -> None:
        self.store = store
        self.cbs = cbs
        self.n_workers = n_workers
        self.concurrent = concurrent
        self.max_depth = max_depth
        self._llm_sem = threading.Semaphore(max_concurrent_llm) if concurrent else None

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

    def run(self, root_func: FunctionRecord, root_taint: TaintParamInfo,
            base_session: str = "") -> None:
        """从根函数出发 DFS。"""
        ctx = PathContext(path_id=_path_id(root_func.func_id, root_taint.signature, "0"))
        self._process(root_func, root_taint, ctx.pre_validations, base_session, ctx, 0)

    # ── 核心: 处理一个函数 (返回本函数发现的校验, 供父链回传) ────────────────
    def _process(self, func: FunctionRecord, taint_params: TaintParamInfo,
                 pre_validations: list[Validation], base_session: str,
                 ctx: PathContext, depth: int) -> list[Validation]:
        # 1) 三重去重
        pre_val_sig = _validation_sig(pre_validations)
        if self.store.find_processed_taint(func.func_id, taint_params.signature, pre_val_sig):
            return []  # 已分析过, 跳过 (无新增校验回传)

        # 2) LLM 污点分析 (fork 会话)
        ctx.depth = depth
        result = self._run_llm(
            self.cbs.analyze_function, self.store, func, taint_params, pre_validations, base_session, ctx)
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
            pre_validations=[v.to_dict() for v in pre_validations],
            pre_validation_signature=pre_val_sig, sessions_path=base_session))

        # 本函数发现的校验 (回传给父链)
        my_discovered = _dedup_validations(
            [v for p in result.propagations for v in p.validations])

        # 4) self_contained=True → 立即挖 (设计点 #2)
        if self_contained:
            self._run_llm(self.cbs.mine_vulns, self.store, func, taint_params, ctx)

        # 5) 构造有序路径 (互斥分叉 + 外部变量分叉); 达深度上限则当叶子 (不递归)
        if depth < self.max_depth:
            paths = self._build_paths(result.propagations, func, ctx, depth)
        else:
            paths = []

        # 6) 逐条链 DFS: 链内顺序, 校验链累加 + 回传; fork 后多链可并发
        base_accumulated = list(pre_validations) + list(my_discovered)
        if self.concurrent and len(paths) > 1:
            threads: list[threading.Thread] = []
            errs: list[BaseException] = []
            for path_steps in paths:
                t = threading.Thread(target=self._run_path, daemon=True,
                                     args=(path_steps, base_accumulated, func, base_session, ctx, depth, errs),
                                     name=f"dvs2-path-{func.name}-{len(threads)}")
                threads.append(t); t.start()
            for t in threads:
                t.join()
            if errs:
                raise errs[0]
        else:
            for path_steps in paths:
                self._run_path(path_steps, base_accumulated, func, base_session, ctx, depth, None)

        # 7) self_contained=False → 全部子链完成后挖 (后序)
        if not self_contained:
            self._run_llm(self.cbs.mine_vulns, self.store, func, taint_params, ctx)

        return my_discovered

    def _run_path(self, steps: list[ChainStep], base_accumulated: list[Validation],
                  func: FunctionRecord, base_session: str, ctx: PathContext,
                  depth: int, errs: list[BaseException] | None) -> None:
        """运行一条有序链: 链内严格顺序, 校验链累加 + 子回传。"""
        try:
            accumulated = list(base_accumulated)
            for step in steps:
                incoming = list(accumulated) + list(step.validations)
                self.store.upsert_edge(OrchestrationEdge(
                    path_id=ctx.path_id, source_function=func.name,
                    source_signature=func.signature, source_func_id=func.func_id,
                    target_function=step.func.name, target_signature=step.func.signature,
                    target_func_id=step.func.func_id, taint_params=step.taint_params,
                    depth=depth + 1, edge_order=step.call_line, status="done"))
                sub_ctx = ctx.fork(_path_id(step.func.func_id, step.taint_params.signature, str(depth + 1)))
                sub_ctx.pre_validations = list(incoming)
                child_fb = self._process(step.func, step.taint_params, incoming,
                                         base_session, sub_ctx, depth + 1)
                accumulated.extend(child_fb)   # 校验链回传: 下一步 callee 可见
        except BaseException as exc:
            if errs is not None:
                errs.append(exc)
            else:
                raise

    # ── 路径构造: 有序链 + 互斥分叉 + 外部分叉 ───────────────────────────────
    def _build_paths(self, props: list[PropagationRecord], func: FunctionRecord,
                     ctx: PathContext, depth: int) -> list[list[ChainStep]]:
        if not props:
            return []
        props_sorted = sorted(props, key=lambda p: p.call_line)
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
                        steps = [s for s in (self._prop_to_step(ap) for ap in arm_props) if s]
                        if steps:
                            new_paths.append(base + steps)
                if new_paths:
                    paths = new_paths
            elif p.is_external:
                # 外部变量传播 → 跟踪 LLM 找跟入函数, 每个跟入 fork 一条子链
                targets = self._run_llm(
                    self.cbs.resolve_external_propagation, self.store, func, _prop_source_taint(self.store, p), ctx)
                if not targets:
                    continue  # TODO stub 未接: 不 fork
                new_paths = []
                for base in paths:
                    for tgt_func, tp in targets:
                        new_paths.append(base + [ChainStep(tgt_func, tp, list(p.validations),
                                                           p.call_line, p.prop_id)])
                paths = new_paths
            else:
                step = self._prop_to_step(p)
                if step is None:
                    continue  # callee 解析失败, 跳过
                for path in paths:
                    path.append(step)
        return [p for p in paths if p]  # 剔除空链

    def _prop_to_step(self, p: PropagationRecord) -> ChainStep | None:
        """callee 传播 → ChainStep (解析 target_func_id 拿 FunctionRecord, 由 actual_args 位置)。"""
        if not p.target_func_id:
            return None
        rec = self.store.get_function(p.target_func_id)
        if rec is None:
            return None
        positions = _derive_positions(p.actual_args, p.target_taint_name, p.source_taint_name)
        tp = TaintParamInfo(positions=positions,
                            signature=p.target_taint_signature, names=[p.target_taint_name])
        return ChainStep(rec, tp, list(p.validations), p.call_line, p.prop_id,
                         p.branch_group_id, p.branch_arm_id)


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
def _path_id(func_id: str, taint_sig: str, depth: str) -> str:
    return hashlib.sha1(f"{func_id}\x1f{taint_sig}\x1f{depth}".encode()).hexdigest()[:16]


def _validation_sig(validations: list[Validation]) -> str:
    return "|".join(f"{v.condition}::{v.content}" for v in validations)


def _dedup_validations(validations: list[Validation]) -> list[Validation]:
    seen: set[str] = set()
    out: list[Validation] = []
    for v in validations:
        k = f"{v.condition}::{v.content}"
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
