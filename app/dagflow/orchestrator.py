"""dagflow 队列驱动 taint 跟踪编排器。

设计: docs/design-taint-analysis.md §9 (队列 BFS; (func,taint) 只分析一次; 已分析重放下游拼接)。
- 每项 (func, taint): reserve_or_skip -> analyze (产 DAG+填行号+存) 或 replay (加载已存 DAG)
  -> emit_followups (callee/return/escape/indirect 边 -> 队列项)
- escape/indirect tracker 项: P5 填充 (P4 先 stub: 记录不解析读者)
"""
from __future__ import annotations
import logging, threading
from typing import Callable, Any
from .models import TaintDAG, WorkItem
from .dag_store import DagflowStore
from .dedup import should_skip, reserve_or_skip, release_on_failure
from .work_queue import WorkQueue, run_workers

logger = logging.getLogger("dvs.dagflow.orchestrator")


class DagflowOrchestrator:
    """队列驱动 taint 跟踪。

    analyze_fn(func, taint_sig) -> TaintDAG: 产 DAG (含行号) 的回调 (生产=taint_analyzer+line_filler, 测试可注入假)。
    func_lookup(name) -> FunctionRecord|None: callee 名 -> FunctionRecord (复用 functions 索引)。
    """

    def __init__(self, *, store: DagflowStore, analyze_fn: Callable,
                 func_lookup: Callable[[str], Any], on_event: Any = None,
                 n_workers: int = 4, task_id: str = "",
                 cancel_event: threading.Event | None = None,
                 tracker_dispatcher: Any = None) -> None:
        self.store = store
        self.analyze_fn = analyze_fn
        self.func_lookup = func_lookup
        self.on_event = on_event
        self.n_workers = n_workers
        self.task_id = task_id
        self.cancel_event = cancel_event
        self.tracker_dispatcher = tracker_dispatcher  # P5: escape/indirect 调度
        self._wq: WorkQueue | None = None

    def run(self, root_func, root_taint: str) -> None:
        """从根 (func, taint) 起 BFS 跟踪, 至队列空 + idle。"""
        self._wq = WorkQueue()
        self._seed(root_func, root_taint)
        run_workers(self._wq, self._process, self.n_workers, self.cancel_event)
        if self.on_event:
            try:
                self.on_event("v2_dagflow_tracking_done", task_id=self.task_id,
                              stats=self._wq.stats, analyzed=len(self.store.list_analyzed()))
            except Exception:
                pass

    def _seed(self, func, taint: str) -> None:
        self._wq.put(WorkItem(kind="callee", target_func=func.func_id,
                              target_taint=taint, origin_func="(root)", origin_node=-1,
                              origin_edge="(seed)"))

    def _process(self, item: WorkItem) -> None:
        """消费一项: callee/return_taint -> analyze/replay + 发下游; escape/indirect -> stub。
        重放(已分析)不发下游 (首次分析已发+去重, 重放重发冗余刷屏)。"""
        if item.kind in ("escape_track", "indirect_track"):
            self._track_stub(item)
            return
        dag, is_fresh, fname = self._analyze_or_replay(item.target_func, item.target_taint, item.depth)
        if dag is not None and is_fresh:
            self._emit_followups(dag, caller_func_id=item.origin_func, depth=item.depth, func_name=fname)

    def _analyze_or_replay(self, func_id: str, taint: str, depth: int = 0) -> tuple[TaintDAG | None, bool, str]:
        """(func, taint): 未分析 -> analyze (产 DAG+存); 已分析 -> 加载已存 DAG (重放)。返回 (dag, is_fresh, func_name)。"""
        if should_skip(self.store, func_id, taint):
            return self.store.load_dag(func_id, taint), False, ""
        if not reserve_or_skip(self.store, func_id, taint):
            return None, False, ""
        # 本线程占位成功 -> analyze
        func = self.func_lookup_by_id(func_id)
        if func is None:
            logger.warning("func not found for func_id=%s, release reserve", func_id[:10])
            release_on_failure(self.store, func_id, taint)
            return None
        # 发标准 trace_start 事件 (dispatcher 卡死检测/前端进度都认这个)
        if self.on_event:
            try:
                self.on_event("trace_start", function=func.name, source_file=getattr(func, "file", ""),
                              depth=depth, max_depth=0, task_id=self.task_id)
            except Exception:
                pass
        try:
            dag = self.analyze_fn(func, taint, depth)
        except Exception as e:
            logger.exception("analyze failed func=%s taint=%s: %s", getattr(func, "name", "?"), taint, e)
            release_on_failure(self.store, func_id, taint)
            return None
        self.store.save_dag(dag)
        if self.on_event:
            try:
                self.on_event("v2_dagflow_dag_stored", function=func.name, taint=taint,
                              nodes=len(dag.nodes), self_contained=dag.self_contained,
                              task_id=self.task_id)
            except Exception:
                pass
        return dag, True, func.name

    def _emit_followups(self, dag: TaintDAG, caller_func_id: str = "", depth: int = 0,
                       func_name: str = "") -> None:
        """从 DAG 边发跟入项入队 (callee/return/escape/indirect)。 callee depth+1。
        return 边回传给 caller (caller_func_id, 非 dag 自己)。"""
        callees: list[str] = []
        for node in dag.nodes:
            for e in node.children:
                if e.kind == "callee":
                    self._emit_callee(dag, node, e, depth)
                    if e.sink_ref and not ("->" in e.sink_ref or e.sink_ref.startswith("(") or "*" in e.sink_ref):
                        callees.append(e.sink_ref)
                elif e.kind == "return":
                    self._emit_return(dag, node, e, caller_func_id, depth)
                elif e.kind in ("extern", "container"):
                    self._wq.put(WorkItem(kind="escape_track", origin_func=dag.func_id,
                                          origin_node=node.id, depth=depth,
                                          origin_edge=f"{node.id}->{e.to_node}"))
                # inside/source 不发跟入项
        # 发标准 trace_callees 事件 (dispatcher/前端认) — 仅首次分析发 (_process 已保证 is_fresh)
        if callees and self.on_event:
            try:
                self.on_event("trace_callees", function=func_name or dag.func_id, callees=callees, depth=depth, task_id=self.task_id)
            except Exception:
                pass

    def _emit_callee(self, dag, node, e, depth: int = 0) -> None:
        """callee 边 -> 每个被污形参拆一项 (D-2)。taint_sig=callee 形参名归一 (D-1)。
        校验 param 是 callee 真实形参 (据签名); 不匹配的跳过 (防 LLM 臆造形参名)。"""
        # sink_ref 可能是限定名/指针表达式 (间接); 间接 -> indirect_track
        if e.sink_ref and ("->" in e.sink_ref or e.sink_ref.startswith("(") or "*" in e.sink_ref):
            self._wq.put(WorkItem(kind="indirect_track", origin_func=dag.func_id,
                                  origin_node=node.id, depth=depth,
                                  origin_edge=f"{node.id}->{e.to_node}"))
            return
        callee = self.func_lookup(e.sink_ref)
        if callee is None:
            logger.debug("callee not indexed: %s (on-demand 待 P5)", e.sink_ref)
            return
        # 校验 callee 真实形参名 (从 signature 提取)
        real_params = _extract_params(getattr(callee, "signature", ""))
        for pt in e.param_taints:
            param = str(pt.get("param", "")).strip()
            if not param or param.startswith("("):
                continue  # 间接/未解析的形参跳过
            if real_params and param not in real_params:
                logger.warning("callee %s 形参 %r 不在签名 %r (LLM 臆造? 跳过该项)",
                               e.sink_ref, param, getattr(callee, "signature", "")[:60])
                continue
            self._wq.put(WorkItem(kind="callee", target_func=callee.func_id,
                                  target_taint=param, origin_func=dag.func_id,
                                  origin_node=node.id, depth=depth + 1,
                                  origin_edge=f"{node.id}->{e.to_node}"))

    def _emit_return(self, dag, node, e, caller_func_id: str = "", depth: int = 0) -> None:
        """return 边 -> 回传项 (caller_func_id, return_taint_sig)。
        caller = 触发本 (func,taint) 分析的调用方 (item.origin_func)。根/无 caller 跳过。"""
        if not caller_func_id or caller_func_id == "(root)":
            return  # 根无 caller, return 不回传
        for t in e.taints:
            self._wq.put(WorkItem(kind="return_taint", target_func=caller_func_id,
                                  target_taint=t, origin_func=dag.func_id,
                                  origin_node=node.id, depth=depth,
                                  origin_edge=f"{node.id}->{e.to_node}"))

    def _track_stub(self, item: WorkItem) -> None:
        """escape/indirect tracker 项 -> dispatcher 解析 (P5)。
        dispatcher 找读者/真实函数 -> 回填 DAG + 入队读者。无 dispatcher -> 记录。"""
        if self.tracker_dispatcher is None:
            if self.on_event:
                try:
                    self.on_event("v2_dagflow_track_pending", kind=item.kind,
                                  origin=item.origin_func, edge=item.origin_edge, task_id=self.task_id)
                except Exception:
                    pass
            return
        # origin_taint: 从 item 无直接给 (item 只有 origin_func/node/edge); 需查 origin DAG 的 taint_signature
        origin_taint = self._origin_taint(item.origin_func, item.origin_node)
        if origin_taint is None:
            return
        if item.kind == "escape_track":
            self.tracker_dispatcher.handle_escape(
                origin_func=item.origin_func, origin_taint=origin_taint,
                origin_node=item.origin_node, origin_edge=item.origin_edge)
        elif item.kind == "indirect_track":
            self.tracker_dispatcher.handle_indirect(
                origin_func=item.origin_func, origin_taint=origin_taint,
                origin_node=item.origin_node, origin_edge=item.origin_edge)

    def _origin_taint(self, origin_func: str, origin_node: int) -> str | None:
        """查 origin DAG 的 taint_signature (escape/indirect 项没带 taint, 从 DAG 节点查)。"""
        # dagflow 一个 func 可有多个 taint DAG; 逐个找含 origin_node 的
        for fid, ts in self.store.list_analyzed():
            if fid == origin_func:
                dag = self.store.load_dag(fid, ts)
                if dag and any(n.id == origin_node for n in dag.nodes):
                    return ts
        return None

    def func_lookup_by_id(self, func_id: str):
        """func_id -> FunctionRecord (复用 functions 索引)。dagflow 无独立 func 表, 查 V2 functions.db。"""
        # 由注入的 func_lookup 提供 (生产: 查 functions.db by func_id)
        lookup = getattr(self, "_func_lookup_by_id", None)
        if lookup is not None:
            return lookup(func_id)
        return None


def _extract_params(signature: str) -> list[str]:
    """从 C/C++ 函数签名提取形参名 (校验 callee param_taints 用)。

    e.g. 'void f(int a, char* b, struct s* c)' -> ['a','b','c']。
    无参数声明 (void f(void)) -> []。失败 -> [] (不阻塞)。"""
    import re
    if not signature:
        return []
    # 取第一个 ( ... ) 内的参数列表
    m = re.search(r"\(([^)]*)\)", signature)
    if not m:
        return []
    plist = m.group(1).strip()
    if not plist or plist == "void":
        return []
    out: list[str] = []
    for part in plist.split(","):
        part = part.strip()
        if not part or part == "void" or part == "...":
            continue
        # 形参名是末尾标识符 (去 [] / * / & / 默认值)
        part = re.sub(r"=.*$", "", part).strip()  # 去默认值
        part = re.sub(r"\[[^\]]*\]", "", part).strip()  # 去数组
        mm = re.search(r"([A-Za-z_]\w*)\s*$", part)  # 末尾标识符
        if mm:
            out.append(mm.group(1))
    return out
