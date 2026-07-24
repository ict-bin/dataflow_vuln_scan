"""dagflow indirect tracker: 函数指针/回调间接调用解析真实函数。

设计: docs/design-taint-analysis.md §9.3 (间接 callee 边 sink_ref=指针表达式;
tracker 解析真实函数 F -> 回填 sink_ref=F + 入队 (F, taint))。
function_resolver(pointer_expr, func) -> [resolved_func_name]: 注入回调 (生产=LLM+注册点扫描, 测试=stub)。
"""
from __future__ import annotations
import logging
from typing import Callable, Any
from .dag_store import DagflowStore

logger = logging.getLogger("dvs.dagflow.indirect_tracker")


def resolve(store: DagflowStore, *, origin_func: str, origin_taint: str,
            origin_node: int, origin_edge: str,
            function_resolver: Callable[[str, str], list[str]] | None,
            func_lookup: Callable[[str], Any],
            on_enqueue: Callable[[str, str], None], on_event: Any = None) -> int:
    """处理 indirect_track 项: 解析指针表达式 -> 真实函数 -> 回填 sink_ref + 入队。

    返回解析出的真实函数数。resolver=None 或返回 [] -> 未解析 (间接边保持指针表达式)。
    """
    dag = store.load_dag(origin_func, origin_taint)
    if dag is None:
        return 0
    src_node = next((n for n in dag.nodes if n.id == origin_node), None)
    if src_node is None:
        return 0
    # 间接 callee 边: sink_ref 含 -> / ( / * (指针表达式)
    indirect_edges = [e for e in src_node.children
                      if e.kind == "callee" and e.sink_ref
                      and ("->" in e.sink_ref or e.sink_ref.startswith("(") or "*" in e.sink_ref)]
    n_resolved = 0
    for e in indirect_edges:
        resolved = function_resolver(e.sink_ref, origin_func) if function_resolver else []
        for fname in resolved:
            callee = func_lookup(fname)
            if callee is None:
                logger.debug("indirect resolved func not indexed: %s", fname)
                continue
            # 回填: 原边 sink_ref 改限定名 (原地) + 入队真实函数
            # 注: 多个真实函数时, 复制边各带一个 sink_ref (避免覆盖)
            if n_resolved == 0:
                e.sink_ref = fname  # 第一个原地改
            else:
                from .models import TaintEdge
                src_node.children.append(TaintEdge(
                    to_node=e.to_node, line=e.line, kind="callee", sink_ref=fname,
                    taints=list(e.taints),
                    param_taints=[{"param": "(callee 形参)", "taint": t} for t in e.taints]))
            for t in e.taints:
                on_enqueue(callee.func_id, t)
            n_resolved += 1
        if on_event:
            try:
                on_event("v2_dagflow_indirect_resolved", origin=origin_func[:10],
                          node=origin_node, expr=e.sink_ref, resolved=resolved)
            except Exception:
                logger.warning(
                    "indirect resolved event emit failed origin=%s node=%s",
                    origin_func,
                    origin_node,
                    exc_info=True,
                )
    if n_resolved:
        store.save_dag(dag)  # 回填 sink_ref
    return n_resolved
