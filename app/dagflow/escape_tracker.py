"""dagflow escape tracker: extern/container 边经中继点接回传播路径。

设计: docs/design-taint-analysis.md §9.3 + GAP-6 (extern/container 边目标=中继点;
tracker 找读者 R -> 从中继点出 callee 边接回 + 入队 (R, taint))。
reader_finder(escape_info) -> [reader_func_name]: 注入回调 (生产=LLM+v2_db, 测试=stub)。
"""
from __future__ import annotations
import logging
from typing import Callable, Any
from .models import TaintEdge
from .dag_store import DagflowStore

logger = logging.getLogger("dvs.dagflow.escape_tracker")


def resolve(store: DagflowStore, *, origin_func: str, origin_taint: str,
            origin_node: int, origin_edge: str,
            reader_finder: Callable[[dict], list[str]] | None,
            func_lookup: Callable[[str], Any],
            on_enqueue: Callable[[str, str], None], on_event: Any = None) -> int:
    """处理 escape_track 项: 找读者 -> relay 插入 callee 边 + 入队。

    返回接入的读者数。reader_finder=None 或返回 [] -> 无读者 (中继点孤立, 待后续)。
    """
    dag = store.load_dag(origin_func, origin_taint)
    if dag is None:
        logger.warning("escape: origin DAG not found %s/%s", origin_func[:10], origin_taint)
        return 0
    # 找 escape 边 (from_node=origin_node, edge 引用含 origin_edge)
    src_node = next((n for n in dag.nodes if n.id == origin_node), None)
    if src_node is None:
        return 0
    esc_edges = [e for e in src_node.children if e.kind in ("extern", "container")]
    # 解析源函数信息 (供 reader_finder 内嵌 prompt, 不用 LLM 查 hash)
    src_func = func_lookup(origin_func) if func_lookup else None
    src_func_name = getattr(src_func, "name", origin_func) if src_func else origin_func
    src_func_file = getattr(src_func, "file", "") if src_func else ""
    src_start = getattr(src_func, "start_line", 0) if src_func else 0
    src_end = getattr(src_func, "end_line", 0) if src_func else 0
    n_readers = 0
    for e in esc_edges:
        info = {"escape_subkind": e.escape_subkind, "carrier": e.carrier,
                "escape_via": e.escape_via, "sink_ref": e.sink_ref,
                "taints": e.taints, "func": origin_func,
                "func_name": src_func_name, "func_file": src_func_file,
                "func_start_line": src_start, "func_end_line": src_end}
        readers = reader_finder(info) if reader_finder else []
        for r_name in readers:
            callee = func_lookup(r_name)
            if callee is None:
                logger.debug("escape reader not indexed: %s", r_name)
                continue
            # relay 插入: 从 src_node (中继点) 出一条 callee 边到 reader
            relay_edge = TaintEdge(
                to_node=-1, line=e.line, kind="callee", sink_ref=r_name,
                taints=list(e.taints),
                param_taints=[{"param": "(reader 形参)", "taint": t} for t in e.taints])
            src_node.children.append(relay_edge)
            for t in e.taints:
                on_enqueue(callee.func_id, t)
            n_readers += 1
        if on_event:
            try:
                on_event("v2_dagflow_escape_resolved", origin=origin_func[:10],
                         node=origin_node, readers=readers, taints=e.taints)
            except Exception:
                pass
    if n_readers:
        store.save_dag(dag)  # relay 边回填图
    return n_readers
