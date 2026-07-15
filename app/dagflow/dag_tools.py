"""dagflow DAG 查询工具 (mining 建链用, 也可作 LLM agent 工具)。

设计: docs/design-vuln-mining.md §2 (dag_get/callee_effect/walk_children/get_func_source/dag_callers)。
"""
from __future__ import annotations
import logging
from typing import Any
from .dag_store import DagflowStore
from .models import TaintDAG

logger = logging.getLogger("dvs.dagflow.dag_tools")


def get_dag(store: DagflowStore, func_id: str, taint_sig: str) -> TaintDAG | None:
    return store.load_dag(func_id, taint_sig)


def get_func_source(source_root: str, func, max_lines: int = 500) -> str:
    """取函数完整源码 (D1 逐行核)。复用 function_extractor.read_function_body。"""
    from ..dataflow_v2.function_extractor import read_function_body
    return read_function_body(source_root, func, max_lines=max_lines)


def get_callers(store: DagflowStore, func_id: str) -> list[tuple[str, str]]:
    """反查谁有 callee 边指向本 func (跨函数反向, D2 用)。"""
    return store.get_callers(func_id)


def callee_effect(store: DagflowStore, callee_fid: str, callee_taint: str,
                  taint_of_interest: str) -> dict:
    """读 callee DAG, 取其对污点的效应摘要 (建链用)。

    返回 {effect: sanitized|return|propagate|unchanged|unknown, detail, downstream: [(func,taint)]}。
    - sanitized: callee DAG 有 prune=sanitized on taint -> 污点被清洗
    - return: callee 有 return 边带该污点 -> 回传
    - propagate: callee 有 callee 边继续传播
    - unchanged: 无 sanitizer 无派生, 透传
    - unknown: callee 未分析
    """
    dag = store.load_dag(callee_fid, callee_taint)
    if dag is None:
        return {"effect": "unknown", "detail": "callee 未分析", "downstream": []}
    # 找 taint_of_interest 相关节点
    sanitized = False
    returns: list[str] = []
    downstream: list[tuple[str, str]] = []
    for n in dag.nodes:
        if n.prune and n.prune.reason == "sanitized" and n.taint == taint_of_interest:
            sanitized = True
        for e in n.children:
            if e.kind == "return" and taint_of_interest in e.taints:
                returns.extend(e.taints)
            if e.kind == "callee":
                for pt in e.param_taints:
                    p = str(pt.get("param", ""))
                    if p and not p.startswith("("):
                        downstream.append((e.sink_ref, p))
    if sanitized:
        return {"effect": "sanitized", "detail": f"callee {callee_fid[:8]} 清洗了 {taint_of_interest}", "downstream": []}
    if returns:
        return {"effect": "return", "detail": f"callee 返回 {returns}", "downstream": []}
    if downstream:
        return {"effect": "propagate", "detail": f"callee 继续传播给 {downstream[:3]}", "downstream": downstream}
    return {"effect": "unchanged", "detail": "callee 透传, 无清洗/派生", "downstream": []}


def list_sink_candidates(dag: TaintDAG) -> list[dict]:
    """本 DAG 的潜在 sink 节点/边 (callee-danger/extern/container/return)。"""
    out = []
    for n in dag.nodes:
        for e in n.children:
            if e.kind in ("callee", "extern", "container", "return"):
                out.append({"node": n.id, "edge_kind": e.kind, "sink_ref": e.sink_ref,
                            "line": e.line, "taints": e.taints,
                            "escape_subkind": e.escape_subkind, "carrier": e.carrier})
    return out
