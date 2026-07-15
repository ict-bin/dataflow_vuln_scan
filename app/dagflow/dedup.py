"""dagflow 去重 facade (双检锁: reserve-before-analyze)。

设计: docs/design-taint-analysis.md §4 (func_id, taint_signature) 去重; §9.2 (分析一次 + 重放)。
(func_id, taint_signature) 只 analyze 一次; 已分析则从已存 DAG 重放下游 (不重分析)。
"""
from __future__ import annotations
from .dag_store import DagflowStore


def should_skip(store: DagflowStore, func_id: str, taint_signature: str) -> bool:
    """已分析过? (find 命中 -> 调用方走重放拼接, 不重 analyze)。"""
    return store.find_processed_taint(func_id, taint_signature)


def reserve_or_skip(store: DagflowStore, func_id: str, taint_signature: str) -> bool:
    """双检锁: try_reserve 占位。
    返回 True=本线程占位成功, 继续 analyze; False=并发 peer 已占或已分析, 跳过。
    find 先查 (已分析 -> 跳过); 未分析 -> try_reserve (并发 -> 跳过)。
    """
    if store.find_processed_taint(func_id, taint_signature):
        return False  # 已分析, 走重放
    return store.try_reserve(func_id, taint_signature)


def release_on_failure(store: DagflowStore, func_id: str, taint_signature: str) -> None:
    """analyze 失败时删占位, 让后续可重试。"""
    store.delete_processed_taint(func_id, taint_signature)
