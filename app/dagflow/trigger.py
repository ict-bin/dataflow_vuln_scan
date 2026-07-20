"""dagflow 挖掘触发: 按函数灵活 (无传出点或所有传出点 taint DAG 就绪即挖)。

设计: docs/vuln-mining.md §1.1 (per-function join on 直接传出点)。
"""
from __future__ import annotations
import json, logging
from .dag_store import DagflowStore

logger = logging.getLogger("dvs.dagflow.trigger")


def is_ready(store: DagflowStore, func_id: str, taint_sig: str,
             func_lookup) -> bool:
    """本 (func, taint) 可挖? 无传出点 或 所有传出 callee 目标均已分析。

    传出点 = callee 边 (sink_ref 限定名) 的目标 func; extern/container/return 是本函数 sink (不外跟)。
    间接 callee (sink_ref 指针) 不算 (待 indirect tracker)。
    """
    outs = store.list_dag_outgoing(func_id, taint_sig)
    callee_edges = [e for e in outs if e["kind"] == "callee"
                    and not _is_indirect(e.get("sink_ref", ""))]
    if not callee_edges:
        logger.info("[trigger] READY (no outgoing callee): func=%s taint=%s", func_id[:12], taint_sig)
        return True  # 无传出 callee -> 可挖 (叶子或 self_contained)
    for e in callee_edges:
        sink = e.get("sink_ref", "")
        callee = func_lookup(sink)
        if callee is None:
            logger.info("[trigger] skip unindexed callee: sink=%s", sink)
            continue  # 未索引 (外部库) -> 不阻塞
        # 取 callee 形参 taint (按 param_taints), 查是否已分析
        pt_json = e.get("param_taints_json") or e.get("param_taints") or "[]"
        params = json.loads(pt_json)
        for pt in params:
            param = str(pt.get("param", ""))
            if param and not param.startswith("("):
                if not store.find_processed_taint(callee.func_id, param):
                    logger.info("[trigger] NOT READY: func=%s taint=%s callee=%s param=%s not analyzed",
                                func_id[:12], taint_sig, sink, param)
                    return False  # 某传出 callee 未分析 -> 未就绪
    logger.info("[trigger] READY (all callees analyzed): func=%s taint=%s", func_id[:12], taint_sig)
    return True


def _is_indirect(sink_ref: str) -> bool:
    return bool(sink_ref) and ("->" in sink_ref or sink_ref.startswith("(") or "*" in sink_ref)
