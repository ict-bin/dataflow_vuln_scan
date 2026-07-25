"""dagflow 正向建链: 从入口按 call_line 顺序拼 callee 效应。

设计: docs/design-vuln-mining.md §1.2 (正向从入口建数据流链, 按序读 callee 效应重建污点状态)。
解决顺序依赖: check(unpack)(handler) 的效应按序拼, msg 在 handler 处状态由前序决定。
"""
from __future__ import annotations
import logging
from typing import Any
from .dag_store import DagflowStore
from .models import TaintDAG
from . import dag_tools

logger = logging.getLogger("dvs.dagflow.chain_builder")


def build_chain(store: DagflowStore, dag: TaintDAG, source_root: str,
                func_lookup: Any) -> list[dict]:
    """从 dag 入口正向建链 (按 call_line 顺序)。

    返回链步骤列表:
      [{step, type: source|inside|callee, line, taint, taint_state,
        callee?: name, effect?: sanitized|return|propagate|unchanged|unknown, detail?}]
    taint_state: tainted|clean (按前序 callee 效应更新)。
    """
    chain: list[dict] = []
    if not dag.nodes:
        return chain
    # 收集所有节点的 checks (跨 taint 可见: 挖掘时任何 check 都可能保护 sink)
    all_checks: list[dict] = []
    for n in dag.nodes:
        if n.checks:
            all_checks.extend(n.checks)
    # 入口节点 (parents 空 或 is_source)
    entry = next((n for n in dag.nodes if not n.parents or n.is_source), dag.nodes[0])
    state = "tainted"
    chain.append({"step": 0, "type": "entry", "node": entry.id, "line": entry.line,
                  "taint": entry.taint, "taint_state": state,
                  "is_source": entry.is_source,
                  "checks": list(entry.checks),
                  "all_checks_in_func": all_checks})
    # 按 call_line 顺序遍历边 (BFS-ish, 简化: 按 edge.line 排序)
    edges_sorted = sorted(
        [(n, e) for n in dag.nodes for e in n.children],
        key=lambda ne: ne[1].line or 0)
    step = 1
    for n, e in edges_sorted:
        if e.kind == "inside":
            # 收集目标节点的 checks (路径上的 sanitizer)
            target_node = next((nd for nd in dag.nodes if nd.id == e.to_node), None)
            target_checks = list(target_node.checks) if target_node else []
            chain.append({"step": step, "type": "inside", "from": n.id, "line": e.line,
                          "taint": e.taints, "taint_state": state,
                          "checks": target_checks,
                          "condition": list(e.condition)})
        elif e.kind == "callee":
            # 读 callee 效应 (按 callee 形参 taint 查, 非 caller taint)
            callee_func = func_lookup(e.sink_ref) if not _is_indirect(e.sink_ref) else None
            effect = {"effect": "unknown", "detail": f"间接/未索引 callee {e.sink_ref}", "downstream": []}
            callee_file = ""
            if callee_func is not None and e.param_taints:
                callee_file = getattr(callee_func, 'file', '')
                param = str(e.param_taints[0].get("param", ""))
                if param and not param.startswith("("):
                    # taint_of_interest = callee 形参 (callee DAG 用形参 taint, 非 caller taint)
                    effect = dag_tools.callee_effect(store, callee_func.func_id, param, param)
            if effect["effect"] == "sanitized":
                state = "clean"
            chain.append({"step": step, "type": "callee", "from": n.id, "line": e.line,
                          "callee": e.sink_ref, "callee_file": callee_file,
                          "taint": e.taints, "taint_state": state,
                          "effect": effect["effect"], "detail": effect["detail"],
                          "downstream": effect.get("downstream", []),
                          "is_indirect": _is_indirect(e.sink_ref),
                          "condition": list(e.condition),
                          "param_taints": list(e.param_taints)})
        elif e.kind in ("extern", "container"):
            chain.append({"step": step, "type": "escape", "from": n.id, "line": e.line,
                          "escape_subkind": e.escape_subkind, "carrier": e.carrier,
                          "escape_via": e.escape_via, "sink_ref": e.sink_ref,
                          "taint": e.taints, "taint_state": state})
        elif e.kind == "return":
            chain.append({"step": step, "type": "return", "from": n.id, "line": e.line,
                          "taint": e.taints, "taint_state": state})
        elif e.kind == "source":
            chain.append({"step": step, "type": "source", "to": e.to_node, "line": e.line,
                          "source_callee": e.sink_ref, "taint": e.taints, "taint_state": "tainted"})
            state = "tainted"
        step += 1
    return chain


def _is_indirect(sink_ref: str) -> bool:
    """间接调用: sink_ref 含 -> / ( / * (指针表达式)。"""
    return bool(sink_ref) and ("->" in sink_ref or sink_ref.startswith("(") or "*" in sink_ref)
