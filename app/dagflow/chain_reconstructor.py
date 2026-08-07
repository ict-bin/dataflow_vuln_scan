"""Phase 1: 从有向图还原完整跨函数调用链 (纯脚本遍历, 无 LLM)。

DAG 图本身就有路径: A 的 callee 边 → B, B 的 callee 边 → C, ...
本类沿 callee 边递归加载 DAG, 还原完整路径树, 供 Phase 2/3 使用。
"""
from __future__ import annotations
import logging
from typing import Any
from .dag_store import DagflowStore
from .models import TaintDAG

logger = logging.getLogger("dvs.dagflow.chain_reconstructor")

# 常见危险 sink 函数 (callee 边指向这些 → is_sink=true)
_SINK_FUNCS = {
    "memcpy", "strcpy", "strncpy", "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "strcat", "strncat", "gets", "scanf", "sscanf", "fscanf", "fgets",
    "memmove", "bcopy", "read", "recv", "recvfrom", "recvmsg",
    "system", "popen", "execve", "execl", "execv", "execvp", "execlp",
    "malloc", "calloc", "realloc", "free",
    "strtok", "strtok_r", "strsep",
    "open", "creat", "openat",
    "ioctl", "setsockopt", "sendto", "sendmsg", "send",
    "write", "fwrite", "pwrite", "writev",
    "atoi", "atol", "strtol", "strtoul", "strtod",
    "sqlite3_exec", "mysql_query", "mysql_real_query",
}


def _is_sink(callee_name: str) -> bool:
    """判断 callee 是否危险 sink (短名匹配)。"""
    short = callee_name.split("::")[-1].split("(")[0].strip("*").strip()
    return short in _SINK_FUNCS


def reconstruct(store: DagflowStore, dag: TaintDAG, func_lookup: Any,
                max_depth: int = 8) -> dict:
    """从根 DAG 出发, 沿 callee 边递归展开完整跨函数链。

    返回路径树:
    {
        "function": func_name, "taint": taint_sig, "taint_state": "tainted",
        "description": dag.description, "self_contained": bool,
        "steps": [ {type, line, ...} ],
    }
    """
    visited: set[str] = set()
    return _build_sub_chain(store, dag, func_lookup, visited, max_depth, 0)


def _build_sub_chain(store: DagflowStore, dag: TaintDAG, func_lookup: Any,
                     visited: set[str], max_depth: int, depth: int) -> dict:
    """递归构建子链 (从一个 DAG 出发)。"""
    func_name = _lookup_func_name(func_lookup, dag.func_id)
    key = f"{dag.func_id}:{dag.taint_signature}"
    if key in visited:
        return {"function": func_name, "taint": dag.taint_signature,
                "taint_state": "tainted", "steps": [],
                "note": "cycle_detected, skipped"}
    visited.add(key)

    # 收集所有 checks (跨 taint 可见)
    all_checks: list[dict] = []
    for n in dag.nodes:
        if n.checks:
            all_checks.extend(n.checks)

    state = "tainted"
    steps: list[dict] = []

    # 入口节点
    entry = next((n for n in dag.nodes if not n.parents or n.is_source), dag.nodes[0] if dag.nodes else None)
    if entry:
        steps.append({
            "step": 0, "type": "entry", "line": entry.line,
            "taint": entry.taint, "taint_state": state,
            "is_source": entry.is_source,
            "checks": list(entry.checks),
            "all_checks_in_func": all_checks,
        })

    # 按 line 排序遍历边
    edges_sorted = sorted(
        [(n, e) for n in dag.nodes for e in n.children],
        key=lambda ne: ne[1].line or 0)

    step_idx = 1
    for n, e in edges_sorted:
        if e.kind == "inside":
            target_node = next((nd for nd in dag.nodes if nd.id == e.to_node), None)
            target_checks = list(target_node.checks) if target_node else []
            steps.append({
                "step": step_idx, "type": "inside",
                "from": n.id, "to": e.to_node, "line": e.line,
                "from_taint": n.taint, "taint": e.taints,
                "taint_state": state,
                "checks": target_checks,
                "conditions": list(e.condition),
            })
        elif e.kind == "callee":
            is_sink = _is_sink(e.sink_ref) if e.sink_ref else False
            sub_chain = None
            callee_effect = "unknown"

            if not is_sink and depth < max_depth:
                callee_func = func_lookup(e.sink_ref) if e.sink_ref and not _is_indirect(e.sink_ref) else None
                if callee_func is not None and e.param_taints:
                    param = str(e.param_taints[0].get("param", ""))
                    if param and not param.startswith("("):
                        callee_dag = store.load_dag(callee_func.func_id, param)
                        if callee_dag is not None:
                            sub_chain = _build_sub_chain(
                                store, callee_dag, func_lookup,
                                visited, max_depth, depth + 1)
                            # 从子链推断效应
                            callee_effect = _infer_effect(sub_chain)
                        else:
                            callee_effect = "unknown"
                elif e.sink_ref and _is_indirect(e.sink_ref):
                    callee_effect = "indirect"
            elif is_sink:
                callee_effect = "sink"

            if callee_effect == "sanitized":
                state = "clean"

            steps.append({
                "step": step_idx, "type": "callee",
                "from": n.id, "line": e.line,
                "callee": e.sink_ref, "taint": e.taints,
                "taint_state": state,
                "effect": callee_effect,
                "is_sink": is_sink,
                "conditions": list(e.condition),
                "param_taints": list(e.param_taints),
                "sub_chain": sub_chain,
            })
        elif e.kind in ("extern", "container"):
            steps.append({
                "step": step_idx, "type": "escape",
                "from": n.id, "line": e.line,
                "escape_subkind": e.escape_subkind, "carrier": e.carrier,
                "escape_via": e.escape_via, "sink_ref": e.sink_ref,
                "taint": e.taints, "taint_state": state,
            })
        elif e.kind == "return":
            steps.append({
                "step": step_idx, "type": "return",
                "from": n.id, "line": e.line,
                "taint": e.taints, "taint_state": state,
            })
        elif e.kind == "source":
            state = "tainted"
            steps.append({
                "step": step_idx, "type": "source",
                "to": e.to_node, "line": e.line,
                "source_callee": e.sink_ref, "taint": e.taints,
                "taint_state": state,
            })
        step_idx += 1

    return {
        "function": func_name, "taint": dag.taint_signature,
        "taint_state": state, "description": dag.description,
        "self_contained": dag.self_contained,
        "steps": steps,
    }


def _infer_effect(sub_chain: dict) -> str:
    """从子链推断 callee 效应。"""
    if not sub_chain or not sub_chain.get("steps"):
        return "unchanged"
    for s in sub_chain["steps"]:
        if s.get("is_sink"):
            return "sink"
        if s.get("effect") == "sanitized":
            return "sanitized"
        if s.get("effect") == "sink":
            return "propagate"
    has_return = any(s["type"] == "return" for s in sub_chain["steps"])
    if has_return:
        return "return"
    return "propagate"


def _lookup_func_name(func_lookup: Any, func_id: str) -> str:
    """通过 func_id 查函数名 (best-effort)。"""
    try:
        fn = func_lookup(func_id) if callable(func_lookup) else None
    except Exception:
        fn = None
    if fn is not None:
        lookup_fn = getattr(func_lookup, "__func__", func_lookup)
        by_id = getattr(lookup_fn, "__self__", None)
        if by_id and hasattr(by_id, "get_by_id"):
            try:
                r = by_id.get_by_id(func_id)
                if r:
                    return r.name
            except Exception:
                pass
    return func_id[:16]


def _is_indirect(sink_ref: str) -> bool:
    """间接调用: sink_ref 含 -> / ( / * (指针表达式)。"""
    return bool(sink_ref) and ("->" in sink_ref or sink_ref.startswith("(") or "*" in sink_ref)
