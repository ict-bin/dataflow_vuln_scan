"""dataflow-v2 图谱导出 (供前端 /tasks/{id}/vuln-graph 端点)。

当任务开启 feature_flags.dataflow_v2 时, vuln-graph 端点改读本模块, 从
output/dataflow-v2/ (或 run/dataflow-v2/) 四库 + vuln-scan.sqlite findings
构建前端可消费的图谱结构 (与 v1 load_vuln_scan_graph 同构 + v2 专属 paths)。

映射:
  taint_nodes      ← taints.db
  taint_edges      ← propagations.db
  followups        ← orchestration.db (DFS 边)
  analysis_runs    ← functions.db (已分析函数)
  vulnerability_findings ← vuln-scan.sqlite (v2 mine_vulns 写入)
  v2_paths         ← orchestration.db 按 path_id 分组的 DFS 路径 (v2 专属)
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


def _find_v2_dir(run_root: str | Path) -> Path | None:
    """定位 dataflow-v2/ 目录 (优先 output 归档, 次 run/, 次 epoch, 次 .run_nfs 镜像)。"""
    root = Path(run_root)
    _nfs = ".run_nfs"
    candidates: list[Path] = []
    if "epochs" in root.parts:
        epoch_idx = list(root.parts).index("epochs")
        run_dir = Path(*root.parts[:epoch_idx])
        candidates += [run_dir.parent / "output" / "dataflow-v2",
                       run_dir / "dataflow-v2",
                       run_dir.parent / _nfs / "output" / "dataflow-v2",
                       run_dir.parent / _nfs / "dataflow-v2"]
        if root.name.isdigit():
            candidates.append(root / "dataflow-v2")
    else:
        candidates += [root / "dataflow-v2", root / "output" / "dataflow-v2",
                       root.parent / "output" / "dataflow-v2",
                       root.parent / _nfs / "output" / "dataflow-v2"]
    for c in candidates:
        try:
            r = c.resolve()
        except (OSError, RuntimeError):
            continue
        if r.is_dir() and (r / "functions.db").exists():
            return r
    return None


def _find_vuln_sqlite(run_root: str | Path) -> Path | None:
    """定位 vuln-scan.sqlite (findings 来源, 与 v1 同候选逻辑)。"""
    root = Path(run_root)
    candidates: list[Path] = []
    if "epochs" in root.parts:
        epoch_idx = list(root.parts).index("epochs")
        run_dir = Path(*root.parts[:epoch_idx])
        candidates += [run_dir.parent / "output" / "vuln-scan.sqlite",
                       run_dir / "vuln-scan.sqlite",
                       run_dir.parent / ".run_nfs" / "output" / "vuln-scan.sqlite"]
    else:
        candidates += [root / "vuln-scan.sqlite", root / "output" / "vuln-scan.sqlite",
                       root.parent / "output" / "vuln-scan.sqlite"]
    for c in candidates:
        try:
            r = c.resolve()
        except (OSError, RuntimeError):
            continue
        if r.exists():
            return r
    return None


def _q(db: sqlite3.Connection, sql: str) -> list[dict]:
    db.row_factory = sqlite3.Row
    return [dict(r) for r in db.execute(sql).fetchall()]


def load_dataflow_v2_graph(run_root: str | Path) -> dict[str, Any]:
    """读四库 + findings, 返回前端图谱结构。"""
    v2 = _find_v2_dir(run_root)
    if v2 is None:
        return {"analysis_runs": [], "taint_nodes": [], "taint_edges": [], "followups": [],
                "vulnerability_findings": [], "v2_paths": [], "v2_available": False}

    # functions → analysis_runs (只含已分析函数, 非全量索引)
    fc = sqlite3.connect(v2 / "functions.db")
    functions = _q(fc, "SELECT func_id, file, name, signature, start_line, end_line, description, processed_taints FROM functions WHERE processed_taints != '[]'")
    fc.close()
    analysis_runs = [{
        "run_id": f["func_id"], "function": f["name"], "source_file": f["file"],
        "signature": f["signature"], "line_hint": f"L" + str(f["start_line"]),
        "description": f["description"],
        "processed_taint_count": len(json.loads(f["processed_taints"] or "[]")),
    } for f in functions]

    # taints → taint_nodes
    tc = sqlite3.connect(v2 / "taints.db")
    taints = _q(tc, "SELECT taint_id, func_id, name, signature, file, function, description FROM taints")
    tc.close()
    taint_nodes = [{
        "node_id": t["taint_id"], "run_id": t["func_id"], "function": t["function"],
        "source_file": t["file"], "taint": t["name"], "signature": t["signature"],
        "description": t["description"],
    } for t in taints]

    # propagations → taint_edges
    pc = sqlite3.connect(v2 / "propagations.db")
    props = _q(pc, "SELECT prop_id, source_func_id, source_taint_name, source_taint_signature, "
                   "target_taint_name, target_taint_signature, target_function, target_func_id, "
                   "call_line, condition, is_external, callsite_validated, "
                   "branch_group_id, branch_arm_id, mutex_siblings, validations, description FROM propagations")
    pc.close()
    taint_edges = [{
        "edge_id": p["prop_id"], "run_id": p["source_func_id"],
        "from_symbol": p["source_taint_name"], "to_symbol": p["target_taint_name"],
        "to_function": p["target_function"], "to_node_id": p["target_func_id"],
        "line": str(p["call_line"]) if p["call_line"] else "",
        "operation": "call_arg", "evidence": p["description"],
        "condition": p["condition"], "is_external": bool(p["is_external"]),
        "callsite_validated": bool(p["callsite_validated"]),
        "branch_group_id": p["branch_group_id"], "branch_arm_id": p["branch_arm_id"],
        "mutex_siblings": json.loads(p["mutex_siblings"] or "[]"),
        "validations": json.loads(p["validations"] or "[]"),
    } for p in props]

    # orchestration → followups + v2_paths
    oc = sqlite3.connect(v2 / "orchestration.db")
    edges = _q(oc, "SELECT edge_id, path_id, source_function, source_func_id, target_function, "
                   "target_func_id, taint_params, depth, edge_order, status FROM orchestration ORDER BY path_id, edge_order")
    oc.close()
    followups = [{
        "followup_id": e["edge_id"], "run_id": e["source_func_id"],
        "callee_function": e["target_function"], "callee_file": "",
        "depth": e["depth"], "reason": f"path={e['path_id'][:8]} order={e['edge_order']}",
        "status": e["status"],
    } for e in edges]
    # v2_paths: 按 path_id 分组的 DFS 路径
    paths: dict[str, list[dict]] = {}
    for e in edges:
        paths.setdefault(e["path_id"], []).append({
            "function": e["target_function"], "func_id": e["target_func_id"],
            "depth": e["depth"], "order": e["edge_order"], "status": e["status"],
            "from": e["source_function"],
        })
    v2_paths = [{"path_id": pid, "steps": steps} for pid, steps in paths.items()]

    # findings ← vuln-scan.sqlite
    findings: list[dict] = []
    sq = _find_vuln_sqlite(run_root)
    if sq is not None:
        try:
            from ..vuln_store import VulnScanStore
            findings = VulnScanStore(sq).export_json().get("vulnerability_findings") or []
        except Exception:
            findings = []

    return {
        "analysis_runs": analysis_runs,
        "taint_nodes": taint_nodes,
        "taint_edges": taint_edges,
        "followups": followups,
        "vulnerability_findings": findings,
        "v2_paths": v2_paths,
        "v2_functions": [{"func_id": f["func_id"], "name": f["name"], "file": f["file"]}
                         for f in functions],
        "v2_available": True,
    }


def build_v2_trace_tree(graph: dict[str, Any]) -> dict[str, Any] | None:
    """从 v2_paths 构建 DFS 路径树 (前端展示调用链)。"""
    paths = graph.get("v2_paths") or []
    if not paths:
        return None
    children: list[dict] = []
    for p in paths:
        steps = p.get("steps") or []
        if not steps:
            continue
        # 路径首节点为根子节点, 后续按 order 串成链
        node = {"function": steps[0].get("from") or "(root)", "function_id": "",
                "depth": 0, "children": []}
        cur = node
        for s in steps:
            child = {"function": s.get("function"), "function_id": s.get("func_id"),
                     "depth": s.get("depth"), "order": s.get("order"),
                     "status": s.get("status"), "children": []}
            cur["children"].append(child)
            cur = child
        children.append(node)
    return {"function": "(root)", "function_id": "", "depth": 0, "children": children}


def summarize_v2_graph(graph: dict[str, Any]) -> dict[str, int]:
    return {
        "runs": len(graph.get("analysis_runs") or []),
        "nodes": len(graph.get("taint_nodes") or []),
        "edges": len(graph.get("taint_edges") or []),
        "followups": len(graph.get("followups") or []),
        "paths": len(graph.get("v2_paths") or []),
        "findings": len(graph.get("vulnerability_findings") or []),
    }
