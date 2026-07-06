"""dataflow-v2 图谱导出 (供前端 /tasks/{id}/vuln-graph 端点)。

当任务开启 feature_flags.dataflow_v2 时, vuln-graph 端点改读本模块, 从
output/dataflow-v2/ 四库 + vuln-scan.sqlite findings 构建前端可消费的图谱结构。

设计:
  - build_v2_trace_tree: 从 orchestration.db DFS 路径直接构建 V1 DataflowVulnTraceTreeNode
    格式树 (充实 taint_inputs/taint_summary/findings_count)
  - load_dataflow_v2_graph: 四库 → V1 兼容 graph 字段 (analysis_runs/taint_nodes/...
    + V2 专属 v2_paths)
  - summarize_v2_graph: 统计指标 (含 executed_followups)
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


def _find_v2_dir(run_root: str | Path) -> Path | None:
    """定位 dataflow-v2/ 目录 (优先 output 归档, 次 run/)。"""
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
    """定位 vuln-scan.sqlite (findings 来源)。"""
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


def _load_func_map(v2: Path) -> dict[str, dict]:
    """func_id → {name, file, signature, start_line, description, processed_taints}"""
    fc = sqlite3.connect(v2 / "functions.db")
    rows = _q(fc, "SELECT func_id, file, name, signature, start_line, end_line, "
                  "description, processed_taints FROM functions")
    fc.close()
    return {r["func_id"]: r for r in rows}


def _load_taints_by_func(v2: Path) -> dict[str, list[dict]]:
    """func_id → [{symbol, kind, line, description}]"""
    tc = sqlite3.connect(v2 / "taints.db")
    rows = _q(tc, "SELECT taint_id, func_id, name, signature, file, function, description FROM taints")
    tc.close()
    out: dict[str, list[dict]] = {}
    for t in rows:
        out.setdefault(t["func_id"], []).append({
            "symbol": t["name"], "kind": "param", "line": "", "description": t["description"] or "",
        })
    return out


def _load_props_by_source(v2: Path) -> dict[str, list[dict]]:
    """source_func_id → [{from_symbol, to_symbol, line, operation, evidence, termination_reason, prop_id, target_function, target_func_id, call_line}]"""
    pc = sqlite3.connect(v2 / "propagations.db")
    rows = _q(pc, "SELECT prop_id, source_func_id, source_taint_name, source_taint_signature, "
                   "target_taint_name, target_taint_signature, target_function, target_func_id, "
                   "call_line, condition, is_external, callsite_validated, "
                   "branch_group_id, branch_arm_id, mutex_siblings, validations, description FROM propagations")
    pc.close()
    out: dict[str, list[dict]] = {}
    for p in rows:
        out.setdefault(p["source_func_id"], []).append({
            "prop_id": p["prop_id"], "from_symbol": p["source_taint_name"],
            "to_symbol": p["target_taint_name"], "to_function": p["target_function"],
            "to_node_id": p["target_func_id"],
            "line": str(p["call_line"]) if p["call_line"] else "",
            "operation": "call_arg", "evidence": p["description"] or "",
            "termination_reason": "", "condition": p["condition"],
            "is_external": bool(p["is_external"]), "callsite_validated": bool(p["callsite_validated"]),
            "branch_group_id": p["branch_group_id"], "branch_arm_id": p["branch_arm_id"],
            "mutex_siblings": json.loads(p["mutex_siblings"] or "[]"),
            "validations": json.loads(p["validations"] or "[]"),
            "target_function": p["target_function"], "target_func_id": p["target_func_id"],
            "call_line": p["call_line"],
        })
    return out


def _load_findings_by_func(vuln_sqlite: Path | None) -> dict[str, int]:
    """function_name → findings_count"""
    if vuln_sqlite is None:
        return {}
    try:
        vc = sqlite3.connect(vuln_sqlite)
        vc.row_factory = sqlite3.Row
        rows = vc.execute("SELECT function_name, COUNT(*) as cnt FROM vulnerability_findings "
                          "GROUP BY function_name").fetchall()
        vc.close()
        return {r["function_name"]: r["cnt"] for r in rows}
    except Exception:
        return {}


def load_dataflow_v2_graph(run_root: str | Path) -> dict[str, Any]:
    """读四库 + findings, 返回 V1 兼容图谱结构 + V2 专属 paths。"""
    v2 = _find_v2_dir(run_root)
    if v2 is None:
        return {"analysis_runs": [], "taint_nodes": [], "taint_edges": [], "followups": [],
                "vulnerability_findings": [], "v2_paths": [], "v2_available": False}

    func_map = _load_func_map(v2)
    taints_by_func = _load_taints_by_func(v2)
    props_by_source = _load_props_by_source(v2)
    vuln_sqlite = _find_vuln_sqlite(run_root)
    findings_by_func = _load_findings_by_func(vuln_sqlite)

    # orchestration → DFS 路径 + 邻接
    oc = sqlite3.connect(v2 / "orchestration.db")
    orch_edges = _q(oc, "SELECT edge_id, path_id, source_function, source_signature, source_func_id, "
                         "target_function, target_signature, target_func_id, taint_params, "
                         "depth, edge_order, status FROM orchestration ORDER BY path_id, edge_order")
    oc.close()

    # 计算每个函数的 min depth (用于 root 检测: depth=0 为根)
    func_depth: dict[str, int] = {}
    for e in orch_edges:
        if e["source_func_id"] not in func_depth or e["depth"] < func_depth[e["source_func_id"]]:
            func_depth[e["source_func_id"]] = e["depth"]
        td = e["depth"] + 1
        if e["target_func_id"] not in func_depth or td < func_depth[e["target_func_id"]]:
            func_depth[e["target_func_id"]] = td

    # functions → analysis_runs (V1 兼容字段: root_function/root_file/status/started_at)
    analysis_runs = []
    for fid, f in func_map.items():
        if not f.get("processed_taints") or f["processed_taints"] == "[]":
            continue
        depth = func_depth.get(fid, 0)
        analysis_runs.append({
            "run_id": fid, "root_function": f["name"], "root_file": f["file"],
            "function": f["name"], "source_file": f["file"],
            "signature": f["signature"], "line_hint": "L" + str(f["start_line"]),
            "description": f["description"] or "",
            "status": "completed",
            "started_at": float(depth),
            "processed_taint_count": len(json.loads(f["processed_taints"] or "[]")),
        })

    # taints → taint_nodes (V1 兼容)
    taint_nodes = []
    for fid, taints in taints_by_func.items():
        f = func_map.get(fid, {})
        for t in taints:
            taint_nodes.append({
                "node_id": fid + "::" + t["symbol"], "run_id": fid,
                "function_name": f.get("name", ""), "symbol": t["symbol"],
                "taint_kind": t["kind"], "line": t["line"], "description": t["description"],
                "source_file": f.get("file", ""),
            })

    # propagations → taint_edges (V1 兼容)
    taint_edges = []
    for fid, props in props_by_source.items():
        for p in props:
            taint_edges.append({
                "edge_id": p["prop_id"], "run_id": fid,
                "from_symbol": p["from_symbol"], "to_symbol": p["to_symbol"],
                "to_function": p["to_function"], "to_node_id": p["to_node_id"],
                "line": p["line"], "operation": p["operation"], "evidence": p["evidence"],
                "termination_reason": p["termination_reason"], "condition": p["condition"],
                "is_external": p["is_external"], "callsite_validated": p["callsite_validated"],
                "branch_group_id": p["branch_group_id"], "branch_arm_id": p["branch_arm_id"],
                "mutex_siblings": p["mutex_siblings"], "validations": p["validations"],
            })

    # orchestration → followups (V1 兼容: edge_id 链接到 propagation 的 prop_id)
    # 建 (source_func_id, target_function) → [prop_id] 查找表
    prop_lookup: dict[tuple, list[str]] = {}
    for fid, props in props_by_source.items():
        for p in props:
            key = (fid, p["target_function"])
            prop_lookup.setdefault(key, []).append(p["prop_id"])

    followups = []
    for e in orch_edges:
        src_fid = e["source_func_id"]
        tgt_func = e["target_function"]
        tgt_fid = e["target_func_id"]
        # 找匹配的 propagation prop_id 作为 edge_id (V1 build_trace_tree 通过 edge_id 链接)
        matched_props = prop_lookup.get((src_fid, tgt_func), [])
        edge_id = matched_props[0] if matched_props else e["edge_id"]
        # callee_file 从目标函数查
        callee_file = func_map.get(tgt_fid, {}).get("file", "")
        # callee_line 从匹配 propagation 查
        callee_line = ""
        if matched_props:
            for p in props_by_source.get(src_fid, []):
                if p["prop_id"] == edge_id:
                    callee_line = "L" + str(p["call_line"]) if p["call_line"] else ""
                    break
        followups.append({
            "followup_id": e["edge_id"], "edge_id": edge_id,
            "run_id": src_fid, "callee_function": tgt_func,
            "callee_file": callee_file, "callee_line": callee_line,
            "tainted_params_json": e["taint_params"] or "[]",
            "depth": e["depth"], "reason": f"path={e['path_id'][:8]} order={e['edge_order']}",
            "status": e["status"],
        })

    # v2_paths: 按 path_id 分组
    paths: dict[str, list[dict]] = {}
    for e in orch_edges:
        paths.setdefault(e["path_id"], []).append({
            "function": e["target_function"], "func_id": e["target_func_id"],
            "depth": e["depth"], "order": e["edge_order"], "status": e["status"],
            "from": e["source_function"],
        })
    v2_paths = [{"path_id": pid, "steps": steps} for pid, steps in paths.items()]

    # findings ← vuln-scan.sqlite
    findings: list[dict] = []
    if vuln_sqlite is not None:
        try:
            from ..vuln_store import VulnScanStore
            findings = VulnScanStore(vuln_sqlite).export_json().get("vulnerability_findings") or []
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
                         for f in func_map.values()],
        "v2_available": True,
    }


def build_v2_trace_tree(run_root: str | Path) -> dict[str, Any] | None:
    """从 orchestration.db DFS 路径直接构建 V1 DataflowVulnTraceTreeNode 格式树。

    不依赖 V1 build_trace_tree (字段映射脆弱), 直接用 orchestration 的 path/depth 构建,
    充实 taint_inputs/taint_summary/findings_count。
    """
    v2 = _find_v2_dir(run_root)
    if v2 is None:
        return None

    func_map = _load_func_map(v2)
    taints_by_func = _load_taints_by_func(v2)
    props_by_source = _load_props_by_source(v2)
    vuln_sqlite = _find_vuln_sqlite(run_root)
    findings_by_func = _load_findings_by_func(vuln_sqlite)

    oc = sqlite3.connect(v2 / "orchestration.db")
    orch_edges = _q(oc, "SELECT edge_id, path_id, source_function, source_func_id, "
                         "target_function, target_func_id, taint_params, "
                         "depth, edge_order, status FROM orchestration ORDER BY path_id, edge_order")
    oc.close()

    if not orch_edges:
        # 无 orchestration 边: 只分析了一个根函数, 手动构建单节点树
        analyzed = [f for f in func_map.values() if f.get("processed_taints") and f["processed_taints"] != "[]"]
        if not analyzed:
            return None
        f = analyzed[0]
        fname = f.get("name", "")
        ffile = f.get("file", "")
        taint_inputs = taints_by_func.get(f["func_id"], [])
        my_props = props_by_source.get(f["func_id"], [])
        taint_summary = [{"from_symbol": p.get("source_taint_name", ""), "to_symbol": p.get("target_taint_name", ""),
                           "line": str(p.get("call_line", "")), "operation": "call_arg",
                           "evidence": p.get("description", ""), "termination_reason": ""}
                          for p in my_props]
        return {"run_id": f["func_id"], "function_name": fname, "source_file": ffile,
                "line_hint": "", "depth": 0, "status": "completed",
                "taint_inputs": taint_inputs, "taint_summary": taint_summary,
                "child_count": 0, "followup_status": "root", "followup_reason": "",
                "findings_count": findings_by_func.get(fname, 0), "termination_reasons": [],
                "children": []}

    # 邻接: source_func_id → [{target_func_id, target_function, depth, edge_order, status, taint_params, call_line}]
    adj: dict[str, list[dict]] = {}
    root_fid = None
    for e in orch_edges:
        if e["depth"] == 0 and root_fid is None:
            root_fid = e["source_func_id"]
        adj.setdefault(e["source_func_id"], []).append({
            "target_func_id": e["target_func_id"], "target_function": e["target_function"],
            "depth": e["depth"], "edge_order": e["edge_order"], "status": e["status"],
            "taint_params": e["taint_params"], "edge_id": e["edge_id"],
        })
        if e["depth"] == 0:
            if root_fid is None:
                root_fid = e["source_func_id"]

    if root_fid is None:
        root_fid = orch_edges[0]["source_func_id"]

    def _build(fid: str, depth: int, followup_status: str, followup_reason: str,
               callee_line: str = "", visited: set | None = None) -> dict[str, Any]:
        if visited is None:
            visited = set()
        if fid in visited:
            return {
                "run_id": fid, "function_name": func_map.get(fid, {}).get("name", fid),
                "source_file": func_map.get(fid, {}).get("file", ""), "line_hint": callee_line,
                "depth": depth, "status": "cycle", "taint_inputs": [], "taint_summary": [],
                "child_count": 0, "followup_status": "cycle", "followup_reason": "recursion detected",
                "findings_count": 0, "termination_reasons": [], "children": [],
                "pruned": True, "prune_reason": "recursion",
            }
        visited = visited | {fid}
        f = func_map.get(fid, {})
        fname = f.get("name", fid)
        ffile = f.get("file", "")
        taint_inputs = taints_by_func.get(fid, [])
        my_props = props_by_source.get(fid, [])
        taint_summary = [{
            "from_symbol": p["from_symbol"], "to_symbol": p["to_symbol"],
            "line": p["line"], "operation": p["operation"], "evidence": p["evidence"],
            "termination_reason": p["termination_reason"],
        } for p in my_props]
        termination_reasons = [p["termination_reason"] for p in my_props if p["termination_reason"]]
        findings_count = findings_by_func.get(fname, 0)

        children: list[dict[str, Any]] = []
        for child_edge in sorted(adj.get(fid, []), key=lambda x: x["edge_order"]):
            cfid = child_edge["target_func_id"]
            cname = child_edge["target_function"]
            cline = ""
            for p in my_props:
                if p["target_function"] == cname and p["call_line"]:
                    cline = "L" + str(p["call_line"])
                    break
            c_status = child_edge["status"]
            if c_status in ("skipped", "depth_limit", "merged"):
                children.append({
                    "run_id": cfid, "function_name": cname,
                    "source_file": func_map.get(cfid, {}).get("file", ""),
                    "line_hint": cline, "depth": depth + 1, "status": c_status,
                    "taint_inputs": [], "taint_summary": [], "child_count": 0,
                    "followup_status": c_status, "followup_reason": child_edge["status"],
                    "findings_count": findings_by_func.get(cname, 0),
                    "termination_reasons": [], "children": [],
                    "pruned": True, "prune_reason": c_status,
                })
            else:
                children.append(_build(cfid, depth + 1, c_status,
                                       f"path order={child_edge['edge_order']}", cline, visited))

        return {
            "run_id": fid, "function_name": fname, "source_file": ffile,
            "line_hint": callee_line, "depth": depth, "status": "completed",
            "taint_inputs": taint_inputs, "taint_summary": taint_summary,
            "child_count": len(children), "followup_status": followup_status,
            "followup_reason": followup_reason, "findings_count": findings_count,
            "termination_reasons": termination_reasons, "children": children,
        }

    return _build(root_fid, 0, "root", "")


def summarize_v2_graph(graph: dict[str, Any]) -> dict[str, int]:
    followups = graph.get("followups") or []
    executed = sum(1 for fw in followups if fw.get("status") in ("completed", "done", "analyzed"))
    return {
        "runs": len(graph.get("analysis_runs") or []),
        "nodes": len(graph.get("taint_nodes") or []),
        "edges": len(graph.get("taint_edges") or []),
        "followups": len(followups),
        "executed_followups": executed,
        "skipped_followups": sum(1 for fw in followups if fw.get("status") in ("skipped", "depth_limit", "merged")),
        "pending_followups": sum(1 for fw in followups if fw.get("status") == "pending"),
        "findings": len(graph.get("vulnerability_findings") or []),
    }
