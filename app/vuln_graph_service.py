"""Read task-local vulnerability graph artifacts."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .vuln_store import VulnScanStore


def load_vuln_scan_graph(run_root: str | Path) -> dict[str, Any]:
    root = Path(run_root)
    candidates: list[Path] = []
    # NFS mirror directory (written by Worker pod's periodic sync)
    _nfs_mirror_dir = ".run_nfs"

    if root.parts and "epochs" in root.parts:
        epoch_idx = list(root.parts).index("epochs")
        run_dir = Path(*root.parts[:epoch_idx])
        task_output_dir = run_dir.parent / "output"
        task_root = run_dir.parent
        # Prefer final archives over epoch-local snapshots so the UI sees the
        # completed recursive graph instead of an early pending followup view.
        candidates.extend([task_output_dir, run_dir])
        # Also check .run_nfs mirror (for API pods during execution)
        candidates.append(task_root / _nfs_mirror_dir)
        candidates.append(task_root / _nfs_mirror_dir / "output")
        if root.name.isdigit():
            candidates.append(root)
        epochs_dir = run_dir / "epochs"
        if epochs_dir.exists():
            epoch_dirs = sorted(
                [
                    path for path in epochs_dir.iterdir()
                    if path.is_dir() and path.name.isdigit()
                ],
                key=lambda path: int(path.name),
                reverse=True,
            )
            candidates.extend(epoch_dirs)
    else:
        candidates.extend([
            root / "output",
            root.parent / "output",
            root.parent / _nfs_mirror_dir,
            root.parent / _nfs_mirror_dir / "output",
            root,
        ])
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError):
            # Broken symlink (Worker pod replaced path with symlink to local /tmp)
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        db_path = resolved / "vuln-scan.sqlite"
        if db_path.exists():
            return VulnScanStore(db_path).export_json()
    return {"analysis_runs": [], "taint_nodes": [], "taint_edges": [], "followups": [], "vulnerability_findings": [], "context_forks": []}


def summarize_graph(graph: dict[str, Any]) -> dict[str, int]:
    followups = graph.get("followups") or []
    executed = sum(1 for f in followups if f.get("status") in ("completed", "passed", "analyzed"))
    skipped = sum(1 for f in followups if f.get("status") in ("skipped", "cycle", "depth_limit", "merged_equivalent_taint_validation", "forked", "tracker_resolved"))
    pending = sum(1 for f in followups if f.get("status") in ("pending", "queued", "running"))
    return {
        "runs": len(graph.get("analysis_runs") or []),
        "nodes": len(graph.get("taint_nodes") or []),
        "edges": len(graph.get("taint_edges") or []),
        "followups": len(followups),
        "executed_followups": executed,
        "skipped_followups": skipped,
        "pending_followups": pending,
        "findings": len(graph.get("vulnerability_findings") or []),
    }


def build_trace_tree(graph: dict[str, Any]) -> dict[str, Any] | None:
    """Build a call tree from analysis runs and followups, including pruned branches."""
    runs: list[dict[str, Any]] = graph.get("analysis_runs") or []
    if not runs:
        return None
    followups: list[dict[str, Any]] = graph.get("followups") or []
    edges: list[dict[str, Any]] = graph.get("taint_edges") or []
    nodes: list[dict[str, Any]] = graph.get("taint_nodes") or []
    contexts: list[dict[str, Any]] = graph.get("analysis_contexts") or []
    constraints: list[dict[str, Any]] = graph.get("taint_constraints") or []
    findings: list[dict[str, Any]] = graph.get("vulnerability_findings") or []

    # Index helpers
    findings_by_run: dict[str, int] = {}
    for f in findings:
        rid = f.get("run_id", "")
        findings_by_run[rid] = findings_by_run.get(rid, 0) + 1

    edges_by_id: dict[str, dict[str, Any]] = {e.get("edge_id", ""): e for e in edges}
    followups_by_edge: dict[str, list[dict[str, Any]]] = {}
    for fw in followups:
        eid = fw.get("edge_id", "")
        followups_by_edge.setdefault(eid, []).append(fw)
    runs_by_id: dict[str, dict[str, Any]] = {r.get("run_id", ""): r for r in runs}
    runs_by_func: dict[str, dict[str, Any]] = {}
    for r in runs:
        key = (r.get("root_file", ""), r.get("root_function", ""))
        runs_by_func[key] = r
    constraints_by_followup: dict[str, list[dict[str, Any]]] = {}
    for c in constraints:
        fid = c.get("followup_id", "")
        if fid:
            constraints_by_followup.setdefault(fid, []).append(c)

    taint_inputs_by_run: dict[str, list[dict[str, Any]]] = {}
    for n in nodes:
        rid = n.get("run_id", "") or ""
        parent = n.get("parent_node_id", "")
        if not rid and parent:
            for e in edges:
                if e.get("to_node_id") == n.get("node_id"):
                    rid = e.get("run_id", "")
                    break
        if rid:
            taint_inputs_by_run.setdefault(rid, []).append({
                "symbol": n.get("symbol", ""),
                "kind": n.get("taint_kind", ""),
                "line": n.get("line", ""),
                "description": n.get("description", ""),
            })

    def _node_edges(run_id: str) -> list[dict[str, Any]]:
        return [e for e in edges if e.get("run_id") == run_id]

    def _build_node(
        run: dict[str, Any],
        depth: int,
        followup_id: str = "",
        followup_reason: str = "",
        followup_status: str = "",
        callee_line: str = "",
        visited_run_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        if visited_run_ids is None:
            visited_run_ids = set()
        rid = run.get("run_id", "")
        if rid in visited_run_ids:
            return {
                "run_id": rid,
                "function_name": run.get("root_function", ""),
                "source_file": run.get("root_file", ""),
                "line_hint": callee_line,
                "depth": depth,
                "status": "cycle",
                "taint_inputs": [],
                "taint_summary": [],
                "child_count": 0,
                "followup_status": "cycle",
                "followup_reason": "recursion detected",
                "findings_count": 0,
                "termination_reasons": [],
                "children": [],
                "pruned": True,
                "prune_reason": "recursion",
                "taint_constraints": [],
            }
        visited_run_ids.add(rid)
        my_edges = _node_edges(rid)
        taint_summary = [{
            "from_symbol": e.get("from_symbol", ""),
            "to_symbol": e.get("to_symbol", ""),
            "line": e.get("line", ""),
            "operation": e.get("operation", ""),
            "evidence": e.get("evidence", ""),
            "termination_reason": e.get("termination_reason", ""),
        } for e in my_edges]
        termination_reasons = [e.get("termination_reason", "") for e in my_edges if e.get("termination_reason")]

        # Children: followups linked to this run's edges
        seen_fids: set[str] = set()
        children: list[dict[str, Any]] = []
        for e in my_edges:
            eid = e.get("edge_id", "")
            for fw in followups_by_edge.get(eid, []):
                child = _build_followup_node(fw, depth + 1, visited_run_ids)
                if child:
                    children.append(child)
                seen_fids.add(fw.get("followup_id", ""))
        # Fallback: orphaned followups (no edge) belong to this run if their
        # parent_node_id belongs to this run's nodes.
        run_node_ids = {n.get("node_id") for n in nodes if n.get("function_name") == run.get("root_function")}
        for fw in followups:
            fid = fw.get("followup_id", "")
            if fid in seen_fids:
                continue
            parent = fw.get("parent_node_id", "")
            if parent and parent in run_node_ids:
                child = _build_followup_node(fw, depth + 1, visited_run_ids)
                if child:
                    children.append(child)

        return {
            "run_id": rid,
            "function_name": run.get("root_function", ""),
            "source_file": run.get("root_file", ""),
            "line_hint": callee_line,
            "depth": depth,
            "status": run.get("status", "pending"),
            "taint_inputs": taint_inputs_by_run.get(rid, []),
            "taint_summary": taint_summary,
            "child_count": len(children),
            "followup_status": followup_status or "root",
            "followup_reason": followup_reason or "",
            "findings_count": findings_by_run.get(rid, 0),
            "termination_reasons": termination_reasons,
            "children": children,
        }

    def _build_followup_node(fw: dict[str, Any], depth: int, visited_run_ids: set[str]) -> dict[str, Any] | None:
        fid = fw.get("followup_id", "")
        fw_status = fw.get("status", "pending")
        fw_reason = fw.get("reason", "")

        # Pruned statuses
        PRUNED_STATUSES = {"skipped", "cycle", "depth_limit", "merged_equivalent_taint_validation"}
        is_pruned = fw_status in PRUNED_STATUSES

        # Find the analysis run for this followup (by matching callee_function)
        callee_func = fw.get("callee_function", "")
        callee_file = fw.get("callee_file", "")
        callee_line = fw.get("callee_line", "")
        tainted_params = []
        try:
            tainted_params = json.loads(fw.get("tainted_params_json", "[]"))
        except Exception:
            pass

        matched_run = runs_by_id.get(fid) or runs_by_func.get((callee_file, callee_func))

        build_taint_inputs = [{
            "symbol": p if isinstance(p, str) else p.get("symbol", str(p)),
            "kind": "param",
            "line": callee_line,
            "description": "",
        } for p in tainted_params]

        my_constraints = constraints_by_followup.get(fid, [])

        if is_pruned or not matched_run:
            return {
                "run_id": fid,
                "function_name": callee_func,
                "source_file": callee_file,
                "line_hint": callee_line,
                "depth": depth,
                "status": fw_status,
                "taint_inputs": build_taint_inputs,
                "taint_summary": [],
                "child_count": 0,
                "followup_status": fw_status,
                "followup_reason": fw_reason,
                "findings_count": 0,
                "termination_reasons": [],
                "children": [],
                "pruned": True,
                "prune_reason": fw_reason or fw_status,
                "taint_constraints": [{
                    "kind": c.get("kind", ""),
                    "target_symbol": c.get("target_symbol", ""),
                    "target_arg_index": c.get("target_arg_index", 0),
                    "evidence": c.get("evidence", ""),
                    "confidence": c.get("confidence", ""),
                } for c in my_constraints],
            }

        return _build_node(
            matched_run, depth,
            followup_id=fid,
            followup_reason=fw_reason,
            followup_status=fw_status,
            callee_line=callee_line,
            visited_run_ids=visited_run_ids,
        )

    root = min(runs, key=lambda r: float(r.get("started_at") or float("inf")))
    return _build_node(root, 0)
