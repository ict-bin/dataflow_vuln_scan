"""Read task-local vulnerability graph artifacts."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .vuln_store import VulnScanStore


def load_vuln_scan_graph(run_root: str | Path) -> dict[str, Any]:
    root = Path(run_root)
    db_path = root / "vuln-scan.sqlite"
    graph_json = root / "vuln-scan-graph.json"
    if db_path.exists():
        return VulnScanStore(db_path).export_json()
    if graph_json.exists():
        try:
            return json.loads(graph_json.read_text(encoding="utf-8"))
        except Exception as exc:
            return {"error": f"failed to read graph json: {exc}", "analysis_runs": [], "taint_nodes": [], "taint_edges": [], "followups": [], "vulnerability_findings": []}
    return {"analysis_runs": [], "taint_nodes": [], "taint_edges": [], "followups": [], "vulnerability_findings": []}


def summarize_graph(graph: dict[str, Any]) -> dict[str, int]:
    return {
        "runs": len(graph.get("analysis_runs") or []),
        "nodes": len(graph.get("taint_nodes") or []),
        "edges": len(graph.get("taint_edges") or []),
        "followups": len(graph.get("followups") or []),
        "findings": len(graph.get("vulnerability_findings") or []),
    }
