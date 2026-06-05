"""Read task-local vulnerability graph artifacts."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .vuln_store import VulnScanStore


def load_vuln_scan_graph(run_root: str | Path) -> dict[str, Any]:
    root = Path(run_root)
    # 新架构：任务最终图谱数据库位于 output/vuln-scan.sqlite；兼容旧 run/ 路径。
    candidates = [
        root / "vuln-scan.sqlite",
        root.parent / "output" / "vuln-scan.sqlite",
    ]
    if root.name.startswith("epoch") or root.name == "run":
        candidates.append(root.parent.parent / "output" / "vuln-scan.sqlite")
    for db_path in candidates:
        if db_path.exists():
            return VulnScanStore(db_path).export_json()
    return {"analysis_runs": [], "taint_nodes": [], "taint_edges": [], "followups": [], "vulnerability_findings": [], "context_forks": []}


def summarize_graph(graph: dict[str, Any]) -> dict[str, int]:
    return {
        "runs": len(graph.get("analysis_runs") or []),
        "nodes": len(graph.get("taint_nodes") or []),
        "edges": len(graph.get("taint_edges") or []),
        "followups": len(graph.get("followups") or []),
        "findings": len(graph.get("vulnerability_findings") or []),
    }
