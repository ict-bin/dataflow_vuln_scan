"""Read task-local vulnerability graph artifacts."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .vuln_store import VulnScanStore


def load_vuln_scan_graph(run_root: str | Path) -> dict[str, Any]:
    root = Path(run_root)
    # 搜索顺序：
    #  1. output/vuln-scan.sqlite  (最终归档后)
    #  2. run/vuln-scan.sqlite     (执行期间共享工作区)
    #  3. 其它兼容路径
    candidates: list[Path] = []
    # 如果传入的是 epoch 运行目录 (run/epochs/<N>)
    if root.parts and "epochs" in root.parts:
        epoch_idx = list(root.parts).index("epochs")
        run_dir = Path(*root.parts[:epoch_idx])  # run/
        task_root = run_dir.parent               # task_id/
        candidates = [
            task_root / "output" / "vuln-scan.sqlite",
            run_dir / "vuln-scan.sqlite",
        ]
    else:
        # root = run/ 或其他
        candidates = [
            root.parent / "output" / "vuln-scan.sqlite",
            root / "vuln-scan.sqlite",
            root,
        ]
    for db_path in candidates:
        if db_path.exists() and db_path.suffix == ".sqlite":
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
