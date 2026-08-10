"""In-memory backends for tests that exercise MySQL-only storage contracts."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from app.dataflow_v2.models import (
    FunctionRecord,
    OrchestrationEdge,
    ProcessedTaint,
    PropagationRecord,
    TaintRecord,
    Validation,
)
from app.dataflow_v2.store import DataflowStore
from app.vuln_store import VulnScanStore


class InMemorySharedMysqlStore:
    """Small test double for the SharedMysqlStore methods used by DataflowStore."""

    def __init__(self) -> None:
        self.functions: dict[str, FunctionRecord] = {}
        self.taints: dict[str, TaintRecord] = {}
        self.propagations: dict[str, PropagationRecord] = {}
        self.edges: dict[str, OrchestrationEdge] = {}
        self.claims: dict[tuple[str, str], ProcessedTaint] = {}
        self.indexing_files: set[str] = set()
        self.indexed_files: set[str] = set()

    def upsert_function(self, **data: Any) -> None:
        self.functions[data["func_id"]] = FunctionRecord(
            file=data["file"],
            name=data["name"],
            signature=data["signature"],
            start_line=int(data["start_line"]),
            end_line=int(data["end_line"]),
            func_hash=data.get("func_hash", ""),
            description=data.get("description", ""),
        )

    def read_function(self, func_id: str) -> FunctionRecord | None:
        return self.functions.get(func_id)

    def read_functions(self, name: str, file: str = "") -> list[FunctionRecord]:
        target = name.strip()
        tail = target.split("::")[-1]
        matches = [
            item for item in self.functions.values()
            if (not file or item.file == file)
            and (item.name == target or item.name.split("::")[-1] == tail)
        ]
        return sorted(matches, key=lambda item: (item.file, item.name, item.func_id))

    def read_list_functions(self) -> list[FunctionRecord]:
        return sorted(self.functions.values(), key=lambda item: item.func_id)

    def count_functions(self) -> int:
        return len(self.functions)

    def read_functions_by_file(self, file: str) -> list[FunctionRecord]:
        return [item for item in self.functions.values() if item.file == file]

    def read_is_indexing(self, file: str) -> bool:
        return file in self.indexing_files

    def read_is_indexed(self, file: str) -> bool:
        return file in self.indexed_files

    def add_indexing_file(self, file: str) -> None:
        self.indexing_files.add(file)

    def finish_indexing_file(self, file: str) -> None:
        self.indexing_files.discard(file)
        self.indexed_files.add(file)

    def v2_find_processed_taint(self, func_id: str, signature: str = "") -> ProcessedTaint | None:
        return self.claims.get((func_id, signature))

    def v2_try_reserve_processed_taint(
        self,
        func_id: str,
        signature: str,
        taint_params: str = "[]",
        sessions_path: str = "",
    ) -> bool:
        key = (func_id, signature)
        if key in self.claims:
            return False
        self.claims[key] = ProcessedTaint(
            taint_signature=signature,
            taint_params=[],
            sessions_path=sessions_path,
        )
        return True

    def v2_add_processed_taint(self, func_id: str, signature: str, taint_params: str = "[]", sessions_path: str = "") -> None:
        self.v2_try_reserve_processed_taint(func_id, signature, taint_params, sessions_path)

    def v2_delete_processed_taint(self, func_id: str, signature: str = "") -> None:
        self.claims.pop((func_id, signature), None)

    def upsert_taint(self, **data: Any) -> None:
        self.taints[data["taint_id"]] = TaintRecord(
            func_id=data["func_id"],
            name=data["name"],
            signature=data["signature"],
            file=data["file"],
            function=data["function"],
            next_propagations=_json_list(data.get("next_propagations")),
            description=data.get("description", ""),
        )

    def read_taints_in_function(self, func_id: str) -> list[TaintRecord]:
        return [item for item in self.taints.values() if item.func_id == func_id]

    def upsert_propagation(self, **data: Any) -> None:
        normalized = dict(data)
        for field in ("actual_args", "mutex_siblings", "branch_path"):
            normalized[field] = _json_list(normalized.get(field))
        normalized["validations"] = [
            value if isinstance(value, Validation) else Validation(**value)
            for value in _json_list(normalized.get("validations"))
        ]
        self.propagations[data["prop_id"]] = PropagationRecord(**normalized)

    def read_propagation(self, prop_id: str) -> PropagationRecord | None:
        return self.propagations.get(prop_id)

    def read_propagations_from(self, func_id: str) -> list[PropagationRecord]:
        return [item for item in self.propagations.values() if item.source_func_id == func_id]

    def upsert_orchestration_edge(self, **data: Any) -> None:
        self.edges[data["edge_id"]] = OrchestrationEdge(
            edge_id=data["edge_id"],
            path_id=data["path_id"],
            source_func_id=data["source_func_id"],
            target_func_id=data["target_func_id"],
            taint_params=_taint_params(data["taint_params"]),
            depth=int(data["depth"]),
            edge_order=int(data["edge_order"]),
            status=data.get("status", "pending"),
            source_function=data.get("source_function", ""),
            source_signature=data.get("source_signature", ""),
            target_function=data.get("target_function", ""),
            target_signature=data.get("target_signature", ""),
        )

    def read_path_edges(self, path_id: str) -> list[OrchestrationEdge]:
        return [item for item in self.edges.values() if item.path_id == path_id]

    def read_pending_edges(self) -> list[OrchestrationEdge]:
        return [item for item in self.edges.values() if item.status == "pending"]

    def update_orchestration_edge_status(self, edge_id: str, status: str) -> None:
        if edge_id in self.edges:
            self.edges[edge_id].status = status


class InMemoryMysqlGraphStore:
    """Test-only MysqlGraphStore equivalent for graph recorder assertions."""

    def __init__(self) -> None:
        self.runs: dict[str, dict[str, Any]] = {}
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.analysis_runs: dict[str, dict[str, Any]] = {}
        self.findings: dict[tuple[str, str], dict[str, Any]] = {}

    def start_task_graph_run(self, rec) -> None:
        self.runs[rec.task_id] = asdict(rec)

    def upsert_task_graph_node(self, rec) -> None:
        self.nodes[rec.node_id] = asdict(rec)

    def update_task_graph_node(self, node_id: str, **data: Any) -> None:
        self.nodes.setdefault(node_id, {"node_id": node_id}).update(data)

    def upsert_task_graph_edge(self, rec) -> None:
        self.edges[rec.edge_id] = asdict(rec)

    def update_task_graph_edge(self, edge_id: str, **data: Any) -> None:
        self.edges.setdefault(edge_id, {"edge_id": edge_id}).update(data)

    def upsert_task_graph_session(self, rec) -> None:
        self.sessions[rec.session_relpath] = asdict(rec)

    def update_task_graph_session(self, session_relpath: str, **data: Any) -> None:
        self.sessions.setdefault(session_relpath, {"session_relpath": session_relpath}).update(data)

    def start_run(self, run_id: str, task_id: str, root_file: str, root_function: str, source_root: str, config: dict) -> None:
        self.analysis_runs[run_id] = {
            "run_id": run_id,
            "task_id": task_id,
            "root_file": root_file,
            "root_function": root_function,
            "source_root": source_root,
            "status": "running",
            "config_json": config,
        }

    def finish_run(self, run_id: str, status: str) -> None:
        self.analysis_runs.setdefault(run_id, {"run_id": run_id})["status"] = status

    def insert_finding(self, **data: Any) -> None:
        self.findings[(str(data.get("run_id") or ""), str(data["finding_id"]))] = data

    def list_task_findings(self, task_id: str) -> list[dict[str, Any]]:
        return [
            item for item in self.findings.values()
            if self.analysis_runs.get(str(item.get("run_id") or ""), {}).get("task_id") == task_id
        ]

    def list_all_findings(self) -> list[dict[str, Any]]:
        return list(self.findings.values())

    def export_task_graph_view(self, task_id: str) -> dict[str, Any]:
        run = self.runs.get(task_id, {})
        nodes = sorted(
            (dict(item) for item in self.nodes.values() if item.get("task_id") == task_id),
            key=lambda item: (int(item.get("depth") or 0), str(item.get("function_name_resolved") or ""), str(item["node_id"])),
        )
        edges = sorted(
            (dict(item) for item in self.edges.values() if item.get("task_id") == task_id),
            key=lambda item: (int(item.get("display_order") or 0), str(item.get("edge_id") or "")),
        )
        sessions = sorted(
            (dict(item) for item in self.sessions.values() if item.get("task_id") == task_id),
            key=lambda item: str(item["session_relpath"]),
        )
        findings = self.list_task_findings(task_id)
        node_by_id = {str(item["node_id"]): item for item in nodes}
        visible = [item for item in edges if int(item.get("visible_in_tree", 1) or 0) == 1]
        by_source: dict[str, list[dict[str, Any]]] = {}
        for edge in visible:
            by_source.setdefault(str(edge.get("source_node_id") or ""), []).append(edge)

        def tree_node(node: dict[str, Any], seen: set[str]) -> dict[str, Any]:
            node_id = str(node["node_id"])
            if node_id in seen:
                return {"node_id": node_id, "children": [], "cycle": True}
            children = []
            for edge in by_source.get(node_id, []):
                target = node_by_id.get(str(edge.get("target_node_id") or ""))
                if target is None:
                    children.append({
                        "node_id": edge.get("target_node_id") or f"virtual::{edge.get('edge_id')}",
                        "edge_id": edge.get("edge_id") or "",
                        "function_name_resolved": edge.get("target_function_resolved") or edge.get("target_function_raw") or "",
                        "function_name_raw": edge.get("target_function_raw") or "",
                        "status": edge.get("status") or "unresolved",
                        "edge_kind": edge.get("edge_kind") or "",
                        "reason_code": edge.get("reason_code") or "",
                        "reason_message": edge.get("reason_message") or "",
                        "children": [],
                        "placeholder": True,
                    })
                else:
                    child = tree_node(target, seen | {node_id})
                    child["edge"] = edge
                    child["edge_id"] = edge.get("edge_id") or ""
                    children.append(child)
            return {
                "node_id": node_id,
                "function_name_resolved": node.get("function_name_resolved") or node.get("function_name_raw") or "",
                "function_name_raw": node.get("function_name_raw") or "",
                "source_file": node.get("source_file") or "",
                "depth": int(node.get("depth") or 0),
                "status": node.get("status") or "done",
                "analysis_status": node.get("analysis_status") or "",
                "findings_count": int(node.get("findings_count") or 0),
                "primary_session_relpath": node.get("primary_session_relpath") or "",
                "children": children,
            }

        root = min(nodes, key=lambda item: int(item.get("depth") or 0), default=None)
        return {
            "task_id": task_id,
            "epoch": str(run.get("epoch") or ""),
            "available": bool(nodes or edges or findings),
            "run_root": str(run.get("run_root") or ""),
            "generated_at": float(run.get("generated_at") or 0),
            "nodes": nodes,
            "edges": edges,
            "tree": tree_node(root, set()) if root else None,
            "sessions": sessions,
            "findings": findings,
            "summary": {
                "nodes_total": len(nodes),
                "edges_total": len(edges),
                "findings_total": len(findings),
                "nodes": len(nodes),
                "edges": len(edges),
                "sessions": len(sessions),
                "findings": len(findings),
                "followed_edges": len(visible),
                "unfollowed_edges": len(edges) - len(visible),
                "edges_done": sum(1 for item in edges if item.get("status") == "done"),
                "edges_running": sum(1 for item in edges if item.get("status") == "running"),
                "edges_failed": sum(1 for item in edges if item.get("status") == "failed"),
                "edges_cancelled": sum(1 for item in edges if item.get("status") == "cancelled"),
                "edges_unresolved": sum(1 for item in edges if item.get("status") == "unresolved"),
                "edges_not_followed": sum(1 for item in edges if item.get("status") == "not_followed"),
            },
        }


def _json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if not value:
        return []
    try:
        import json
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def _taint_params(value: Any):
    from app.dataflow_v2.models import TaintParamInfo

    if isinstance(value, TaintParamInfo):
        return value
    if isinstance(value, str):
        return TaintParamInfo.from_json(value)
    if isinstance(value, dict):
        return TaintParamInfo(**value)
    return TaintParamInfo()


def make_dataflow_store(run_dir: str | Path, **kwargs: Any) -> DataflowStore:
    """Create a DataflowStore with an explicit MySQL-contract test backend."""
    return DataflowStore(run_dir, mysql_store=InMemorySharedMysqlStore(), **kwargs)


class TestGraphStoreFactory:
    """Keeps a graph backend stable when a test reopens the same graph path."""

    def __init__(self) -> None:
        self._stores: dict[str, InMemoryMysqlGraphStore] = {}

    def create(self, db_path: str | Path) -> VulnScanStore:
        key = str(Path(db_path))
        return VulnScanStore(
            db_path,
            mysql_store=self._stores.setdefault(key, InMemoryMysqlGraphStore()),
        )
