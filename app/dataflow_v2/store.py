"""dataflow-v2 存储层 (MySQL ONLY)。

V2 引擎的所有数据全部存 MySQL, 不再使用 SQLite。

数据分布:
  MySQL dvs_<source_dir_id> 库:
    functions / include_index / class_hierarchy / class_members / indexing_files
    processed_taints / processed_taint_scope_claims / taints / propagations / orchestration

  MySQL dvs_<project_hash> 库 (MysqlGraphStore):
    dvs_task_graph_runs / nodes / edges / sessions
    dvs_vuln_findings / dvs_analysis_runs

函数体不单独存文件 (数据库有 start_line/end_line, 需要时 read_function_body 从原源文件按行读)。
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .models import (
    FunctionRecord, OrchestrationEdge, ProcessedTaint, PropagationRecord,
    TaintParamInfo, TaintRecord, Validation, _norm_sig, _sha,
)

logger = logging.getLogger("dvs.dataflow_v2.store")


def _validation_from_dict(v: dict) -> Validation:
    """从 dict 重建 Validation。"""
    if not isinstance(v, dict):
        return Validation()
    return Validation(
        line=int(v.get("line") or 0),
        kind=str(v.get("kind") or ""),
        target=str(v.get("target") or ""),
        summary=str(v.get("summary") or ""),
        function_file=str(v.get("function_file") or ""),
        function_name=str(v.get("function_name") or ""),
        function_start_line=int(v.get("function_start_line") or 0),
        function_end_line=int(v.get("function_end_line") or 0),
    )


class DataflowStore:
    """V2 引擎存储访问层 (MySQL ONLY, 无 SQLite)。"""

    def __init__(self, run_dir: str | Path, mysql_store=None,
                 cross_task_function_dedup_enabled: bool = True) -> None:
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._mysql = mysql_store  # SharedMysqlStore
        self._cross_task_function_dedup_enabled = bool(cross_task_function_dedup_enabled)

    def close(self) -> None:
        pass  # MySQL 连接由 SharedMysqlStore 管理

    # ── 函数库 ──────────────────────────────────────────────────────────────
    def upsert_function(self, rec: FunctionRecord) -> None:
        if self._mysql:
            self._mysql.upsert_function(func_id=rec.func_id, file=rec.file, name=rec.name,
                signature=rec.signature, start_line=rec.start_line, end_line=rec.end_line,
                func_hash=rec.func_hash or "", description=rec.description or "")

    def get_function(self, func_id: str) -> FunctionRecord | None:
        if self._mysql:
            return self._mysql.read_function(func_id)
        return None

    def find_function(self, name: str, file: str = "") -> FunctionRecord | None:
        matches = self.find_functions(name, file)
        return matches[0] if matches else None

    def find_functions(self, name: str, file: str = "") -> list[FunctionRecord]:
        if self._mysql:
            return self._mysql.read_functions(name, file) or []
        return []

    def list_functions(self) -> list[FunctionRecord]:
        if self._mysql:
            return self._mysql.read_list_functions() or []
        return []

    def count_functions(self) -> int:
        if self._mysql:
            return self._mysql.count_functions()
        return 0

    def functions_by_file(self, file: str) -> list[FunctionRecord]:
        if self._mysql:
            return self._mysql.read_functions_by_file(file) or []
        return []

    # ── 调用关系 (call_edges) ──────────────────────────────────────────
    def save_call_edges(self, caller_func_id: str, edges: list[dict]) -> None:
        pass  # 无 MySQL 镜像, 无读取方, 不再存储

    def is_call_edges_indexed(self, func_id: str) -> bool:
        return False

    def query_callees(self, caller_func_id: str) -> list[dict]:
        return []

    def query_callers(self, callee_name: str) -> list[dict]:
        return []

    # ── include 索引 (C 作用域) ────────────────────────────────────────
    def add_include(self, header: str, file: str) -> None:
        if self._mysql:
            self._mysql.add_include(header, file)

    def get_files_including(self, header: str) -> list[str]:
        if self._mysql:
            return self._mysql.read_files_including(header) or []
        return []

    # ── class 继承图 (C++ 作用域) ──────────────────────────────────────
    def add_class(self, class_name: str, bases: list[str], file: str = "") -> None:
        import json
        if self._mysql:
            self._mysql.add_class(class_name, json.dumps(bases), file)

    def add_class_member(self, class_name: str, member_name: str,
                         member_type: str = "", file: str = "") -> None:
        if self._mysql:
            self._mysql.add_class_member(class_name, member_name, member_type, file)

    def get_bases(self, class_name: str) -> list[str]:
        if self._mysql:
            return self._mysql.read_bases(class_name) or []
        return []

    def get_all_ancestors(self, class_name: str) -> list[str]:
        visited = set()
        queue = [class_name]
        while queue:
            cls = queue.pop(0)
            if cls in visited:
                continue
            visited.add(cls)
            for base in self.get_bases(cls):
                if base not in visited:
                    queue.append(base)
        visited.discard(class_name)
        return list(visited)

    def get_all_descendants(self, class_name: str) -> list[str]:
        if self._mysql:
            descs = self._mysql.read_all_descendants(class_name)
            return descs or []
        return []

    def get_member_declaring_class(self, class_name: str, member_name: str) -> str | None:
        if self._mysql:
            result = self._mysql.read_member_declaring_class(class_name, member_name)
            if result: return result
        return None

    def get_class_scope_methods(self, class_name: str, member_name: str = "") -> list[str]:
        if self._mysql:
            methods = self._mysql.read_class_scope_methods(class_name, member_name)
            return methods or []
        return []

    def get_functions_with_type_in_signature(self, type_name: str) -> list[str]:
        if self._mysql:
            names = self._mysql.read_functions_with_type_in_signature(type_name)
            return names or []
        return []

    # ── processed_taints (父任务范围内函数级去重 + 每任务审计) ─────────
    def add_processed_taint(self, func_id: str, pt: ProcessedTaint) -> None:
        """写入 processed_taint (func_id 级, per-task 隔离)。"""
        if not self._cross_task_function_dedup_enabled or not self._mysql:
            return
        ts = _norm_sig(pt.taint_signature or "")
        tp_json = json.dumps(pt.taint_params, ensure_ascii=False)
        self._mysql.v2_add_processed_taint(func_id, ts, tp_json, pt.sessions_path or "")

    def try_reserve_processed_taint(self, func_id: str, pt: ProcessedTaint) -> bool:
        """跨任务原子占位: (source_dir_id, parent_task_scope_id, func_id, taint_signature) 级。

        仅同一父任务范围内的已有分析会使占位失败。
        """
        if not self._cross_task_function_dedup_enabled or not self._mysql:
            return True
        ts = _norm_sig(pt.taint_signature or "")
        tp_json = json.dumps(pt.taint_params, ensure_ascii=False)
        return self._mysql.v2_try_reserve_processed_taint(func_id, ts, tp_json, pt.sessions_path or "")

    def delete_processed_taint(self, func_id: str, taint_signature: str,
                               pre_validation_signature: str = "") -> None:
        """删除占位 (仅本任务记录, 分析失败时让后续可重试)。"""
        if not self._cross_task_function_dedup_enabled or not self._mysql:
            return
        ts = _norm_sig(taint_signature or "")
        self._mysql.v2_delete_processed_taint(func_id, ts)

    def find_processed_taint(self, func_id: str, taint_signature: str,
                             pre_validation_signature: str = "") -> ProcessedTaint | None:
        """跨任务去重: (source_dir_id, parent_task_scope_id, func_id, taint_signature) 级。

        同一父任务范围内任意任务已分析过该函数+该污点 → 跳过并复用。
        """
        if not self._cross_task_function_dedup_enabled or not self._mysql:
            return None
        ts = _norm_sig(taint_signature or "")
        return self._mysql.v2_find_processed_taint(func_id, ts)

    # ── 污点库 ──────────────────────────────────────────────────────────────
    def upsert_taint(self, rec: TaintRecord) -> None:
        r = rec.to_row()
        if self._mysql:
            self._mysql.upsert_taint(taint_id=r["taint_id"], func_id=r["func_id"],
                name=r["name"], signature=r["signature"], file=r["file"], function=r["function"],
                next_propagations=r["next_propagations"], description=r["description"])

    def get_taint(self, taint_id: str) -> TaintRecord | None:
        return None  # 废弃, 用 list_taints_in_function

    def list_taints_in_function(self, func_id: str) -> list[TaintRecord]:
        if self._mysql:
            return self._mysql.read_taints_in_function(func_id) or []
        return []

    def add_propagation_to_taint(self, taint_id: str, prop_id: str) -> None:
        pass  # 废弃, 无调用方

    # ── 传播库 ──────────────────────────────────────────────────────────────
    def upsert_propagation(self, rec: PropagationRecord) -> None:
        r = rec.to_row()
        if self._mysql:
            self._mysql.upsert_propagation(**r)

    def get_propagation(self, prop_id: str) -> PropagationRecord | None:
        if self._mysql:
            return self._mysql.read_propagation(prop_id)
        return None

    def list_propagations_from(self, func_id: str) -> list[PropagationRecord]:
        if self._mysql:
            return self._mysql.read_propagations_from(func_id) or []
        return []

    # ── 编排库 ──────────────────────────────────────────────────────────────
    def upsert_edge(self, edge: OrchestrationEdge) -> None:
        r = edge.to_row()
        if self._mysql:
            self._mysql.upsert_orchestration_edge(edge_id=r["edge_id"], path_id=r["path_id"],
                source_func_id=r["source_func_id"], target_func_id=r["target_func_id"],
                taint_params=r["taint_params"], depth=r["depth"], edge_order=r["edge_order"],
                status=r["status"],
                source_function=r["source_function"], source_signature=r["source_signature"],
                target_function=r["target_function"], target_signature=r["target_signature"])

    def set_edge_status(self, edge_id: str, status: str) -> None:
        pass  # 废弃, 无调用方

    def list_path_edges(self, path_id: str) -> list[OrchestrationEdge]:
        if self._mysql:
            return self._mysql.read_path_edges(path_id) or []
        return []

    def pending_edges(self) -> list[OrchestrationEdge]:
        if self._mysql:
            return self._mysql.read_pending_edges() or []
        return []
