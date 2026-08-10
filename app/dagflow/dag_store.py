"""dagflow DAG 存储 (MySQL ONLY, 独立于 V2 DataflowStore)。

表 (MySQL dvs_<source_dir_id>):
  dag_nodes            (func_id, taint_signature, node_id, ..., task_id)
  dag_edges            (func_id, taint_signature, edge_id, ..., task_id)
  dag_meta             (func_id, taint_signature, ..., task_id)
  dag_processed_taints (func_id, taint_signature, task_id)

去重 (跨任务): find/try_reserve 不含 task_id (任意任务分析过即跳过);
delete/clear 含 task_id (restart 只清本任务记录, 不影响其他任务)。
DAG 数据 (nodes/edges/meta) 为 per-task 分析产出, 含 task_id。

设计: docs/design-taint-analysis.md §8。
"""
from __future__ import annotations
import json, logging
from pathlib import Path
from typing import Any
from .models import TaintDAG, TaintNode, TaintEdge, PruneSignal

logger = logging.getLogger("dvs.dagflow.dag_store")


class DagflowStore:
    """dagflow DAG 存储 + 去重锚点 (MySQL ONLY)。"""

    def __init__(self, run_dir: str | Path | None = None, mysql_store: Any = None,
                 cross_task_function_dedup_enabled: bool = True) -> None:
        # run_dir 保留兼容签名, 不再创建 SQLite 文件
        self.run_dir = Path(run_dir) if run_dir else Path("/tmp/dagflow_none")
        self._mysql = mysql_store  # SharedMysqlStore (必需)
        self._cross_task_function_dedup_enabled = bool(cross_task_function_dedup_enabled)

    def close(self) -> None:
        pass  # MySQL 连接由 SharedMysqlStore 管理

    # ── DAG 存取 ─────────────────────────────────────────────────────────
    def save_dag(self, dag: TaintDAG) -> None:
        """落库整棵 DAG (MySQL ONLY)。幂等: 先删旧再插 (同 key 覆盖)。"""
        if not self._mysql:
            logger.warning("save_dag: no mysql_store, skip")
            return
        fid, ts = dag.func_id, dag.taint_signature
        nodes_m = [{"node_id": n.id, "line": n.line, "taint": n.taint,
                     "parents": n.parents, "checks": n.checks,
                     "prune": n.prune.to_dict() if n.prune else {},
                     "is_source": n.is_source} for n in dag.nodes]
        edges_m = []
        for n in dag.nodes:
            for i, e in enumerate(n.children):
                eid = f"{n.id}->{e.to_node}_{e.kind}_{i}"
                edges_m.append({"edge_id": eid, "from_node": n.id, "to_node": e.to_node,
                                "line": e.line, "condition": e.condition, "taints": e.taints,
                                "kind": e.kind, "sink_ref": e.sink_ref,
                                "param_taints": e.param_taints, "escape_subkind": e.escape_subkind,
                                "carrier": e.carrier, "escape_via": e.escape_via})
        meta_m = {"self_contained": dag.self_contained,
                  "description": dag.description, "taint_failed": dag.taint_failed}
        self._mysql.save_dag(fid, ts, nodes_m, edges_m, meta_m)

    def load_dag(self, func_id: str, taint_signature: str) -> TaintDAG | None:
        """从 MySQL 加载 DAG (per-task: 本任务的 DAG 数据)。"""
        if not self._mysql:
            return None
        return self._mysql.load_dag(func_id, taint_signature, self._mysql.task_id)

    # ── 去重锚点 (跨任务: find/try_reserve 不含 task_id) ──────────────────
    def find_processed_taint(self, func_id: str, taint_signature: str) -> bool:
        """(func_id, taint_signature) 已被任意任务分析过? (跨任务)"""
        if not self._cross_task_function_dedup_enabled or not self._mysql:
            return False
        return self._mysql.dag_find_processed(func_id, taint_signature)

    def try_reserve(self, func_id: str, taint_signature: str) -> bool:
        """分析前占位 (跨任务原子: INSERT...WHERE NOT EXISTS)。"""
        if not self._cross_task_function_dedup_enabled or not self._mysql:
            return True  # 无 MySQL 时放行 (不阻断)
        return self._mysql.dag_try_reserve(func_id, taint_signature)

    def delete_processed_taint(self, func_id: str, taint_signature: str) -> None:
        """analyze 失败时删占位 (只删本任务)。"""
        if not self._cross_task_function_dedup_enabled or not self._mysql:
            return
        self._mysql.dag_delete_processed(func_id, taint_signature)

    # ── 跨函数查询 (per-task: 本任务数据) ────────────────────────────────
    def get_callers(self, func_id: str) -> list[tuple[str, str]]:
        """反查哪些 DAG 有 callee 边指向本 func (本任务)。"""
        if not self._mysql:
            return []
        return self._mysql.dag_get_callers(func_id, self._mysql.task_id)

    def list_analyzed(self) -> list[tuple[str, str]]:
        """本任务所有已分析的 (func_id, taint_signature)。"""
        if not self._mysql:
            return []
        return self._mysql.dag_list_analyzed(self._mysql.task_id)

    def list_dag_outgoing(self, func_id: str, taint_signature: str) -> list[dict]:
        """本 DAG 的传出边 (callee/return/extern/container)。"""
        if not self._mysql:
            return []
        return self._mysql.dag_list_outgoing(func_id, taint_signature, self._mysql.task_id)
