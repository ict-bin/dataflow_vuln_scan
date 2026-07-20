"""dagflow 图存储记录器: 把 DAG 分析的节点/边/会话写入 vuln-scan.sqlite。

复用 V2 的 VulnScanStore graph API (start_task_graph_run / upsert_task_graph_node /
upsert_task_graph_edge / upsert_task_graph_session / finish_run)。
前端 /tasks/{task_id}/graph-view 从同一数据库读取, 无需区分 V2/dagflow。
"""
from __future__ import annotations
import logging, time
from pathlib import Path
from typing import Any

logger = logging.getLogger("dvs.dagflow.graph_recorder")


class GraphRecorder:
    """把 dagflow 分析过程记录到 vuln-scan.sqlite (兼容前端 graph-view API)。"""

    def __init__(self, *, vuln_store: Any, task_id: str, epoch: str,
                 run_root: str, root_function: str = "") -> None:
        self.store = vuln_store
        self.task_id = task_id
        self.epoch = epoch
        self.run_root = run_root
        self.root_function = root_function

    def _ready(self) -> bool:
        return self.store is not None and hasattr(self.store, "upsert_task_graph_node")

    def _node_id(self, func_id: str) -> str:
        return f"node::{self.task_id}::{self.epoch}::{func_id}"

    def _session_relpath(self, session_path: str) -> str:
        p = Path(session_path)
        try:
            return str(p.resolve().relative_to(Path(self.run_root).resolve())).replace("\\", "/")
        except Exception:
            try:
                return str(p.relative_to(self.run_root)).replace("\\", "/")
            except Exception:
                return str(p).replace("\\", "/")

    # ── run 生命周期 ──────────────────────────────────────────────────

    def start_run(self) -> None:
        if not self._ready():
            return
        try:
            from ..vuln_store import TaskGraphRunRecord
            self.store.start_task_graph_run(TaskGraphRunRecord(
                task_id=self.task_id,
                epoch=self.epoch,
                run_root=self.run_root,
                root_function=self.root_function,
            ))
            self.store.start_run(self.task_id, self.task_id, "", self.root_function, "", {})
        except Exception as e:
            logger.warning("graph start_run failed: %s", e)

    def finish_run(self, status: str = "done") -> None:
        if not self._ready():
            return
        try:
            self.store.finish_run(self.task_id, status)
        except Exception as e:
            logger.warning("graph finish_run failed: %s", e)

    # ── 节点 (函数分析) ──────────────────────────────────────────────

    def record_node(self, *, func_id: str, func_name: str, file: str,
                    depth: int, status: str = "done",
                    analysis_status: str = "done") -> str:
        """记录一个函数节点 (分析开始/完成时调)。"""
        if not self._ready():
            return ""
        node_id = self._node_id(func_id)
        try:
            from ..vuln_store import TaskGraphNodeRecord
            self.store.upsert_task_graph_node(TaskGraphNodeRecord(
                node_id=node_id,
                task_id=self.task_id,
                epoch=self.epoch,
                func_id=func_id,
                function_name_resolved=func_name,
                function_name_raw=func_name,
                source_file=file,
                depth=depth,
                status=status,
                analysis_status=analysis_status,
                started_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                session_group_key=f"d{depth:02d}::{func_name}",
            ))
        except Exception as e:
            logger.warning("graph record_node failed: %s", e)
        return node_id

    # ── 边 (传播/callee/return/escape) ────────────────────────────────

    def record_edge(self, *, edge_id: str, source_func_id: str, target_func_id: str,
                    source_func_name: str, target_func_name: str,
                    target_func_raw: str = "", source_file: str = "",
                    target_file: str = "", edge_kind: str = "direct_call",
                    status: str = "discovered", call_line: int = 0,
                    source_taint: str = "", target_taint: str = "",
                    condition: str = "", depth: int = 0) -> None:
        """记录一条传播边。"""
        if not self._ready():
            return
        try:
            from ..vuln_store import TaskGraphEdgeRecord
            self.store.upsert_task_graph_edge(TaskGraphEdgeRecord(
                edge_id=edge_id,
                task_id=self.task_id,
                epoch=self.epoch,
                source_node_id=self._node_id(source_func_id),
                target_node_id=self._node_id(target_func_id) if target_func_id else "",
                source_func_id=source_func_id,
                target_func_id=target_func_id,
                source_function_resolved=source_func_name,
                target_function_resolved=target_func_name,
                target_function_raw=target_func_raw or target_func_name,
                source_file=source_file,
                target_file=target_file,
                edge_kind=edge_kind,
                status=status,
                call_line=call_line or None,
                source_taint_name=source_taint,
                target_taint_name=target_taint,
                display_order=max(depth, 0) * 1000 + (call_line or 0),
            ))
        except Exception as e:
            logger.warning("graph record_edge failed: %s", e)

    # ── 会话 ──────────────────────────────────────────────────────────

    def record_session(self, *, session_path: str, node_id: str = "",
                       edge_id: str = "", session_role: str = "",
                       session_kind: str = "", status: str = "done") -> str:
        """记录一个会话。"""
        if not self._ready():
            return ""
        relpath = self._session_relpath(session_path)
        try:
            from ..vuln_store import TaskGraphSessionRecord
            self.store.upsert_task_graph_session(TaskGraphSessionRecord(
                session_relpath=relpath,
                task_id=self.task_id,
                epoch=self.epoch,
                node_id=node_id,
                edge_id=edge_id,
                session_role=session_role,
                session_kind=session_kind,
                display_name=Path(session_path).stem,
                status=status,
                started_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            ))
        except Exception as e:
            logger.warning("graph record_session failed: %s", e)
        return relpath
