"""MySQL 读取层 (Step 3: worker 读 MySQL, 回退 SQLite)。

SharedMysqlStore 的读取方法, 返回与 DataflowStore 相同的 record 类型。
DataflowStore 在 SQLite 查不到时, 调用此处作为 fallback。

设计原则:
- 只读不写 (写由 SharedMysqlStore 的 upsert_* 方法负责)
- 返回值与 DataflowStore 的同名方法签名一致
- 查询失败返回空/None, 不抛异常 (不阻塞主流程)
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import text as sa_text

from ..dataflow_v2.models import (
    FunctionRecord, OrchestrationEdge, ProcessedTaint, PropagationRecord,
    TaintParamInfo, TaintRecord, _norm_sig, _sha,
)

logger = logging.getLogger("dvs.db.mysql_read")


def _dict_to_function(d: dict) -> FunctionRecord:
    """MySQL row dict → FunctionRecord (MySQL functions 表无 processed_taints 列)。"""
    return FunctionRecord(
        file=d.get("file") or "",
        name=d.get("name") or "",
        signature=d.get("signature") or "",
        start_line=int(d.get("start_line") or 0),
        end_line=int(d.get("end_line") or 0),
        func_hash=d.get("func_hash") or "",
        description=d.get("description") or "",
        func_id=d.get("func_id") or "",
    )


def _dict_to_taint(d: dict) -> TaintRecord:
    return TaintRecord(
        taint_id=d.get("taint_id") or "",
        func_id=d.get("func_id") or "",
        name=d.get("name") or "",
        signature=d.get("signature") or "",
        file=d.get("file") or "",
        function=d.get("function") or "",
        next_propagations=json.loads(d.get("next_propagations") or "[]"),
        description=d.get("description") or "",
    )


def _dict_to_propagation(d: dict) -> PropagationRecord:
    from ..dataflow_v2.store import _validation_from_dict
    vals = json.loads(d.get("validations") or "[]")
    return PropagationRecord(
        prop_id=d.get("prop_id") or "",
        source_func_id=d.get("source_func_id") or "",
        source_taint_name=d.get("source_taint_name") or "",
        source_taint_signature=d.get("source_taint_signature") or "",
        target_taint_name=d.get("target_taint_name") or "",
        target_taint_signature=d.get("target_taint_signature") or "",
        target_func_id=d.get("target_func_id") or "",
        target_function=d.get("target_function") or "",
        target_file=d.get("target_file") or "",
        call_line=int(d.get("call_line") or 0),
        condition=d.get("condition") or "",
        is_external=bool(d.get("is_external")),
        is_indirect_call=bool(d.get("is_indirect_call")),
        escape_kind=d.get("escape_kind") or "",
        carrier=d.get("carrier") or "",
        escape_via=d.get("escape_via") or "",
        actual_args=json.loads(d.get("actual_args") or "[]"),
        validations=[_validation_from_dict(v) for v in vals if isinstance(v, dict)],
        description=d.get("description") or "",
    )


def _dict_to_edge(d: dict) -> OrchestrationEdge:
    return OrchestrationEdge(
        edge_id=d.get("edge_id") or "",
        path_id=d.get("path_id") or "",
        source_function=d.get("source_function") or "",
        source_signature=d.get("source_signature") or "",
        source_func_id=d.get("source_func_id") or "",
        target_function=d.get("target_function") or "",
        target_signature=d.get("target_signature") or "",
        target_func_id=d.get("target_func_id") or "",
        taint_params=TaintParamInfo.from_json(d.get("taint_params") or "{}"),
        depth=int(d.get("depth") or 0),
        edge_order=int(d.get("edge_order") or 0),
        status=d.get("status") or "pending",
    )


def _dict_to_processed_taint(d: dict) -> ProcessedTaint:
    return ProcessedTaint(
        taint_params=json.loads(d.get("taint_params") or "[]"),
        taint_signature=d.get("taint_signature") or "",
        pre_validations=[],
        pre_validation_signature=d.get("pre_validation_signature") or "",
        sessions_path=d.get("sessions_path") or "",
    )


class MysqlReadMixin:
    """为 SharedMysqlStore 添加读取方法 (mixin, 不单独实例化)。"""

    # ── functions 表 ────────────────────────────────────────────────

    def read_function(self, func_id: str) -> FunctionRecord | None:
        """按 func_id 查函数。"""
        try:
            with self._engine.connect() as conn:
                row = conn.execute(sa_text(
                    "SELECT * FROM functions WHERE func_id=:fid"
                ), {"fid": func_id}).fetchone()
                return _dict_to_function(dict(row._mapping)) if row else None
        except Exception:
            return None

    def read_functions(self, name: str, file: str = "") -> list[FunctionRecord]:
        """按名查全部候选函数 (对应 DataflowStore.find_functions 的 MySQL 版)。

        匹配逻辑与 SQLite 版一致:
        1. 精确 name 匹配 (带可选 file 过滤)
        2. 限定名退回尾名精确匹配
        3. 尾名后缀匹配 %::tail
        """
        sid = self.source_dir_id
        try:
            with self._engine.connect() as conn:
                # Layer 1: exact name
                if file:
                    rows = conn.execute(sa_text(
                        "SELECT * FROM functions WHERE name=:nm AND `file`=:fl "
                        "ORDER BY start_line"),
                        {"sid": sid, "nm": name, "fl": file}).fetchall()
                else:
                    rows = conn.execute(sa_text(
                        "SELECT * FROM functions WHERE name=:nm "
                        "ORDER BY start_line"),
                        {"sid": sid, "nm": name}).fetchall()
                if rows:
                    return [_dict_to_function(dict(r._mapping)) for r in rows]

                # Layer 2: tail exact (for Class::method → method)
                tail = name.split("::")[-1].strip() if "::" in name else name
                if not tail:
                    return []
                if file:
                    rows = conn.execute(sa_text(
                        "SELECT * FROM functions WHERE name=:nm AND `file`=:fl "
                        "ORDER BY start_line"),
                        {"sid": sid, "nm": tail, "fl": file}).fetchall()
                else:
                    rows = conn.execute(sa_text(
                        "SELECT * FROM functions WHERE name=:nm "
                        "ORDER BY start_line"),
                        {"sid": sid, "nm": tail}).fetchall()
                if rows:
                    return [_dict_to_function(dict(r._mapping)) for r in rows]

                # Layer 3: suffix %::tail → use name_tail index
                if file:
                    rows = conn.execute(sa_text(
                        "SELECT * FROM functions WHERE name_tail=:nm AND `file`=:fl "
                        "ORDER BY start_line"),
                        {"sid": sid, "nm": tail, "fl": file}).fetchall()
                else:
                    rows = conn.execute(sa_text(
                        "SELECT * FROM functions WHERE name_tail=:nm "
                        "ORDER BY start_line"),
                        {"sid": sid, "nm": tail}).fetchall()
                return [_dict_to_function(dict(r._mapping)) for r in rows]
        except Exception:
            return []

    # ── processed_taints 表 ─────────────────────────────────────────

    def read_processed_taint(self, func_id: str, taint_signature: str) -> ProcessedTaint | None:
        """按 (func_id, taint_signature) 查已处理污点。"""
        ts = _norm_sig(taint_signature)
        try:
            with self._engine.connect() as conn:
                row = conn.execute(sa_text(
                    "SELECT taint_signature, pre_validation_signature, taint_params, sessions_path "
                    "FROM processed_taints "
                    "WHERE func_id=:fid AND taint_signature=:ts LIMIT 1"),
                    {"fid": func_id, "ts": ts}).fetchone()
                return _dict_to_processed_taint(dict(row._mapping)) if row else None
        except Exception:
            return None

    # ── taints 表 ────────────────────────────────────────────────────

    def read_taints_in_function(self, func_id: str) -> list[TaintRecord]:
        try:
            with self._engine.connect() as conn:
                rows = conn.execute(sa_text(
                    "SELECT * FROM taints WHERE func_id=:fid"),
                    {"fid": func_id}).fetchall()
                return [_dict_to_taint(dict(r._mapping)) for r in rows]
        except Exception:
            return []

    # ── propagations 表 ──────────────────────────────────────────────

    def read_propagations_from(self, func_id: str) -> list[PropagationRecord]:
        try:
            with self._engine.connect() as conn:
                rows = conn.execute(sa_text(
                    "SELECT * FROM propagations WHERE source_func_id=:fid"),
                    {"fid": func_id}).fetchall()
                return [_dict_to_propagation(dict(r._mapping)) for r in rows]
        except Exception:
            return []

    def read_propagation(self, prop_id: str) -> PropagationRecord | None:
        try:
            with self._engine.connect() as conn:
                row = conn.execute(sa_text(
                    "SELECT * FROM propagations WHERE prop_id=:pid"),
                    {"pid": prop_id}).fetchone()
                return _dict_to_propagation(dict(row._mapping)) if row else None
        except Exception:
            return None

    # ── orchestration 表 ─────────────────────────────────────────────

    def read_path_edges(self, path_id: str) -> list[OrchestrationEdge]:
        try:
            with self._engine.connect() as conn:
                rows = conn.execute(sa_text(
                    "SELECT * FROM orchestration WHERE path_id=:pid "
                    "ORDER BY edge_order"),
                    {"pid": path_id}).fetchall()
                return [_dict_to_edge(dict(r._mapping)) for r in rows]
        except Exception:
            return []

    def read_pending_edges(self) -> list[OrchestrationEdge]:
        try:
            with self._engine.connect() as conn:
                rows = conn.execute(sa_text(
                    "SELECT * FROM orchestration WHERE `status`='pending' "
                    "ORDER BY edge_order"),
                    {}).fetchall()
                return [_dict_to_edge(dict(r._mapping)) for r in rows]
        except Exception:
            return []

    # ── 共享数据 (源码级, 无 task_id) ────────────────────────────────

    def read_list_functions(self) -> list[FunctionRecord]:
        try:
            with self._engine.connect() as conn:
                rows = conn.execute(sa_text(
                    "SELECT * FROM functions WHERE 1=1"),
                    {}).fetchall()
                return [_dict_to_function(dict(r._mapping)) for r in rows]
        except Exception:
            return []

    def count_functions(self) -> int:
        """COUNT(*) 快速计数 (避免加载全部行)。"""
        try:
            with self._engine.connect() as conn:
                return conn.execute(sa_text(
                    "SELECT COUNT(*) FROM functions WHERE 1=1"),
                    {}).scalar()
        except Exception:
            return 0

    def read_functions_by_file(self, file: str) -> list[FunctionRecord]:
        """按文件查函数 (用 idx_func_file 索引)。"""
        try:
            with self._engine.connect() as conn:
                rows = conn.execute(sa_text(
                    "SELECT * FROM functions WHERE `file`=:fl "
                    "ORDER BY start_line"),
                    {"fl": file}).fetchall()
                return [_dict_to_function(dict(r._mapping)) for r in rows]
        except Exception:
            return []

    def read_files_including(self, header: str) -> list[str]:
        try:
            with self._engine.connect() as conn:
                rows = conn.execute(sa_text(
                    "SELECT `file` FROM include_index WHERE header=:h"),
                    {"h": header}).fetchall()
                return [r[0] for r in rows]
        except Exception:
            return []

    def read_bases(self, class_name: str) -> list[str]:
        try:
            with self._engine.connect() as conn:
                row = conn.execute(sa_text(
                    "SELECT bases FROM class_hierarchy WHERE class_name=:cn"),
                    {"cn": class_name}).fetchone()
                return json.loads(row[0] or "[]") if row else []
        except Exception:
            return []

    def read_all_ancestors(self, class_name: str) -> list[str]:
        visited: set[str] = set()
        queue = [class_name]
        while queue:
            cls = queue.pop(0)
            if cls in visited:
                continue
            visited.add(cls)
            for base in self.read_bases(cls):
                if base not in visited:
                    queue.append(base)
        visited.discard(class_name)
        return list(visited)

    def read_all_descendants(self, class_name: str) -> list[str]:
        visited = {class_name}
        try:
            with self._engine.connect() as conn:
                rows = conn.execute(sa_text(
                    "SELECT class_name, bases FROM class_hierarchy WHERE 1=1"),
                    {}).fetchall()
            changed = True
            while changed:
                changed = False
                for r in rows:
                    cn = r[0]
                    if cn in visited:
                        continue
                    bases = json.loads(r[1] or "[]")
                    if any(b in visited for b in bases):
                        visited.add(cn)
                        changed = True
        except Exception:
            pass
        visited.discard(class_name)
        return list(visited)

    def read_member_declaring_class(self, class_name: str, member_name: str) -> str | None:
        candidates = [class_name] + self.read_all_ancestors(class_name)
        try:
            with self._engine.connect() as conn:
                for cls in candidates:
                    row = conn.execute(sa_text(
                        "SELECT class_name FROM class_members "
                        "WHERE class_name=:cn AND member_name=:mn"),
                        {"cn": cls, "mn": member_name}).fetchone()
                    if row:
                        return cls
        except Exception:
            pass
        return None

    def read_class_scope_methods(self, class_name: str, member_name: str = "") -> list[str]:
        if member_name:
            declaring = self.read_member_declaring_class(class_name, member_name) or class_name
        else:
            declaring = class_name
        classes = {declaring} | set(self.read_all_descendants(declaring))
        result: list[str] = []
        try:
            with self._engine.connect() as conn:
                for cls in classes:
                    rows = conn.execute(sa_text(
                        "SELECT name FROM functions WHERE name LIKE :pat"),
                        {"pat": f"{cls}::%"}).fetchall()
                    result.extend(r[0] for r in rows)
        except Exception:
            pass
        return result

    def read_functions_with_type_in_signature(self, type_name: str) -> list[str]:
        try:
            with self._engine.connect() as conn:
                rows = conn.execute(sa_text(
                    "SELECT name FROM functions WHERE signature LIKE :pat"),
                    {"pat": f"%{type_name}%"}).fetchall()
                return [r[0] for r in rows]
        except Exception:
            return []

    # ── indexing_files (源码级共享) ──────────────────────────────────

    def read_is_indexed(self, file_path: str) -> bool:
        try:
            with self._engine.connect() as conn:
                row = conn.execute(sa_text(
                    "SELECT 1 FROM indexing_files WHERE file_path=:fp"),
                    {"fp": file_path}).fetchone()
                return row is not None
        except Exception:
            return False

    def read_is_indexing(self, file_path: str) -> bool:
        try:
            with self._engine.connect() as conn:
                row = conn.execute(sa_text(
                    "SELECT 1 FROM indexing_files WHERE file_path=:fp AND started_at > 0"),
                    {"fp": file_path}).fetchone()
                return row is not None
        except Exception:
            return False

    def add_indexing_file(self, file_path: str) -> None:
        try:
            with self._engine.connect() as conn:
                conn.execute(sa_text(
                    "INSERT IGNORE INTO indexing_files (file_path, started_at) "
                    "VALUES (:fp, :ts)"),
                    {"fp": file_path, "ts": __import__("time").time()})
                conn.commit()
        except Exception:
            pass

    def finish_indexing_file(self, file_path: str) -> None:
        try:
            with self._engine.connect() as conn:
                conn.execute(sa_text(
                    "UPDATE indexing_files SET started_at=0 WHERE file_path=:fp"),
                    {"fp": file_path})
                conn.commit()
        except Exception:
            pass
