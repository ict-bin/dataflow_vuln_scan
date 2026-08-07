"""DAG 模式 MySQL 存储 (独立于 V2, 继承 SharedMysqlStore 共享基础设施)。

DAG 专属表 (与 V2 表完全独立, 删 DAG 模式只需删本文件 + dagflow/ 目录):
  dag_processed_taints  (func_id, taint_signature, task_id)  PK(func_id,taint_signature,task_id)
  dag_nodes              (func_id, taint_signature, node_id, ..., task_id)
  dag_edges              (func_id, taint_signature, edge_id, ..., task_id)
  dag_meta               (func_id, taint_signature, ..., task_id)

去重 (跨任务): find/try_reserve 不含 task_id; delete/clear 含 task_id。
DAG 数据 (nodes/edges/meta) 为 per-task 分析产出。

继承自 SharedMysqlStore:
  - 引擎管理 (db_name = dvs_<source_dir_id>, 同一数据库)
  - 共享表 DDL (functions, class_hierarchy, ...)
  - 共享方法 (upsert_function, insert_finding, get_task_finding_stats, ...)
  - _ensure_schema 被覆盖: 只建共享表 + DAG 表 (不建 V2 表)
  - clear_task_analysis 被覆盖: 只清 DAG 表
"""
from __future__ import annotations
import json, logging
from typing import Any

from ..db.shared_mysql import SharedMysqlStore, sa_text, _DDL_NO_TASK

logger = logging.getLogger("dvs.dagflow.dag_mysql_store")

_DDL_DAG = """
CREATE TABLE IF NOT EXISTS dag_processed_taints (
    func_id          VARCHAR(128) NOT NULL,
    taint_signature  VARCHAR(128) NOT NULL,
    task_id          VARCHAR(64) NOT NULL,
    analyzed_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (func_id, taint_signature, task_id)
);
CREATE INDEX idx_dag_processed_taints ON dag_processed_taints(func_id, taint_signature);
CREATE INDEX idx_dpt_task ON dag_processed_taints(task_id);
CREATE TABLE IF NOT EXISTS dag_nodes (
    func_id          VARCHAR(128) NOT NULL,
    taint_signature  VARCHAR(128) NOT NULL,
    node_id          INTEGER NOT NULL,
    line             INTEGER NOT NULL DEFAULT 0,
    taint            VARCHAR(128) NOT NULL,
    parents_json     TEXT,
    checks_json      TEXT,
    prune_json       TEXT,
    is_source        INTEGER NOT NULL DEFAULT 0,
    task_id          VARCHAR(64) NOT NULL,
    PRIMARY KEY (func_id, taint_signature, node_id, task_id)
);
CREATE TABLE IF NOT EXISTS dag_edges (
    func_id            VARCHAR(128) NOT NULL,
    taint_signature    VARCHAR(256) NOT NULL,
    edge_id            VARCHAR(128) NOT NULL,
    from_node          INTEGER NOT NULL,
    to_node            INTEGER NOT NULL,
    line               INTEGER NOT NULL DEFAULT 0,
    condition_json     TEXT,
    taints_json        TEXT,
    kind               VARCHAR(32) NOT NULL DEFAULT 'inside',
    sink_ref           VARCHAR(512),
    param_taints_json  TEXT,
    escape_subkind     VARCHAR(128),
    carrier            VARCHAR(128),
    escape_via          VARCHAR(128),
    task_id            VARCHAR(64) NOT NULL,
    PRIMARY KEY (func_id, taint_signature, edge_id, task_id)
);
CREATE INDEX idx_dag_edges ON dag_edges(sink_ref);
CREATE TABLE IF NOT EXISTS dag_meta (
    func_id         VARCHAR(128) NOT NULL,
    taint_signature VARCHAR(512) NOT NULL,
    self_contained  INTEGER NOT NULL DEFAULT 0,
    description     TEXT,
    taint_failed    INTEGER NOT NULL DEFAULT 0,
    task_id         VARCHAR(64) NOT NULL,
    PRIMARY KEY (func_id, taint_signature, task_id)
);
"""

_DAG_TASK_TABLES = ["dag_processed_taints", "dag_nodes", "dag_edges", "dag_meta"]


class DAGMysqlStore(SharedMysqlStore):
    """DAG 模式 MySQL 存储: 共享基础设施 + DAG 专属表/方法。

    与 V2 的 SharedMysqlStore 完全独立:
    - _ensure_schema 只建共享表 + DAG 表 (不建 V2 表)
    - clear_task_analysis 只清 DAG 表
    - DAG 方法集中在此文件, 删 DAG 模式只需删本文件 + dagflow/
    """

    def _ensure_schema(self):
        """覆盖: 建共享表 + DAG 表 (不建 V2 表)。"""
        def _is_benign_ddl_error(e: Exception) -> bool:
            msg = str(e).lower()
            return any(k in msg for k in ("already exists", "duplicate", "1060"))

        def _exec_multi(ddl: str):
            for s in ddl.split(";"):
                s = s.strip()
                if not s:
                    continue
                try:
                    with self._engine.connect() as conn:
                        conn.execute(sa_text(s))
                        conn.commit()
                except Exception as e:
                    if _is_benign_ddl_error(e):
                        logger.debug("DDL skip benign: %s (%s)", s[:60], e)
                    else:
                        logger.warning("DDL skip: %s (%s)", s[:60], e)

        # 共享表 (functions, class_hierarchy, ...)
        _exec_multi(_DDL_NO_TASK)
        # DAG 专属表
        _exec_multi(_DDL_DAG)
        # 迁移: 清除旧版本的 source_dir_id 冗余列 (共享方法)
        self._migrate_drop_source_dir_id()

    def clear_task_analysis(self):
        """覆盖: 只清 DAG 表 (WHERE task_id)。"""
        for t in _DAG_TASK_TABLES:
            try:
                with self._engine.begin() as conn:
                    conn.execute(sa_text(
                        f"DELETE FROM {t} WHERE task_id=:tid"),
                        {"tid": self.task_id})
            except Exception as e:
                logger.warning("[dag_mysql] clear %s failed: %s", t, str(e)[:120])
        logger.info("[dag_mysql] cleared task %s DAG records (source_dir=%s, tables=%s)",
                    self.task_id, self.source_dir_id, _DAG_TASK_TABLES)

    # ── DAG 去重 (跨任务: find/try_reserve 不含 task_id) ───────────────

    def dag_find_processed(self, func_id: str, taint_sig: str) -> bool:
        """跨任务: (func_id, taint_sig) 被任意任务分析过?"""
        with self._engine.connect() as conn:
            row = conn.execute(sa_text(
                "SELECT 1 FROM dag_processed_taints WHERE func_id=:fid AND taint_signature=:ts LIMIT 1"),
                {"fid": func_id, "ts": taint_sig}).fetchone()
            return row is not None

    def dag_try_reserve(self, func_id: str, taint_sig: str) -> bool:
        """跨任务原子占位: INSERT...WHERE NOT EXISTS。
        rowcount=1 → 本任务占位成功; rowcount=0 → 已被其他任务分析过。"""
        with self._engine.connect() as conn:
            r = conn.execute(sa_text(
                "INSERT INTO dag_processed_taints (func_id,taint_signature,task_id) "
                "SELECT :fid,:ts,:tid FROM DUAL "
                "WHERE NOT EXISTS ("
                "  SELECT 1 FROM dag_processed_taints WHERE func_id=:fid AND taint_signature=:ts)"),
                {"fid": func_id, "ts": taint_sig, "tid": self.task_id})
            conn.commit()
            return r.rowcount > 0

    def dag_delete_processed(self, func_id: str, taint_sig: str):
        """analyze 失败时删本任务占位 (WHERE task_id)。"""
        with self._engine.connect() as conn:
            conn.execute(sa_text(
                "DELETE FROM dag_processed_taints WHERE func_id=:fid AND taint_signature=:ts AND task_id=:tid"),
                {"fid": func_id, "ts": taint_sig, "tid": self.task_id})
            conn.commit()

    # ── DAG 存取 ─────────────────────────────────────────────────────────

    def save_dag(self, func_id: str, taint_sig: str, nodes: list[dict], edges: list[dict], meta: dict):
        """保存 DAG (先删旧再插, per-task: WHERE func_id+taint_sig+task_id)。"""
        tid = self.task_id
        with self._engine.connect() as conn:
            for t in ("dag_nodes", "dag_edges", "dag_meta"):
                conn.execute(sa_text(
                    f"DELETE FROM {t} WHERE func_id=:fid AND taint_signature=:ts AND task_id=:tid"),
                    {"fid": func_id, "ts": taint_sig, "tid": tid})
            for n in nodes:
                conn.execute(sa_text(
                    """INSERT IGNORE INTO dag_nodes (func_id,taint_signature,node_id,line,taint,
                    parents_json,checks_json,prune_json,is_source,task_id)
                    VALUES (:fid,:ts,:nid,:ln,:t,:p,:c,:pr,:is,:tid)"""),
                    {"fid": func_id, "ts": taint_sig, "nid": n["node_id"], "ln": n["line"],
                     "t": n["taint"], "p": json.dumps(n.get("parents", []), ensure_ascii=False),
                     "c": json.dumps(n.get("checks", []), ensure_ascii=False),
                     "pr": json.dumps(n.get("prune", {}), ensure_ascii=False) if n.get("prune") else "",
                     "is": 1 if n.get("is_source") else 0, "tid": tid})
            for e in edges:
                conn.execute(sa_text(
                    """INSERT IGNORE INTO dag_edges (func_id,taint_signature,edge_id,from_node,to_node,
                    line,condition_json,taints_json,kind,sink_ref,param_taints_json,escape_subkind,carrier,escape_via,task_id)
                    VALUES (:fid,:ts,:eid,:fn,:tn,:ln,:cond,:taints,:kind,:sr,:pt,:es,:car,:ev,:tid)"""),
                    {"fid": func_id, "ts": taint_sig, "eid": e["edge_id"],
                     "fn": e["from_node"], "tn": e["to_node"], "ln": e["line"],
                     "cond": json.dumps(e.get("condition", []), ensure_ascii=False),
                     "taints": json.dumps(e.get("taints", []), ensure_ascii=False),
                     "kind": e.get("kind", "inside"), "sr": e.get("sink_ref", ""),
                     "pt": json.dumps(e.get("param_taints", []), ensure_ascii=False),
                     "es": e.get("escape_subkind", ""), "car": e.get("carrier", ""),
                     "ev": e.get("escape_via", ""), "tid": tid})
            conn.execute(sa_text(
                """INSERT IGNORE INTO dag_meta (func_id,taint_signature,self_contained,description,taint_failed,task_id)
                VALUES (:fid,:ts,:sc,:desc,:tf,:tid)
                ON DUPLICATE KEY UPDATE self_contained=VALUES(self_contained),
                description=VALUES(description),taint_failed=VALUES(taint_failed)"""),
                {"fid": func_id, "ts": taint_sig,
                 "sc": 1 if meta.get("self_contained") else 0,
                 "desc": meta.get("description", ""),
                 "tf": 1 if meta.get("taint_failed") else 0, "tid": tid})
            conn.commit()

    def load_dag(self, func_id: str, taint_sig: str, task_id: str) -> Any:
        """从 MySQL 加载 DAG (per-task)。返回 TaintDAG | None。"""
        from .models import TaintDAG, TaintNode, TaintEdge, PruneSignal
        with self._engine.connect() as conn:
            rows_n = conn.execute(sa_text(
                "SELECT * FROM dag_nodes WHERE func_id=:fid AND taint_signature=:ts AND task_id=:tid ORDER BY node_id"),
                {"fid": func_id, "ts": taint_sig, "tid": task_id}).fetchall()
            if not rows_n:
                return None
            nodes: list[TaintNode] = []
            for r in rows_n:
                n = TaintNode(
                    id=r.node_id, line=r.line, taint=r.taint,
                    parents=json.loads(r.parents_json or "[]"),
                    checks=list(json.loads(r.checks_json or "[]")),
                    prune=PruneSignal.from_dict(json.loads(r.prune_json) if r.prune_json else None),
                    is_source=bool(r.is_source))
                nodes.append(n)
            by_id = {n.id: n for n in nodes}
            rows_e = conn.execute(sa_text(
                "SELECT * FROM dag_edges WHERE func_id=:fid AND taint_signature=:ts AND task_id=:tid ORDER BY from_node"),
                {"fid": func_id, "ts": taint_sig, "tid": task_id}).fetchall()
            for r in rows_e:
                e = TaintEdge(
                    to_node=r.to_node, line=r.line,
                    condition=list(json.loads(r.condition_json or "[]")),
                    taints=json.loads(r.taints_json or "[]"),
                    kind=r.kind, sink_ref=r.sink_ref,
                    param_taints=json.loads(r.param_taints_json or "[]"),
                    escape_subkind=r.escape_subkind, carrier=r.carrier, escape_via=r.escape_via)
                fn = by_id.get(r.from_node)
                if fn is not None:
                    fn.children.append(e)
            rows_m = conn.execute(sa_text(
                "SELECT * FROM dag_meta WHERE func_id=:fid AND taint_signature=:ts AND task_id=:tid"),
                {"fid": func_id, "ts": taint_sig, "tid": task_id}).fetchall()
            m = rows_m[0] if rows_m else None
            return TaintDAG(
                func_id=func_id, taint_signature=taint_sig, nodes=nodes,
                self_contained=bool(m.self_contained) if m else False,
                description=(m.description if m else ""),
                taint_failed=bool(m.taint_failed) if m else False)

    # ── 跨函数查询 (per-task) ───────────────────────────────────────────

    def dag_get_callers(self, func_id: str, task_id: str) -> list[tuple[str, str]]:
        """反查本任务中哪些 DAG 有 callee 边指向本 func。"""
        with self._engine.connect() as conn:
            rows = conn.execute(sa_text(
                "SELECT DISTINCT func_id, taint_signature FROM dag_edges "
                "WHERE kind='callee' AND sink_ref=:fid AND task_id=:tid"),
                {"fid": func_id, "tid": task_id}).fetchall()
            return [(r[0], r[1]) for r in rows] if rows else []

    def dag_list_analyzed(self, task_id: str) -> list[tuple[str, str]]:
        """本任务所有已分析的 (func_id, taint_signature)。"""
        with self._engine.connect() as conn:
            rows = conn.execute(sa_text(
                "SELECT func_id, taint_signature FROM dag_processed_taints WHERE task_id=:tid"),
                {"tid": task_id}).fetchall()
            return [(r[0], r[1]) for r in rows] if rows else []

    def dag_list_outgoing(self, func_id: str, taint_sig: str, task_id: str) -> list[dict]:
        """本 DAG 的传出边 (callee/return/extern/container)。"""
        with self._engine.connect() as conn:
            rows = conn.execute(sa_text(
                "SELECT * FROM dag_edges WHERE func_id=:fid AND taint_signature=:ts AND task_id=:tid "
                "AND kind IN ('callee','return','extern','container')"),
                {"fid": func_id, "ts": taint_sig, "tid": task_id}).fetchall()
            return [dict(r._mapping) for r in rows] if rows else []


def create_dag_mysql_store(mysql_url: str, source_root: str, task_id: str,
                           project_id: str = "") -> DAGMysqlStore | None:
    """工厂: 创建 DAGMysqlStore, 失败返回 None。"""
    try:
        return DAGMysqlStore(mysql_url, "dagflow", source_root, task_id, project_id=project_id)
    except Exception as e:
        logger.warning("create DAGMysqlStore failed: %s", e)
        return None
