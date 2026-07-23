"""MySQL 图谱存储读取层 (Step 2: API 读 MySQL 不读 SQLite)。

在 secflow 数据库中创建 task_graph 镜像表, worker 写 vuln-scan.sqlite 时
同步写 MySQL, API 优先读 MySQL, 回退读 SQLite。

表名加 dvs_ 前缀避免与现有 secflow 表冲突:
  dvs_task_graph_runs
  dvs_task_graph_nodes
  dvs_task_graph_edges
  dvs_task_graph_sessions
  dvs_vuln_findings
  dvs_analysis_runs
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

from sqlalchemy import create_engine, text as sa_text
from sqlalchemy.engine import Engine

logger = logging.getLogger("dvs.db.mysql_graph")

_ENGINE: Engine | None = None
_ENGINE_LOCK = threading.Lock()

_DDL = """
CREATE TABLE IF NOT EXISTS dvs_task_graph_runs (
    task_id VARCHAR(64) PRIMARY KEY,
    epoch VARCHAR(8) NOT NULL DEFAULT '',
    run_root TEXT,
    graph_version INTEGER NOT NULL DEFAULT 1,
    root_function VARCHAR(256) NOT NULL DEFAULT '',
    generated_at DOUBLE NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS dvs_task_graph_nodes (
    node_id VARCHAR(256) PRIMARY KEY,
    task_id VARCHAR(64) NOT NULL,
    epoch VARCHAR(8) NOT NULL DEFAULT '',
    func_id VARCHAR(128) NOT NULL DEFAULT '',
    function_name_resolved VARCHAR(256) NOT NULL DEFAULT '',
    function_name_raw VARCHAR(256) NOT NULL DEFAULT '',
    source_file VARCHAR(512) NOT NULL DEFAULT '',
    depth INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'discovered',
    analysis_status VARCHAR(32) NOT NULL DEFAULT 'pending',
    findings_count INTEGER NOT NULL DEFAULT 0,
    started_at VARCHAR(40),
    finished_at VARCHAR(40),
    primary_session_relpath TEXT,
    session_group_key VARCHAR(256) NOT NULL DEFAULT '',
    visible_in_tree INTEGER NOT NULL DEFAULT 1,
    visible_in_all_propagations INTEGER NOT NULL DEFAULT 1,
    extra_json TEXT
);
CREATE INDEX ix_dvs_tgn_task ON dvs_task_graph_nodes(task_id, depth);
CREATE TABLE IF NOT EXISTS dvs_task_graph_edges (
    edge_id VARCHAR(256) PRIMARY KEY,
    task_id VARCHAR(64) NOT NULL,
    epoch VARCHAR(8) NOT NULL DEFAULT '',
    source_node_id VARCHAR(256) NOT NULL DEFAULT '',
    target_node_id VARCHAR(256) NOT NULL DEFAULT '',
    source_func_id VARCHAR(128) NOT NULL DEFAULT '',
    target_func_id VARCHAR(128) NOT NULL DEFAULT '',
    source_function_resolved VARCHAR(256) NOT NULL DEFAULT '',
    target_function_resolved VARCHAR(256) NOT NULL DEFAULT '',
    target_function_raw VARCHAR(256) NOT NULL DEFAULT '',
    source_file VARCHAR(512) NOT NULL DEFAULT '',
    target_file VARCHAR(512) NOT NULL DEFAULT '',
    edge_kind VARCHAR(64) NOT NULL DEFAULT 'direct_call',
    status VARCHAR(32) NOT NULL DEFAULT 'discovered',
    reason_code VARCHAR(128) NOT NULL DEFAULT '',
    reason_message TEXT,
    reason_source VARCHAR(64) NOT NULL DEFAULT '',
    source_prop_id VARCHAR(256) NOT NULL DEFAULT '',
    source_orchestration_edge_id VARCHAR(256) NOT NULL DEFAULT '',
    call_line INTEGER,
    source_taint_name VARCHAR(256) NOT NULL DEFAULT '',
    target_taint_name VARCHAR(256) NOT NULL DEFAULT '',
    validations_json TEXT,
    actual_args_json TEXT,
    tracker_type VARCHAR(64) NOT NULL DEFAULT '',
    tracker_result_json TEXT,
    display_order INTEGER NOT NULL DEFAULT 0,
    visible_in_tree INTEGER NOT NULL DEFAULT 1,
    visible_in_all_propagations INTEGER NOT NULL DEFAULT 1,
    created_at VARCHAR(40),
    updated_at VARCHAR(40)
);
CREATE INDEX ix_dvs_tge_task ON dvs_task_graph_edges(task_id, display_order);
CREATE TABLE IF NOT EXISTS dvs_task_graph_sessions (
    session_relpath VARCHAR(512) PRIMARY KEY,
    task_id VARCHAR(64) NOT NULL,
    epoch VARCHAR(8) NOT NULL DEFAULT '',
    node_id VARCHAR(256) NOT NULL DEFAULT '',
    edge_id VARCHAR(256) NOT NULL DEFAULT '',
    session_role VARCHAR(64) NOT NULL DEFAULT '',
    session_kind VARCHAR(64) NOT NULL DEFAULT '',
    display_name VARCHAR(256) NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'unknown',
    started_at VARCHAR(40),
    ended_at VARCHAR(40),
    mtime DOUBLE,
    event_count INTEGER NOT NULL DEFAULT 0,
    extra_json TEXT
);
CREATE INDEX ix_dvs_tgs_task ON dvs_task_graph_sessions(task_id);
CREATE TABLE IF NOT EXISTS dvs_vuln_findings (
    finding_id VARCHAR(128) NOT NULL,
    run_id VARCHAR(64) NOT NULL,
    task_id VARCHAR(64) NOT NULL DEFAULT '',
    node_id VARCHAR(256) NOT NULL DEFAULT '',
    edge_id VARCHAR(256) NOT NULL DEFAULT '',
    source_file VARCHAR(512) NOT NULL DEFAULT '',
    function_name VARCHAR(256) NOT NULL DEFAULT '',
    line VARCHAR(64) NOT NULL DEFAULT '',
    vuln_type VARCHAR(64) NOT NULL DEFAULT 'unknown',
    severity VARCHAR(32) NOT NULL DEFAULT 'unknown',
    title VARCHAR(512) NOT NULL DEFAULT '',
    summary TEXT,
    evidence TEXT,
    exploitability TEXT,
    confidence DOUBLE NOT NULL DEFAULT 0,
    output_dir TEXT,
    report_status VARCHAR(32) NOT NULL DEFAULT '',
    report_case_id VARCHAR(128) NOT NULL DEFAULT '',
    code_snippet TEXT,
    code_explanation TEXT,
    fix_suggestion TEXT,
    created_at VARCHAR(40) NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX ux_dvs_vf_task_finding ON dvs_vuln_findings(task_id, finding_id);
CREATE INDEX ix_dvs_vf_run ON dvs_vuln_findings(run_id);
CREATE INDEX ix_dvs_vf_task ON dvs_vuln_findings(task_id);
CREATE TABLE IF NOT EXISTS dvs_analysis_runs (
    run_id VARCHAR(64) PRIMARY KEY,
    task_id VARCHAR(64) NOT NULL,
    root_file VARCHAR(512) NOT NULL DEFAULT '',
    root_function VARCHAR(256) NOT NULL DEFAULT '',
    source_root TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'running',
    started_at DOUBLE NOT NULL DEFAULT 0,
    finished_at DOUBLE,
    config_json TEXT
);
CREATE INDEX ix_dvs_ar_task ON dvs_analysis_runs(task_id);
"""

_POST_DDL_MIGRATIONS = (
    """
    ALTER TABLE dvs_vuln_findings
        DROP PRIMARY KEY,
        ADD PRIMARY KEY (task_id, finding_id)
    """,
    """
    ALTER TABLE dvs_vuln_findings
        MODIFY finding_id VARCHAR(128) NOT NULL
    """,
    "CREATE INDEX ix_dvs_vf_finding ON dvs_vuln_findings(finding_id)",
)


def _get_engine(mysql_url: str) -> Engine:
    """获取/缓存 engine (连 secflow 库)。"""
    global _ENGINE
    with _ENGINE_LOCK:
        if _ENGINE is not None:
            return _ENGINE
        eng = create_engine(mysql_url, pool_size=2, max_overflow=3,
                           pool_pre_ping=True, pool_recycle=3600)
        with eng.connect() as conn:
            for stmt in _DDL.split(";"):
                s = stmt.strip()
                if s:
                    try:
                        conn.execute(sa_text(s))
                    except Exception as e:
                        logger.debug("DDL skip: %s", e)
            for stmt in _POST_DDL_MIGRATIONS:
                try:
                    conn.execute(sa_text(stmt))
                except Exception as e:
                    logger.debug("DDL post-migration skip: %s", e)
            conn.commit()
        _ENGINE = eng
        return eng


class MysqlGraphStore:
    """MySQL 图谱读取层。API 优先用此类读 MySQL, 回退读 SQLite VulnScanStore。"""

    def __init__(self, mysql_url: str, project_id: str = "",
                 source_dir_id: str = "", source_root: str = "") -> None:
        # 每个源码目录独立一个数据库: dvs_<source_dir_id>
        db_name = f"dvs_{source_dir_id}" if source_dir_id else (
            f"dvs_{project_id[:12]}" if project_id else None)
        if db_name:
            # Handle URLs with/without database part
            if "?" in mysql_url:
                base_url = mysql_url.rsplit("/", 1)[0]
            elif mysql_url.endswith("/"):
                base_url = mysql_url[:-1]
            else:
                last_slash = mysql_url.rfind("/")
                if last_slash > mysql_url.find("//") + 1:
                    base_url = mysql_url[:last_slash]
                else:
                    base_url = mysql_url
            from sqlalchemy import create_engine, text as sa_text
            try:
                admin_eng = create_engine(f"{base_url}/mysql?charset=utf8mb4", pool_pre_ping=True, pool_recycle=3600)
                with admin_eng.connect() as conn:
                    conn.execute(sa_text(f"CREATE DATABASE IF NOT EXISTS `{db_name}` DEFAULT CHARSET utf8mb4"))
                    conn.commit()
                admin_eng.dispose()
            except Exception:
                pass
            mysql_url = f"{base_url}/{db_name}?charset=utf8mb4"
        self._engine = _get_engine(mysql_url)

    # ── 读取层 (API 调) ──────────────────────────────────────────────

    def export_task_graph_view(self, task_id: str) -> dict[str, Any]:
        """从 MySQL 读取任务图谱视图 (与 VulnScanStore.export_task_graph_view 同构)。"""
        with self._engine.connect() as conn:
            run = conn.execute(sa_text(
                "SELECT * FROM dvs_task_graph_runs WHERE task_id=:tid"),
                {"tid": task_id}).fetchone()
            nodes = [dict(r._mapping) for r in conn.execute(sa_text(
                "SELECT * FROM dvs_task_graph_nodes WHERE task_id=:tid "
                "ORDER BY depth, function_name_resolved, node_id"),
                {"tid": task_id}).fetchall()]
            edges = [dict(r._mapping) for r in conn.execute(sa_text(
                "SELECT * FROM dvs_task_graph_edges WHERE task_id=:tid "
                "ORDER BY display_order, source_function_resolved, edge_id"),
                {"tid": task_id}).fetchall()]
            sessions = [dict(r._mapping) for r in conn.execute(sa_text(
                "SELECT * FROM dvs_task_graph_sessions WHERE task_id=:tid "
                "ORDER BY session_relpath"),
                {"tid": task_id}).fetchall()]
            findings = [dict(r._mapping) for r in conn.execute(sa_text(
                "SELECT vf.* FROM dvs_vuln_findings vf "
                "JOIN dvs_analysis_runs ar ON ar.run_id = vf.run_id "
                "WHERE ar.task_id = :tid "
                "ORDER BY vf.created_at, vf.finding_id"),
                {"tid": task_id}).fetchall()]

        run_dict = dict(run._mapping) if run else {}
        run_root = str(run_dict.get("run_root") or "")
        epoch = str(run_dict.get("epoch") or "")

        # MySQL TEXT columns are nullable; replace None with appropriate defaults
        # to match SQLite's NOT NULL DEFAULT behavior for pydantic models.
        _JSON_DEFAULTS = {"extra_json": "{}", "tracker_result_json": "{}",
                         "validations_json": "[]", "actual_args_json": "[]"}
        _KEEP_NONE = {"mtime", "confidence", "call_line", "started_at",
                       "ended_at", "created_at", "updated_at",
                       "finished_at", "started_at", "finished_at"}
        for row_list in (nodes, edges, sessions, findings):
            for row in row_list:
                for key in list(row.keys()):
                    if row[key] is None:
                        if key in _KEEP_NONE:
                            pass  # leave as None (pydantic Optional handles it)
                        elif key in _JSON_DEFAULTS:
                            row[key] = _JSON_DEFAULTS[key]
                        else:
                            row[key] = ""  # str fields

        node_by_id = {str(n.get("node_id") or ""): n for n in nodes}
        edges_by_source: dict[str, list[dict]] = {}
        for edge in edges:
            if int(edge.get("visible_in_tree") or 0) != 1:
                continue
            edges_by_source.setdefault(
                str(edge.get("source_node_id") or ""), []).append(edge)
        for el in edges_by_source.values():
            el.sort(key=lambda item: (
                int(item.get("display_order") or 0),
                str(item.get("edge_id") or "")))

        seen_cycle: set[str] = set()

        def _tree_node(node: dict, seen: set[str]) -> dict:
            nid = str(node.get("node_id") or "")
            if nid in seen:
                return {
                    "node_id": nid,
                    "function_name_resolved":
                        node.get("function_name_resolved") or "",
                    "depth": int(node.get("depth") or 0),
                    "status": node.get("status") or "done",
                    "children": [], "cycle": True,
                }
            next_seen = set(seen)
            next_seen.add(nid)
            children: list[dict] = []
            for edge in edges_by_source.get(nid, []):
                tid = str(edge.get("target_node_id") or "")
                target = node_by_id.get(tid)
                if target is None:
                    children.append({
                        "node_id": tid or f"virtual::{edge.get('edge_id')}",
                        "edge_id": edge.get("edge_id") or "",
                        "function_name_resolved": edge.get("target_function_resolved") or edge.get("target_function_raw") or "",
                        "function_name_raw": edge.get("target_function_raw") or "",
                        "source_file": edge.get("target_file") or "",
                        "depth": int(node.get("depth") or 0) + 1,
                        "status": edge.get("status") or "unresolved",
                        "edge_kind": edge.get("edge_kind") or "",
                        "reason_code": edge.get("reason_code") or "",
                        "reason_message": edge.get("reason_message") or "",
                        "children": [],
                        "placeholder": True,
                    })
                else:
                    child = _tree_node(target, next_seen)
                    child["edge"] = edge
                    children.append(child)
            return {
                "node_id": nid,
                "function_name_resolved":
                    node.get("function_name_resolved")
                    or node.get("function_name_raw") or "",
                "function_name_raw": node.get("function_name_raw") or "",
                "source_file": node.get("source_file") or "",
                "depth": int(node.get("depth") or 0),
                "status": node.get("status") or "done",
                "analysis_status": node.get("analysis_status") or "",
                "findings_count": int(node.get("findings_count") or 0),
                "primary_session_relpath":
                    node.get("primary_session_relpath") or "",
                "children": children,
            }

        root_node = None
        for n in nodes:
            if root_node is None or int(n.get("depth") or 0) < int(root_node.get("depth") or 0):
                root_node = n
        tree = _tree_node(root_node, set()) if root_node else None

        followed = [e for e in edges if int(e.get("visible_in_tree") or 0) == 1]
        unfollowed = [e for e in edges if int(e.get("visible_in_tree") or 0) != 1]

        return {
            "task_id": task_id,
            "epoch": epoch,
            "available": bool(nodes or edges or findings),
            "run_root": run_root,
            "generated_at": float(run_dict.get("generated_at") or 0),
            "nodes": nodes,
            "edges": edges,
            "tree": tree,
            "sessions": sessions,
            "findings": findings,
            "summary": {
                "nodes": len(nodes),
                "edges": len(edges),
                "sessions": len(sessions),
                "findings": len(findings),
                "followed_edges": len(followed),
                "unfollowed_edges": len(unfollowed),
            },
        }

    def list_task_findings(self, task_id: str) -> list[dict]:
        with self._engine.connect() as conn:
            rows = conn.execute(sa_text(
                "SELECT vf.* FROM dvs_vuln_findings vf "
                "JOIN dvs_analysis_runs ar ON ar.run_id = vf.run_id "
                "WHERE ar.task_id = :tid ORDER BY vf.created_at"),
                {"tid": task_id}).fetchall()
            return [dict(r._mapping) for r in rows]

    def list_all_findings(self) -> list[dict]:
        with self._engine.connect() as conn:
            rows = conn.execute(sa_text(
                "SELECT * FROM dvs_vuln_findings ORDER BY created_at")
            ).fetchall()
            return [dict(r._mapping) for r in rows]

    # ── 双写方法 (worker 调, 与 VulnStore 同名同签名) ──────────────

    def upsert_task_graph_node(self, rec) -> None:
        cols = ("node_id", "task_id", "epoch", "func_id",
                "function_name_resolved", "function_name_raw",
                "source_file", "depth", "status", "analysis_status",
                "findings_count", "started_at", "finished_at",
                "primary_session_relpath", "session_group_key",
                "visible_in_tree", "visible_in_all_propagations",
                "extra_json")
        vals = {c: getattr(rec, c, "") for c in cols}
        col_list = ",".join(cols)
        ph = ",".join(f":{c}" for c in cols)
        sql = (
            f"INSERT INTO dvs_task_graph_nodes ({col_list}) VALUES ({ph}) "
            f"AS new ON DUPLICATE KEY UPDATE status=new.status,"
            f"analysis_status=new.analysis_status,"
            f"findings_count=new.findings_count,"
            f"started_at=new.started_at,"
            f"finished_at=new.finished_at,"
            f"primary_session_relpath=new.primary_session_relpath"
        )
        with self._engine.connect() as conn:
            conn.execute(sa_text(sql), vals)
            conn.commit()

    def update_task_graph_node(self, node_id: str, **kw) -> None:
        if not kw:
            return
        sets = ", ".join(f"{k}=:{k}" for k in kw)
        sql = f"UPDATE dvs_task_graph_nodes SET {sets} WHERE node_id=:node_id"
        params = {"node_id": node_id, **kw}
        with self._engine.connect() as conn:
            conn.execute(sa_text(sql), params)
            conn.commit()

    def upsert_task_graph_session(self, rec) -> None:
        cols = ("session_relpath", "task_id", "epoch", "node_id",
                "edge_id", "session_role", "session_kind",
                "display_name", "status", "started_at")
        vals = {c: getattr(rec, c, "") for c in cols}
        col_list = ",".join(cols)
        ph = ",".join(f":{c}" for c in cols)
        sql = (
            f"INSERT INTO dvs_task_graph_sessions ({col_list}) VALUES ({ph}) "
            f"AS new ON DUPLICATE KEY UPDATE node_id=new.node_id,"
            f"edge_id=new.edge_id,"
            f"session_role=new.session_role,"
            f"status=new.status"
        )
        with self._engine.connect() as conn:
            conn.execute(sa_text(sql), vals)
            conn.commit()

    def update_task_graph_session(self, session_relpath: str, **kw) -> None:
        if not kw:
            return
        sets = ", ".join(f"{k}=:{k}" for k in kw)
        sql = f"UPDATE dvs_task_graph_sessions SET {sets} WHERE session_relpath=:sr"
        params = {"sr": session_relpath, **kw}
        with self._engine.connect() as conn:
            conn.execute(sa_text(sql), params)
            conn.commit()

    def upsert_task_graph_edge(self, rec) -> None:
        cols = ("edge_id", "task_id", "epoch", "source_node_id",
                "target_node_id", "source_func_id", "target_func_id",
                "source_function_resolved", "target_function_resolved",
                "target_function_raw", "source_file", "target_file",
                "edge_kind", "status", "reason_code", "reason_message",
                "reason_source", "source_prop_id", "call_line",
                "source_taint_name", "target_taint_name",
                "display_order", "visible_in_tree",
                "visible_in_all_propagations")
        vals = {c: getattr(rec, c, "") for c in cols}
        if vals.get("call_line") is None:
            vals["call_line"] = 0
        col_list = ",".join(cols)
        ph = ",".join(f":{c}" for c in cols)
        sql = (
            f"INSERT INTO dvs_task_graph_edges ({col_list}) VALUES ({ph}) "
            f"AS new ON DUPLICATE KEY UPDATE status=new.status,"
            f"reason_code=new.reason_code,"
            f"reason_message=new.reason_message,"
            f"reason_source=new.reason_source"
        )
        with self._engine.connect() as conn:
            conn.execute(sa_text(sql), vals)
            conn.commit()

    def update_task_graph_edge(self, edge_id: str, **kw) -> None:
        """部分更新 edge (对应 VulnStore.update_task_graph_edge)。"""
        if not kw:
            return
        sets = ", ".join(f"{k}=:{k}" for k in kw)
        sql = f"UPDATE dvs_task_graph_edges SET {sets} WHERE edge_id=:eid"
        params = {**kw, "eid": edge_id}
        with self._engine.connect() as conn:
            conn.execute(sa_text(sql), params)
            conn.commit()

    def start_run(self, run_id, task_id, root_file, root_function,
                   source_root, config) -> None:
        with self._engine.connect() as conn:
            conn.execute(sa_text(
                "INSERT INTO dvs_analysis_runs "
                "(run_id,task_id,root_file,root_function,source_root,"
                "status,started_at) "
                "VALUES (:rid,:tid,:rf,:rfunc,:sr,'running',:ts) "
                "AS new ON DUPLICATE KEY UPDATE status='running',"
                "started_at=new.started_at"),
                {"rid": run_id, "tid": task_id, "rf": root_file,
                 "rfunc": root_function, "sr": str(source_root),
                 "ts": time.time()})
            conn.commit()

    def finish_run(self, run_id, status) -> None:
        with self._engine.connect() as conn:
            conn.execute(sa_text(
                "UPDATE dvs_analysis_runs SET status=:st,"
                "finished_at=:ts WHERE run_id=:rid"),
                {"st": status, "ts": time.time(), "rid": run_id})
            conn.commit()

    def start_task_graph_run(self, rec) -> None:
        sql = (
            "INSERT INTO dvs_task_graph_runs "
            "(task_id,epoch,run_root,graph_version,root_function,"
            "generated_at) "
            "VALUES (:tid,:ep,:rr,:gv,:rf,:ga) "
            "AS new ON DUPLICATE KEY UPDATE run_root=new.run_root,"
            "root_function=new.root_function"
        )
        with self._engine.connect() as conn:
            conn.execute(sa_text(sql), {
                "tid": rec.task_id, "ep": rec.epoch,
                "rr": rec.run_root, "gv": rec.graph_version,
                "rf": rec.root_function,
                "ga": rec.generated_at or time.time()})
            conn.commit()

    def clear_task(self, task_id: str) -> None:
        """清本任务图谱数据 (restart 用)。"""
        with self._engine.connect() as conn:
            for t in ("dvs_task_graph_nodes", "dvs_task_graph_edges",
                      "dvs_task_graph_sessions"):
                conn.execute(sa_text(
                    f"DELETE FROM {t} WHERE task_id=:tid"),
                    {"tid": task_id})
            conn.execute(sa_text(
                "DELETE FROM dvs_task_graph_runs WHERE task_id=:tid"),
                {"tid": task_id})
            conn.commit()

    def update_finding_report_status(
        self,
        finding_id: str,
        status: str,
        case_id: str = "",
        *,
        task_id: str = "",
    ) -> None:
        with self._engine.connect() as conn:
            if str(task_id or "").strip():
                conn.execute(
                    sa_text(
                        "UPDATE dvs_vuln_findings SET report_status=:st,"
                        "report_case_id=:cid WHERE task_id=:tid AND finding_id=:fid"
                    ),
                    {"st": status, "cid": case_id, "tid": task_id, "fid": finding_id},
                )
            else:
                conn.execute(
                    sa_text(
                        "UPDATE dvs_vuln_findings SET report_status=:st,"
                        "report_case_id=:cid WHERE finding_id=:fid"
                    ),
                    {"st": status, "cid": case_id, "fid": finding_id},
                )
            conn.commit()

    def insert_finding(self, **kw) -> None:
        """插入漏洞 finding 到 MySQL。"""
        kw.setdefault("created_at",
                      time.strftime("%Y-%m-%dT%H:%M:%S"))
        cols = list(kw.keys())
        col_list = ",".join(cols)
        ph = ",".join(f":{c}" for c in cols)
        update_cols = [col for col in cols if col not in {"task_id", "finding_id"}]
        update_sql = ",".join(f"{col}=VALUES({col})" for col in update_cols)
        sql = (
            f"INSERT INTO dvs_vuln_findings ({col_list}) VALUES ({ph}) "
            f"ON DUPLICATE KEY UPDATE {update_sql}"
        )
        with self._engine.connect() as conn:
            conn.execute(sa_text(sql), kw)
            conn.commit()


def create_mysql_graph_store(mysql_url: str, project_id: str = "",
                                source_dir_id: str = "",
                                source_root: str = "") -> MysqlGraphStore | None:
    """工厂: 创建 MysqlGraphStore, 失败返回 None。"""
    try:
        return MysqlGraphStore(mysql_url, project_id=project_id,
                               source_dir_id=source_dir_id, source_root=source_root)
    except Exception as e:
        logger.warning("create MysqlGraphStore failed: %s", e)
        return None
