"""MySQL 共享存储 (双写: worker 同时写 SQLite + MySQL)。

设计:
  三种模式用独立数据库: dvs_complete / dvs_autonomous / dvs_dagflow
  以 source_dir_id (sha1(source_root)[:16]) 为分区键
  源码信息表 (functions/include/class) 无 task_id, 共享不清
  分析记录表 (processed_taints/dag_*/taints/propagations/orchestration) 有 task_id, restart 清本任务的

当前只实现写 + 清理, 不实现读 (worker 读仍走 SQLite)。
"""
from __future__ import annotations
import hashlib, logging, threading
from typing import Any
from sqlalchemy import create_engine, text as sa_text

logger = logging.getLogger("dvs.db.shared_mysql")

# 缓存 engine (每 db_name 一个)
_ENGINES: dict[str, Any] = {}
_ENGINES_LOCK = threading.Lock()

_MODE_DB = {
    "complete": "dvs_complete",
    "autonomous": "dvs_autonomous",
    "dagflow": "dvs_dagflow",
}

_DDL_NO_TASK = """
CREATE TABLE IF NOT EXISTS source_dirs (
    source_dir_id  VARCHAR(64) PRIMARY KEY,
    source_root    TEXT NOT NULL,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS functions (
    source_dir_id  VARCHAR(64) NOT NULL,
    func_id        VARCHAR(128) NOT NULL,
    `file`         VARCHAR(512) NOT NULL,
    name           VARCHAR(128) NOT NULL,
    signature      VARCHAR(512) NOT NULL,
    start_line     INTEGER NOT NULL,
    end_line       INTEGER NOT NULL,
    func_hash      VARCHAR(128),
    description    VARCHAR(128),
    PRIMARY KEY (source_dir_id, func_id)
);
CREATE INDEX idx_func_name ON functions(source_dir_id, name);
CREATE TABLE IF NOT EXISTS include_index (
    source_dir_id  VARCHAR(64) NOT NULL,
    header         VARCHAR(128) NOT NULL,
    `file`         VARCHAR(512) NOT NULL,
    PRIMARY KEY (source_dir_id, header, file)
);
CREATE TABLE IF NOT EXISTS class_hierarchy (
    source_dir_id  VARCHAR(64) NOT NULL,
    class_name     VARCHAR(128) NOT NULL,
    bases          TEXT,
    `file`         VARCHAR(512),
    PRIMARY KEY (source_dir_id, class_name)
);
CREATE TABLE IF NOT EXISTS class_members (
    source_dir_id  VARCHAR(64) NOT NULL,
    class_name     VARCHAR(128) NOT NULL,
    member_name    VARCHAR(128) NOT NULL,
    member_type    VARCHAR(128),
    `file`         VARCHAR(512),
    PRIMARY KEY (source_dir_id, class_name, member_name)
);
"""

_DDL_WITH_TASK_V2 = """
CREATE TABLE IF NOT EXISTS processed_taints (
    source_dir_id    VARCHAR(64) NOT NULL,
    func_id          VARCHAR(128) NOT NULL,
    taint_signature  VARCHAR(128) NOT NULL,
    task_id          VARCHAR(64) NOT NULL,
    taint_params     TEXT,
    sessions_path    VARCHAR(128),
    analyzed_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (source_dir_id, func_id, taint_signature, task_id)
);
CREATE INDEX idx_pt_dir_func ON processed_taints(source_dir_id, func_id, taint_signature);
CREATE INDEX idx_pt_task ON processed_taints(task_id);
CREATE TABLE IF NOT EXISTS taints (
    source_dir_id       VARCHAR(64) NOT NULL,
    taint_id            VARCHAR(128) NOT NULL,
    func_id             VARCHAR(128) NOT NULL,
    name                VARCHAR(128) NOT NULL,
    signature           VARCHAR(512) NOT NULL,
    file                VARCHAR(512) NOT NULL,
    `function`          VARCHAR(512) NOT NULL,
    next_propagations   TEXT,
    description         VARCHAR(128),
    task_id             VARCHAR(64) NOT NULL,
    PRIMARY KEY (source_dir_id, taint_id, task_id)
);
CREATE INDEX idx_taint_func ON taints(source_dir_id, func_id);
CREATE TABLE IF NOT EXISTS propagations (
    source_dir_id           VARCHAR(64) NOT NULL,
    prop_id                 VARCHAR(128) NOT NULL,
    source_func_id          VARCHAR(128),
    source_taint_signature  VARCHAR(128) NOT NULL,
    target_taint_signature  VARCHAR(128) NOT NULL,
    target_func_id          VARCHAR(128),
    target_function         VARCHAR(512),
    target_file             VARCHAR(512),
    call_line               INTEGER,
    `condition`              VARCHAR(128),
    is_external             INTEGER DEFAULT 0,
    is_indirect_call        INTEGER DEFAULT 0,
    escape_kind             VARCHAR(128),
    carrier                 VARCHAR(128),
    escape_via              VARCHAR(128),
    actual_args             TEXT,
    validations             TEXT,
    task_id                 VARCHAR(64) NOT NULL,
    PRIMARY KEY (source_dir_id, prop_id, task_id)
);
CREATE INDEX idx_prop_source ON propagations(source_dir_id, source_func_id);
CREATE TABLE IF NOT EXISTS orchestration (
    source_dir_id   VARCHAR(64) NOT NULL,
    edge_id          VARCHAR(128) NOT NULL,
    path_id          VARCHAR(128) NOT NULL,
    source_func_id   VARCHAR(128) NOT NULL,
    target_func_id   VARCHAR(128) NOT NULL,
    taint_params     TEXT NOT NULL,
    depth            INTEGER NOT NULL,
    edge_order       INTEGER NOT NULL,
    `status`           VARCHAR(32) DEFAULT 'pending',
    task_id          VARCHAR(64) NOT NULL,
    PRIMARY KEY (source_dir_id, edge_id, task_id)
);
CREATE INDEX idx_orch_status ON orchestration(source_dir_id, status);
"""

_DDL_WITH_TASK_DAG = """
CREATE TABLE IF NOT EXISTS dag_processed_taints (
    source_dir_id    VARCHAR(64) NOT NULL,
    func_id          VARCHAR(128) NOT NULL,
    taint_signature  VARCHAR(128) NOT NULL,
    task_id          VARCHAR(64) NOT NULL,
    analyzed_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (source_dir_id, func_id, taint_signature, task_id)
);
CREATE INDEX idx_dpt_dir_func ON dag_processed_taints(source_dir_id, func_id, taint_signature);
CREATE INDEX idx_dpt_task ON dag_processed_taints(task_id);
CREATE TABLE IF NOT EXISTS dag_nodes (
    source_dir_id    VARCHAR(64) NOT NULL,
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
    PRIMARY KEY (source_dir_id, func_id, taint_signature, node_id, task_id)
);
CREATE TABLE IF NOT EXISTS dag_edges (
    source_dir_id      VARCHAR(64) NOT NULL,
    func_id            VARCHAR(128) NOT NULL,
    taint_signature    VARCHAR(512) NOT NULL,
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
    PRIMARY KEY (source_dir_id, func_id, taint_signature, edge_id, task_id)
);
CREATE INDEX idx_dag_edges_sink ON dag_edges(source_dir_id, sink_ref);
CREATE TABLE IF NOT EXISTS dag_meta (
    source_dir_id   VARCHAR(64) NOT NULL,
    func_id         VARCHAR(128) NOT NULL,
    taint_signature VARCHAR(512) NOT NULL,
    self_contained  INTEGER NOT NULL DEFAULT 0,
    description     VARCHAR(128),
    taint_failed    INTEGER NOT NULL DEFAULT 0,
    task_id         VARCHAR(64) NOT NULL,
    PRIMARY KEY (source_dir_id, func_id, taint_signature, task_id)
);
"""

_V2_TASK_TABLES = ["processed_taints", "taints", "propagations", "orchestration"]
_DAG_TASK_TABLES = ["dag_processed_taints", "dag_nodes", "dag_edges", "dag_meta"]


class SharedMysqlStore:
    """MySQL 共享存储 (只写 + 清理, 不读)。

    使用: 在 store 初始化时创建, 传入 mode/source_root/task_id。
    worker 每次 SQLite 写完后调对应方法同步写 MySQL。
    restart/delete 时调 clear_task_analysis() 清本任务数据。
    """

    def __init__(self, mysql_url: str, mode: str, source_root: str, task_id: str) -> None:
        self.source_dir_id = hashlib.sha1(source_root.encode("utf-8")).hexdigest()[:16]
        self.task_id = task_id
        self.mode = mode
        self.db_name = _MODE_DB.get(mode)
        if not self.db_name:
            raise ValueError(f"unknown mode: {mode}")
        self._engine = self._get_engine(mysql_url, self.db_name)
        self._ensure_schema()
        self._register_source_dir(source_root)

    @staticmethod
    def _get_engine(mysql_url: str, db_name: str):
        """获取/缓存 engine (每 db_name 一个)。先建库再连。"""
        with _ENGINES_LOCK:
            if db_name in _ENGINES:
                return _ENGINES[db_name]
            # 先连默认库, 建目标库
            base = mysql_url.rsplit("/", 1)[0]  # 去掉 /dbname?charset=...
            # base 形如 mysql+pymysql://user:pass@host:port
            admin_url = f"{base}/mysql?charset=utf8mb4"
            admin_eng = create_engine(admin_url, pool_pre_ping=True, pool_recycle=3600)
            with admin_eng.connect() as conn:
                conn.execute(sa_text(f"CREATE DATABASE IF NOT EXISTS {db_name} DEFAULT CHARSET utf8mb4"))
                conn.commit()
            admin_eng.dispose()
            # 连目标库
            url = f"{base}/{db_name}?charset=utf8mb4"
            eng = create_engine(url, pool_size=3, max_overflow=5, pool_pre_ping=True, pool_recycle=3600)
            _ENGINES[db_name] = eng
            return eng

    def _ensure_schema(self):
        """建表 (幂等, 容错: 单条失败不阻断后续)。"""
        def _exec_multi(ddl: str):
            for stmt in ddl.split(";"):
                s = stmt.strip()
                if not s:
                    continue
                try:
                    with self._engine.connect() as conn:
                        conn.execute(sa_text(s))
                        conn.commit()
                except Exception as e:
                    logger.debug("DDL skip: %s (%s)", s[:60], e)
        _exec_multi(_DDL_NO_TASK)
        if self.mode in ("complete", "autonomous"):
            _exec_multi(_DDL_WITH_TASK_V2)
        elif self.mode == "dagflow":
            _exec_multi(_DDL_WITH_TASK_DAG)

    def _register_source_dir(self, source_root: str):
        """注册源码目录 (INSERT IGNORE)。"""
        with self._engine.connect() as conn:
            conn.execute(sa_text(
                "INSERT IGNORE INTO source_dirs (source_dir_id, source_root) VALUES (:sid, :sr)"),
                {"sid": self.source_dir_id, "sr": source_root})
            conn.commit()

    # ── 清理 (restart/delete 调) ──────────────────────────────────────

    def clear_task_analysis(self):
        """清本任务在本源码目录的所有分析记录 (不清函数索引)。"""
        tables = _V2_TASK_TABLES if self.mode in ("complete", "autonomous") else _DAG_TASK_TABLES
        with self._engine.connect() as conn:
            for t in tables:
                conn.execute(sa_text(
                    f"DELETE FROM {t} WHERE source_dir_id=:sid AND task_id=:tid"),
                    {"sid": self.source_dir_id, "tid": self.task_id})
            conn.commit()
        logger.info("[shared_mysql] cleared task %s analysis records (mode=%s, source_dir=%s, tables=%s)",
                    self.task_id, self.mode, self.source_dir_id, tables)

    # ── 源码信息 (无 task_id, 共享) ──────────────────────────────────

    def upsert_function(self, *, func_id: str, file: str, name: str, signature: str,
                        start_line: int, end_line: int, func_hash: str = "",
                        description: str = ""):
        sql = """INSERT INTO functions (source_dir_id,func_id,file,name,signature,
            start_line,end_line,func_hash,description)
            VALUES (:sid,:fid,:file,:name,:sig,:sl,:el,:fh,:desc)
            ON DUPLICATE KEY UPDATE file=VALUES(file),name=VALUES(name),signature=VALUES(signature),
            start_line=VALUES(start_line),end_line=VALUES(end_line),
            func_hash=VALUES(func_hash),description=VALUES(description)"""
        with self._engine.connect() as conn:
            conn.execute(sa_text(sql), {"sid": self.source_dir_id, "fid": func_id, "file": file,
                "name": name, "sig": signature, "sl": start_line, "el": end_line,
                "fh": func_hash, "desc": description})
            conn.commit()

    def add_include(self, header: str, file: str):
        with self._engine.connect() as conn:
            conn.execute(sa_text(
                "INSERT IGNORE INTO include_index (source_dir_id,header,file) VALUES (:sid,:h,:f)"),
                {"sid": self.source_dir_id, "h": header, "f": file})
            conn.commit()

    def add_class(self, class_name: str, bases: str, file: str = ""):
        import json
        with self._engine.connect() as conn:
            conn.execute(sa_text(
                """INSERT INTO class_hierarchy (source_dir_id,class_name,bases,file)
                VALUES (:sid,:cn,:b,:f)
                ON DUPLICATE KEY UPDATE bases=VALUES(bases),file=VALUES(file)"""),
                {"sid": self.source_dir_id, "cn": class_name, "b": bases, "f": file})
            conn.commit()

    def add_class_member(self, class_name: str, member_name: str, member_type: str = "", file: str = ""):
        with self._engine.connect() as conn:
            conn.execute(sa_text(
                "INSERT IGNORE INTO class_members (source_dir_id,class_name,member_name,member_type,file) "
                "VALUES (:sid,:cn,:mn,:mt,:f)"),
                {"sid": self.source_dir_id, "cn": class_name, "mn": member_name,
                 "mt": member_type, "f": file})
            conn.commit()

    # ── 分析记录 (有 task_id) ────────────────────────────────────────

    def add_processed_taint(self, func_id: str, taint_sig: str, taint_params: str = "[]",
                           sessions_path: str = ""):
        with self._engine.connect() as conn:
            conn.execute(sa_text(
                "INSERT IGNORE INTO processed_taints (source_dir_id,func_id,taint_signature,task_id,taint_params,sessions_path) "
                "VALUES (:sid,:fid,:ts,:tid,:tp,:sp)"),
                {"sid": self.source_dir_id, "fid": func_id, "ts": taint_sig,
                 "tid": self.task_id, "tp": taint_params, "sp": sessions_path})
            conn.commit()

    def delete_processed_taint(self, func_id: str, taint_sig: str):
        with self._engine.connect() as conn:
            conn.execute(sa_text(
                "DELETE FROM processed_taints WHERE source_dir_id=:sid AND func_id=:fid AND taint_signature=:ts AND task_id=:tid"),
                {"sid": self.source_dir_id, "fid": func_id, "ts": taint_sig, "tid": self.task_id})
            conn.commit()

    def upsert_taint(self, *, taint_id: str, func_id: str, name: str, signature: str,
                     file: str, function: str, next_propagations: str = "[]", description: str = ""):
        sql = """INSERT INTO taints (source_dir_id,taint_id,func_id,name,signature,file,function,
            next_propagations,description,task_id)
            VALUES (:sid,:tid,:fid,:name,:sig,:file,:func,:np,:desc,:task)
            ON DUPLICATE KEY UPDATE next_propagations=VALUES(next_propagations),description=VALUES(description)"""
        with self._engine.connect() as conn:
            conn.execute(sa_text(sql), {"sid": self.source_dir_id, "tid": taint_id, "fid": func_id,
                "name": name, "sig": signature, "file": file, "func": function,
                "np": next_propagations, "desc": description, "task": self.task_id})
            conn.commit()

    def upsert_propagation(self, **kw):
        """propagations 表插入 (key = prop_id, 列名与表结构对应)。"""
        cols = ["prop_id", "source_func_id", "source_taint_signature", "target_taint_signature",
                "target_func_id", "target_function", "target_file", "call_line", "condition",
                "is_external", "is_indirect_call", "escape_kind", "carrier", "escape_via",
                "actual_args", "validations"]
        vals = {c: kw.get(c, "") for c in cols}
        placeholders = ", ".join(f":{c}" for c in cols)
        col_list = ", ".join(cols)
        sql = (f"INSERT IGNORE INTO propagations (source_dir_id,{col_list},task_id) "
               f"VALUES (:sid,{placeholders},:task)")
        params = {"sid": self.source_dir_id, "task": self.task_id, **vals}
        with self._engine.connect() as conn:
            conn.execute(sa_text(sql), params)
            conn.commit()

    def upsert_orchestration_edge(self, *, edge_id: str, path_id: str, source_func_id: str,
                                  target_func_id: str, taint_params: str, depth: int,
                                  edge_order: int, status: str = "pending"):
        sql = """INSERT IGNORE INTO orchestration (source_dir_id,edge_id,path_id,source_func_id,
            target_func_id,taint_params,depth,edge_order,status,task_id)
            VALUES (:sid,:eid,:pid,:sfid,:tfid,:tp,:d,:eo,:st,:task)"""
        with self._engine.connect() as conn:
            conn.execute(sa_text(sql), {"sid": self.source_dir_id, "eid": edge_id, "pid": path_id,
                "sfid": source_func_id, "tfid": target_func_id, "tp": taint_params,
                "d": depth, "eo": edge_order, "st": status, "task": self.task_id})
            conn.commit()

    # ── DAG (仅 dagflow 模式) ─────────────────────────────────────────

    def dag_try_reserve(self, func_id: str, taint_sig: str) -> bool:
        """INSERT IGNORE → rowcount=1 表示本任务占位成功。"""
        with self._engine.connect() as conn:
            r = conn.execute(sa_text(
                "INSERT IGNORE INTO dag_processed_taints (source_dir_id,func_id,taint_signature,task_id) "
                "VALUES (:sid,:fid,:ts,:tid)"),
                {"sid": self.source_dir_id, "fid": func_id, "ts": taint_sig, "tid": self.task_id})
            conn.commit()
            return r.rowcount > 0

    def dag_delete_processed(self, func_id: str, taint_sig: str):
        with self._engine.connect() as conn:
            conn.execute(sa_text(
                "DELETE FROM dag_processed_taints WHERE source_dir_id=:sid AND func_id=:fid AND taint_signature=:ts AND task_id=:tid"),
                {"sid": self.source_dir_id, "fid": func_id, "ts": taint_sig, "tid": self.task_id})
            conn.commit()

    def save_dag(self, func_id: str, taint_sig: str, nodes: list[dict], edges: list[dict], meta: dict):
        """保存 DAG (先删旧再插, 限定 source_dir + func + taint + task)。"""
        import json
        sd, tid = self.source_dir_id, self.task_id
        with self._engine.connect() as conn:
            for t in ("dag_nodes", "dag_edges", "dag_meta"):
                conn.execute(sa_text(
                    f"DELETE FROM {t} WHERE source_dir_id=:sid AND func_id=:fid AND taint_signature=:ts AND task_id=:tid"),
                    {"sid": sd, "fid": func_id, "ts": taint_sig, "tid": tid})
            for n in nodes:
                conn.execute(sa_text(
                    """INSERT INTO dag_nodes (source_dir_id,func_id,taint_signature,node_id,line,taint,
                    parents_json,checks_json,prune_json,is_source,task_id)
                    VALUES (:sid,:fid,:ts,:nid,:ln,:t,:p,:c,:pr,:is,:tid)"""),
                    {"sid": sd, "fid": func_id, "ts": taint_sig, "nid": n["node_id"], "ln": n["line"],
                     "t": n["taint"], "p": json.dumps(n.get("parents", []), ensure_ascii=False),
                     "c": json.dumps(n.get("checks", []), ensure_ascii=False),
                     "pr": json.dumps(n.get("prune", {}), ensure_ascii=False) if n.get("prune") else "",
                     "is": 1 if n.get("is_source") else 0, "tid": tid})
            for e in edges:
                conn.execute(sa_text(
                    """INSERT INTO dag_edges (source_dir_id,func_id,taint_signature,edge_id,from_node,to_node,
                    line,condition_json,taints_json,kind,sink_ref,param_taints_json,escape_subkind,carrier,escape_via,task_id)
                    VALUES (:sid,:fid,:ts,:eid,:fn,:tn,:ln,:cond,:taints,:kind,:sr,:pt,:es,:car,:ev,:tid)"""),
                    {"sid": sd, "fid": func_id, "ts": taint_sig, "eid": e["edge_id"],
                     "fn": e["from_node"], "tn": e["to_node"], "ln": e["line"],
                     "cond": json.dumps(e.get("condition", []), ensure_ascii=False),
                     "taints": json.dumps(e.get("taints", []), ensure_ascii=False),
                     "kind": e.get("kind", "inside"), "sr": e.get("sink_ref", ""),
                     "pt": json.dumps(e.get("param_taints", []), ensure_ascii=False),
                     "es": e.get("escape_subkind", ""), "car": e.get("carrier", ""),
                     "ev": e.get("escape_via", ""), "tid": tid})
            conn.execute(sa_text(
                """INSERT INTO dag_meta (source_dir_id,func_id,taint_signature,self_contained,description,taint_failed,task_id)
                VALUES (:sid,:fid,:ts,:sc,:desc,:tf,:tid)
                ON DUPLICATE KEY UPDATE self_contained=VALUES(self_contained),
                description=VALUES(description),taint_failed=VALUES(taint_failed)"""),
                {"sid": sd, "fid": func_id, "ts": taint_sig,
                 "sc": 1 if meta.get("self_contained") else 0,
                 "desc": meta.get("description", ""),
                 "tf": 1 if meta.get("taint_failed") else 0, "tid": tid})
            conn.commit()


def create_shared_store(mysql_url: str, mode: str, source_root: str, task_id: str) -> SharedMysqlStore | None:
    """工厂: 创建 SharedMysqlStore, 失败返回 None (不影响主流程)。"""
    try:
        return SharedMysqlStore(mysql_url, mode, source_root, task_id)
    except Exception as e:
        logger.warning("create SharedMysqlStore failed (mode=%s): %s", mode, e)
        return None
