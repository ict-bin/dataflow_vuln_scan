"""MySQL 共享存储 (双写: worker 同时写 SQLite + MySQL)。

设计:
  三种模式用独立数据库: dvs_complete / dvs_autonomous / dvs_dagflow
  以 source_dir_id (sha1(source_root)[:16]) 为分区键
  源码信息表 (functions/include/class) 无 task_id, 共享不清
  分析记录表 (processed_taints/dag_*/taints/propagations/orchestration) 有 task_id, restart 清本任务的

当前只实现写 + 清理, 不实现读 (worker 读仍走 SQLite)。
"""
from __future__ import annotations
import hashlib, json, logging, re, threading
from typing import Any
from sqlalchemy import create_engine, text as sa_text

from .mysql_read import MysqlReadMixin
from ..dataflow_v2.models import ProcessedTaint

logger = logging.getLogger("dvs.db.shared_mysql")

# 缓存 engine (每 db_name 一个)
_ENGINES: dict[str, Any] = {}
_ENGINES_LOCK = threading.Lock()

# 按项目隔离: 数据库名 = dvs_<project_id[:12]>
# 不同项目的数据完全隔离, 互不影响
# 兼容旧数据: 如果无 project_id, 回退到 dvs_<mode>
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
    name_tail      VARCHAR(128) NOT NULL DEFAULT '',
    signature      VARCHAR(512) NOT NULL,
    start_line     INTEGER NOT NULL,
    end_line       INTEGER NOT NULL,
    func_hash      VARCHAR(128),
    description    TEXT,
    PRIMARY KEY (source_dir_id, func_id)
);
CREATE INDEX idx_func_name ON functions(source_dir_id, name);
CREATE INDEX idx_func_tail ON functions(source_dir_id, name_tail);
CREATE INDEX idx_func_file ON functions(source_dir_id, `file`);
ALTER TABLE functions ADD COLUMN IF NOT EXISTS name_tail VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE functions ADD INDEX IF NOT EXISTS idx_func_tail (source_dir_id, name_tail);
ALTER TABLE functions ADD INDEX IF NOT EXISTS idx_func_file (source_dir_id, `file`);
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
CREATE TABLE IF NOT EXISTS indexing_files (
    source_dir_id  VARCHAR(64) NOT NULL,
    file_path      VARCHAR(512) NOT NULL,
    started_at     DOUBLE NOT NULL DEFAULT 0,
    PRIMARY KEY (source_dir_id, file_path)
);
"""

_DDL_WITH_TASK_V2 = """
CREATE TABLE IF NOT EXISTS processed_taints (
    source_dir_id    VARCHAR(64) NOT NULL,
    func_id          VARCHAR(128) NOT NULL,
    taint_signature  VARCHAR(128) NOT NULL,
    task_id          VARCHAR(64) NOT NULL,
    taint_params     TEXT,
    sessions_path    VARCHAR(512),
    analyzed_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (source_dir_id, func_id, taint_signature, task_id)
);
CREATE INDEX idx_pt_dir_func ON processed_taints(source_dir_id, func_id, taint_signature);
CREATE INDEX idx_pt_task ON processed_taints(task_id);
ALTER TABLE processed_taints MODIFY COLUMN sessions_path VARCHAR(512);
CREATE TABLE IF NOT EXISTS taints (
    source_dir_id       VARCHAR(64) NOT NULL,
    taint_id            VARCHAR(128) NOT NULL,
    func_id             VARCHAR(128) NOT NULL,
    name                VARCHAR(128) NOT NULL,
    signature           VARCHAR(512) NOT NULL,
    file                VARCHAR(512) NOT NULL,
    `function`          VARCHAR(512) NOT NULL,
    next_propagations   TEXT,
    description         TEXT,
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
ALTER TABLE propagations ADD COLUMN IF NOT EXISTS source_taint_name VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE propagations ADD COLUMN IF NOT EXISTS target_taint_name VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE propagations ADD COLUMN IF NOT EXISTS callsite_validated INTEGER NOT NULL DEFAULT 0;
ALTER TABLE propagations ADD COLUMN IF NOT EXISTS is_external_callee INTEGER NOT NULL DEFAULT 0;
ALTER TABLE propagations ADD COLUMN IF NOT EXISTS dispatch_kind VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE propagations ADD COLUMN IF NOT EXISTS branch_group_id VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE propagations ADD COLUMN IF NOT EXISTS branch_arm_id VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE propagations ADD COLUMN IF NOT EXISTS branch_path TEXT;
ALTER TABLE propagations ADD COLUMN IF NOT EXISTS mutex_siblings TEXT;
ALTER TABLE propagations ADD COLUMN IF NOT EXISTS description TEXT;
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
ALTER TABLE orchestration ADD COLUMN IF NOT EXISTS source_function VARCHAR(512) NOT NULL DEFAULT '';
ALTER TABLE orchestration ADD COLUMN IF NOT EXISTS source_signature VARCHAR(512) NOT NULL DEFAULT '';
ALTER TABLE orchestration ADD COLUMN IF NOT EXISTS target_function VARCHAR(512) NOT NULL DEFAULT '';
ALTER TABLE orchestration ADD COLUMN IF NOT EXISTS target_signature VARCHAR(512) NOT NULL DEFAULT '';
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
    PRIMARY KEY (source_dir_id, func_id, taint_signature, edge_id, task_id)
);
CREATE INDEX idx_dag_edges_sink ON dag_edges(source_dir_id, sink_ref);
CREATE TABLE IF NOT EXISTS dag_meta (
    source_dir_id   VARCHAR(64) NOT NULL,
    func_id         VARCHAR(128) NOT NULL,
    taint_signature VARCHAR(512) NOT NULL,
    self_contained  INTEGER NOT NULL DEFAULT 0,
    description     TEXT,
    taint_failed    INTEGER NOT NULL DEFAULT 0,
    task_id         VARCHAR(64) NOT NULL,
    PRIMARY KEY (source_dir_id, func_id, taint_signature, task_id)
);
"""

_V2_TASK_TABLES = ["taints", "propagations", "orchestration"]
# processed_taints 不清: 跨任务共享去重状态 (source-dir 级)
_DAG_TASK_TABLES = ["dag_processed_taints", "dag_nodes", "dag_edges", "dag_meta"]


class SharedMysqlStore(MysqlReadMixin):
    """MySQL 共享存储 (读写 + 清理)。

    使用: 在 store 初始化时创建, 传入 mode/source_root/task_id。
    worker 每次 SQLite 写完后调对应方法同步写 MySQL。
    restart/delete 时调 clear_task_analysis() 清本任务数据。
    """

    def __init__(self, mysql_url: str, mode: str, source_root: str, task_id: str,
                 project_id: str = "") -> None:
        self.source_dir_id = hashlib.sha1(source_root.encode("utf-8")).hexdigest()[:16]
        self.task_id = task_id
        self.mode = mode
        # 每个源码目录独立一个数据库: dvs_<source_dir_id>
        self.db_name = f"dvs_{self.source_dir_id}"
        # 数据文件存储路径: /data/files/<project_id>/app/secflow-app-dataflow-vuln-scan/mysql/<source_dir_id>/
        self.data_dir = self._compute_data_dir(source_root)
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
            # 确保 URL 有数据库部分 (没有就加 /)
            # URL 形如: mysql+pymysql://user:pass@host:port[/dbname?charset=...]
            if "?" in mysql_url:
                base = mysql_url.rsplit("/", 1)[0]
            elif mysql_url.endswith("/"):
                base = mysql_url[:-1]
            else:
                # 没有 dbname 也没有 ? — 检查是否有 /
                last_slash = mysql_url.rfind("/")
                if last_slash > mysql_url.find("//") + 1:
                    base = mysql_url[:last_slash]
                else:
                    base = mysql_url  # 无 dbname, base 就是完整 URL
            # base 形如 mysql+pymysql://user:pass@host:port
            try:
                admin_url = f"{base}/mysql?charset=utf8mb4"
                admin_eng = create_engine(admin_url, pool_pre_ping=True, pool_recycle=3600)
                with admin_eng.connect() as conn:
                    conn.execute(sa_text(f"CREATE DATABASE IF NOT EXISTS `{db_name}` DEFAULT CHARSET utf8mb4"))
                    conn.commit()
                admin_eng.dispose()
            except Exception:
                logger.debug("CREATE DATABASE failed (secflow may lack privilege); trying direct connect")
            # 连目标库
            url = f"{base}/{db_name}?charset=utf8mb4"
            eng = create_engine(url, pool_size=2, max_overflow=3, pool_pre_ping=True, pool_recycle=3600)
            _ENGINES[db_name] = eng
            return eng

    def _ensure_schema(self):
        """建表 (幂等, 容错: 单条失败不阻断后续)。

        尝试用 DATA DIRECTORY 将 .ibd 放到 NFS 项目路径; 失败则回退默认路径。
        """
        data_dir_clause = f" DATA DIRECTORY='{self.data_dir}'" if self.data_dir else ""

        def _index_exists(table_name: str, index_name: str) -> bool:
            sql = sa_text(
                """
                SELECT 1
                FROM information_schema.statistics
                WHERE table_schema = DATABASE()
                  AND table_name = :table_name
                  AND index_name = :index_name
                LIMIT 1
                """
            )
            with self._engine.connect() as conn:
                row = conn.execute(sql, {"table_name": table_name, "index_name": index_name}).fetchone()
            return row is not None

        def _column_exists(table_name: str, column_name: str) -> bool:
            sql = sa_text(
                """
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = DATABASE()
                  AND table_name = :table_name
                  AND column_name = :column_name
                LIMIT 1
                """
            )
            with self._engine.connect() as conn:
                row = conn.execute(sql, {"table_name": table_name, "column_name": column_name}).fetchone()
            return row is not None

        def _normalize_mysql_ddl(stmt: str) -> tuple[str | None, str | None]:
            compact = " ".join(stmt.split())
            match = re.match(r"CREATE INDEX\s+`?([A-Za-z0-9_]+)`?\s+ON\s+`?([A-Za-z0-9_]+)`?", compact, re.IGNORECASE)
            if match:
                index_name, table_name = match.group(1), match.group(2)
                if _index_exists(table_name, index_name):
                    return None, f"index {table_name}.{index_name} already exists"
                return stmt, None

            match = re.match(
                r"ALTER TABLE\s+`?([A-Za-z0-9_]+)`?\s+ADD COLUMN IF NOT EXISTS\s+`?([A-Za-z0-9_]+)`?\s+(.*)",
                compact,
                re.IGNORECASE,
            )
            if match:
                table_name, column_name, suffix = match.group(1), match.group(2), match.group(3)
                if _column_exists(table_name, column_name):
                    return None, f"column {table_name}.{column_name} already exists"
                return f"ALTER TABLE {table_name} ADD COLUMN {column_name} {suffix}", None

            match = re.match(
                r"ALTER TABLE\s+`?([A-Za-z0-9_]+)`?\s+ADD INDEX IF NOT EXISTS\s+`?([A-Za-z0-9_]+)`?\s*(\(.*\))",
                compact,
                re.IGNORECASE,
            )
            if match:
                table_name, index_name, index_expr = match.group(1), match.group(2), match.group(3)
                if _index_exists(table_name, index_name):
                    return None, f"index {table_name}.{index_name} already exists"
                return f"ALTER TABLE {table_name} ADD INDEX {index_name} {index_expr}", None

            return stmt, None

        def _is_benign_ddl_error(exc: Exception) -> bool:
            text = str(exc).lower()
            return (
                "duplicate key name" in text
                or "duplicate column name" in text
                or "already exists" in text
            )

        def _exec_multi(ddl: str):
            for stmt in ddl.split(";"):
                s = stmt.strip()
                if not s:
                    continue
                try:
                    normalized_stmt, skip_reason = _normalize_mysql_ddl(s)
                except Exception as exc:
                    logger.debug("DDL normalize failed: %s (%s)", s[:60], exc, exc_info=True)
                    normalized_stmt, skip_reason = s, None
                if normalized_stmt is None:
                    logger.debug("DDL skip benign: %s (%s)", s[:60], skip_reason)
                    continue
                s = normalized_stmt
                # 在 CREATE TABLE 语句末尾插入 DATA DIRECTORY
                if s.upper().startswith("CREATE TABLE") and data_dir_clause:
                    last_paren = s.rfind(")")
                    if last_paren >= 0:
                        s_dd = s[:last_paren + 1] + data_dir_clause + s[last_paren + 1:]
                        try:
                            with self._engine.connect() as conn:
                                conn.execute(sa_text(s_dd))
                                conn.commit()
                            continue
                        except Exception:
                            pass  # DATA DIRECTORY 失败, 回退默认路径
                try:
                    with self._engine.connect() as conn:
                        conn.execute(sa_text(s))
                        conn.commit()
                except Exception as e:
                    if _is_benign_ddl_error(e):
                        logger.debug("DDL skip benign: %s (%s)", s[:60], e)
                    else:
                        logger.warning("DDL skip: %s (%s)", s[:60], e)
        _exec_multi(_DDL_NO_TASK)
        if self.mode in ("complete", "autonomous"):
            _exec_multi(_DDL_WITH_TASK_V2)
        elif self.mode == "dagflow":
            _exec_multi(_DDL_WITH_TASK_DAG)

    def _compute_data_dir(self, source_root: str) -> str:
        """从 source_root 提取 project_id, 返回 NFS 上的 MySQL 数据目录路径。

        source_root = /data/files/<project_id>/app/.../input
        → /data/files/<project_id>/app/secflow-app-dataflow-vuln-scan/mysql/<source_dir_id>/
        """
        import os
        parts = source_root.split("/")
        if len(parts) > 3 and parts[1] == "data" and parts[2] == "files":
            project_id = parts[3]
            d = f"/data/files/{project_id}/app/secflow-app-dataflow-vuln-scan/mysql/{self.source_dir_id}"
        else:
            d = ""  # 无法推断 project_id, 不使用 DATA DIRECTORY
        if d:
            os.makedirs(d, exist_ok=True)
        return d

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
        for t in tables:
            try:
                with self._engine.begin() as conn:
                    conn.execute(sa_text(
                        f"DELETE FROM {t} WHERE source_dir_id=:sid AND task_id=:tid"),
                        {"sid": self.source_dir_id, "tid": self.task_id})
            except Exception as e:
                logger.warning("[shared_mysql] clear %s failed: %s", t, str(e)[:120])
        logger.info("[shared_mysql] cleared task %s analysis records (mode=%s, source_dir=%s, tables=%s)",
                    self.task_id, self.mode, self.source_dir_id, tables)

    # ── 源码信息 (无 task_id, 共享) ──────────────────────────────────

    def upsert_function(self, *, func_id: str, file: str, name: str, signature: str,
                        start_line: int, end_line: int, func_hash: str = "",
                        description: str = ""):
        name_tail = name.split("::")[-1].strip() if "::" in name else name
        sql = """INSERT INTO functions (source_dir_id,func_id,`file`,name,name_tail,signature,
            start_line,end_line,func_hash,description)
            VALUES (:sid,:fid,:file,:name,:tail,:sig,:sl,:el,:fh,:desc)
            AS new ON DUPLICATE KEY UPDATE `file`=new.`file`,name=new.name,name_tail=new.name_tail,
            signature=new.signature,start_line=new.start_line,end_line=new.end_line,
            func_hash=new.func_hash,description=new.description"""
        with self._engine.connect() as conn:
            conn.execute(sa_text(sql), {"sid": self.source_dir_id, "fid": func_id, "file": file,
                "name": name, "tail": name_tail, "sig": signature, "sl": start_line, "el": end_line,
                "fh": func_hash, "desc": description})
            conn.commit()

    def add_include(self, header: str, file: str):
        with self._engine.connect() as conn:
            conn.execute(sa_text(
                "INSERT IGNORE INTO include_index (source_dir_id,header,`file`) VALUES (:sid,:h,:f)"),
                {"sid": self.source_dir_id, "h": header, "f": file})
            conn.commit()

    def add_class(self, class_name: str, bases: str, file: str = ""):
        import json
        with self._engine.connect() as conn:
            conn.execute(sa_text(
                """INSERT INTO class_hierarchy (source_dir_id,class_name,bases,`file`)
                VALUES (:sid,:cn,:b,:f)
                ON DUPLICATE KEY UPDATE bases=VALUES(bases),`file`=VALUES(`file`)"""),
                {"sid": self.source_dir_id, "cn": class_name, "b": bases, "f": file})
            conn.commit()

    def add_class_member(self, class_name: str, member_name: str, member_type: str = "", file: str = ""):
        with self._engine.connect() as conn:
            conn.execute(sa_text(
                "INSERT IGNORE INTO class_members (source_dir_id,class_name,member_name,member_type,`file`) "
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

    def try_reserve_processed_taint(self, func_id: str, taint_sig: str,
                                    taint_params: str = "[]", sessions_path: str = "") -> bool:
        """跨 worker 原子占位 (INSERT IGNORE, rowcount=1=占位成功)。"""
        with self._engine.connect() as conn:
            result = conn.execute(sa_text(
                "INSERT IGNORE INTO processed_taints (source_dir_id,func_id,taint_signature,task_id,taint_params,sessions_path) "
                "VALUES (:sid,:fid,:ts,:tid,:tp,:sp)"),
                {"sid": self.source_dir_id, "fid": func_id, "ts": taint_sig,
                 "tid": self.task_id, "tp": taint_params, "sp": sessions_path})
            conn.commit()
            return result.rowcount == 1

    def delete_processed_taint(self, func_id: str, taint_sig: str):
        with self._engine.connect() as conn:
            conn.execute(sa_text(
                "DELETE FROM processed_taints WHERE source_dir_id=:sid AND func_id=:fid AND taint_signature=:ts AND task_id=:tid"),
                {"sid": self.source_dir_id, "fid": func_id, "ts": taint_sig, "tid": self.task_id})
            conn.commit()

    # ── V2 模式专用: func_id 级去重 (per-task 隔离) ──────────────────
    def v2_find_processed_taint(self, func_id: str, taint_sig: str = "") -> ProcessedTaint | None:
        """V2 跨任务去重: (source_dir_id, func_id, taint_signature) 级。

        同一源码目录下, 任意任务已分析过该函数+该污点 → 后续任务跳过。
        """
        try:
            with self._engine.connect() as conn:
                row = conn.execute(sa_text(
                    "SELECT taint_signature, taint_params, sessions_path "
                    "FROM processed_taints "
                    "WHERE source_dir_id=:sid AND func_id=:fid AND taint_signature=:ts LIMIT 1"),
                    {"sid": self.source_dir_id, "fid": func_id, "ts": taint_sig}).fetchone()
                if row is None:
                    return None
                m = row._mapping
                return ProcessedTaint(
                    taint_params=json.loads(m.get("taint_params") or "[]"),
                    taint_signature=m.get("taint_signature") or "",
                    pre_validations=[],
                    pre_validation_signature="",
                    sessions_path=m.get("sessions_path") or "")
        except Exception:
            logger.warning("v2_find_processed_taint failed func_id=%s", func_id, exc_info=True)
            return None

    def v2_try_reserve_processed_taint(self, func_id: str, taint_sig: str,
                                       taint_params: str = "[]", sessions_path: str = "") -> bool:
        """V2 跨任务原子占位: INSERT ... WHERE NOT EXISTS。

        去重键: (source_dir_id, func_id, taint_signature) — 不含 task_id。
        任意任务已分析过该函数+该污点 → INSERT 被跳过, 返回 False。
        """
        try:
            with self._engine.connect() as conn:
                result = conn.execute(sa_text(
                    "INSERT INTO processed_taints "
                    "(source_dir_id, func_id, taint_signature, task_id, taint_params, sessions_path) "
                    "SELECT :sid, :fid, :ts, :tid, :tp, :sp "
                    "WHERE NOT EXISTS ("
                    "  SELECT 1 FROM processed_taints "
                    "  WHERE source_dir_id=:sid AND func_id=:fid AND taint_signature=:ts"
                    ")"),
                    {"sid": self.source_dir_id, "fid": func_id, "ts": taint_sig,
                     "tid": self.task_id, "tp": taint_params, "sp": sessions_path})
                conn.commit()
                return result.rowcount == 1
        except Exception:
            logger.warning("v2_try_reserve_processed_taint failed func_id=%s", func_id, exc_info=True)
            return False

    def v2_delete_processed_taint(self, func_id: str, taint_sig: str = "") -> None:
        """V2 删除占位: 仅删本任务的记录 (分析失败重试)。

        去重键不含 task_id (跨任务共享), 但删除只删自己的, 不影响其他任务。
        """
        with self._engine.connect() as conn:
            conn.execute(sa_text(
                "DELETE FROM processed_taints "
                "WHERE source_dir_id=:sid AND func_id=:fid AND taint_signature=:ts AND task_id=:tid"),
                {"sid": self.source_dir_id, "fid": func_id, "ts": taint_sig, "tid": self.task_id})
            conn.commit()

    def v2_add_processed_taint(self, func_id: str, taint_sig: str,
                               taint_params: str = "[]", sessions_path: str = "") -> None:
        """V2 写入 processed_taint (func_id 级, per-task)。"""
        self.v2_try_reserve_processed_taint(func_id, taint_sig, taint_params, sessions_path)

    # ── V2 计数方法 (诊断用) ────────────────────────────────────────
    def v2_count_orchestration(self) -> int:
        try:
            with self._engine.connect() as conn:
                row = conn.execute(sa_text(
                    "SELECT COUNT(*) FROM orchestration "
                    "WHERE source_dir_id=:sid AND task_id=:tid"),
                    {"sid": self.source_dir_id, "tid": self.task_id}).fetchone()
                return int(row[0]) if row else 0
        except Exception:
            return 0

    def v2_count_propagations(self) -> int:
        try:
            with self._engine.connect() as conn:
                row = conn.execute(sa_text(
                    "SELECT COUNT(*) FROM propagations "
                    "WHERE source_dir_id=:sid AND task_id=:tid"),
                    {"sid": self.source_dir_id, "tid": self.task_id}).fetchone()
                return int(row[0]) if row else 0
        except Exception:
            return 0

    def v2_count_taints(self) -> int:
        try:
            with self._engine.connect() as conn:
                row = conn.execute(sa_text(
                    "SELECT COUNT(*) FROM taints "
                    "WHERE source_dir_id=:sid AND task_id=:tid"),
                    {"sid": self.source_dir_id, "tid": self.task_id}).fetchone()
                return int(row[0]) if row else 0
        except Exception:
            return 0

    def upsert_taint(self, *, taint_id: str, func_id: str, name: str, signature: str,
                     file: str, function: str, next_propagations: str = "[]", description: str = ""):
        sql = """INSERT INTO taints (source_dir_id,taint_id,func_id,name,signature,`file`,`function`,
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
                "source_taint_name", "target_taint_name",
                "target_func_id", "target_function", "target_file", "call_line", "condition",
                "is_external", "is_indirect_call", "is_external_callee", "dispatch_kind",
                "escape_kind", "carrier", "escape_via", "callsite_validated",
                "branch_group_id", "branch_arm_id", "branch_path", "mutex_siblings",
                "actual_args", "validations", "description"]
        vals = {c: kw.get(c, "") for c in cols}
        placeholders = ", ".join(f":{c}" for c in cols)
        col_list = ", ".join(f"`{c}`" for c in cols)
        sql = (f"INSERT IGNORE INTO propagations (source_dir_id,{col_list},task_id) "
               f"VALUES (:sid,{placeholders},:task)")
        params = {"sid": self.source_dir_id, "task": self.task_id, **vals}
        with self._engine.connect() as conn:
            conn.execute(sa_text(sql), params)
            conn.commit()

    def upsert_orchestration_edge(self, *, edge_id: str, path_id: str, source_func_id: str,
                                  target_func_id: str, taint_params: str, depth: int,
                                  edge_order: int, status: str = "pending",
                                  source_function: str = "", source_signature: str = "",
                                  target_function: str = "", target_signature: str = ""):
        sql = """INSERT IGNORE INTO orchestration (source_dir_id,edge_id,path_id,source_func_id,
            target_func_id,taint_params,depth,edge_order,status,task_id,
            source_function,source_signature,target_function,target_signature)
            VALUES (:sid,:eid,:pid,:sfid,:tfid,:tp,:d,:eo,:st,:task,:sf,:ssig,:tf,:tsig)"""
        with self._engine.connect() as conn:
            conn.execute(sa_text(sql), {"sid": self.source_dir_id, "eid": edge_id, "pid": path_id,
                "sfid": source_func_id, "tfid": target_func_id, "tp": taint_params,
                "d": depth, "eo": edge_order, "st": status, "task": self.task_id,
                "sf": source_function, "ssig": source_signature,
                "tf": target_function, "tsig": target_signature})
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


def dispose_engine(self):
    """释放引擎 (按需加载: 任务结束后调用, 释放连接)。"""
    global _ENGINES
    with _ENGINES_LOCK:
        eng = _ENGINES.pop(self.db_name, None)
        if eng:
            try:
                eng.dispose()
                logger.info("disposed engine for db=%s", self.db_name)
            except Exception:
                pass


def create_shared_store(mysql_url: str, mode: str, source_root: str, task_id: str,
                          project_id: str = "") -> SharedMysqlStore | None:
    """工厂: 创建 SharedMysqlStore, 失败返回 None (不影响主流程)。"""
    try:
        return SharedMysqlStore(mysql_url, mode, source_root, task_id, project_id=project_id)
    except Exception as e:
        logger.warning("create SharedMysqlStore failed (mode=%s): %s", mode, e)
        return None
