"""dataflow-v2 四库存储层 (sqlite3)。

四个独立 sqlite 文件, 存放在 task run 目录下 dataflow-v2/:
  functions.db       函数库
  taints.db          污点库
  propagations.db    传播库
  orchestration.db   编排库

函数体不单独存文件 (数据库有 start_line/end_line, 需要时 read_function_body 从原源文件按行读)。

设计原则:
- 四库物理隔离 (匹配 "几个数据库" 的模型), 各自独立连接; 编排库不 JOIN
  其它库, 而是冗余存函数名/签名, 避免跨库 ATTACH。
- 所有 JSON 字段以 TEXT 存, 访问层 (de)serialize。
- 三重去重 (函数签名 + 污点参数 + 前置校验) 由 find_processed_taint() 实现。
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

from ..service.file_access_logging import sqlite_connect_logged
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

_DDL = {
    "functions": """
        CREATE TABLE IF NOT EXISTS functions (
            func_id          TEXT PRIMARY KEY,
            file             TEXT NOT NULL,
            name             TEXT NOT NULL,
            signature        TEXT NOT NULL,
            start_line       INTEGER NOT NULL,
            end_line         INTEGER NOT NULL,
            body_path        TEXT,
            func_hash        TEXT,
            description      TEXT DEFAULT '',
            processed_taints TEXT DEFAULT '[]',
            call_edges_indexed INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_func_name ON functions(name);
        CREATE INDEX IF NOT EXISTS idx_func_file ON functions(file);
        CREATE TABLE IF NOT EXISTS processed_taints (
            func_id                  TEXT NOT NULL,
            taint_signature          TEXT NOT NULL,
            pre_validation_signature TEXT NOT NULL DEFAULT '',
            taint_params             TEXT DEFAULT '[]',
            sessions_path            TEXT DEFAULT '',
            PRIMARY KEY (func_id)
        );
        CREATE INDEX IF NOT EXISTS idx_pt_func ON processed_taints(func_id);
        CREATE TABLE IF NOT EXISTS include_index (
            header TEXT NOT NULL,
            file   TEXT NOT NULL,
            PRIMARY KEY (header, file)
        );
        CREATE INDEX IF NOT EXISTS idx_include_header ON include_index(header);
        CREATE INDEX IF NOT EXISTS idx_include_file ON include_index(file);
        CREATE TABLE IF NOT EXISTS class_hierarchy (
            class_name  TEXT PRIMARY KEY,
            bases       TEXT DEFAULT '[]',
            file        TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS class_members (
            class_name   TEXT NOT NULL,
            member_name  TEXT NOT NULL,
            member_type  TEXT DEFAULT '',
            file         TEXT DEFAULT '',
            PRIMARY KEY (class_name, member_name)
        );
        CREATE INDEX IF NOT EXISTS idx_member_class ON class_members(class_name);
        CREATE INDEX IF NOT EXISTS idx_member_name ON class_members(member_name);
        CREATE TABLE IF NOT EXISTS indexing_files (
            file_path TEXT PRIMARY KEY,
            started_at REAL DEFAULT 0
        );
        -- 调用关系表 (按需填值): caller 调用 callee 的边
        CREATE TABLE IF NOT EXISTS call_edges (
            caller_func_id   TEXT NOT NULL,
            callee_name       TEXT NOT NULL,
            call_line         INTEGER NOT NULL DEFAULT 0,
            call_file         TEXT DEFAULT '',
            call_expr         TEXT DEFAULT '',
            PRIMARY KEY (caller_func_id, callee_name, call_line)
        );
        CREATE INDEX IF NOT EXISTS idx_call_edges_caller ON call_edges(caller_func_id);
        CREATE INDEX IF NOT EXISTS idx_call_edges_callee ON call_edges(callee_name);
    """,
    "taints": """
        CREATE TABLE IF NOT EXISTS taints (
            taint_id          TEXT PRIMARY KEY,
            func_id           TEXT NOT NULL,
            name              TEXT NOT NULL,
            signature         TEXT NOT NULL,
            file              TEXT NOT NULL,
            function          TEXT NOT NULL,
            next_propagations TEXT DEFAULT '[]',
            description       TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_taint_func ON taints(func_id);
        CREATE INDEX IF NOT EXISTS idx_taint_name ON taints(name);
    """,
    "propagations": """
        CREATE TABLE IF NOT EXISTS propagations (
            prop_id                TEXT PRIMARY KEY,
            source_func_id         TEXT,
            source_taint_name      TEXT NOT NULL,
            source_taint_signature TEXT NOT NULL,
            target_taint_name      TEXT NOT NULL,
            target_taint_signature TEXT NOT NULL,
            target_func_id         TEXT,
            target_function        TEXT,
            target_file            TEXT,
            call_line              INTEGER,
            condition              TEXT DEFAULT '',
            is_external            INTEGER DEFAULT 0,
            is_indirect_call       INTEGER DEFAULT 0,
            dispatch_kind          TEXT DEFAULT '',
            escape_kind            TEXT DEFAULT '',
            carrier                TEXT DEFAULT '',
            escape_via             TEXT DEFAULT '',
            callsite_validated     INTEGER DEFAULT 0,
            branch_group_id        TEXT DEFAULT '',
            branch_arm_id          TEXT DEFAULT '',
            branch_path            TEXT DEFAULT '[]',
            mutex_siblings         TEXT DEFAULT '[]',
            actual_args            TEXT DEFAULT '[]',
            validations            TEXT DEFAULT '[]',
            description            TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_prop_source ON propagations(source_func_id);
        CREATE INDEX IF NOT EXISTS idx_prop_target ON propagations(target_func_id);
        CREATE INDEX IF NOT EXISTS idx_prop_branch ON propagations(branch_group_id);
    """,
    "orchestration": """
        CREATE TABLE IF NOT EXISTS orchestration (
            edge_id          TEXT PRIMARY KEY,
            path_id          TEXT NOT NULL,
            source_function  TEXT NOT NULL,
            source_signature TEXT NOT NULL,
            source_func_id   TEXT NOT NULL,
            target_function  TEXT NOT NULL,
            target_signature TEXT NOT NULL,
            target_func_id   TEXT NOT NULL,
            taint_params     TEXT NOT NULL,
            depth            INTEGER NOT NULL,
            edge_order       INTEGER NOT NULL,
            status           TEXT DEFAULT 'pending'
        );
        CREATE INDEX IF NOT EXISTS idx_orch_path   ON orchestration(path_id);
        CREATE INDEX IF NOT EXISTS idx_orch_target ON orchestration(target_func_id);
        CREATE INDEX IF NOT EXISTS idx_orch_status ON orchestration(status);
    """,
}


class DataflowStore:
    """四库的统一访问层。线程安全 (每库一把锁; sqlite check_same_thread=False)。"""

    def __init__(self, run_dir: str | Path, mysql_store=None) -> None:
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir).mkdir(parents=True, exist_ok=True)
        self._mysql = mysql_store  # SharedMysqlStore (双写, 可选)
        self._paths = {
            "functions": self.run_dir / "functions.db",
            "taints": self.run_dir / "taints.db",
            "propagations": self.run_dir / "propagations.db",
            "orchestration": self.run_dir / "orchestration.db",
        }
        self._conns: dict[str, sqlite3.Connection] = {}
        self._locks: dict[str, threading.Lock] = {}
        for name, p in self._paths.items():
            conn = sqlite_connect_logged(
                p,
                logger=logger,
                purpose=f"v2_store_{name}",
                check_same_thread=False,
                timeout=30,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
            conn.executescript(_DDL[name])
            conn.commit()
            self._conns[name] = conn
            self._locks[name] = threading.Lock()
        # 轻量迁移: 为旧库补新列 (CREATE TABLE IF NOT EXISTS 不会加列)
        self._migrate_columns("propagations", [
            "escape_kind", "carrier", "escape_via",
        ])
        self._migrate_columns("functions", [
            "call_edges_indexed",
        ])
        # 迁移 processed_taints PK: historical variants → func_id only.
        self._migrate_processed_taints_pk()

    def _migrate_processed_taints_pk(self) -> None:
        """迁移 processed_taints PK 到 func_id 级别。

        历史表曾使用 (func_id, taint_sig, pre_val_sig) 或 (func_id, taint_sig),
        仍会让同一函数因不同污点名被重复分析。现在任务/epoch 内同一函数只分析一次。
        SQLite 不支持 ALTER TABLE DROP CONSTRAINT, 所以重建表。
        """
        with self._locks["functions"]:
            c = self._conns["functions"]
            try:
                cols = c.execute("PRAGMA table_info(processed_taints)").fetchall()
                pk_cols = sorted(r["name"] for r in cols if r["pk"] > 0)
                if pk_cols == ["func_id"]:
                    return  # 已是新 schema
            except Exception as e:
                logger.debug("processed_taints schema check failed: %s", e)
                return
            logger.info("[V2-store] migrating processed_taints PK to func_id-only")
            c.executescript("""
                DROP TABLE IF EXISTS _pt_new;
                CREATE TABLE IF NOT EXISTS _pt_new (
                    func_id TEXT NOT NULL, taint_signature TEXT NOT NULL,
                    pre_validation_signature TEXT NOT NULL DEFAULT '',
                    taint_params TEXT DEFAULT '[]', sessions_path TEXT DEFAULT '',
                    PRIMARY KEY (func_id)
                );
                INSERT OR IGNORE INTO _pt_new
                    (func_id, taint_signature, pre_validation_signature, taint_params, sessions_path)
                SELECT func_id, taint_signature, pre_validation_signature, taint_params, sessions_path
                FROM processed_taints ORDER BY func_id, taint_signature, pre_validation_signature;
                DROP TABLE processed_taints;
                ALTER TABLE _pt_new RENAME TO processed_taints;
                CREATE INDEX IF NOT EXISTS idx_pt_func ON processed_taints(func_id);
            """)
            c.commit()
            logger.info("[V2-store] migration done, rows=%d", c.execute("SELECT count(*) FROM processed_taints").fetchone()[0])

    def _migrate_columns(self, db: str, cols: list[str]) -> None:
        """为已有表补列 (TEXT, 默认 ''), 已有则跳过。"""
        table = db
        existing = {r["name"] for r in self._q(db, f"PRAGMA table_info({table})")}
        for c in cols:
            if c not in existing:
                try:
                    self._exec(db, f"ALTER TABLE {table} ADD COLUMN {c} TEXT DEFAULT ''")
                except sqlite3.OperationalError:
                    logger.warning(
                        "[V2-store] add column skipped db=%s column=%s",
                        db,
                        c,
                        exc_info=True,
                    )

    # ── 通用 ────────────────────────────────────────────────────────────────
    def close(self) -> None:
        for c in self._conns.values():
            try:
                c.close()
            except Exception:
                logger.warning("[V2-store] close connection failed", exc_info=True)

    def _exec(self, db: str, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._locks[db]:
            cur = self._conns[db].execute(sql, params)
            self._conns[db].commit()
            return cur

    def _q(self, db: str, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._locks[db]:
            return list(self._conns[db].execute(sql, params).fetchall())

    # ── 函数库 ──────────────────────────────────────────────────────────────
    def upsert_function(self, rec: FunctionRecord) -> None:
        # MySQL ONLY (SQLite 废弃): functions 表只写 MySQL, 不写 functions.db
        if self._mysql:
            self._mysql.upsert_function(func_id=rec.func_id, file=rec.file, name=rec.name,
                signature=rec.signature, start_line=rec.start_line, end_line=rec.end_line,
                func_hash=rec.func_hash or "", description=rec.description or "")

    def get_function(self, func_id: str) -> FunctionRecord | None:
        if self._mysql:
            return self._mysql.read_function(func_id)
        return None

    def find_function(self, name: str, file: str = "") -> FunctionRecord | None:
        """按名查找函数。C++ 方法: LLM 报短名 (ReadDataTask), 库存限定名
        (Class::ReadDataTask) → 先精确匹配, 再后缀匹配 (::短名 或 =短名)。"""
        matches = self.find_functions(name, file)
        return matches[0] if matches else None

    def find_functions(self, name: str, file: str = "") -> list[FunctionRecord]:
        """按名查找全部候选函数。

        解析顺序保持与 find_function 一致, 但不在多匹配时丢弃候选:
        1. 原始名称精确匹配
        2. 限定名退回尾名精确匹配
        3. 尾名后缀匹配 `%::tail`

        一旦某一层有命中, 仅返回该层结果, 不再混入后续回退层, 避免把
        精确匹配和宽松匹配揉成一锅。
        """
        # MySQL 优先
        if self._mysql:
            mrecs = self._mysql.read_functions(name, file)
            return mrecs or []  # MySQL ONLY (SQLite 废弃)
        return []  # SQLite 废弃: find_functions 只用 MySQL

    def list_functions(self) -> list[FunctionRecord]:
        if self._mysql:
            return self._mysql.read_list_functions()
        return []  # SQLite 废弃

    def count_functions(self) -> int:
        if self._mysql:
            return self._mysql.count_functions()
        return 0  # SQLite 废弃

    def functions_by_file(self, file: str) -> list[FunctionRecord]:
        if self._mysql:
            return self._mysql.read_functions_by_file(file)
        return []  # SQLite 废弃

    # ── 调用关系 (call_edges) ──────────────────────────────────────────
    def save_call_edges(self, caller_func_id: str, edges: list[dict]) -> None:
        """存储函数调用边 (按需填值, INSERT OR IGNORE 幂等)。
        edges: [{callee_name, call_line, call_file, call_expr}, ...]
        同时标记 call_edges_indexed=1 防止重复提取。"""
        if not edges: return
        with self._locks["functions"]:
            c = self._conns["functions"]
            for e in edges:
                c.execute(
                    "INSERT OR IGNORE INTO call_edges "
                    "(caller_func_id, callee_name, call_line, call_file, call_expr) "
                    "VALUES (?,?,?,?,?)",
                    (caller_func_id, e.get("callee_name", ""),
                     e.get("call_line", 0), e.get("call_file", ""), e.get("call_expr", "")))
            # 标记已提取
            c.execute(
                "UPDATE functions SET call_edges_indexed=1 WHERE func_id=?", (caller_func_id,))
            c.commit()

    def is_call_edges_indexed(self, func_id: str) -> bool:
        """查某函数的 call_edges 是否已提取 (避免重复查找)。"""
        rows = self._q("functions",
            "SELECT call_edges_indexed FROM functions WHERE func_id=?", (func_id,))
        return bool(rows and rows[0]["call_edges_indexed"])

    def query_callees(self, caller_func_id: str) -> list[dict]:
        """查某函数调用了哪些函数 (callee)。返回 [{callee_name, call_line, call_file, call_expr}, ...]"""
        rows = self._q("functions",
            "SELECT callee_name, call_line, call_file, call_expr "
            "FROM call_edges WHERE caller_func_id=? ORDER BY call_line", (caller_func_id,))
        return [dict(r) for r in rows] if rows else []

    def query_callers(self, callee_name: str) -> list[dict]:
        """查哪些函数调用了某函数 (caller)。返回 [{caller_func_id, call_line, call_file, call_expr}, ...]"""
        rows = self._q("functions",
            "SELECT caller_func_id, call_line, call_file, call_expr "
            "FROM call_edges WHERE callee_name=? ORDER BY caller_func_id", (callee_name,))
        return [dict(r) for r in rows] if rows else []

    # ── include 索引 (C 作用域) ────────────────────────────────────────
    def add_include(self, header: str, file: str) -> None:
        if self._mysql:
            try:
                self._mysql.add_include(header, file)
                return
            except Exception:
                logger.warning("mysql add_include failed, fallback sqlite: header=%s file=%s", header, file, exc_info=True)
        # SQLite 废弃: include_index 只写 MySQL

    def get_files_including(self, header: str) -> list[str]:
        """查找所有传递性 include 了指定 header 的 .c/.cpp 文件。"""
        if self._mysql:
            files = self._mysql.read_files_including(header)
            if files: return files
        return []  # SQLite 废弃

    # ── class 继承图 (C++ 作用域) ──────────────────────────────────────
    def add_class(self, class_name: str, bases: list[str], file: str = "") -> None:
        import json
        if self._mysql:
            try:
                self._mysql.add_class(class_name, json.dumps(bases), file)
                return
            except Exception:
                logger.warning("mysql add_class failed, fallback sqlite: class_name=%s", class_name, exc_info=True)
        # SQLite 废弃: class_hierarchy 只写 MySQL

    def add_class_member(self, class_name: str, member_name: str,
                         member_type: str = "", file: str = "") -> None:
        if self._mysql:
            try:
                self._mysql.add_class_member(class_name, member_name, member_type, file)
                return
            except Exception:
                logger.warning(
                    "mysql add_class_member failed, fallback sqlite: class_name=%s member_name=%s",
                    class_name, member_name, exc_info=True)
        # SQLite 废弃: class_members 只写 MySQL

    def get_bases(self, class_name: str) -> list[str]:
        import json
        if self._mysql:
            return self._mysql.read_bases(class_name)
        return []  # SQLite 废弃
        return json.loads(rows[0]["bases"] or "[]") if rows else []

    def get_all_ancestors(self, class_name: str) -> list[str]:
        """传递闭包: class → 所有祖先类 (含间接继承)。"""
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
        """传递闭包: class → 所有派生类 (含间接继承)。"""
        # 反向遍历: 找所有 bases 含 class_name 的类
        import json
        visited = {class_name}
        if self._mysql:
            descs = self._mysql.read_all_descendants(class_name)
            return descs or []  # MySQL ONLY
