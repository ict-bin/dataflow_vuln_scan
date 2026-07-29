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
            PRIMARY KEY (func_id, taint_signature)
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
        # 迁移 processed_taints PK: (func_id, taint_sig, pre_val) → (func_id, taint_sig)
        self._migrate_processed_taints_pk()

    def _migrate_processed_taints_pk(self) -> None:
        """迁移 processed_taints PK: (func_id, taint_sig, pre_val_sig) → (func_id, taint_sig)。

        旧表 PK 含 pre_validation_signature, 导致同 (func, taint) 不同 pre_val 产生多行。
        新 PK 只用 (func_id, taint_signature), 保证每个 (func, taint) 只有一条记录。
        SQLite 不支持 ALTER TABLE DROP CONSTRAINT, 所以重建表。
        """
        with self._locks["functions"]:
            c = self._conns["functions"]
            try:
                cols = c.execute("PRAGMA table_info(processed_taints)").fetchall()
                pk_cols = sorted(r["name"] for r in cols if r["pk"] > 0)
                if pk_cols == ["func_id", "taint_signature"]:
                    return  # 已是新 schema
            except Exception as e:
                logger.debug("processed_taints schema check failed: %s", e)
                return
            logger.info("[V2-store] migrating processed_taints PK: (func,taint,pre_val) → (func,taint)")
            c.executescript("""
                CREATE TABLE IF NOT EXISTS _pt_new (
                    func_id TEXT NOT NULL, taint_signature TEXT NOT NULL,
                    pre_validation_signature TEXT NOT NULL DEFAULT '',
                    taint_params TEXT DEFAULT '[]', sessions_path TEXT DEFAULT '',
                    PRIMARY KEY (func_id, taint_signature)
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
        existing = {r["name"] for r in self._q(db, "PRAGMA table_info(propagations)")}
        for c in cols:
            if c not in existing:
                try:
                    self._exec(db, f"ALTER TABLE propagations ADD COLUMN {c} TEXT DEFAULT ''")
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
        r = rec.to_row()
        self._exec("functions", """
            INSERT INTO functions (func_id,file,name,signature,start_line,end_line,
                body_path,func_hash,description,processed_taints)
            VALUES (:func_id,:file,:name,:signature,:start_line,:end_line,
                :body_path,:func_hash,:description,:processed_taints)
            ON CONFLICT(func_id) DO UPDATE SET
                file=excluded.file, name=excluded.name, signature=excluded.signature,
                start_line=excluded.start_line, end_line=excluded.end_line,
                body_path=excluded.body_path, func_hash=excluded.func_hash,
                description=excluded.description
        """, r)
        if self._mysql:
            try:
                self._mysql.upsert_function(func_id=rec.func_id, file=rec.file, name=rec.name,
                    signature=rec.signature, start_line=rec.start_line, end_line=rec.end_line,
                    func_hash=rec.func_hash or "", description=rec.description or "")
            except Exception:
                logger.warning("mysql upsert_function failed: func_id=%s", rec.func_id, exc_info=True)

    def get_function(self, func_id: str) -> FunctionRecord | None:
        if self._mysql:
            rec = self._mysql.read_function(func_id)
            if rec: return rec
        row = self._q("functions", "SELECT * FROM functions WHERE func_id=?", (func_id,))
        return _row_to_function(row[0]) if row else None

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
            if mrecs: return mrecs
        seen: set[str] = set()

        def _rows(sql: str, args: tuple) -> list[FunctionRecord]:
            out: list[FunctionRecord] = []
            for row in self._q("functions", sql, args):
                rec = _row_to_function(row)
                if rec.func_id in seen:
                    continue
                seen.add(rec.func_id)
                out.append(rec)
            return out

        exact = _rows(
            "SELECT * FROM functions WHERE name=? ORDER BY start_line",
            (name,),
        ) if not file else _rows(
            "SELECT * FROM functions WHERE name=? AND file=? ORDER BY start_line",
            (name, file),
        )
        if exact:
            return exact

        tail = ""
        if "::" in name:
            tail = name.split("::")[-1].strip()
            if tail:
                tail_exact = _rows(
                    "SELECT * FROM functions WHERE name=? ORDER BY start_line",
                    (tail,),
                ) if not file else _rows(
                    "SELECT * FROM functions WHERE name=? AND file=? ORDER BY start_line",
                    (tail, file),
                )
                if tail_exact:
                    return tail_exact
        else:
            tail = name

        if not tail:
            return []
        suf = "%::" + tail
        result = _rows(
            "SELECT * FROM functions WHERE name LIKE ? ORDER BY start_line",
            (suf,),
        ) if not file else _rows(
            "SELECT * FROM functions WHERE name LIKE ? AND file=? ORDER BY start_line",
            (suf, file),
        )
        return result

    def list_functions(self) -> list[FunctionRecord]:
        if self._mysql:
            recs = self._mysql.read_list_functions()
            if recs: return recs
        rows = self._q("functions", "SELECT * FROM functions")
        return [_row_to_function(r) for r in rows] if rows else []

    def count_functions(self) -> int:
        """快速计数 (COUNT, 不加载全部行)。"""
        if self._mysql:
            cnt = self._mysql.count_functions()
            if cnt: return cnt
        rows = self._q("functions", "SELECT COUNT(*) as c FROM functions")
        return rows[0]["c"] if rows else 0

    def functions_by_file(self, file: str) -> list[FunctionRecord]:
        """按文件查函数 (用索引, 不全量扫描)。"""
        if self._mysql:
            recs = self._mysql.read_functions_by_file(file)
            if recs: return recs
        rows = self._q("functions", "SELECT * FROM functions WHERE file=? ORDER BY start_line", (file,))
        return [_row_to_function(r) for r in rows] if rows else []

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
        self._exec("functions",
                   "INSERT OR IGNORE INTO include_index (header, file) VALUES (?, ?)",
                   (header, file))
        if self._mysql:
            try:
                self._mysql.add_include(header, file)
            except Exception:
                logger.warning("mysql add_include failed: header=%s file=%s", header, file, exc_info=True)

    def get_files_including(self, header: str) -> list[str]:
        """查找所有传递性 include 了指定 header 的 .c/.cpp 文件。"""
        if self._mysql:
            files = self._mysql.read_files_including(header)
            if files: return files
        rows = self._q("functions", "SELECT file FROM include_index WHERE header=?", (header,))
        return [r["file"] for r in rows] if rows else []

    # ── class 继承图 (C++ 作用域) ──────────────────────────────────────
    def add_class(self, class_name: str, bases: list[str], file: str = "") -> None:
        import json
        self._exec("functions",
                   "INSERT OR REPLACE INTO class_hierarchy (class_name, bases, file) VALUES (?, ?, ?)",
                   (class_name, json.dumps(bases), file))
        if self._mysql:
            try:
                self._mysql.add_class(class_name, json.dumps(bases), file)
            except Exception:
                logger.warning("mysql add_class failed: class_name=%s", class_name, exc_info=True)

    def add_class_member(self, class_name: str, member_name: str,
                         member_type: str = "", file: str = "") -> None:
        self._exec("functions",
                   "INSERT OR IGNORE INTO class_members (class_name, member_name, member_type, file) VALUES (?, ?, ?, ?)",
                   (class_name, member_name, member_type, file))
        if self._mysql:
            try:
                self._mysql.add_class_member(class_name, member_name, member_type, file)
            except Exception:
                logger.warning(
                    "mysql add_class_member failed: class_name=%s member_name=%s",
                    class_name,
                    member_name,
                    exc_info=True,
                )

    def get_bases(self, class_name: str) -> list[str]:
        import json
        if self._mysql:
            bases = self._mysql.read_bases(class_name)
            if bases: return bases
        rows = self._q("functions", "SELECT bases FROM class_hierarchy WHERE class_name=?", (class_name,))
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
            if descs: return descs
        rows = self._q("functions", "SELECT class_name, bases FROM class_hierarchy")
        changed = True
        while changed:
            changed = False
            for r in rows:
                if r["class_name"] in visited:
                    continue
                bases = json.loads(r["bases"] or "[]")
                if any(b in visited for b in bases):
                    visited.add(r["class_name"])
                    changed = True
        visited.discard(class_name)
        return list(visited)

    def get_member_declaring_class(self, class_name: str, member_name: str) -> str | None:
        """查找 member 声明在哪个类 (从 class_name 往祖先找)。"""
        candidates = [class_name] + self.get_all_ancestors(class_name)
        for cls in candidates:
            rows = self._q("functions",
                           "SELECT class_name FROM class_members WHERE class_name=? AND member_name=?",
                           (cls, member_name))
        if self._mysql:
            result = self._mysql.read_member_declaring_class(class_name, member_name)
            if result: return result
        for cls in candidates:
            rows = self._q("functions",
                           "SELECT class_name FROM class_members WHERE class_name=? AND member_name=?",
                           (cls, member_name))
            if rows:
                return cls
        return None

    def get_class_scope_methods(self, class_name: str, member_name: str = "") -> list[str]:
        """获取能访问 member 的所有方法 (声明类 + 所有派生类的方法)。

        返回函数名列表 (Class::method 格式)。
        """
        if member_name:
            declaring_class = self.get_member_declaring_class(class_name, member_name)
            if not declaring_class:
                declaring_class = class_name
        else:
            declaring_class = class_name
        if self._mysql:
            methods = self._mysql.read_class_scope_methods(class_name, member_name)
            if methods: return methods
        # 声明类 + 所有派生类
        classes = {declaring_class} | set(self.get_all_descendants(declaring_class))
        # 查函数名以 ClassName:: 开头的
        result = []
        for cls in classes:
            like_pattern = f"{cls}::%"
            rows = self._q("functions", "SELECT name FROM functions WHERE name LIKE ?", (like_pattern,))
            result.extend(r["name"] for r in rows)
        return result

    def get_functions_with_type_in_signature(self, type_name: str) -> list[str]:
        """查找签名中包含指定类型的函数 (用于 C struct 字段作用域)。"""
        if self._mysql:
            names = self._mysql.read_functions_with_type_in_signature(type_name)
            if names: return names
        like_pattern = f"%{type_name}%"
        rows = self._q("functions", "SELECT name FROM functions WHERE signature LIKE ?", (like_pattern,))
        return [r["name"] for r in rows] if rows else []

    def add_processed_taint(self, func_id: str, pt: ProcessedTaint) -> None:
        """写入 processed_taint (INSERT OR IGNORE, PRIMARY KEY 去重)。"""
        ts = _norm_sig(pt.taint_signature or "")
        pvs = pt.pre_validation_signature or ""
        self._exec("functions",
            "INSERT OR IGNORE INTO processed_taints (func_id, taint_signature, pre_validation_signature, taint_params, sessions_path) VALUES (?,?,?,?,?)",
            (func_id, ts, pvs, json.dumps(pt.taint_params, ensure_ascii=False), pt.sessions_path))
        # 注: processed_taints 不双写 MySQL — 它是"本任务 BFS 去重/占位"状态, 必须任务级隔离;
        # per-source-dir MySQL 跨任务共享, 双写会导致新任务根函数被前任务残留记录跳过 (0 分析)。

    def try_reserve_processed_taint(self, func_id: str, pt: ProcessedTaint) -> bool:
        """分析前预留占位 (MySQL 优先原子占位, SQLite 为本地缓存)。

        去重键: (func_id, taint_signature)。MySQL INSERT IGNORE 是跨 worker
        原子操作; SQLite 做本地缓存。analyze 失败时 delete 占位 (可重试)。
        """
        ts = _norm_sig(pt.taint_signature or "")
        pvs = pt.pre_validation_signature or ""
        tp_json = json.dumps(pt.taint_params, ensure_ascii=False)
        # processed_taints 仅用任务本地 SQLite (per-epoch): 单 worker/单进程内原子占位即可。
        # 不走 MySQL: per-source-dir 库跨任务共享, 会导致跨任务残留跳过根分析。
        with self._locks["functions"]:
            row = self._conns["functions"].execute(
                "SELECT 1 FROM processed_taints WHERE func_id=? AND taint_signature=? LIMIT 1",
                (func_id, ts)).fetchone()
            if row is not None:
                return False
            cur = self._conns["functions"].execute(
                "INSERT OR IGNORE INTO processed_taints (func_id, taint_signature, pre_validation_signature, taint_params, sessions_path) VALUES (?,?,?,?,?)",
                (func_id, ts, pvs, tp_json, pt.sessions_path))
            self._conns["functions"].commit()
            return cur.rowcount == 1

    def delete_processed_taint(self, func_id: str, taint_signature: str,
                               pre_validation_signature: str = "") -> None:
        ts = _norm_sig(taint_signature or "")
        self._exec("functions",
            "DELETE FROM processed_taints WHERE func_id=? AND taint_signature=?",
            (func_id, ts))
        # 不双写 MySQL (见 try_reserve 注释)

    def find_processed_taint(self, func_id: str, taint_signature: str,
                             pre_validation_signature: str = "") -> ProcessedTaint | None:
        """二重去重: (func_id, taint_signature) — 不依赖前置校验集。

        只要同一函数+同一污点已被分析过, 后续任何路径到达都不重分析。
        pre_validation_signature 参数保留兼容签名但不参与查询。
        """
        ts = _norm_sig(taint_signature)
        # 仅查任务本地 SQLite (per-epoch); 不查共享 MySQL 避免跨任务残留误判"已分析"。
        rows = self._q("functions",
            "SELECT taint_signature, pre_validation_signature, taint_params, sessions_path FROM processed_taints WHERE func_id=? AND taint_signature=? LIMIT 1",
            (func_id, ts))
        if rows:
            r = rows[0]
            return ProcessedTaint(taint_params=json.loads(r["taint_params"] or "[]"),
                                   taint_signature=r["taint_signature"], pre_validations=[],
                                   pre_validation_signature=r["pre_validation_signature"],
                                   sessions_path=r["sessions_path"])
        return None

    # ── 污点库 ──────────────────────────────────────────────────────────────
    def upsert_taint(self, rec: TaintRecord) -> None:
        r = rec.to_row()
        self._exec("taints", """
            INSERT INTO taints (taint_id,func_id,name,signature,file,function,
                next_propagations,description)
            VALUES (:taint_id,:func_id,:name,:signature,:file,:function,
                :next_propagations,:description)
            ON CONFLICT(taint_id) DO UPDATE SET
                next_propagations=excluded.next_propagations, description=excluded.description
        """, r)
        if self._mysql:
            try: self._mysql.upsert_taint(taint_id=r["taint_id"], func_id=r["func_id"],
                name=r["name"], signature=r["signature"], file=r["file"], function=r["function"],
                next_propagations=r["next_propagations"], description=r["description"])
            except Exception: logger.debug("mysql upsert_taint failed", exc_info=True)

    def get_taint(self, taint_id: str) -> TaintRecord | None:
        row = self._q("taints", "SELECT * FROM taints WHERE taint_id=?", (taint_id,))
        return _row_to_taint(row[0]) if row else None

    def list_taints_in_function(self, func_id: str) -> list[TaintRecord]:
        if self._mysql:
            recs = self._mysql.read_taints_in_function(func_id)
            if recs: return recs
        rows = self._q("taints", "SELECT * FROM taints WHERE func_id=?", (func_id,))
        return [_row_to_taint(r) for r in rows] if rows else []

    def add_propagation_to_taint(self, taint_id: str, prop_id: str) -> None:
        t = self.get_taint(taint_id)
        if t is None:
            return
        if prop_id not in t.next_propagations:
            t.next_propagations.append(prop_id)
            self._exec("taints", "UPDATE taints SET next_propagations=? WHERE taint_id=?",
                       (json.dumps(t.next_propagations, ensure_ascii=False), taint_id))

    # ── 传播库 ──────────────────────────────────────────────────────────────
    def upsert_propagation(self, rec: PropagationRecord) -> None:
        r = rec.to_row()
        self._exec("propagations", """
            INSERT INTO propagations (prop_id,source_func_id,source_taint_name,
                source_taint_signature,target_taint_name,target_taint_signature,
                target_func_id,target_function,target_file,call_line,condition,is_external,
                is_indirect_call,dispatch_kind,
                escape_kind,carrier,escape_via,
                callsite_validated,branch_group_id,branch_arm_id,branch_path,mutex_siblings,
                actual_args,validations,description)
            VALUES (:prop_id,:source_func_id,:source_taint_name,
                :source_taint_signature,:target_taint_name,:target_taint_signature,
                :target_func_id,:target_function,:target_file,:call_line,:condition,:is_external,
                :is_indirect_call,:dispatch_kind,
                :escape_kind,:carrier,:escape_via,
                :callsite_validated,:branch_group_id,:branch_arm_id,:branch_path,:mutex_siblings,
                :actual_args,:validations,:description)
            ON CONFLICT(prop_id) DO UPDATE SET
                target_func_id=excluded.target_func_id, target_function=excluded.target_function,
                target_file=excluded.target_file, call_line=excluded.call_line,
                condition=excluded.condition, is_external=excluded.is_external,
                is_indirect_call=excluded.is_indirect_call, dispatch_kind=excluded.dispatch_kind,
                escape_kind=excluded.escape_kind, carrier=excluded.carrier, escape_via=excluded.escape_via,
                callsite_validated=excluded.callsite_validated,
                branch_group_id=excluded.branch_group_id, branch_arm_id=excluded.branch_arm_id,
                branch_path=excluded.branch_path, mutex_siblings=excluded.mutex_siblings,
                actual_args=excluded.actual_args,
                validations=excluded.validations, description=excluded.description
        """, r)
        if self._mysql:
            try: self._mysql.upsert_propagation(**r)
            except Exception: logger.debug("mysql upsert_propagation failed", exc_info=True)

    def get_propagation(self, prop_id: str) -> PropagationRecord | None:
        if self._mysql:
            rec = self._mysql.read_propagation(prop_id)
            if rec: return rec
        row = self._q("propagations", "SELECT * FROM propagations WHERE prop_id=?", (prop_id,))
        return _row_to_propagation(row[0]) if row else None

    def list_propagations_from(self, func_id: str) -> list[PropagationRecord]:
        if self._mysql:
            recs = self._mysql.read_propagations_from(func_id)
            if recs: return recs
        rows = self._q("propagations", "SELECT * FROM propagations WHERE source_func_id=?", (func_id,))
        return [_row_to_propagation(r) for r in rows] if rows else []

    # ── 编排库 ──────────────────────────────────────────────────────────────
    def upsert_edge(self, edge: OrchestrationEdge) -> None:
        r = edge.to_row()
        self._exec("orchestration", """
            INSERT INTO orchestration (edge_id,path_id,source_function,source_signature,
                source_func_id,target_function,target_signature,target_func_id,
                taint_params,depth,edge_order,status)
            VALUES (:edge_id,:path_id,:source_function,:source_signature,
                :source_func_id,:target_function,:target_signature,:target_func_id,
                :taint_params,:depth,:edge_order,:status)
            ON CONFLICT(edge_id) DO UPDATE SET status=excluded.status
        """, r)
        if self._mysql:
            try: self._mysql.upsert_orchestration_edge(edge_id=r["edge_id"], path_id=r["path_id"],
                source_func_id=r["source_func_id"], target_func_id=r["target_func_id"],
                taint_params=r["taint_params"], depth=r["depth"], edge_order=r["edge_order"],
                status=r["status"],
                source_function=r["source_function"], source_signature=r["source_signature"],
                target_function=r["target_function"], target_signature=r["target_signature"])
            except Exception: logger.debug("mysql upsert_edge failed", exc_info=True)

    def set_edge_status(self, edge_id: str, status: str) -> None:
        self._exec("orchestration", "UPDATE orchestration SET status=? WHERE edge_id=?", (status, edge_id))

    def list_path_edges(self, path_id: str) -> list[OrchestrationEdge]:
        if self._mysql:
            recs = self._mysql.read_path_edges(path_id)
            if recs: return recs
        rows = self._q("orchestration", "SELECT * FROM orchestration WHERE path_id=? ORDER BY edge_order", (path_id,))
        return [_row_to_edge(r) for r in rows] if rows else []

    def pending_edges(self) -> list[OrchestrationEdge]:
        if self._mysql:
            recs = self._mysql.read_pending_edges()
            if recs: return recs
        rows = self._q("orchestration", "SELECT * FROM orchestration WHERE status='pending' ORDER BY depth, edge_order")
        return [_row_to_edge(r) for r in rows] if rows else []


# ── row → record 反序列化 ────────────────────────────────────────────────────

def _row_to_function(row: sqlite3.Row) -> FunctionRecord:
    pts_raw = json.loads(row["processed_taints"] or "[]")
    pts = [ProcessedTaint(**{k: p.get(k) for k in (
        "taint_params", "taint_signature", "pre_validations", "pre_validation_signature", "sessions_path")})
        for p in pts_raw]
    return FunctionRecord(
        file=row["file"], name=row["name"], signature=row["signature"],
        start_line=row["start_line"], end_line=row["end_line"], body_path=row["body_path"],
        func_hash=row["func_hash"], description=row["description"],
        processed_taints=pts, func_id=row["func_id"])


def _row_to_taint(row: sqlite3.Row) -> TaintRecord:
    return TaintRecord(
        taint_id=row["taint_id"], func_id=row["func_id"], name=row["name"],
        signature=row["signature"], file=row["file"], function=row["function"],
        next_propagations=json.loads(row["next_propagations"] or "[]"),
        description=row["description"])


def _row_to_propagation(row: sqlite3.Row) -> PropagationRecord:
    vals = json.loads(row["validations"] or "[]")
    return PropagationRecord(
        prop_id=row["prop_id"], source_func_id=row["source_func_id"],
        source_taint_name=row["source_taint_name"], source_taint_signature=row["source_taint_signature"],
        target_taint_name=row["target_taint_name"], target_taint_signature=row["target_taint_signature"],
        target_func_id=row["target_func_id"], target_function=row["target_function"],
        target_file=row["target_file"], call_line=row["call_line"], condition=row["condition"],
        is_external=bool(row["is_external"]), callsite_validated=bool(row["callsite_validated"]),
        is_indirect_call=bool(row["is_indirect_call"]), dispatch_kind=row["dispatch_kind"],
        escape_kind=row["escape_kind"], carrier=row["carrier"], escape_via=row["escape_via"],
        branch_group_id=row["branch_group_id"], branch_arm_id=row["branch_arm_id"],
        branch_path=json.loads(row["branch_path"] or "[]"),
        mutex_siblings=json.loads(row["mutex_siblings"] or "[]"),
        actual_args=json.loads(row["actual_args"] or "[]"),
        validations=[_validation_from_dict(v) for v in vals if isinstance(v, dict)],
        description=row["description"])


def _row_to_edge(row: sqlite3.Row) -> OrchestrationEdge:
    return OrchestrationEdge(
        edge_id=row["edge_id"], path_id=row["path_id"],
        source_function=row["source_function"], source_signature=row["source_signature"],
        source_func_id=row["source_func_id"],
        target_function=row["target_function"], target_signature=row["target_signature"],
        target_func_id=row["target_func_id"],
        taint_params=TaintParamInfo.from_json(row["taint_params"]),
        depth=row["depth"], edge_order=row["edge_order"], status=row["status"])
