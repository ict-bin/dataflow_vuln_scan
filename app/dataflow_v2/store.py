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
        # MySQL ONLY (SQLite 废弃): functions 表只写 MySQL
        if self._mysql:
            self._mysql.upsert_function(func_id=rec.func_id, file=rec.file, name=rec.name,
                signature=rec.signature, start_line=rec.start_line, end_line=rec.end_line,
                func_hash=rec.func_hash or "", description=rec.description or "")

    def get_function(self, func_id: str) -> FunctionRecord | None:
        if self._mysql:
            return self._mysql.read_function(func_id)
        return None  # SQLite 废弃

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
        # MySQL ONLY (SQLite 废弃)
        if self._mysql:
            mrecs = self._mysql.read_functions(name, file)
            return mrecs or []
        return []

    def list_functions(self) -> list[FunctionRecord]:
        if self._mysql:
            return self._mysql.read_list_functions() or []
        return []  # SQLite 废弃

    def count_functions(self) -> int:
        """快速计数 (COUNT, 不加载全部行)。"""
        if self._mysql:
            return self._mysql.count_functions()
        return 0  # SQLite 废弃

    def functions_by_file(self, file: str) -> list[FunctionRecord]:
        """按文件查函数 (用索引, 不全量扫描)。"""
        if self._mysql:
            return self._mysql.read_functions_by_file(file) or []
        return []  # SQLite 废弃

    # ── 调用关系 (call_edges) ──────────────────────────────────────────
    def save_call_edges(self, caller_func_id: str, edges: list[dict]) -> None:
        """存储函数调用边到 SQLite (无 MySQL 镜像, 仅 worker 单进程写)。
        edges: [{callee_name, call_line, call_file, call_expr}, ...]"""
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
            c.commit()

    def is_call_edges_indexed(self, func_id: str) -> bool:
        """查某函数的 call_edges 是否已提取 (避免重复查找)。
        废弃: functions 表已改 MySQL ONLY, 此方法仅查 SQLite (无数据)。
        如需查重请用 query_callees 返回值非空判断。"""
        return False  # SQLite 废弃

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
            self._mysql.add_include(header, file)
        # SQLite 废弃: include_index 只写 MySQL

    def get_files_including(self, header: str) -> list[str]:
        """查找所有传递性 include 了指定 header 的 .c/.cpp 文件。"""
        if self._mysql:
            return self._mysql.read_files_including(header) or []
        return []  # SQLite 废弃

    # ── class 继承图 (C++ 作用域) ──────────────────────────────────────
    def add_class(self, class_name: str, bases: list[str], file: str = "") -> None:
        import json
        if self._mysql:
            self._mysql.add_class(class_name, json.dumps(bases), file)
        # SQLite 废弃: class_hierarchy 只写 MySQL

    def add_class_member(self, class_name: str, member_name: str,
                         member_type: str = "", file: str = "") -> None:
        if self._mysql:
            self._mysql.add_class_member(class_name, member_name, member_type, file)
        # SQLite 废弃: class_members 只写 MySQL

    def get_bases(self, class_name: str) -> list[str]:
        if self._mysql:
            return self._mysql.read_bases(class_name) or []
        return []  # SQLite 废弃

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
        if self._mysql:
            descs = self._mysql.read_all_descendants(class_name)
            return descs or []  # MySQL ONLY (SQLite 废弃)
        return []  # SQLite 废弃

    def get_member_declaring_class(self, class_name: str, member_name: str) -> str | None:
        """查找 member 声明在哪个类 (从 class_name 往祖先找)。"""
        if self._mysql:
            result = self._mysql.read_member_declaring_class(class_name, member_name)
            if result: return result
        return None  # SQLite 废弃

    def get_class_scope_methods(self, class_name: str, member_name: str = "") -> list[str]:
        """获取能访问 member 的所有方法 (声明类 + 所有派生类的方法)。

        返回函数名列表 (Class::method 格式)。
        """
        if self._mysql:
            methods = self._mysql.read_class_scope_methods(class_name, member_name)
            return methods or []
        return []  # SQLite 废弃

    def get_functions_with_type_in_signature(self, type_name: str) -> list[str]:
        """查找签名中包含指定类型的函数 (用于 C struct 字段作用域)。"""
        if self._mysql:
            names = self._mysql.read_functions_with_type_in_signature(type_name)
            return names or []
        return []  # SQLite 废弃

    def add_processed_taint(self, func_id: str, pt: ProcessedTaint) -> None:
        """写入 processed_taint (func_id 级 INSERT OR IGNORE 去重)。"""
        ts = _norm_sig(pt.taint_signature or "")
        pvs = pt.pre_validation_signature or ""
        self._exec("functions",
            "INSERT OR IGNORE INTO processed_taints (func_id, taint_signature, pre_validation_signature, taint_params, sessions_path) VALUES (?,?,?,?,?)",
            (func_id, ts, pvs, json.dumps(pt.taint_params, ensure_ascii=False), pt.sessions_path))
        # 注: processed_taints 不双写 MySQL — 它是"本任务 BFS 去重/占位"状态, 必须任务级隔离;
        # per-source-dir MySQL 跨任务共享, 双写会导致新任务根函数被前任务残留记录跳过 (0 分析)。

    def try_reserve_processed_taint(self, func_id: str, pt: ProcessedTaint) -> bool:
        """分析前预留占位。

        去重键: func_id。任务/epoch 内同一函数只分析一次, 即使不同调用路径给出
        不同污点名/签名, 也视为同一函数级分析结果。analyze 失败时 delete 占位可重试。
        """
        ts = _norm_sig(pt.taint_signature or "")
        pvs = pt.pre_validation_signature or ""
        tp_json = json.dumps(pt.taint_params, ensure_ascii=False)
        # processed_taints 仅用任务本地 SQLite (per-epoch): 单 worker/单进程内原子占位即可。
        # 不走 MySQL: per-source-dir 库跨任务共享, 会导致跨任务残留跳过根分析。
        with self._locks["functions"]:
            row = self._conns["functions"].execute(
                "SELECT 1 FROM processed_taints WHERE func_id=? LIMIT 1",
                (func_id,)).fetchone()
            if row is not None:
                return False
            cur = self._conns["functions"].execute(
                "INSERT OR IGNORE INTO processed_taints (func_id, taint_signature, pre_validation_signature, taint_params, sessions_path) VALUES (?,?,?,?,?)",
                (func_id, ts, pvs, tp_json, pt.sessions_path))
            self._conns["functions"].commit()
            return cur.rowcount == 1

    def delete_processed_taint(self, func_id: str, taint_signature: str,
                               pre_validation_signature: str = "") -> None:
        self._exec("functions",
            "DELETE FROM processed_taints WHERE func_id=?",
            (func_id,))
        # 不双写 MySQL (见 try_reserve 注释)

    def find_processed_taint(self, func_id: str, taint_signature: str,
                             pre_validation_signature: str = "") -> ProcessedTaint | None:
        """函数级去重: func_id — 不依赖污点签名或前置校验集。

        只要同一任务/epoch 内同一函数已被分析过, 后续任何路径到达都不重分析。
        taint_signature / pre_validation_signature 参数保留兼容签名但不参与查询。
        """
        # 仅查任务本地 SQLite (per-epoch); 不查共享 MySQL 避免跨任务残留误判"已分析"。
        rows = self._q("functions",
            "SELECT taint_signature, pre_validation_signature, taint_params, sessions_path FROM processed_taints WHERE func_id=? LIMIT 1",
            (func_id,))
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
        if self._mysql:
            self._mysql.upsert_taint(taint_id=r["taint_id"], func_id=r["func_id"],
                name=r["name"], signature=r["signature"], file=r["file"], function=r["function"],
                next_propagations=r["next_propagations"], description=r["description"])
        # SQLite 废弃: taints 只写 MySQL

    def get_taint(self, taint_id: str) -> TaintRecord | None:
        # 废弃: upsert_taint 已改 MySQL ONLY, SQLite taints 表不再有数据
        # 如需读取请用 list_taints_in_function (MySQL) 或新增 MySQL read_taint_by_id
        return None  # SQLite 废弃

    def list_taints_in_function(self, func_id: str) -> list[TaintRecord]:
        if self._mysql:
            return self._mysql.read_taints_in_function(func_id) or []
        return []  # SQLite 废弃

    def add_propagation_to_taint(self, taint_id: str, prop_id: str) -> None:
        # 废弃: get_taint 返回 None (见上), 无调用方
        pass  # SQLite 废弃

    # ── 传播库 ──────────────────────────────────────────────────────────────
    def upsert_propagation(self, rec: PropagationRecord) -> None:
        r = rec.to_row()
        if self._mysql:
            self._mysql.upsert_propagation(**r)
        # SQLite 废弃: propagations 只写 MySQL

    def get_propagation(self, prop_id: str) -> PropagationRecord | None:
        if self._mysql:
            return self._mysql.read_propagation(prop_id)
        return None  # SQLite 废弃

    def list_propagations_from(self, func_id: str) -> list[PropagationRecord]:
        if self._mysql:
            return self._mysql.read_propagations_from(func_id) or []
        return []  # SQLite 废弃

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
        # SQLite 废弃: orchestration 只写 MySQL

    def set_edge_status(self, edge_id: str, status: str) -> None:
        # 废弃: upsert_edge 已改 MySQL ONLY, 无调用方
        pass  # SQLite 废弃

    def list_path_edges(self, path_id: str) -> list[OrchestrationEdge]:
        if self._mysql:
            return self._mysql.read_path_edges(path_id) or []
        return []  # SQLite 废弃

    def pending_edges(self) -> list[OrchestrationEdge]:
        if self._mysql:
            return self._mysql.read_pending_edges() or []
        return []  # SQLite 废弃


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
