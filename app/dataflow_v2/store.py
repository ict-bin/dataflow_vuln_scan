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
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .models import (
    FunctionRecord, OrchestrationEdge, ProcessedTaint, PropagationRecord,
    TaintParamInfo, TaintRecord, Validation, _norm_sig, _sha,
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
            processed_taints TEXT DEFAULT '[]'
        );
        CREATE INDEX IF NOT EXISTS idx_func_name ON functions(name);
        CREATE INDEX IF NOT EXISTS idx_func_file ON functions(file);
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

    def __init__(self, run_dir: str | Path) -> None:
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir).mkdir(parents=True, exist_ok=True)
        self._paths = {
            "functions": self.run_dir / "functions.db",
            "taints": self.run_dir / "taints.db",
            "propagations": self.run_dir / "propagations.db",
            "orchestration": self.run_dir / "orchestration.db",
        }
        self._conns: dict[str, sqlite3.Connection] = {}
        self._locks: dict[str, threading.Lock] = {}
        for name, p in self._paths.items():
            conn = sqlite3.connect(str(p), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.executescript(_DDL[name])
            conn.commit()
            self._conns[name] = conn
            self._locks[name] = threading.Lock()
        # 轻量迁移: 为旧库补新列 (CREATE TABLE IF NOT EXISTS 不会加列)
        self._migrate_columns("propagations", [
            "escape_kind", "carrier", "escape_via",
        ])

    def _migrate_columns(self, db: str, cols: list[str]) -> None:
        """为已有表补列 (TEXT, 默认 ''), 已有则跳过。"""
        existing = {r["name"] for r in self._q(db, "PRAGMA table_info(propagations)")}
        for c in cols:
            if c not in existing:
                try:
                    self._exec(db, f"ALTER TABLE propagations ADD COLUMN {c} TEXT DEFAULT ''")
                except sqlite3.OperationalError:
                    pass  # 并发/已存在, 忽略

    # ── 通用 ────────────────────────────────────────────────────────────────
    def close(self) -> None:
        for c in self._conns.values():
            try:
                c.close()
            except Exception:
                pass

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
                description=excluded.description, processed_taints=excluded.processed_taints
        """, r)

    def get_function(self, func_id: str) -> FunctionRecord | None:
        row = self._q("functions", "SELECT * FROM functions WHERE func_id=?", (func_id,))
        return _row_to_function(row[0]) if row else None

    def find_function(self, name: str, file: str = "") -> FunctionRecord | None:
        """按名查找函数。C++ 方法: LLM 报短名 (ReadDataTask), 库存限定名
        (Class::ReadDataTask) → 先精确匹配, 再后缀匹配 (::短名 或 =短名)。"""
        rows = self._q("functions", "SELECT * FROM functions WHERE name=? ORDER BY start_line",
                       (name,)) if not file else self._q("functions",
                       "SELECT * FROM functions WHERE name=? AND file=? ORDER BY start_line", (name, file))
        if rows:
            return _row_to_function(rows[0])
        # 后缀匹配: 短名 ReadDataTask 匹配 Class::ReadDataTask
        suf = "%::" + name
        rows = self._q("functions",
                       "SELECT * FROM functions WHERE name LIKE ? ORDER BY start_line", (suf,)) if not file \
            else self._q("functions", "SELECT * FROM functions WHERE name LIKE ? AND file=? ORDER BY start_line", (suf, file))
        return _row_to_function(rows[0]) if rows else None

    def list_functions(self) -> list[FunctionRecord]:
        return [_row_to_function(r) for r in self._q("functions", "SELECT * FROM functions")]

    # ── include 索引 (C 作用域) ────────────────────────────────────────
    def add_include(self, header: str, file: str) -> None:
        self._exec("functions",
                   "INSERT OR IGNORE INTO include_index (header, file) VALUES (?, ?)",
                   (header, file))

    def get_files_including(self, header: str) -> list[str]:
        """查找所有传递性 include 了指定 header 的 .c/.cpp 文件。"""
        rows = self._q("functions", "SELECT file FROM include_index WHERE header=?", (header,))
        return [r["file"] for r in rows]

    # ── class 继承图 (C++ 作用域) ──────────────────────────────────────
    def add_class(self, class_name: str, bases: list[str], file: str = "") -> None:
        import json
        self._exec("functions",
                   "INSERT OR REPLACE INTO class_hierarchy (class_name, bases, file) VALUES (?, ?, ?)",
                   (class_name, json.dumps(bases), file))

    def add_class_member(self, class_name: str, member_name: str,
                         member_type: str = "", file: str = "") -> None:
        self._exec("functions",
                   "INSERT OR IGNORE INTO class_members (class_name, member_name, member_type, file) VALUES (?, ?, ?, ?)",
                   (class_name, member_name, member_type, file))

    def get_bases(self, class_name: str) -> list[str]:
        import json
        rows = self._q("functions", "SELECT bases FROM class_hierarchy WHERE class_name=?", (class_name,))
        if not rows:
            return []
        return json.loads(rows[0]["bases"] or "[]")

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
        like_pattern = f"%{type_name}%"
        rows = self._q("functions", "SELECT name FROM functions WHERE signature LIKE ?", (like_pattern,))
        return [r["name"] for r in rows]

    def add_processed_taint(self, func_id: str, pt: ProcessedTaint) -> None:
        f = self.get_function(func_id)
        if f is None:
            return
        f.processed_taints.append(pt)
        self._exec("functions", "UPDATE functions SET processed_taints=? WHERE func_id=?",
                   (json.dumps([p.__dict__ if isinstance(p, ProcessedTaint) else p for p in f.processed_taints],
                               ensure_ascii=False), func_id))

    def find_processed_taint(self, func_id: str, taint_signature: str,
                             pre_validation_signature: str) -> ProcessedTaint | None:
        """三重去重: (func_id, taint_signature, 前置校验集)。

        前置校验用 (op,value) 规范 token 集做**子集/超集**匹配: 若已存在记录的校验集
        是当前的**超集** (已含更全校验, 通常因 LLM 某轮漏报一两个校验) -> 当前视为已覆盖, 跳过。
        当前为空校验集时仅与空集匹配 (避免 空 ⊆ 非空 的误并)。
        """
        f = self.get_function(func_id)
        if f is None:
            return None
        ts = _norm_sig(taint_signature)
        cur = set(_norm_sig(p) for p in (pre_validation_signature or "").split("|") if p)
        for pt in f.processed_taints:
            if _norm_sig(pt.taint_signature) != ts:
                continue
            existing = set(_norm_sig(p) for p in (pt.pre_validation_signature or "").split("|") if p)
            if not cur:
                # 当前无前置校验: 仅当已存在也无校验才命中 (避免 空 ⊆ 非空 误并不同路径)
                if not existing:
                    return pt
                continue
            if cur <= existing:  # 当前 ⊆ 已存在 (已存在更完整 -> 已覆盖当前)
                return pt
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

    def get_taint(self, taint_id: str) -> TaintRecord | None:
        row = self._q("taints", "SELECT * FROM taints WHERE taint_id=?", (taint_id,))
        return _row_to_taint(row[0]) if row else None

    def list_taints_in_function(self, func_id: str) -> list[TaintRecord]:
        return [_row_to_taint(r) for r in self._q("taints",
                "SELECT * FROM taints WHERE func_id=?", (func_id,))]

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

    def get_propagation(self, prop_id: str) -> PropagationRecord | None:
        row = self._q("propagations", "SELECT * FROM propagations WHERE prop_id=?", (prop_id,))
        return _row_to_propagation(row[0]) if row else None

    def list_propagations_from(self, func_id: str) -> list[PropagationRecord]:
        return [_row_to_propagation(r) for r in self._q("propagations",
                "SELECT * FROM propagations WHERE source_func_id=?", (func_id,))]

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

    def set_edge_status(self, edge_id: str, status: str) -> None:
        self._exec("orchestration", "UPDATE orchestration SET status=? WHERE edge_id=?", (status, edge_id))

    def list_path_edges(self, path_id: str) -> list[OrchestrationEdge]:
        return [_row_to_edge(r) for r in self._q("orchestration",
                "SELECT * FROM orchestration WHERE path_id=? ORDER BY edge_order", (path_id,))]

    def pending_edges(self) -> list[OrchestrationEdge]:
        return [_row_to_edge(r) for r in self._q("orchestration",
                "SELECT * FROM orchestration WHERE status='pending' ORDER BY depth, edge_order")]


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
        validations=[Validation(**v) for v in vals if isinstance(v, dict)],
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
