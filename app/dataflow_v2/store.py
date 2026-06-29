"""dataflow-v2 四库存储层 (sqlite3)。

四个独立 sqlite 文件, 存放在 task run 目录下 dataflow-v2/:
  functions.db       函数库
  taints.db          污点库
  propagations.db    传播库
  orchestration.db   编排库

函数体存放在 run/functions/ (body_path 索引指向这里)。

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
            callsite_validated     INTEGER DEFAULT 0,
            branch_group_id        TEXT DEFAULT '',
            branch_arm_id          TEXT DEFAULT '',
            branch_path            TEXT DEFAULT '[]',
            mutex_siblings         TEXT DEFAULT '[]',
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
        (self.run_dir / "functions").mkdir(parents=True, exist_ok=True)
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
        rows = self._q("functions", "SELECT * FROM functions WHERE name=? ORDER BY start_line",
                       (name,)) if not file else self._q("functions",
                       "SELECT * FROM functions WHERE name=? AND file=? ORDER BY start_line", (name, file))
        return _row_to_function(rows[0]) if rows else None

    def list_functions(self) -> list[FunctionRecord]:
        return [_row_to_function(r) for r in self._q("functions", "SELECT * FROM functions")]

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
        """三重去重: (函数签名→func_id, 污点参数→taint_signature, 前置校验→pre_validation_signature)。

        返回已处理记录则跳过重复分析。
        """
        f = self.get_function(func_id)
        if f is None:
            return None
        ts, ps = _norm_sig(taint_signature), _norm_sig(pre_validation_signature)
        for pt in f.processed_taints:
            if _norm_sig(pt.taint_signature) == ts and _norm_sig(pt.pre_validation_signature) == ps:
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
                callsite_validated,branch_group_id,branch_arm_id,branch_path,mutex_siblings,
                validations,description)
            VALUES (:prop_id,:source_func_id,:source_taint_name,
                :source_taint_signature,:target_taint_name,:target_taint_signature,
                :target_func_id,:target_function,:target_file,:call_line,:condition,:is_external,
                :callsite_validated,:branch_group_id,:branch_arm_id,:branch_path,:mutex_siblings,
                :validations,:description)
            ON CONFLICT(prop_id) DO UPDATE SET
                target_func_id=excluded.target_func_id, target_function=excluded.target_function,
                target_file=excluded.target_file, call_line=excluded.call_line,
                condition=excluded.condition, is_external=excluded.is_external,
                callsite_validated=excluded.callsite_validated,
                branch_group_id=excluded.branch_group_id, branch_arm_id=excluded.branch_arm_id,
                branch_path=excluded.branch_path, mutex_siblings=excluded.mutex_siblings,
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
        branch_group_id=row["branch_group_id"], branch_arm_id=row["branch_arm_id"],
        branch_path=json.loads(row["branch_path"] or "[]"),
        mutex_siblings=json.loads(row["mutex_siblings"] or "[]"),
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
