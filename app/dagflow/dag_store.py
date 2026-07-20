"""dagflow DAG 存储 (独立于 V2 DataflowStore)。

表 (run/dagflow/dagflow.db):
  taint_dag_nodes  (func_id, taint_signature, node_id, line, taint, parents_json,
                    checks_json, prune_json, is_source)  PK(func_id,taint_signature,node_id)
  taint_dag_edges  (func_id, taint_signature, edge_id, from_node, to_node, line,
                    condition_json, taints_json, kind, sink_ref, param_taints_json,
                    escape_subkind, carrier, escape_via)  PK(func_id,taint_signature,edge_id)
  taint_dag_meta   (func_id, taint_signature, self_contained, description, taint_failed)
                    PK(func_id,taint_signature)
  dag_processed_taints  (func_id, taint_signature)  PK(func_id,taint_signature)  -- 去重锚点

设计: docs/design-taint-analysis.md §8 (独立表, 旧 V2 taints/propagations 废弃不碰)。
单共享连接 + lock (work_queue 多线程, check_same_thread=False, _exec 立即 commit)。
"""
from __future__ import annotations
import json, sqlite3, threading
from pathlib import Path
from .models import TaintDAG, TaintNode, TaintEdge, PruneSignal


_DDL = """
CREATE TABLE IF NOT EXISTS taint_dag_nodes (
    func_id          TEXT NOT NULL,
    taint_signature  TEXT NOT NULL,
    node_id          INTEGER NOT NULL,
    line             INTEGER NOT NULL DEFAULT 0,
    taint            TEXT NOT NULL DEFAULT '',
    parents_json     TEXT DEFAULT '[]',
    checks_json      TEXT DEFAULT '[]',
    prune_json       TEXT DEFAULT '',
    is_source        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (func_id, taint_signature, node_id)
);
CREATE TABLE IF NOT EXISTS taint_dag_edges (
    func_id          TEXT NOT NULL,
    taint_signature  TEXT NOT NULL,
    edge_id          TEXT NOT NULL,
    from_node        INTEGER NOT NULL,
    to_node          INTEGER NOT NULL,
    line             INTEGER NOT NULL DEFAULT 0,
    condition_json   TEXT DEFAULT '[]',
    taints_json      TEXT DEFAULT '[]',
    kind             TEXT NOT NULL DEFAULT 'inside',
    sink_ref         TEXT DEFAULT '',
    param_taints_json TEXT DEFAULT '[]',
    escape_subkind   TEXT DEFAULT '',
    carrier          TEXT DEFAULT '',
    escape_via       TEXT DEFAULT '',
    PRIMARY KEY (func_id, taint_signature, edge_id)
);
CREATE INDEX IF NOT EXISTS idx_dag_edges_kind ON taint_dag_edges(kind);
CREATE INDEX IF NOT EXISTS idx_dag_edges_sink ON taint_dag_edges(sink_ref);
CREATE TABLE IF NOT EXISTS taint_dag_meta (
    func_id          TEXT NOT NULL,
    taint_signature  TEXT NOT NULL,
    self_contained   INTEGER NOT NULL DEFAULT 0,
    description      TEXT DEFAULT '',
    taint_failed     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (func_id, taint_signature)
);
CREATE TABLE IF NOT EXISTS dag_processed_taints (
    func_id          TEXT NOT NULL,
    taint_signature  TEXT NOT NULL,
    PRIMARY KEY (func_id, taint_signature)
);
"""


class DagflowStore:
    """dagflow DAG 存储 + 去重锚点 (独立 db, 不碰 V2 functions/taints/propagations)。"""

    def __init__(self, run_dir: str | Path, mysql_store=None) -> None:
        self.run_dir = Path(run_dir)
        (self.run_dir / "dagflow").mkdir(parents=True, exist_ok=True)
        self.db_path = self.run_dir / "dagflow" / "dagflow.db"
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_DDL)
        self._conn.commit()
        self._lock = threading.Lock()
        self._mysql = mysql_store  # SharedMysqlStore (双写, 可选)

    def close(self) -> None:
        with self._lock:
            try: self._conn.close()
            except Exception: pass

    # ── 通用 ────────────────────────────────────────────────────────────
    def _exec(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def _q(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params).fetchall())

    # ── DAG 存取 ─────────────────────────────────────────────────────────
    def save_dag(self, dag: TaintDAG) -> None:
        """落库整棵 DAG (节点/边/meta)。幂等: 先删旧再插 (同 key 覆盖)。"""
        fid, ts = dag.func_id, dag.taint_signature
        with self._lock:
            c = self._conn
            c.execute("DELETE FROM taint_dag_nodes WHERE func_id=? AND taint_signature=?", (fid, ts))
            c.execute("DELETE FROM taint_dag_edges WHERE func_id=? AND taint_signature=?", (fid, ts))
            for n in dag.nodes:
                c.execute(
                    "INSERT INTO taint_dag_nodes (func_id,taint_signature,node_id,line,taint,"
                    "parents_json,checks_json,prune_json,is_source) VALUES (?,?,?,?,?,?,?,?,?)",
                    (fid, ts, n.id, n.line, n.taint,
                     json.dumps(n.parents, ensure_ascii=False),
                     json.dumps(n.checks, ensure_ascii=False),
                     json.dumps(n.prune.to_dict(), ensure_ascii=False) if n.prune else "",
                     1 if n.is_source else 0))
            for n in dag.nodes:
                for i, e in enumerate(n.children):
                    eid = f"{n.id}->{e.to_node}_{e.kind}_{i}"
                    c.execute(
                        "INSERT INTO taint_dag_edges (func_id,taint_signature,edge_id,from_node,to_node,"
                        "line,condition_json,taints_json,kind,sink_ref,param_taints_json,"
                        "escape_subkind,carrier,escape_via) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (fid, ts, eid, n.id, e.to_node, e.line,
                         json.dumps(e.condition, ensure_ascii=False),
                         json.dumps(e.taints, ensure_ascii=False),
                         e.kind, e.sink_ref,
                         json.dumps(e.param_taints, ensure_ascii=False),
                         e.escape_subkind, e.carrier, e.escape_via))
            c.execute(
                "INSERT INTO taint_dag_meta (func_id,taint_signature,self_contained,description,taint_failed) "
                "VALUES (?,?,?,?,?) ON CONFLICT(func_id,taint_signature) DO UPDATE SET "
                "self_contained=excluded.self_contained, description=excluded.description, taint_failed=excluded.taint_failed",
                (fid, ts, 1 if dag.self_contained else 0, dag.description, 1 if dag.taint_failed else 0))
            self._conn.commit()
        # MySQL 双写
        if self._mysql:
            try:
                nodes_m = [{"node_id": n.id, "line": n.line, "taint": n.taint,
                           "parents": n.parents, "checks": n.checks,
                           "prune": n.prune.to_dict() if n.prune else {},
                           "is_source": n.is_source} for n in dag.nodes]
                edges_m = []
                for n in dag.nodes:
                    for i, e in enumerate(n.children):
                        eid = f"{n.id}->{e.to_node}_{e.kind}_{i}"
                        edges_m.append({"edge_id": eid, "from_node": n.id, "to_node": e.to_node,
                                        "line": e.line, "condition": e.condition, "taints": e.taints,
                                        "kind": e.kind, "sink_ref": e.sink_ref,
                                        "param_taints": e.param_taints, "escape_subkind": e.escape_subkind,
                                        "carrier": e.carrier, "escape_via": e.escape_via})
                meta_m = {"self_contained": dag.self_contained,
                          "description": dag.description, "taint_failed": dag.taint_failed}
                self._mysql.save_dag(fid, ts, nodes_m, edges_m, meta_m)
            except Exception as e:
                logger.warning("mysql save_dag failed: %s", e)

    def load_dag(self, func_id: str, taint_signature: str) -> TaintDAG | None:
        rows_n = self._q(
            "SELECT * FROM taint_dag_nodes WHERE func_id=? AND taint_signature=? ORDER BY node_id",
            (func_id, taint_signature))
        if not rows_n:
            return None
        nodes: list[TaintNode] = []
        for r in rows_n:
            n = TaintNode(
                id=r["node_id"], line=r["line"], taint=r["taint"],
                parents=json.loads(r["parents_json"] or "[]"),
                checks=list(json.loads(r["checks_json"] or "[]")),
                prune=PruneSignal.from_dict(json.loads(r["prune_json"]) if r["prune_json"] else None),
                is_source=bool(r["is_source"]))
            nodes.append(n)
        # 边: 按 from_node 装回对应节点 children
        rows_e = self._q(
            "SELECT * FROM taint_dag_edges WHERE func_id=? AND taint_signature=? ORDER BY from_node",
            (func_id, taint_signature))
        by_id = {n.id: n for n in nodes}
        for r in rows_e:
            e = TaintEdge(
                to_node=r["to_node"], line=r["line"],
                condition=list(json.loads(r["condition_json"] or "[]")),
                taints=json.loads(r["taints_json"] or "[]"),
                kind=r["kind"], sink_ref=r["sink_ref"],
                param_taints=json.loads(r["param_taints_json"] or "[]"),
                escape_subkind=r["escape_subkind"], carrier=r["carrier"], escape_via=r["escape_via"])
            fn = by_id.get(r["from_node"])
            if fn is not None:
                fn.children.append(e)
        meta = self._q(
            "SELECT * FROM taint_dag_meta WHERE func_id=? AND taint_signature=?",
            (func_id, taint_signature))
        m = meta[0] if meta else None
        return TaintDAG(
            func_id=func_id, taint_signature=taint_signature, nodes=nodes,
            self_contained=bool(m["self_contained"]) if m else False,
            description=(m["description"] if m else ""),
            taint_failed=bool(m["taint_failed"]) if m else False)

    # ── 去重锚点 (双检锁原子操作) ────────────────────────────────────────
    def find_processed_taint(self, func_id: str, taint_signature: str) -> bool:
        """(func_id, taint_signature) 已分析过?"""
        r = self._q("SELECT 1 FROM dag_processed_taints WHERE func_id=? AND taint_signature=?",
                    (func_id, taint_signature))
        return bool(r)

    def try_reserve(self, func_id: str, taint_signature: str) -> bool:
        """分析前占位 (INSERT OR IGNORE, PK 去重)。rowcount=1=本线程占位成功; 0=并发 peer 已占。"""
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO dag_processed_taints (func_id, taint_signature) VALUES (?,?)",
                (func_id, taint_signature))
            self._conn.commit()
            return cur.rowcount == 1

    def delete_processed_taint(self, func_id: str, taint_signature: str) -> None:
        """analyze 失败时删占位 (让后续可重试)。"""
        self._exec(
            "DELETE FROM dag_processed_taints WHERE func_id=? AND taint_signature=?",
            (func_id, taint_signature))
        if self._mysql:
            try: self._mysql.dag_delete_processed(func_id, taint_signature)
            except Exception: pass

    # ── 跨函数查询 (dag_tools 用) ────────────────────────────────────────
    def get_callers(self, func_id: str) -> list[tuple[str, str]]:
        """反查哪些 DAG 有 callee 边指向本 func (跨函数反向)。返回 [(caller_func_id, taint_sig)]。"""
        rows = self._q(
            "SELECT DISTINCT func_id, taint_signature FROM taint_dag_edges "
            "WHERE kind='callee' AND sink_ref=?", (func_id,))
        return [(r["func_id"], r["taint_signature"]) for r in rows]

    def list_analyzed(self) -> list[tuple[str, str]]:
        """所有已分析的 (func_id, taint_signature)。"""
        return [(r["func_id"], r["taint_signature"])
                for r in self._q("SELECT func_id, taint_signature FROM dag_processed_taints")]

    def list_dag_outgoing(self, func_id: str, taint_signature: str) -> list[dict]:
        """本 DAG 的传出边 (callee/return/extern/container, 用于挖掘触发判定)。"""
        rows = self._q(
            "SELECT * FROM taint_dag_edges WHERE func_id=? AND taint_signature=? "
            "AND kind IN ('callee','return','extern','container')",
            (func_id, taint_signature))
        return [dict(r) for r in rows]
