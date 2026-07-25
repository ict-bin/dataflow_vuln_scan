"""dagflow 纯数据模型 (简化版: 行号为沟通桥梁)。

设计: docs/design-taint-analysis.md §3 (LLM 输出行号, 脚本解析源码补全)。

LLM 输出简化格式:
  nodes: [{taint, line, source, check_lines, edges: [{to, kind, taints, line, callee, tainted_args, cond_lines, carrier, escape_via}]}]
  prunes: {"0": "low_value_callee"}

脚本后处理 (line_filler):
  从行号读源码 → tree-sitter 解析 → 填 condition/checks/param_taints/sink_ref/escape_subkind/parents
"""
from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("dvs.dagflow.models")


# ── 行号/行号范围归一 ──────────────────────────────────────────────────

def _norm_line(v) -> tuple[int, int]:
    """行号/行号范围 → (start, end), end=0 表示单行。

    支持: 765 (int), [765] (list), [765,767] (range), "765" (str), "765-767" (str range)
    """
    if isinstance(v, bool):
        return (0, 0)
    if isinstance(v, (int, float)):
        return (int(v), 0)
    if isinstance(v, (list, tuple)):
        if len(v) == 0:
            return (0, 0)
        if len(v) == 1:
            return (int(v[0]), 0)
        return (int(v[0]), int(v[1]))
    if isinstance(v, str):
        s = v.strip()
        if "-" in s:
            parts = s.split("-", 1)
            try:
                return (int(parts[0]), int(parts[1]))
            except ValueError as e:
                logger.debug("parse 'a-b' range failed (s=%r): %s", s, e)
                pass
        try:
            return (int(s), 0)
        except ValueError as e:
            logger.debug("parse single int range failed (s=%r): %s", s, e)
            return (0, 0)
    return (0, 0)


def _norm_line_list(v) -> list[tuple[int, int]]:
    """行号列表 → [(start, end), ...]。每个元素可以是 int 或 [int, int]。"""
    if not v:
        return []
    if isinstance(v, (int, float, str)):
        return [_norm_line(v)]
    result = []
    for item in v:
        result.append(_norm_line(item))
    return result


# ── 剪枝信号 (节点) ──────────────────────────────────────────────────

@dataclass
class PruneSignal:
    """sanitized(清洗成安全, LLM) | low_value_callee(无安全价值, LLM) | sink_recorded(编排器定)"""
    reason: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {"reason": self.reason, "detail": self.detail}

    @staticmethod
    def from_dict(d) -> "PruneSignal | None":
        if not d:
            return None
        if isinstance(d, str):
            return PruneSignal(reason=d)
        return PruneSignal(reason=str(d.get("reason", "")), detail=str(d.get("detail", "")))


# ── 传播边 ─────────────────────────────────────────────────────────────

EDGE_KINDS = ("inside", "callee", "extern", "container", "return")


@dataclass
class TaintEdge:
    """DAG 出边。

    LLM 输出字段: to, kind, taints, line, callee, tainted_args, cond_lines, carrier, escape_via
    脚本后处理填: sink_ref, param_taints, condition, escape_subkind
    """
    to_node: int
    line: int = 0                     # LLM 输出 (传播行)
    line_end: int = 0                 # LLM 输出 (多行结束行, 0=单行)
    kind: str = "inside"
    taints: list[str] = field(default_factory=list)
    # LLM 输出 (callee 边)
    callee: str = ""                  # callee 函数名 (限定名)
    tainted_args: list[dict] = field(default_factory=list)  # [{i: int, taint: str}]
    cond_lines: list = field(default_factory=list)  # LLM 输出行号/行号范围列表
    # LLM 输出 (extern/container 边)
    carrier: str = ""
    escape_via: str = ""
    # 脚本后处理填
    sink_ref: str = ""                # = callee (callee 边) 或 escape_via
    param_taints: list[dict] = field(default_factory=list)  # [{param: 形参名, taint: 污点}]
    condition: list[dict] = field(default_factory=list)     # [{line, text}] 脚本从 cond_lines 解析
    escape_subkind: str = ""          # 脚本推断: global/field_alias/container

    def to_dict(self) -> dict:
        return {
            "to": self.to_node, "line": self.line, "line_end": self.line_end,
            "kind": self.kind, "taints": self.taints,
            "callee": self.callee, "tainted_args": self.tainted_args,
            "cond_lines": self.cond_lines,
            "carrier": self.carrier, "escape_via": self.escape_via,
            "sink_ref": self.sink_ref, "param_taints": self.param_taints,
            "condition": self.condition, "escape_subkind": self.escape_subkind,
        }

    @staticmethod
    def from_dict(d: dict) -> "TaintEdge":
        sl, el = _norm_line(d.get("line", 0))
        # cond_lines: 支持 cond_line (单值) 和 cond_lines (列表) 两种 key
        cond_raw = d.get("cond_lines")
        if cond_raw is None:
            cl = d.get("cond_line")
            cond_raw = [cl] if cl is not None else []
        return TaintEdge(
            to_node=int(d.get("to", -1) if d.get("to") is not None else -1),
            line=sl, line_end=el,
            kind=str(d.get("kind", "inside")),
            taints=list(d.get("taints") or []),
            callee=str(d.get("callee", "")),
            tainted_args=list(d.get("tainted_args") or []),
            cond_lines=list(cond_raw),
            carrier=str(d.get("carrier", "")),
            escape_via=str(d.get("escape_via", "")),
            # 兼容: 已有脚本填好的字段 (从 DB 加载时)
            sink_ref=str(d.get("sink_ref", "")),
            param_taints=list(d.get("param_taints") or []),
            condition=list(d.get("condition") or []),
            escape_subkind=str(d.get("escape_subkind", "")),
        )


# ── 传播节点 ────────────────────────────────────────────────────────────

@dataclass
class TaintNode:
    """DAG 节点。

    LLM 输出: taint, line, source, check_lines, edges(children)
    脚本后处理填: id(数组下标), parents(从edges反推), checks(从check_lines解析), is_source(=source非空)
    """
    id: int
    line: int = 0                     # LLM 输出
    line_end: int = 0                 # LLM 输出 (多行)
    taint: str = ""                   # 该节点处污点签名
    source: str = ""                  # LLM 输出: 源函数名 (空=非源节点)
    check_lines: list = field(default_factory=list)  # LLM 输出: if 条件行号列表
    children: list[TaintEdge] = field(default_factory=list)
    # 脚本后处理填
    parents: list[int] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)  # [{line, text}] 从 check_lines 解析
    prune: PruneSignal | None = None
    is_source: bool = False           # = (source 非空)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "line": self.line, "line_end": self.line_end,
            "taint": self.taint, "source": self.source,
            "check_lines": self.check_lines,
            "children": [e.to_dict() for e in self.children],
            "parents": self.parents,
            "checks": self.checks,
            "prune": self.prune.to_dict() if self.prune else None,
            "is_source": self.is_source,
        }

    @staticmethod
    def from_dict(d: dict) -> "TaintNode":
        sl, el = _norm_line(d.get("line", 0))
        source = str(d.get("source", "") or "")
        return TaintNode(
            id=int(d.get("id", 0)),
            line=sl, line_end=el,
            taint=str(d.get("taint", "")),
            source=source,
            check_lines=list(d.get("check_lines") or []),
            children=[TaintEdge.from_dict(e) for e in (d.get("children") or d.get("edges") or [])],
            parents=list(d.get("parents") or []),
            checks=list(d.get("checks") or []),
            prune=PruneSignal.from_dict(d.get("prune")),
            is_source=bool(d.get("is_source", False)) or bool(source),
        )


# ── 单函数 DAG ──────────────────────────────────────────────────────────

@dataclass
class TaintDAG:
    """一次 (func_id, taint_signature) 分析的 DAG。"""
    func_id: str
    taint_signature: str
    nodes: list[TaintNode] = field(default_factory=list)
    self_contained: bool = False
    description: str = ""
    taint_failed: bool = False

    def to_dict(self) -> dict:
        return {
            "func_id": self.func_id, "taint_signature": self.taint_signature,
            "nodes": [n.to_dict() for n in self.nodes],
            "self_contained": self.self_contained, "description": self.description,
            "taint_failed": self.taint_failed,
        }

    @staticmethod
    def from_dict(d: dict) -> "TaintDAG":
        nodes = [TaintNode.from_dict(n) for n in (d.get("nodes") or [])]
        # id = 数组下标 (LLM 不输出 id)
        for i, n in enumerate(nodes):
            n.id = i
        # 解析 prunes (顶层 dict {node_index: reason})
        prunes = d.get("prunes") or {}
        if isinstance(prunes, dict):
            for k, v in prunes.items():
                try:
                    idx = int(k)
                except (ValueError, TypeError) as e:
                    logger.debug("parse prune index failed (k=%r): %s", k, e)
                    continue
                if 0 <= idx < len(nodes):
                    nodes[idx].prune = PruneSignal.from_dict(v) if not isinstance(v, str) else PruneSignal(reason=v)
        # 计算 parents (从 edges 反推)
        for n in nodes:
            for e in n.children:
                to = e.to_node
                if 0 <= to < len(nodes):
                    if n.id not in nodes[to].parents:
                        nodes[to].parents.append(n.id)
        dag = TaintDAG(
            func_id=str(d.get("func_id", "")), taint_signature=str(d.get("taint_signature", "")),
            nodes=nodes,
            self_contained=bool(d.get("self_contained", False)),
            description=str(d.get("description", "")),
            taint_failed=bool(d.get("taint_failed", False)),
        )
        # 顶层 edges 数组 (扁平格式, LLM 自然输出): 每条有 from+to, 分发到 from 节点的 children
        top_edges = d.get("edges")
        if top_edges:
            import logging as _log
            _l = _log.getLogger("dvs.dagflow.models")
            by_id = {n.id: n for n in dag.nodes}
            for er in top_edges:
                e = TaintEdge.from_dict(er)
                fr = er.get("from", er.get("from_node"))
                if fr is None:
                    _l.warning("top-level edge missing 'from', skipped: to=%s kind=%s", er.get("to"), er.get("kind"))
                    continue
                try:
                    fr = int(fr)
                except (ValueError, TypeError):
                    _l.warning("top-level edge 'from' not int: %r, skipped", fr)
                    continue
                fn = by_id.get(fr)
                if fn is not None:
                    fn.children.append(e)
                else:
                    _l.warning("top-level edge 'from'=%d out of range (nodes=%d), skipped", fr, len(dag.nodes))
            _l.info("top-level edges: %d parsed, distributed to nodes", len(top_edges))
        return dag


# ── 工作队列项 ────────────────────────────────────────────────────────

ITEM_KINDS = ("callee", "return_taint", "escape_track", "indirect_track")


@dataclass
class WorkItem:
    """跨函数跟踪的跟入项 (轻量引用, DAG 为权威)。"""
    kind: str
    target_func: str = ""
    target_taint: str = ""
    origin_func: str = ""
    origin_node: int = -1
    origin_edge: str = ""
    depth: int = 0

    def to_dict(self) -> dict:
        return {"kind": self.kind, "target_func": self.target_func, "target_taint": self.target_taint,
                "origin_func": self.origin_func, "origin_node": self.origin_node, "origin_edge": self.origin_edge,
                "depth": self.depth}


# ── 挖掘 finding ─────────────────────────────────────────────────────

@dataclass
class Dimension:
    pass_: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {"pass": self.pass_, "reason": self.reason}

    @staticmethod
    def from_dict(d: dict) -> "Dimension":
        return Dimension(pass_=bool(d.get("pass", False)), reason=str(d.get("reason", "")))


@dataclass
class Finding:
    vuln_type: str = ""
    severity: str = ""
    title: str = ""
    summary: str = ""
    entry_point: str = ""
    trigger_path: str = ""
    evidence: str = ""
    location_func: str = ""
    location_line: str = ""
    dag_path: list[dict] = field(default_factory=list)
    exploitability: dict = field(default_factory=dict)
    dimensions: dict[str, Dimension] = field(default_factory=dict)
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type, "severity": self.severity, "title": self.title,
            "summary": self.summary, "entry_point": self.entry_point, "trigger_path": self.trigger_path,
            "evidence": self.evidence,
            "location": {"function": self.location_func, "line": self.location_line},
            "dag_path": self.dag_path, "exploitability": self.exploitability,
            "dimensions": {k: v.to_dict() for k, v in self.dimensions.items()},
            "confidence": self.confidence,
        }
