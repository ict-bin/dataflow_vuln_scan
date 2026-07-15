"""dagflow 纯数据模型。

设计来源: docs/design-taint-analysis.md + docs/design-vuln-mining.md
无逻辑, 只 dataclass + to/from_dict。
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


# ── 传播条件 CondTerm (边, 路径条件) ─────────────────────────────────────

@dataclass
class Atom:
    """原子条件: {left, op, right}。left/right 取代码字面量 (标识符/宏/枚举/nullptr/数值)。"""
    left: str = ""
    op: str = ""        # == != <= >= < >
    right: str = ""

    def to_dict(self) -> dict: return {"Atom": {"left": self.left, "op": self.op, "right": self.right}}

    @staticmethod
    def from_dict(d: dict) -> "Atom":
        i = d.get("Atom", d)
        return Atom(left=str(i.get("left", "")), op=str(i.get("op", "")), right=str(i.get("right", "")))


@dataclass
class Compound:
    """复合条件: 保留布尔结构 (AND/OR), 不拍平。"""
    comb: str = "AND"   # AND | OR
    terms: list["CondTerm"] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"Compound": {"comb": self.comb, "terms": [t.to_dict() for t in self.terms]}}

    @staticmethod
    def from_dict(d: dict) -> "Compound":
        i = d.get("Compound", d)
        return Compound(comb=str(i.get("comb", "AND")),
                        terms=[_cond_from_dict(t) for t in (i.get("terms") or [])])


CondTerm = Atom | Compound   # 递归 (Compound.terms 元素也是 CondTerm)


def _cond_from_dict(d: dict) -> CondTerm:
    if "Compound" in d or (d.get("comb") and d.get("terms")):
        return Compound.from_dict(d)
    return Atom.from_dict(d)


# ── 污点校验 Check (节点 sanitizer, 对污点本身的约束) ─────────────────────

@dataclass
class Check:
    """{left, op, right}; left 必须是该污点或其字段。仅对污点本身做约束才进 check (非路径条件)。"""
    left: str = ""
    op: str = ""
    right: str = ""

    def to_dict(self) -> dict: return {"left": self.left, "op": self.op, "right": self.right}

    @staticmethod
    def from_dict(d: dict) -> "Check":
        return Check(left=str(d.get("left", "")), op=str(d.get("op", "")), right=str(d.get("right", "")))


# ── 剪枝信号 PruneSignal (节点) ──────────────────────────────────────────

@dataclass
class PruneSignal:
    """sanitized(清洗成安全, LLM) | low_value_callee(无安全价值, LLM) | sink_recorded(编排器定)"""
    reason: str = ""
    detail: str = ""

    def to_dict(self) -> dict: return {"reason": self.reason, "detail": self.detail}

    @staticmethod
    def from_dict(d: dict | None) -> "PruneSignal | None":
        if not d: return None
        return PruneSignal(reason=str(d.get("reason", "")), detail=str(d.get("detail", "")))


# ── 传播边 TaintEdge ─────────────────────────────────────────────────────

EDGE_KINDS = ("inside", "callee", "extern", "container", "return", "source")


@dataclass
class TaintEdge:
    """DAG 出边。line 由脚本填 (非 LLM)。"""
    to_node: int                      # 目标节点 id (-1/null=return/source 的虚拟目标)
    line: int = 0                     # 传播行号【脚本填】
    condition: list[CondTerm] = field(default_factory=list)   # 路径条件 (空=无条件)
    taints: list[str] = field(default_factory=list)          # 沿边传播的污点签名 (单污点长 1)
    kind: str = "inside"              # inside|callee|extern|container|return|source
    sink_ref: str = ""                # callee: 限定函数名; extern/container: 外部容器/载体; source: 源 callee
    param_taints: list[dict] = field(default_factory=list)   # callee: [{param: callee形参, taint: caller污点}]
    escape_subkind: str = ""          # extern/global | extern/field_alias | container
    carrier: str = ""                 # 载体变量名
    escape_via: str = ""              # 逃逸调用名 (仅记录)

    def to_dict(self) -> dict:
        return {
            "to": self.to_node, "line": self.line,
            "condition": [c.to_dict() for c in self.condition],
            "taints": self.taints, "kind": self.kind, "sink_ref": self.sink_ref,
            "param_taints": self.param_taints,
            "escape_subkind": self.escape_subkind, "carrier": self.carrier, "escape_via": self.escape_via,
        }

    @staticmethod
    def from_dict(d: dict) -> "TaintEdge":
        return TaintEdge(
            to_node=int(d.get("to", -1) if d.get("to") is not None else -1),
            line=int(d.get("line", 0)),
            condition=[_cond_from_dict(c) for c in (d.get("condition") or [])],
            taints=list(d.get("taints") or []),
            kind=str(d.get("kind", "inside")),
            sink_ref=str(d.get("sink_ref", "")),
            param_taints=list(d.get("param_taints") or []),
            escape_subkind=str(d.get("escape_subkind", "")),
            carrier=str(d.get("carrier", "")),
            escape_via=str(d.get("escape_via", "")),
        )


# ── 传播节点 TaintNode ────────────────────────────────────────────────────

@dataclass
class TaintNode:
    """DAG 节点。line 由脚本填。merge 节点多 parent (DAG)。"""
    id: int
    line: int = 0                     # 【脚本填】
    taint: str = ""                   # 该节点处污点签名 (归一)
    parents: list[int] = field(default_factory=list)
    children: list[TaintEdge] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    prune: PruneSignal | None = None
    is_source: bool = False           # 污点源节点 (无入口参数, 函数内自生)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "line": self.line, "taint": self.taint,
            "parents": self.parents, "children": [e.to_dict() for e in self.children],
            "checks": [c.to_dict() for c in self.checks],
            "prune": self.prune.to_dict() if self.prune else None,
            "is_source": self.is_source,
        }

    @staticmethod
    def from_dict(d: dict) -> "TaintNode":
        return TaintNode(
            id=int(d.get("id", 0)),
            line=int(d.get("line", 0)),
            taint=str(d.get("taint", "")),
            parents=list(d.get("parents") or []),
            children=[TaintEdge.from_dict(e) for e in (d.get("children") or [])],
            checks=[Check.from_dict(c) for c in (d.get("checks") or [])],
            prune=PruneSignal.from_dict(d.get("prune")),
            is_source=bool(d.get("is_source", False)),
        )


# ── 单函数 DAG (一次分析的归属) ──────────────────────────────────────────

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
        dag = TaintDAG(
            func_id=str(d.get("func_id", "")), taint_signature=str(d.get("taint_signature", "")),
            nodes=[TaintNode.from_dict(n) for n in (d.get("nodes") or [])],
            self_contained=bool(d.get("self_contained", False)),
            description=str(d.get("description", "")),
            taint_failed=bool(d.get("taint_failed", False)),
        )
        # 兼容顶层 edges 数组格式 (golden 文件用 from/to; 分发到 from 节点的 children)
        top_edges = d.get("edges")
        if top_edges:
            by_id = {n.id: n for n in dag.nodes}
            for er in top_edges:
                e = TaintEdge.from_dict(er)
                fr = er.get("from", er.get("from_node"))
                fn = by_id.get(int(fr) if fr is not None else -1)
                if fn is not None:
                    fn.children.append(e)
        return dag


# ── 工作队列项 WorkItem ──────────────────────────────────────────────────

ITEM_KINDS = ("callee", "return_taint", "escape_track", "indirect_track")


@dataclass
class WorkItem:
    """跨函数跟踪的跟入项 (轻量引用, DAG 为权威)。"""
    kind: str                         # callee | return_taint | escape_track | indirect_track
    target_func: str = ""             # callee/return_taint: 目标 func_id
    target_taint: str = ""            # callee: callee 形参名归一; return_taint: 回传污点签名
    origin_func: str = ""             # 溯源: 产出此项的函数
    origin_node: int = -1             # 溯源: 产出节点 id
    origin_edge: str = ""              # 溯源: "from->to" 边引用 (DAG 权威, line/condition 留在 DAG)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "target_func": self.target_func, "target_taint": self.target_taint,
                "origin_func": self.origin_func, "origin_node": self.origin_node, "origin_edge": self.origin_edge}


# ── 挖掘 finding ─────────────────────────────────────────────────────────

@dataclass
class Dimension:
    pass_: bool = False
    reason: str = ""

    def to_dict(self) -> dict: return {"pass": self.pass_, "reason": self.reason}

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
