"""dataflow-v2 数据模型 (dataclasses).

对应四张库的记录类型 + 污点路径去重所需的结构。字段命名与 v2 设计文档一致;
持久化时 JSON 字段以 TEXT(JSON) 存, 访问层负责 (de)serialize。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any


def _sha(*parts: str) -> str:
    return hashlib.sha1("\x1f".join(p or "" for p in parts).encode("utf-8")).hexdigest()[:16]


def _norm_sig(signature: str) -> str:
    """Normalize a signature for identity comparison (strip ws, lower)."""
    return "".join((signature or "").split()).lower()


# ── 函数库 ───────────────────────────────────────────────────────────────────

@dataclass
class ProcessedTaint:
    """函数已处理过的一条污点路径 (用于三重去重)。"""
    taint_params: list[str] = field(default_factory=list)        # 污点参数 (位置 + 名)
    taint_signature: str = ""                                    # 归一化污点签名
    pre_validations: list[dict] = field(default_factory=list)   # 传入时的前置校验 [{condition,content}]
    pre_validation_signature: str = ""                          # 前置校验归一化签名
    sessions_path: str = ""                                     # 该次分析的 session 路径

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @staticmethod
    def from_json(s: str) -> "ProcessedTaint":
        d = json.loads(s) if s else {}
        return ProcessedTaint(**{k: d.get(k) for k in (
            "taint_params", "taint_signature", "pre_validations", "pre_validation_signature", "sessions_path")})


@dataclass
class FunctionRecord:
    """函数库一条记录。"""
    file: str
    name: str
    signature: str
    start_line: int
    end_line: int
    body_path: str = ""                 # run/functions/<rel>__<name>__<hash>.c 索引
    func_hash: str = ""                 # 函数体内容哈希
    description: str = ""               # 功能说明 (LLM 填)
    processed_taints: list[ProcessedTaint] = field(default_factory=list)
    func_id: str = ""                   # = _sha(file, name, norm_signature)

    def __post_init__(self) -> None:
        if not self.func_id:
            self.func_id = _sha(self.file, self.name, _norm_sig(self.signature))

    def to_row(self) -> dict:
        return {
            "func_id": self.func_id,
            "file": self.file,
            "name": self.name,
            "signature": self.signature,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "body_path": self.body_path,
            "func_hash": self.func_hash,
            "description": self.description,
            "processed_taints": json.dumps(
                [asdict(p) for p in self.processed_taints], ensure_ascii=False),
        }


# ── 污点库 ───────────────────────────────────────────────────────────────────

@dataclass
class TaintRecord:
    taint_id: str = ""                  # = _sha(func_id, name, signature)
    func_id: str = ""                   # 所在函数
    name: str = ""                      # 污点名 (变量/参数名)
    signature: str = ""                 # 污点签名
    file: str = ""
    function: str = ""                  # 函数名 (冗余, 便于查询)
    next_propagations: list[str] = field(default_factory=list)   # prop_id 列表
    description: str = ""               # 污点内容说明

    def __post_init__(self) -> None:
        if not self.taint_id:
            self.taint_id = _sha(self.func_id, self.name, _norm_sig(self.signature))

    def to_row(self) -> dict:
        return {
            "taint_id": self.taint_id, "func_id": self.func_id, "name": self.name,
            "signature": self.signature, "file": self.file, "function": self.function,
            "next_propagations": json.dumps(self.next_propagations, ensure_ascii=False),
            "description": self.description,
        }


# ── 传播库 ───────────────────────────────────────────────────────────────────

@dataclass
class Validation:
    condition: str = ""                 # 校验条件 (如 "msg->length > 0")
    content: str = ""                   # 校验内容/语义

    def to_dict(self) -> dict:
        return {"condition": self.condition, "content": self.content}


@dataclass
class PropagationRecord:
    prop_id: str = ""
    source_func_id: str = ""            # 传播发生在哪个函数内
    source_taint_name: str = ""
    source_taint_signature: str = ""
    target_taint_name: str = ""
    target_taint_signature: str = ""
    target_func_id: str = ""            # 若传播到 callee, 目标函数; ""=函数内变量/外部
    target_function: str = ""           # 目标 callee 名 (便于查询, clang 校验对象)
    target_file: str = ""               # 目标 callee 文件
    call_line: int = 0                  # 调用点行号 (clang 据此标注分支)
    condition: str = ""                 # 传播条件 (人类可读; 分支互斥性由 clang 判)
    is_external: bool = False           # 传播到外部/全局数据变量 → 触发 nonlocal 跟踪 LLM
    is_indirect_call: bool = False     # 函数指针/回调/dispatch 间接调用 → 触发 function_pointer tracker
    is_external_callee: bool = False   # callee 定义不在源码树 → 记录传播但不跟入, 不走 tracker
    dispatch_kind: str = ""            # 间接调用类型 (function_pointer_field/callback/vtable/dispatch_map)
    escape_kind: str = ""             # 外部逃逸种类 (container|global|field_alias), LLM 判定, 脚本不覆盖
    carrier: str = ""                 # 逃逸载体变量名 (常是 alloc/new 产物, LLM 报, 供 tracker 上下文)
    escape_via: str = ""             # 实现逃逸的调用名 (如 list_add_tail, LLM 报, 仅记录/观测)
    # clang 标注 (analyze_function 填, 编排器路径分叉消费):
    callsite_validated: bool = False    # clang 确认该 call_line 确有对 target_function 的 CallExpr
    branch_group_id: str = ""          # 调用点所属分支组 (if/switch); 同组不同 arm = 互斥
    branch_arm_id: str = ""            # arm 标识 (then/else/case...)
    branch_path: list[dict] = field(default_factory=list)  # 祖先分支栈快照
    mutex_siblings: list[str] = field(default_factory=list)  # 互斥兄弟 callee 名
    actual_args: list[str] = field(default_factory=list)  # clang 调用点实参表达式 (推参数位置)
    validations: list[Validation] = field(default_factory=list)   # 传播过程校验列表
    description: str = ""               # 传播污点内容说明 (如 "struct.field only")
    _llm_said_external: bool = False   # LLM 原始 is_external (脚本覆盖前, 用于 clang 幽灵→indirect 判定)

    def __post_init__(self) -> None:
        if not self.prop_id:
            self.prop_id = _sha(self.source_func_id, self.source_taint_name,
                                self.target_taint_name, str(self.call_line), self.condition)

    def to_row(self) -> dict:
        return {
            "prop_id": self.prop_id, "source_func_id": self.source_func_id,
            "source_taint_name": self.source_taint_name, "source_taint_signature": self.source_taint_signature,
            "target_taint_name": self.target_taint_name, "target_taint_signature": self.target_taint_signature,
            "target_func_id": self.target_func_id, "target_function": self.target_function,
            "target_file": self.target_file, "call_line": self.call_line,
            "condition": self.condition, "is_external": 1 if self.is_external else 0,
            "is_indirect_call": 1 if self.is_indirect_call else 0, "dispatch_kind": self.dispatch_kind,
            "is_external_callee": 1 if self.is_external_callee else 0,
            "escape_kind": self.escape_kind,
            "carrier": self.carrier,
            "escape_via": self.escape_via,
            "callsite_validated": 1 if self.callsite_validated else 0,
            "branch_group_id": self.branch_group_id, "branch_arm_id": self.branch_arm_id,
            "branch_path": json.dumps(self.branch_path, ensure_ascii=False),
            "mutex_siblings": json.dumps(self.mutex_siblings, ensure_ascii=False),
            "actual_args": json.dumps(self.actual_args, ensure_ascii=False),
            "validations": json.dumps([v.to_dict() for v in self.validations], ensure_ascii=False),
            "description": self.description,
        }


# ── 编排库 ───────────────────────────────────────────────────────────────────

@dataclass
class TaintParamInfo:
    """编排边上的污点参数信息 (位置优先)。"""
    positions: list[int] = field(default_factory=list)   # 参数位置 (0-based)
    signature: str = ""                                  # 归一化污点签名
    names: list[str] = field(default_factory=list)       # 参数名 (辅助)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @staticmethod
    def from_json(s: str) -> "TaintParamInfo":
        d = json.loads(s) if s else {}
        return TaintParamInfo(**{k: d.get(k) for k in ("positions", "signature", "names")})


@dataclass
class OrchestrationEdge:
    edge_id: str = ""
    path_id: str = ""                   # 一条 DFS 路径
    source_function: str = ""
    source_signature: str = ""
    source_func_id: str = ""
    target_function: str = ""
    target_signature: str = ""
    target_func_id: str = ""
    taint_params: TaintParamInfo = field(default_factory=TaintParamInfo)
    depth: int = 0
    edge_order: int = 0
    status: str = "pending"             # pending/analyzing/done

    def __post_init__(self) -> None:
        if not self.edge_id:
            self.edge_id = _sha(self.path_id, str(self.edge_order), self.target_func_id)

    def to_row(self) -> dict:
        return {
            "edge_id": self.edge_id, "path_id": self.path_id,
            "source_function": self.source_function, "source_signature": self.source_signature,
            "source_func_id": self.source_func_id,
            "target_function": self.target_function, "target_signature": self.target_signature,
            "target_func_id": self.target_func_id,
            "taint_params": self.taint_params.to_json(),
            "depth": self.depth, "edge_order": self.edge_order, "status": self.status,
        }
