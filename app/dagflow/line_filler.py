"""dagflow 行号填充: tree-sitter 据语义锚点定位行号。

设计: docs/design-taint-analysis.md §3/§10 (行号脚本填, LLM 不输出)。
LLM 的 DAG 节点/边带语义锚点 (taint 变量名, callee sink_ref, escape sink_ref)。
本模块用 tree-sitter 解析函数体 AST, 把锚点映射到行号。

策略 (best-effort, 无 clang 语义):
- callee 边: 找函数内 CallExpression 名 == sink_ref (或含 sink_ref 段) → 该 call 行。
- return 边: 找 return_statement → 行。
- source 边: sink_ref 是源 callee (getenv/read) → 找该 call 行。
- inside 边/节点: best-effort 找变量赋值/使用行; 找不到留 0 (line_suspicious, 不丢)。
- extern/container 边: sink_ref/escape_via 出现行 (best-effort)。

行号是函数体内相对行? 否——用 tree-sitter start_point[0]+1 (文件绝对行)。
"""
from __future__ import annotations
import logging
from pathlib import Path
from typing import Any
from .models import TaintDAG, TaintEdge

logger = logging.getLogger("dvs.dagflow.line_filler")


def _walk(node: Any):
    """递归 yield 所有节点。"""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        for c in n.children:
            stack.append(c)


def _call_name(call_node: Any, source: bytes) -> str:
    """从 call_expression / call_expression 取被调函数名 (text)。"""
    fn = call_node.child_by_field_name("function")
    if fn is not None:
        return fn.text.decode("utf-8", "replace")
    # 兜底: 第一个 identifier/scoped_identifier 子节点
    for c in call_node.children:
        if c.type in ("identifier", "scoped_identifier", "qualified_identifier",
                      "field_expression", "pointer_expression"):
            return c.text.decode("utf-8", "replace")
    return ""


def _find_function_def(root: Any, func_name: str, start_line: int):
    """在 AST root 找匹配 func_name + start_line 的 function_definition。"""
    best = None
    for n in _walk(root):
        if n.type == "function_definition":
            sl = n.start_point[0] + 1
            # 匹配函数名 (declarator 内 identifier)
            decl = n.child_by_field_name("declarator")
            nm = ""
            cur = decl
            while cur is not None:
                if cur.type in ("identifier", "type_identifier", "scoped_identifier",
                                 "qualified_identifier", "namespace_qualified_name"):
                    nm = cur.text.decode("utf-8", "replace"); break
                cur = cur.child_by_field_name("declarator") or (cur.children[0] if cur.children else None)
            if nm == func_name or (start_line and abs(sl - start_line) <= 2):
                if best is None or (start_line and abs(sl - start_line) < abs(best.start_point[0] + 1 - start_line)):
                    best = n
    return best


def fill_lines(dag: TaintDAG, func, source_root: str) -> None:
    """就地填 dag.nodes[].line + edges[].line (best-effort, 找不到留 0)。

    func: FunctionRecord (file, name, start_line, end_line)。
    """
    from ..dataflow_v2.function_extractor import _parser_for
    src_path = Path(source_root) / func.file
    if not src_path.is_file():
        return
    src = src_path.read_bytes()
    parser = _parser_for(src_path, src)
    if parser is None:
        return
    tree = parser.parse(src)
    fdef = _find_function_def(tree.root_node, func.name, func.start_line)
    if fdef is None:
        # 退化: 在函数行范围内找 calls/returns
        fdef = tree.root_node

    # 索引: call 名 -> 行; return 行列表
    calls: dict[str, list[int]] = {}
    call_substrings: list[tuple[str, int]] = []  # (full_call_text, line) 用于间接/部分匹配
    returns: list[int] = []
    assignments: list[tuple[str, int]] = []  # (lhs var, line)
    for n in _walk(fdef):
        t = n.type
        if t in ("call_expression", "CALL_EXPRESSION"):
            nm = _call_name(n, src)
            ln = n.start_point[0] + 1
            calls.setdefault(nm, []).append(ln)
            call_substrings.append((nm, ln))
        elif t in ("return_statement",):
            returns.append(n.start_point[0] + 1)
        elif t == "assignment_expression":
            lhs = n.child_by_field_name("left")
            if lhs is not None:
                assignments.append((lhs.text.decode("utf-8", "replace").strip(), n.start_point[0] + 1))
        elif t == "declaration":
            # C/C++ 声明带初始化 (int a = t;) -> 当作赋值 (declared_name, line)
            for child in n.children:
                if child.type in ("init_declarator",):
                    decl = child.child_by_field_name("declarator")
                    if decl is not None:
                        # 取声明的变量名 (剥指针/引用)
                        nm = decl.text.decode("utf-8", "replace").strip().lstrip("*&")
                        assignments.append((nm, n.start_point[0] + 1))

    # 填边
    used_calls: set[tuple[str, int]] = set()  # 避免同 call 被多边复用 (按出现序匹配)
    def _next_call_line(nm: str) -> int:
        for ln in calls.get(nm, []):
            if (nm, ln) not in used_calls:
                used_calls.add((nm, ln))
                return ln
        # 子串/间接匹配 (sink_ref 含 -> 或是表达式, 找含该子串的 call)
        for full, ln in call_substrings:
            if (full, ln) in used_calls:
                continue
            if nm and (nm in full or full in nm):
                used_calls.add((full, ln))
                return ln
        return 0

    for node in dag.nodes:
        for e in node.children:
            if e.line:  # 已填跳过
                continue
            if e.kind == "callee" or e.kind == "source":
                e.line = _next_call_line(e.sink_ref)
            elif e.kind == "return":
                e.line = returns[0] if returns else 0
                if returns:
                    returns.pop(0)
            elif e.kind in ("extern", "container"):
                # escape_via 或 sink_ref 出现行
                e.line = _next_call_line(e.escape_via) or _next_call_line(e.sink_ref)
            elif e.kind == "inside":
                # best-effort: 找 taints[0] 的赋值行
                if e.taints:
                    for var, ln in assignments:
                        if e.taints[0] in var:
                            e.line = ln
                            break

    # 填节点 line: best-effort (首个 child 边的 line, 或根=start_line, source 节点=source 边 line)
    for node in dag.nodes:
        if node.line:
            continue
        if node.is_source:
            for e in node.children:
                if e.kind == "source" and e.line:
                    node.line = e.line; break
            if not node.line:
                node.line = func.start_line
        elif not node.parents:
            node.line = func.start_line  # 根
        elif node.children:
            node.line = node.children[0].line or func.start_line
        else:
            node.line = func.start_line
