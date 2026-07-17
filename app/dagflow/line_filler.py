"""dagflow 后处理: 从 LLM 输出的行号解析源码补全 DAG 字段。

设计: docs/design-taint-analysis.md §3 (行号为桥梁)。
LLM 输出行号 (node.line, edge.line, edge.cond_lines, node.check_lines)。
本模块用 tree-sitter 解析函数体 AST, 从行号提取:
  - condition: cond_lines → if-statement 条件文本
  - checks: check_lines → if-statement 条件文本
  - param_taints: tainted_args 索引 → CallExpr args → callee 签名形参名
  - sink_ref: = callee (callee 边) 或 escape_via
  - escape_subkind: 从 kind + carrier 推断
  - parents: 从 edges 反推 (在 models.from_dict 已做)

行号范围支持: 765 (单行), [765,767] (多行)。
"""
from __future__ import annotations
import logging
from pathlib import Path
from typing import Any
from .models import TaintDAG, TaintEdge, TaintNode, _norm_line, _norm_line_list

logger = logging.getLogger("dvs.dagflow.line_filler")


def _walk(node: Any):
    """递归 yield 所有节点。"""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        for c in n.children:
            stack.append(c)


def _find_function_def(root: Any, func_name: str, start_line: int):
    """在 AST root 找匹配 func_name + start_line 的 function_definition。"""
    best = None
    for n in _walk(root):
        if n.type == "function_definition":
            sl = n.start_point[0] + 1
            decl = n.child_by_field_name("declarator")
            nm = ""
            cur = decl
            while cur is not None:
                if cur.type in ("identifier", "type_identifier", "scoped_identifier",
                                "qualified_identifier", "namespace_qualified_name"):
                    nm = cur.text.decode("utf-8", "replace")
                    break
                cur = cur.child_by_field_name("declarator") or (cur.children[0] if cur.children else None)
            if nm == func_name or (start_line and abs(sl - start_line) <= 2):
                if best is None or (start_line and abs(sl - start_line) < abs(best.start_point[0] + 1 - start_line)):
                    best = n
    return best


def _node_text(node: Any, source: bytes) -> str:
    """获取 AST 节点的源码文本。"""
    try:
        return node.text.decode("utf-8", "replace").strip()
    except Exception:
        return ""


def _find_if_condition(fdef: Any, start: int, end: int, source: bytes) -> str:
    """在函数体 AST 找 start行(到end行) 的 if-statement, 返回条件表达式文本。

    支持多行 if: if (a &&
                      b) → 返回 "a && b"
    """
    for n in _walk(fdef):
        if n.type in ("if_statement", "IF_STATEMENT"):
            nl = n.start_point[0] + 1
            if nl == start or (start <= nl <= end) or (nl <= start and n.end_point[0] + 1 >= start):
                # if_statement 的第一个条件子节点
                cond = n.child_by_field_name("condition")
                if cond is not None:
                    return _node_text(cond, source)
                # 兼容: 第一个非括号子节点
                for c in n.children:
                    if c.type not in ("if_keyword", "else_keyword", "compound_statement",
                                      "ELSE_KEYWORD", "IF_KEYWORD", "{", "}", "(", ")"):
                        return _node_text(c, source)
    return ""


def _find_call_at_line(fdef: Any, start: int, end: int, source: bytes) -> tuple[str, list[str]] | None:
    """在函数体 AST 找 start行(到end行) 的 CallExpression, 返回 (callee_name, args)。

    args 是实参表达式文本列表。
    """
    best = None
    for n in _walk(fdef):
        if n.type in ("call_expression", "CALL_EXPRESSION"):
            nl = n.start_point[0] + 1
            if nl == start or (start <= nl <= end) or (nl <= start and n.end_point[0] + 1 >= start):
                fn_node = n.child_by_field_name("function")
                callee = ""
                if fn_node is not None:
                    callee = _node_text(fn_node, source)
                args = []
                # CallExpr 的 arguments: function 子节点之后的子节点 (排除 function 和括号)
                found_fn = False
                for c in n.children:
                    ct = c.type
                    if c is fn_node:
                        found_fn = True
                        continue
                    if ct in ("argument_list", "ARGUMENT_LIST"):
                        for arg_child in c.children:
                            if arg_child.type not in (",", "(", ")"):
                                args.append(_node_text(arg_child, source))
                        break
                    if found_fn and ct not in ("(", ")", ","):
                        args.append(_node_text(c, source))
                if best is None or abs(nl - start) < abs(best[2] - start):
                    best = (callee, args, nl)
    if best is None:
        return None
    return (best[0], best[1])


def _extract_params(signature: str) -> list[str]:
    """从 C/C++ 函数签名提取形参名。"""
    import re
    # 取括号内参数部分
    m = re.search(r"\(([^)]*)\)", signature)
    if not m:
        return []
    params_str = m.group(1).strip()
    if not params_str or params_str == "void":
        return []
    params = []
    for raw in params_str.split(","):
        raw = raw.strip()
        if not raw:
            continue
        # 去掉类型: 取最后一个标识符 (变量名), 兼容指针/引用/数组
        raw = re.sub(r"\[.*?\]", "", raw).strip()
        raw = raw.lstrip("*&")
        # 取最后一个 word (可能含 -> 或 :: 但形参名通常在最后)
        m2 = re.search(r"([A-Za-z_]\w*)\s*$", raw)
        if m2:
            params.append(m2.group(1))
    return params


def _extract_return_expr(fdef: Any, start: int, end: int, source: bytes) -> str | None:
    """在函数体 AST 找 start行(到end行) 的 return_statement, 返回返回表达式文本。

    e.g. return ret; → "ret"
         return conn->field; → "conn->field"
         return -1; → "-1" (调用方判断常量后删边)
         return callee(args); → "callee(args)"
    """
    best = None
    for n in _walk(fdef):
        if n.type in ("return_statement", "RETURN_STATEMENT"):
            nl = n.start_point[0] + 1
            if nl == start or (start <= nl <= end) or (nl <= start and n.end_point[0] + 1 >= start):
                # return_statement 的子节点 = 返回表达式 (无 return 关键字)
                for c in n.children:
                    if c.type not in ("return_keyword", "RETURN_KEYWORD", ";"):
                        txt = _node_text(c, source)
                        if txt:
                            if best is None or abs(nl - start) < abs(best[1] - start):
                                best = (txt, nl)
                            break
    return best[0] if best else None


def fill_lines(dag: TaintDAG, func, source_root: str, func_lookup=None) -> None:
    """后处理: 从 LLM 输出的行号解析源码补全 DAG 字段。

    补全:
    - edge.sink_ref = callee (callee 边) 或 escape_via
    - edge.param_taints (从 tainted_args 索引 + CallExpr args + callee 签名)
    - edge.condition (从 cond_lines → if 条件文本)
    - edge.escape_subkind (从 kind + carrier 推断)
    - node.checks (从 check_lines → if 条件文本)

    func: FunctionRecord (file, name, start_line, end_line)。
    func_lookup: 可选, 用于查 callee 签名 (映射 tainted_args 到形参名)。
    """
    from ..dataflow_v2.function_extractor import _parser_for
    src_path = Path(source_root) / func.file
    if not src_path.is_file():
        logger.warning("line_filler: source file not found: %s", func.file)
        return
    src = src_path.read_bytes()
    parser = _parser_for(src_path, src)
    if parser is None:
        logger.warning("line_filler: no parser for %s", func.file)
        return
    tree = parser.parse(src)
    fdef = _find_function_def(tree.root_node, func.name, func.start_line)
    if fdef is None:
        fdef = tree.root_node

    # ── 填 edge 字段 ──
    for node in dag.nodes:
        for e in node.children:
            # sink_ref: callee 边 = callee 名; extern/container = escape_via
            if e.kind == "callee":
                e.sink_ref = e.callee
            elif e.kind in ("extern", "container"):
                e.sink_ref = e.escape_via or e.carrier

            # escape_subkind 推断
            if e.kind == "extern":
                # carrier 含 -> 或 . → field_alias; 否则 global
                if e.carrier and ("->" in e.carrier or "." in e.carrier):
                    e.escape_subkind = "field_alias"
                else:
                    e.escape_subkind = "global"
            elif e.kind == "container":
                e.escape_subkind = "container"

            # condition: 从 cond_lines → if 条件文本
            if e.cond_lines:
                for cl in e.cond_lines:
                    s, ee = _norm_line(cl)
                    cond_text = _find_if_condition(fdef, s, ee or s, src)
                    if cond_text:
                        e.condition.append({"line": s, "text": cond_text})
                    else:
                        # 找不到 if → 仍记录行号 (挖掘 LLM 可自行读源码)
                        e.condition.append({"line": s, "text": ""})

            # param_taints: 从 tainted_args + CallExpr args + callee 签名
            if e.kind == "callee" and e.tainted_args and e.line:
                sl, el = (e.line, e.line_end or e.line)
                call_info = _find_call_at_line(fdef, sl, el, src)
                if call_info is not None:
                    call_callee, call_args = call_info
                    # 校验 LLM 输出的 callee 名与 AST 一致
                    if e.callee and call_callee and e.callee not in call_callee and call_callee not in e.callee:
                        logger.warning("callee mismatch: LLM=%s AST=%s at L%d", e.callee, call_callee, sl)
                    # 查 callee 签名形参名
                    real_params = []
                    if func_lookup:
                        callee_func = func_lookup(e.callee)
                        if callee_func is not None:
                            real_params = _extract_params(getattr(callee_func, "signature", ""))
                    # 映射: tainted_args 索引 → call_args → real_params
                    for ta in e.tainted_args:
                        idx = int(ta.get("i", -1))
                        taint = str(ta.get("taint", ""))
                        param_name = ""
                        if 0 <= idx < len(call_args):
                            arg_expr = call_args[idx]
                            if real_params and idx < len(real_params):
                                param_name = real_params[idx]
                            else:
                                # 无签名 → 用实参表达式作 param 名 (best-effort)
                                param_name = arg_expr
                        if param_name:
                            e.param_taints.append({"param": param_name, "taint": taint})

    # ── 填 node.checks ──
    for node in dag.nodes:
        if node.check_lines:
            for cl in node.check_lines:
                s, ee = _norm_line(cl)
                cond_text = _find_if_condition(fdef, s, ee or s, src)
                node.checks.append({"line": s, "text": cond_text})

    # ── 填 node.is_source (从 source 字段) ──
    for node in dag.nodes:
        node.is_source = bool(node.source)

    # ── return 边: 从源码提取返回表达式 → 填 taints (常量返回删边) ──
    _CONST_RE = None
    import re as _re
    _CONST_RE = _re.compile(r'^\s*(return\s+)?(?:0|-1+|NULL|nullptr|true|false|\d+(?:\.\d+)?[fLuU]*)\s*;?\s*$', _re.IGNORECASE)
    edges_to_remove = []
    for node in dag.nodes:
        for i, e in enumerate(node.children):
            if e.kind != "return" or not e.line:
                continue
            expr = _extract_return_expr(fdef, e.line, e.line_end or e.line, src)
            if expr is None:
                # 找不到 return 语句 → 保留边但 taints 为空 (挖掘 LLM 可自行读源码)
                continue
            if _CONST_RE.match(f"return {expr};"):
                # 常量返回 → 无污点传播 → 标记删除
                edges_to_remove.append((node, i))
                logger.info("return edge removed: constant return at L%d", e.line)
            else:
                e.taints = [expr]
    # 删除常量返回边
    for node, i in sorted(edges_to_remove, key=lambda x: -x[1]):
        if i < len(node.children):
            node.children.pop(i)
