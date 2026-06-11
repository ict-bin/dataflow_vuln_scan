"""Best-effort callsite analysis for DVS followup scheduling."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tree_sitter import Language, Parser
import tree_sitter_c
import tree_sitter_cpp

_CPP_EXTS = {".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}


@dataclass
class CallsiteInfo:
    call_expr: str = ""
    actual_args: list[str] = field(default_factory=list)
    derived_validations: list[dict[str, Any]] = field(default_factory=list)


def _language(path: Path):
    return Language(tree_sitter_cpp.language()) if path.suffix.lower() in _CPP_EXTS else Language(tree_sitter_c.language())


def _text(node, data: bytes) -> str:
    return data[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _callee_name(node, data: bytes) -> str:
    fn = node.child_by_field_name("function")
    if fn is None:
        return ""
    value = _text(fn, data).strip()
    return value.split("->")[-1].split(".")[-1].split("::")[-1]


def _arg_list(node, data: bytes) -> list[str]:
    args = node.child_by_field_name("arguments")
    if args is None:
        return []
    result: list[str] = []
    for child in args.children:
        if child.type in {"(", ")", ","}:
            continue
        result.append(_text(child, data).strip())
    return result


def _line_num(line_hint: str) -> int:
    try:
        return int(str(line_hint or "").lstrip("Ll"))
    except ValueError:
        return 0


def _fact_from_condition(cond: str, arg_index: int, actual_expr: str, line: int) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    target = {"arg_index": arg_index, "symbol": f"arg{arg_index}", "access_path": []}
    evidence = cond.strip()
    if not evidence:
        return facts
    low = evidence.lower()
    if actual_expr and actual_expr in evidence:
        symbol_pat = re.escape(actual_expr)
    else:
        m = re.search(r"[A-Za-z_]\w*", actual_expr or "")
        symbol_pat = re.escape(m.group(0)) if m else r"[A-Za-z_]\w*"
    if re.search(rf"{symbol_pat}\s*!=\s*(?:0|null|nullptr)", low, re.I) or re.search(rf"!\s*{symbol_pat}", low, re.I):
        facts.append({"kind": "null_check", "target": target, "predicate": {"op": "!=", "rhs": {"type": "null"}}, "scope": {"line": f"L{line}", "dominates_call": True}, "effect": "constrains", "confidence": "medium", "evidence": evidence})
    m = re.search(rf"{symbol_pat}\s*(<=|<|>=|>)\s*(-?\d+)", evidence)
    if m:
        facts.append({"kind": "range", "target": target, "predicate": {"op": m.group(1), "rhs": {"type": "const", "value": int(m.group(2))}}, "scope": {"line": f"L{line}", "dominates_call": True}, "effect": "constrains", "confidence": "medium", "evidence": evidence})
    m = re.search(rf"(-?\d+)\s*(<=|<|>=|>)\s*{symbol_pat}", evidence)
    if m:
        flip = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}[m.group(2)]
        facts.append({"kind": "range", "target": target, "predicate": {"op": flip, "rhs": {"type": "const", "value": int(m.group(1))}}, "scope": {"line": f"L{line}", "dominates_call": True}, "effect": "constrains", "confidence": "medium", "evidence": evidence})
    if any(k in low for k in ["len", "size", "sizeof", "bound"]):
        facts.append({"kind": "bounds", "target": target, "predicate": {"op": "bounded"}, "scope": {"line": f"L{line}", "dominates_call": True}, "effect": "constrains", "confidence": "low", "evidence": evidence})
    return facts


def _ancestor_conditions(call_node, data: bytes, actual_args: list[str]) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    node = getattr(call_node, "parent", None)
    while node is not None:
        if node.type == "if_statement":
            cond = node.child_by_field_name("condition")
            if cond is not None:
                cond_text = _text(cond, data)
                line = int(node.start_point[0]) + 1
                for idx, arg in enumerate(actual_args, start=1):
                    facts.extend(_fact_from_condition(cond_text, idx, arg, line))
        node = getattr(node, "parent", None)
    return facts


def analyze_callsite(source_root: str, source_file: str, line_hint: str, callee_function: str) -> CallsiteInfo:
    root = Path(source_root)
    path = Path(source_file)
    if not path.is_absolute():
        path = root / source_file
    if not path.exists():
        return CallsiteInfo()
    target_line = _line_num(line_hint)
    data = path.read_bytes()
    parser = Parser(); parser.language = _language(path)
    tree = parser.parse(data)
    short = callee_function.split("::")[-1]
    exact: list[Any] = []
    nearby: list[Any] = []

    def visit(node):
        if node.type == "call_expression" and _callee_name(node, data) == short:
            start = int(node.start_point[0]) + 1
            end = int(node.end_point[0]) + 1
            if target_line and start <= target_line <= end:
                exact.append(node)
            elif not target_line or abs(start - target_line) <= 2:
                nearby.append(node)
        for child in node.children:
            visit(child)
    visit(tree.root_node)
    candidates = exact if exact else nearby
    # Do not infer validations when multiple same-line callsites are possible;
    # otherwise a guarded call can incorrectly sanitize an unguarded sibling.
    if len(candidates) != 1:
        return CallsiteInfo()
    best = candidates[0]
    args = _arg_list(best, data)
    return CallsiteInfo(call_expr=_text(best, data).strip(), actual_args=args, derived_validations=_ancestor_conditions(best, data, args))


def map_taint_signature(raw_params: list[str], actual_args: list[str]) -> tuple[list[str], str]:
    """Normalise tainted parameter names into position-based signatures (arg1, arg2, ...).

    The return value is used as part of the dedup key so two followups that pass
    different variable names to the same positional parameter of the same function
    are recognised as equivalent.
    """
    mapped: set[str] = set()
    used_positions: set[int] = set()
    for i, raw in enumerate(raw_params):
        item = str(raw or "").strip()
        # Explicit positional notation: "arg3" or "参数2"
        m = re.search(r"(?:arg|param|参数|第)\s*([0-9]+)", item.lower())
        if m:
            pos = int(m.group(1))
            mapped.add(f"arg{pos}")
            used_positions.add(pos)
            continue
        # Try to match by symbolic name against actual call-site arguments
        matched = False
        for idx, actual in enumerate(actual_args or [], start=1):
            a = str(actual or "").strip()
            if item and (item == a or item in a or a in item):
                mapped.add(f"arg{idx}")
                used_positions.add(idx)
                matched = True
                break
        if not matched:
            # Fallback: use positional index.  When the Worker lists params in
            # order, this maps the first param to arg1, second to arg2, etc.
            fallback = i + 1
            mapped.add(f"arg{fallback}")
    result = sorted(mapped)
    return result, "+".join(result) if result else "none"
