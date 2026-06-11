"""Best-effort callsite analysis for DVS followup scheduling.

Primary:  regex extracts call arguments from source lines (fast, reliable).
Fallback: tree-sitter enriches with validation conditions (if/while guards).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_CPP_EXTS = {".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}


@dataclass
class CallsiteInfo:
    call_expr: str = ""
    actual_args: list[str] = field(default_factory=list)
    derived_validations: list[dict[str, Any]] = field(default_factory=list)


def _line_num(line_hint: str) -> int:
    try:
        return int(str(line_hint or "").lstrip("Ll"))
    except ValueError:
        return 0


def _read_lines(source_root: str, source_file: str) -> list[str] | None:
    path = Path(source_root) / source_file
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


# ─── primary: regex arg extraction ────────────────────────────────────────────


def _split_args(raw: str) -> list[str]:
    """Split comma-separated arguments, respecting nested parens/brackets."""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in raw:
        if ch in "(<{":
            depth += 1
        elif ch in ")>}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur.clear()
            continue
        cur.append(ch)
    if cur:
        parts.append("".join(cur).strip())
    return parts


def _extract_args_regex(
    lines: list[str], line_hint: str, callee_function: str,
) -> tuple[str, list[str]] | None:
    """Extract call args from source lines using a positional regex.

    Returns (call_expr, [arg1, arg2, ...]) or None.
    """
    short = callee_function.rsplit("::", 1)[-1]
    target = _line_num(line_hint)
    # Build a regex that matches:  short_name ( args )
    # allowing for  obj->short_name(  and  obj.short_name(  prefixes.
    pat = re.compile(
        r"(?:->|\.|\s|^)"
        + re.escape(short)
        + r"\s*\((?P<args>[^()]*(?:\([^()]*\)[^()]*)*)\)"
    )
    for window in (0, 1, 3, 8):
        lo = max(0, (target - 1 - window) if target else 0)
        hi = min(len(lines), (target + window) if target else len(lines))
        window_text = " ".join(lines[lo:hi])
        m = pat.search(window_text)
        if m:
            raw_args = m.group("args").strip()
            args = [a.strip() for a in _split_args(raw_args) if a.strip()]
            return window_text[m.start():m.end()], args
    return None


# ─── fallback: tree-sitter validation extraction ──────────────────────────────

def _tree_sitter_validations(
    source_root: str, source_file: str, line_hint: str, callee_function: str,
    args: list[str],
) -> list[dict[str, Any]]:
    """Extract `if` / `while` guard validations from the callsite's ancestor nodes."""
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_c
        import tree_sitter_cpp
    except ImportError:
        return []
    path = Path(source_root) / source_file
    if not path.is_file():
        return []
    try:
        data = path.read_bytes()
    except OSError:
        return []
    try:
        lang = (
            Language(tree_sitter_cpp.language())
            if path.suffix.lower() in _CPP_EXTS
            else Language(tree_sitter_c.language())
        )
        parser = Parser()
        parser.language = lang
        tree = parser.parse(data)
    except Exception:
        return []
    short = callee_function.rsplit("::", 1)[-1]
    target_line = _line_num(line_hint)
    exact: list[Any] = []
    nearby: list[Any] = []

    def _ts_text(node) -> str:
        return data[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip()

    def visit(node):
        if node.type != "call_expression":
            for child in node.children:
                visit(child)
            return
        fn = node.child_by_field_name("function")
        if fn is None:
            for child in node.children:
                visit(child)
            return
        name = _ts_text(fn).split("->")[-1].split(".")[-1].split("::")[-1]
        if name != short:
            for child in node.children:
                visit(child)
            return
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
    if len(candidates) != 1:
        return []
    best = candidates[0]

    # Walk up to find `if` / `while` ancestor conditions
    facts: list[dict[str, Any]] = []
    node = getattr(best, "parent", None)
    while node is not None:
        if node.type in ("if_statement", "while_statement"):
            cond = node.child_by_field_name("condition")
            if cond is not None:
                cond_text = _ts_text(cond)
                line = int(node.start_point[0]) + 1
                for idx, arg in enumerate(args, start=1):
                    facts.extend(
                        _guard_facts(cond_text, idx, arg, f"L{line}")
                    )
        node = getattr(node, "parent", None)
    return facts


def _guard_facts(
    cond: str, arg_index: int, actual_expr: str, line: str,
) -> list[dict[str, Any]]:
    """Derive validation facts from a guard condition."""
    facts: list[dict[str, Any]] = []
    target = {"arg_index": arg_index, "symbol": f"arg{arg_index}", "access_path": []}
    evidence = cond.strip()
    if not evidence:
        return facts
    low = evidence.lower()
    # null check:  ptr != NULL  /  !ptr
    sym = re.escape(actual_expr) if actual_expr else r"[A-Za-z_]\w*"
    if re.search(rf"{sym}\s*!=\s*(?:0|null|nullptr)", low) or re.search(rf"!\s*{sym}", low):
        facts.append({
            "kind": "null_check", "target": target,
            "predicate": {"op": "!=", "rhs": {"type": "null"}},
            "scope": {"line": line, "dominates_call": True},
            "effect": "constrains", "confidence": "medium", "evidence": evidence,
        })
    # range:  len <= 1024  or  1024 >= len
    m = re.search(rf"{sym}\s*(<=|<|>=|>)\s*(-?\d+)", evidence)
    if m:
        facts.append({
            "kind": "range", "target": target,
            "predicate": {"op": m.group(1), "rhs": {"type": "const", "value": int(m.group(2))}},
            "scope": {"line": line, "dominates_call": True},
            "effect": "constrains", "confidence": "medium", "evidence": evidence,
        })
    m = re.search(rf"(-?\d+)\s*(<=|<|>=|>)\s*{sym}", evidence)
    if m:
        flip = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}[m.group(2)]
        facts.append({
            "kind": "range", "target": target,
            "predicate": {"op": flip, "rhs": {"type": "const", "value": int(m.group(1))}},
            "scope": {"line": line, "dominates_call": True},
            "effect": "constrains", "confidence": "medium", "evidence": evidence,
        })
    # bounds: size / len / sizeof hints
    if any(k in low for k in ("len", "size", "sizeof", "bound")):
        facts.append({
            "kind": "bounds", "target": target,
            "predicate": {"op": "bounded"},
            "scope": {"line": line, "dominates_call": True},
            "effect": "constrains", "confidence": "low", "evidence": evidence,
        })
    return facts


# ─── public entry point ───────────────────────────────────────────────────────

def analyze_callsite(
    source_root: str, source_file: str, line_hint: str, callee_function: str,
) -> CallsiteInfo:
    """Analyze a function callsite.

    Primary:  regex extracts call arguments (fast, no tree-sitter dependency).
    Fallback: tree-sitter enriches with `if`/`while` guard validations.
    """
    lines = _read_lines(source_root, source_file)
    if lines is None:
        return CallsiteInfo()
    regex_result = _extract_args_regex(lines, line_hint, callee_function)
    if regex_result is None:
        return CallsiteInfo()
    call_expr, args = regex_result
    validations = _tree_sitter_validations(
        source_root, source_file, line_hint, callee_function, args,
    )
    return CallsiteInfo(
        call_expr=call_expr,
        actual_args=args,
        derived_validations=validations,
    )


# ─── downstream helpers ───────────────────────────────────────────────────────

def map_taint_signature(
    raw_params: list[str], actual_args: list[str],
) -> tuple[list[str], str]:
    """Normalise tainted parameter names into position-based signatures (arg1, arg2, ...).

    The return value is used as part of the dedup key so two followups that pass
    different variable names to the same positional parameter of the same function
    are recognised as equivalent.
    """
    mapped: set[str] = set()
    for i, raw in enumerate(raw_params):
        item = str(raw or "").strip()
        m = re.search(r"(?:arg|param|参数|第)\s*([0-9]+)", item.lower())
        if m:
            mapped.add(f"arg{int(m.group(1))}")
        else:
            # match by name against actual_args
            for idx, actual in enumerate(actual_args or [], start=1):
                norm_actual = actual.strip().lstrip("&").strip()
                if item == norm_actual or item == actual.strip():
                    mapped.add(f"arg{idx}")
                    break
            else:
                mapped.add(item)
    sig = ",".join(sorted(mapped)) if mapped else "unknown"
    return list(mapped), sig
