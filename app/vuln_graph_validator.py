"""Validation helpers for dataflow vulnerability scan structured artifacts."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

VALID_SANITIZER_EFFECTS = {"none", "partial", "complete", "unknown"}
VALID_OPERATIONS = {
    "assignment", "call_arg", "return", "field", "container", "condition",
    "sink", "terminate", "validation", "sanitizer", "unknown",
}

_OPERATION_ALIASES = {
    "return_value": "return",
    "call_argument": "call_arg",
    "argument": "call_arg",
    "arg": "call_arg",
    "indirect": "call_arg",
    "function_pointer": "call_arg",
    "dlsym": "call_arg",
    "dereference": "field",
    "field_write": "field",
    "field_read": "field",
    "member": "field",
    "log": "sink",
    "logging": "sink",
    "file": "sink",
    "path": "sink",
}


def normalize_operation(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    return _OPERATION_ALIASES.get(text, text if text in VALID_OPERATIONS else "unknown")


def normalize_taint_graph(obj: dict[str, Any]) -> dict[str, Any]:
    """Normalize LLM JSON to the SQLite schema without failing on harmless vocabulary drift."""
    if not isinstance(obj, dict):
        return obj
    for edge in obj.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        edge["operation"] = normalize_operation(edge.get("operation"))
        if not str(edge.get("from") or edge.get("from_symbol") or "").strip():
            edge["from"] = "unknown"
        if not str(edge.get("to") or edge.get("to_symbol") or "").strip():
            op = str(edge.get("operation") or "unknown")
            edge["to"] = "terminate" if op == "terminate" else ("sink" if op == "sink" else "unknown")
        if not str(edge.get("line") or "").strip():
            edge["line"] = "unknown"
        if not str(edge.get("evidence") or "").strip():
            edge["evidence"] = "not provided"
        effect = str(edge.get("sanitizer_effect") or "none").strip().lower()
        edge["sanitizer_effect"] = effect if effect in VALID_SANITIZER_EFFECTS else "unknown"
        if edge.get("operation") == "terminate" and not str(edge.get("termination_reason") or "").strip():
            edge["termination_reason"] = "terminated by model without detailed reason"
    for item in obj.get("followups") or []:
        if not isinstance(item, dict):
            continue
        params = item.get("tainted_params")
        if isinstance(params, str):
            item["tainted_params"] = [x.strip() for x in params.split(",") if x.strip()]
        elif params is None:
            item["tainted_params"] = []
    return obj


def load_taint_graph(path: str | Path) -> tuple[dict[str, Any] | None, list[str]]:
    warnings: list[str] = []
    p = Path(path)
    if not p.exists():
        return None, [f"taint graph not found: {p}"]
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, [f"taint graph JSON parse failed: {exc}"]
    if not isinstance(obj, dict):
        return None, ["taint graph root must be object"]
    warnings.extend(validate_taint_graph(obj))
    return obj, warnings


def validate_taint_graph(obj: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    if not str(obj.get("function") or "").strip():
        warnings.append("missing function")
    if not str(obj.get("source_file") or "").strip():
        warnings.append("missing source_file")
    taints = obj.get("taints")
    if taints is not None and not isinstance(taints, list):
        warnings.append("taints must be list")
    edges = obj.get("edges")
    if edges is None:
        warnings.append("missing edges")
        edges = []
    if not isinstance(edges, list):
        warnings.append("edges must be list")
        return warnings
    for idx, edge in enumerate(edges):
        if not isinstance(edge, dict):
            warnings.append(f"edges[{idx}] must be object")
            continue
        if not str(edge.get("from") or edge.get("from_symbol") or "").strip():
            warnings.append(f"edges[{idx}] missing from")
        if not str(edge.get("to") or edge.get("to_symbol") or "").strip():
            warnings.append(f"edges[{idx}] missing to")
        if not str(edge.get("line") or "").strip():
            warnings.append(f"edges[{idx}] missing line")
        if not str(edge.get("evidence") or "").strip():
            warnings.append(f"edges[{idx}] missing evidence")
        op = str(edge.get("operation") or "unknown").strip()
        if op not in VALID_OPERATIONS:
            warnings.append(f"edges[{idx}] unknown operation: {op}")
        effect = str(edge.get("sanitizer_effect") or "none").strip()
        if effect not in VALID_SANITIZER_EFFECTS:
            warnings.append(f"edges[{idx}] invalid sanitizer_effect: {effect}")
        if op == "terminate" and not str(edge.get("termination_reason") or "").strip():
            warnings.append(f"edges[{idx}] terminate edge missing termination_reason")
    followups = obj.get("followups", [])
    if not isinstance(followups, list):
        warnings.append("followups must be list")
    else:
        for idx, item in enumerate(followups):
            if not isinstance(item, dict):
                warnings.append(f"followups[{idx}] must be object")
                continue
            if not str(item.get("function") or "").strip():
                warnings.append(f"followups[{idx}] missing function")
            params = item.get("tainted_params")
            if params is not None and not isinstance(params, list):
                warnings.append(f"followups[{idx}].tainted_params must be list")
    return warnings
