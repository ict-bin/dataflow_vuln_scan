"""Validation-state normalization for taint-context merging.

The scheduler must not merge two paths only because they reach the same callee
with the same tainted argument.  The caller-side validation state is part of the
analysis context: an unvalidated path is more dangerous and can cover a validated
path, but a validated path must never cover an unvalidated path.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class ValidationState:
    facts: list[dict[str, Any]]
    signature: str
    risk_rank: int
    risk_class: str


_NO_VALIDATION_TERMS = {"", "none", "no", "no_validation", "无", "无校验", "未校验", "没有校验"}


def _as_list(raw: Any) -> list[Any]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, tuple):
        return list(raw)
    return [raw]


def _target_from_text(text: str, default_target: str = "") -> dict[str, Any]:
    low = text.lower()
    m = re.search(r"(?:arg|param|参数|第)\s*([0-9]+)", low)
    if m:
        return {"arg_index": int(m.group(1)), "symbol": f"arg{int(m.group(1))}", "access_path": []}
    m = re.search(r"\b([A-Za-z_]\w*)\b", text)
    sym = m.group(1) if m else default_target
    return {"arg_index": 0, "symbol": sym or default_target or "taint", "access_path": []}


def _fact(kind: str, target: dict[str, Any], *, predicate: dict[str, Any] | None = None,
          evidence: str = "", line: str = "", confidence: str = "medium") -> dict[str, Any]:
    return {
        "kind": kind,
        "target": target,
        "predicate": predicate or {},
        "scope": {"line": line, "dominates_call": True},
        "effect": "constrains" if kind not in {"no_validation", "unknown"} else kind,
        "confidence": confidence,
        "evidence": evidence,
    }


def _normalize_one(raw: Any, default_target: str = "") -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        kind = str(raw.get("kind") or raw.get("type") or "unknown").strip().lower()
        target = raw.get("target") if isinstance(raw.get("target"), dict) else _target_from_text(str(raw.get("target") or raw.get("symbol") or ""), default_target)
        pred = raw.get("predicate") if isinstance(raw.get("predicate"), dict) else {}
        return [_fact(kind, target, predicate=pred, evidence=str(raw.get("evidence") or raw.get("reason") or ""), line=str(raw.get("line") or ""), confidence=str(raw.get("confidence") or "medium"))]
    text = str(raw or "").strip()
    low = text.lower()
    target = _target_from_text(text, default_target)
    if low in _NO_VALIDATION_TERMS:
        return []
    facts: list[dict[str, Any]] = []
    if any(k in low for k in ["null", "nullptr", "非空", "空指针", "!=" "null"]):
        facts.append(_fact("null_check", target, predicate={"op": "!=", "rhs": {"type": "null"}}, evidence=text))
    m = re.search(r"(?:<=|<|>=|>)\s*(-?\d+)", low)
    if m or any(k in low for k in ["range", "范围", "上限", "下限"]):
        op = re.search(r"(<=|<|>=|>)", low)
        facts.append(_fact("range", target, predicate={"op": op.group(1) if op else "constrained", "rhs": {"type": "const", "value": int(m.group(1)) if m else None}}, evidence=text))
    if any(k in low for k in ["bound", "bounds", "length", "len", "size", "越界", "边界", "长度"]):
        facts.append(_fact("bounds", target, predicate={"op": "bounded"}, evidence=text))
    if any(k in low for k in ["enum", "whitelist", "白名单", "枚举"]):
        facts.append(_fact("enum", target, predicate={"op": "in"}, evidence=text))
    if any(k in low for k in ["auth", "permission", "owner", "权限", "授权", "归属"]):
        facts.append(_fact("auth", target, predicate={"op": "authorized"}, evidence=text))
    if any(k in low for k in ["sanitize", "sanitizer", "clean", "canonical", "清洗", "净化", "转义"]):
        facts.append(_fact("sanitizer", target, predicate={"op": "sanitized"}, evidence=text))
    return facts or [_fact("unknown", target, evidence=text)]


def normalize_validation_state(raw: Any = None, *, sanitizer_effect: str = "", default_target: str = "") -> ValidationState:
    facts: list[dict[str, Any]] = []
    for item in _as_list(raw):
        facts.extend(_normalize_one(item, default_target))
    if str(sanitizer_effect or "").lower() == "complete":
        facts.append(_fact("sanitizer", {"arg_index": 0, "symbol": default_target or "taint", "access_path": []}, predicate={"op": "sanitized"}, confidence="high"))
    if not facts:
        return ValidationState([], "none", 100, "no_validation")
    # Stable canonical form excludes free-form evidence.
    canonical = []
    for f in facts:
        canonical.append({
            "kind": f.get("kind", "unknown"),
            "target": f.get("target", {}),
            "predicate": f.get("predicate", {}),
            "effect": f.get("effect", ""),
        })
    canonical.sort(key=lambda x: json.dumps(x, sort_keys=True, ensure_ascii=False))
    kinds = {str(f.get("kind") or "unknown") for f in facts}
    if "no_validation" in kinds:
        return ValidationState(facts, "none", 100, "no_validation")
    if "unknown" in kinds:
        risk = 80; cls = "unknown"
    elif kinds == {"sanitizer"}:
        risk = 10; cls = "sanitized"
    elif any(k in kinds for k in ["range", "bounds", "enum", "auth", "null_check"]):
        risk = 40; cls = "validated"
    else:
        risk = 60; cls = "partial_validation"
    sig = hashlib.sha1(json.dumps(canonical, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]
    return ValidationState(facts, sig, risk, cls)


def validation_covers(existing_signature: str, existing_risk_rank: int, incoming_signature: str, incoming_risk_rank: int) -> bool:
    """Return True if an existing context is conservative enough to cover incoming.

    Only same validation signatures, no-validation, or unknown high-risk contexts
    cover other contexts. A validated/sanitized context never covers a less
    validated incoming path.
    """
    if existing_signature == incoming_signature:
        return True
    if existing_signature == "none":
        return True
    if existing_signature == "unknown" and incoming_signature != "none":
        return True
    return False
