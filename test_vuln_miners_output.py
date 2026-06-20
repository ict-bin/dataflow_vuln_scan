"""Unit tests for the updated vuln-miners output handling.

Covers the structured exploitability object, the four-dimension self-check
(aligned with vuln-verify's code_accurate/path_reachable/unmitigated/
security_impact verdict), the confidence gate, and backward compatibility
with legacy free-text findings.
"""
from __future__ import annotations

import os

from app.vuln_workflow import (
    _check_finding_dimensions,
    _format_dimensions_md,
    _format_exploitability_md,
    _format_vuln_report_md,
    _vuln_intake_min_confidence,
)

_DIMS_PASS = {
    "code_accurate": {"passed": True, "reason": "lines/ops match source"},
    "path_reachable": {"passed": True, "reason": "external entry reachable"},
    "unmitigated": {"passed": True, "reason": "no implicit defense"},
    "security_impact": {"passed": True, "reason": "heap overflow reachable"},
}
_DIMS_FAIL = dict(_DIMS_PASS, security_impact={"passed": False, "reason": "DoS only"})


# ── exploitability rendering ────────────────────────────────────────────────

def test_exploitability_structured_object() -> None:
    md = _format_exploitability_md(
        {"preconditions": "ctrl parg3", "trigger_complexity": "low", "worst_case_impact": "DoS"}
    )
    assert "ctrl parg3" in md
    assert "low" in md
    assert "DoS" in md


def test_exploitability_legacy_string() -> None:
    assert _format_exploitability_md("attacker-reachable") == "attacker-reachable"


def test_exploitability_empty() -> None:
    assert _format_exploitability_md("") == "未知"
    assert _format_exploitability_md(None) == "未知"


# ── four-dimension self-check ────────────────────────────────────────────────

def test_dimensions_render_markdown_table() -> None:
    md = _format_dimensions_md(_DIMS_PASS)
    assert "四维度自检" in md
    assert "PASS" in md
    assert "external entry reachable" in md


def test_dimensions_missing_returns_empty() -> None:
    assert _format_dimensions_md({}) == ""
    assert _format_dimensions_md(None) == ""


def test_check_dimensions_all_passed() -> None:
    assert _check_finding_dimensions(_DIMS_PASS) is True


def test_check_dimensions_single_fail_disqualifies() -> None:
    assert _check_finding_dimensions(_DIMS_FAIL) is False


def test_check_dimensions_absent_is_eligible() -> None:
    # Legacy / partial findings: rely on the confidence gate instead.
    assert _check_finding_dimensions({}) is True
    assert _check_finding_dimensions(None) is True


# ── full report render ──────────────────────────────────────────────────────

def test_full_report_contains_structured_fields() -> None:
    item = {
        "title": "heap overflow",
        "vuln_type": "heap-buffer-overflow",
        "severity": "high",
        "confidence": 0.85,
        "summary": "tainted len controls memcpy",
        "evidence": "L10: memcpy(d,s,len)",
        "exploitability": {"preconditions": "ctrl parg3", "trigger_complexity": "low", "worst_case_impact": "DoS"},
        "dimensions": _DIMS_FAIL,
    }
    md = _format_vuln_report_md(item, "vuln_test", "a.c", "foo", "L10")
    assert "heap-buffer-overflow" in md
    assert "L10" in md
    assert "ctrl parg3" in md
    # FAIL must surface for the failed dimension
    assert "FAIL" in md and "PASS" in md


def test_full_report_legacy_compatibility() -> None:
    item = {"title": "legacy", "summary": "s", "evidence": "e", "exploitability": "free text"}
    md = _format_vuln_report_md(item, "vuln_x", "b.c", "bar", "")
    assert "free text" in md
    # No dimensions section when absent
    assert "四维度自检" not in md


# ── confidence gate ─────────────────────────────────────────────────────────

def _set_conf(value: str) -> None:
    os.environ["DVS_VULN_INTAKE_MIN_CONFIDENCE"] = value


def test_min_confidence_default() -> None:
    os.environ.pop("DVS_VULN_INTAKE_MIN_CONFIDENCE", None)
    assert _vuln_intake_min_confidence() == 0.5


def test_min_confidence_override() -> None:
    _set_conf("0.7")
    try:
        assert _vuln_intake_min_confidence() == 0.7
    finally:
        _set_conf("0.5")


def test_min_confidence_clamps_invalid() -> None:
    for bad in ("abc", "2.5", "-3"):
        _set_conf(bad)
        try:
            v = _vuln_intake_min_confidence()
            assert 0.0 <= v <= 1.0
        finally:
            _set_conf("0.5")


if __name__ == "__main__":
    # Lightweight standalone runner for environments without pytest.
    funcs = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in funcs:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
            passed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL  {fn.__name__}: {exc!r}")
            raise
    print(f"\n{passed}/{len(funcs)} tests passed")
