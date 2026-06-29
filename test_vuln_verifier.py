"""Tests for app/vuln_verifier.py.

Covers the no-clang logic deterministically (V1 line-exists, V5 session-read
audit, callee-claim parsing, fail-safe degradation) and guards the clang path
behind libclang_available() so it runs on the pod but is skipped elsewhere.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))

from app import vuln_verifier
from app.vuln_verifier import (
    _audit_session_reads,
    _extract_callee_claims,
    _parse_line,
    verify_finding,
)


class _Rec:
    def __init__(self, source_file="", function_name=""):
        self.source_file = source_file
        self.function_name = function_name


def _write_tree(tmp: Path, files: dict[str, str]) -> str:
    for rel, body in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return str(tmp)


class TestParsing(unittest.TestCase):
    def test_parse_line(self):
        self.assertEqual(_parse_line("L588"), 588)
        self.assertEqual(_parse_line("588"), 588)
        self.assertEqual(_parse_line("L588-590"), 588)
        self.assertIsNone(_parse_line(None))
        self.assertIsNone(_parse_line(""))

    def test_extract_callee_claims_finds_realloc(self):
        txt = "调用 _http_head_buffer_append(L596), 其内部 realloc 扩容导致堆溢出"
        claims = dict(_extract_callee_claims(txt, own_func="http_head_parse_http1_1"))
        self.assertIn("_http_head_buffer_append", claims)
        kws = claims["_http_head_buffer_append"]
        self.assertTrue(any(k in ("realloc", "扩容") for k in kws), kws)

    def test_extract_callee_claims_skips_own_func_and_builtins(self):
        txt = "memcpy(buf, src, n); http_parse() 调用"
        claims = dict(_extract_callee_claims(txt, own_func="http_parse"))
        self.assertNotIn("http_parse", claims)
        self.assertNotIn("memcpy", claims)


class TestV1LineExists(unittest.TestCase):
    def test_phantom_line_fails(self):
        with tempfile.TemporaryDirectory() as td:
            _write_tree(Path(td), {"a.c": "line1\nline2\nline3\n"})
            rec = _Rec("a.c", "foo")
            item = {"line": "L999", "function_name": "foo", "summary": "x", "evidence": ""}
            vr = verify_finding(rec, item, td, None, "nonexistent.jsonl")
            self.assertFalse(vr["passed"])
            self.assertTrue(any("v1_line_exists" in r for r in vr["reasons"]), vr["reasons"])
            self.assertEqual(vr["checks"]["v1_line_exists"]["status"], "fail")

    def test_real_line_passes(self):
        with tempfile.TemporaryDirectory() as td:
            _write_tree(Path(td), {"a.c": "line1\nline2\nline3\n"})
            rec = _Rec("a.c", "foo")
            item = {"line": "L2", "function_name": "foo", "summary": "x"}
            vr = verify_finding(rec, item, td, None, "nonexistent.jsonl")
            self.assertEqual(vr["checks"]["v1_line_exists"]["status"], "pass")
            # no clang -> v2/v3/v4 skipped; v5 skipped (no session); passed True
            self.assertTrue(vr["passed"], vr)


class TestV5SessionAudit(unittest.TestCase):
    def test_unread_callee_fails(self):
        with tempfile.TemporaryDirectory() as td:
            _write_tree(Path(td), {"a.c": "x\n" * 5})
            sess = Path(td) / "fork.jsonl"
            # session only read funcA; finding claims funcB does realloc
            sess.write_text(json.dumps({
                "role": "tool_use", "name": "extract_func",
                "input": {"function": "funcA"}
            }, ensure_ascii=False) + "\n", encoding="utf-8")
            rec = _Rec("a.c", "caller")
            item = {"line": "L2", "function_name": "caller",
                    "evidence": "funcB() 内部 realloc 扩容"}
            vr = verify_finding(rec, item, td, None, str(sess))
            self.assertEqual(vr["checks"]["v5_session_read_audit"]["status"], "fail", vr["checks"])
            self.assertFalse(vr["passed"])

    def test_read_callee_passes(self):
        with tempfile.TemporaryDirectory() as td:
            _write_tree(Path(td), {"a.c": "x\n" * 5})
            sess = Path(td) / "fork.jsonl"
            sess.write_text(json.dumps({
                "role": "tool_use", "name": "extract_func",
                "input": {"function": "funcB", "body": "funcB() { realloc(p, n); }"}
            }, ensure_ascii=False) + "\n", encoding="utf-8")
            rec = _Rec("a.c", "caller")
            item = {"line": "L2", "function_name": "caller",
                    "evidence": "funcB() 内部 realloc 扩容"}
            vr = verify_finding(rec, item, td, None, str(sess))
            self.assertEqual(vr["checks"]["v5_session_read_audit"]["status"], "pass", vr["checks"])


class TestDegradation(unittest.TestCase):
    def test_libclang_unavailable_skips_clang_checks(self):
        with tempfile.TemporaryDirectory() as td:
            _write_tree(Path(td), {"a.c": "x\n" * 5})
            rec = _Rec("a.c", "foo")
            item = {"line": "L2", "function_name": "foo",
                    "evidence": "bar() 内部 realloc 扩容"}
            with mock.patch("app.vuln_verifier.function_calls_callee", return_value=None), \
                 mock.patch("app.vuln_verifier.callee_body_contains_token", return_value=None), \
                 mock.patch("app.vuln_verifier.get_function_callees", return_value=None):
                vr = verify_finding(rec, item, td, None, "nope.jsonl")
            for k in ("v2_callsite_exists", "v3_callee_behavior", "v4_reachability"):
                self.assertEqual(vr["checks"][k]["status"], "skipped", (k, vr["checks"][k]))
            # v1 pass, v5 skipped(no session) -> no fail -> passed True
            self.assertTrue(vr["passed"], vr)


class TestClangPath(unittest.TestCase):
    """End-to-end clang verification; only runs when libclang is available."""

    def setUp(self):
        try:
            from app.clang_analyzer import libclang_available
        except Exception:
            self.skipTest("clang_analyzer import failed")
        if not libclang_available():
            self.skipTest("libclang unavailable in this env")

    def test_phantom_callee_and_realloc_hallucination_fail(self):
        src = (
            "void sink_write(char *d, int n){ memcpy(d, src, n); }\n"      # callee, no realloc
            "int caller_http1(char *p, int len){\n"
            "    sink_write(p, len);\n"                                    # real call
            "    return 0;\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            _write_tree(Path(td), {"a.c": src})
            rec = _Rec("a.c", "caller_http1")
            # finding hallucinates: claims bar_realloc() called & realloc; bar not in body
            item = {"line": "L3", "function_name": "caller_http1",
                    "evidence": "调用 bar_realloc(L3) 内部 realloc 扩容导致溢出",
                    "trigger_path": "步骤1: caller_http1 调用 bar_realloc() 触发"}
            vr = verify_finding(rec, item, td, None, "nope.jsonl")
            # bar_realloc not called by caller_http1 -> v2 fail
            self.assertEqual(vr["checks"]["v2_callsite_exists"]["status"], "fail", vr["checks"])
            self.assertFalse(vr["passed"])

    def test_real_sink_passes(self):
        src = (
            "void sink_write(char *d, int n){ char *q = realloc(d, n); memcpy(q, src, n); }\n"
            "int caller_http1(char *p, int len){ sink_write(p, len); return 0; }\n"
        )
        with tempfile.TemporaryDirectory() as td:
            _write_tree(Path(td), {"a.c": src})
            rec = _Rec("a.c", "caller_http1")
            item = {"line": "L2", "function_name": "caller_http1",
                    "evidence": "调用 sink_write(p, len) 内部 realloc 扩容"}
            vr = verify_finding(rec, item, td, None, "nope.jsonl")
            self.assertEqual(vr["checks"]["v2_callsite_exists"]["status"], "pass", vr["checks"])
            self.assertEqual(vr["checks"]["v3_callee_behavior"]["status"], "pass", vr["checks"])
            self.assertTrue(vr["passed"], vr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
