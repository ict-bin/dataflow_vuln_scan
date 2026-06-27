"""Tests for clang_analyzer mutual-exclusion logic and graceful degradation.

The mutex computation is pure-python (operates on _CallHit dataclasses) so it
can be tested without libclang. The libclang path itself is exercised in the
deployed pod (libclang-19 present); here we only assert the degrade path.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.clang_analyzer import (  # noqa: E402
    _CallHit,
    _compute_mutex,
    analyze_function_callsites,
    libclang_available,
)


def _hit(name, branch_path):
    return _CallHit(name=name, call_line=0, call_expr="", actual_args=[], branch_path=branch_path)


class MutexLogicTests(unittest.TestCase):
    def test_if_else_arms_are_mutually_exclusive(self):
        g = "g1"
        h1 = _hit("Handl_1", [{"group_id": g, "arm": "then", "line": 1}])
        h2 = _hit("handl_2", [{"group_id": g, "arm": "else", "line": 1}])
        c = _hit("C", [])  # after if/else, no enclosing branch
        _compute_mutex([h1, h2, c], ["Handl_1", "handl_2", "C"])
        self.assertEqual(["handl_2"], h1._mutex_siblings)
        self.assertEqual(["Handl_1"], h2._mutex_siblings)
        self.assertEqual([], c._mutex_siblings)

    def test_same_arm_not_mutually_exclusive(self):
        g = "g1"
        f = _hit("f", [{"group_id": g, "arm": "then", "line": 1}])
        k = _hit("g", [{"group_id": g, "arm": "then", "line": 1}])
        _compute_mutex([f, k], ["f", "g"])
        self.assertEqual([], f._mutex_siblings)
        self.assertEqual([], k._mutex_siblings)

    def test_independent_ifs_not_mutually_exclusive(self):
        # if(a){f();} if(b){g();}  -> different if statements, both may run
        f = _hit("f", [{"group_id": "if1", "arm": "then", "line": 1}])
        k = _hit("g", [{"group_id": "if2", "arm": "then", "line": 3}])
        _compute_mutex([f, k], ["f", "g"])
        self.assertEqual([], f._mutex_siblings)
        self.assertEqual([], k._mutex_siblings)

    def test_nested_else_if_chain_is_mutually_exclusive(self):
        # if(a){f();} else { if(b){g();} } -> f(outer then) vs g(outer else, inner then)
        f = _hit("f", [{"group_id": "o", "arm": "then", "line": 1}])
        k = _hit("g", [
            {"group_id": "o", "arm": "else", "line": 1},
            {"group_id": "i", "arm": "then", "line": 4},
        ])
        _compute_mutex([f, k], ["f", "g"])
        self.assertEqual(["g"], f._mutex_siblings)
        self.assertEqual(["f"], k._mutex_siblings)

    def test_switch_cases_mutually_exclusive(self):
        s = "sw1"
        a = _hit("caseA", [{"group_id": s, "arm": "switch", "line": 1},
                           {"group_id": s, "arm": "case 1", "line": 2}])
        b = _hit("caseB", [{"group_id": s, "arm": "switch", "line": 1},
                           {"group_id": s, "arm": "case 2", "line": 5}])
        _compute_mutex([a, b], ["caseA", "caseB"])
        # share switch group, different case arm -> mutex
        self.assertEqual(["caseB"], a._mutex_siblings)
        self.assertEqual(["caseA"], b._mutex_siblings)


class DegradeTests(unittest.TestCase):
    def test_returns_empty_when_libclang_unavailable(self):
        if libclang_available():
            self.skipTest("libclang present in this env; skip degrade path")
        with tempfile.TemporaryDirectory() as td:
            r = analyze_function_callsites(td, "nope.c", "f", ["g"])
        self.assertEqual({}, r)

    def test_returns_empty_for_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            r = analyze_function_callsites(td, "missing.c", "f", ["g"],
                                            cache_dir=Path(td) / "cc")
        self.assertEqual({}, r)

    def test_empty_callee_names(self):
        self.assertEqual({}, analyze_function_callsites(".", "x.c", "f", []))


if __name__ == "__main__":
    unittest.main()
