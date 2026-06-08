import tempfile
import unittest
from pathlib import Path

from app.callsite_analysis import analyze_callsite, map_taint_signature


class CallsiteAnalysisTests(unittest.TestCase):
    def test_callsite_maps_actual_expr_and_derives_dominating_range(self):
        root = Path(tempfile.mkdtemp())
        (root / "sample.c").write_text(
            "int C(int x) { return x; }\n"
            "void A(int len) {\n"
            "  if (len <= 1024) {\n"
            "    C(len);\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        info = analyze_callsite(str(root), "sample.c", "L4", "C")
        self.assertEqual(["len"], info.actual_args)
        mapped, sig = map_taint_signature(["len"], info.actual_args)
        self.assertEqual(["arg1"], mapped)
        self.assertEqual("arg1", sig)
        self.assertTrue(any(f.get("kind") == "range" and f.get("target", {}).get("arg_index") == 1 for f in info.derived_validations))
    def test_ambiguous_same_line_calls_do_not_infer_validation(self):
        root = Path(tempfile.mkdtemp())
        (root / "sample.c").write_text(
            "int C(int x) { return x; }\n"
            "void A(int len) { if (len <= 1024) { C(len); } C(len); }\n",
            encoding="utf-8",
        )
        info = analyze_callsite(str(root), "sample.c", "L2", "C")
        self.assertEqual([], info.actual_args)
        self.assertEqual([], info.derived_validations)


if __name__ == "__main__":
    unittest.main()
