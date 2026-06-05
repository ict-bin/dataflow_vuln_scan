from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.models import TaskConfig
from app.vuln_workflow import DataflowVulnWorkflow


class SourceIsolationTests(unittest.TestCase):
    def test_link_source_tree_copies_sources_and_excludes_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "src"
            root.mkdir()
            (root / "foo.c").write_text("int foo(void){return 0;}\n", encoding="utf-8")
            (root / "tainted.list").write_text("bad###Bad###L1###x\n", encoding="utf-8")
            (root / "dataflow-old.md").write_text("old\n", encoding="utf-8")
            out = Path(td) / "run"
            cfg = TaskConfig(task="x", cwd=str(root), workers={"agents": [{"model": "dummy"}]})
            wf = DataflowVulnWorkflow(cfg=cfg, func_name="foo", src_file="foo.c", line_hint="", taint_params=["x"], taint_ctx="", task_id="t", out_dir=out, dep=0, max_depth=1)
            wf._link_source_tree()
            copied = wf.ws / "foo.c"
            self.assertTrue(copied.exists())
            self.assertFalse(copied.is_symlink())
            copied.write_text("changed\n", encoding="utf-8")
            self.assertEqual((root / "foo.c").read_text(encoding="utf-8"), "int foo(void){return 0;}\n")
            self.assertFalse((wf.ws / "tainted.list").exists())
            self.assertFalse((wf.ws / "dataflow-old.md").exists())


if __name__ == "__main__":
    unittest.main()
