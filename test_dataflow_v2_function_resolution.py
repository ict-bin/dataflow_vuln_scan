"""dataflow-v2 命名空间/限定名函数解析回归测试。"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.dataflow_v2.function_extractor import ensure_file_indexed, find_func_in_source
from app.dataflow_v2.models import FunctionRecord
from app.dataflow_v2.store import DataflowStore


class DataflowV2FunctionResolutionTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.source_root = Path(self.td.name) / "src"
        self.run_root = Path(self.td.name) / "run"
        self.source_root.mkdir(parents=True, exist_ok=True)
        self.store = DataflowStore(self.run_root)

    def tearDown(self):
        self.store.close()
        self.td.cleanup()

    def test_namespace_qualified_callee_search_includes_definition_file(self):
        call_file = self.source_root / "socket_module.cpp"
        call_file.write_text(
            """
            namespace demo {
            void use() {
                ModuleTemplate::OnSharedManager();
            }
            }
            """.strip()
            + "\n",
            encoding="utf-8",
        )
        def_file = self.source_root / "module_template.cpp"
        def_file.write_text(
            """
            namespace OHOS::NetStack::ModuleTemplate {
            int OnSharedManager() {
                return 0;
            }
            }
            """.strip()
            + "\n",
            encoding="utf-8",
        )

        matches = find_func_in_source("ModuleTemplate::OnSharedManager", self.source_root)
        matched_files = {rel for rel, _ in matches}
        self.assertIn("module_template.cpp", matched_files)

    def test_qualified_lookup_falls_back_to_tail_name_after_index(self):
        func = FunctionRecord(
            file="module_template.cpp",
            name="OnSharedManager",
            signature="int OnSharedManager()",
            start_line=1,
            end_line=3,
            func_hash="hash-on-shared-manager",
        )
        self.store.upsert_function(func)
        resolved = self.store.find_function("ModuleTemplate::OnSharedManager")
        self.assertIsNotNone(resolved)
        self.assertEqual("module_template.cpp", resolved.file)
        self.assertEqual("OnSharedManager", resolved.name)

    def test_incremental_indexing_can_be_triggered_for_search_results(self):
        def_file = self.source_root / "module_template.cpp"
        def_file.write_text(
            """
            namespace OHOS::NetStack::ModuleTemplate {
            int OnSharedManager() {
                return 0;
            }
            }
            """.strip()
            + "\n",
            encoding="utf-8",
        )
        matches = find_func_in_source("ModuleTemplate::OnSharedManager", self.source_root)
        self.assertIn(("module_template.cpp", "OnSharedManager"), matches)
        for rel_file, _ in matches:
            ensure_file_indexed(str(self.source_root), rel_file, self.store)


if __name__ == "__main__":
    unittest.main(verbosity=2)
