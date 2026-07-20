"""dataflow-v2 真实限定名 callee E2E 回归。"""
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))

from app.dataflow_v2.function_extractor import find_func_in_source
from app.dataflow_v2.models import FunctionRecord, PropagationRecord, TaintParamInfo
from app.dataflow_v2.orchestrator import AnalysisCallbacks, AnalysisResult, DfsOrchestrator
from app.dataflow_v2.store import DataflowStore
from app.dataflow_v2.trackers import resolve_external
from app.dataflow_v2.trackers import resolve_indirect


class _RealCaseCallbacks(AnalysisCallbacks):
    def __init__(self, store: DataflowStore):
        self.store = store
        self.analyzed: list[str] = []
        self.mined: list[str] = []
        self.source_root = ""
        self.cfg = type("Cfg", (), {"source_root": ""})()
        self.on_event = lambda *args, **kwargs: None

    def analyze_function(self, store, func, taint_params, pre_validations, base_session, ctx):
        self.analyzed.append(func.name)
        if func.name == "SocketModuleExports::LocalSocket::On":
            return AnalysisResult(
                propagations=[
                    PropagationRecord(
                        source_func_id=func.func_id,
                        source_taint_name="msg",
                        source_taint_signature="msg_t*",
                        target_taint_name="mgr",
                        target_taint_signature="mgr_t*",
                        target_function="ModuleTemplate::OnSharedManager",
                        call_line=104,
                        condition="always",
                    )
                ],
                self_contained=False,
                description="root",
            )
        return AnalysisResult(self_contained=True, description=func.name)

    def mine_vulns(self, store, func, taint_params, ctx, base_session=""):
        self.mined.append(func.name)
        return 0


class _TrackerCfg:
    class _Workers:
        agents = [SimpleNamespace(model="test-model", tools=[])]
        default_tools = []

    workers = _Workers()
    agent_run_timeout_seconds = 30
    agent_timeout_retry_enabled = False
    agent_timeout_max_retries = 0
    pi_max_retries = 0
    pi_retry_delay = 0


class DataflowV2NamespaceCalleeE2ETests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.source_root = Path(self.td.name) / "source"
        self.source_root.mkdir(parents=True, exist_ok=True)
        self.store = DataflowStore(Path(self.td.name) / "run")
        self.root_file = self.source_root / "socket_module.cpp"
        self.def_file = self.source_root / "module_template.cpp"
        self.root_file.write_text(
            """
            namespace demo {
            void SocketModuleExports_LocalSocket_On() {
                ModuleTemplate::OnSharedManager();
            }
            }
            """.strip()
            + "\n",
            encoding="utf-8",
        )
        self.def_file.write_text(
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
        self.root_func = FunctionRecord(
            file="socket_module.cpp",
            name="SocketModuleExports::LocalSocket::On",
            signature="void SocketModuleExports::LocalSocket::On()",
            start_line=1,
            end_line=5,
            func_hash="root-hash",
        )
        self.store.upsert_function(self.root_func)

    def tearDown(self):
        self.store.close()
        self.td.cleanup()

    def test_real_case_search_finds_qualified_and_nested_qualified_targets(self):
        short_matches = find_func_in_source("ModuleTemplate::OnSharedManager", self.source_root)
        nested_matches = find_func_in_source("OHOS::NetStack::ModuleTemplate::OnSharedManager", self.source_root)
        self.assertIn(("module_template.cpp", "OnSharedManager"), short_matches)
        self.assertIn(("module_template.cpp", "OnSharedManager"), nested_matches)

    def test_real_case_search_returns_both_callsite_and_definition_candidates(self):
        matches = find_func_in_source("ModuleTemplate::OnSharedManager", self.source_root)
        matched_files = {rel for rel, _ in matches}
        self.assertIn("socket_module.cpp", matched_files)
        self.assertIn("module_template.cpp", matched_files)
        self.assertIn(("module_template.cpp", "OnSharedManager"), matches)
        self.assertIn(("socket_module.cpp", "ModuleTemplate::OnSharedManager"), matches)

    def test_orchestrator_follows_real_case_to_namespace_definition(self):
        cbs = _RealCaseCallbacks(self.store)
        cbs.source_root = str(self.source_root)
        cbs.cfg.source_root = str(self.source_root)
        orch = DfsOrchestrator(self.store, cbs, concurrent=False, max_depth=2)

        def _fake_ensure_file_indexed(source_root, rel_file, store):
            if rel_file == "module_template.cpp":
                store.upsert_function(
                    FunctionRecord(
                        file="module_template.cpp",
                        name="OnSharedManager",
                        signature="int OnSharedManager()",
                        start_line=1,
                        end_line=4,
                        func_hash="callee-hash",
                    )
                )
            return "indexed"

        with patch("app.dataflow_v2.function_extractor.ensure_file_indexed", side_effect=_fake_ensure_file_indexed):
            orch.run(self.root_func, TaintParamInfo([0], "msg_t*", ["msg"]))

        self.assertIn("SocketModuleExports::LocalSocket::On", cbs.analyzed)
        self.assertIn("OnSharedManager", cbs.analyzed)
        self.assertIn("OnSharedManager", cbs.mined)

    def test_orchestrator_prefers_definition_even_when_callsite_file_is_indexed_first(self):
        cbs = _RealCaseCallbacks(self.store)
        cbs.source_root = str(self.source_root)
        cbs.cfg.source_root = str(self.source_root)
        orch = DfsOrchestrator(self.store, cbs, concurrent=False, max_depth=2)
        indexed_files: list[str] = []

        def _fake_ensure_file_indexed(source_root, rel_file, store):
            indexed_files.append(rel_file)
            if rel_file == "module_template.cpp":
                store.upsert_function(
                    FunctionRecord(
                        file="module_template.cpp",
                        name="OnSharedManager",
                        signature="int OnSharedManager()",
                        start_line=1,
                        end_line=4,
                        func_hash="callee-hash",
                    )
                )
            return "indexed"

        with patch("app.dataflow_v2.function_extractor.ensure_file_indexed", side_effect=_fake_ensure_file_indexed):
            orch.run(self.root_func, TaintParamInfo([0], "msg_t*", ["msg"]))

        self.assertGreaterEqual(len(indexed_files), 2)
        self.assertIn("socket_module.cpp", indexed_files)
        self.assertIn("module_template.cpp", indexed_files)
        self.assertEqual(1, cbs.analyzed.count("OnSharedManager"))

    def test_store_lookup_falls_back_to_tail_name_for_preindexed_callee(self):
        self.store.upsert_function(
            FunctionRecord(
                file="module_template.cpp",
                name="OnSharedManager",
                signature="int OnSharedManager()",
                start_line=1,
                end_line=4,
                func_hash="callee-hash",
            )
        )
        resolved = self.store.find_function("ModuleTemplate::OnSharedManager")
        self.assertIsNotNone(resolved)
        self.assertEqual("OnSharedManager", resolved.name)
        self.assertEqual("module_template.cpp", resolved.file)

    def test_store_lookup_falls_back_from_deep_namespace_to_tail_name(self):
        self.store.upsert_function(
            FunctionRecord(
                file="module_template.cpp",
                name="OnSharedManager",
                signature="int OnSharedManager()",
                start_line=1,
                end_line=4,
                func_hash="callee-hash",
            )
        )
        resolved = self.store.find_function("OHOS::NetStack::ModuleTemplate::OnSharedManager")
        self.assertIsNotNone(resolved)
        self.assertEqual("OnSharedManager", resolved.name)

    def test_tracker_path_reuses_same_incremental_resolution_logic(self):
        self.store.upsert_function(
            FunctionRecord(
                file="reader.cpp",
                name="Reader",
                signature="void Reader()",
                start_line=1,
                end_line=2,
                func_hash="reader-hash",
            )
        )
        prop = PropagationRecord(
            source_func_id=self.root_func.func_id,
            source_taint_name="msg",
            source_taint_signature="msg_t*",
            target_taint_name="ModuleTemplate::OnSharedManager",
            target_taint_signature="msg_t*",
            escape_kind="container",
            carrier="shared_manager",
            escape_via="ModuleTemplate::OnSharedManager",
        )

        with patch("app.dataflow_v2.trackers.run_agent") as run_agent_mock, \
             patch("app.dataflow_v2.trackers.ensure_file_indexed") as ensure_mock:
            run_agent_mock.return_value = type(
                "AgentResult",
                (),
                {"output": '{"confirmed":[{"function":"ModuleTemplate::OnSharedManager","taint_param":"manager","reason":"real case"}]}'},
            )()

            def _index_side_effect(source_root, rel_file, store):
                if rel_file == "module_template.cpp":
                    store.upsert_function(
                        FunctionRecord(
                            file="module_template.cpp",
                            name="OnSharedManager",
                            signature="int OnSharedManager()",
                            start_line=1,
                            end_line=4,
                            func_hash="callee-hash",
                        )
                    )
                return "indexed"

            ensure_mock.side_effect = _index_side_effect
            confirmed = resolve_external(
                _TrackerCfg(),
                str(self.source_root),
                Path(self.td.name) / "sessions",
                self.store,
                self.root_func,
                prop,
                cancel_event=None,
                on_event=None,
                depth=0,
            )

        self.assertEqual(1, len(confirmed))
        self.assertEqual("OnSharedManager", confirmed[0][0].name)
        self.assertTrue(any(call.args[1] == "module_template.cpp" for call in ensure_mock.call_args_list))

    def test_external_tracker_reuses_parent_session_history(self):
        self.store.upsert_function(
            FunctionRecord(
                file="module_template.cpp",
                name="OnSharedManager",
                signature="int OnSharedManager()",
                start_line=1,
                end_line=4,
                func_hash="callee-hash",
            )
        )
        sessions_dir = Path(self.td.name) / "sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        base_session = sessions_dir / "parent.jsonl"
        base_session.write_text('{"role":"user","content":"parent-history"}\n', encoding="utf-8")
        prop = PropagationRecord(
            source_func_id=self.root_func.func_id,
            source_taint_name="msg",
            source_taint_signature="msg_t*",
            target_taint_name="ModuleTemplate::OnSharedManager",
            target_taint_signature="msg_t*",
            escape_kind="container",
            carrier="shared_manager",
            escape_via="ModuleTemplate::OnSharedManager",
        )
        captured: dict[str, str] = {}

        def _fake_external_run_agent(**kwargs):
            captured["session_text"] = Path(kwargs["session_file"]).read_text(encoding="utf-8")
            return type("AgentResult", (), {"output": '{"confirmed":[{"function":"OnSharedManager","taint_param":"manager","reason":"real case"}]}'})()

        with patch("app.dataflow_v2.trackers.run_agent", side_effect=_fake_external_run_agent):
            confirmed = resolve_external(
                _TrackerCfg(),
                str(self.source_root),
                sessions_dir,
                self.store,
                self.root_func,
                prop,
                cancel_event=None,
                on_event=None,
                depth=0,
                base_session=str(base_session),
            )

        self.assertEqual(1, len(confirmed))
        self.assertIn("parent-history", captured["session_text"])

    def test_indirect_tracker_reuses_parent_session_history(self):
        target = FunctionRecord(
            file="handler.cpp",
            name="OnSharedManager",
            signature="int OnSharedManager()",
            start_line=1,
            end_line=4,
            func_hash="handler-hash",
        )
        self.store.upsert_function(target)
        sessions_dir = Path(self.td.name) / "sessions-indirect"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        base_session = sessions_dir / "parent.jsonl"
        base_session.write_text('{"role":"user","content":"parent-history"}\n', encoding="utf-8")
        prop = PropagationRecord(
            source_func_id=self.root_func.func_id,
            source_taint_name="msg",
            source_taint_signature="msg_t*",
            target_taint_name="cb",
            target_taint_signature="msg_t*",
            target_function="ctxt->sax->OnSharedManager",
            call_line=88,
            is_indirect_call=True,
        )
        captured: dict[str, str] = {}

        def _fake_run_agent(**kwargs):
            captured["session_text"] = Path(kwargs["session_file"]).read_text(encoding="utf-8")
            return type("AgentResult", (), {"output": '{"handlers":[{"function":"OnSharedManager","file":"handler.cpp","reason":"match"}]}'})()

        with patch("app.dataflow_v2.trackers.run_agent", side_effect=_fake_run_agent):
            resolved = resolve_indirect(
                _TrackerCfg(),
                str(self.source_root),
                sessions_dir,
                self.store,
                self.root_func,
                prop,
                cancel_event=None,
                on_event=None,
                depth=0,
                base_session=str(base_session),
            )

        self.assertEqual(1, len(resolved))
        self.assertIn("parent-history", captured["session_text"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
