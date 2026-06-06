import tempfile
import unittest
from pathlib import Path

from app.models import AgentInstanceConfig, RoleConfig, TaskConfig, TaskResult, TaskStatus
from app.vuln_graph_service import load_vuln_scan_graph, summarize_graph
from app.vuln_graph_validator import validate_taint_graph
from app.cpp_resolver import _find_virtual_override_candidates_if_stub, _resolve_virtual_override_if_stub
from app.vuln_store import FollowupRecord, TaintEdgeRecord, TaintSourceRecord, VulnFindingRecord, VulnScanStore
from app.vuln_workflow import DataflowVulnWorkflow


class VulnGraphStoreTests(unittest.TestCase):
    def test_store_records_tree_and_findings(self):
        root = Path(tempfile.mkdtemp())
        store = VulnScanStore(root / "vuln-scan.sqlite")
        store.start_run("run1", "task1", "a.c", "foo", "/src", {"max_depth": 3})
        store.upsert_taint_node(TaintSourceRecord(
            node_id="n1", source_file="a.c", function_name="foo", taint_kind="param", symbol="buf"
        ))
        store.add_taint_edges([TaintEdgeRecord(
            edge_id="e1", run_id="run1", from_node_id="n1", to_node_id="n2",
            source_file="a.c", function_name="foo", from_symbol="buf", to_symbol="len",
            line="L10", operation="assignment", evidence="L10: len = buf->len"
        )])
        store.add_finding(VulnFindingRecord(
            finding_id="v1", run_id="run1", node_id="n1", source_file="a.c", function_name="foo", line="L10", vuln_type="overflow", title="overflow"
        ))
        graph = load_vuln_scan_graph(root)
        self.assertEqual({"runs": 1, "nodes": 1, "edges": 1, "followups": 0, "findings": 1}, summarize_graph(graph))
        self.assertEqual("buf", graph["taint_nodes"][0]["symbol"])
        self.assertEqual("foo", graph["vulnerability_findings"][0]["function_name"])

    def test_validator_requires_edge_evidence(self):
        warnings = validate_taint_graph({
            "function": "foo",
            "source_file": "a.c",
            "edges": [{"from": "a", "to": "b", "operation": "terminate"}],
            "followups": [],
        })
        self.assertTrue(any("missing line" in item for item in warnings))
        self.assertTrue(any("termination_reason" in item for item in warnings))

    def test_workflow_records_followups_and_manifest(self):
        root = Path(tempfile.mkdtemp())
        cfg = TaskConfig(
            task="x",
            cwd=str(root / "src"),
            output_dir=str(root),
            source_file="a.c",
            function_name="foo",
            workers=RoleConfig(agents=[AgentInstanceConfig(model="dummy")]),
        )
        workflow = DataflowVulnWorkflow(
            cfg=cfg,
            func_name="foo",
            src_file="a.c",
            line_hint="1",
            taint_params=["buf"],
            taint_ctx="",
            task_id="task1",
            out_dir=root / "run",
            dep=0,
            max_depth=3,
            graph_db_path=root / "vuln-scan.sqlite",
        )
        workflow.store.start_run(workflow.run_id, "task1", "a.c", "foo", str(root / "src"), {})
        node_ids = workflow._seed_nodes()
        result = TaskResult(
            task_id="task1",
            task="x",
            status=TaskStatus.PASSED,
            final_output="{}",
            upstream_entry_metadata={
                "taint_graph": {
                    "function": "foo",
                    "source_file": "a.c",
                    "edges": [
                        {"from": "buf", "to": "tmp", "line": "L2", "operation": "assignment", "evidence": "tmp = buf", "sanitizer_effect": "none"}
                    ],
                    "followups": [
                        {"file": "b.c", "function": "bar", "line": "L3", "tainted_params": ["tmp"], "reason": "tmp passed"}
                    ],
                    "termination": {"terminated": False},
                }
            },
        )
        workflow._record_edges_from_result(result, node_ids)
        graph = workflow.store.export_json()
        self.assertEqual(2, len(graph["taint_edges"]))
        self.assertEqual(1, len(graph["followups"]))
        self.assertEqual("bar", result.upstream_entry_metadata["followup_refs"][0]["callee_function"])
        self.assertTrue(result.upstream_entry_metadata["followup_refs"][0]["followup_id"])
        self.assertTrue((root / "artifact-manifest.json").exists())

    def test_store_updates_followup_status(self):
        root = Path(tempfile.mkdtemp())
        store = VulnScanStore(root / "vuln-scan.sqlite")
        store.start_run("run1", "task1", "a.c", "foo", "/src", {})
        store.upsert_taint_node(TaintSourceRecord(
            node_id="n1", source_file="a.c", function_name="foo", taint_kind="param", symbol="buf"
        ))
        store.add_taint_edges([TaintEdgeRecord(
            edge_id="e1", run_id="run1", from_node_id="n1", to_node_id="n2",
            source_file="a.c", function_name="foo", from_symbol="buf", to_symbol="arg",
            line="L10", operation="call_arg", evidence="bar(arg)"
        )])
        store.add_followups([FollowupRecord(
            followup_id="f1", edge_id="e1", parent_node_id="n1", callee_file="b.c",
            callee_function="bar", callee_line="L3", tainted_params_json='["arg"]', status="pending", depth=1,
        )])
        store.update_followup_status("f1", "analyzed")
        followups = store.list_followups()
        self.assertEqual("analyzed", followups[0].status)

    def test_resolver_redirects_trivial_base_stub_to_unique_override(self):
        root = Path(tempfile.mkdtemp())
        src = root / "src"
        src.mkdir()
        (src / "base.h").write_text(
            "class Sandbox { public: virtual int PrepareExec(const char *containerId, const char *execId, int *processSpec, const char *consoleFifos[]); };\n"
            "class SandboxerSandbox : public Sandbox { public: int PrepareExec(const char *containerId, const char *execId, int *processSpec, const char *consoleFifos[]) override; };\n",
            encoding="utf-8",
        )
        (src / "sandbox.cc").write_text(
            "#include \"base.h\"\n"
            "int Sandbox::PrepareExec(const char *containerId, const char *execId, int *processSpec, const char *consoleFifos[])\n"
            "{\n    return 0;\n}\n",
            encoding="utf-8",
        )
        mocks = src / "test" / "mocks"
        mocks.mkdir(parents=True)
        (mocks / "sandboxer_sandbox_mock.cc").write_text(
            "int SandboxerSandbox::PrepareExec(const char *containerId, const char *execId, int *processSpec, const char *consoleFifos[])\n"
            "{\n    return mock_exec(containerId);\n}\n",
            encoding="utf-8",
        )
        (src / "sandboxer_sandbox.cc").write_text(
            "#include \"base.h\"\n"
            "int SandboxerSandbox::PrepareExec(const char *containerId, const char *execId, int *processSpec, const char *consoleFifos[])\n"
            "{\n    return do_exec(containerId, execId, processSpec, consoleFifos);\n}\n",
            encoding="utf-8",
        )
        resolved = _resolve_virtual_override_if_stub(str(root), "Sandbox::PrepareExec", "src/sandbox.cc", "L2")
        self.assertEqual("SandboxerSandbox::PrepareExec", resolved[0])
        self.assertEqual("src/sandboxer_sandbox.cc", resolved[1])
        self.assertTrue(resolved[3])

    def test_resolver_returns_multiple_overrides_for_forking(self):
        root = Path(tempfile.mkdtemp())
        src = root / "src"
        src.mkdir()
        (src / "base.h").write_text(
            "namespace runtime { class Sandbox { public: virtual int Run(const char *id); }; }\n"
            "class A : public runtime::Sandbox { public: int Run(const char *id) override; };\n"
            "class B : public runtime::Sandbox { public: int Run(const char *id) override; };\n",
            encoding="utf-8",
        )
        (src / "sandbox.cc").write_text(
            "#include \"base.h\"\n"
            "int runtime::Sandbox::Run(const char *id)\n"
            "{\n    return 0;\n}\n",
            encoding="utf-8",
        )
        (src / "a.cc").write_text("int A::Run(const char *id)\n{\n return run_a(id);\n}\n", encoding="utf-8")
        (src / "b.cc").write_text("int B::Run(const char *id)\n{\n return run_b(id);\n}\n", encoding="utf-8")
        candidates = _find_virtual_override_candidates_if_stub(str(root), "runtime::Sandbox::Run", "src/sandbox.cc", "L2")
        self.assertEqual(["A::Run", "B::Run"], sorted(c[0] for c in candidates))
        # Compatibility wrapper must not arbitrarily choose among multiple overrides.
        resolved = _resolve_virtual_override_if_stub(str(root), "runtime::Sandbox::Run", "src/sandbox.cc", "L2")
        self.assertEqual("runtime::Sandbox::Run", resolved[0])
        self.assertEqual("", resolved[3])


if __name__ == "__main__":
    unittest.main()
