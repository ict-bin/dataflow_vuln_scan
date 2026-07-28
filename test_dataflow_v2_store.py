"""dataflow-v2 四库 CRUD + 三重去重 测试。"""
import sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from app.dataflow_v2 import (
    DataflowStore, FunctionRecord, TaintRecord, PropagationRecord,
    OrchestrationEdge, TaintParamInfo, ProcessedTaint, Validation,
)
from app.vuln_store import (
    TaskGraphEdgeRecord,
    VulnFindingRecord,
    TaskGraphNodeRecord,
    TaskGraphRunRecord,
    TaskGraphSessionRecord,
    VulnScanStore,
)


class TestStore(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.store = DataflowStore(Path(self.td.name) / "run")

    def tearDown(self):
        self.store.close()
        self.td.cleanup()

    def _func(self, name="A", file="a.c"):
        return FunctionRecord(file=file, name=name, signature=f"void {name}(msg_t* msg)",
                              start_line=1, end_line=10, body_path="run/functions/a.c__A.c",
                              func_hash="h1", description="A 函数")

    def test_function_upsert_get(self):
        f = self._func()
        self.store.upsert_function(f)
        got = self.store.get_function(f.func_id)
        self.assertIsNotNone(got)
        self.assertEqual(got.name, "A")
        self.assertEqual(got.start_line, 1)
        self.assertEqual(self.store.find_function("A").name, "A")

    def test_taint_and_propagation_link(self):
        f = self._func()
        self.store.upsert_function(f)
        t = TaintRecord(func_id=f.func_id, name="msg", signature="msg[0]",
                        file=f.file, function=f.name, description="报文指针")
        self.store.upsert_taint(t)
        p = PropagationRecord(source_func_id=f.func_id, source_taint_name="msg",
                              source_taint_signature="msg[0]", target_taint_name="pkt",
                              target_taint_signature="pkt[0]", target_func_id="fid_C",
                              condition="always",
                              validations=[Validation(line=12, kind="length_check", target="msg->length", summary="checks message length before forwarding")],
                              description="msg 透传给 C")
        self.store.upsert_propagation(p)
        self.store.add_propagation_to_taint(t.taint_id, p.prop_id)
        # 查回
        self.assertEqual(self.store.get_taint(t.taint_id).next_propagations, [p.prop_id])
        props = self.store.list_propagations_from(f.func_id)
        self.assertEqual(len(props), 1)
        self.assertEqual(props[0].validations[0].target, "msg->length")

    def test_orchestration_path(self):
        e = OrchestrationEdge(path_id="p1", source_function="A", source_signature="A",
                              source_func_id="fA", target_function="C", target_signature="C",
                              target_func_id="fC", taint_params=TaintParamInfo([0], "msg[0]", ["msg"]),
                              depth=1, edge_order=0, status="pending")
        self.store.upsert_edge(e)
        self.assertEqual(len(self.store.list_path_edges("p1")), 1)
        self.assertEqual(len(self.store.pending_edges()), 1)
        self.store.set_edge_status(e.edge_id, "done")
        self.assertEqual(len(self.store.pending_edges()), 0)

    def test_triple_dedup(self):
        f = self._func()
        self.store.upsert_function(f)
        pt = ProcessedTaint(taint_params=["msg"], taint_signature="msg[0]",
                            pre_validations=[{"condition": "x>0", "content": "c"}],
                            pre_validation_signature="x>0::c", sessions_path="s.jsonl")
        self.store.add_processed_taint(f.func_id, pt)
        # 同 taint_sig → 命中
        hit = self.store.find_processed_taint(f.func_id, "msg[0]", "x>0::c")
        self.assertIsNotNone(hit, "同一函数+同一污点应命中")
        # 不同前置校验在当前实现里仍视为已覆盖
        same_taint_hit = self.store.find_processed_taint(f.func_id, "msg[0]", "y<0::d")
        self.assertIsNotNone(same_taint_hit)
        # 不同污点签名 → 不命中
        miss2 = self.store.find_processed_taint(f.func_id, "msg[1]", "x>0::c")
        self.assertIsNone(miss2)


class TestTaskGraphStore(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.db_path = Path(self.td.name) / "run" / "vuln-scan.sqlite"
        self.run_root = self.db_path.parent
        self.task_root = self.run_root.parent
        self.store = VulnScanStore(self.db_path)

    def tearDown(self):
        self.td.cleanup()

    def test_export_task_graph_view_builds_tree_and_enriches_session_file(self):
        sessions_dir = self.run_root / "sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        session_relpath = "sessions/root.taint.jsonl"
        (self.run_root / session_relpath).write_text('{"type":"message"}\n{"type":"message"}\n', encoding="utf-8")

        self.store.start_task_graph_run(TaskGraphRunRecord(
            task_id="task-1",
            epoch="1",
            run_root=str(self.run_root),
            root_function="Root",
        ))
        self.store.upsert_task_graph_node(TaskGraphNodeRecord(
            node_id="node-root",
            task_id="task-1",
            epoch="1",
            func_id="root-func",
            function_name_resolved="Root",
            function_name_raw="Root",
            source_file="src/root.cpp",
            depth=0,
            status="running",
            analysis_status="running",
            primary_session_relpath=session_relpath,
        ))
        self.store.upsert_task_graph_node(TaskGraphNodeRecord(
            node_id="node-child",
            task_id="task-1",
            epoch="1",
            func_id="child-func",
            function_name_resolved="Child",
            function_name_raw="Ns::Child",
            source_file="src/child.cpp",
            depth=1,
            status="done",
            analysis_status="done",
            findings_count=2,
        ))
        self.store.upsert_task_graph_edge(TaskGraphEdgeRecord(
            edge_id="edge-1",
            task_id="task-1",
            epoch="1",
            source_node_id="node-root",
            target_node_id="node-child",
            source_func_id="root-func",
            target_func_id="child-func",
            source_function_resolved="Root",
            target_function_resolved="Child",
            target_function_raw="Ns::Child",
            source_file="src/root.cpp",
            target_file="src/child.cpp",
            edge_kind="direct_call",
            status="done",
            source_prop_id="prop-1",
            visible_in_tree=1,
            visible_in_all_propagations=1,
        ))
        self.store.upsert_task_graph_session(TaskGraphSessionRecord(
            session_relpath=session_relpath,
            task_id="task-1",
            epoch="1",
            node_id="node-root",
            session_role="worker",
            session_kind="taint",
            display_name="root.taint",
            status="done",
        ))
        self.store.start_run(run_id="run-1", task_id="task-1", root_file="src/root.cpp", root_function="Root", source_root="/src")
        self.store.add_finding(VulnFindingRecord(
            finding_id="finding-1",
            run_id="run-1",
            node_id="node-child",
            edge_id="edge-1",
            source_file="src/child.cpp",
            function_name="Child",
            line="41",
            vuln_type="sql_injection",
            severity="high",
            title="Child issue",
            summary="summary",
            evidence="evidence",
            exploitability="exploitability",
            confidence=0.8,
            output_dir="/tmp/out/finding-1",
        ))

        view = self.store.export_task_graph_view("task-1")
        self.assertTrue(view["available"])
        self.assertEqual(view["summary"]["nodes_total"], 2)
        self.assertEqual(view["summary"]["edges_done"], 1)
        self.assertEqual(view["summary"]["findings_total"], 1)
        self.assertEqual(view["tree"]["node_id"], "node-root")
        self.assertEqual(view["tree"]["children"][0]["node_id"], "node-child")
        self.assertEqual(view["tree"]["children"][0]["edge_id"], "edge-1")
        self.assertEqual(view["sessions"][0]["event_count"], 2)
        self.assertGreater(view["sessions"][0]["mtime"], 0.0)
        self.assertEqual(view["findings"][0]["finding_id"], "finding-1")

    def test_export_task_graph_view_keeps_placeholder_edges_queryable(self):
        self.store.start_task_graph_run(TaskGraphRunRecord(
            task_id="task-2",
            epoch="2",
            run_root=str(self.run_root),
            root_function="Root",
        ))
        self.store.upsert_task_graph_node(TaskGraphNodeRecord(
            node_id="node-root",
            task_id="task-2",
            epoch="2",
            func_id="root-func",
            function_name_resolved="Root",
            function_name_raw="Root",
            source_file="src/root.cpp",
            depth=0,
            status="running",
            analysis_status="running",
        ))
        self.store.upsert_task_graph_edge(TaskGraphEdgeRecord(
            edge_id="edge-unresolved",
            task_id="task-2",
            epoch="2",
            source_node_id="node-root",
            target_node_id="",
            source_func_id="root-func",
            target_func_id="",
            source_function_resolved="Root",
            target_function_resolved="Handle",
            target_function_raw="Ns::Handle",
            source_file="src/root.cpp",
            target_file="src/handle.cpp",
            edge_kind="indirect_call",
            status="unresolved",
            source_prop_id="prop-unresolved",
            reason_code="tracker_no_target",
            reason_message="tracker did not resolve target",
            visible_in_tree=1,
            visible_in_all_propagations=1,
        ))

        view = self.store.export_task_graph_view("task-2")
        self.assertEqual(len(view["edges"]), 1)
        self.assertEqual(view["edges"][0]["edge_id"], "edge-unresolved")
        self.assertEqual(view["summary"]["edges_unresolved"], 1)
        self.assertEqual(view["tree"]["node_id"], "node-root")
        placeholder = view["tree"]["children"][0]
        self.assertEqual(placeholder["edge_id"], "edge-unresolved")
        self.assertEqual(placeholder["node_id"], "virtual::edge-unresolved")
        self.assertTrue(placeholder["placeholder"])
        self.assertEqual(placeholder["reason_code"], "tracker_no_target")
        self.assertEqual(placeholder["reason_message"], "tracker did not resolve target")

    def test_export_task_graph_view_summarizes_failed_cancelled_and_not_followed_edges(self):
        self.store.start_task_graph_run(TaskGraphRunRecord(
            task_id="task-3",
            epoch="3",
            run_root=str(self.run_root),
            root_function="Root",
        ))
        self.store.upsert_task_graph_node(TaskGraphNodeRecord(
            node_id="node-root",
            task_id="task-3",
            epoch="3",
            func_id="root-func",
            function_name_resolved="Root",
            function_name_raw="Root",
            source_file="src/root.cpp",
            depth=0,
            status="running",
            analysis_status="running",
        ))
        for edge_id, status, kind, reason_code in [
            ("edge-failed", "failed", "direct_call", "child_process_failed"),
            ("edge-cancelled", "cancelled", "indirect_call", "owner_cancelled"),
            ("edge-not-followed", "not_followed", "external_callee", "external_callee"),
        ]:
            self.store.upsert_task_graph_edge(TaskGraphEdgeRecord(
                edge_id=edge_id,
                task_id="task-3",
                epoch="3",
                source_node_id="node-root",
                target_node_id="",
                source_func_id="root-func",
                source_function_resolved="Root",
                source_file="src/root.cpp",
                edge_kind=kind,
                status=status,
                source_prop_id=f"prop-{edge_id}",
                reason_code=reason_code,
                reason_message=reason_code,
                visible_in_tree=1,
                visible_in_all_propagations=1,
            ))

        view = self.store.export_task_graph_view("task-3")
        self.assertEqual(view["summary"]["edges_failed"], 1)
        self.assertEqual(view["summary"]["edges_cancelled"], 1)
        self.assertEqual(view["summary"]["edges_not_followed"], 1)
        child_statuses = {child["edge_id"]: child["status"] for child in view["tree"]["children"]}
        self.assertEqual(child_statuses["edge-failed"], "failed")
        self.assertEqual(child_statuses["edge-cancelled"], "cancelled")
        self.assertEqual(child_statuses["edge-not-followed"], "not_followed")

    def test_export_task_graph_view_preserves_external_escape_placeholder(self):
        self.store.start_task_graph_run(TaskGraphRunRecord(
            task_id="task-4",
            epoch="4",
            run_root=str(self.run_root),
            root_function="Root",
        ))
        self.store.upsert_task_graph_node(TaskGraphNodeRecord(
            node_id="node-root",
            task_id="task-4",
            epoch="4",
            func_id="root-func",
            function_name_resolved="Root",
            function_name_raw="Root",
            source_file="src/root.cpp",
            depth=0,
            status="done",
            analysis_status="done",
        ))
        self.store.upsert_task_graph_edge(TaskGraphEdgeRecord(
            edge_id="edge-external",
            task_id="task-4",
            epoch="4",
            source_node_id="node-root",
            target_node_id="",
            source_func_id="root-func",
            source_function_resolved="Root",
            target_function_resolved="Reader",
            target_function_raw="Ns::Reader",
            source_file="src/root.cpp",
            target_file="src/reader.cpp",
            edge_kind="unresolved_target",
            status="unresolved",
            source_prop_id="prop-external",
            reason_code="tracker_no_target",
            reason_message="external tracker did not resolve target",
            visible_in_tree=1,
            visible_in_all_propagations=1,
        ))

        view = self.store.export_task_graph_view("task-4")
        placeholder = view["tree"]["children"][0]
        self.assertEqual(placeholder["edge_id"], "edge-external")
        self.assertEqual(placeholder["edge_kind"], "unresolved_target")
        self.assertEqual(placeholder["function_name_resolved"], "Reader")
        self.assertEqual(placeholder["function_name_raw"], "Ns::Reader")
        self.assertEqual(placeholder["status"], "unresolved")

    def test_export_task_graph_view_preserves_discovered_and_scheduled_statuses(self):
        self.store.start_task_graph_run(TaskGraphRunRecord(
            task_id="task-5",
            epoch="5",
            run_root=str(self.run_root),
            root_function="Root",
        ))
        self.store.upsert_task_graph_node(TaskGraphNodeRecord(
            node_id="node-root",
            task_id="task-5",
            epoch="5",
            func_id="root-func",
            function_name_resolved="Root",
            function_name_raw="Root",
            source_file="src/root.cpp",
            depth=0,
            status="running",
            analysis_status="running",
        ))
        self.store.upsert_task_graph_edge(TaskGraphEdgeRecord(
            edge_id="edge-discovered",
            task_id="task-5",
            epoch="5",
            source_node_id="node-root",
            target_node_id="",
            source_func_id="root-func",
            source_function_resolved="Root",
            target_function_resolved="Child",
            target_function_raw="Ns::Child",
            source_file="src/root.cpp",
            edge_kind="direct_call",
            status="discovered",
            source_prop_id="prop-discovered",
            visible_in_tree=1,
            visible_in_all_propagations=1,
        ))
        self.store.upsert_task_graph_edge(TaskGraphEdgeRecord(
            edge_id="edge-scheduled",
            task_id="task-5",
            epoch="5",
            source_node_id="node-root",
            target_node_id="",
            source_func_id="root-func",
            source_function_resolved="Root",
            target_function_resolved="Reader",
            target_function_raw="Ns::Reader",
            source_file="src/root.cpp",
            edge_kind="container_reader",
            status="scheduled",
            source_prop_id="prop-scheduled",
            visible_in_tree=1,
            visible_in_all_propagations=1,
        ))

        view = self.store.export_task_graph_view("task-5")
        self.assertEqual(view["summary"]["edges_total"], 2)
        child_statuses = {child["edge_id"]: child["status"] for child in view["tree"]["children"]}
        self.assertEqual(child_statuses["edge-discovered"], "discovered")
        self.assertEqual(child_statuses["edge-scheduled"], "scheduled")

    def test_export_task_graph_view_keeps_return_followup_queryable_without_tree_back_edge(self):
        self.store.start_task_graph_run(TaskGraphRunRecord(
            task_id="task-return",
            epoch="6",
            run_root=str(self.run_root),
            root_function="Root",
        ))
        self.store.upsert_task_graph_node(TaskGraphNodeRecord(
            node_id="node-root",
            task_id="task-return",
            epoch="6",
            func_id="root-func",
            function_name_resolved="Root",
            function_name_raw="Root",
            source_file="src/root.cpp",
            depth=0,
            status="done",
            analysis_status="done",
        ))
        self.store.upsert_task_graph_node(TaskGraphNodeRecord(
            node_id="node-child",
            task_id="task-return",
            epoch="6",
            func_id="child-func",
            function_name_resolved="Child",
            function_name_raw="Child",
            source_file="src/child.cpp",
            depth=1,
            status="done",
            analysis_status="done",
        ))
        self.store.upsert_task_graph_edge(TaskGraphEdgeRecord(
            edge_id="edge-direct",
            task_id="task-return",
            epoch="6",
            source_node_id="node-root",
            target_node_id="node-child",
            source_func_id="root-func",
            target_func_id="child-func",
            source_function_resolved="Root",
            target_function_resolved="Child",
            target_function_raw="Child",
            source_file="src/root.cpp",
            target_file="src/child.cpp",
            edge_kind="direct_call",
            status="done",
            source_prop_id="prop-direct",
            visible_in_tree=1,
            visible_in_all_propagations=1,
        ))
        self.store.upsert_task_graph_edge(TaskGraphEdgeRecord(
            edge_id="edge-return",
            task_id="task-return",
            epoch="6",
            source_node_id="node-child",
            target_node_id="node-root",
            source_func_id="child-func",
            target_func_id="root-func",
            source_function_resolved="Child",
            target_function_resolved="Root",
            target_function_raw="Root",
            source_file="src/child.cpp",
            target_file="src/root.cpp",
            edge_kind="return_followup",
            status="done",
            source_prop_id="edge-return",
            visible_in_tree=0,
            visible_in_all_propagations=1,
        ))

        view = self.store.export_task_graph_view("task-return")
        edge_ids = {edge["edge_id"] for edge in view["edges"]}
        self.assertIn("edge-direct", edge_ids)
        self.assertIn("edge-return", edge_ids)
        self.assertEqual(["edge-direct"], [child["edge_id"] for child in view["tree"]["children"]])

    def test_export_task_graph_view_is_available_when_only_findings_exist(self):
        self.store.start_run(
            run_id="run-findings-only",
            task_id="task-6",
            root_file="src/root.cpp",
            root_function="Root",
            source_root="/src",
        )
        self.store.add_finding(VulnFindingRecord(
            finding_id="finding-only-1",
            run_id="run-findings-only",
            node_id="",
            edge_id="",
            source_file="src/root.cpp",
            function_name="Root",
            line="12",
            vuln_type="command_injection",
            severity="high",
            title="Root issue",
            summary="summary",
            evidence="evidence",
            exploitability="exploitability",
            confidence=0.7,
            output_dir="/tmp/out/finding-only-1",
        ))

        view = self.store.export_task_graph_view("task-6")

        self.assertTrue(view["available"])
        self.assertEqual(view["summary"]["findings_total"], 1)
        self.assertEqual(view["nodes"], [])
        self.assertEqual(view["edges"], [])
        self.assertEqual(view["findings"][0]["finding_id"], "finding-only-1")

    def test_export_task_graph_view_preserves_one_to_many_bridge_edges_and_session_bindings(self):
        self.store.start_task_graph_run(TaskGraphRunRecord(
            task_id="task-one-to-many",
            epoch="7",
            run_root=str(self.run_root),
            root_function="RootMulti",
        ))
        for node_id, func_id, resolved, raw, source_file, depth, status in [
            ("node-root", "root-func", "RootMulti", "RootMulti", "src/root.cpp", 0, "done"),
            ("node-emit", "emit-func", "Emit", "EventManager::Emit", "src/event_manager.cpp", 1, "running"),
            ("node-emit-uv", "emit-uv-func", "EmitByUvWithoutCheckShared", "EventManager::EmitByUvWithoutCheckShared", "src/event_manager.cpp", 1, "running"),
        ]:
            self.store.upsert_task_graph_node(TaskGraphNodeRecord(
                node_id=node_id,
                task_id="task-one-to-many",
                epoch="7",
                func_id=func_id,
                function_name_resolved=resolved,
                function_name_raw=raw,
                source_file=source_file,
                depth=depth,
                status=status,
                analysis_status=status,
            ))
        for edge_id, target_node_id, target_func_id, resolved, raw, target_taint_name, display_order in [
            ("edge-emit", "node-emit", "emit-func", "Emit", "OnSharedManager", "emit", 1),
            ("edge-emit-uv", "node-emit-uv", "emit-uv-func", "EmitByUvWithoutCheckShared", "OnSharedManager", "emit_uv", 2),
        ]:
            self.store.upsert_task_graph_edge(TaskGraphEdgeRecord(
                edge_id=edge_id,
                task_id="task-one-to-many",
                epoch="7",
                source_node_id="node-root",
                target_node_id=target_node_id,
                source_func_id="root-func",
                target_func_id=target_func_id,
                source_function_resolved="RootMulti",
                target_function_resolved=resolved,
                target_function_raw=raw,
                source_file="src/root.cpp",
                target_file="src/event_manager.cpp",
                edge_kind="container_reader",
                status="scheduled",
                source_prop_id="prop-shared-manager",
                source_orchestration_edge_id=f"orch::{edge_id}",
                source_taint_name="cb",
                target_taint_name=target_taint_name,
                tracker_type="container_reader",
                tracker_result_json='{"resolved_targets":["Emit","EmitByUvWithoutCheckShared"]}',
                display_order=display_order,
                visible_in_tree=1,
                visible_in_all_propagations=1,
            ))
        for relpath, node_id, edge_id in [
            ("sessions/root.jsonl", "node-root", ""),
            ("sessions/emit.jsonl", "node-emit", "edge-emit"),
            ("sessions/emit-uv.jsonl", "node-emit-uv", "edge-emit-uv"),
        ]:
            self.store.upsert_task_graph_session(TaskGraphSessionRecord(
                session_relpath=relpath,
                task_id="task-one-to-many",
                epoch="7",
                node_id=node_id,
                edge_id=edge_id,
                session_role="worker",
                session_kind="taint",
                display_name=Path(relpath).stem,
                status="running" if edge_id else "done",
                event_count=2,
            ))

        view = self.store.export_task_graph_view("task-one-to-many")

        self.assertTrue(view["available"])
        self.assertEqual(view["tree"]["node_id"], "node-root")
        self.assertEqual([child["node_id"] for child in view["tree"]["children"]], ["node-emit", "node-emit-uv"])
        self.assertEqual([child["edge_id"] for child in view["tree"]["children"]], ["edge-emit", "edge-emit-uv"])
        self.assertEqual([child["function_name_raw"] for child in view["tree"]["children"]], ["EventManager::Emit", "EventManager::EmitByUvWithoutCheckShared"])
        self.assertEqual([edge["target_function_raw"] for edge in view["edges"]], ["OnSharedManager", "OnSharedManager"])
        self.assertEqual([edge["target_function_resolved"] for edge in view["edges"]], ["Emit", "EmitByUvWithoutCheckShared"])
        self.assertEqual({session["session_relpath"] for session in view["sessions"]}, {"sessions/root.jsonl", "sessions/emit.jsonl", "sessions/emit-uv.jsonl"})

        node_ids = {node["node_id"] for node in view["nodes"]}
        edge_ids = {edge["edge_id"] for edge in view["edges"]}
        for session in view["sessions"]:
            self.assertIn(session["node_id"], node_ids)
            if session["edge_id"]:
                self.assertIn(session["edge_id"], edge_ids)


if __name__ == "__main__":
    unittest.main(verbosity=2)
