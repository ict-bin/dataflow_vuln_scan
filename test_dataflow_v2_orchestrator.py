"""dataflow-v2 编排器路径构造测试 (互斥分叉 + 顺序链)。"""
import json
import sys, tempfile, time, unittest
from threading import Event
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).parent))

from app.dataflow_v2 import (
    DataflowStore, FunctionRecord, PropagationRecord, ProcessedTaint, TaintParamInfo, TaintRecord, Validation,
)
from app.dataflow_v2.analysis import TaintAnalysisCallbacks
from app.dataflow_v2.orchestrator import DfsOrchestrator, AnalysisCallbacks, AnalysisResult, PathContext
from app.models import AgentInstanceConfig, RoleConfig, TaskConfig
from app.vuln_store import TaskGraphEdgeRecord, TaskGraphNodeRecord, TaskGraphRunRecord, VulnScanStore
from test_storage_fakes import TestGraphStoreFactory, make_dataflow_store

_GRAPH_STORES = TestGraphStoreFactory()


def _graph_store(db_path):
    return _GRAPH_STORES.create(db_path)


class _NoOpCbs(AnalysisCallbacks):
    """不调 LLM/clang 的空回调, 仅供路径构造测试。"""
    pass


def _func(store, name, file="a.c"):
    f = FunctionRecord(file=file, name=name, signature=f"void {name}(msg_t* m)",
                       start_line=1, end_line=10, func_hash=name)
    store.upsert_function(f)
    return f


def _prop(src_func, tgt_name, tgt_func_id, call_line, group="", arm=""):
    return PropagationRecord(
        source_func_id=src_func.func_id, source_taint_name="msg", source_taint_signature="msg_t*",
        target_taint_name="m", target_taint_signature="msg_t*",
        target_function=tgt_name, target_func_id=tgt_func_id, call_line=call_line,
        condition="always", branch_group_id=group, branch_arm_id=arm)


class TestPathBuilding(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.store = make_dataflow_store(Path(self.td.name) / "run")
        self.A = _func(self.store, "A"); self.C = _func(self.store, "C")
        self.D = _func(self.store, "D"); self.E = _func(self.store, "E"); self.F = _func(self.store, "F")
        self.orch = DfsOrchestrator(self.store, _NoOpCbs())

    def tearDown(self):
        self.store.close(); self.td.cleanup()

    def _paths(self, props):
        ctx = PathContext(path_id="p0")
        return self.orch._build_paths(props, self.A, ctx, 0, ["msg"])

    def test_sequential_chain(self):
        # C, F 顺序 (无分支) → 单链 [C, F]
        paths = self._paths([_prop(self.A, "C", self.C.func_id, 10),
                             _prop(self.A, "F", self.F.func_id, 30)])
        self.assertEqual(len(paths), 1)
        self.assertEqual([s.func.name for s in paths[0]], ["C", "F"])

    def test_mutex_fork(self):
        # C(顺序) → D(then)/E(else) 互斥 → F(顺序)
        # 期望: [C,D,F] 与 [C,E,F]
        props = [_prop(self.A, "C", self.C.func_id, 10),
                 _prop(self.A, "D", self.D.func_id, 20, group="G1", arm="then"),
                 _prop(self.A, "E", self.E.func_id, 25, group="G1", arm="else"),
                 _prop(self.A, "F", self.F.func_id, 30)]
        paths = self._paths(props)
        names = sorted([tuple(s.func.name for s in p) for p in paths])
        self.assertEqual(names, [("C", "D", "F"), ("C", "E", "F")], names)

    def test_independent_ifs_not_mutex(self):
        # 两个独立 if (不同 group) → 不互斥, 同链顺序
        props = [_prop(self.A, "C", self.C.func_id, 10, group="G1", arm="then"),
                 _prop(self.A, "D", self.D.func_id, 20, group="G2", arm="then")]
        paths = self._paths(props)
        self.assertEqual(len(paths), 1, "不同 group 不应分叉")
        self.assertEqual([s.func.name for s in paths[0]], ["C", "D"])

    def test_same_arm_not_mutex(self):
        # 同 group 同 arm (两调用都在 then) → 不互斥, 顺序
        props = [_prop(self.A, "C", self.C.func_id, 10, group="G1", arm="then"),
                 _prop(self.A, "D", self.D.func_id, 20, group="G1", arm="then")]
        paths = self._paths(props)
        self.assertEqual(len(paths), 1)
        self.assertEqual([s.func.name for s in paths[0]], ["C", "D"])

    def test_direct_call_fans_out_when_tail_lookup_has_multiple_matches(self):
        alt_c = _func(self.store, "C", file="c_alt.cpp")
        prop = PropagationRecord(
            source_func_id=self.A.func_id,
            source_taint_name="msg",
            source_taint_signature="msg_t*",
            target_taint_name="m",
            target_taint_signature="msg_t*",
            target_function="Ns::C",
            call_line=10,
            condition="always",
        )
        paths = self._paths([prop])
        self.assertEqual(len(paths), 2)
        resolved = {(path[0].func.name, path[0].func.file) for path in paths}
        self.assertEqual(
            {("C", "a.c"), ("C", "c_alt.cpp")},
            resolved,
        )

    def test_external_fork(self):
        # 外部变量传播 (is_external) + 两个跟入函数 → fork (stub 返回空, 故不分叉)
        # 这里直接验证: is_external 且 stub 无返回 → 不产生路径 (不崩)
        p = PropagationRecord(source_func_id=self.A.func_id, source_taint_name="msg",
                              source_taint_signature="msg_t*", target_taint_name="g_msg",
                              target_taint_signature="g_t", target_function="", call_line=20,
                              is_external=True)
        paths = self._paths([p])
        self.assertEqual(paths, [])

    def test_escape_container_forks_reader(self):
        # 容器逃逸 propagation (is_external=true, escape_kind=container, target_function 是插入调用)
        # → resolve_external_propagation 返回读者 → fork 子路径跟入读者 (list_add_tail 不当 callee 跟入)
        reader = _func(self.store, "Reader")
        class _ReaderCbs(AnalysisCallbacks):
            def resolve_external_propagation(self, store, func, prop, ctx, base_session=""):
                if prop.escape_kind == "container":
                    return [(reader, TaintParamInfo(positions=[0], signature="head", names=["head"]))]
                return []
        orch = DfsOrchestrator(self.store, _ReaderCbs())
        ctx = PathContext(path_id="p0")
        p = PropagationRecord(
            source_func_id=self.A.func_id, source_taint_name="msg", source_taint_signature="msg_t*",
            target_taint_name="params", target_taint_signature="params",
            target_function="list_add_tail", call_line=20,
            is_external=True, escape_kind="container", carrier="params",
            escape_via="list_add_tail")
        paths = orch._build_paths([p], self.A, ctx, 0, ["msg"])
        self.assertEqual(len(paths), 1, paths)
        self.assertEqual(paths[0][0].func.name, "Reader")
        self.assertEqual(paths[0][0].taint_params.names, ["head"])


class TestDedupAndFeedback(unittest.TestCase):
    def test_dedup_validations(self):
        from app.dataflow_v2.orchestrator import _dedup_validations
        vs = [
            Validation(line=10, kind="null_check", target="buf", summary="ensures buf is not null"),
            Validation(line=10, kind="null_check", target="buf", summary="ensures buf is not null"),
            Validation(line=20, kind="length_check", target="len", summary="checks len before copy"),
        ]
        out = _dedup_validations(vs)
        self.assertEqual(len(out), 2)


class TestResolvedTraceCallees(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.store = make_dataflow_store(Path(self.td.name) / "run")
        self.root = _func(self.store, "Root")
        self.callee = _func(self.store, "OnSharedManager", file="module_template.cpp")
        self.events: list[tuple[str, dict]] = []

        class _Cbs(AnalysisCallbacks):
            pass

        self.cbs = _Cbs()
        self.cbs.sessions_dir = Path(self.td.name) / "sessions"
        self.cbs.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.cbs.source_root = ""
        self.cbs.cfg = type("Cfg", (), {"source_root": ""})()
        self.cbs.analyze_function = self._analyze
        self.cbs.mine_vulns = lambda *args, **kwargs: 0
        self.cbs.on_event = self._on_event
        self.orch = DfsOrchestrator(self.store, self.cbs, concurrent=False, max_depth=2)

    def tearDown(self):
        self.store.close()
        self.td.cleanup()

    def _on_event(self, etype, **data):
        self.events.append((etype, data))

    def _analyze(self, store, func, taint_params, pre_validations, base_session, ctx):
        from app.dataflow_v2.orchestrator import AnalysisResult
        if func.name == "Root":
            return AnalysisResult(
                propagations=[
                    PropagationRecord(
                        source_func_id=func.func_id,
                        source_taint_name="msg",
                        source_taint_signature="msg_t*",
                        target_taint_name="mgr",
                        target_taint_signature="mgr_t*",
                        target_function="ModuleTemplate::OnSharedManager",
                        call_line=10,
                        condition="always",
                    )
                ],
                self_contained=False,
                description="root",
            )
        return AnalysisResult(self_contained=True, description=func.name)

    def test_resolved_trace_callees_only_emits_resolved_name(self):
        self.orch.run(self.root, TaintParamInfo([0], "msg_t*", ["msg"]))
        resolved_events = [
            data for etype, data in self.events
            if etype == "trace_callees" and data.get("resolved")
        ]
        self.assertEqual(1, len(resolved_events))
        self.assertEqual(["OnSharedManager"], resolved_events[0]["callees"])


class _MockCbs(AnalysisCallbacks):
    """mock: A→{C,D(then)/E(else),F}; 叶子自洽。记录分析/挖掘顺序。"""
    def __init__(self, store):
        self.store = store
        self.analyzed: list[str] = []
        self.mined: list[str] = []
        self._lock = __import__("threading").Lock()
        self.on_event = lambda *a, **k: None
    def _fid(self, name):
        return self.store.find_function(name).func_id
    def analyze_function(self, store, func, tp, pre_vals, base_session, ctx):
        from app.dataflow_v2.orchestrator import AnalysisResult
        with self._lock: self.analyzed.append(func.name)
        time.sleep(0.05)  # 暴露并发
        if func.name == "A":
            from app.dataflow_v2.models import PropagationRecord
            props = [
                PropagationRecord(source_func_id=func.func_id, source_taint_name="msg",
                    source_taint_signature="m", target_taint_name="m", target_taint_signature="m",
                    target_function=t, target_func_id=self._fid(t), call_line=ln,
                    branch_group_id=g, branch_arm_id=arm)
                for (t, ln, g, arm) in [("C",10,"",""),("D",20,"G","then"),("E",25,"G","else"),("F",30,"","")]
            ]
            return AnalysisResult(propagations=props, self_contained=False, description="A")
        return AnalysisResult(self_contained=True, description=func.name)  # 叶子自洽
    def resolve_external_propagation(self, store, func, taint, ctx, base_session=""):
        return []
    def mine_vulns(self, store, func, tp, ctx, base_session=""):
        with self._lock: self.mined.append(func.name)
        return 0


class TestConcurrentDfs(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.store = make_dataflow_store(Path(self.td.name) / "run")
        for n in ["A","C","D","E","F"]:
            _func(self.store, n)
        self.cbs = _MockCbs(self.store)
    def tearDown(self):
        self.store.close(); self.td.cleanup()
    def _run(self, concurrent):
        from app.dataflow_v2.orchestrator import DfsOrchestrator
        orch = DfsOrchestrator(self.store, self.cbs, concurrent=concurrent, max_concurrent_llm=4)
        orch.run(self.store.find_function("A"), TaintParamInfo([0], "m", ["msg"]))
    def test_all_functions_analyzed(self):
        self._run(True)
        self.assertEqual(set(self.cbs.analyzed), {"A","C","D","E","F"})
    def test_leaves_mined_immediately_root_postorder(self):
        self._run(True)
        # mining 后台化: 所有函数都被 mine, 顺序非确定 (后台线程并发完成)
        expected = {"A", "C", "D", "E", "F"}
        actual = set(self.cbs.mined)
        self.assertEqual(actual, expected, f"mined={self.cbs.mined}")
    def test_concurrent_faster_than_sequential(self):
        import time as _t
        t0 = _t.time(); self._run(False); seq = _t.time()-t0
        self.cbs.analyzed.clear(); self.cbs.mined.clear()
        t0 = _t.time(); self._run(True); par = _t.time()-t0
        # 并发应不慢于顺序 (5 个 analyze × 0.05s; 并发路径折叠)
        self.assertLessEqual(par, seq + 0.1, f"par={par} seq={seq}")


class TestFunctionLevelDedup(unittest.TestCase):
    def test_same_function_reached_by_different_taints_is_analyzed_once(self):
        with tempfile.TemporaryDirectory() as td:
            store = make_dataflow_store(Path(td) / "run")
            root = _func(store, "Root")
            mid = _func(store, "Mid")
            leaf = _func(store, "Leaf")
            analyzed: list[tuple[str, str]] = []

            class _Cbs(AnalysisCallbacks):
                def __init__(self):
                    self.on_event = lambda *args, **kwargs: None

                def analyze_function(self, store, func, taint_params, pre_validations, base_session, ctx):
                    analyzed.append((func.name, taint_params.signature))
                    if func.func_id == root.func_id:
                        return AnalysisResult(
                            propagations=[
                                PropagationRecord(
                                    source_func_id=func.func_id,
                                    source_taint_name="root_t",
                                    source_taint_signature="root_t",
                                    target_taint_name="mid_t",
                                    target_taint_signature="mid_t",
                                    target_function=mid.name,
                                    target_func_id=mid.func_id,
                                    call_line=10,
                                ),
                                PropagationRecord(
                                    source_func_id=func.func_id,
                                    source_taint_name="root_t",
                                    source_taint_signature="root_t",
                                    target_taint_name="direct_leaf_t",
                                    target_taint_signature="direct_leaf_t",
                                    target_function=leaf.name,
                                    target_func_id=leaf.func_id,
                                    call_line=20,
                                ),
                            ],
                            self_contained=False,
                            description="Root",
                        )
                    if func.func_id == mid.func_id:
                        return AnalysisResult(
                            propagations=[
                                PropagationRecord(
                                    source_func_id=func.func_id,
                                    source_taint_name="mid_t",
                                    source_taint_signature="mid_t",
                                    target_taint_name="via_mid_leaf_t",
                                    target_taint_signature="via_mid_leaf_t",
                                    target_function=leaf.name,
                                    target_func_id=leaf.func_id,
                                    call_line=30,
                                )
                            ],
                            self_contained=False,
                            description="Mid",
                        )
                    return AnalysisResult(self_contained=True, description=func.name)

                def mine_vulns(self, store, func, taint_params, ctx, base_session=""):
                    return 0

            orch = DfsOrchestrator(store, _Cbs(), concurrent=False, max_depth=3)
            orch.run(root, TaintParamInfo([0], "root_t", ["root_t"]))

            self.assertEqual(
                [
                    ("Root", "root_t"),
                    ("Mid", "mid_t"),
                    ("Leaf", "via_mid_leaf_t"),
                    ("Leaf", "direct_leaf_t"),
                ],
                analyzed,
            )
            self.assertIsNotNone(store.find_processed_taint(leaf.func_id, "direct_leaf_t"))
            store.close()


class TestReturnFollowupDisabled(unittest.TestCase):
    def test_root_return_taint_no_longer_triggers_caller_followup(self):
        with tempfile.TemporaryDirectory() as td:
            store = make_dataflow_store(Path(td) / "run")
            root = _func(store, "Root", file="root.c")
            caller = _func(store, "Caller", file="caller.c")
            analyzed: list[tuple[str, int]] = []

            class _Cbs(AnalysisCallbacks):
                def __init__(self):
                    self.sessions_dir = Path(td) / "sessions"
                    self.sessions_dir.mkdir(parents=True, exist_ok=True)
                    self.source_root = td
                    self.on_event = lambda *args, **kwargs: None

                def analyze_function(self, store, func, taint_params, pre_validations, base_session, ctx):
                    analyzed.append((func.name, ctx.depth))
                    if func.name == "Root":
                        return AnalysisResult(
                            self_contained=True,
                            description="Root",
                            return_taints=[
                                TaintRecord(
                                    func_id=func.func_id,
                                    name="ret_msg",
                                    signature="ret_msg",
                                    file=func.file,
                                    function=func.name,
                                )
                            ],
                        )
                    return AnalysisResult(self_contained=True, description=func.name)

                def mine_vulns(self, store, func, taint_params, ctx, base_session=""):
                    return 0

            orch = DfsOrchestrator(store, _Cbs(), concurrent=False, max_depth=2)
            with patch(
                "app.dataflow_v2.function_extractor.read_function_body",
                side_effect=lambda source_root, f, max_lines=4000: "Root(msg);" if f.func_id == caller.func_id else "",
            ):
                orch.run(root, TaintParamInfo([0], "msg_t*", ["msg"]))

            self.assertEqual([("Root", 0)], analyzed)
            store.close()

    def test_child_return_taint_no_longer_creates_return_followup_edge(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "run"
            graph_store = _graph_store(run_dir / "vuln-scan.sqlite")
            store = make_dataflow_store(run_dir / "dataflow-v2")
            root = _func(store, "Root", file="root.c")
            child = _func(store, "Child", file="child.c")

            graph_store.start_task_graph_run(TaskGraphRunRecord(
                task_id="task-return-disabled",
                epoch="run",
                run_root=str(run_dir),
                root_function="Root",
            ))
            for func, depth in ((root, 0), (child, 1)):
                graph_store.upsert_task_graph_node(TaskGraphNodeRecord(
                    node_id=f"node::{func.func_id}",
                    task_id="task-return-disabled",
                    epoch="run",
                    func_id=func.func_id,
                    function_name_resolved=func.name,
                    function_name_raw=func.name,
                    source_file=func.file,
                    depth=depth,
                    status="running",
                    analysis_status="running",
                ))

            class _Cbs(AnalysisCallbacks):
                def __init__(self):
                    self.graph_store = graph_store
                    self.task_id = "task-return-disabled"
                    self.graph_epoch = "run"
                    self.graph_node_id = lambda func: f"node::{func.func_id}"
                    self.cancel_event = None
                    self.sessions_dir = run_dir / "sessions"
                    self.sessions_dir.mkdir(parents=True, exist_ok=True)
                    self.source_root = td
                    self.on_event = lambda *args, **kwargs: None

                def analyze_function(self, store, func, taint_params, pre_validations, base_session, ctx):
                    if func.name == "Root":
                        return AnalysisResult(
                            propagations=[
                                PropagationRecord(
                                    source_func_id=func.func_id,
                                    source_taint_name="msg",
                                    source_taint_signature="msg_t*",
                                    target_taint_name="child_msg",
                                    target_taint_signature="msg_t*",
                                    target_function="Child",
                                    target_func_id=child.func_id,
                                    call_line=12,
                                )
                            ],
                            self_contained=False,
                            description="Root",
                        )
                    return AnalysisResult(
                        self_contained=True,
                        description="Child",
                        return_taints=[
                            TaintRecord(
                                func_id=func.func_id,
                                name="ret_msg",
                                signature="ret_msg",
                                file=func.file,
                                function=func.name,
                            )
                        ],
                    )

                def mine_vulns(self, store, func, taint_params, ctx, base_session=""):
                    return 0

            orch = DfsOrchestrator(store, _Cbs(), concurrent=False, max_depth=2)
            orch.run(root, TaintParamInfo([0], "msg_t*", ["msg"]))

            view = graph_store.export_task_graph_view("task-return-disabled")
            return_edges = [edge for edge in view["edges"] if edge["edge_kind"] == "return_followup"]
            self.assertEqual([], return_edges)
            store.close()


class TestGraphUnresolvedTargetKind(unittest.TestCase):
    def test_external_tracker_miss_rewrites_edge_kind_to_unresolved_target(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "run"
            graph_store = _graph_store(run_dir / "vuln-scan.sqlite")
            store = make_dataflow_store(run_dir / "dataflow-v2")
            root = _func(store, "Root", file="root.c")

            class _Cbs(AnalysisCallbacks):
                def __init__(self):
                    self.graph_store = graph_store
                    self.task_id = "task-unresolved-external"
                    self.graph_epoch = "run"
                    self.graph_node_id = lambda func: f"node::{func.func_id}"

                def resolve_external_propagation(self, store, func, prop, ctx, base_session=""):
                    return []

            graph_store.start_task_graph_run(TaskGraphRunRecord(
                task_id="task-unresolved-external",
                epoch="run",
                run_root=str(run_dir),
                root_function="Root",
            ))
            graph_store.upsert_task_graph_node(TaskGraphNodeRecord(
                node_id=f"node::{root.func_id}",
                task_id="task-unresolved-external",
                epoch="run",
                func_id=root.func_id,
                function_name_resolved=root.name,
                function_name_raw=root.name,
                source_file=root.file,
                depth=0,
                status="running",
                analysis_status="running",
            ))

            orch = DfsOrchestrator(store, _Cbs(), concurrent=False, max_depth=2)
            prop = PropagationRecord(
                source_func_id=root.func_id,
                source_taint_name="msg",
                source_taint_signature="msg_t*",
                target_taint_name="reader",
                target_taint_signature="reader_t*",
                target_function="Reader",
                call_line=10,
                is_external=True,
            )
            orch._record_propagation_edge(root, prop, 0)
            paths = orch._build_paths([prop], root, PathContext("p0"), 0, ["msg"])

            self.assertEqual([], paths)
            view = graph_store.export_task_graph_view("task-unresolved-external")
            edge = view["edges"][0]
            self.assertEqual("unresolved_target", edge["edge_kind"])
            self.assertEqual("unresolved", edge["status"])
            self.assertEqual("tracker_no_target", edge["reason_code"])
            self.assertEqual("external_escape", edge["tracker_type"])

    def test_direct_resolution_miss_rewrites_edge_kind_to_unresolved_target(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "run"
            graph_store = _graph_store(run_dir / "vuln-scan.sqlite")
            store = make_dataflow_store(run_dir / "dataflow-v2")
            root = _func(store, "Root", file="root.c")

            class _Cbs(AnalysisCallbacks):
                def __init__(self):
                    self.graph_store = graph_store
                    self.task_id = "task-unresolved-direct"
                    self.graph_epoch = "run"
                    self.graph_node_id = lambda func: f"node::{func.func_id}"

            graph_store.start_task_graph_run(TaskGraphRunRecord(
                task_id="task-unresolved-direct",
                epoch="run",
                run_root=str(run_dir),
                root_function="Root",
            ))
            graph_store.upsert_task_graph_node(TaskGraphNodeRecord(
                node_id=f"node::{root.func_id}",
                task_id="task-unresolved-direct",
                epoch="run",
                func_id=root.func_id,
                function_name_resolved=root.name,
                function_name_raw=root.name,
                source_file=root.file,
                depth=0,
                status="running",
                analysis_status="running",
            ))

            orch = DfsOrchestrator(store, _Cbs(), concurrent=False, max_depth=2)
            prop = PropagationRecord(
                source_func_id=root.func_id,
                source_taint_name="msg",
                source_taint_signature="msg_t*",
                target_taint_name="child_msg",
                target_taint_signature="child_msg_t*",
                target_function="Missing::Child",
                call_line=11,
            )
            orch._record_propagation_edge(root, prop, 0)
            paths = orch._build_paths([prop], root, PathContext("p0"), 0, ["msg"])

            self.assertEqual([], paths)
            view = graph_store.export_task_graph_view("task-unresolved-direct")
            edge = view["edges"][0]
            self.assertEqual("unresolved_target", edge["edge_kind"])
            self.assertEqual("unresolved", edge["status"])
            self.assertEqual("callee_not_resolved", edge["reason_code"])
            self.assertEqual("orchestrator", edge["reason_source"])


class TestGraphBridgeVisibility(unittest.TestCase):
    def test_bridge_edge_keeps_original_propagation_visible_in_all_propagations(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "run"
            graph_store = _graph_store(run_dir / "vuln-scan.sqlite")
            store = make_dataflow_store(run_dir / "dataflow-v2")
            root = _func(store, "Root", file="root.c")
            reader = _func(store, "Reader", file="reader.c")

            class _Cbs(AnalysisCallbacks):
                def __init__(self):
                    self.graph_store = graph_store
                    self.task_id = "task-bridge-visibility"
                    self.graph_epoch = "run"
                    self.graph_node_id = lambda func: f"node::{func.func_id}"

            graph_store.start_task_graph_run(TaskGraphRunRecord(
                task_id="task-bridge-visibility",
                epoch="run",
                run_root=str(run_dir),
                root_function="Root",
            ))
            for func, depth in ((root, 0), (reader, 1)):
                graph_store.upsert_task_graph_node(TaskGraphNodeRecord(
                    node_id=f"node::{func.func_id}",
                    task_id="task-bridge-visibility",
                    epoch="run",
                    func_id=func.func_id,
                    function_name_resolved=func.name,
                    function_name_raw=func.name,
                    source_file=func.file,
                    depth=depth,
                    status="running",
                    analysis_status="running",
                ))

            orch = DfsOrchestrator(store, _Cbs(), concurrent=False, max_depth=2)
            prop = PropagationRecord(
                source_func_id=root.func_id,
                source_taint_name="msg",
                source_taint_signature="msg_t*",
                target_taint_name="reader",
                target_taint_signature="reader_t*",
                target_function="Ns::Reader",
                target_func_id="",
                call_line=18,
                is_external=True,
            )
            orch._record_propagation_edge(root, prop, 0)
            bridge_edge_id = orch._graph_bridge_edge_id(
                "container_reader",
                "p0",
                prop.call_line,
                reader.func_id,
                prop.prop_id,
            )
            orch._record_bridge_edge(
                root,
                prop,
                reader,
                PathContext("p0"),
                0,
                edge_kind="container_reader",
                tracker_type="external_escape",
                bridge_edge_id=bridge_edge_id,
                tracker_result={"resolved_targets": [reader.name]},
            )

            view = graph_store.export_task_graph_view("task-bridge-visibility")
            edge_by_id = {edge["edge_id"]: edge for edge in view["edges"]}
            self.assertEqual(1, int(edge_by_id[prop.prop_id]["visible_in_all_propagations"]))
            self.assertEqual(0, int(edge_by_id[prop.prop_id]["visible_in_tree"]))
            self.assertEqual("external_escape", edge_by_id[prop.prop_id]["edge_kind"])
            self.assertEqual("container_reader", edge_by_id[bridge_edge_id]["edge_kind"])
            self.assertEqual(1, int(edge_by_id[bridge_edge_id]["visible_in_all_propagations"]))


class TestTrackerSessionPropagation(unittest.TestCase):
    def test_build_paths_passes_chain_session_to_external_tracker(self):
        with tempfile.TemporaryDirectory() as td:
            store = make_dataflow_store(Path(td) / "run")
            root = _func(store, "Root", file="root.c")
            reader = _func(store, "Reader", file="reader.c")
            seen: dict[str, str] = {}

            class _Cbs(AnalysisCallbacks):
                def resolve_external_propagation(self, store, func, prop, ctx, base_session=""):
                    seen["base_session"] = base_session
                    return [(reader, TaintParamInfo([0], "head", ["head"]))]

            orch = DfsOrchestrator(store, _Cbs(), concurrent=False, max_depth=2)
            prop = PropagationRecord(
                source_func_id=root.func_id,
                source_taint_name="msg",
                source_taint_signature="msg_t*",
                target_taint_name="reader",
                target_taint_signature="reader_t*",
                target_function="Reader",
                call_line=10,
                is_external=True,
                escape_kind="container",
            )
            paths = orch._build_paths([prop], root, PathContext("p0"), 0, ["msg"], "/tmp/chain-session.jsonl")

            self.assertEqual(1, len(paths))
            self.assertEqual("/tmp/chain-session.jsonl", seen["base_session"])
            store.close()


class TestBaseSessionIndexing(unittest.TestCase):
    def test_register_created_base_session_writes_runtime_index(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "run"
            sessions_dir = run_dir / "sessions"
            sessions_dir.mkdir(parents=True, exist_ok=True)
            store = make_dataflow_store(run_dir / "dataflow-v2")
            chain_session = sessions_dir / "d00-Root-taint-msg-00.jsonl"
            chain_session.write_text('{"type":"session","timestamp":"2026-07-27T00:00:00Z"}\n', encoding="utf-8")

            class _Cbs(AnalysisCallbacks):
                def __init__(self):
                    self.task_id = "task-return-followup-base-index"
                    self.graph_epoch = "run"
                    self.cancel_event = None
                    self.sessions_dir = sessions_dir
                    self.session_lineage_run_root = run_dir
                    self.source_root = td
                    self.on_event = lambda *args, **kwargs: None

            orch = DfsOrchestrator(store, _Cbs(), concurrent=False, max_depth=2)
            orch._register_created_base_session(
                session_path=chain_session,
                parent_session_path=sessions_dir / "parent.jsonl",
                relation_kind="fork",
                session_kind="taint",
            )

            payload = json.loads((run_dir / "session-index.json").read_text(encoding="utf-8"))
            relpaths = {str(item.get("session_relpath")) for item in payload.get("items", []) if isinstance(item, dict)}
            self.assertIn("sessions/d00-Root-taint-msg-00.jsonl", relpaths)
            child = next(item for item in payload["items"] if item.get("session_relpath") == "sessions/d00-Root-taint-msg-00.jsonl")
            self.assertEqual("sessions/parent.jsonl", child.get("parent_session_relpath"))
            self.assertEqual("fork", child.get("relation_kind"))
            store.close()


class TestGraphExecutionLifecycle(unittest.TestCase):
    def test_external_callee_propagation_stays_not_followed_in_authoritative_graph(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "run"
            graph_store = _graph_store(run_dir / "vuln-scan.sqlite")
            store = make_dataflow_store(run_dir / "dataflow-v2")
            root = _func(store, "Root", file="root.c")

            class _ExternalCalleeCbs(AnalysisCallbacks):
                def __init__(self):
                    self.graph_store = graph_store
                    self.task_id = "task-external-callee"
                    self.graph_epoch = "run"
                    self.graph_node_id = lambda func: f"node::{func.func_id}"
                    self.cancel_event = None
                    self.sessions_dir = run_dir / "sessions"
                    self.sessions_dir.mkdir(parents=True, exist_ok=True)
                    self.source_root = td
                    self.on_event = lambda *args, **kwargs: None

                def analyze_function(self, store, func, taint_params, pre_validations, base_session, ctx):
                    self.graph_store.upsert_task_graph_node(TaskGraphNodeRecord(
                        node_id=self.graph_node_id(func),
                        task_id=self.task_id,
                        epoch=self.graph_epoch,
                        func_id=func.func_id,
                        function_name_resolved=func.name,
                        function_name_raw=func.name,
                        source_file=func.file,
                        depth=max(0, getattr(ctx, "depth", 0)),
                        status="running",
                        analysis_status="running",
                    ))
                    return AnalysisResult(
                        propagations=[
                            PropagationRecord(
                                source_func_id=func.func_id,
                                source_taint_name="msg",
                                source_taint_signature="msg_t*",
                                target_taint_name="cb",
                                target_taint_signature="cb_t*",
                                target_function="ThirdParty::Callback",
                                target_func_id="",
                                target_file="third_party/callback.h",
                                call_line=21,
                                is_external_callee=True,
                            )
                        ],
                        self_contained=False,
                        description="Root",
                    )

                def mine_vulns(self, store, func, taint_params, ctx, base_session=""):
                    return 0

            orch = DfsOrchestrator(store, _ExternalCalleeCbs(), concurrent=False, max_depth=2)
            orch.run(root, TaintParamInfo([0], "msg_t*", ["msg"]))

            view = graph_store.export_task_graph_view("task-external-callee")
            self.assertEqual(1, len(view["nodes"]))
            self.assertEqual(1, len(view["edges"]))
            edge = view["edges"][0]
            self.assertEqual("external_callee", edge["edge_kind"])
            self.assertEqual("not_followed", edge["status"])
            self.assertEqual("external_callee", edge["reason_code"])
            self.assertEqual("analysis", edge["reason_source"])
            self.assertEqual("ThirdParty::Callback", edge["target_function_raw"])
            self.assertEqual("ThirdParty::Callback", edge["target_function_resolved"])
            self.assertEqual(1, len(view["tree"]["children"]))
            placeholder = view["tree"]["children"][0]
            self.assertEqual("external_callee", placeholder["edge_kind"])
            self.assertEqual("not_followed", placeholder["status"])
            self.assertTrue(placeholder["placeholder"])
            self.assertEqual("ThirdParty::Callback", placeholder["function_name_resolved"])

    def test_bridge_edge_lifecycle_reaches_done_via_real_external_tracker_path(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "run"
            graph_store = _graph_store(run_dir / "vuln-scan.sqlite")
            store = make_dataflow_store(run_dir / "dataflow-v2")
            root = _func(store, "Root", file="root.c")
            reader = _func(store, "Reader", file="reader.c")

            class _BridgeLifecycleCbs(AnalysisCallbacks):
                def __init__(self):
                    self.graph_store = graph_store
                    self.task_id = "task-bridge-lifecycle"
                    self.graph_epoch = "run"
                    self.graph_node_id = lambda func: f"node::{func.func_id}"
                    self.cancel_event = None
                    self.sessions_dir = run_dir / "sessions"
                    self.sessions_dir.mkdir(parents=True, exist_ok=True)
                    self.source_root = td
                    self.on_event = lambda *args, **kwargs: None

                def analyze_function(self, store, func, taint_params, pre_validations, base_session, ctx):
                    self.graph_store.upsert_task_graph_node(TaskGraphNodeRecord(
                        node_id=self.graph_node_id(func),
                        task_id=self.task_id,
                        epoch=self.graph_epoch,
                        func_id=func.func_id,
                        function_name_resolved=func.name,
                        function_name_raw=func.name,
                        source_file=func.file,
                        depth=max(0, getattr(ctx, "depth", 0)),
                        status="running",
                        analysis_status="running",
                    ))
                    if func.func_id == root.func_id:
                        return AnalysisResult(
                            propagations=[
                                PropagationRecord(
                                    source_func_id=func.func_id,
                                    source_taint_name="msg",
                                    source_taint_signature="msg_t*",
                                    target_taint_name="reader",
                                    target_taint_signature="reader_t*",
                                    target_function="Ns::Reader",
                                    target_func_id="",
                                    call_line=18,
                                    is_external=True,
                                    escape_kind="container",
                                    carrier="callbacks",
                                    escape_via="list_add_tail",
                                )
                            ],
                            self_contained=False,
                            description="Root",
                        )
                    return AnalysisResult(
                        self_contained=True,
                        description="Reader",
                    )

                def resolve_external_propagation(self, store, func, prop, ctx, base_session=""):
                    return [(reader, TaintParamInfo([0], "head", ["head"]))]

                def mine_vulns(self, store, func, taint_params, ctx, base_session=""):
                    return 0

            orch = DfsOrchestrator(store, _BridgeLifecycleCbs(), concurrent=False, max_depth=2)
            orch.run(root, TaintParamInfo([0], "msg_t*", ["msg"]))

            view = graph_store.export_task_graph_view("task-bridge-lifecycle")
            edge_by_id = {edge["edge_id"]: edge for edge in view["edges"]}
            self.assertEqual(2, len(edge_by_id))

            original_edge = next(edge for edge in edge_by_id.values() if edge["edge_kind"] == "external_escape")
            bridge_edge = next(edge for edge in edge_by_id.values() if edge["edge_kind"] == "container_reader")
            reader_node = next(node for node in view["nodes"] if node["node_id"] == f"node::{reader.func_id}")

            self.assertEqual("discovered", original_edge["status"])
            self.assertEqual(0, int(original_edge["visible_in_tree"]))
            self.assertEqual(1, int(original_edge["visible_in_all_propagations"]))
            self.assertEqual("external_escape", original_edge["tracker_type"])

            self.assertEqual("done", bridge_edge["status"])
            self.assertEqual(f"node::{reader.func_id}", bridge_edge["target_node_id"])
            self.assertEqual(reader.func_id, bridge_edge["target_func_id"])
            self.assertEqual("external_escape", bridge_edge["tracker_type"])
            self.assertEqual(1, int(bridge_edge["visible_in_tree"]))
            self.assertEqual(1, int(bridge_edge["visible_in_all_propagations"]))

            self.assertEqual("done", reader_node["status"])
            self.assertEqual("done", reader_node["analysis_status"])
            self.assertEqual([child["edge_id"] for child in view["tree"]["children"]], [bridge_edge["edge_id"]])
            self.assertEqual([child["node_id"] for child in view["tree"]["children"]], [f"node::{reader.func_id}"])


class TestGraphCancellationWrites(unittest.TestCase):
    def test_analyze_function_marks_graph_node_and_session_cancelled(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "run"
            sessions_dir = run_dir / "sessions"
            vuln_root = run_dir / "vulnerabilities"
            graph_db_path = run_dir / "vuln-scan.sqlite"
            store = make_dataflow_store(run_dir / "dataflow-v2")
            func = FunctionRecord(
                file="src/root.c",
                name="Root",
                signature="void Root(msg_t* msg)",
                start_line=1,
                end_line=10,
                func_hash="root",
            )
            store.upsert_function(func)

            cancel_event = Event()
            cfg = TaskConfig(
                task="test",
                source_file="src/root.c",
                function_name="Root",
                cwd=td,
                workers=RoleConfig(
                    agents=[AgentInstanceConfig(model="fake-model")],
                ),
            )
            cbs = TaintAnalysisCallbacks(
                cfg=cfg,
                source_root=td,
                run_dir=run_dir,
                sessions_dir=sessions_dir,
                graph_db_path=graph_db_path,
                vuln_root=vuln_root,
                run_id="run-cancel",
                task_id="task-cancel",
                cancel_event=cancel_event,
                on_event=lambda *args, **kwargs: None,
            )
            cbs.graph_store = _graph_store(graph_db_path)
            cbs.graph_store.start_task_graph_run(TaskGraphRunRecord(
                task_id="task-cancel",
                epoch=cbs.graph_epoch,
                run_root=str(run_dir),
                root_function="Root",
            ))
            ctx = PathContext(path_id="path-cancel")
            ctx.depth = 0

            class _FakeAgentResult:
                output = json.dumps({"description": "cancelled", "self_contained": True, "taints": [], "propagations": []})
                error = ""
                messages: list[dict] = []

            with patch("app.dataflow_v2.analysis.ensure_file_indexed", lambda *args, **kwargs: None), \
                 patch("app.runner.run_agent", side_effect=lambda *args, **kwargs: (cancel_event.set() or _FakeAgentResult())):
                cbs._read_body = lambda _func: "void Root(msg_t* msg) { return; }"  # type: ignore[method-assign]
                cbs.analyze_function(store, func, TaintParamInfo([0], "msg_t*", ["msg"]), [], "", ctx)

            view = _graph_store(graph_db_path).export_task_graph_view("task-cancel")
            self.assertEqual("cancelled", view["nodes"][0]["status"])
            self.assertEqual("cancelled", view["nodes"][0]["analysis_status"])
            self.assertEqual("cancelled", view["sessions"][0]["status"])

    def test_run_path_marks_child_edge_and_node_cancelled_when_cancel_requested(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "run"
            graph_store = _graph_store(run_dir / "vuln-scan.sqlite")
            store = make_dataflow_store(run_dir / "dataflow-v2")
            parent = _func(store, "Parent")
            child = _func(store, "Child", file="child.c")
            cancel_event = Event()

            class _GraphCbs(AnalysisCallbacks):
                def __init__(self):
                    self.cancel_event = cancel_event
                    self.graph_store = graph_store
                    self.task_id = "task-cancel-path"
                    self.graph_epoch = "run"
                    self.graph_node_id = lambda func: f"node::{func.func_id}"

            cbs = _GraphCbs()
            graph_store.start_task_graph_run(TaskGraphRunRecord(
                task_id="task-cancel-path",
                epoch="run",
                run_root=str(run_dir),
                root_function="Parent",
            ))
            graph_store.upsert_task_graph_node(TaskGraphNodeRecord(
                node_id=f"node::{parent.func_id}",
                task_id="task-cancel-path",
                epoch="run",
                func_id=parent.func_id,
                function_name_resolved=parent.name,
                function_name_raw=parent.name,
                source_file=parent.file,
                depth=0,
                status="running",
                analysis_status="running",
            ))
            graph_store.upsert_task_graph_node(TaskGraphNodeRecord(
                node_id=f"node::{child.func_id}",
                task_id="task-cancel-path",
                epoch="run",
                func_id=child.func_id,
                function_name_resolved=child.name,
                function_name_raw=child.name,
                source_file=child.file,
                depth=1,
                status="running",
                analysis_status="running",
            ))
            graph_store.upsert_task_graph_edge(TaskGraphEdgeRecord(
                edge_id="prop-child",
                task_id="task-cancel-path",
                epoch="run",
                source_node_id=f"node::{parent.func_id}",
                target_node_id=f"node::{child.func_id}",
                source_func_id=parent.func_id,
                target_func_id=child.func_id,
                source_function_resolved=parent.name,
                target_function_resolved=child.name,
                target_function_raw=child.name,
                source_file=parent.file,
                target_file=child.file,
                edge_kind="direct_call",
                status="scheduled",
                source_prop_id="prop-child",
            ))

            orch = DfsOrchestrator(store, cbs, concurrent=False, max_depth=2)
            original_process = orch._process

            def _cancelled_process(*args, **kwargs):
                cancel_event.set()
                return [], []

            orch._process = _cancelled_process  # type: ignore[method-assign]
            try:
                step = type("Step", (), {
                    "func": child,
                    "taint_params": TaintParamInfo([0], "msg_t*", ["msg"]),
                    "validations": [],
                    "call_line": 12,
                    "prop_id": "prop-child",
                })()
                orch._run_path([step], [], parent, "", PathContext("path"), 0)
            finally:
                orch._process = original_process  # type: ignore[method-assign]

            view = graph_store.export_task_graph_view("task-cancel-path")
            edge = next(item for item in view["edges"] if item["edge_id"] == "prop-child")
            child_node = next(item for item in view["nodes"] if item["node_id"] == f"node::{child.func_id}")
            self.assertEqual("cancelled", edge["status"])
            self.assertEqual("task_cancelled", edge["reason_code"])
            self.assertEqual("cancelled", child_node["status"])
            self.assertEqual("cancelled", child_node["analysis_status"])


class TestGraphFailureWrites(unittest.TestCase):
    def test_run_path_marks_child_edge_and_node_failed_when_child_analysis_raises(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "run"
            graph_store = _graph_store(run_dir / "vuln-scan.sqlite")
            store = make_dataflow_store(run_dir / "dataflow-v2")
            parent = _func(store, "Parent")
            child = _func(store, "Child", file="child.c")

            class _GraphCbs(AnalysisCallbacks):
                def __init__(self):
                    self.graph_store = graph_store
                    self.task_id = "task-failed-path"
                    self.graph_epoch = "run"
                    self.graph_node_id = lambda func: f"node::{func.func_id}"
                    self.cancel_event = None
                    self.sessions_dir = run_dir / "sessions"
                    self.sessions_dir.mkdir(parents=True, exist_ok=True)
                    self.source_root = td
                    self.on_event = lambda *args, **kwargs: None

                def analyze_function(self, store, func, taint_params, pre_validations, base_session, ctx):
                    self.graph_store.upsert_task_graph_node(TaskGraphNodeRecord(
                        node_id=self.graph_node_id(func),
                        task_id=self.task_id,
                        epoch=self.graph_epoch,
                        func_id=func.func_id,
                        function_name_resolved=func.name,
                        function_name_raw=func.name,
                        source_file=func.file,
                        depth=max(0, getattr(ctx, "depth", 0)),
                        status="running",
                        analysis_status="running",
                    ))
                    if func.func_id == parent.func_id:
                        self.prop = PropagationRecord(
                            source_func_id=func.func_id,
                            source_taint_name="msg",
                            source_taint_signature="msg_t*",
                            target_taint_name="child_msg",
                            target_taint_signature="child_msg_t*",
                            target_function="Child",
                            target_func_id=child.func_id,
                            call_line=12,
                        )
                        return AnalysisResult(
                            propagations=[self.prop],
                            self_contained=False,
                            description="Parent",
                        )
                    raise RuntimeError("child analysis failed")

                def mine_vulns(self, store, func, taint_params, ctx, base_session=""):
                    return 0

            cbs = _GraphCbs()
            orch = DfsOrchestrator(store, cbs, concurrent=False, max_depth=2)
            with self.assertRaises(RuntimeError):
                orch.run(parent, TaintParamInfo([0], "msg_t*", ["msg"]))

            view = graph_store.export_task_graph_view("task-failed-path")
            edge = next(item for item in view["edges"] if item["edge_id"] == cbs.prop.prop_id)
            child_node = next(item for item in view["nodes"] if item["node_id"] == f"node::{child.func_id}")
            self.assertEqual("failed", edge["status"])
            self.assertEqual("child_process_failed", edge["reason_code"])
            self.assertEqual("failed", child_node["status"])
            self.assertEqual("failed", child_node["analysis_status"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
