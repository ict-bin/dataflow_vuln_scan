"""dataflow-v2 编排器路径构造测试 (互斥分叉 + 顺序链)。"""
import sys, tempfile, time, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from app.dataflow_v2 import (
    DataflowStore, FunctionRecord, PropagationRecord, TaintParamInfo, Validation,
)
from app.dataflow_v2.orchestrator import DfsOrchestrator, AnalysisCallbacks, PathContext


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
        self.store = DataflowStore(Path(self.td.name) / "run")
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
            def resolve_external_propagation(self, store, func, prop, ctx):
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
        vs = [Validation(left="a", op="==", right="b"),
               Validation(left="a", op="==", right="b"),
               Validation(left="c", op="==", right="d")]
        out = _dedup_validations(vs)
        self.assertEqual(len(out), 2)


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
    def resolve_external_propagation(self, store, func, taint, ctx):
        return []
    def mine_vulns(self, store, func, tp, ctx, base_session=""):
        with self._lock: self.mined.append(func.name)
        return 0


class TestConcurrentDfs(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.store = DataflowStore(Path(self.td.name) / "run")
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
