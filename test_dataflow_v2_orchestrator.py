"""dataflow-v2 编排器路径构造测试 (互斥分叉 + 顺序链)。"""
import sys, tempfile, unittest
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
        return self.orch._build_paths(props, self.A, ctx, 0)

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


class TestDedupAndFeedback(unittest.TestCase):
    def test_dedup_validations(self):
        from app.dataflow_v2.orchestrator import _dedup_validations
        vs = [Validation("a", "b"), Validation("a", "b"), Validation("c", "d")]
        out = _dedup_validations(vs)
        self.assertEqual(len(out), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
