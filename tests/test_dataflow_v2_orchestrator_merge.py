from pathlib import Path

from app.dataflow_v2.models import FunctionRecord, TaintParamInfo, Validation
from app.dataflow_v2.orchestrator import ChainStep, DfsOrchestrator, AnalysisCallbacks
from app.dataflow_v2.store import DataflowStore
from test_storage_fakes import make_dataflow_store


def _func(name: str) -> FunctionRecord:
    return FunctionRecord(
        file=f"src/{name}.c",
        name=name,
        signature=f"void {name}(char *buf)",
        start_line=1,
        end_line=20,
    )


def _step(
    func: FunctionRecord,
    *,
    signature: str,
    names: list[str],
    positions: list[int],
    prop_id: str,
    call_line: int,
    validation_target: str,
) -> ChainStep:
    return ChainStep(
        func,
        TaintParamInfo(positions=positions, signature=signature, names=names),
        [Validation(line=call_line, kind="bounds", target=validation_target, summary=f"check {validation_target}")],
        call_line=call_line,
        prop_id=prop_id,
    )


def _orch(tmp_path: Path) -> DfsOrchestrator:
    store = make_dataflow_store(tmp_path / "dataflow-v2")
    return DfsOrchestrator(store, AnalysisCallbacks())


def test_merge_steps_by_func_id_unions_taint_and_edges(tmp_path: Path) -> None:
    orch = _orch(tmp_path)
    callee = _func("foo")

    merged = orch._merge_steps(
        [
            _step(callee, signature="msg", names=["msg"], positions=[0], prop_id="p1", call_line=12, validation_target="msg"),
            _step(callee, signature="buf", names=["buf"], positions=[1], prop_id="p2", call_line=28, validation_target="buf"),
        ]
    )

    assert len(merged) == 1
    step = merged[0]
    assert step.func.func_id == callee.func_id
    assert step.taint_params.positions == [0, 1]
    assert step.taint_params.names == ["buf", "msg"]
    assert step.taint_params.signature == "buf|msg"
    assert step.source_prop_ids == ["p1", "p2"]
    assert step.source_call_lines == [12, 28]
    assert step.call_line == 12
    assert sorted(v.target for v in step.validations) == ["buf", "msg"]


def test_merge_equivalent_paths_collapses_duplicate_func_sequences(tmp_path: Path) -> None:
    orch = _orch(tmp_path)
    foo = _func("foo")
    bar = _func("bar")

    paths = orch._merge_equivalent_paths(
        [
            [
                _step(foo, signature="msg", names=["msg"], positions=[0], prop_id="p1", call_line=10, validation_target="msg"),
                _step(bar, signature="tmp", names=["tmp"], positions=[1], prop_id="p2", call_line=20, validation_target="tmp"),
            ],
            [
                _step(foo, signature="buf", names=["buf"], positions=[1], prop_id="p3", call_line=30, validation_target="buf"),
                _step(bar, signature="tmp2", names=["tmp2"], positions=[1], prop_id="p4", call_line=40, validation_target="tmp2"),
            ],
        ]
    )

    assert len(paths) == 1
    assert [step.func.name for step in paths[0]] == ["foo", "bar"]
    assert paths[0][0].source_prop_ids == ["p1", "p3"]
    assert paths[0][0].taint_params.signature == "buf|msg"
    assert paths[0][1].source_prop_ids == ["p2", "p4"]
