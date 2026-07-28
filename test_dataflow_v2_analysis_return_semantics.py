from __future__ import annotations

import tempfile
from pathlib import Path

from app.dataflow_v2 import DataflowStore, FunctionRecord, TaintParamInfo
from app.dataflow_v2.analysis import TaintAnalysisCallbacks
from app.models import TaskConfig


def _make_callbacks(tmp_path: Path) -> TaintAnalysisCallbacks:
    run_dir = tmp_path / "run"
    sessions_dir = run_dir / "sessions"
    vuln_root = run_dir / "vulnerabilities"
    graph_db_path = run_dir / "vuln-scan.sqlite"
    cfg = TaskConfig(
        task="test-task",
        source_file="src/demo.c",
        function_name="demo_func",
        cwd=str(tmp_path),
        project_id="proj-1",
        task_name="demo-task",
        parent_task_id="parent-1",
        parent_task_name="parent-task",
        parent_task_type="binary_security",
        task_origin_type="binary_security",
    )
    return TaintAnalysisCallbacks(
        cfg=cfg,
        source_root=str(tmp_path),
        run_dir=run_dir,
        sessions_dir=sessions_dir,
        graph_db_path=graph_db_path,
        vuln_root=vuln_root,
        run_id="run-1",
        task_id="task-1",
        on_event=lambda *args, **kwargs: None,
    )


def test_external_callee_return_taint_stays_local_to_current_function(tmp_path: Path):
    callbacks = _make_callbacks(tmp_path)
    store = DataflowStore(tmp_path / "df")
    func = FunctionRecord(
        file="src/demo.c",
        name="demo_func",
        signature="int demo_func(char *msg)",
        start_line=1,
        end_line=20,
        func_hash="demo_func",
    )
    store.upsert_function(func)

    callbacks._infer_external_callees = lambda props, func, session: {  # type: ignore[method-assign]
        "MBUF_MakeMemoryContinuous_fl": {
            "inferable": True,
            "return_taint": "v64",
            "propagation": "",
            "validation": "",
        }
    }

    result = callbacks._build_result(  # type: ignore[attr-defined]
        store,
        func,
        TaintParamInfo([0], "char *", ["msg"]),
        {
            "description": "demo",
            "self_contained": False,
            "taints": [{"name": "msg", "description": "input"}],
            "propagations": [
                {
                    "source_taint": "msg",
                    "target_taint": "v64",
                    "target_function": "MBUF_MakeMemoryContinuous_fl",
                    "description": "external callee return",
                }
            ],
            "return_taints": [],
        },
        callbacks.sessions_dir / "sessions/d00-demo_func-taint-msg-00.jsonl",
        body="int demo_func(char *msg) { int v64 = MBUF_MakeMemoryContinuous_fl(msg); return 0; }",
        taint_failed=False,
    )

    assert [item.name for item in result.return_taints] == []
    assert [item.name for item in result.callee_return_taints] == ["v64"]

    store.close()


def test_model_return_taint_remains_caller_followup_signal(tmp_path: Path):
    callbacks = _make_callbacks(tmp_path)
    store = DataflowStore(tmp_path / "df")
    func = FunctionRecord(
        file="src/demo.c",
        name="demo_func",
        signature="int demo_func(char *msg)",
        start_line=1,
        end_line=20,
        func_hash="demo_func",
    )
    store.upsert_function(func)

    result = callbacks._build_result(  # type: ignore[attr-defined]
        store,
        func,
        TaintParamInfo([0], "char *", ["msg"]),
        {
            "description": "demo",
            "self_contained": False,
            "taints": [{"name": "msg", "description": "input"}],
            "propagations": [],
            "return_taints": [{"name": "ret_msg", "description": "returned to caller"}],
        },
        callbacks.sessions_dir / "sessions/d00-demo_func-taint-msg-00.jsonl",
        body="int demo_func(char *msg) { return msg; }",
        taint_failed=False,
    )

    assert [item.name for item in result.return_taints] == ["ret_msg"]
    assert result.callee_return_taints == []

    store.close()
