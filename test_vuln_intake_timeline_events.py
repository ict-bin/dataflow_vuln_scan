from __future__ import annotations

from pathlib import Path

from app.dataflow_v2.analysis import TaintAnalysisCallbacks
from app.models import TaskConfig
from app.vuln_store import VulnFindingRecord


def _make_callbacks(tmp_path: Path, events: list[tuple[str, dict]]) -> TaintAnalysisCallbacks:
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
        on_event=lambda event_type, **payload: events.append((event_type, payload)),
    )


def _sample_record() -> VulnFindingRecord:
    return VulnFindingRecord(
        finding_id="finding-1",
        run_id="run-1",
        node_id="node::demo",
        source_file="src/demo.c",
        function_name="demo_func",
        line="42",
        vuln_type="dos",
        severity="high",
        title="demo finding",
        summary="summary",
        evidence="evidence",
        exploitability="{}",
        confidence=0.8,
        output_dir="/tmp/finding",
    )


def test_record_intake_result_emits_success_timeline_message(tmp_path: Path):
    events: list[tuple[str, dict]] = []
    callbacks = _make_callbacks(tmp_path, events)

    callbacks._record_intake_result(  # type: ignore[attr-defined]
        "finding-1",
        _sample_record(),
        {"status": "reported", "case_id": "CASE-1", "duplicate": True, "url": "http://intake/case/1"},
    )

    assert events
    event_type, payload = events[-1]
    assert event_type == "vuln_intake_reported"
    assert payload["level"] == "info"
    assert payload["case_id"] == "CASE-1"
    assert payload["duplicate"] is True
    assert payload["report_url"] == "http://intake/case/1"
    assert "漏洞上报成功" in payload["message"]
    assert "finding=finding-1" in payload["message"]


def test_record_intake_result_emits_failure_timeline_message(tmp_path: Path):
    events: list[tuple[str, dict]] = []
    callbacks = _make_callbacks(tmp_path, events)

    callbacks._record_intake_result(  # type: ignore[attr-defined]
        "finding-1",
        _sample_record(),
        {"status": "failed", "error": "boom", "url": "http://intake/error"},
    )

    assert events
    event_type, payload = events[-1]
    assert event_type == "vuln_intake_report_failed"
    assert payload["level"] == "error"
    assert payload["status"] == "failed"
    assert payload["error"] == "boom"
    assert payload["report_url"] == "http://intake/error"
    assert "漏洞上报失败" in payload["message"]
    assert "error=boom" in payload["message"]


def test_report_finding_to_intake_emits_fallback_timeline_message(tmp_path: Path, monkeypatch):
    events: list[tuple[str, dict]] = []
    callbacks = _make_callbacks(tmp_path, events)
    rec = _sample_record()
    vuln_dir = callbacks.vuln_root / rec.finding_id
    vuln_dir.mkdir(parents=True, exist_ok=True)

    responses = iter([
        {"status": "failed", "error": "parent task does not exist"},
        {"status": "reported", "case_id": "CASE-2"},
    ])

    monkeypatch.setattr(callbacks, "_do_intake", lambda *args, **kwargs: next(responses))

    callbacks._report_finding_to_intake(rec.finding_id, rec, vuln_dir)  # type: ignore[attr-defined]

    fallback_events = [payload for event_type, payload in events if event_type == "vuln_intake_fallback_self"]
    assert len(fallback_events) == 1
    fallback = fallback_events[0]
    assert fallback["level"] == "warning"
    assert "漏洞上报父任务被拒" in fallback["message"]
    assert fallback["parent_error"] == "parent task does not exist"

    assert events[-1][0] == "vuln_intake_reported"
