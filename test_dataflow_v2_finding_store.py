from __future__ import annotations

from pathlib import Path

from app.dataflow_v2.finding_store import persist_finding


class _FakeMysql:
    def __init__(self, *, fail_insert: bool = False):
        self.fail_insert = fail_insert
        self.inserted: dict | None = None
        self.updated: tuple[tuple, dict] | None = None

    def insert_finding(self, **data):
        if self.fail_insert:
            raise RuntimeError("mysql insert failed")
        self.inserted = data

    def update_finding_report_status(self, *args, **kwargs):
        self.updated = (args, kwargs)
        return True

    def get_task_finding_stats(self, task_id):
        return {"total": 1, "reported": 1, "unreported": 0}


class _FakeGraphStore:
    def __init__(self, mysql: _FakeMysql):
        self._mysql = mysql

    def update_finding_report_status(self, *args, **kwargs):
        return self._mysql.update_finding_report_status(*args, **kwargs)

    def get_finding_report_state(self, *args, **kwargs):
        return None


def _sample_item() -> dict:
    return {
        "source_file": "src/demo.c",
        "function_name": "demo_func",
        "line": "42",
        "vuln_type": "dos",
        "severity": "high",
        "title": "demo finding",
        "summary": "summary",
        "evidence": "evidence",
        "exploitability": {"trigger": "packet"},
        "confidence": 0.8,
    }


def test_persist_finding_writes_authoritative_mysql_and_emits_events(tmp_path: Path, monkeypatch):
    vuln_root = tmp_path / "run" / "epochs" / "0001" / "vulnerabilities"
    session_path = tmp_path / "session.jsonl"
    session_path.write_text('{"type":"session"}\n', encoding="utf-8")
    mysql = _FakeMysql()
    store = _FakeGraphStore(mysql)
    events: list[tuple[str, dict]] = []

    monkeypatch.setattr(
        "app.dataflow_v2.finding_store.report_finding_to_intake",
        lambda **kwargs: {"status": "reported", "case_id": "CASE-1"},
    )
    monkeypatch.setattr(
        "app.dataflow_v2.finding_store._sync_vuln_count_mysql",
        lambda *args, **kwargs: True,
    )

    finding_id = persist_finding(
        graph_store=store,
        run_id="run-1",
        task_id="task-1",
        source_root="/src",
        vuln_root=vuln_root,
        func_file="src/demo.c",
        func_name="demo_func",
        func_description="demo desc",
        item=_sample_item(),
        context_text="context",
        context_session_path=str(session_path),
        cfg_project_id="p1",
        cfg_task_name="task",
        on_event=lambda etype, **payload: events.append((etype, payload)),
    )

    assert finding_id
    assert mysql.inserted is not None
    assert mysql.inserted["finding_id"] == finding_id
    assert mysql.inserted["task_id"] == "task-1"
    assert mysql.updated is not None
    assert mysql.updated[1] == {
        "status": "reported",
        "case_id": "CASE-1",
        "task_id": "task-1",
        "run_id": "run-1",
    }
    persisted_payload = next(payload for etype, payload in events if etype == "vuln_finding_persisted")
    intake_payload = next(payload for etype, payload in events if etype == "vuln_intake_result")
    mirror_dir = tmp_path / "run" / "vulnerabilities" / finding_id
    assert mirror_dir.exists()
    assert (mirror_dir / "vulnerability-report.md").exists()
    assert (mirror_dir / "context.jsonl").exists()
    assert (mirror_dir / "context.jsonl").read_text(encoding="utf-8") == '{"type":"session"}\n'
    assert "context" in (mirror_dir / "vulnerability-report.md").read_text(encoding="utf-8")
    assert persisted_payload["title"] == "demo finding"
    assert persisted_payload["summary"] == "summary"
    assert persisted_payload["summary_preview"] == "summary"
    assert persisted_payload["evidence_preview"] == "evidence"
    assert persisted_payload["vuln_type"] == "dos"
    assert persisted_payload["severity"] == "high"
    assert persisted_payload["mirror_dir"] == str(mirror_dir)
    assert "发现漏洞并已落库" in persisted_payload["message"]
    assert "摘要=summary" in persisted_payload["message"]
    assert intake_payload["title"] == "demo finding"
    assert intake_payload["summary"] == "summary"
    assert intake_payload["summary_preview"] == "summary"
    assert intake_payload["evidence_preview"] == "evidence"
    assert intake_payload["vuln_type"] == "dos"
    assert intake_payload["severity"] == "high"
    assert "漏洞上报成功" in intake_payload["message"]
    assert "摘要=summary" in intake_payload["message"]
class _BrokenGraphStore:
    def __init__(self):
        self._mysql = _FakeMysql(fail_insert=True)


def test_persist_finding_returns_none_when_authoritative_insert_fails(tmp_path: Path, monkeypatch):
    vuln_root = tmp_path / "run" / "vulnerabilities"
    session_path = tmp_path / "session.jsonl"
    session_path.write_text('{"type":"session"}\n', encoding="utf-8")
    events: list[tuple[str, dict]] = []

    called = {"intake": False, "sync": False}

    def _intake(**kwargs):
        called["intake"] = True
        return {"status": "reported", "case_id": "CASE-1"}

    def _sync(*args, **kwargs):
        called["sync"] = True
        return True

    monkeypatch.setattr("app.dataflow_v2.finding_store.report_finding_to_intake", _intake)
    monkeypatch.setattr("app.dataflow_v2.finding_store._sync_vuln_count_mysql", _sync)

    finding_id = persist_finding(
        graph_store=_BrokenGraphStore(),
        run_id="run-1",
        task_id="task-1",
        source_root="/src",
        vuln_root=vuln_root,
        func_file="src/demo.c",
        func_name="demo_func",
        func_description="demo desc",
        item=_sample_item(),
        context_text="context",
        context_session_path=str(session_path),
        cfg_project_id="p1",
        cfg_task_name="task",
        on_event=lambda etype, **payload: events.append((etype, payload)),
    )

    assert finding_id is None
    assert called["intake"] is False
    assert called["sync"] is False
    failure_events = [payload for etype, payload in events if etype == "vuln_finding_persist_failed"]
    assert len(failure_events) == 1
    assert failure_events[0]["stage"] == "mysql_insert"


def test_persist_finding_skips_intake_when_mysql_marks_finding_reported(tmp_path: Path, monkeypatch):
    class _ReportedGraphStore(_FakeGraphStore):
        def get_finding_report_state(self, *args, **kwargs):
            return {"report_status": "reported", "report_case_id": "CASE-EXISTING"}

    mysql = _FakeMysql()
    store = _ReportedGraphStore(mysql)
    session_path = tmp_path / "session.jsonl"
    session_path.write_text('{"type":"session"}\n', encoding="utf-8")
    events: list[tuple[str, dict]] = []
    called = {"intake": False}

    def _intake(**kwargs):
        called["intake"] = True
        return {"status": "reported", "case_id": "CASE-NEW"}

    monkeypatch.setattr("app.dataflow_v2.finding_store.report_finding_to_intake", _intake)
    monkeypatch.setattr("app.dataflow_v2.finding_store._sync_vuln_count_mysql", lambda *args, **kwargs: True)

    finding_id = persist_finding(
        graph_store=store,
        run_id="run-1",
        task_id="task-1",
        source_root="/src",
        vuln_root=tmp_path / "run" / "epochs" / "0001" / "vulnerabilities",
        func_file="src/demo.c",
        func_name="demo_func",
        func_description="demo desc",
        item=_sample_item(),
        context_text="context",
        context_session_path=str(session_path),
        cfg_project_id="p1",
        cfg_task_name="task",
        on_event=lambda event_type, **payload: events.append((event_type, payload)),
    )

    assert finding_id
    assert called["intake"] is False
    skipped = [payload for event_type, payload in events if event_type == "vuln_intake_report_skipped_already_reported"]
    assert skipped == [{
        "level": "info",
        "message": f"漏洞已上报，跳过重复提交: {finding_id}",
        "finding_id": finding_id,
        "function": "demo_func",
        "task_id": "task-1",
        "case_id": "CASE-EXISTING",
    }]
