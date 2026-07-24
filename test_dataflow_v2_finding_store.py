from __future__ import annotations

import sqlite3
from pathlib import Path

from app.dataflow_v2.finding_store import persist_finding
from app.vuln_store import VulnScanStore


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


def test_persist_finding_writes_authoritative_sqlite_and_emits_events(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "run" / "vuln-scan.sqlite"
    vuln_root = tmp_path / "run" / "vulnerabilities"
    session_path = tmp_path / "session.jsonl"
    session_path.write_text('{"type":"session"}\n', encoding="utf-8")
    store = VulnScanStore(db_path)
    events: list[tuple[str, dict]] = []

    monkeypatch.setattr(
        "app.dataflow_v2.finding_store.report_finding_to_intake",
        lambda **kwargs: {"status": "reported", "case_id": "CASE-1"},
    )
    monkeypatch.setattr(
        "app.dataflow_v2.finding_store.refresh_task_vuln_snapshot_by_task_id",
        lambda task_id, prefer_live=True: True,
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
    rows = store.list_all_findings()
    assert len(rows) == 1
    assert rows[0]["finding_id"] == finding_id
    assert rows[0]["function_name"] == "demo_func"
    assert any(etype == "vuln_finding_persisted" for etype, _ in events)
    assert any(etype == "vuln_intake_result" for etype, _ in events)


class _BrokenGraphStore:
    def connect(self):
        return sqlite3.connect(":memory:")


def test_persist_finding_returns_none_when_authoritative_insert_fails(tmp_path: Path, monkeypatch):
    vuln_root = tmp_path / "run" / "vulnerabilities"
    session_path = tmp_path / "session.jsonl"
    session_path.write_text('{"type":"session"}\n', encoding="utf-8")
    events: list[tuple[str, dict]] = []

    called = {"intake": False, "sync": False}

    def _intake(**kwargs):
        called["intake"] = True
        return {"status": "reported", "case_id": "CASE-1"}

    def _sync(task_id: str, prefer_live: bool = True):
        called["sync"] = True
        return True

    monkeypatch.setattr("app.dataflow_v2.finding_store.report_finding_to_intake", _intake)
    monkeypatch.setattr("app.dataflow_v2.finding_store.refresh_task_vuln_snapshot_by_task_id", _sync)

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
    assert failure_events[0]["stage"] == "authoritative_sqlite"
