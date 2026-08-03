from __future__ import annotations

from types import SimpleNamespace

import app.api.tasks as tasks_module


def test_manual_report_does_not_resubmit_already_reported_finding(tmp_path, monkeypatch):
    row = SimpleNamespace(
        task_id="task-1",
        output_path=str(tmp_path),
    )
    monkeypatch.setattr(tasks_module, "_get_task_row", lambda db, task_id: row)
    monkeypatch.setattr(
        tasks_module,
        "_load_task_vulnerability_findings",
        lambda *args, **kwargs: [{
            "finding_id": "finding-1",
            "report_status": "reported",
            "report_case_id": "CASE-1",
        }],
    )
    monkeypatch.setattr(
        "app.vuln_intake_reporter.report_finding_to_intake",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("must not call intake")),
    )

    result = tasks_module._do_report_finding("task-1", "finding-1", db=object())

    assert result == {
        "task_id": "task-1",
        "finding_id": "finding-1",
        "report_id": None,
        "case_id": "CASE-1",
        "status": "reported",
        "duplicate": True,
        "already_reported": True,
        "error": None,
    }
