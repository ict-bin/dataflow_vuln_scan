from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AppDvsTask
from app.service import session_lineage_index
from app.service.task_paths import open_authoritative_vuln_scan_store
from app.service.task_service import TaskService, _sync_task_vuln_stats
from app.vuln_store import VulnScanStore


def _insert_run_and_findings(
    db_path: Path,
    *,
    task_id: str,
    run_id: str,
    reported: int,
    unreported: int,
) -> None:
    store = VulnScanStore(db_path)
    with store.connect() as conn:
        conn.execute(
            """
            INSERT INTO analysis_runs(
                run_id, task_id, root_file, root_function, source_root, status, started_at, config_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (run_id, task_id, "src/root.cpp", "Root", "/src", "done", 1780000000.0, "{}"),
        )
        for idx in range(reported):
            conn.execute(
                """
                INSERT INTO vulnerability_findings(
                    finding_id, run_id, node_id, edge_id, source_file, function_name, line,
                    vuln_type, severity, title, summary, evidence, exploitability, confidence,
                    output_dir, report_status, report_case_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"finding-r-{idx}",
                    run_id,
                    "node-root",
                    "edge-root",
                    "src/root.cpp",
                    "Root",
                    str(idx + 1),
                    "sql_injection",
                    "high",
                    f"reported-{idx}",
                    "summary",
                    "evidence",
                    "exploitability",
                    0.9,
                    f"/tmp/finding-r-{idx}",
                    "reported",
                    f"CASE-{idx}",
                ),
            )
        for idx in range(unreported):
            conn.execute(
                """
                INSERT INTO vulnerability_findings(
                    finding_id, run_id, node_id, edge_id, source_file, function_name, line,
                    vuln_type, severity, title, summary, evidence, exploitability, confidence,
                    output_dir, report_status, report_case_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"finding-u-{idx}",
                    run_id,
                    "node-root",
                    "edge-root",
                    "src/root.cpp",
                    "Root",
                    str(idx + 101),
                    "command_injection",
                    "medium",
                    f"unreported-{idx}",
                    "summary",
                    "evidence",
                    "exploitability",
                    0.5,
                    f"/tmp/finding-u-{idx}",
                    "",
                    "",
                ),
            )


def test_sync_task_vuln_stats_uses_authoritative_run_sqlite(tmp_path: Path):
    task_root = tmp_path / "output-root" / "dvs_task_1"
    run_db = task_root / "run" / "vuln-scan.sqlite"
    output_db = task_root / "output" / "vuln-scan.sqlite"
    _insert_run_and_findings(run_db, task_id="dvs_task_1", run_id="run-1", reported=1, unreported=1)
    _insert_run_and_findings(output_db, task_id="dvs_task_1", run_id="run-1", reported=0, unreported=5)

    row = AppDvsTask(
        task_id="dvs_task_1",
        project_id="p1",
        task_name="demo",
        input_path="/tmp/input",
        source_root_path="/tmp/source-root",
        output_path=str(tmp_path / "output-root"),
        prompt_content="prompt",
        vuln_total_count=0,
        vuln_reported_count=0,
        vuln_unreported_count=0,
    )

    changed = _sync_task_vuln_stats(row)

    assert changed is True
    assert row.vuln_total_count == 2
    assert row.vuln_reported_count == 1
    assert row.vuln_unreported_count == 1


def test_sync_task_vuln_stats_falls_back_to_output_sqlite(tmp_path: Path):
    task_root = tmp_path / "output-root" / "dvs_task_1"
    output_db = task_root / "output" / "vuln-scan.sqlite"
    _insert_run_and_findings(output_db, task_id="dvs_task_1", run_id="run-1", reported=2, unreported=3)

    row = AppDvsTask(
        task_id="dvs_task_1",
        project_id="p1",
        task_name="demo",
        input_path="/tmp/input",
        source_root_path="/tmp/source-root",
        output_path=str(tmp_path / "output-root"),
        prompt_content="prompt",
        vuln_total_count=0,
        vuln_reported_count=0,
        vuln_unreported_count=0,
    )

    changed = _sync_task_vuln_stats(row)

    assert changed is True
    assert row.vuln_total_count == 5
    assert row.vuln_reported_count == 2
    assert row.vuln_unreported_count == 3


def test_get_task_refreshes_vuln_snapshot_from_authoritative_sqlite(tmp_path: Path):
    engine = create_engine("sqlite:///:memory:")
    AppDvsTask.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    db_session = SessionLocal()
    output_root = tmp_path / "output-root"
    task_root = output_root / "dvs_task_1"
    run_db = task_root / "run" / "vuln-scan.sqlite"
    _insert_run_and_findings(run_db, task_id="dvs_task_1", run_id="run-1", reported=2, unreported=1)
    row = AppDvsTask(
        task_id="dvs_task_1",
        project_id="p1",
        task_name="demo",
        input_path="/tmp/input",
        source_root_path="/tmp/source-root",
        output_path=str(output_root),
        prompt_content="prompt",
        status="running",
        vuln_total_count=0,
        vuln_reported_count=0,
        vuln_unreported_count=0,
    )
    db_session.add(row)
    db_session.commit()

    try:
        payload = TaskService().get_task(db_session, "dvs_task_1")

        assert payload["vuln_total_count"] == 3
        assert payload["vuln_reported_count"] == 2
        assert payload["vuln_unreported_count"] == 1
    finally:
        db_session.close()
        engine.dispose()


def test_get_task_tolerates_authoritative_sqlite_race(tmp_path: Path, monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    AppDvsTask.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    db_session = SessionLocal()
    output_root = tmp_path / "output-root"
    row = AppDvsTask(
        task_id="dvs_task_1",
        project_id="p1",
        task_name="demo",
        input_path="/tmp/input",
        source_root_path="/tmp/source-root",
        output_path=str(output_root),
        prompt_content="prompt",
        status="running",
        vuln_total_count=7,
        vuln_reported_count=3,
        vuln_unreported_count=4,
    )
    db_session.add(row)
    db_session.commit()

    class _BrokenStore:
        def list_task_findings(self, task_id: str):
            raise sqlite3.OperationalError("unable to open database file")

    monkeypatch.setattr(
        "app.service.task_paths.open_authoritative_vuln_scan_store",
        lambda task_root, prefer_live=True: _BrokenStore(),
    )

    try:
        payload = TaskService().get_task(db_session, "dvs_task_1")
        assert payload["vuln_total_count"] == 7
        assert payload["vuln_reported_count"] == 3
        assert payload["vuln_unreported_count"] == 4
    finally:
        db_session.close()
        engine.dispose()


def test_session_file_stats_missing_file_is_debug_only(tmp_path: Path, caplog):
    run_root = tmp_path / "run"
    run_root.mkdir(parents=True, exist_ok=True)

    with caplog.at_level(logging.DEBUG, logger="dvs.session_lineage_index"):
        mtime, line_count = session_lineage_index._session_file_stats(run_root, "sessions/missing.jsonl")

    assert (mtime, line_count) == (None, None)
    assert "session file not ready yet" in caplog.text
    assert "file access stat failed" not in caplog.text


def test_open_authoritative_vuln_scan_store_can_read_live_sqlite_without_wal(tmp_path: Path):
    task_root = tmp_path / "output-root" / "dvs_task_1"
    run_db = task_root / "run" / "vuln-scan.sqlite"
    _insert_run_and_findings(run_db, task_id="dvs_task_1", run_id="run-1", reported=1, unreported=0)

    store = open_authoritative_vuln_scan_store(
        task_root,
        prefer_live=True,
        readonly=True,
        enable_wal=False,
    )

    assert store is not None
    assert store.readonly is True
    assert store.enable_wal is False
    assert [item["finding_id"] for item in store.list_task_findings("dvs_task_1")] == ["finding-r-0"]
