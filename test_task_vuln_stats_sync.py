from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AppDvsTask
from app.service.task_service import TaskService, _sync_task_vuln_stats


class _FakeMysqlGraphStore:
    def __init__(self, total: int, reported: int) -> None:
        self._stats = {
            "total": total,
            "reported": reported,
            "unreported": total - reported,
        }

    def get_task_finding_stats(self, task_id: str) -> dict[str, int]:
        assert task_id == "dvs_task_1"
        return dict(self._stats)


def test_sync_task_vuln_stats_uses_mysql_graph_authoritative_counts(monkeypatch):
    row = AppDvsTask(
        task_id="dvs_task_1",
        project_id="p1",
        task_name="demo",
        input_path="/tmp/input",
        source_root_path="/tmp/source-root",
        output_path="/tmp/output",
        prompt_content="prompt",
        vuln_total_count=0,
        vuln_reported_count=0,
        vuln_unreported_count=0,
    )

    monkeypatch.setattr(
        "app.db.mysql_graph_store.create_mysql_graph_store",
        lambda *args, **kwargs: _FakeMysqlGraphStore(total=4, reported=1),
    )

    changed = _sync_task_vuln_stats(row)

    assert changed is True
    assert row.vuln_total_count == 4
    assert row.vuln_reported_count == 1
    assert row.vuln_unreported_count == 3


def test_get_task_refreshes_vuln_snapshot_from_mysql_graph(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    AppDvsTask.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    db_session = SessionLocal()
    row = AppDvsTask(
        task_id="dvs_task_1",
        project_id="p1",
        task_name="demo",
        input_path="/tmp/input",
        source_root_path="/tmp/source-root",
        output_path="/tmp/output",
        prompt_content="prompt",
        status="running",
        vuln_total_count=0,
        vuln_reported_count=0,
        vuln_unreported_count=0,
    )
    db_session.add(row)
    db_session.commit()

    monkeypatch.setattr(
        "app.db.mysql_graph_store.create_mysql_graph_store",
        lambda *args, **kwargs: _FakeMysqlGraphStore(total=5, reported=2),
    )

    try:
        payload = TaskService().get_task(db_session, "dvs_task_1")

        assert payload["vuln_total_count"] == 5
        assert payload["vuln_reported_count"] == 2
        assert payload["vuln_unreported_count"] == 3
    finally:
        db_session.close()
        engine.dispose()
