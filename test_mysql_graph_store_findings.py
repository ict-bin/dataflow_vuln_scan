from __future__ import annotations

from app.db.mysql_graph_store import MysqlGraphStore, _POST_DDL_MIGRATIONS


class _FakeConn:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.commits = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, stmt, params=None):
        self.calls.append((str(stmt), dict(params or {})))
        return None

    def commit(self):
        self.commits += 1


class _FakeEngine:
    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn

    def connect(self):
        return self._conn


def _build_store(conn: _FakeConn) -> MysqlGraphStore:
    store = MysqlGraphStore.__new__(MysqlGraphStore)
    store._engine = _FakeEngine(conn)
    return store


def test_post_ddl_migration_promotes_task_scoped_primary_key():
    assert any("ADD PRIMARY KEY (task_id, finding_id)" in stmt for stmt in _POST_DDL_MIGRATIONS)


def test_insert_finding_uses_task_scoped_upsert():
    conn = _FakeConn()
    store = _build_store(conn)

    store.insert_finding(
        task_id="task-a",
        finding_id="finding-1",
        run_id="task-a",
        severity="medium",
    )

    sql, params = conn.calls[0]
    assert "INSERT INTO dvs_vuln_findings" in sql
    assert "ON DUPLICATE KEY UPDATE" in sql
    assert "task_id=VALUES(task_id)" not in sql
    assert "finding_id=VALUES(finding_id)" not in sql
    assert params["task_id"] == "task-a"
    assert params["finding_id"] == "finding-1"
    assert conn.commits == 1


def test_update_finding_report_status_scopes_by_task_when_provided():
    conn = _FakeConn()
    store = _build_store(conn)

    store.update_finding_report_status(
        "finding-1",
        status="reported",
        case_id="case-1",
        task_id="task-a",
    )

    sql, params = conn.calls[0]
    assert "WHERE task_id=:tid AND finding_id=:fid" in sql
    assert params == {
        "st": "reported",
        "cid": "case-1",
        "tid": "task-a",
        "fid": "finding-1",
    }
    assert conn.commits == 1


def test_update_finding_report_status_keeps_legacy_fallback_without_task():
    conn = _FakeConn()
    store = _build_store(conn)

    store.update_finding_report_status(
        "finding-1",
        status="failed",
        case_id="case-2",
    )

    sql, params = conn.calls[0]
    assert "WHERE finding_id=:fid" in sql
    assert "task_id=:tid" not in sql
    assert params == {
        "st": "failed",
        "cid": "case-2",
        "fid": "finding-1",
    }
    assert conn.commits == 1
