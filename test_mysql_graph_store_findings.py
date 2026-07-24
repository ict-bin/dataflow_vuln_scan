from __future__ import annotations

import app.db.mysql_graph_store as mysql_graph_store_module
from app.db.mysql_graph_store import MysqlGraphStore, _POST_DDL_MIGRATIONS


class _FakeConn:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.commits = 0
        self.fetchall_results: list[list] = []
        self.fetchone_results: list[object] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, stmt, params=None):
        self.calls.append((str(stmt), dict(params or {})))
        if self.fetchone_results or self.fetchall_results:
            return _FakeResult(
                fetchone_result=self.fetchone_results.pop(0) if self.fetchone_results else None,
                fetchall_result=self.fetchall_results.pop(0) if self.fetchall_results else [],
            )
        return _FakeResult()

    def commit(self):
        self.commits += 1


class _FakeEngine:
    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn

    def connect(self):
        return self._conn


class _FakeRow:
    def __init__(self, mapping):
        self._mapping = mapping


class _FakeResult:
    def __init__(self, fetchone_result=None, fetchall_result=None) -> None:
        self._fetchone_result = fetchone_result
        self._fetchall_result = fetchall_result or []

    def fetchone(self):
        return self._fetchone_result

    def fetchall(self):
        return self._fetchall_result


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


def test_clear_task_removes_task_scoped_findings():
    conn = _FakeConn()
    store = _build_store(conn)

    store.clear_task("task-a")

    sql_calls = [sql for sql, _ in conn.calls]
    assert any("DELETE FROM dvs_vuln_findings WHERE task_id=:tid" in sql for sql in sql_calls)
    assert any("DELETE FROM dvs_task_graph_runs WHERE task_id=:tid" in sql for sql in sql_calls)
    assert conn.commits == 1


def test_export_task_graph_view_exposes_sqlite_compatible_summary_keys():
    conn = _FakeConn()
    conn.fetchone_results = [_FakeRow({"task_id": "task-a", "epoch": "0001", "run_root": "/tmp/run", "generated_at": 1.0})]
    conn.fetchall_results = [
        [],
        [_FakeRow({"node_id": "node-1", "task_id": "task-a", "depth": 0, "status": "done", "analysis_status": "done", "findings_count": 0, "function_name_resolved": "Root", "function_name_raw": "Root", "source_file": "", "primary_session_relpath": ""})],
        [],
        [],
        [_FakeRow({"finding_id": "finding-1", "task_id": "task-a", "run_id": "run-a", "created_at": "2026-07-23T00:00:00", "severity": "high"})],
    ]
    store = _build_store(conn)

    view = store.export_task_graph_view("task-a")

    assert view["summary"]["nodes_total"] == 1
    assert view["summary"]["edges_total"] == 0
    assert view["summary"]["findings_total"] == 1
    assert view["summary"]["findings"] == 1


def test_get_task_finding_stats_uses_task_scoped_mysql_rows():
    conn = _FakeConn()
    conn.fetchone_results = [_FakeRow({"total": 4, "reported": 1})]
    store = _build_store(conn)

    stats = store.get_task_finding_stats("task-a")

    sql, params = conn.calls[0]
    assert "JOIN dvs_analysis_runs ar ON ar.run_id = vf.run_id" in sql
    assert "WHERE ar.task_id=:tid" in sql
    assert params == {"tid": "task-a"}
    assert stats == {"total": 4, "reported": 1, "unreported": 3}


def test_get_engine_is_scoped_by_final_mysql_url(monkeypatch):
    created_urls: list[str] = []
    engines: dict[str, object] = {}

    class _AdminConn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, stmt, params=None):
            return _FakeResult()

        def commit(self):
            return None

    class _AdminEngine:
        def connect(self):
            return _AdminConn()

        def dispose(self):
            return None

    class _FinalConn(_AdminConn):
        pass

    class _FinalEngine:
        def __init__(self, url: str) -> None:
            self.url = url

        def connect(self):
            return _FinalConn()

    def _fake_create_engine(url: str, *args, **kwargs):
        if url.endswith("/mysql?charset=utf8mb4"):
            return _AdminEngine()
        created_urls.append(url)
        engine = engines.get(url)
        if engine is None:
            engine = _FinalEngine(url)
            engines[url] = engine
        return engine

    monkeypatch.setattr(mysql_graph_store_module, "_ENGINES", {})
    monkeypatch.setattr(mysql_graph_store_module, "create_engine", _fake_create_engine)

    store_a = MysqlGraphStore(
        "mysql+pymysql://root:pwd@mysql:3306/secflow?charset=utf8mb4",
        project_id="project",
        source_dir_id="source_a",
        source_root="/src/a",
    )
    store_b = MysqlGraphStore(
        "mysql+pymysql://root:pwd@mysql:3306/secflow?charset=utf8mb4",
        project_id="project",
        source_dir_id="source_b",
        source_root="/src/b",
    )

    assert store_a._engine is not store_b._engine
    assert created_urls == [
        "mysql+pymysql://root:pwd@mysql:3306/dvs_source_a?charset=utf8mb4",
        "mysql+pymysql://root:pwd@mysql:3306/dvs_source_b?charset=utf8mb4",
    ]
