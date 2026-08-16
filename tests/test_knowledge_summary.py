from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import base64
import os
import subprocess
import sys

import app.service.knowledge_summary as knowledge_summary
import app.service.llm_provider_sync as llm_provider_sync


class _TaskQuery:
    def __init__(self, task):
        self.task = task

    def filter(self, *_args):
        return self

    def one_or_none(self):
        return self.task

    def update(self, *_args, **_kwargs):
        return 0


class _ExistingSummaryQuery:
    def __init__(self, row):
        self.row = row

    def filter(self, *_args):
        return self

    def one_or_none(self):
        return self.row

    def update(self, *_args, **_kwargs):
        return 0


class _Db:
    def __init__(self, task, summary_task=None):
        self.task = task
        self.summary_task = summary_task
        self.rows = []
        self.commits = 0

    def query(self, model):
        if model is knowledge_summary.AppDvsKnowledgeSummaryTask:
            return _ExistingSummaryQuery(self.summary_task)
        return _TaskQuery(self.task)

    def add(self, row):
        self.rows.append(row)

    def flush(self):
        pass

    def commit(self):
        self.commits += 1

    def rollback(self):
        pass

    def close(self):
        pass


class _SummaryQuery:
    def __init__(self, row):
        self.row = row

    def filter_by(self, **_kwargs):
        return self

    def one_or_none(self):
        return self.row


class _SummaryDb:
    def __init__(self, row):
        self.row = row
        self.commits = 0

    def query(self, _model):
        return _SummaryQuery(self.row)

    def commit(self):
        self.commits += 1

    def close(self):
        pass


def _case(*, run_id: str = "dvs_12345678", project_id: str = "project-a", updated_at: str = "2026-08-15T00:00:00"):
    return {
        "id": "case-1",
        "project_id": project_id,
        "human_confirmed": True,
        "confirmation_status": "vulnerable",
        "updated_at": updated_at,
        "source_task": {"run_id": run_id, "finding_id": "finding-1"},
        "metadata": {},
    }


def test_create_uses_source_task_run_id_only(monkeypatch, tmp_path: Path):
    files_root = tmp_path / "files"
    finding_dir = files_root / "project-a" / "app" / "secflow-app-dataflow-vuln-scan" / "dvs_12345678" / "output" / "vulnerabilities" / "finding-1"
    finding_dir.mkdir(parents=True)
    source_root = files_root / "project-a" / "source"
    source_root.mkdir(parents=True)
    task = SimpleNamespace(task_id="dvs_12345678", project_id="project-a", is_deleted=False, output_path=str(files_root / "project-a" / "app" / "secflow-app-dataflow-vuln-scan"), source_root_path=str(source_root), input_path=str(source_root))
    db = _Db(task)
    monkeypatch.setattr(knowledge_summary, "_FILESERVER_ROOT", files_root)
    monkeypatch.setattr(knowledge_summary, "_session", lambda: db)
    case = _case()
    case["metadata"] = {"dataflow_vuln_scan": {"output_dir": str(finding_dir)}}

    assert knowledge_summary.KnowledgeSummaryService()._create_from_case(case)
    assert len(db.rows) == 1
    assert db.rows[0].dvs_task_id == "dvs_12345678"
    assert db.rows[0].status == "queued"


def test_vuln_center_human_confirmation_fields_create_queued_task(monkeypatch, tmp_path: Path):
    files_root = tmp_path / "files"
    finding_dir = files_root / "project-a" / "app" / "secflow-app-dataflow-vuln-scan" / "dvs_12345678" / "output" / "vulnerabilities" / "finding-1"
    finding_dir.mkdir(parents=True)
    source_root = files_root / "project-a" / "source"
    source_root.mkdir(parents=True)
    task = SimpleNamespace(task_id="dvs_12345678", project_id="project-a", is_deleted=False, output_path=str(files_root / "project-a" / "app" / "secflow-app-dataflow-vuln-scan"), source_root_path=str(source_root), input_path=str(source_root))
    db = _Db(task)
    monkeypatch.setattr(knowledge_summary, "_FILESERVER_ROOT", files_root)
    monkeypatch.setattr(knowledge_summary, "_session", lambda: db)
    case = _case()
    case.pop("human_confirmed")
    case.pop("confirmation_status")
    case.update({
        "is_human_finished": True,
        "decision_status": "vulnerable",
        "human_confirmation": {"result": "vulnerable", "confirmed_at": "2026-08-16T00:00:00Z"},
        "metadata": {"dataflow_vuln_scan": {"output_dir": str(finding_dir)}},
    })

    assert knowledge_summary.KnowledgeSummaryService()._create_from_case(case)
    assert len(db.rows) == 1
    assert db.rows[0].status == "queued"
    assert db.rows[0].human_confirmed_at is not None


def test_valid_case_recovers_same_fingerprint_skipped_task(monkeypatch, tmp_path: Path):
    files_root = tmp_path / "files"
    finding_dir = files_root / "project-a" / "app" / "secflow-app-dataflow-vuln-scan" / "dvs_12345678" / "output" / "vulnerabilities" / "finding-1"
    finding_dir.mkdir(parents=True)
    source_root = files_root / "project-a" / "source"
    source_root.mkdir(parents=True)
    task = SimpleNamespace(task_id="dvs_12345678", project_id="project-a", is_deleted=False, output_path=str(files_root / "project-a" / "app" / "secflow-app-dataflow-vuln-scan"), source_root_path=str(source_root), input_path=str(source_root))
    skipped = SimpleNamespace(summary_task_id="dks_existing", status="skipped", result_json={"old": True}, error_message="漏洞中心记录未人工确认")
    db = _Db(task, skipped)
    monkeypatch.setattr(knowledge_summary, "_FILESERVER_ROOT", files_root)
    monkeypatch.setattr(knowledge_summary, "_session", lambda: db)
    case = _case()
    case["metadata"] = {"dataflow_vuln_scan": {"output_dir": str(finding_dir)}}

    assert knowledge_summary.KnowledgeSummaryService()._create_from_case(case)
    assert db.rows == []
    assert skipped.status == "queued"
    assert skipped.error_message is None
    assert skipped.result_json is None


def test_create_records_non_dvs_or_missing_run_id_as_skipped(monkeypatch):
    db = _Db(None)
    monkeypatch.setattr(knowledge_summary, "_session", lambda: db)
    service = knowledge_summary.KnowledgeSummaryService()
    assert service._create_from_case(_case(run_id="test-e2e"))
    assert db.rows[0].status == "skipped"


def test_project_mismatch_is_recorded_as_skipped(monkeypatch):
    db = _Db(None)
    monkeypatch.setattr(knowledge_summary, "_session", lambda: db)

    assert knowledge_summary.KnowledgeSummaryService()._create_from_case(_case())
    assert len(db.rows) == 1
    assert db.rows[0].status == "skipped"
    assert "项目不一致" in db.rows[0].error_message


def test_changed_decision_fingerprint_creates_new_revision(monkeypatch, tmp_path: Path):
    files_root = tmp_path / "files"
    finding_dir = files_root / "project-a" / "app" / "secflow-app-dataflow-vuln-scan" / "dvs_12345678" / "output" / "vulnerabilities" / "finding-1"
    finding_dir.mkdir(parents=True)
    source_root = files_root / "project-a" / "source"
    source_root.mkdir(parents=True)
    task = SimpleNamespace(task_id="dvs_12345678", project_id="project-a", is_deleted=False, output_path=str(files_root / "project-a" / "app" / "secflow-app-dataflow-vuln-scan"), source_root_path=str(source_root), input_path=str(source_root))
    db = _Db(task)
    monkeypatch.setattr(knowledge_summary, "_FILESERVER_ROOT", files_root)
    monkeypatch.setattr(knowledge_summary, "_session", lambda: db)
    service = knowledge_summary.KnowledgeSummaryService()
    first = _case()
    first["metadata"] = {"dataflow_vuln_scan": {"output_dir": str(finding_dir)}}
    second = _case(updated_at="2026-08-16T00:00:00")
    second["metadata"] = first["metadata"]

    assert service._create_from_case(first)
    assert service._create_from_case(second)
    assert db.rows[0].decision_fingerprint != db.rows[1].decision_fingerprint


def test_snapshot_evidence_stays_bounded_and_under_fileserver(monkeypatch, tmp_path: Path):
    files_root = tmp_path / "files"
    finding_dir = files_root / "project-a" / "task" / "output" / "vulnerabilities" / "finding-1"
    finding_dir.mkdir(parents=True)
    (finding_dir / "report.md").write_text("evidence", encoding="utf-8")
    (finding_dir / "large.log").write_bytes(b"x" * 100)
    destination = tmp_path / "snapshot"
    monkeypatch.setattr(knowledge_summary, "_FILESERVER_ROOT", files_root)
    monkeypatch.setattr(knowledge_summary, "_EVIDENCE_MAX_FILE_BYTES", 32)
    row = SimpleNamespace(finding_dir=str(finding_dir))

    manifest = knowledge_summary.KnowledgeSummaryService()._snapshot_evidence(row, {}, destination)
    assert manifest["copied_files"] == [{"path": "project-a/task/output/vulnerabilities/finding-1/report.md", "bytes": 8}]
    assert (destination / "project-a/task/output/vulnerabilities/finding-1/report.md").read_text(encoding="utf-8") == "evidence"


def test_enqueue_uses_dedicated_celery_queue(monkeypatch):
    calls = []

    class _Celery:
        def send_task(self, *args, **kwargs):
            calls.append((args, kwargs))

    row = SimpleNamespace(status="queued", celery_task_id=None, dispatch_requested_at=None, last_dispatch_error=None)
    db = _SummaryDb(row)
    monkeypatch.setattr(knowledge_summary, "_session", lambda: db)
    monkeypatch.setitem(sys.modules, "app.celery_app", SimpleNamespace(app=_Celery()))

    assert knowledge_summary.enqueue_knowledge_summary_task("dks_12345678")
    assert calls[0][0] == ("app.celery_tasks.run_knowledge_summary_task",)
    assert calls[0][1]["args"] == ("dks_12345678",)
    assert calls[0][1]["queue"] == "dvs-knowledge-summary"
    assert row.celery_task_id.startswith("dks-dispatch-")


def test_agent_output_requires_full_knowledge_schema():
    incomplete = {"label": "SQL 注入"}
    try:
        knowledge_summary.KnowledgeSummaryOutput.model_validate(incomplete)
    except Exception:
        pass
    else:
        raise AssertionError("incomplete output must be rejected")


def test_knowledge_summary_uses_global_worker_agent_config(monkeypatch):
    class _ConfigService:
        def get_config(self, _db):
            return {
                "project_id": "",
                "updated_at": "2026-08-16T00:00:00",
                "agent_run_timeout_seconds": 900,
                "agent_timeout_retry_enabled": False,
                "agent_timeout_max_retries": 7,
                "pi_max_retries": 5,
                "pi_retry_delay": 2.5,
                "workers": {
                    "default_thinking_level": "low",
                    "agents": [{"model": "local-glm/glm-5.2", "thinking_level": "high"}],
                },
            }

    monkeypatch.setattr(knowledge_summary, "get_config_service", lambda: _ConfigService())
    monkeypatch.setenv("DVS_KNOWLEDGE_SUMMARY_MODEL", "gaiasec/auto")
    monkeypatch.delenv("DVS_KNOWLEDGE_SUMMARY_AGENT_TIMEOUT_SECONDS", raising=False)

    runtime = knowledge_summary._knowledge_summary_agent_runtime(object())

    assert runtime.model == "local-glm/glm-5.2"
    assert runtime.thinking_level == "high"
    assert runtime.run_timeout_seconds == 900
    assert runtime.timeout_retry_enabled is False
    assert runtime.timeout_max_retries == 7
    assert runtime.pi_max_retries == 5
    assert runtime.pi_retry_delay == 2.5


def test_knowledge_summary_requires_configured_worker_agent(monkeypatch):
    class _ConfigService:
        def get_config(self, _db):
            return {"workers": {"agents": []}}

    monkeypatch.setattr(knowledge_summary, "get_config_service", lambda: _ConfigService())

    try:
        knowledge_summary._knowledge_summary_agent_runtime(object())
    except RuntimeError as exc:
        assert "未配置 Worker Agent" in str(exc)
    else:
        raise AssertionError("knowledge summary must not fall back to a hard-coded model")


def test_provider_runtime_sync_uses_service_machine_token(monkeypatch):
    calls = []
    service_yaml = SimpleNamespace(
        configcenter=SimpleNamespace(base_url="http://config-center", timeout=17),
        auth_service=SimpleNamespace(service_machine_token="machine-token"),
    )

    monkeypatch.setattr(llm_provider_sync, "get_service_yaml", lambda: service_yaml, raising=False)
    monkeypatch.setattr("app.config.get_service_yaml", lambda: service_yaml)
    monkeypatch.setattr(
        llm_provider_sync,
        "sync_providers_to_pi",
        lambda **kwargs: calls.append(kwargs) or True,
    )

    assert llm_provider_sync.sync_dvs_provider_runtime(db="db-session")
    assert calls == [{
        "base_url": "http://config-center",
        "token": "machine-token",
        "timeout": 17,
        "db": "db-session",
    }]


def test_readonly_helper_blocks_writes_and_outside_paths(tmp_path: Path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    permitted = allowed / "evidence.txt"
    permitted.write_text("safe", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    helper = Path(__file__).parents[1] / "bin" / "knowledge_summary_readonly.py"
    env = {**os.environ, "DVS_READONLY_ROOTS": str(allowed)}
    def run(command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(helper), "--command", base64.b64encode(command.encode()).decode()],
            env=env, text=True, capture_output=True, check=False,
        )

    assert run(f"cat {permitted}").returncode == 0
    assert run(f"cat {outside}").returncode != 0
    assert run(f"rm {permitted}").returncode != 0
