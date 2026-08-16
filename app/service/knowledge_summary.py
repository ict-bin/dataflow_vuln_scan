"""Human-confirmed DVS finding knowledge-summary worker."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

import httpx
import redis
from pydantic import BaseModel, ConfigDict
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from app.config import get_service_yaml
from app.db.models import AppDvsKnowledgeSummaryScanState, AppDvsKnowledgeSummaryTask, AppDvsTask
from app.models import ServiceConfig
from app.runner import run_agent
from app.runtime_context import INSTANCE_ID
from app.service.config_service import get_config_service
from app.service.llm_provider_sync import sync_dvs_provider_runtime
from app.service.pi_runtime import materialize_pi_runtime
from app.time_utils import now_local

logger = logging.getLogger("dvs.knowledge_summary")

_DVS_TASK_ID_RE = re.compile(r"^dvs_[A-Za-z0-9]{8,64}$")
_LEADER_KEY = os.environ.get("DVS_KNOWLEDGE_SUMMARY_LEADER_KEY", "dvs:knowledge-summary:leader")
_LEADER_TTL_SECONDS = max(30, int(os.environ.get("DVS_KNOWLEDGE_SUMMARY_LEADER_TTL_SECONDS", "90")))
_LEASE_SECONDS = max(60, int(os.environ.get("DVS_KNOWLEDGE_SUMMARY_TASK_LEASE_SECONDS", "1800")))
_POLL_SECONDS = max(10, int(os.environ.get("DVS_KNOWLEDGE_SUMMARY_POLL_SECONDS", "600")))
_MAX_CASE_PAGES = max(1, int(os.environ.get("DVS_KNOWLEDGE_SUMMARY_MAX_CASE_PAGES", "100")))
_CASE_PAGE_SIZE = min(200, max(1, int(os.environ.get("DVS_KNOWLEDGE_SUMMARY_CASE_PAGE_SIZE", "100"))))
_DISPATCH_RETRY_SECONDS = max(30, int(os.environ.get("DVS_KNOWLEDGE_SUMMARY_DISPATCH_RETRY_SECONDS", "300")))
_EVIDENCE_MAX_BYTES = max(64 * 1024, int(os.environ.get("DVS_KNOWLEDGE_SUMMARY_EVIDENCE_MAX_BYTES", str(8 * 1024 * 1024))))
_EVIDENCE_MAX_FILE_BYTES = max(4 * 1024, int(os.environ.get("DVS_KNOWLEDGE_SUMMARY_EVIDENCE_MAX_FILE_BYTES", str(1024 * 1024))))
_SCAN_LOOKBACK_SECONDS = max(60, int(os.environ.get("DVS_KNOWLEDGE_SUMMARY_SCAN_LOOKBACK_SECONDS", "3600")))
_FULL_SCAN_SECONDS = max(3600, int(os.environ.get("DVS_KNOWLEDGE_SUMMARY_FULL_SCAN_SECONDS", "86400")))
_SCANNER_NAME = "dvs-human-confirmed-knowledge-summary-v1"
_FILESERVER_ROOT = Path(os.environ.get("FILESERVER_ROOT", "/data/files")).resolve()


@dataclass(frozen=True)
class _KnowledgeSummaryAgentRuntime:
    model: str
    thinking_level: str
    run_timeout_seconds: int
    timeout_retry_enabled: bool
    timeout_max_retries: int
    pi_max_retries: int
    pi_retry_delay: float


def _knowledge_summary_agent_runtime(db) -> _KnowledgeSummaryAgentRuntime:
    """Resolve the shared DVS Worker Agent configuration for knowledge summaries."""
    config_data = dict(get_config_service().get_config(db))
    config_data.pop("project_id", None)
    config_data.pop("updated_at", None)
    service_config = ServiceConfig(**config_data)
    agents = list(service_config.workers.agents or [])
    if not agents:
        raise RuntimeError("数据流漏洞挖掘 Agent 参数配置中未配置 Worker Agent")
    agent = agents[0]
    model = _text(agent.model)
    if not model:
        raise RuntimeError("数据流漏洞挖掘 Agent 参数配置中的 Worker 模型为空")
    thinking_level = _text(agent.thinking_level) or _text(service_config.workers.default_thinking_level) or "medium"
    timeout_override = _text(os.environ.get("DVS_KNOWLEDGE_SUMMARY_AGENT_TIMEOUT_SECONDS"))
    try:
        run_timeout_seconds = int(timeout_override) if timeout_override else int(service_config.agent_run_timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("知识总结 Agent 超时配置无效") from exc
    if run_timeout_seconds <= 0:
        raise RuntimeError("知识总结 Agent 超时配置必须大于 0")
    return _KnowledgeSummaryAgentRuntime(
        model=model,
        thinking_level=thinking_level,
        run_timeout_seconds=run_timeout_seconds,
        timeout_retry_enabled=bool(service_config.agent_timeout_retry_enabled),
        timeout_max_retries=int(service_config.agent_timeout_max_retries),
        pi_max_retries=int(service_config.pi_max_retries),
        pi_retry_delay=float(service_config.pi_retry_delay),
    )


class KnowledgeSummaryOutput(BaseModel):
    model_config = ConfigDict(extra="allow")
    label: str
    label_reason: str
    attack_precondition: str
    taint_evidence: list[Any] | str
    source_evidence: list[Any] | str
    sink_evidence: list[Any] | str
    path_evidence: list[Any] | str
    valid_signal: list[Any] | str
    invalid_signal: list[Any] | str
    false_positive_or_false_negative_root_cause: str
    reusable_detection_rules: list[Any] | str
    code_pattern: str
    recommended_prompt_or_rule_changes: list[Any] | str
    limitations: list[Any] | str


def _session():
    from app import db as db_module

    if db_module._SessionLocal is None:
        raise RuntimeError("database is not initialized")
    return db_module._SessionLocal()


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: object) -> str:
    return str(value or "").strip()


def _parse_dt(value: object) -> datetime | None:
    raw = _text(value)
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _decision(case: dict[str, Any]) -> str:
    confirmation = _as_dict(case.get("human_confirmation"))
    return _text(
        case.get("confirmation_status")
        or case.get("decision_status")
        or confirmation.get("result")
        or case.get("latest_human_decision")
    ).lower()


def _is_human_confirmed(case: dict[str, Any]) -> bool:
    confirmation = _as_dict(case.get("human_confirmation"))
    return bool(
        case.get("human_confirmed")
        or case.get("is_human_finished")
        or confirmation.get("confirmed_at")
        or confirmation.get("result")
    )


def _fingerprint(case: dict[str, Any], decision: str) -> str:
    confirmation = _as_dict(case.get("human_confirmation"))
    source = {
        "case_id": _text(case.get("id")),
        "decision": decision,
        "confirmed_at": _text(confirmation.get("confirmed_at") or confirmation.get("updated_at") or case.get("confirmed_at")),
        "reason": _text(confirmation.get("reason") or case.get("false_positive_reason") or case.get("confirmation_reason")),
        "updated_at": _text(case.get("updated_at")),
    }
    return hashlib.sha256(json.dumps(source, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def _safe_path(value: str, *, require_exists: bool = False) -> Path | None:
    if not value:
        return None
    try:
        path = Path(value).resolve()
        path.relative_to(_FILESERVER_ROOT)
    except (OSError, ValueError):
        return None
    if require_exists and not path.is_dir():
        return None
    return path


def _extract_json(text: str) -> dict[str, Any]:
    raw = _text(text)
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1] if "\n" in raw else ""
        if raw.rstrip().endswith("```"):
            raw = raw.rstrip()[:-3]
    start = raw.find("{")
    end = raw.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("agent did not return a JSON object")
    result = json.loads(raw[start:end + 1])
    if not isinstance(result, dict):
        raise ValueError("agent result is not an object")
    return result


class _LeaderLease:
    def __init__(self) -> None:
        self.token = f"{INSTANCE_ID}:{uuid.uuid4().hex}"
        self.client = redis.Redis(
            host=os.environ.get("DVS_SCHEDULER_HOST", "secflow-app-dataflow-vuln-scan-scheduler"),
            port=int(os.environ.get("DVS_SCHEDULER_REDIS_PORT", "6379")),
            db=int(os.environ.get("DVS_KNOWLEDGE_SUMMARY_REDIS_DB", "2")),
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3,
        )

    def acquire(self) -> bool:
        return bool(self.client.set(_LEADER_KEY, self.token, nx=True, ex=_LEADER_TTL_SECONDS))

    def renew(self) -> bool:
        return bool(self.client.eval(
            "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('expire', KEYS[1], ARGV[2]) else return 0 end",
            1,
            _LEADER_KEY,
            self.token,
            _LEADER_TTL_SECONDS,
        ))

    def release(self) -> None:
        self.client.eval(
            "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end",
            1,
            _LEADER_KEY,
            self.token,
        )


class _LeaderHeartbeat:
    def __init__(self, lease: _LeaderLease, stop_event: threading.Event) -> None:
        self._lease = lease
        self._stop_event = stop_event
        self._lost = threading.Event()
        self._thread = threading.Thread(target=self._run, name="dvs-knowledge-summary-leader", daemon=True)

    @property
    def held(self) -> bool:
        return not self._lost.is_set()

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._thread.join(timeout=5)

    def _run(self) -> None:
        interval = max(5, _LEADER_TTL_SECONDS // 3)
        while not self._stop_event.wait(interval):
            try:
                if not self._lease.renew():
                    self._lost.set()
                    logger.warning("knowledge summary leader lease was lost")
                    return
            except Exception:
                self._lost.set()
                logger.exception("knowledge summary leader lease renewal failed")
                return


class _ExecutionLeaseHeartbeat:
    def __init__(
        self,
        service: "KnowledgeSummaryService",
        summary_task_id: str,
        epoch: int,
        stop_event: threading.Event,
    ) -> None:
        self._service = service
        self._summary_task_id = summary_task_id
        self._epoch = epoch
        self._stop_event = stop_event
        self._lost = threading.Event()
        self._thread = threading.Thread(target=self._run, name="dvs-knowledge-summary-execution", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._thread.join(timeout=5)

    @property
    def lost(self) -> bool:
        return self._lost.is_set()

    def _run(self) -> None:
        interval = max(15, _LEASE_SECONDS // 3)
        while not self._stop_event.wait(interval):
            try:
                if not self._service._renew_execution_lease(self._summary_task_id, self._epoch):
                    self._lost.set()
                    self._stop_event.set()
                    logger.warning("knowledge summary execution lease was lost: %s", self._summary_task_id)
                    return
            except Exception:
                self._lost.set()
                self._stop_event.set()
                logger.exception("knowledge summary execution lease renewal failed: %s", self._summary_task_id)
                return


class KnowledgeSummaryService:
    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._lease = _LeaderLease()

    def stop(self) -> None:
        self._stop_event.set()

    def run_forever(self) -> None:
        while not self._stop_event.is_set():
            try:
                if self._lease.acquire() or self._lease.renew():
                    heartbeat_stop = threading.Event()
                    heartbeat = _LeaderHeartbeat(self._lease, heartbeat_stop)
                    heartbeat.start()
                    created = self.scan_once(lambda: heartbeat.held and not self._stop_event.is_set())
                    dispatched = self.dispatch_queued(lambda: heartbeat.held and not self._stop_event.is_set())
                    heartbeat.stop()
                    self._lease.release()
                    logger.info("knowledge summary tick completed: created=%s dispatched=%s", created, dispatched)
            except Exception:
                logger.exception("knowledge summary tick failed")
                self._record_scan_error("knowledge summary scheduler tick failed")
            self._stop_event.wait(_POLL_SECONDS)

    def _record_scan_error(self, message: str) -> None:
        try:
            db = _session()
            try:
                state = self._scan_state(db)
                state.leader_instance_id = INSTANCE_ID
                state.last_error = message
                db.commit()
            finally:
                db.close()
        except Exception:
            logger.exception("failed to persist knowledge summary scan error")

    def _list_cases(self, cutoff: datetime | None, active: Callable[[], bool]) -> list[dict[str, Any]]:
        cfg = get_service_yaml()
        token = _text(os.environ.get("DVS_VULN_ENGINE_TOKEN") or cfg.auth_service.service_machine_token)
        if not token:
            raise RuntimeError("missing service machine token for vulnerability-center read")
        base_url = os.environ.get("DVS_VULN_ENGINE_BASE_URL", "http://secflow-platform-vuln").rstrip("/")
        result: list[dict[str, Any]] = []
        with httpx.Client(timeout=float(os.environ.get("DVS_KNOWLEDGE_SUMMARY_HTTP_TIMEOUT_SECONDS", "30"))) as client:
            for page in range(1, _MAX_CASE_PAGES + 1):
                if not active():
                    break
                response = client.get(
                    f"{base_url}/api/vuln/cases",
                    headers={"Authorization": f"Bearer {token}"},
                    params={
                        "tool_name": "kg_source_vuln_scan_e2e",
                        "human_confirmed": "true",
                        "confirmation_status": "vulnerable,not_vulnerable",
                        "sort_field": "updated_at",
                        "sort_direction": "desc",
                        "page": page,
                        "page_size": _CASE_PAGE_SIZE,
                    },
                )
                response.raise_for_status()
                body = response.json()
                items = body.get("items") if isinstance(body, dict) else []
                if not isinstance(items, list) or not items:
                    break
                page_items = [item for item in items if isinstance(item, dict)]
                if cutoff:
                    result.extend(item for item in page_items if (_parse_dt(item.get("updated_at")) or cutoff) >= cutoff)
                    timestamps = [_parse_dt(item.get("updated_at")) for item in page_items]
                    if timestamps and all(timestamp and timestamp < cutoff for timestamp in timestamps):
                        break
                else:
                    result.extend(page_items)
                if len(items) < _CASE_PAGE_SIZE:
                    break
        return result

    def _scan_state(self, db) -> AppDvsKnowledgeSummaryScanState:
        state = db.query(AppDvsKnowledgeSummaryScanState).filter_by(scanner_name=_SCANNER_NAME).one_or_none()
        if state is None:
            state = AppDvsKnowledgeSummaryScanState(scanner_name=_SCANNER_NAME)
            db.add(state)
            db.flush()
        return state

    def scan_once(self, active: Callable[[], bool] = lambda: True) -> int:
        db = _session()
        try:
            state = self._scan_state(db)
            now = now_local()
            full_scan = not state.last_full_scan_at or state.last_full_scan_at < now - timedelta(seconds=_FULL_SCAN_SECONDS)
            cutoff = None if full_scan or not state.watermark_updated_at else state.watermark_updated_at - timedelta(seconds=_SCAN_LOOKBACK_SECONDS)
        finally:
            db.close()
        created = 0
        skipped = 0
        cases = self._list_cases(cutoff, active)
        latest_updated_at: datetime | None = None
        for case in cases:
            if not active():
                break
            if self._create_from_case(case):
                created += 1
            if not _DVS_TASK_ID_RE.fullmatch(_text(_as_dict(case.get("source_task")).get("run_id"))) or _decision(case) not in {"vulnerable", "not_vulnerable"}:
                skipped += 1
            updated_at = _parse_dt(case.get("updated_at"))
            if updated_at and (latest_updated_at is None or updated_at > latest_updated_at):
                latest_updated_at = updated_at
        if active():
            db = _session()
            try:
                state = self._scan_state(db)
                state.last_successful_scan_at = now_local()
                state.leader_instance_id = INSTANCE_ID
                state.last_scan_case_count = len(cases)
                state.last_created_count = created
                state.last_skipped_count = skipped
                state.last_error = None
                if latest_updated_at:
                    state.watermark_updated_at = latest_updated_at
                if full_scan:
                    state.last_full_scan_at = now_local()
                db.commit()
            finally:
                db.close()
        return created

    def dispatch_queued(self, active: Callable[[], bool] = lambda: True) -> int:
        """Publish queued work to the dedicated Celery queue; DB state remains authoritative."""
        db = _session()
        try:
            retry_before = now_local() - timedelta(seconds=_DISPATCH_RETRY_SECONDS)
            rows = db.query(AppDvsKnowledgeSummaryTask).filter(
                AppDvsKnowledgeSummaryTask.status == "queued",
                or_(
                    AppDvsKnowledgeSummaryTask.dispatch_requested_at.is_(None),
                    AppDvsKnowledgeSummaryTask.dispatch_requested_at < retry_before,
                ),
            ).order_by(AppDvsKnowledgeSummaryTask.created_at.asc()).limit(100).all()
            task_ids = [row.summary_task_id for row in rows]
        finally:
            db.close()
        dispatched = 0
        for summary_task_id in task_ids:
            if not active():
                break
            if enqueue_knowledge_summary_task(summary_task_id):
                dispatched += 1
        if active():
            db = _session()
            try:
                state = self._scan_state(db)
                state.last_dispatched_count = dispatched
                state.leader_instance_id = INSTANCE_ID
                db.commit()
            finally:
                db.close()
        return dispatched

    def _create_from_case(self, case: dict[str, Any]) -> bool:
        source_task = _as_dict(case.get("source_task"))
        dvs_task_id = _text(source_task.get("run_id"))
        decision = _decision(case)
        case_id = _text(case.get("id")) or f"invalid-{hashlib.sha256(json.dumps(case, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24]}"
        project_id = _text(case.get("project_id"))
        fingerprint = _fingerprint({**case, "id": case_id}, decision or "invalid")
        db = _session()
        try:
            if not _is_human_confirmed(case):
                return self._create_skipped(db, case, case_id, project_id, fingerprint, "漏洞中心记录未人工确认")
            if decision not in {"vulnerable", "not_vulnerable"}:
                return self._create_skipped(db, case, case_id, project_id, fingerprint, "人工确认结论不是 vulnerable/not_vulnerable")
            if not _DVS_TASK_ID_RE.fullmatch(dvs_task_id):
                return self._create_skipped(db, case, case_id, project_id, fingerprint, "source_task.run_id 缺失或不是 DVS 子任务 ID")
            if not project_id:
                return self._create_skipped(db, case, case_id, "unknown", fingerprint, "漏洞中心记录缺少 project_id")
            source_task_row = db.query(AppDvsTask).filter(
                AppDvsTask.task_id == dvs_task_id,
                AppDvsTask.project_id == project_id,
                AppDvsTask.is_deleted.is_(False),
            ).one_or_none()
            if source_task_row is None:
                return self._create_skipped(db, case, case_id, project_id, fingerprint, "DVS 子任务不存在或项目不一致")
            metadata = _as_dict(case.get("metadata"))
            dataflow_meta = _as_dict(metadata.get("dataflow_vuln_scan"))
            finding_id = _text(source_task.get("finding_id") or dataflow_meta.get("finding_id"))
            task_root = self._resolve_task_root(source_task_row)
            if task_root is None:
                return self._create_skipped(db, case, case_id, project_id, fingerprint, "无法定位原始 DVS 任务目录")
            source_root = _safe_path(_text(source_task_row.source_root_path or source_task_row.input_path), require_exists=True)
            if source_root is None:
                return self._create_skipped(db, case, case_id, project_id, fingerprint, "原始 DVS 源码根目录不存在或越界")
            finding_dir = self._resolve_finding_dir(task_root, finding_id, _text(dataflow_meta.get("output_dir")))
            if finding_dir is None:
                return self._create_skipped(db, case, case_id, project_id, fingerprint, "无法定位当前 finding 的漏洞输出目录")
            output_dir = _FILESERVER_ROOT / project_id / "app" / "secflow-app-dataflow-vuln-scan" / "knowledge-summary"
            snapshot = dict(case)
            snapshot["knowledge_summary_source_root"] = str(source_root)
            existing = db.query(AppDvsKnowledgeSummaryTask).filter(
                AppDvsKnowledgeSummaryTask.case_id == case_id,
                AppDvsKnowledgeSummaryTask.decision_fingerprint == fingerprint,
            ).one_or_none()
            if existing is not None:
                if existing.status != "skipped":
                    return False
                row = existing
                row.project_id = project_id
                row.dvs_task_id = dvs_task_id
                row.finding_id = finding_id or None
                row.decision = decision
                row.human_confirmed_at = _parse_dt(_as_dict(case.get("human_confirmation")).get("confirmed_at") or case.get("confirmed_at"))
                row.case_updated_at = _parse_dt(case.get("updated_at"))
                row.status = "queued"
                row.source_snapshot_json = snapshot
                row.result_json = None
                row.error_message = None
                row.task_root = str(task_root)
                row.finding_dir = str(finding_dir) if finding_dir else None
                row.output_dir = str(output_dir)
                row.execution_owner_id = None
                row.lease_until = None
                row.celery_task_id = None
                row.dispatch_requested_at = None
                row.last_dispatch_error = None
                row.finished_at = None
            else:
                row = AppDvsKnowledgeSummaryTask(
                    summary_task_id=f"dks_{uuid.uuid4().hex[:16]}",
                    project_id=project_id,
                    case_id=case_id,
                    dvs_task_id=dvs_task_id,
                    finding_id=finding_id or None,
                    decision=decision,
                    decision_fingerprint=fingerprint,
                    human_confirmed_at=_parse_dt(_as_dict(case.get("human_confirmation")).get("confirmed_at") or case.get("confirmed_at")),
                    case_updated_at=_parse_dt(case.get("updated_at")),
                    status="queued",
                    source_snapshot_json=snapshot,
                    task_root=str(task_root),
                    finding_dir=str(finding_dir) if finding_dir else None,
                    output_dir=str(output_dir),
                )
                db.add(row)
                db.flush()
            db.query(AppDvsKnowledgeSummaryTask).filter(
                AppDvsKnowledgeSummaryTask.case_id == case_id,
                AppDvsKnowledgeSummaryTask.summary_task_id != row.summary_task_id,
                AppDvsKnowledgeSummaryTask.status.in_(("queued", "running", "succeeded", "failed")),
            ).update({
                AppDvsKnowledgeSummaryTask.status: "superseded",
                AppDvsKnowledgeSummaryTask.superseded_by_task_id: row.summary_task_id,
                AppDvsKnowledgeSummaryTask.superseded_at: now_local(),
            }, synchronize_session=False)
            db.commit()
            return True
        except IntegrityError:
            db.rollback()
            return False
        finally:
            db.close()

    def _resolve_task_root(self, task: AppDvsTask) -> Path | None:
        output_base = _safe_path(_text(task.output_path))
        candidate = output_base / task.task_id if output_base else None
        if candidate and candidate.is_dir():
            return candidate
        fallback = _FILESERVER_ROOT / task.project_id / "app" / "secflow-app-dataflow-vuln-scan" / task.task_id
        return fallback if fallback.is_dir() else None

    def _resolve_finding_dir(self, task_root: Path, finding_id: str, metadata_path: str) -> Path | None:
        metadata_dir = _safe_path(metadata_path, require_exists=True)
        if metadata_dir:
            try:
                metadata_dir.relative_to(task_root)
                return metadata_dir
            except ValueError:
                return None
        if not finding_id:
            return None
        vulnerabilities_root = task_root / "output" / "vulnerabilities"
        if not vulnerabilities_root.is_dir():
            return None
        direct = vulnerabilities_root / finding_id
        if direct.is_dir():
            return direct.resolve()
        matches = [path.resolve() for path in vulnerabilities_root.rglob(finding_id) if path.is_dir()]
        return matches[0] if len(matches) == 1 else None

    def _create_skipped(self, db, case: dict[str, Any], case_id: str, project_id: str, fingerprint: str, reason: str) -> bool:
        source_task = _as_dict(case.get("source_task"))
        try:
            db.add(AppDvsKnowledgeSummaryTask(
                summary_task_id=f"dks_{uuid.uuid4().hex[:16]}",
                project_id=project_id,
                case_id=case_id,
                dvs_task_id=_text(source_task.get("run_id")) or "unknown",
                finding_id=_text(source_task.get("finding_id")) or None,
                decision=_decision(case) or "invalid",
                decision_fingerprint=fingerprint,
                status="skipped",
                source_snapshot_json=case,
                error_message=reason,
                task_root="",
                output_dir="",
                finished_at=now_local(),
            ))
            db.commit()
            return True
        except IntegrityError:
            db.rollback()
            return False

    def run_task(self, summary_task_id: str) -> bool:
        db = _session()
        try:
            now = now_local()
            row = db.query(AppDvsKnowledgeSummaryTask).filter(
                AppDvsKnowledgeSummaryTask.summary_task_id == summary_task_id,
                AppDvsKnowledgeSummaryTask.status == "queued",
                or_(AppDvsKnowledgeSummaryTask.lease_until.is_(None), AppDvsKnowledgeSummaryTask.lease_until < now),
            ).with_for_update(skip_locked=True).one_or_none()
            if row is None:
                return False
            row.status = "running"
            row.execution_owner_id = INSTANCE_ID
            row.execution_epoch += 1
            row.attempt_count += 1
            row.lease_until = now + timedelta(seconds=_LEASE_SECONDS)
            row.started_at = now
            row.error_message = None
            db.commit()
            task_id = row.summary_task_id
            epoch = row.execution_epoch
        finally:
            db.close()
        heartbeat_stop = threading.Event()
        heartbeat = _ExecutionLeaseHeartbeat(self, task_id, epoch, heartbeat_stop)
        heartbeat.start()
        self._execute(task_id, epoch, heartbeat_stop)
        heartbeat.stop()
        return True

    def _renew_execution_lease(self, summary_task_id: str, epoch: int) -> bool:
        db = _session()
        try:
            row = db.query(AppDvsKnowledgeSummaryTask).filter(
                AppDvsKnowledgeSummaryTask.summary_task_id == summary_task_id,
                AppDvsKnowledgeSummaryTask.execution_owner_id == INSTANCE_ID,
                AppDvsKnowledgeSummaryTask.execution_epoch == epoch,
                AppDvsKnowledgeSummaryTask.status == "running",
            ).one_or_none()
            if row is None:
                return False
            row.lease_until = now_local() + timedelta(seconds=_LEASE_SECONDS)
            db.commit()
            return True
        finally:
            db.close()

    def _execute(self, summary_task_id: str, epoch: int, cancel_event: threading.Event) -> None:
        db = _session()
        try:
            row = db.query(AppDvsKnowledgeSummaryTask).filter_by(summary_task_id=summary_task_id).one()
            task_dir = _safe_path(row.output_dir)
            if task_dir is None:
                raise RuntimeError("knowledge output directory escapes fileserver")
            task_dir = task_dir / summary_task_id
            input_dir = task_dir / "input"
            output_dir = task_dir / "output"
            sessions_dir = task_dir / "sessions"
            for path in (input_dir, output_dir, sessions_dir):
                path.mkdir(parents=True, exist_ok=True)
            snapshot = _as_dict(row.source_snapshot_json)
            source_task = _as_dict(snapshot.get("source_task"))
            source_context = {
                "case_id": row.case_id,
                "human_decision": row.decision,
                "dvs_task_id": row.dvs_task_id,
                "finding_id": row.finding_id,
                "task_root": row.task_root,
                "finding_dir": row.finding_dir,
                "source_root": _text(snapshot.get("knowledge_summary_source_root")),
                "source_file": source_task.get("source_file"),
                "function_name": source_task.get("function_name"),
                "line": source_task.get("line"),
            }
            (input_dir / "case.json").write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
            (input_dir / "source-context.json").write_text(json.dumps(source_context, ensure_ascii=False, indent=2), encoding="utf-8")
            evidence = self._snapshot_evidence(row, source_task, input_dir / "evidence")
            (input_dir / "evidence-manifest.json").write_text(
                json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            prompt = (
                "基于 input/case.json、input/source-context.json 和授权目录中的只读证据总结一条经过人工确认的数据流漏洞知识。"
                "人工结论是唯一事实基准；必须解释原始自动分析与人工结论一致或冲突的原因。"
                "仅输出一个 JSON 对象，字段必须包含 label、label_reason、attack_precondition、"
                "taint_evidence、source_evidence、sink_evidence、path_evidence、valid_signal、invalid_signal、"
                "false_positive_or_false_negative_root_cause、reusable_detection_rules、code_pattern、"
                "recommended_prompt_or_rule_changes、limitations。"
            )
            source_root = _safe_path(_text(snapshot.get("knowledge_summary_source_root")), require_exists=True)
            authorized_roots = [task_dir, Path(row.task_root)]
            if row.finding_dir:
                authorized_roots.append(Path(row.finding_dir))
            if source_root:
                authorized_roots.append(source_root)
            agent_runtime = _knowledge_summary_agent_runtime(db)
            if not sync_dvs_provider_runtime(db):
                raise RuntimeError("知识总结 Agent Provider 运行时同步失败")
            materialize_pi_runtime(secret="")
            logger.info(
                "knowledge summary agent runtime resolved source=dvs_global_workers_config model=%s thinking_level=%s",
                agent_runtime.model,
                agent_runtime.thinking_level,
            )
            result = run_agent(
                prompt,
                model=agent_runtime.model,
                tools=["bash"],
                system_prompt="你是软件安全知识工程师。只总结证据充分的可复用知识，不得改变任何原始文件。",
                cwd=str(task_dir),
                session_file=str(sessions_dir / "knowledge-summary.jsonl"),
                thinking_level=agent_runtime.thinking_level,
                run_timeout_seconds=agent_runtime.run_timeout_seconds,
                timeout_retry_enabled=agent_runtime.timeout_retry_enabled,
                timeout_max_retries=agent_runtime.timeout_max_retries,
                pi_max_retries=agent_runtime.pi_max_retries,
                pi_retry_delay=agent_runtime.pi_retry_delay,
                cancel_event=cancel_event,
                env={"DVS_READONLY_ROOTS": ":".join(str(path.resolve()) for path in authorized_roots if path and path.is_dir())},
                extension="/opt/dataflow_vuln_scan/extensions/knowledge-summary-readonly.ts",
                task_context={"agent_role": "knowledge-summary"},
            )
            if result.error:
                raise RuntimeError(result.error)
            knowledge = KnowledgeSummaryOutput.model_validate(_extract_json(result.output)).model_dump(mode="json")
            (output_dir / "knowledge.json").write_text(json.dumps(knowledge, ensure_ascii=False, indent=2), encoding="utf-8")
            markdown = f"# 漏洞知识总结\n\n- Case: `{row.case_id}`\n- DVS 子任务: `{row.dvs_task_id}`\n- 人工结论: `{row.decision}`\n\n```json\n{json.dumps(knowledge, ensure_ascii=False, indent=2)}\n```\n"
            (output_dir / "knowledge.md").write_text(markdown, encoding="utf-8")
            if row.execution_owner_id != INSTANCE_ID or row.execution_epoch != epoch or row.status != "running":
                raise RuntimeError("knowledge summary execution lease was lost before result commit")
            row.status = "succeeded"
            row.result_json = knowledge
            row.finished_at = now_local()
            row.lease_until = None
            db.commit()
        except Exception as exc:
            db.rollback()
            row = db.query(AppDvsKnowledgeSummaryTask).filter_by(summary_task_id=summary_task_id).one_or_none()
            if row and row.execution_owner_id == INSTANCE_ID and row.execution_epoch == epoch:
                row.status = "failed"
                row.error_message = str(exc)[:8000]
                row.lease_until = None
                row.finished_at = now_local()
                db.commit()
            logger.exception("knowledge summary execution failed: %s", summary_task_id)
        finally:
            db.close()

    def _snapshot_evidence(
        self,
        row: AppDvsKnowledgeSummaryTask,
        source_task: dict[str, Any],
        destination: Path,
    ) -> dict[str, Any]:
        """Copy bounded, relevant evidence so the agent never needs original task-directory access."""
        destination.mkdir(parents=True, exist_ok=True)
        candidates: list[Path] = []
        finding_dir = _safe_path(row.finding_dir or "", require_exists=True)
        if finding_dir:
            candidates.append(finding_dir)
        source_file = _safe_path(_text(source_task.get("source_file")))
        if source_file and source_file.is_file():
            candidates.append(source_file)
        copied: list[dict[str, Any]] = []
        remaining = _EVIDENCE_MAX_BYTES
        for candidate in candidates:
            if remaining <= 0:
                break
            files = [candidate] if candidate.is_file() else sorted(path for path in candidate.rglob("*") if path.is_file())
            for source in files:
                if remaining <= 0:
                    break
                try:
                    size = source.stat().st_size
                    relative = source.relative_to(_FILESERVER_ROOT)
                except (OSError, ValueError):
                    continue
                if size > _EVIDENCE_MAX_FILE_BYTES or size > remaining:
                    continue
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                copied.append({"path": str(relative), "bytes": size})
                remaining -= size
        return {
            "copied_files": copied,
            "copied_bytes": _EVIDENCE_MAX_BYTES - remaining,
            "max_bytes": _EVIDENCE_MAX_BYTES,
        }


def get_knowledge_summary_service() -> KnowledgeSummaryService:
    return KnowledgeSummaryService()


def enqueue_knowledge_summary_task(summary_task_id: str) -> bool:
    """Persist dispatch metadata only after Celery accepts the dedicated work message."""
    celery_task_id = f"dks-dispatch-{uuid.uuid4().hex}"
    try:
        from app.celery_app import app as celery_app

        celery_app.send_task(
            "app.celery_tasks.run_knowledge_summary_task",
            args=(summary_task_id,),
            task_id=celery_task_id,
            queue="dvs-knowledge-summary",
        )
    except Exception as exc:
        db = _session()
        try:
            row = db.query(AppDvsKnowledgeSummaryTask).filter_by(summary_task_id=summary_task_id).one_or_none()
            if row and row.status == "queued":
                row.last_dispatch_error = str(exc)[:8000]
                db.commit()
        finally:
            db.close()
        logger.exception("knowledge summary Celery dispatch failed: %s", summary_task_id)
        return False

    db = _session()
    try:
        row = db.query(AppDvsKnowledgeSummaryTask).filter_by(summary_task_id=summary_task_id).one_or_none()
        if row and row.status == "queued":
            row.celery_task_id = celery_task_id
            row.dispatch_requested_at = now_local()
            row.last_dispatch_error = None
            db.commit()
    finally:
        db.close()
    return True
