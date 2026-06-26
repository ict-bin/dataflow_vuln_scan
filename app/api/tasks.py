"""Task management API routes for dataflow-vuln-scan."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import httpx
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db import get_db
from app.db.models import AppDvsTask
from app.time_utils import isoformat_local
from app.service.worker_snapshot import build_worker_cluster_snapshot
from app.service.session_index import build_session_catalog
from app.service.task_service import generate_prompt_from_path, get_task_service
from app.vuln_graph_service import load_vuln_scan_graph, summarize_graph, build_trace_tree
from .deps import ensure_admin_user, ensure_project_access, get_current_user
from .task_models import (
    TaskCreateRequest,
    GeneratePromptRequest,
    TaskSessionIndexNodeResponse,
    TaskSessionIndexEdgeResponse,
    TaskSessionIndexGroupResponse,
    TaskSessionIndexResponse,
    WorkerActiveJobResponse,
    WorkerCapacityResponse,
    WorkerClusterCapacityResponse,
    AgentProcessSnapshotResponse,
    AgentTaskOwnershipSnapshotResponse,
    AgentPodSnapshotResponse,
    AgentObservabilitySummaryResponse,
    AgentProcessKillItemResponse,
    AgentProcessKillResponse,
    AgentRuntimeAggregateSummaryResponse,
    AgentRuntimeAggregateResponse,
    TaskTimelineEventResponse,
    TaskTimelineResponse,
    ActionResponse,
    TaskListStatsResponse,
)

from . import router

logger = logging.getLogger(__name__)
internal_observability_router = APIRouter(prefix="/api/app/dataflow-vuln-scan")
AGGREGATE_HTTP_TIMEOUT_SECONDS = float(os.environ.get("DVS_AGENT_AGGREGATE_TIMEOUT_SECONDS", "3"))
AGGREGATE_HTTP_PORT = int(os.environ.get("DVS_AGENT_AGGREGATE_PORT", os.environ.get("PORT", "3000")))
AGGREGATE_CACHE_TTL_SECONDS = max(0.0, float(os.environ.get("DVS_AGENT_AGGREGATE_CACHE_TTL_SECONDS", "2.5")))
_LAST_AGENT_AGGREGATE_META: dict[str, Any] = {
    "partial": False,
    "sources": 0,
    "fanout_errors": 0,
    "duration_seconds": 0.0,
    "cache_hit": False,
    "cache_age_seconds": 0.0,
    "failed_targets": [],
    "cache_hits": 0,
    "cache_misses": 0,
}
_AGENT_AGGREGATE_CACHE: dict[str, dict[str, Any]] = {}
_AGENT_AGGREGATE_SUMMARY_CACHE: dict[str, dict[str, Any]] = {}
AGGREGATE_CONCURRENCY = max(1, int(os.environ.get("DVS_AGENT_AGGREGATE_CONCURRENCY", "8")))


TERMINAL_STATUSES = {"passed", "failed", "error", "cancelled", "invalid_input", "completed_limited"}



def _auth_headers_from_token(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _agent_cache_key() -> str:
    return "__global__"


def _snapshot_query_params() -> dict[str, Any]:
    return {}


def _resolve_worker_targets(*, pod_ip: str | None, pod_name: str | None) -> list[str]:
    targets: list[str] = []
    normalized_ip = str(pod_ip or "").strip()
    if normalized_ip:
        targets.append(normalized_ip)
    normalized_name = str(pod_name or "").strip()
    if normalized_name and normalized_name not in targets:
        targets.append(normalized_name)
    return targets


def _resolve_worker_http_port(worker) -> int:
    try:
        return max(1, int(getattr(worker, "http_port", 0) or 8080))
    except Exception:
        return 8080


def _aggregate_base_urls(worker) -> list[str]:
    targets: list[str] = []
    pod_ip = str(getattr(worker, "pod_ip", "") or "").strip()
    pod_name = str(getattr(worker, "pod_name", "") or "").strip()
    http_port = _resolve_worker_http_port(worker)
    for host in _resolve_worker_targets(pod_ip=pod_ip, pod_name=pod_name):
        if not host:
            continue
        targets.append(f"http://{host}:{http_port}/api/app/dataflow-vuln-scan")
    return targets


def _fanout_get_json(urls: list[str], *, path: str, token: str, params: dict[str, Any]) -> tuple[Any | None, str | None, dict[str, Any] | None]:
    headers = _auth_headers_from_token(token)
    with httpx.AsyncClient(timeout=AGGREGATE_HTTP_TIMEOUT_SECONDS) as client:
        for base_url in urls:
            url = f"{base_url}{path}"
            try:
                response = client.get(url, headers=headers, params=params)
                if response.status_code == 200:
                    return response.json(), base_url, None
                logger.warning("dvs-agent-fanout http_error url=%s status=%s body=%s", url, response.status_code, response.text[:200])
                return None, None, {"attempted_url": url, "error_kind": "http_error", "status_code": response.status_code, "message": response.text[:200]}
            except httpx.ConnectTimeout:
                logger.warning("dvs-agent-fanout connect_timeout url=%s", url)
                return None, None, {"attempted_url": url, "error_kind": "connect_timeout", "status_code": None, "message": "connect timeout"}
            except httpx.ConnectError:
                logger.warning("dvs-agent-fanout connection_refused url=%s", url)
                return None, None, {"attempted_url": url, "error_kind": "connection_refused", "status_code": None, "message": "connection refused"}
            except Exception as exc:
                logger.warning("dvs-agent-fanout transport_error url=%s", url, exc_info=True)
                return None, None, {"attempted_url": url, "error_kind": "transport_error", "status_code": None, "message": str(exc)}
    return None, None, {"attempted_url": None, "error_kind": "no_target", "status_code": None, "message": "no target responded"}


def _summary_with_meta(summary: dict[str, Any], *, cache_hit: bool, cache_age_seconds: float = 0.0) -> dict[str, Any]:
    row = dict(summary or {})
    row["aggregate_cache_hit"] = cache_hit
    row["aggregate_cache_age_seconds"] = cache_age_seconds
    return row


def _failed_target_label(worker) -> str:
    return str(getattr(worker, "pod_name", "") or getattr(worker, "worker_id", "") or "unknown")


def _failed_target_detail(worker, urls: list[str], error_detail: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "pod_name": getattr(worker, "pod_name", None),
        "pod_ip": getattr(worker, "pod_ip", None),
        "http_port": _resolve_worker_http_port(worker),
        "attempted_urls": urls,
        "error_kind": (error_detail or {}).get("error_kind"),
        "status_code": (error_detail or {}).get("status_code"),
        "message": (error_detail or {}).get("message"),
        "attempted_url": (error_detail or {}).get("attempted_url"),
    }


def _get_agent_observability_snapshot_impl(
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    _, _token = user_and_token
    from app.service.agent_observability import get_agent_observability_service

    return get_agent_observability_service().build_snapshot(db, project_id=None)


@router.get("/agent-observability/snapshot")
def get_agent_observability_snapshot(
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    return _get_agent_observability_snapshot_impl(db=db, user_and_token=user_and_token)


@internal_observability_router.get("/agent-observability/snapshot", response_model=dict[str, Any], include_in_schema=False)
def get_internal_agent_observability_snapshot(
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    return _get_agent_observability_snapshot_impl(db=db, user_and_token=user_and_token)


def _build_agent_aggregate_snapshot(token: str, db: Session) -> dict[str, Any]:
    now_ts = __import__("time").time()
    cache_key = _agent_cache_key()
    cached = _AGENT_AGGREGATE_CACHE.get(cache_key)
    if cached and (now_ts - float(cached.get("created_at") or 0.0)) <= AGGREGATE_CACHE_TTL_SECONDS:
        cache_age = now_ts - float(cached.get("created_at") or 0.0)
        meta = cached.get("meta") or {}
        _LAST_AGENT_AGGREGATE_META.update({
            "partial": bool(meta.get("partial")),
            "sources": int(meta.get("sources") or 0),
            "fanout_errors": int(meta.get("fanout_errors") or 0),
            "duration_seconds": float(meta.get("duration_seconds") or 0.0),
            "cache_hit": True,
            "cache_age_seconds": cache_age,
            "failed_targets": list(meta.get("failed_targets") or []),
            "cache_hits": int(_LAST_AGENT_AGGREGATE_META.get("cache_hits") or 0) + 1,
        })
        cached_snapshot = dict(cached["snapshot"])
        cached_snapshot["summary"] = _summary_with_meta(
            cached_snapshot.get("summary") or {},
            cache_hit=True,
            cache_age_seconds=cache_age,
        )
        return cached_snapshot

    started = __import__("time").perf_counter()
    local_snapshot = get_task_service()  # ensure task service initialized
    del local_snapshot
    from app.service.agent_observability import get_agent_observability_service

    local = get_agent_observability_service().build_snapshot(db, project_id=None)
    cluster_snapshot = build_worker_cluster_snapshot(db, project_id=None)
    workers = [worker for worker in cluster_snapshot.workers if worker.healthy and _resolve_worker_targets(pod_ip=worker.pod_ip, pod_name=worker.pod_name)]
    total_target_pods = len(workers)
    total_healthy_pods = sum(1 for worker in workers if worker.healthy)

    merged_processes: list[dict[str, Any]] = []
    merged_tasks: list[dict[str, Any]] = []
    pod_rows: list[dict[str, Any]] = []
    sources = 0
    partial = False
    fanout_errors = 0
    failed_targets: list[str] = []
    failed_target_details: list[dict[str, Any]] = []
    seen_pods: set[str] = set()
    seen_process_keys: set[tuple[str, int]] = set()
    seen_task_keys: set[tuple[str, str]] = set()

    work_items: list[tuple[Any, list[str]]] = []
    for worker in workers:
        urls = _aggregate_base_urls(worker)
        if not urls:
            partial = True
            fanout_errors += 1
            failed_targets.append(_failed_target_label(worker))
            failed_target_details.append(_failed_target_detail(worker, urls, {"error_kind": "missing_target", "status_code": None, "message": "worker has no reachable aggregate targets", "attempted_url": None}))
            continue
        work_items.append((worker, urls))

    semaphore = threading.Semaphore(AGGREGATE_CONCURRENCY)

    def _fetch_worker_snapshot(worker, urls: list[str]) -> tuple[Any, list[str], Any | None, str | None, dict[str, Any] | None]:
        with semaphore:
            worker_snapshot, process_source, error_detail = _fanout_get_json(urls, path="/agent-observability/snapshot", token=token, params=_snapshot_query_params())
            return worker, urls, worker_snapshot, process_source, error_detail

    # Parallel fetch using ThreadPoolExecutor
    from concurrent.futures import ThreadPoolExecutor, as_completed
    snapshot_results = []
    if work_items:
        with ThreadPoolExecutor(max_workers=AGGREGATE_CONCURRENCY) as _exec:
            _futures = {_exec.submit(_fetch_worker_snapshot, w, urls): (w, urls) for w, urls in work_items}
            for _f in as_completed(_futures):
                snapshot_results.append(_f.result())
    for worker, urls, worker_snapshot, process_source, error_detail in snapshot_results:
        if worker_snapshot is None:
            partial = True
            fanout_errors += 1
            failed_targets.append(_failed_target_label(worker))
            failed_target_details.append(_failed_target_detail(worker, urls, error_detail))
            continue
        sources += 1
        if process_source:
            logger.info("dvs agent aggregate source=%s", process_source)
        for item in worker_snapshot.get("processes") or []:
            key = (str(item.get("pod_name") or ""), int(item.get("pid") or 0))
            if key in seen_process_keys:
                continue
            seen_process_keys.add(key)
            merged_processes.append(item)
            seen_pods.add(str(item.get("pod_name") or ""))
        for item in worker_snapshot.get("tasks") or []:
            key = (str(item.get("pod_name") or ""), str(item.get("task_id") or ""))
            if key in seen_task_keys:
                continue
            seen_task_keys.add(key)
            merged_tasks.append(item)
        for item in worker_snapshot.get("pods") or []:
            pod_name = str(item.get("pod_name") or "")
            if pod_name in seen_pods:
                pod_rows = [row for row in pod_rows if str(row.get("pod_name") or "") != pod_name]
            pod_rows.append(item)
            seen_pods.add(pod_name)

    all_sources_failed = bool(workers) and sources == 0 and fanout_errors > 0
    if not workers:
        merged_processes = list(local.get("processes") or [])
        merged_tasks = list(local.get("tasks") or [])
        pod_rows = list(local.get("pods") or [])
        sources = 1
        partial = False
        all_sources_failed = False
        total_target_pods = len(pod_rows)
        total_healthy_pods = len([row for row in pod_rows if bool(row.get("healthy", True))])

    summary = {
        "pod_name": "dvs-aggregate",
        "active_processes": len([item for item in merged_processes if str(item.get("owner_kind") or "") == "tracked"]),
        "residual_processes": len([item for item in merged_processes if str(item.get("owner_kind") or "") == "residual"]),
        "unknown_processes": len([item for item in merged_processes if str(item.get("owner_kind") or "") == "unknown"]),
        "killable_residual_processes": len([item for item in merged_processes if str(item.get("owner_kind") or "") == "residual" and bool(item.get("kill_allowed"))]),
        "killable_unknown_processes": len([item for item in merged_processes if str(item.get("owner_kind") or "") == "unknown" and bool(item.get("kill_allowed"))]),
        "scanned_at": __import__("time").time(),
        "scan_errors": 0,
        "aggregate_mode": "fanout",
        "aggregate_partial": partial,
        "aggregate_sources": sources,
        "aggregate_fanout_errors": fanout_errors,
        "aggregate_duration_seconds": __import__("time").perf_counter() - started,
        "aggregate_cache_hit": False,
        "aggregate_cache_age_seconds": 0.0,
        "aggregate_failed_targets": failed_targets,
        "aggregate_failed_target_details": failed_target_details,
        "aggregate_all_sources_failed": all_sources_failed,
        "total_pods": total_target_pods,
        "healthy_pods": total_healthy_pods,
    }
    _LAST_AGENT_AGGREGATE_META.update({
        "partial": partial,
        "sources": sources,
        "fanout_errors": fanout_errors,
        "duration_seconds": summary["aggregate_duration_seconds"],
        "cache_hit": False,
        "cache_age_seconds": 0.0,
        "failed_targets": failed_targets,
        "failed_target_details": failed_target_details,
        "cache_misses": int(_LAST_AGENT_AGGREGATE_META.get("cache_misses") or 0) + 1,
    })
    snapshot = {
        "summary": summary,
        "processes": merged_processes,
        "tasks": merged_tasks,
        "pods": pod_rows,
    }
    _AGENT_AGGREGATE_CACHE[cache_key] = {
        "created_at": now_ts,
        "snapshot": snapshot,
        "meta": dict(_LAST_AGENT_AGGREGATE_META),
    }
    return snapshot


def _build_agent_aggregate_summary(token: str, db: Session) -> dict[str, Any]:
    now_ts = __import__("time").time()
    cache_key = _agent_cache_key()
    cached = _AGENT_AGGREGATE_SUMMARY_CACHE.get(cache_key)
    if cached and (now_ts - float(cached.get("created_at") or 0.0)) <= AGGREGATE_CACHE_TTL_SECONDS:
        cache_age = now_ts - float(cached.get("created_at") or 0.0)
        meta = cached.get("meta") or {}
        _LAST_AGENT_AGGREGATE_META.update({
            "partial": bool(meta.get("partial")),
            "sources": int(meta.get("sources") or 0),
            "fanout_errors": int(meta.get("fanout_errors") or 0),
            "duration_seconds": float(meta.get("duration_seconds") or 0.0),
            "cache_hit": True,
            "cache_age_seconds": cache_age,
            "failed_targets": list(meta.get("failed_targets") or []),
            "cache_hits": int(_LAST_AGENT_AGGREGATE_META.get("cache_hits") or 0) + 1,
        })
        return _summary_with_meta(cached.get("summary") or {}, cache_hit=True, cache_age_seconds=cache_age)

    started = __import__("time").perf_counter()
    from app.service.agent_observability import get_agent_observability_service

    local_summary = dict(get_agent_observability_service().build_snapshot(db, project_id=None)["summary"])
    cluster_snapshot = build_worker_cluster_snapshot(db, project_id=None)
    workers = [worker for worker in cluster_snapshot.workers if worker.healthy and _resolve_worker_targets(pod_ip=worker.pod_ip, pod_name=worker.pod_name)]

    sources = 0
    partial = False
    fanout_errors = 0
    failed_targets: list[str] = []
    failed_target_details: list[dict[str, Any]] = []
    counters = {
        "active_processes": 0,
        "residual_processes": 0,
        "unknown_processes": 0,
        "killable_residual_processes": 0,
        "killable_unknown_processes": 0,
        "scan_errors": 0,
    }

    work_items: list[tuple[Any, list[str]]] = []
    for worker in workers:
        urls = _aggregate_base_urls(worker)
        if not urls:
            partial = True
            fanout_errors += 1
            failed_targets.append(_failed_target_label(worker))
            failed_target_details.append(_failed_target_detail(worker, urls, {"error_kind": "missing_target", "status_code": None, "message": "worker has no reachable aggregate targets", "attempted_url": None}))
            continue
        work_items.append((worker, urls))

    semaphore = threading.Semaphore(AGGREGATE_CONCURRENCY)

    def _fetch_worker_summary(worker, urls: list[str]) -> tuple[Any, list[str], Any | None, dict[str, Any] | None]:
        with semaphore:
            worker_summary, _, error_detail = _fanout_get_json(urls, path="/agent-observability/summary", token=token, params=_snapshot_query_params())
            return worker, urls, worker_summary, error_detail

    # Parallel fetch using ThreadPoolExecutor
    from concurrent.futures import ThreadPoolExecutor, as_completed
    summary_results = []
    if work_items:
        with ThreadPoolExecutor(max_workers=AGGREGATE_CONCURRENCY) as _exec:
            _futures = {_exec.submit(_fetch_worker_summary, w, urls): (w, urls) for w, urls in work_items}
            for _f in as_completed(_futures):
                summary_results.append(_f.result())
    for worker, urls, worker_summary, error_detail in summary_results:
        if worker_summary is None:
            partial = True
            fanout_errors += 1
            failed_targets.append(_failed_target_label(worker))
            failed_target_details.append(_failed_target_detail(worker, urls, error_detail))
            continue
        sources += 1
        for key in counters:
            counters[key] += int(worker_summary.get(key) or 0)

    all_sources_failed = bool(workers) and sources == 0 and fanout_errors > 0
    if not workers:
        summary = {
            **local_summary,
            "aggregate_mode": "local",
            "aggregate_partial": False,
            "aggregate_sources": 1,
            "aggregate_fanout_errors": 0,
            "aggregate_duration_seconds": __import__("time").perf_counter() - started,
            "aggregate_cache_hit": False,
            "aggregate_cache_age_seconds": 0.0,
            "aggregate_failed_targets": [],
            "aggregate_failed_target_details": [],
            "aggregate_all_sources_failed": False,
        }
    else:
        summary = {
            "pod_name": "dvs-aggregate",
            **counters,
            "scanned_at": __import__("time").time(),
            "aggregate_mode": "fanout",
            "aggregate_partial": partial,
            "aggregate_sources": sources,
            "aggregate_fanout_errors": fanout_errors,
            "aggregate_duration_seconds": __import__("time").perf_counter() - started,
            "aggregate_cache_hit": False,
            "aggregate_cache_age_seconds": 0.0,
            "aggregate_failed_targets": failed_targets,
            "aggregate_failed_target_details": failed_target_details,
            "aggregate_all_sources_failed": all_sources_failed,
        }

    _LAST_AGENT_AGGREGATE_META.update({
        "partial": bool(summary.get("aggregate_partial")),
        "sources": int(summary.get("aggregate_sources") or 0),
        "fanout_errors": int(summary.get("aggregate_fanout_errors") or 0),
        "duration_seconds": float(summary.get("aggregate_duration_seconds") or 0.0),
        "cache_hit": False,
        "cache_age_seconds": 0.0,
        "failed_targets": list(summary.get("aggregate_failed_targets") or []),
        "failed_target_details": list(summary.get("aggregate_failed_target_details") or []),
        "cache_misses": int(_LAST_AGENT_AGGREGATE_META.get("cache_misses") or 0) + 1,
    })
    _AGENT_AGGREGATE_SUMMARY_CACHE[cache_key] = {
        "created_at": now_ts,
        "summary": dict(summary),
        "meta": dict(_LAST_AGENT_AGGREGATE_META),
    }
    return summary


def _build_agent_runtime_aggregate(snapshot: dict[str, Any]) -> dict[str, Any]:
    pods = list(snapshot.get("pods") or [])
    processes = list(snapshot.get("processes") or [])
    tasks = list(snapshot.get("tasks") or [])
    summary = dict(snapshot.get("summary") or {})
    return {
        "summary": {
            "total_pods": int(summary.get("total_pods") or len(pods)),
            "healthy_pods": int(summary.get("healthy_pods") or len([item for item in pods if bool(item.get("healthy", True))])),
            "total_processes": len(processes),
            "tracked_processes": len([item for item in processes if str(item.get("owner_kind") or "") == "tracked"]),
            "residual_processes": len([item for item in processes if str(item.get("owner_kind") or "") == "residual"]),
            "unknown_processes": len([item for item in processes if str(item.get("owner_kind") or "") == "unknown"]),
            "killable_residual_processes": len([item for item in processes if str(item.get("owner_kind") or "") == "residual" and bool(item.get("kill_allowed"))]),
            "killable_unknown_processes": len([item for item in processes if str(item.get("owner_kind") or "") == "unknown" and bool(item.get("kill_allowed"))]),
            "aggregate_partial": bool(summary.get("aggregate_partial")),
            "aggregate_sources": int(summary.get("aggregate_sources") or 0),
            "aggregate_fanout_errors": int(summary.get("aggregate_fanout_errors") or 0),
            "aggregate_failed_targets": list(summary.get("aggregate_failed_targets") or []),
            "aggregate_failed_target_details": list(summary.get("aggregate_failed_target_details") or []),
            "aggregate_all_sources_failed": bool(summary.get("aggregate_all_sources_failed")),
            "scanned_at": summary.get("scanned_at"),
        },
        "pods": pods,
        "processes": processes,
        "tasks": tasks,
    }


def _invalidate_agent_aggregate_cache() -> None:
    _AGENT_AGGREGATE_CACHE.clear()
    _AGENT_AGGREGATE_SUMMARY_CACHE.clear()


def _audit_agent_kill_event(
    db: Session,
    *,
    project_id: str,
    operator: str,
    event_type: str,
    message: str,
    payload: dict[str, object],
    task_id: str | None = None,
) -> None:
    if not task_id:
        return
    row = db.query(AppDvsTask).filter(AppDvsTask.task_id == task_id, AppDvsTask.is_deleted.is_(False)).first()
    if row is None:
        return
    from app.service.task_service import _record_task_event

    _record_task_event(
        db,
        row=row,
        event_type=event_type,
        message=message,
        source="agent_observability",
        level="warning",
        status=row.status,
        payload={
            "operator": operator,
            **payload,
        },
        worker_id=str(payload.get("pod_name") or ""),
        execution_owner_id=str(payload.get("pod_name") or ""),
    )


def _get_task_row(db: Session, task_id: str):
    from app.db.models import AppDvsTask

    row = db.query(AppDvsTask).filter(
        AppDvsTask.task_id == task_id,
        AppDvsTask.is_deleted.is_(False),
    ).first()
    if not row:
        raise HTTPException(404, f"任务不存在: {task_id}")
    return row


def _task_root(row) -> Path:
    output_path = row.output_path or ""
    if output_path:
        return Path(output_path).expanduser().resolve() / row.task_id
    # Fallback for tasks where output_path was never persisted (EA-created / pre-fix).
    project_id = str(getattr(row, "project_id", "") or "").strip()
    if project_id:
        import os as _os
        _fs = _os.environ.get("FILESERVER_ROOT", "/data/files")
        return Path(_fs) / project_id / "app" / "secflow-app-dataflow-vuln-scan" / row.task_id
    return Path()


def _latest_epoch_run_root(root: Path) -> Path:
    run_root = root / "run"
    epochs_root = run_root / "epochs"
    if not epochs_root.exists():
        return run_root
    # Only numeric epoch directories are execution attempts.  Auxiliary folders
    # such as run/epochs/output contain intermediate snapshots and must not win.
    candidates = [path for path in epochs_root.iterdir() if path.is_dir() and path.name.isdigit()]
    if not candidates:
        return run_root
    return sorted(candidates, key=lambda path: int(path.name))[-1]


def _epoch_label(path: Path) -> str | None:
    if not path:
        return None
    parts = path.parts
    if "epochs" in parts:
        idx = parts.index("epochs")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def _read_text(path: Path, warnings: List[str], label: str, limit: int = 2_000_000) -> str:
    try:
        if not path.exists() or not path.is_file():
            return ""
        data = path.read_text(encoding="utf-8", errors="replace")
        if len(data) > limit:
            warnings.append(f"{label} 内容过大，仅返回前 {limit} 字符")
            return data[:limit]
        return data
    except Exception as exc:  # pragma: no cover - best effort read endpoint
        warnings.append(f"读取 {label} 失败: {exc}")
        return ""


def _load_result_json(row, root: Path, warnings: List[str]) -> Dict[str, Any]:
    result_path = root / "run" / "result.json"
    if result_path.exists():
        try:
            return json.loads(result_path.read_text(encoding="utf-8", errors="replace") or "{}")
        except Exception as exc:
            warnings.append(f"解析 run/result.json 失败: {exc}")
    return row.result_json or {}


def _collect_rounds(result_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    rounds = result_json.get("rounds")
    if isinstance(rounds, list):
        return [item for item in rounds if isinstance(item, dict)]
    task_result = result_json.get("task_result")
    if isinstance(task_result, dict) and isinstance(task_result.get("rounds"), list):
        return [item for item in task_result["rounds"] if isinstance(item, dict)]
    return []


def _number(value: Any) -> float:
    try:
        return float(value or 0)
    except Exception:
        return 0.0


def _summarize_rounds(rounds: List[Dict[str, Any]], result_json: Dict[str, Any]) -> Dict[str, Any]:
    token_total = 0.0
    cost_total = 0.0
    passed_count = 0
    functions = set()
    for item in rounds:
        if item.get("passed") is True or item.get("status") in {"passed", "success"}:
            passed_count += 1
        func = item.get("function") or item.get("func") or item.get("entry")
        if func:
            functions.add(str(func))
        metrics = item.get("metrics") if isinstance(item.get("metrics"), dict) else {}
        usage = item.get("token_usage") if isinstance(item.get("token_usage"), dict) else {}
        token_total += _number(metrics.get("token_total") or usage.get("total_tokens") or item.get("total_tokens"))
        cost_total += _number(metrics.get("cost") or usage.get("cost") or item.get("cost"))
    root_usage = result_json.get("token_usage") if isinstance(result_json.get("token_usage"), dict) else {}
    token_total = token_total or _number(root_usage.get("total_tokens"))
    cost_total = cost_total or _number(root_usage.get("cost"))
    return {
        "round_count": len(rounds),
        "passed_round_count": passed_count,
        "function_count": len(functions),
        "total_tokens": int(token_total),
        "total_cost": cost_total,
        "effectiveness": {
            "final_round_pass_rate": (passed_count / len(rounds)) if rounds else 0,
        },
    }


def _safe_session_file(root: Path, relative_path: str) -> Path:
    rel = Path(relative_path)
    if rel.is_absolute() or ".." in rel.parts:
        raise HTTPException(400, "非法会话路径")
    run_root = (root / "run").resolve()
    target = (run_root / rel).resolve()
    try:
        target.relative_to(run_root)
    except ValueError:
        raise HTTPException(400, "非法会话路径")
    if target.suffix != ".jsonl":
        raise HTTPException(400, "仅支持 jsonl 会话文件")
    return target


def _parse_session_file(path: Path) -> Dict[str, Any]:
    events: List[Dict[str, Any]] = []
    warnings: List[str] = []
    session_meta: Optional[Dict[str, Any]] = None
    if not path.exists() or not path.is_file():
        raise HTTPException(404, "会话文件不存在")
    for index, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            warnings.append(f"第 {index} 行 JSON 解析失败")
            events.append({"type": "raw", "event_index": index, "line": index, "raw_line": line[:500], "summary": line[:200]})
            continue
        if isinstance(obj, dict) and obj.get("type") == "session":
            session_meta = obj
            continue
        if not isinstance(obj, dict):
            warnings.append(f"第 {index} 行不是 JSON 对象")
            continue
        obj.setdefault("event_index", index)
        obj.setdefault("line", index)
        obj.setdefault("raw_line", line)
        events.append(obj)
    return {"events": events, "warnings": warnings, "session_meta": session_meta, "line_count": len(path.read_text(encoding="utf-8", errors="replace").splitlines())}


def _write_json_atomic(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2))
            handle.flush()
            os.fsync(handle.fileno())
        Path(tmp_name).replace(path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def _build_task_session_catalog(row) -> Dict[str, Any]:
    root = _task_root(row)
    run_root = root / "run" if str(root) else Path()
    if not run_root.exists():
        return {
            "task_id": row.task_id,
            "status": row.status,
            "sessions_root": str(run_root / "sessions"),
            "index_path": str(run_root / "sessions" / "index.json"),
            "generated_at": None,
            "items": [],
            "index": {
                "version": 1,
                "generated_at": None,
                "task_id": row.task_id,
                "task_status": row.status,
                "sessions_root": str(run_root / "sessions"),
                "summary": {},
                "nodes": [],
                "edges": [],
                "groups": [],
                "warnings": [],
            },
        }
    result_json = _load_result_json(row, root, [])
    return build_session_catalog(
        task_id=row.task_id,
        row_status=row.status,
        run_root=run_root,
        result_json=result_json,
        write_json_atomic=_write_json_atomic,
    )


@router.post("/tasks", status_code=201)
def create_task(body: TaskCreateRequest, db: Session = Depends(get_db)):
    prompt = body.prompt_content
    if not prompt or not prompt.strip():
        prompt = generate_prompt_from_path(body.input_path)

    task_config_json: Dict[str, Any] = {}
    if body.source_file:
        task_config_json["source_file"] = body.source_file
    if body.function_name:
        task_config_json["function_name"] = body.function_name
    if body.line_hint:
        task_config_json["line_hint"] = body.line_hint
    if body.definition_kind:
        task_config_json["definition_kind"] = str(body.definition_kind).strip()
    if body.taint_params:
        task_config_json["taint_params"] = [str(value).strip() for value in body.taint_params if str(value).strip()]
    if body.function_description:
        task_config_json["function_description"] = str(body.function_description).strip()
    if body.entry_reason:
        task_config_json["entry_reason"] = str(body.entry_reason).strip()
    if body.function_description or body.function_description_source:
        task_config_json["function_description_source"] = str(body.function_description_source or "agent").strip() or "agent"
    if body.entry_reason or body.entry_reason_source:
        task_config_json["entry_reason_source"] = str(body.entry_reason_source or "agent").strip() or "agent"
    if body.taint_details:
        task_config_json["taint_details"] = [
            {
                "name": str(item.get("name") or item.get("taint") or item.get("param") or "").strip(),
                "description": str(item.get("description") or item.get("summary") or "").strip(),
                "description_source": "agent" if str(item.get("description") or item.get("summary") or "").strip() else "default",
                **({"source_kind": str(item.get("source_kind")).strip()} if str(item.get("source_kind") or "").strip() else {}),
            }
            for item in body.taint_details
            if isinstance(item, dict) and str(item.get("name") or item.get("taint") or item.get("param") or "").strip()
        ]
    if body.funcdb_path:
        task_config_json["funcdb_path"] = str(body.funcdb_path).strip()
    if body.func_hash:
        task_config_json["func_hash"] = str(body.func_hash).strip()
    if any(
        value is not None
        for value in (
            body.agent_task_key_id,
            body.agent_task_key_name,
            body.agent_task_key_prefix,
            body.agent_task_key_secret,
            body.agent_task_key_source,
        )
    ):
        task_config_json["agent_task_key"] = {
            "id": body.agent_task_key_id,
            "name": body.agent_task_key_name,
            "prefix": body.agent_task_key_prefix,
            "secret": body.agent_task_key_secret,
            "source": body.agent_task_key_source,
        }
    if body.model:
        task_config_json["model"] = str(body.model).strip()

    svc = get_task_service()
    return svc.create_task(
        db,
        project_id=body.project_id,
        task_name=body.task_name,
        input_path=body.input_path,
        module_input_path=body.module_input_path,
        source_root_path=body.source_root_path,
        output_path=body.output_path,
        task_description=body.task_description,
        prompt_template_id=body.prompt_template_id,
        prompt_content=prompt,
        task_config_json=task_config_json or None,
        task_origin_type=body.task_origin_type,
        parent_project_id=body.parent_project_id,
        parent_task_id=body.parent_task_id,
        parent_task_type=body.parent_task_type,
        parent_stage_name=body.parent_stage_name,
        parent_stage_item_id=body.parent_stage_item_id,
        parent_stage_item_key=body.parent_stage_item_key,
    )


@router.get("/tasks")
def list_tasks(
    project_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=1000),
    status: Optional[str] = Query(None),
    mode: Optional[str] = Query(None),
    parent_task_id: Optional[str] = Query(None),
    parent_stage_item_id: Optional[str] = Query(None),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc"),
    db: Session = Depends(get_db),
):
    return get_task_service().list_tasks(
        db,
        project_id=project_id,
        page=page,
        per_page=per_page,
        status=status,
        mode=mode,
        parent_task_id=parent_task_id,
        parent_stage_item_id=parent_stage_item_id,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@router.get("/tasks/stats", response_model=TaskListStatsResponse)
def get_task_stats(
    project_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    mode: Optional[str] = Query(None),
    parent_task_id: Optional[str] = Query(None),
    parent_stage_item_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    return get_task_service().get_task_stats(
        db,
        project_id=project_id,
        status=status,
        mode=mode,
        parent_task_id=parent_task_id,
        parent_stage_item_id=parent_stage_item_id,
    )


def _build_worker_cluster_capacity_response(db: Session, project_id: str | None = None) -> WorkerClusterCapacityResponse:
    snapshot = build_worker_cluster_snapshot(db, project_id=project_id)
    return WorkerClusterCapacityResponse(
        worker_count=snapshot.worker_count,
        healthy_workers=snapshot.healthy_workers,
        stale_workers=snapshot.stale_workers,
        total_capacity=snapshot.total_capacity,
        running_jobs=snapshot.running_jobs,
        queued_jobs=snapshot.queued_jobs,
        available_slots=snapshot.available_slots,
        updated_at=isoformat_local(snapshot.updated_at),
        workers=[
            WorkerCapacityResponse(
                worker_id=worker.worker_id,
                host_name=worker.host_name,
                pod_name=worker.pod_name,
                pod_ip=worker.pod_ip,
                http_port=worker.http_port,
                healthy=worker.healthy,
                max_concurrent_jobs=worker.max_concurrent_jobs,
                running_jobs=worker.running_jobs,
                available_slots=worker.available_slots,
                source=worker.source,
                last_heartbeat_at=isoformat_local(worker.last_heartbeat_at),
                pod_created_at=worker.pod_created_at,
                pod_started_at=worker.pod_started_at,
                pod_metrics_at=worker.pod_metrics_at,
                pod_cpu_usage_millicores=worker.pod_cpu_usage_millicores,
                pod_memory_usage_bytes=worker.pod_memory_usage_bytes,
                pod_cpu_request_millicores=worker.pod_cpu_request_millicores,
                pod_memory_request_bytes=worker.pod_memory_request_bytes,
                pod_cpu_limit_millicores=worker.pod_cpu_limit_millicores,
                pod_memory_limit_bytes=worker.pod_memory_limit_bytes,
                error=worker.error,
                active_jobs=[
                    WorkerActiveJobResponse(
                        task_id=job.task_id,
                        task_name=job.task_name,
                        status=job.status,
                        parent_task_id=job.parent_task_id,
                        parent_task_type=job.parent_task_type,
                        task_origin_type=job.task_origin_type,
                        input_path=job.input_path,
                        started_at=isoformat_local(job.started_at),
                        updated_at=isoformat_local(job.updated_at),
                        dispatch_status=job.dispatch_status,
                        execution_owner_id=job.execution_owner_id,
                        execution_lease_until=isoformat_local(job.execution_lease_until),
                        execution_heartbeat_at=isoformat_local(job.execution_heartbeat_at),
                        mapped=job.mapped,
                        mapping_reason=job.mapping_reason,
                    )
                    for job in worker.active_jobs
                ],
            )
            for worker in snapshot.workers
        ],
    )


@router.get("/workers/cluster-capacity", response_model=WorkerClusterCapacityResponse)
def get_worker_cluster_capacity(
    project_id: str | None = Query(None),
    db: Session = Depends(get_db),
):
    return _build_worker_cluster_capacity_response(db, project_id=project_id)


@router.get("/workers/slot-cluster", response_model=WorkerClusterCapacityResponse)
def get_global_slot_cluster_compat(db: Session = Depends(get_db)):
    return _build_worker_cluster_capacity_response(db, project_id=None)


@router.get("/projects/{project_id}/slot-cluster", response_model=WorkerClusterCapacityResponse)
def get_project_slot_cluster_compat(project_id: str, db: Session = Depends(get_db)):
    return _build_worker_cluster_capacity_response(db, project_id=project_id)


@router.get("/agent-observability/summary", response_model=AgentObservabilitySummaryResponse)
def get_agent_observability_summary(
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    del user_and_token
    from app.service.agent_observability import get_agent_observability_service

    return get_agent_observability_service().build_snapshot(db, project_id=None)["summary"]


@router.get("/agent-observability/aggregate/summary", response_model=AgentObservabilitySummaryResponse)
def get_agent_observability_aggregate_summary(
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    _, token = user_and_token
    return _build_agent_aggregate_summary(token, db)


@router.get("/agent-observability/processes", response_model=list[AgentProcessSnapshotResponse])
def list_agent_processes(
    pod: Optional[str] = Query(None),
    task_id: Optional[str] = Query(None),
    stage_key: Optional[str] = Query(None),
    role_kind: Optional[str] = Query(None),
    owner_kind: Optional[str] = Query(None),
    kill_allowed: Optional[bool] = Query(None),
    orphan_only: bool = Query(False),
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    del user_and_token
    from app.service.agent_observability import get_agent_observability_service

    rows = list(get_agent_observability_service().build_snapshot(db, project_id=None)["processes"])
    if pod:
        rows = [row for row in rows if str(row.get("pod_name") or "") == pod]
    if task_id:
        rows = [row for row in rows if str(row.get("task_id") or "") == task_id]
    if stage_key:
        rows = [row for row in rows if str(row.get("stage_key") or "") == stage_key]
    if role_kind:
        rows = [row for row in rows if str(row.get("role_kind") or "") == role_kind]
    if owner_kind:
        rows = [row for row in rows if str(row.get("owner_kind") or "") == owner_kind]
    if kill_allowed is not None:
        rows = [row for row in rows if bool(row.get("kill_allowed")) is bool(kill_allowed)]
    if orphan_only:
        rows = [row for row in rows if str(row.get("owner_kind") or "") == "orphan"]
    return rows


@router.get("/agent-observability/aggregate/processes", response_model=list[AgentProcessSnapshotResponse])
def list_agent_aggregate_processes(
    pod: Optional[str] = Query(None),
    task_id: Optional[str] = Query(None),
    stage_key: Optional[str] = Query(None),
    role_kind: Optional[str] = Query(None),
    owner_kind: Optional[str] = Query(None),
    kill_allowed: Optional[bool] = Query(None),
    orphan_only: bool = Query(False),
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    _, token = user_and_token
    rows = list((_build_agent_aggregate_snapshot(token, db))["processes"])
    if pod:
        rows = [row for row in rows if str(row.get("pod_name") or "") == pod]
    if task_id:
        rows = [row for row in rows if str(row.get("task_id") or "") == task_id]
    if stage_key:
        rows = [row for row in rows if str(row.get("stage_key") or "") == stage_key]
    if role_kind:
        rows = [row for row in rows if str(row.get("role_kind") or "") == role_kind]
    if owner_kind:
        rows = [row for row in rows if str(row.get("owner_kind") or "") == owner_kind]
    if kill_allowed is not None:
        rows = [row for row in rows if bool(row.get("kill_allowed")) is bool(kill_allowed)]
    if orphan_only:
        rows = [row for row in rows if str(row.get("owner_kind") or "") == "residual"]
    return rows


@router.get("/agent-observability/sessions/content")
def get_agent_session_content(
    task_id: str = Query(...),
    session_file: str = Query(...),
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    del user_and_token
    return get_task_service().get_task_session_file(db, task_id, session_file)


@router.get("/agent-observability/tasks", response_model=list[AgentTaskOwnershipSnapshotResponse])
def list_agent_tasks(
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    del user_and_token
    from app.service.agent_observability import get_agent_observability_service

    return get_agent_observability_service().build_snapshot(db, project_id=None)["tasks"]


@router.get("/agent-observability/aggregate/tasks", response_model=list[AgentTaskOwnershipSnapshotResponse])
def list_agent_aggregate_tasks(
    pod: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    _, token = user_and_token
    rows = list((_build_agent_aggregate_snapshot(token, db))["tasks"])
    if pod:
        rows = [row for row in rows if str(row.get("pod_name") or "") == pod]
    return rows


@router.get("/agent-observability/pods", response_model=list[AgentPodSnapshotResponse])
def list_agent_pods(
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    del user_and_token
    from app.service.agent_observability import get_agent_observability_service

    return get_agent_observability_service().build_snapshot(db, project_id=None)["pods"]


@router.get("/agent-observability/aggregate/pods", response_model=list[AgentPodSnapshotResponse])
def list_agent_aggregate_pods(
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    _, token = user_and_token
    return (_build_agent_aggregate_snapshot(token, db))["pods"]


@router.get("/agent-observability/aggregate/runtime", response_model=AgentRuntimeAggregateResponse)
def get_agent_aggregate_runtime(
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    _, token = user_and_token
    snapshot = _build_agent_aggregate_snapshot(token, db)
    return _build_agent_runtime_aggregate(snapshot)


def _fanout_post_json(urls: list[str], *, path: str, token: str, params: dict[str, Any]) -> tuple[Any | None, str | None, dict[str, Any] | None]:
    headers = _auth_headers_from_token(token)
    with httpx.AsyncClient(timeout=AGGREGATE_HTTP_TIMEOUT_SECONDS) as client:
        for base_url in urls:
            url = f"{base_url}{path}"
            try:
                response = client.post(url, headers=headers, params=params)
                if response.status_code == 200:
                    return response.json(), base_url, None
                logger.warning("dvs agent fanout post non-200 status=%s url=%s", response.status_code, url)
                return None, None, {"attempted_url": url, "error_kind": "http_error", "status_code": response.status_code, "message": response.text[:200]}
            except httpx.ConnectTimeout:
                logger.warning("dvs agent fanout post connect_timeout url=%s", url)
                return None, None, {"attempted_url": url, "error_kind": "connect_timeout", "status_code": None, "message": "connect timeout"}
            except httpx.ConnectError:
                logger.warning("dvs agent fanout post connection_refused url=%s", url)
                return None, None, {"attempted_url": url, "error_kind": "connection_refused", "status_code": None, "message": "connection refused"}
            except Exception as exc:
                logger.warning("dvs agent fanout post failed url=%s", url, exc_info=True)
                return None, None, {"attempted_url": url, "error_kind": "transport_error", "status_code": None, "message": str(exc)}
    return None, None, {"attempted_url": None, "error_kind": "no_target", "status_code": None, "message": "no target responded"}


def _kill_agent_process_impl(
    pid: int,
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    user, token = user_and_token
    ensure_admin_user(user)
    from app.service.agent_observability import get_agent_observability_service

    snapshot = get_agent_observability_service().build_snapshot(db, project_id=None)
    matched = [row for row in snapshot["processes"] if int(row.get("pid") or -1) == pid]
    if not matched:
        return AgentProcessKillResponse(requested=1, matched=0, succeeded=0, failed=0, skipped=1, items=[])
    row = matched[0]
    if not row.get("kill_allowed"):
        return AgentProcessKillResponse(
            requested=1,
            matched=1,
            succeeded=0,
            failed=0,
            skipped=1,
            items=[AgentProcessKillItemResponse(pid=pid, pgid=row.get("pgid"), status="skipped", reason=row.get("kill_block_reason"))],
        )
    logger.warning(
        "dataflow-agent-manual-kill operator=%s project_id=%s pid=%s pgid=%s task_id=%s workspace_root=%s owner_reason=%s",
        user.get("username") or user.get("name") or "unknown",
        row.get("project_id"),
        pid,
        row.get("pgid"),
        row.get("task_id"),
        row.get("workspace_root"),
        row.get("owner_reason"),
    )
    _audit_agent_kill_event(
        db,
        project_id=str(row.get("project_id") or ""),
        operator=user.get("username") or user.get("name") or "unknown",
        event_type="agent_process_manual_kill",
        message=f"管理员手工终止残留智能体进程 pid={pid}",
        payload={
            "pid": pid,
            "pgid": row.get("pgid"),
            "pod_name": row.get("pod_name"),
            "workspace_root": row.get("workspace_root"),
            "owner_reason": row.get("owner_reason"),
            "kill_mode": "local",
        },
        task_id=row.get("task_id"),
    )
    result = get_agent_observability_service().kill_process(pid)
    _invalidate_agent_aggregate_cache()
    return AgentProcessKillResponse(
        requested=1,
        matched=1,
        succeeded=1 if result.get("status") in {"killed", "gone"} else 0,
        failed=1 if result.get("status") == "failed" else 0,
        skipped=0,
        items=[AgentProcessKillItemResponse(**result)],
    )


@router.post("/agent-observability/processes/{pid}/kill", response_model=AgentProcessKillResponse)
def kill_agent_process(
    pid: int,
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    return _kill_agent_process_impl(pid=pid, db=db, user_and_token=user_and_token)


@internal_observability_router.post("/agent-observability/processes/{pid}/kill", response_model=AgentProcessKillResponse, include_in_schema=False)
def kill_internal_agent_process(
    pid: int,
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    return _kill_agent_process_impl(pid=pid, db=db, user_and_token=user_and_token)


@router.post("/agent-observability/aggregate/processes/{pid}/kill", response_model=AgentProcessKillResponse)
def kill_agent_aggregate_process(
    pid: int,
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    user, token = user_and_token
    ensure_admin_user(user)
    snapshot = _build_agent_aggregate_snapshot(token, db)
    matched = [row for row in snapshot["processes"] if int(row.get("pid") or -1) == pid]
    if not matched:
        return AgentProcessKillResponse(requested=1, matched=0, succeeded=0, failed=0, skipped=1, items=[])
    row = matched[0]
    if not row.get("kill_allowed"):
        return AgentProcessKillResponse(
            requested=1,
            matched=1,
            succeeded=0,
            failed=0,
            skipped=1,
            items=[AgentProcessKillItemResponse(pid=pid, pgid=row.get("pgid"), status="skipped", reason=row.get("kill_block_reason"))],
        )

    cluster_snapshot = build_worker_cluster_snapshot(db, project_id=None)
    target_worker = next((worker for worker in cluster_snapshot.workers if str(worker.pod_name or "") == str(row.get("pod_name") or "")), None)
    if target_worker is None:
        return AgentProcessKillResponse(
            requested=1,
            matched=1,
            succeeded=0,
            failed=1,
            skipped=0,
            items=[AgentProcessKillItemResponse(pid=pid, pgid=row.get("pgid"), status="failed", reason="target pod not found in cluster snapshot")],
        )

    logger.warning(
        "dataflow-agent-aggregate-manual-kill operator=%s project_id=%s pid=%s target_pod=%s task_id=%s",
        user.get("username") or user.get("name") or "unknown",
        row.get("project_id"),
        pid,
        row.get("pod_name"),
        row.get("task_id"),
    )
    _audit_agent_kill_event(
        db,
        project_id=str(row.get("project_id") or ""),
        operator=user.get("username") or user.get("name") or "unknown",
        event_type="agent_process_manual_kill",
        message=f"管理员跨 Pod 手工终止残留智能体进程 pid={pid}",
        payload={
            "pid": pid,
            "pgid": row.get("pgid"),
            "pod_name": row.get("pod_name"),
            "workspace_root": row.get("workspace_root"),
            "owner_reason": row.get("owner_reason"),
            "kill_mode": "aggregate",
        },
        task_id=row.get("task_id"),
    )
    result, _, error_detail = _fanout_post_json(
        _aggregate_base_urls(target_worker),
        path=f"/agent-observability/processes/{pid}/kill",
        token=token,
        params={},
    )
    if result is None:
        return AgentProcessKillResponse(
            requested=1,
            matched=1,
            succeeded=0,
            failed=1,
            skipped=0,
            items=[AgentProcessKillItemResponse(pid=pid, pgid=row.get("pgid"), status="failed", reason=(error_detail or {}).get("message") or "fanout kill request failed")],
        )
    _invalidate_agent_aggregate_cache()
    return AgentProcessKillResponse(**result)


@router.post("/agent-observability/processes/kill-all-orphans", response_model=AgentProcessKillResponse)
def kill_all_orphan_processes(
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    user, token = user_and_token
    ensure_admin_user(user)
    from app.service.agent_observability import get_agent_observability_service

    snapshot = get_agent_observability_service().build_snapshot(db, project_id=None)
    killable = [row for row in snapshot["processes"] if row.get("owner_kind") == "residual" and row.get("kill_allowed")]
    logger.warning(
        "dataflow-agent-bulk-kill operator=%s project_id=%s count=%s pids=%s",
        user.get("username") or user.get("name") or "unknown",
        None,
        len(killable),
        [row.get("pid") for row in killable],
    )
    for row in killable:
        _audit_agent_kill_event(
            db,
            project_id=str(row.get("project_id") or ""),
            operator=user.get("username") or user.get("name") or "unknown",
            event_type="agent_process_bulk_manual_kill",
            message=f"管理员批量终止残留智能体进程 pid={int(row.get('pid') or 0)}",
            payload={
                "pid": int(row.get("pid") or 0),
                "pgid": row.get("pgid"),
                "pod_name": row.get("pod_name"),
                "workspace_root": row.get("workspace_root"),
                "owner_reason": row.get("owner_reason"),
                "kill_mode": "local_bulk",
            },
            task_id=row.get("task_id"),
        )
    items = [get_agent_observability_service().kill_process(int(row["pid"])) for row in killable]
    _invalidate_agent_aggregate_cache()
    succeeded = sum(1 for item in items if item.get("status") in {"killed", "gone"})
    failed = sum(1 for item in items if item.get("status") == "failed")
    return AgentProcessKillResponse(
        requested=len(killable),
        matched=len(killable),
        succeeded=succeeded,
        failed=failed,
        skipped=0,
        items=[AgentProcessKillItemResponse(**item) for item in items],
    )


@router.post("/agent-observability/aggregate/processes/kill-all-orphans", response_model=AgentProcessKillResponse)
def kill_all_agent_aggregate_orphans(
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    user, token = user_and_token
    ensure_admin_user(user)
    snapshot = _build_agent_aggregate_snapshot(token, db)
    killable = [row for row in snapshot["processes"] if row.get("owner_kind") == "residual" and row.get("kill_allowed")]
    cluster_snapshot = build_worker_cluster_snapshot(db, project_id=None)
    worker_by_pod = {str(worker.pod_name or ""): worker for worker in cluster_snapshot.workers}
    items: list[dict[str, Any]] = []

    logger.warning(
        "dataflow-agent-aggregate-bulk-kill operator=%s project_id=%s count=%s",
        user.get("username") or user.get("name") or "unknown",
        None,
        len(killable),
    )

    for row in killable:
        _audit_agent_kill_event(
            db,
            project_id=str(row.get("project_id") or ""),
            operator=user.get("username") or user.get("name") or "unknown",
            event_type="agent_process_bulk_manual_kill",
            message=f"管理员跨 Pod 批量终止残留智能体进程 pid={int(row.get('pid') or 0)}",
            payload={
                "pid": int(row.get("pid") or 0),
                "pgid": row.get("pgid"),
                "pod_name": row.get("pod_name"),
                "workspace_root": row.get("workspace_root"),
                "owner_reason": row.get("owner_reason"),
                "kill_mode": "aggregate_bulk",
            },
            task_id=row.get("task_id"),
        )
        target_worker = worker_by_pod.get(str(row.get("pod_name") or ""))
        if target_worker is None:
            items.append({"pid": int(row.get("pid") or 0), "pgid": row.get("pgid"), "status": "failed", "reason": "target pod not found in cluster snapshot"})
            continue
        result, _, error_detail = _fanout_post_json(
            _aggregate_base_urls(target_worker),
            path=f"/agent-observability/processes/{int(row.get('pid') or 0)}/kill",
            token=token,
            params={},
        )
        if not result:
            items.append({"pid": int(row.get("pid") or 0), "pgid": row.get("pgid"), "status": "failed", "reason": (error_detail or {}).get("message") or "fanout kill request failed"})
            continue
        for item in result.get("items") or []:
            items.append(item)

    succeeded = sum(1 for item in items if item.get("status") in {"killed", "gone"})
    failed = sum(1 for item in items if item.get("status") == "failed")
    skipped = sum(1 for item in items if item.get("status") == "skipped")
    _invalidate_agent_aggregate_cache()
    return AgentProcessKillResponse(
        requested=len(killable),
        matched=len(killable),
        succeeded=succeeded,
        failed=failed,
        skipped=skipped,
        items=[AgentProcessKillItemResponse(**item) for item in items],
    )


@router.post("/agent-observability/aggregate/processes/kill-all-suspected-orphans", response_model=AgentProcessKillResponse)
def kill_all_agent_aggregate_suspected_orphans(
    db: Session = Depends(get_db),
    user_and_token=Depends(get_current_user),
):
    user, token = user_and_token
    ensure_admin_user(user)
    snapshot = _build_agent_aggregate_snapshot(token, db)
    killable = [row for row in snapshot["processes"] if row.get("owner_kind") == "unknown" and row.get("kill_allowed")]
    cluster_snapshot = build_worker_cluster_snapshot(db, project_id=None)
    worker_by_pod = {str(worker.pod_name or ""): worker for worker in cluster_snapshot.workers}
    items: list[dict[str, Any]] = []

    logger.warning(
        "dataflow-agent-aggregate-bulk-kill-suspected operator=%s project_id=%s count=%s",
        user.get("username") or user.get("name") or "unknown",
        None,
        len(killable),
    )

    for row in killable:
        _audit_agent_kill_event(
            db,
            project_id=str(row.get("project_id") or ""),
            operator=user.get("username") or user.get("name") or "unknown",
            event_type="agent_process_bulk_manual_kill",
            message=f"管理员跨 Pod 批量终止未归属智能体进程 pid={int(row.get('pid') or 0)}",
            payload={
                "pid": int(row.get("pid") or 0),
                "pgid": row.get("pgid"),
                "pod_name": row.get("pod_name"),
                "workspace_root": row.get("workspace_root"),
                "owner_reason": row.get("owner_reason"),
                "owner_kind": row.get("owner_kind"),
                "kill_mode": "aggregate_bulk_suspected",
            },
            task_id=row.get("task_id"),
        )
        target_worker = worker_by_pod.get(str(row.get("pod_name") or ""))
        if target_worker is None:
            items.append({"pid": int(row.get("pid") or 0), "pgid": row.get("pgid"), "status": "failed", "reason": "target pod not found in cluster snapshot"})
            continue
        result, _, error_detail = _fanout_post_json(
            _aggregate_base_urls(target_worker),
            path=f"/agent-observability/processes/{int(row.get('pid') or 0)}/kill",
            token=token,
            params={},
        )
        if not result:
            items.append({"pid": int(row.get("pid") or 0), "pgid": row.get("pgid"), "status": "failed", "reason": (error_detail or {}).get("message") or "fanout kill request failed"})
            continue
        for item in result.get("items") or []:
            items.append(item)

    succeeded = sum(1 for item in items if item.get("status") in {"killed", "gone"})
    failed = sum(1 for item in items if item.get("status") == "failed")
    skipped = sum(1 for item in items if item.get("status") == "skipped")
    _invalidate_agent_aggregate_cache()
    return AgentProcessKillResponse(
        requested=len(killable),
        matched=len(killable),
        succeeded=succeeded,
        failed=failed,
        skipped=skipped,
        items=[AgentProcessKillItemResponse(**item) for item in items],
    )


@router.get("/tasks/{task_id}/vuln-graph")
def get_task_vuln_graph(task_id: str, db: Session = Depends(get_db)):
    row = _get_task_row(db, task_id)
    root = _task_root(row)
    latest_run_root = _latest_epoch_run_root(root) if str(root) else Path()
    run_root = latest_run_root if latest_run_root.exists() else root / "run"
    graph = load_vuln_scan_graph(run_root)
    trace_tree = build_trace_tree(graph)
    return {
        "task_id": task_id,
        "available": bool(graph.get("analysis_runs") or graph.get("taint_nodes") or graph.get("taint_edges") or graph.get("vulnerability_findings")),
        "run_root": str(run_root),
        "summary": summarize_graph(graph),
        "trace_tree": trace_tree,
        "graph": graph,
    }


@router.get("/tasks/{task_id}/vuln-findings")
def get_task_vuln_findings(task_id: str, db: Session = Depends(get_db)):
    row = _get_task_row(db, task_id)
    root = _task_root(row)
    latest_run_root = _latest_epoch_run_root(root) if str(root) else Path()
    run_root = latest_run_root if latest_run_root.exists() else root / "run"
    graph = load_vuln_scan_graph(run_root)
    findings = graph.get("vulnerability_findings") or []
    return {
        "task_id": task_id,
        "available": bool(findings),
        "count": len(findings),
        "items": findings,
    }


@router.post("/tasks/{task_id}/vuln-findings/{finding_id}/report")
def report_task_vuln_finding(task_id: str, finding_id: str, db: Session = Depends(get_db)):
    """手动重新上报指定漏洞疑点到漏洞中心。"""
    result = _do_report_finding(task_id, finding_id, db)
    if result is None:
        raise HTTPException(404, f"Finding {finding_id} not found")
    return result


@router.post("/tasks/{task_id}/vuln-findings/report-all")
def report_all_task_vuln_findings(task_id: str, db: Session = Depends(get_db)):
    """一键上报所有未提交的漏洞疑点到漏洞中心。"""
    row = _get_task_row(db, task_id)
    root = _task_root(row)
    latest_run_root = _latest_epoch_run_root(root) if str(root) else Path()
    run_root = latest_run_root if latest_run_root.exists() else root / "run"
    graph = load_vuln_scan_graph(run_root)
    findings = graph.get("vulnerability_findings") or []
    unreported = [f for f in findings if f.get("report_status") != "reported"]
    results = []
    for f in unreported:
        fid = f.get("finding_id", "")
        if not fid:
            continue
        r = _do_report_finding(task_id, fid, db)
        results.append(r or {"finding_id": fid, "status": "skipped", "error": "not found"})
    return {
        "task_id": task_id,
        "total_findings": len(findings),
        "unreported": len(unreported),
        "results": results,
    }


def _do_report_finding(task_id: str, finding_id: str, db: Session):
    """Common helper to report a single finding. Returns dict or None if not found."""
    from app.vuln_intake_reporter import report_finding_to_intake
    from app.vuln_store import VulnFindingRecord
    row = _get_task_row(db, task_id)
    root = _task_root(row)
    # Prefer run/vuln-scan.sqlite (always complete), fallback to latest epoch
    run_sqlite = root / "run" / "vuln-scan.sqlite"
    if run_sqlite.exists():
        run_root = root / "run"
    else:
        latest_run_root = _latest_epoch_run_root(root) if str(root) else Path()
        run_root = latest_run_root if latest_run_root.exists() else root / "run"
    graph = load_vuln_scan_graph(run_root)
    findings = graph.get("vulnerability_findings") or []
    finding = next((f for f in findings if f.get("finding_id") == finding_id), None)
    if not finding:
        return None
    project_id = str(row.project_id or "").strip()
    task_name = str(row.task_name or "").strip()
    parent_task_id = str(row.parent_task_id or "").strip()
    source_root = str(row.source_root_path or "").strip()
    output_dir = str(finding.get("output_dir") or "")
    report_path = str(Path(output_dir) / "vulnerability-report.md") if output_dir else ""
    taint_path = str(Path(output_dir) / "taint-path-report.md") if output_dir else ""
    rec = VulnFindingRecord(
        finding_id=finding_id,
        run_id=str(finding.get("run_id") or ""),
        node_id=str(finding.get("node_id") or ""),
        source_file=str(finding.get("source_file") or ""),
        function_name=str(finding.get("function_name") or ""),
        line=str(finding.get("line") or ""),
        vuln_type=str(finding.get("vuln_type") or "unknown"),
        severity=str(finding.get("severity") or "medium"),
        title=str(finding.get("title") or finding_id),
        summary=str(finding.get("summary") or ""),
        evidence=str(finding.get("evidence") or ""),
        exploitability=str(finding.get("exploitability") or ""),
        confidence=float(finding.get("confidence") or 0),
        output_dir=output_dir,
    )
    result = report_finding_to_intake(
        project_id=project_id,
        task_id=task_id,
        task_name=task_name,
        parent_task_id=parent_task_id,
        finding=rec,
        source_root=source_root,
        report_path=report_path,
        taint_path_report_path=taint_path,
    )
    reported_ok = result.get("status") == "reported"
    if reported_ok:
        try:
            from app.vuln_store import VulnScanStore
            store = VulnScanStore(run_root / "vuln-scan.sqlite")
            store.update_finding_report_status(
                finding_id,
                status="reported",
                case_id=str(result.get("case_id") or ""),
            )
            from app.service.task_service import _sync_task_vuln_stats
            _sync_task_vuln_stats(row)
            db.commit()
        except Exception:
            pass
    return {
        "task_id": task_id,
        "finding_id": finding_id,
        "report_id": result.get("report_id"),
        "case_id": result.get("case_id"),
        "status": result.get("status"),
        "duplicate": result.get("duplicate"),
        "error": result.get("error"),
    }


@router.get("/tasks/{task_id}")
def get_task(task_id: str, db: Session = Depends(get_db)):
    return get_task_service().get_task(db, task_id)


# ── Project-level vuln stats & batch report ─────────────────────────────────

@router.get("/vuln-stats")
def get_project_vuln_stats(project_id: str = Query(...), db: Session = Depends(get_db)):
    """聚合项目下所有 DVS 任务的漏洞上报统计（从 MySQL 读取）。"""
    from sqlalchemy import func as sa_func
    result = db.query(
        sa_func.sum(AppDvsTask.vuln_total_count),
        sa_func.sum(AppDvsTask.vuln_reported_count),
        sa_func.sum(AppDvsTask.vuln_unreported_count),
    ).filter(
        AppDvsTask.project_id == project_id,
        AppDvsTask.is_deleted == False,
    ).first()
    total = int(result[0] or 0)
    reported = int(result[1] or 0)
    unreported = int(result[2] or 0)
    return {
        "project_id": project_id,
        "total_findings": total,
        "reported": reported,
        "unreported": unreported,
    }


@router.post("/vuln-stats/report-all")
def report_all_project_vuln_findings(project_id: str = Query(...), db: Session = Depends(get_db)):
    """一键上报项目下所有 DVS 任务的未提交漏洞。"""
    rows = db.query(AppDvsTask).filter(
        AppDvsTask.project_id == project_id,
        AppDvsTask.is_deleted == False,
    ).all()
    all_results = []
    total = 0
    ok = 0
    for row in rows:
        task_id = row.task_id
        root = _task_root(row)
        latest_run_root = _latest_epoch_run_root(root) if str(root) else Path()
        run_root = latest_run_root if latest_run_root.exists() else root / "run"
        graph = load_vuln_scan_graph(run_root)
        findings = graph.get("vulnerability_findings") or []
        for f in findings:
            fid = f.get("finding_id", "")
            if not fid or f.get("report_status") == "reported":
                continue
            total += 1
            r = _do_report_finding(task_id, fid, db)
            all_results.append(r or {"task_id": task_id, "finding_id": fid, "status": "skipped", "error": "not found"})
            if r and r.get("status") == "reported":
                ok += 1
    return {
        "project_id": project_id,
        "total_unreported": total,
        "reported_ok": ok,
        "failed": total - ok,
        "results": all_results,
    }


@router.get("/tasks/vuln-stats-batch")
def get_tasks_vuln_stats_batch(task_ids: str = Query(...), db: Session = Depends(get_db)):
    ids = [tid.strip() for tid in task_ids.split(",") if tid.strip()]
    result = {}
    for tid in ids:
        row = db.query(AppDvsTask).filter(AppDvsTask.task_id == tid, AppDvsTask.is_deleted == False).first()
        if not row:
            result[tid] = {"total": 0, "reported": 0, "unreported": 0}
            continue
        root = _task_root(row)
        latest = _latest_epoch_run_root(root) if str(root) else Path()
        run_root = latest if latest.exists() else root / "run"
        graph = load_vuln_scan_graph(run_root)
        findings = graph.get("vulnerability_findings") or []
        total = len(findings)
        reported = sum(1 for f in findings if f.get("report_status") == "reported")
        result[tid] = {"total": total, "reported": reported, "unreported": total - reported}
    return result


@router.get("/tasks/{task_id}")


@router.get("/tasks/{task_id}/execution")
def get_task_execution(task_id: str, db: Session = Depends(get_db)):
    return get_task_service().get_task_execution(db, task_id)


@router.get("/tasks/{task_id}/result")
def get_task_result(task_id: str, db: Session = Depends(get_db)):
    row = _get_task_row(db, task_id)
    root = _task_root(row)
    warnings: List[str] = []
    output_root = root / "output" if str(root) else Path()
    run_root = root / "run" if str(root) else Path()
    result_json = _load_result_json(row, root, warnings) if str(root) else (row.result_json or {})
    rounds = _collect_rounds(result_json)
    latest_run_root = _latest_epoch_run_root(root) if str(root) else Path()
    current_epoch = _epoch_label(latest_run_root)

    output_files: List[Dict[str, Any]] = []
    dataflow_files: List[Dict[str, Any]] = []
    result_markdown = ""
    if output_root.exists():
        for path in sorted(output_root.glob("*.md")):
            markdown = _read_text(path, warnings, path.name)
            item = {
                "name": path.name,
                "relative_path": str(path.relative_to(root)),
                "markdown": markdown,
                "size": path.stat().st_size,
                "mtime": path.stat().st_mtime,
            }
            output_files.append(item)
            if not result_markdown:
                result_markdown = markdown
        dataflow_dir = output_root / "dataflow"
        if dataflow_dir.exists():
            for path in sorted(dataflow_dir.glob("*.md")):
                dataflow_files.append({
                    "name": path.name,
                    "relative_path": str(path.relative_to(root)),
                    "markdown": _read_text(path, warnings, path.name),
                    "size": path.stat().st_size,
                    "mtime": path.stat().st_mtime,
                })

    run_report = _read_text(latest_run_root / "report.md", warnings, "run/report.md") if latest_run_root.exists() else ""
    available = bool(result_markdown or run_report or dataflow_files or result_json)
    if row.status not in TERMINAL_STATUSES and not available:
        available = False

    summary = _summarize_rounds(rounds, result_json)
    # Enrich summary with vuln-graph data (function_count, total_findings) when
    # the round-based summary is incomplete for the new SQLite-based architecture.
    try:
        graph_run_root = latest_run_root if latest_run_root.exists() else run_root
        graph = load_vuln_scan_graph(graph_run_root)
        graph_summary = summarize_graph(graph)
        if graph_summary.get("runs", 0) > 0:
            if not summary.get("function_count"):
                summary["function_count"] = graph_summary["runs"]
            summary["total_findings"] = graph_summary["findings"]
            findings = graph.get("vulnerability_findings") or []
            by_severity: dict[str, int] = {}
            for f in findings:
                sev = str(f.get("severity") or "unknown").upper()
                by_severity[sev] = by_severity.get(sev, 0) + 1
            summary["findings_by_severity"] = by_severity
    except Exception:
        pass

    return {
        "task_id": task_id,
        "available": available,
        "status": row.status,
        "output_root": str(output_root) if str(root) else "",
        "latest_run_root": str(latest_run_root) if latest_run_root.exists() else "",
        "current_epoch": current_epoch,
        "warnings": warnings,
        "result_markdown": result_markdown,
        "run_report_markdown": run_report,
        "result_json": result_json,
        "output_files": output_files,
        "dataflow_files": dataflow_files,
        "summary": summary,
    }


@router.get("/tasks/{task_id}/sessions")
def list_task_sessions(task_id: str, db: Session = Depends(get_db)):
    row = _get_task_row(db, task_id)
    catalog = _build_task_session_catalog(row)
    return {"task_id": task_id, "items": catalog.get("items", []), "current_epoch": None}

@router.get("/tasks/{task_id}/sessions/index", response_model=TaskSessionIndexResponse)
def get_task_session_index(task_id: str, db: Session = Depends(get_db)):
    row = _get_task_row(db, task_id)
    catalog = _build_task_session_catalog(row)
    return {
        "task_id": catalog.get("task_id") or row.task_id,
        "status": catalog.get("status") or row.status,
        "sessions_root": catalog.get("sessions_root"),
        "index_path": catalog.get("index_path"),
        "generated_at": catalog.get("generated_at"),
        **(catalog.get("index") or {}),
    }


@router.get("/tasks/{task_id}/sessions/file")
def get_task_session_file(task_id: str, path: str = Query(...), db: Session = Depends(get_db)):
    row = _get_task_row(db, task_id)
    root = _task_root(row)
    target = _safe_session_file(root, path)
    parsed = _parse_session_file(target)
    stat = target.stat()
    return {
        "task_id": task_id,
        "path": path,
        "line_count": parsed["line_count"],
        "events": parsed["events"],
        "warnings": parsed["warnings"],
        "session_meta": parsed["session_meta"],
        "meta": {
            "session_id": path,
            "session_name": target.stem,
            "relative_path": path,
            "stage_group": "root",
            "role_name": target.stem,
            "size": stat.st_size,
            "mtime": stat.st_mtime,
            "event_count": parsed["line_count"],
            "is_active": row.status == "running",
            "display_name": target.stem,
        },
    }


@router.get("/tasks/{task_id}/evaluation")
def get_task_evaluation(task_id: str, db: Session = Depends(get_db)):
    return get_task_service().get_task_evaluation(db, task_id)


@router.post("/tasks/{task_id}/cancel")
def cancel_task(task_id: str, db: Session = Depends(get_db)):
    return get_task_service().cancel_task(db, task_id)

@router.post("/tasks/{task_id}/restart", status_code=201)
def restart_task(task_id: str, db: Session = Depends(get_db)):
    """Clone an existing task and start it immediately."""
    return get_task_service().restart_task(db, task_id)


@router.post("/tasks/{task_id}/resume", status_code=201)
def resume_task(task_id: str, db: Session = Depends(get_db)):
    """resume 暂未实现，等同于 restart（重新执行）。"""
    return get_task_service().restart_task(db, task_id)


@router.delete("/tasks/{task_id}", status_code=204)
def delete_task(
    task_id: str,
    delete_files: bool = True,
    db: Session = Depends(get_db),
):
    """软删除任务记录，可选删除输出目录文件。"""
    get_task_service().delete_task(db, task_id, delete_files=delete_files)


@router.get("/tasks/{task_id}/timeline", response_model=TaskTimelineResponse)
def get_task_timeline(task_id: str, db: Session = Depends(get_db)):
    return get_task_service().get_task_timeline(db, task_id)


@router.delete("/tasks/{task_id}/timeline", response_model=ActionResponse)
def clear_task_timeline(task_id: str, db: Session = Depends(get_db)):
    deleted_event_count = get_task_service().clear_task_timeline(db, task_id)
    db.commit()
    return ActionResponse(status="ok", task_id=task_id, message="任务时间线已清空", deleted_event_count=deleted_event_count)


@router.delete("/tasks/{task_id}/timeline/{event_id}", response_model=ActionResponse)
def delete_task_timeline_event(task_id: str, event_id: str, db: Session = Depends(get_db)):
    deleted_event_count = get_task_service().delete_task_timeline_event(db, task_id, event_id)
    db.commit()
    return ActionResponse(status="ok", task_id=task_id, message="事件已删除", deleted_event_count=deleted_event_count)


@router.get("/tasks/{task_id}/logs")
def get_task_logs(task_id: str, db: Session = Depends(get_db)):
    """获取任务的实时阶段事件（stages_json）。"""
    from app.db.models import AppDvsTask
    row = db.query(AppDvsTask).filter(
        AppDvsTask.task_id == task_id,
        AppDvsTask.is_deleted.is_(False),
    ).first()
    if not row:
        from fastapi import HTTPException
        raise HTTPException(404, f"任务不存在: {task_id}")
    return {"task_id": task_id, "status": row.status,
            "stages_json": row.stages_json or {"events": []}}


@router.post("/generate-prompt")
def generate_prompt(body: GeneratePromptRequest):
    """Auto-generate a data flow analysis prompt from an input path."""
    return {"prompt": generate_prompt_from_path(body.input_path)}
