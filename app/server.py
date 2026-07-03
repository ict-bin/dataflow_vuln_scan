"""dataflow_vuln_scan — REST API 服务器

  Management layer (persistent, project-scoped):
    POST /api/app/dataflow-vuln-scan/tasks          创建任务
    GET  /api/app/dataflow-vuln-scan/tasks          任务列表（project_id 过滤）
    GET  /api/app/dataflow-vuln-scan/tasks/{id}     任务详情
    GET  /api/app/dataflow-vuln-scan/tasks/{id}/logs  实时阶段事件
    POST /api/app/dataflow-vuln-scan/tasks/{id}/cancel   取消任务
    POST /api/app/dataflow-vuln-scan/tasks/{id}/restart  重新运行
        POST /api/app/dataflow-vuln-scan/tasks/{id}/resume   断点续跑（暂未实现，等同于 restart）
    DELETE /api/app/dataflow-vuln-scan/tasks/{id}        删除任务
    GET  /api/app/dataflow-vuln-scan/prompts        Prompt 模板列表
    POST /api/app/dataflow-vuln-scan/prompts        创建 Prompt 模板
    GET  /api/app/dataflow-vuln-scan/prompts/{id}   Prompt 模板详情
    PUT  /api/app/dataflow-vuln-scan/prompts/{id}   更新 Prompt 模板
    DELETE /api/app/dataflow-vuln-scan/prompts/{id} 删除 Prompt 模板
    POST /api/app/dataflow-vuln-scan/prompts/{id}/clone  克隆 Prompt 模板
    POST /api/app/dataflow-vuln-scan/generate-prompt    根据路径生成 prompt
    GET  /api/app/dataflow-vuln-scan/health         健康检查

  Legacy engine routes (in-memory, backward compat):
    POST /analyse           直接提交分析（CLI 兼容）
    GET  /task/{id}         查询结果
    GET  /task/{id}/stream  SSE 实时事件流
    POST /task/{id}/abort   中止
    GET  /tasks             列出任务
    GET  /health            健康检查
"""

from __future__ import annotations

import threading
import contextlib
from queue import Queue, Full
import json
import logging
import os
import time
from contextlib import contextmanager
from threading import Lock
from typing import Any, Callable

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from fastapi.responses import StreamingResponse

from .build_info import build_service_meta
from .config import build_task_config, get_service_yaml, load_service_config
from .event_adapter import coerce_swarm_event
from .logging_utils import configure_container_logging
from .metrics import normalize_http_route, observe_http_request as observe_metrics_request, observe_http_request_inflight, render_aggregate_metrics, render_local_metrics, render_summary_metrics
from .metrics_summary import build_ai_summary, build_generic_observability_summary, build_rest_api_summary, parse_prometheus_metrics
from .models import SwarmEvent, TaskResult, TaskStatus, make_id
from .dataflow_v2.runner import DataflowV2Runner as Orchestrator
from .probe_server import ThreadedProbeServer
from .runtime_context import (
    DISPATCHER_ENABLED,
    EXECUTOR_ENABLED,
    INSTANCE_ID,
    PUBLIC_API_ENABLED,
    REGISTRY_ENABLED,
    ROLE,
)
from .service.runtime_bootstrap import get_runtime_bootstrap
from .service.task_service import get_task_service
from .time_utils import now_local
from .logging_utils import log_event

load_dotenv()
configure_container_logging("01-dataflow_vuln_scan")

# 使用统一的路径配置（优先读取环境变量）
from .config import CONFIG_DIR, TARGET_DIR

SERVICE_CONFIG_PATH = os.environ.get("SERVICE_CONFIG", f"{CONFIG_DIR}/config.json")
CLEANUP_DELAY = int(os.environ.get("CLEANUP_DELAY", "300"))
_SUMMARY_CACHE_TTL_SECONDS = 5.0
_summary_cache: dict[str, tuple[float, Any]] = {}
_summary_cache_lock = Lock()
_loop_lag_seconds = 0.0
_loop_lag_exceeded_total = 0
_control_plane_last_tick_at = 0.0
_probe_server: ThreadedProbeServer | None = None
_probe_shutdown = False
_probe_started_at = 0.0

logger = logging.getLogger("dvs.server")


def _external_probe_process_enabled() -> bool:
    return str(os.environ.get("SECFLOW_EXTERNAL_PROBE_PROCESS", "")).strip().lower() in {"1", "true", "yes", "on"}


def _cached_summary(key: str, builder: Callable[[], Any]) -> Any:
    now = time.monotonic()
    with _summary_cache_lock:
        cached = _summary_cache.get(key)
        if cached and now - cached[0] <= _SUMMARY_CACHE_TTL_SECONDS:
            return cached[1]
    value = builder()
    with _summary_cache_lock:
        _summary_cache[key] = (time.monotonic(), value)
    return value


def _aggregate_metrics_rows():
    return parse_prometheus_metrics(render_summary_metrics())


def _control_plane_loop_monitor() -> None:
    global _loop_lag_seconds, _loop_lag_exceeded_total, _control_plane_last_tick_at
    interval = 1.0
    while True:
        started = time.monotonic()
        time.sleep(interval)
        now = time.monotonic()
        lag = max(0.0, now - started - interval)
        _loop_lag_seconds = lag
        _control_plane_last_tick_at = time.time()
        if lag > 2.0:
            _loop_lag_exceeded_total += 1
            log_event(
                logger,
                logging.ERROR if lag > 5.0 else logging.WARNING,
                "control-plane event loop lag detected",
                event="control_plane_event_loop_stall_detected",
                lag_seconds=round(lag, 3),
            )


class TaskEntry:
    def __init__(self, orch: Orchestrator, task_id: str, prompt: str):
        self.orch = orch
        self.task_id = task_id
        self.prompt = prompt
        self.result: TaskResult | None = None
        self.events: list[dict] = []
        self.queues: list[Queue] = []
        self.done = threading.Event()
        self.callback_url: str | None = None


_tasks: dict[str, TaskEntry] = {}


def _forbidden_for_role(feature: str) -> HTTPException:
    return HTTPException(status_code=503, detail=f"{feature} disabled for role={ROLE}")


# ─── Lifespan ────────────────────────────────────────────────────────────────

# @asynccontextmanager replaced with on_event
def _on_startup():
    global _probe_shutdown, _probe_started_at
    _probe_shutdown = False
    _probe_started_at = time.time()
    if not _external_probe_process_enabled():
        _ensure_probe_server_started()
    get_runtime_bootstrap().start(app)
    lag_thread = threading.Thread(target=_control_plane_loop_monitor, name="dvs_control_plane_loop_monitor", daemon=True)
    lag_thread.start()
    app.state._lag_thread = lag_thread

def _on_shutdown():
    global _probe_shutdown
    _probe_shutdown = True
    lag_thread = getattr(app.state, '_lag_thread', None)
    if lag_thread:
        lag_thread.join(timeout=5.0)
    get_runtime_bootstrap().stop()
    if not _external_probe_process_enabled():
        _stop_probe_server()
app = FastAPI(title="dataflow_vuln_scan", version="2.0.0")

@app.on_event("startup")
def _on_startup_event():
    _on_startup()

@app.on_event("shutdown")
def _on_shutdown_event():
    _on_shutdown()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
get_runtime_bootstrap().install_internal_observability_router(app)


@app.middleware("http")
async def collect_request_metrics(request, call_next):
    started = time.perf_counter()
    response = None
    route = request.scope.get("route")
    path = getattr(route, "path", None) or request.url.path
    normalized_route = normalize_http_route(str(path))
    observe_http_request_inflight(request.method, normalized_route, 1)
    try:
        response = await call_next(request)
        return response
    finally:
        status_code = response.status_code if response is not None else 500
        observe_metrics_request(request.method, str(path), status_code, time.perf_counter() - started)
        observe_http_request_inflight(request.method, normalized_route, -1)

# 启动时加载一次服务配置
_svc_config = None


def _get_svc_config():
    global _svc_config
    if _svc_config is None:
        for p in [SERVICE_CONFIG_PATH, "/opt/dataflow_vuln_scan/config.example.json"]:
            if os.path.isfile(p):
                _svc_config = load_service_config(p)
                break
        if _svc_config is None:
            raise RuntimeError(f"服务配置文件不存在: {SERVICE_CONFIG_PATH}")
    return _svc_config


@app.get("/metrics")
@app.get("/api/app/dataflow-vuln-scan/metrics", include_in_schema=False)
def metrics():
    return PlainTextResponse(render_local_metrics(), media_type="text/plain; version=0.0.4; charset=utf-8")


@app.get("/api/app/dataflow-vuln-scan/metrics/aggregate", include_in_schema=False)
def aggregate_metrics():
    return PlainTextResponse(render_aggregate_metrics(), media_type="text/plain; version=0.0.4; charset=utf-8")


@app.get("/api/app/dataflow-vuln-scan/metrics/summary", include_in_schema=False)
def metrics_summary():
    return _cached_summary(
        "summary",
        lambda: build_generic_observability_summary(_aggregate_metrics_rows(), title="数据流漏洞挖掘"),
    )


@app.get("/api/app/dataflow-vuln-scan/metrics/rest-api-summary", include_in_schema=False)
def metrics_rest_api_summary():
    return _cached_summary(
        "rest-api-summary",
        lambda: build_rest_api_summary(_aggregate_metrics_rows()),
    )


@app.get("/api/app/dataflow-vuln-scan/metrics/ai-summary", include_in_schema=False)
def metrics_ai_summary():
    return _cached_summary(
        "ai-summary",
        lambda: build_ai_summary(_aggregate_metrics_rows(), coverage_text="数据流漏洞挖掘 AI 指标覆盖 trace / round / review / judge 相关调用。"),
    )


# ─── 请求体 ──────────────────────────────────────────────────────────────────

class AnalyseRequest(BaseModel):
    prompt: str = Field(..., description="一句话任务描述，如：对 firmware.c 的 parse_packet 函数完成数据流漏洞挖掘")
    cwd: str = Field(default="", description="待分析文件目录，默认 /data/target")
    callback_url: str = Field(default="", description="任务完成后 POST 通知的 URL")


# ─── 路由 ─────────────────────────────────────────────────────────────────────

@app.get("/health")
@app.get("/api/app/dataflow-vuln-scan/health")
def health():
    return _probe_payload()


def _probe_payload() -> dict[str, object]:
    bootstrap = get_runtime_bootstrap().status()
    worker_slot = get_runtime_bootstrap().worker_slot_status()
    running_task_reconcile = get_runtime_bootstrap().running_task_reconcile_status()
    supervisor = get_task_service().supervisor_status()
    runtime_reconcile = get_task_service().runtime_reconcile_status()
    local_running_raw = get_task_service().local_running_task_count_raw()
    local_running_effective = get_task_service().local_effective_running_task_count()
    local_stale_contexts = get_task_service().local_stale_context_count()
    now_ts = time.time()
    heartbeat_recent = bool(worker_slot["last_heartbeat_at"] and now_ts - float(worker_slot["last_heartbeat_at"]) <= 90)
    worker_role_enabled = ROLE in {"worker", "all", "standalone"} or bool(DISPATCHER_ENABLED or EXECUTOR_ENABLED)
    worker_ready = (not worker_role_enabled) or (
        bool(worker_slot["thread_alive"])
        and heartbeat_recent
        and bool(supervisor["thread_alive"])
    )
    ready_ok = bool(
        bootstrap["ready"]
        and worker_ready
        and _loop_lag_seconds <= 5.0
        and not _probe_shutdown
    )
    payload = {
        "status": "ready" if ready_ok else ("stopping" if _probe_shutdown else ("booting" if bootstrap["error"] is None else "error")),
        **build_service_meta(),
        "service": "secflow-app-dataflow-vuln-scan",
        "instance_id": INSTANCE_ID,
        "role": ROLE,
        "public_api_enabled": PUBLIC_API_ENABLED,
        "dispatcher_enabled": DISPATCHER_ENABLED,
        "executor_enabled": EXECUTOR_ENABLED,
        "registry_enabled": REGISTRY_ENABLED,
        "active": sum(1 for t in _tasks.values() if t.result is None),
        "completed": sum(1 for t in _tasks.values() if t.result is not None),
        "dispatcher_running": get_runtime_bootstrap().dispatcher_running(),
        "leased_tasks": local_running_effective,
        "local_running_task_count_raw": local_running_raw,
        "local_effective_running_task_count": local_running_effective,
        "local_stale_context_count": local_stale_contexts,
        "startup_phase": bootstrap["phase"],
        "startup_ready": bootstrap["ready"],
        "startup_error": bootstrap["error"],
        "db_ready": bootstrap["db_ready"],
        "management_api_ready": bootstrap["management_api_ready"],
        "bootstrap_attempts": bootstrap["attempts"],
        "control_plane_alive": True,
        "control_plane_last_tick_at": _control_plane_last_tick_at or None,
        "event_loop_lag_seconds": _loop_lag_seconds,
        "event_loop_lag_exceeded_total": _loop_lag_exceeded_total,
        "worker_slot_heartbeat_thread_alive": worker_slot["thread_alive"],
        "worker_slot_last_heartbeat_at": worker_slot["last_heartbeat_at"] or None,
        "worker_slot_last_heartbeat_ok": worker_slot["last_heartbeat_ok"],
        "worker_slot_last_error": worker_slot["last_error"],
        "execution_supervisor_thread_alive": supervisor["thread_alive"],
        "execution_supervisor_last_run_at": supervisor["last_run_at"] or None,
        "execution_supervisor_last_error": supervisor["last_error"],
        "running_task_reconcile_thread_alive": running_task_reconcile["thread_alive"],
        "running_task_reconcile_last_run_at": running_task_reconcile["last_run_at"] or None,
        "running_task_reconcile_last_error": running_task_reconcile["last_error"],
        "runtime_reconcile_last_run_at": runtime_reconcile["last_run_at"] or None,
        "runtime_reconcile_last_error": runtime_reconcile["last_error"],
        "runtime_reconcile_db_repairs_total": runtime_reconcile["db_repairs_total"],
        "runtime_reconcile_local_drops_total": runtime_reconcile["local_drops_total"],
        "runtime_reconcile_db_recoveries_total": runtime_reconcile["db_recoveries_total"],
        "started_at": _probe_started_at or None,
        "updated_at": now_ts,
        "shutting_down": _probe_shutdown,
        "liveness_ok": (not _probe_shutdown) and bool((_control_plane_last_tick_at or 0) <= 0 or now_ts - float(_control_plane_last_tick_at or now_ts) <= 30.0),
        "readiness_ok": ready_ok,
        "last_error": bootstrap["error"],
        "reason": None if ready_ok else (
            "shutting_down"
            if _probe_shutdown
            else bootstrap["error"]
            or (
                "worker_slot_heartbeat_stale"
                if worker_role_enabled and not heartbeat_recent
                else (
                    "execution_supervisor_unavailable"
                    if worker_role_enabled and not bool(supervisor["thread_alive"])
                    else "control_plane_lagged"
                )
            )
        ),
        "checks": {
            "bootstrap": {
                "ready": bool(bootstrap["ready"]),
                "db_ready": bool(bootstrap["db_ready"]),
                "management_api_ready": bool(bootstrap["management_api_ready"]),
                "attempts": int(bootstrap["attempts"] or 0),
            },
            "control_plane": {
                "ok": _loop_lag_seconds <= 5.0,
                "event_loop_lag_seconds": _loop_lag_seconds,
                "last_tick_at": _control_plane_last_tick_at or None,
            },
            "heartbeat": {
                "ok": (not worker_role_enabled) or (heartbeat_recent and bool(worker_slot["thread_alive"])),
                "thread_alive": bool(worker_slot["thread_alive"]),
                "last_heartbeat_at": worker_slot["last_heartbeat_at"] or None,
                "last_heartbeat_ok": bool(worker_slot["last_heartbeat_ok"]),
                "last_error": worker_slot["last_error"],
                "required": worker_role_enabled,
            },
            "supervisor": {
                "ok": (not worker_role_enabled) or bool(supervisor["thread_alive"]),
                "thread_alive": bool(supervisor["thread_alive"]),
                "last_run_at": supervisor["last_run_at"] or None,
                "last_error": supervisor["last_error"],
                "required": worker_role_enabled,
            },
            "running_task_reconcile": {
                "ok": (not worker_role_enabled) or bool(running_task_reconcile["thread_alive"]),
                "thread_alive": bool(running_task_reconcile["thread_alive"]),
                "last_run_at": running_task_reconcile["last_run_at"] or None,
                "last_error": running_task_reconcile["last_error"],
                "required": worker_role_enabled,
            },
        },
    }
    return payload


def _ensure_probe_server_started() -> None:
    global _probe_server
    if _probe_server is not None:
        _probe_server.start()
        return
    port = int(os.environ.get("SECFLOW_DATAFLOW_ANALYSE_PROBE_PORT", "18080"))
    _probe_server = ThreadedProbeServer(
        host="0.0.0.0",
        port=port,
        payload_provider=_probe_payload,
        health_paths=("/health", "/api/app/dataflow-vuln-scan/health"),
        ready_paths=("/ready", "/api/app/dataflow-vuln-scan/ready"),
    )
    _probe_server.start()


def _stop_probe_server() -> None:
    global _probe_server
    if _probe_server is not None:
        _probe_server.stop()
        _probe_server = None


@app.get("/ready")
@app.get("/api/app/dataflow-vuln-scan/ready")
def ready():
    payload = _probe_payload()
    ready_ok = bool(payload["readiness_ok"])
    payload["status"] = "ready" if ready_ok else "not_ready"
    if ready_ok:
        return payload
    return JSONResponse(status_code=503, content=payload)


@app.post("/analyse", status_code=202)
def submit_analyse(body: AnalyseRequest):
    """提交分析任务。只需一句话 prompt。"""
    if not PUBLIC_API_ENABLED:
        raise _forbidden_for_role("legacy submit API")
    if not EXECUTOR_ENABLED:
        raise _forbidden_for_role("legacy in-process executor")
    svc = _get_svc_config()
    cwd = body.cwd or TARGET_DIR
    cfg = build_task_config(svc, body.prompt, cwd=cwd)
    task_id = make_id()

    def on_event(*args: Any, **kwargs: Any):
        event = coerce_swarm_event(*args, default_task_id=task_id, **kwargs)
        entry = _tasks.get(task_id)
        if not entry:
            return
        d = event.model_dump()
        entry.events.append(d)
        for q in entry.queues:
            try:
                q.put_nowait(d)
            except QueueFull:
                pass

    orch = Orchestrator(config=cfg, on_event=on_event, task_id=task_id)
    entry = TaskEntry(orch, task_id, body.prompt)
    entry.callback_url = body.callback_url or None
    _tasks[task_id] = entry

    def _run():
        try:
            entry.result = orch.execute_recursive(task_id)
        except Exception as e:
            entry.result = TaskResult(
                task_id=task_id, status=TaskStatus.ERROR,
                task=body.prompt, error=str(e))
        finally:
            done_data = {
                "type": "done", "task_id": task_id,
                "status": entry.result.status.value if entry.result else "error",
            }
            for q in entry.queues:
                try:
                    q.put_nowait(done_data)
                except QueueFull:
                    pass
            entry.done.set()
            if entry.callback_url and entry.result:
                _notify(entry)
            time.sleep(CLEANUP_DELAY)
            _tasks.pop(task_id, None)

    threading.Thread(target=_run, daemon=True).start()
    return {
        "task_id": task_id,
        "source_file": cfg.source_file,
        "function_name": cfg.function_name,
        "status": "accepted",
        "stream": f"/task/{task_id}/stream",
        "result": f"/task/{task_id}",
    }


def _notify(entry: TaskEntry):
    if not entry.callback_url or not entry.result:
        return
    try:
        with httpx.Client(timeout=30) as client:
            client.post(entry.callback_url, json={
                "task_id": entry.task_id,
                "status": entry.result.status.value,
                "duration_ms": entry.result.total_duration_ms,
                "cost": entry.result.total_tokens.cost,
            })
    except Exception:
        pass


@app.get("/task/{task_id}")
def get_task(task_id: str):
    if not PUBLIC_API_ENABLED:
        raise _forbidden_for_role("legacy task API")
    entry = _tasks.get(task_id)
    if not entry:
        raise HTTPException(404, "Task not found")
    if entry.result:
        return entry.result.model_dump()
    return {"task_id": task_id, "status": "running", "events_count": len(entry.events)}


@app.get("/task/{task_id}/stream")
def stream_task(task_id: str):
    if not PUBLIC_API_ENABLED:
        raise _forbidden_for_role("legacy task stream API")
    entry = _tasks.get(task_id)
    if not entry:
        raise HTTPException(404, "Task not found")
    queue: Queue = Queue(maxsize=1000)
    entry.queues.append(queue)

    def gen():
        for evt in entry.events:
            yield {"data": json.dumps(evt, ensure_ascii=False)}
        if entry.result:
            yield {"data": json.dumps({"type": "done", "task_id": task_id})}
            return
        try:
            while True:
                try:
                    evt = queue.get(timeout=30)
                    yield {"data": json.dumps(evt, ensure_ascii=False)}
                    if evt.get("type") == "done":
                        return
                except queue.Empty:
                    yield {"comment": "keepalive"}
        finally:
            if queue in entry.queues:
                entry.queues.remove(queue)

    def _sse_gen():
        yield from gen()
    return StreamingResponse(_sse_gen(), media_type="text/event-stream")


@app.post("/task/{task_id}/abort")
def abort_task(task_id: str):
    if not PUBLIC_API_ENABLED:
        raise _forbidden_for_role("legacy task abort API")
    entry = _tasks.get(task_id)
    if not entry:
        raise HTTPException(404)
    if entry.result:
        return {"message": "Already completed", "status": entry.result.status.value}
    entry.orch.abort()
    return {"message": "Abort sent", "task_id": task_id}


@app.get("/tasks")
def list_tasks():
    if not PUBLIC_API_ENABLED:
        raise _forbidden_for_role("legacy task list API")
    return {"tasks": [
        {"task_id": tid, "prompt": e.prompt[:100],
         "status": e.result.status.value if e.result else "running"}
        for tid, e in _tasks.items()
    ]}
