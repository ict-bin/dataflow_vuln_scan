"""Bootstrap DB-dependent runtime components with retry.

v1 的 dispatcher/worker_slot/reconcile 已删除 (Celery 接管调度)。
本模块现在只负责: DB init + 管理 router (api/debugger) + registry (api) + failure_debug (debugger)。
worker pod 跑 celery CLI, 不经本模块。
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import asdict, dataclass
from typing import Optional

from fastapi import FastAPI

from app.config import get_service_yaml
from app.runtime_context import (
    INSTANCE_ID,
    PUBLIC_API_ENABLED,
    REGISTRY_ENABLED,
    ROLE,
    is_debugger_role,
)
from app.service.task_service import get_task_service
from app.logging_utils import log_event

logger = logging.getLogger("dvs.bootstrap")

DB_INIT_RETRY_SECONDS = int(os.environ.get("DVS_DB_INIT_RETRY_SECONDS", "5"))


@dataclass
class RuntimeBootstrapStatus:
    db_ready: bool = False
    management_api_ready: bool = False
    registry_ready: bool = False
    failure_debug_started: bool = False
    ready: bool = False
    phase: str = "booting"
    error: str | None = None
    attempts: int = 0


class RuntimeBootstrap:
    def __init__(self) -> None:
        self._task: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._status = RuntimeBootstrapStatus()
        self._router_installed = False

    def start(self, app: FastAPI) -> None:
        if self._task and self._task.is_alive():
            return
        self._stop_event = threading.Event()
        self._status = RuntimeBootstrapStatus()
        self._task = threading.Thread(target=self._bootstrap_loop, args=(app,), name="dvs_runtime_bootstrap", daemon=True)
        self._task.start()

    def stop(self) -> None:
        self._stop_event.set()
        svc = get_task_service()
        stop_supervisor = getattr(svc, "stop_supervisor", None)
        if callable(stop_supervisor):
            stop_supervisor()
        if self._task and self._task.is_alive():
            self._task.join(timeout=5.0)
        self._task = None
        try:
            from app.service.failure_debug import get_failure_debug_service

            get_failure_debug_service().stop()
        except Exception as _e:
            logger.warning("unexpected error stopping failure_debug: %s", _e, exc_info=True)
        try:
            from app.service.registry_service import get_registry_service

            get_registry_service().stop()
        except Exception as _e:
            logger.warning("unexpected error in runtime_bootstrap.py: %s", _e, exc_info=True)
        log_event(logger, logging.INFO, "runtime bootstrap stopped", event="runtime_bootstrap_stopped", owner_id=INSTANCE_ID)

    def status(self) -> dict:
        return asdict(self._status)

    def _bootstrap_loop(self, app: FastAPI) -> None:
        svc_yaml = get_service_yaml()

        while not self._stop_event.is_set():
            made_progress = False

            if not self._status.db_ready:
                made_progress = self._init_db(svc_yaml)

            if self._status.db_ready:
                if (PUBLIC_API_ENABLED or is_debugger_role()) and not self._router_installed:
                    made_progress = self._attempt_component_start(
                        "router_init",
                        lambda: self._install_management_router(app),
                    ) or made_progress

                if REGISTRY_ENABLED and not self._status.registry_ready:
                    made_progress = self._attempt_async_component_start(
                        "registry_register",
                        self._register_registry,
                    ) or made_progress

                # debugger 角色：DB 就绪后启动失败调试循环
                if is_debugger_role() and self._status.db_ready and not self._status.failure_debug_started:
                    made_progress = self._attempt_component_start(
                        "failure_debug_start",
                        self._start_failure_debug,
                    ) or made_progress

                if self._all_required_components_ready():
                    self._status.phase = "ready"
                    self._status.ready = True
                    self._status.error = None
                    log_event(
                        logger,
                        logging.INFO,
                        "startup ready",
                        event="startup_ready",
                        owner_id=INSTANCE_ID,
                        role=ROLE,
                        public_api_enabled=PUBLIC_API_ENABLED,
                        registry_enabled=REGISTRY_ENABLED,
                    )
                    return

            if made_progress:
                continue

            try:
                self._stop_event.wait(DB_INIT_RETRY_SECONDS)
            except Exception as _e:
                logger.warning("unexpected error in runtime_bootstrap.py: %s", _e, exc_info=True)

    def _init_db(self, svc_yaml) -> bool:
        self._status.phase = "db_init"
        self._status.attempts += 1
        log_event(logger, logging.INFO, "startup phase begin", event="startup_phase_begin", phase=self._status.phase)
        try:
            from app.db import init_db

            init_db(
                    svc_yaml.database.url,
                    svc_yaml.database.pool_size,
                    svc_yaml.database.max_overflow,
                )
            self._status.db_ready = True
            self._status.error = None
            logger.info("DB initialized: %s:%s/%s", svc_yaml.database.host, svc_yaml.database.port, svc_yaml.database.name)
            return True
        except Exception as exc:
            self._status.error = f"db_init: {exc}"
            logger.warning(
                "startup DB init failed on %s (attempt %s, retry in %ss): %s",
                INSTANCE_ID,
                self._status.attempts,
                DB_INIT_RETRY_SECONDS,
                exc,
            )
            return False

    def _attempt_component_start(self, phase: str, starter) -> bool:
        self._status.phase = phase
        log_event(logger, logging.INFO, "startup phase begin", event="startup_phase_begin", phase=phase)
        try:
            starter()
            self._status.error = None
            return True
        except Exception as exc:
            self._status.error = f"{phase}: {exc}"
            logger.warning("%s failed on %s (retry in %ss): %s", phase, INSTANCE_ID, DB_INIT_RETRY_SECONDS, exc, exc_info=True)
            return False

    def _attempt_async_component_start(self, phase: str, starter) -> bool:
        return self._attempt_component_start(phase, starter)

    def _install_management_router(self, app: FastAPI) -> None:
        from app.api import router as mgmt_router

        app.include_router(mgmt_router)
        self._router_installed = True
        self._status.management_api_ready = True

    def install_internal_observability_router(self, app: FastAPI) -> None:
        if getattr(app.state, "dvs_internal_observability_router_installed", False):
            return
        from app.api.tasks import internal_observability_router

        app.include_router(internal_observability_router)
        app.state.dvs_internal_observability_router_installed = True

    def _register_registry(self) -> None:
        from app.service.registry_service import get_registry_service

        registry = get_registry_service()
        registry.register()
        registry.start()
        self._status.registry_ready = True

    def _start_failure_debug(self) -> None:
        from app.service.failure_debug import get_failure_debug_service

        get_failure_debug_service().start()
        self._status.failure_debug_started = True

    def _all_required_components_ready(self) -> bool:
        if not self._status.db_ready:
            return False
        if (PUBLIC_API_ENABLED or is_debugger_role()) and not self._status.management_api_ready:
            return False
        if REGISTRY_ENABLED and not self._status.registry_ready:
            return False
        if is_debugger_role() and not self._status.failure_debug_started:
            return False
        return True


_runtime_bootstrap: RuntimeBootstrap | None = None


def get_runtime_bootstrap() -> RuntimeBootstrap:
    global _runtime_bootstrap
    if _runtime_bootstrap is None:
        _runtime_bootstrap = RuntimeBootstrap()
    return _runtime_bootstrap
