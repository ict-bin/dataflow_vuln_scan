"""SQLAlchemy ORM models for secflow-app-dataflow-vuln-scan."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

import json

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.mysql import JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.time_utils import now_local


class Base(DeclarativeBase):
    pass


class AppDvsTask(Base):
    """Data flow analysis task, scoped to a project."""
    __tablename__ = "secflow_app_dvs_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    project_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    task_origin_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    parent_project_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    parent_task_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    parent_task_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    parent_stage_name: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    parent_stage_item_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    parent_stage_item_key: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    task_name: Mapped[str] = mapped_column(String(255), nullable=False)
    task_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    input_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    module_input_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    source_root_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    output_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)

    prompt_template_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    prompt_content: Mapped[str] = mapped_column(Text, nullable=False)

    # Status: pending | running | passed | failed | error | cancelled
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    result_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    stages_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    latest_abnormal_reason_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Per-task overrides / resume flags (e.g. {"resume": true})
    task_config_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, onupdate=now_local)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    execution_owner_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    execution_lease_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, index=True)
    execution_heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    execution_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    control_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dispatch_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    vuln_total_count: Mapped[int] = mapped_column(Integer, nullable=False, default=-1)
    vuln_reported_count: Mapped[int] = mapped_column(Integer, nullable=False, default=-1)
    vuln_unreported_count: Mapped[int] = mapped_column(Integer, nullable=False, default=-1)

    celery_task_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class AppDvsTaskEvent(Base):
    """Database-backed task timeline event for DVS task execution tracing."""

    __tablename__ = "secflow_app_dvs_task_events"
    __table_args__ = (
        UniqueConstraint("dedupe_key", name="uq_secflow_app_dvs_task_events_dedupe_key"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="dvs", index=True)
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="info", index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    worker_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    execution_owner_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    execution_epoch: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    control_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dispatch_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    function_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_file: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    line_hint: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    parent_task_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    parent_stage_item_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    payload_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, index=True)

    @property
    def payload(self) -> dict[str, Any]:
        if not self.payload_json:
            return {}
        try:
            loaded = json.loads(self.payload_json)
            return loaded if isinstance(loaded, dict) else {}
        except Exception:
            return {}

    @payload.setter
    def payload(self, value: dict[str, Any] | None) -> None:
        self.payload_json = json.dumps(value or {}, ensure_ascii=False)


class AppDvsPromptTemplate(Base):
    """Reusable prompt templates for secflow-app-dataflow-vuln-scan."""
    __tablename__ = "secflow_app_dvs_prompt_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    prompt_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="general")
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    variables_json: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, onupdate=now_local)

    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class AppDvsProjectConfig(Base):
    """Global dataflow vulnerability mining configuration blob (project_id="" is the singleton)."""
    __tablename__ = "secflow_app_dvs_project_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    config_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, onupdate=now_local)


class AppDvsFailureDebug(Base):
    """任务失败时 LLM 自动调试生成的故障定位报告（debugger 角色）。"""
    __tablename__ = "secflow_app_dvs_failure_debug"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    project_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    task_name: Mapped[str] = mapped_column(String(255), nullable=False)
    # status: pending | running | done | error | skipped
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    error_kind: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    failing_stage: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    summary: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    report_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    report_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    debug_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, onupdate=now_local)


class AppDvsDebugConfig(Base):
    """Singleton config blob for the debugger role (e.g. debug model selection)."""
    __tablename__ = "secflow_app_dvs_debug_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    config_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True, default="global")
    config_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, onupdate=now_local)
