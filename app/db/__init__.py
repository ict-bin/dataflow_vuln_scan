"""Database engine and session management."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Generator, Literal

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

logger = logging.getLogger("dvs.db")

_engine = None
_SessionLocal = None

@dataclass(frozen=True)
class Migration:
    kind: Literal["column", "index", "table"]
    table_name: str
    name: str
    statement: str


_MIGRATIONS = [
    Migration(
        kind="index",
        table_name="secflow_app_dvs_worker_slots",
        name="ix_dvs_worker_slots_heartbeat",
        statement="CREATE INDEX ix_dvs_worker_slots_heartbeat ON secflow_app_dvs_worker_slots (last_heartbeat_at)",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_worker_slots",
        name="http_port",
        statement="ALTER TABLE secflow_app_dvs_worker_slots ADD COLUMN http_port INTEGER NOT NULL DEFAULT 8080",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="task_config_json",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN task_config_json JSON NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="stages_json",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN stages_json JSON NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="latest_abnormal_reason_json",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN latest_abnormal_reason_json JSON NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="prompt_template_id",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN prompt_template_id VARCHAR(64) NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="task_origin_type",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN task_origin_type VARCHAR(32) NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="parent_project_id",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN parent_project_id VARCHAR(100) NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="parent_task_id",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN parent_task_id VARCHAR(64) NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="parent_task_type",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN parent_task_type VARCHAR(32) NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="parent_stage_name",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN parent_stage_name VARCHAR(64) NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="parent_stage_item_id",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN parent_stage_item_id VARCHAR(64) NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="parent_stage_item_key",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN parent_stage_item_key VARCHAR(255) NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="module_input_path",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN module_input_path VARCHAR(1024) NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="source_root_path",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN source_root_path VARCHAR(1024) NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="execution_owner_id",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN execution_owner_id VARCHAR(128) NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="execution_lease_until",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN execution_lease_until DATETIME NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="execution_heartbeat_at",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN execution_heartbeat_at DATETIME NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="execution_epoch",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN execution_epoch INT NOT NULL DEFAULT 0",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="control_version",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN control_version INT NOT NULL DEFAULT 0",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="dispatch_status",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN dispatch_status VARCHAR(32) NULL",
    ),
    Migration(
        kind="index",
        table_name="secflow_app_dvs_tasks",
        name="ix_dvs_tasks_project_deleted_created_id",
        statement="CREATE INDEX ix_dvs_tasks_project_deleted_created_id ON secflow_app_dvs_tasks (project_id, is_deleted, created_at, id)",
    ),
    Migration(
        kind="index",
        table_name="secflow_app_dvs_tasks",
        name="ix_dvs_tasks_project_created_id",
        statement="CREATE INDEX ix_dvs_tasks_project_created_id ON secflow_app_dvs_tasks (project_id, created_at, id)",
    ),
    Migration(
        kind="index",
        table_name="secflow_app_dvs_tasks",
        name="ix_dvs_tasks_project_deleted_status_created_id",
        statement="CREATE INDEX ix_dvs_tasks_project_deleted_status_created_id ON secflow_app_dvs_tasks (project_id, is_deleted, status, created_at, id)",
    ),
    Migration(
        kind="index",
        table_name="secflow_app_dvs_tasks",
        name="ix_dvs_tasks_sched",
        statement="CREATE INDEX ix_dvs_tasks_sched ON secflow_app_dvs_tasks (is_deleted, status, execution_lease_until, created_at, id)",
    ),
    Migration(
        kind="index",
        table_name="secflow_app_dvs_tasks",
        name="ix_dvs_tasks_owner",
        statement="CREATE INDEX ix_dvs_tasks_owner ON secflow_app_dvs_tasks (execution_owner_id, status)",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="vuln_total_count",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN vuln_total_count INT NOT NULL DEFAULT -1",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="vuln_reported_count",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN vuln_reported_count INT NOT NULL DEFAULT -1",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="vuln_unreported_count",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN vuln_unreported_count INT NOT NULL DEFAULT -1",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="celery_task_id",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN celery_task_id VARCHAR(64) NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="dispatch_reserved_at",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN dispatch_reserved_at DATETIME NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="dispatch_published_at",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN dispatch_published_at DATETIME NULL",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="dispatch_attempts",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN dispatch_attempts INT NOT NULL DEFAULT 0",
    ),
    Migration(
        kind="column",
        table_name="secflow_app_dvs_tasks",
        name="last_dispatch_error",
        statement="ALTER TABLE secflow_app_dvs_tasks ADD COLUMN last_dispatch_error TEXT NULL",
    ),
    Migration(
        kind="index",
        table_name="secflow_app_dvs_tasks",
        name="ix_dvs_tasks_dispatch_pending",
        statement=(
            "CREATE INDEX ix_dvs_tasks_dispatch_pending "
            "ON secflow_app_dvs_tasks (status, is_deleted, celery_task_id, created_at)"
        ),
    ),
]


def _migration_exists(engine, migration: Migration) -> bool:
    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    if migration.kind == "table":
        return migration.table_name in table_names
    if migration.table_name == "secflow_app_dvs_worker_slots" and "secflow_app_dvs_worker_slots" not in table_names:
        return False
    if migration.kind == "column":
        return migration.name in {col["name"] for col in inspector.get_columns(migration.table_name)}
    return migration.name in {idx["name"] for idx in inspector.get_indexes(migration.table_name)}


def _run_migrations(engine) -> None:
    """Apply additive schema migrations; silently skips already-applied ones."""
    with engine.connect() as conn:
        try:
            conn.execute(text("SET SESSION lock_wait_timeout = 5"))
        except Exception:
            conn.rollback()
        try:
            conn.execute(text("SET SESSION innodb_lock_wait_timeout = 5"))
        except Exception:
            conn.rollback()
        for migration in _MIGRATIONS:
            stmt = migration.statement
            if _migration_exists(engine, migration):
                logger.info("Migration already satisfied: %s %s.%s", migration.kind, migration.table_name, migration.name)
                continue
            try:
                logger.info("Migration begin: %s", stmt[:120])
                conn.execute(text(stmt))
                conn.commit()
                logger.info("Migration applied: %s", stmt[:120])
            except Exception as exc:
                conn.rollback()
                logger.info("Migration skipped: %s (%s)", stmt[:120], exc)


def init_db(db_url: str, pool_size: int = 5, max_overflow: int = 10) -> None:
    """Initialize the database engine and create tables."""
    global _engine, _SessionLocal
    logger.info("Database engine init begin")
    _engine = create_engine(
        db_url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=True,
        pool_recycle=3600,
    )
    # Long-running DVS tasks keep Python objects alive for tens of minutes while LLMs run.
    # Keep ORM instances usable after commit and avoid accidental lazy refresh on a stale MySQL
    # connection during terminal result materialization.
    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine, expire_on_commit=False)
    logger.info("Database metadata create_all begin")
    Base.metadata.create_all(bind=_engine)
    logger.info("Database metadata create_all done")
    logger.info("Database migrations begin")
    _run_migrations(_engine)
    logger.info("Database migrations done")
    logger.info("Database initialized")


def is_retryable_db_error(exc: BaseException) -> bool:
    """Return True for transient MySQL/DBAPI disconnect/deadlock errors."""
    if isinstance(exc, (OperationalError, InterfaceError, DBAPIError)):
        text = str(exc).lower()
        # MySQL: 2006 server has gone away, 2013 lost connection, 2014 commands out of sync,
        # 1205 lock wait timeout, 1213 deadlock. Also match common disconnect wording.
        return any(token in text for token in (
            "2006", "2013", "2014", "1205", "1213",
            "lost connection", "server has gone away", "connection reset",
            "connection refused", "broken pipe", "commands out of sync",
            "deadlock", "lock wait timeout",
        ))
    text = str(exc).lower()
    return any(token in text for token in ("lost connection", "server has gone away", "connection reset", "broken pipe"))


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that provides a DB session."""
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    db: Session = _SessionLocal()
    try:
        yield db
    finally:
        db.close()
