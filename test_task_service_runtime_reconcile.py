import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.db.models import AppDvsTask, Base
from app.service import task_service as task_service_module
from app.service.task_service import (
    TaskService,
    _RunningTaskContext,
    _register_running_task_context,
    _unregister_running_task_context,
    _get_running_task_context,
)
from app.time_utils import now_local


class TaskServiceRuntimeReconcileTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.service = TaskService()
        self._clear_runtime_state()

    def tearDown(self):
        self._clear_runtime_state()

    def _clear_runtime_state(self):
        with task_service_module._RUNNING_TASK_LOCK:
            task_service_module._running_tasks.clear()
            task_service_module._running_task_contexts.clear()
            task_service_module._runtime_invalidations.clear()

    def _session(self):
        return self.Session()

    def _insert_task(self, **kwargs):
        db = self._session()
        try:
            row = AppDvsTask(
                task_id=kwargs.get("task_id", "dvs_test_1"),
                project_id=kwargs.get("project_id", "p1"),
                task_name=kwargs.get("task_name", "test"),
                input_path=kwargs.get("input_path", "/data/files/p1/input"),
                output_path=kwargs.get("output_path", "/data/files/p1/output"),
                prompt_content=kwargs.get("prompt_content", "analyse"),
                status=kwargs.get("status", "pending"),
                execution_owner_id=kwargs.get("execution_owner_id"),
                execution_lease_until=kwargs.get("execution_lease_until"),
                execution_heartbeat_at=kwargs.get("execution_heartbeat_at"),
                execution_epoch=kwargs.get("execution_epoch", 0),
                control_version=kwargs.get("control_version", 0),
                dispatch_status=kwargs.get("dispatch_status"),
            )
            db.add(row)
            db.commit()
        finally:
            db.close()

    def test_dead_context_does_not_count_as_effective_running(self):
        _register_running_task_context("task-a", execution_thread=threading.Thread(target=lambda: None))
        self.assertEqual(1, self.service.local_running_task_count_raw())
        with patch.object(TaskService, "_has_strong_runtime_evidence", return_value=False):
            self.assertEqual(0, self.service.local_effective_running_task_count())
            self.assertEqual(1, self.service.local_stale_context_count())

    def test_reconcile_repairs_db_when_runtime_evidence_exists_and_owner_missing(self):
        self._insert_task(
            task_id="task-repair",
            status="pending",
            execution_owner_id=None,
            execution_epoch=7,
            control_version=3,
            dispatch_status="pending",
        )
        _register_running_task_context(
            "task-repair",
            execution_thread=threading.Thread(target=lambda: None),
            epoch=7,
            control_version=3,
        )
        db = self._session()
        try:
            with patch.object(TaskService, "_has_strong_runtime_evidence", return_value=True):
                decisions = self.service.reconcile_running_task_contexts(db)
            row = db.query(AppDvsTask).filter_by(task_id="task-repair").first()
            self.assertEqual(1, decisions["db_repairs"])
            self.assertEqual("running", row.status)
            self.assertEqual("running", row.dispatch_status)
            self.assertEqual(task_service_module.WORKER_ID, row.execution_owner_id)
        finally:
            db.close()

    def test_reconcile_recovers_db_to_pending_when_no_runtime_evidence(self):
        now = now_local()
        self._insert_task(
            task_id="task-recover",
            status="running",
            execution_owner_id=task_service_module.WORKER_ID,
            execution_lease_until=now,
            execution_heartbeat_at=now,
            execution_epoch=5,
            control_version=2,
            dispatch_status="running",
        )
        _register_running_task_context(
            "task-recover",
            execution_thread=threading.Thread(target=lambda: None),
            epoch=5,
            control_version=2,
        )
        db = self._session()
        try:
            with patch.object(TaskService, "_has_strong_runtime_evidence", return_value=False):
                decisions = self.service.reconcile_running_task_contexts(db)
            row = db.query(AppDvsTask).filter_by(task_id="task-recover").first()
            self.assertEqual(1, decisions["db_recoveries"])
            self.assertEqual(1, decisions["local_drops"])
            self.assertEqual("pending", row.status)
            self.assertEqual("pending", row.dispatch_status)
            self.assertIsNone(row.execution_owner_id)
            self.assertIsNone(_get_running_task_context("task-recover"))
        finally:
            db.close()

    def test_handle_ownership_lost_unregisters_context_immediately(self):
        _register_running_task_context(
            "task-owned",
            execution_thread=threading.Thread(target=lambda: time.sleep(1)),
            epoch=2,
            control_version=9,
        )
        self.assertIsNotNone(_get_running_task_context("task-owned"))
        self.service._handle_ownership_lost(
            None,
            task_id="task-owned",
            epoch=2,
            control_version=9,
            reason="control_guard_abort",
            event_type="task_control_guard_abort",
            message="ownership changed",
        )
        self.assertIsNone(_get_running_task_context("task-owned"))

    def test_dispatch_once_reconciles_stale_context_before_capacity_check(self):
        _register_running_task_context("task-stale", execution_thread=threading.Thread(target=lambda: None))
        with patch.object(TaskService, "reconcile_stale_local_contexts_before_claim", side_effect=lambda: _unregister_running_task_context("task-stale")) as reconcile_mock, patch.object(
            TaskService,
            "local_effective_running_task_count",
            side_effect=[0],
        ), patch("app.db.get_db") as get_db_mock:
            class _DummyDb:
                pass

            def _gen():
                db = _DummyDb()
                yield db

            get_db_mock.side_effect = _gen
            with patch("app.service.task_service.claim_one_runnable_task", return_value=None):
                task_id = self.service.dispatch_once()
        self.assertIsNone(task_id)
        reconcile_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
