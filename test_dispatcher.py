import unittest
from datetime import timedelta
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AppDvsTask, Base
from app.dispatcher import Dispatcher
from app.time_utils import now_local


class _FakeInspect:
    def __init__(self, active_payload, reserved_payload=None, scheduled_payload=None):
        self._active_payload = active_payload
        self._reserved_payload = reserved_payload or {}
        self._scheduled_payload = scheduled_payload or {}

    def active(self):
        return self._active_payload

    def reserved(self):
        return self._reserved_payload

    def scheduled(self):
        return self._scheduled_payload


class _FakeControl:
    def __init__(self, active_payload, reserved_payload=None, scheduled_payload=None):
        self._active_payload = active_payload
        self._reserved_payload = reserved_payload or {}
        self._scheduled_payload = scheduled_payload or {}
        self.revoked: list[tuple[str, bool, str]] = []

    def inspect(self, timeout=None):
        return _FakeInspect(self._active_payload, self._reserved_payload, self._scheduled_payload)

    def revoke(self, task_id, terminate=False, signal=None):
        self.revoked.append((task_id, terminate, signal))


class _FakeCeleryApp:
    def __init__(self, active_payload, reserved_payload=None, scheduled_payload=None):
        self.control = _FakeControl(active_payload, reserved_payload, scheduled_payload)


class DispatcherStaleLoopTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)

    def _get_db(self):
        db = self.SessionLocal()
        try:
            yield db
        finally:
            db.close()

    def _insert_task(self, **kwargs):
        db = self.SessionLocal()
        try:
            row = AppDvsTask(
                task_id=kwargs.get("task_id", "dvs_dispatcher_1"),
                project_id="p1",
                task_name="dispatcher-test",
                input_path="/tmp/in",
                output_path="/tmp/out",
                prompt_content="analyse",
                status=kwargs.get("status", "running"),
                celery_task_id=kwargs.get("celery_task_id", "celery-1"),
                execution_owner_id=kwargs.get("execution_owner_id", "pod-a"),
                execution_lease_until=kwargs.get("execution_lease_until"),
                execution_heartbeat_at=kwargs.get("execution_heartbeat_at"),
                execution_epoch=kwargs.get("execution_epoch", 1),
                dispatch_status=kwargs.get("dispatch_status", "running"),
            )
            db.add(row)
            db.commit()
        finally:
            db.close()

    def test_stale_loop_keeps_running_task_when_heartbeat_is_fresh_but_inspect_misses_it(self):
        self._insert_task(
            execution_heartbeat_at=now_local(),
            execution_lease_until=now_local() + timedelta(minutes=5),
        )
        fake_app = _FakeCeleryApp(active_payload={})
        dispatcher = Dispatcher()

        with patch("app.db.get_db", self._get_db), patch("app.celery_app.app", fake_app):
            reset = dispatcher._stale_once()

        self.assertEqual(0, reset)
        self.assertEqual([], fake_app.control.revoked)
        db = self.SessionLocal()
        try:
            row = db.query(AppDvsTask).filter_by(task_id="dvs_dispatcher_1").first()
            self.assertEqual("running", row.status)
            self.assertEqual("celery-1", row.celery_task_id)
            self.assertEqual("pod-a", row.execution_owner_id)
            self.assertEqual("running", row.dispatch_status)
        finally:
            db.close()

    def test_stale_loop_resets_running_task_when_heartbeat_is_stale(self):
        self._insert_task(
            task_id="dvs_dispatcher_2",
            celery_task_id="celery-2",
            execution_heartbeat_at=now_local() - timedelta(seconds=601),
            execution_lease_until=now_local() - timedelta(seconds=1),
        )
        fake_app = _FakeCeleryApp(active_payload={})
        dispatcher = Dispatcher()

        with patch("app.db.get_db", self._get_db), patch("app.celery_app.app", fake_app):
            reset = dispatcher._stale_once()

        self.assertEqual(1, reset)
        self.assertEqual([("celery-2", True, "SIGKILL")], fake_app.control.revoked)
        db = self.SessionLocal()
        try:
            row = db.query(AppDvsTask).filter_by(task_id="dvs_dispatcher_2").first()
            self.assertEqual("pending", row.status)
            self.assertIsNone(row.celery_task_id)
            self.assertIsNone(row.execution_owner_id)
            self.assertIsNone(row.execution_lease_until)
            self.assertIsNone(row.dispatch_status)
        finally:
            db.close()

    def test_stale_loop_keeps_recent_pending_task_with_celery_id(self):
        self._insert_task(
            task_id="dvs_dispatcher_3",
            status="pending",
            celery_task_id="celery-3",
            execution_owner_id=None,
            execution_lease_until=None,
            execution_heartbeat_at=None,
            dispatch_status=None,
        )
        fake_app = _FakeCeleryApp(active_payload={})
        dispatcher = Dispatcher()

        with patch("app.db.get_db", self._get_db), patch("app.celery_app.app", fake_app):
            reset = dispatcher._stale_once()

        self.assertEqual(0, reset)
        db = self.SessionLocal()
        try:
            row = db.query(AppDvsTask).filter_by(task_id="dvs_dispatcher_3").first()
            self.assertEqual("pending", row.status)
            self.assertEqual("celery-3", row.celery_task_id)
        finally:
            db.close()

    def test_stale_loop_resets_old_pending_task_with_lost_celery_message(self):
        self._insert_task(
            task_id="dvs_dispatcher_4",
            status="pending",
            celery_task_id="celery-4",
            execution_owner_id=None,
            execution_lease_until=None,
            execution_heartbeat_at=None,
            dispatch_status=None,
        )
        db = self.SessionLocal()
        try:
            row = db.query(AppDvsTask).filter_by(task_id="dvs_dispatcher_4").first()
            row.updated_at = now_local() - timedelta(seconds=601)
            db.commit()
        finally:
            db.close()
        fake_app = _FakeCeleryApp(active_payload={})
        dispatcher = Dispatcher()

        with patch("app.db.get_db", self._get_db), patch("app.celery_app.app", fake_app):
            reset = dispatcher._stale_once()

        self.assertEqual(1, reset)
        db = self.SessionLocal()
        try:
            row = db.query(AppDvsTask).filter_by(task_id="dvs_dispatcher_4").first()
            self.assertEqual("pending", row.status)
            self.assertIsNone(row.celery_task_id)
            self.assertIsNone(row.execution_owner_id)
            self.assertIsNone(row.execution_lease_until)
            self.assertIsNone(row.dispatch_status)
        finally:
            db.close()

    def test_stale_loop_keeps_pending_task_when_celery_is_reserved(self):
        self._insert_task(
            task_id="dvs_dispatcher_5",
            status="pending",
            celery_task_id="celery-5",
            execution_owner_id=None,
            execution_lease_until=None,
            execution_heartbeat_at=None,
            dispatch_status=None,
        )
        db = self.SessionLocal()
        try:
            row = db.query(AppDvsTask).filter_by(task_id="dvs_dispatcher_5").first()
            row.updated_at = now_local() - timedelta(seconds=601)
            db.commit()
        finally:
            db.close()
        fake_app = _FakeCeleryApp(active_payload={}, reserved_payload={"worker-a": [{"id": "celery-5"}]})
        dispatcher = Dispatcher()

        with patch("app.db.get_db", self._get_db), patch("app.celery_app.app", fake_app):
            reset = dispatcher._stale_once()

        self.assertEqual(0, reset)
        db = self.SessionLocal()
        try:
            row = db.query(AppDvsTask).filter_by(task_id="dvs_dispatcher_5").first()
            self.assertEqual("pending", row.status)
            self.assertEqual("celery-5", row.celery_task_id)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
