import unittest
from datetime import timedelta
from unittest.mock import Mock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AppDvsTask, Base
from app.dispatcher import Dispatcher
from app.service.execution_coordinator import claim_specific_task
from app.time_utils import now_local


class _FakeInspect:
    def __init__(
        self,
        active_payload=None,
        reserved_payload=None,
        scheduled_payload=None,
        ping_payload=None,
        stats_payload=None,
        error=None,
    ):
        self._active_payload = active_payload or {}
        self._reserved_payload = reserved_payload or {}
        self._scheduled_payload = scheduled_payload or {}
        self._ping_payload = ping_payload or {}
        self._stats_payload = stats_payload or {}
        self._error = error

    def _value(self, value):
        if self._error:
            raise self._error
        return value

    def active(self):
        return self._value(self._active_payload)

    def reserved(self):
        return self._value(self._reserved_payload)

    def scheduled(self):
        return self._value(self._scheduled_payload)

    def ping(self):
        return self._value(self._ping_payload)

    def stats(self):
        return self._value(self._stats_payload)


class _FakeControl:
    def __init__(self, inspect):
        self._inspect = inspect
        self.revoked: list[tuple[str, bool, str]] = []

    def inspect(self, timeout=None):
        return self._inspect

    def revoke(self, task_id, terminate=False, signal=None):
        self.revoked.append((task_id, terminate, signal))


class _FakeCeleryApp:
    def __init__(self, inspect):
        self.control = _FakeControl(inspect)


def _healthy_inspect(*, active=None, reserved=None, scheduled=None, capacity=1):
    return _FakeInspect(
        active_payload=active or {"worker-a": []},
        reserved_payload=reserved or {},
        scheduled_payload=scheduled or {},
        ping_payload={"worker-a": {"ok": "pong"}},
        stats_payload={"worker-a": {"pool": {"max-concurrency": capacity}}},
    )


class DispatcherTests(unittest.TestCase):
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
                dispatch_reserved_at=kwargs.get("dispatch_reserved_at"),
                dispatch_published_at=kwargs.get("dispatch_published_at"),
                dispatch_attempts=kwargs.get("dispatch_attempts", 0),
                last_dispatch_error=kwargs.get("last_dispatch_error"),
            )
            db.add(row)
            db.commit()
        finally:
            db.close()

    def _task(self, task_id):
        db = self.SessionLocal()
        try:
            return db.query(AppDvsTask).filter_by(task_id=task_id).first()
        finally:
            db.close()

    def test_pump_publishes_pending_task_only_once(self):
        self._insert_task(
            status="pending",
            celery_task_id=None,
            execution_owner_id=None,
            dispatch_status=None,
        )
        apply_async = Mock()
        dispatcher = Dispatcher()

        with patch("app.db.get_db", self._get_db), patch(
            "app.celery_tasks.run_dvs_task.apply_async", apply_async
        ):
            self.assertEqual(1, dispatcher._pump_once())
            self.assertEqual(0, dispatcher._pump_once())

        row = self._task("dvs_dispatcher_1")
        self.assertEqual(1, apply_async.call_count)
        self.assertEqual("published", row.dispatch_status)
        self.assertIsNotNone(row.celery_task_id)
        self.assertIsNotNone(row.dispatch_reserved_at)
        self.assertIsNotNone(row.dispatch_published_at)
        self.assertEqual(1, row.dispatch_attempts)
        self.assertIsNone(row.last_dispatch_error)
        self.assertEqual(("dvs_dispatcher_1",), apply_async.call_args.kwargs["args"])
        self.assertEqual(row.celery_task_id, apply_async.call_args.kwargs["task_id"])

    def test_pump_skips_candidate_when_another_scheduler_already_reserved_it(self):
        self._insert_task(
            status="pending",
            celery_task_id=None,
            execution_owner_id=None,
            dispatch_status=None,
        )
        dispatcher = Dispatcher()
        apply_async = Mock()

        def reservation_lost(*_args, **_kwargs):
            # Another scheduler won the conditional UPDATE before this one.
            return 0

        with patch("app.db.get_db", self._get_db), patch(
            "app.celery_tasks.run_dvs_task.apply_async", apply_async
        ), patch("sqlalchemy.orm.query.Query.update", autospec=True, side_effect=reservation_lost):
            self.assertEqual(0, dispatcher._pump_once())

        row = self._task("dvs_dispatcher_1")
        self.assertEqual(0, apply_async.call_count)
        self.assertIsNone(row.celery_task_id)

    def test_pump_publish_failure_releases_only_its_reservation(self):
        self._insert_task(
            status="pending",
            celery_task_id=None,
            execution_owner_id=None,
            dispatch_status=None,
        )
        dispatcher = Dispatcher()
        apply_async = Mock(side_effect=RuntimeError("redis unavailable"))

        with patch("app.db.get_db", self._get_db), patch(
            "app.celery_tasks.run_dvs_task.apply_async", apply_async
        ):
            self.assertEqual(0, dispatcher._pump_once())

        row = self._task("dvs_dispatcher_1")
        self.assertIsNone(row.celery_task_id)
        self.assertEqual("pending", row.dispatch_status)
        self.assertIsNone(row.dispatch_reserved_at)
        self.assertIsNone(row.dispatch_published_at)
        self.assertEqual(1, row.dispatch_attempts)
        self.assertIn("redis unavailable", row.last_dispatch_error)

    def test_pump_continues_after_publish_failure(self):
        self._insert_task(
            task_id="dvs_dispatcher_publish_fail",
            status="pending",
            celery_task_id=None,
            execution_owner_id=None,
            dispatch_status=None,
        )
        self._insert_task(
            task_id="dvs_dispatcher_publish_ok",
            status="pending",
            celery_task_id=None,
            execution_owner_id=None,
            dispatch_status=None,
        )
        apply_async = Mock(side_effect=[RuntimeError("first publish failed"), None])

        with patch("app.db.get_db", self._get_db), patch(
            "app.celery_tasks.run_dvs_task.apply_async", apply_async
        ):
            self.assertEqual(1, Dispatcher()._pump_once())

        failed = self._task("dvs_dispatcher_publish_fail")
        published = self._task("dvs_dispatcher_publish_ok")
        self.assertEqual(2, apply_async.call_count)
        self.assertIsNone(failed.celery_task_id)
        self.assertEqual("published", published.dispatch_status)
        self.assertIsNotNone(published.celery_task_id)

    def test_startup_does_not_clear_existing_dispatch_reservations(self):
        self._insert_task(
            status="pending",
            celery_task_id="celery-keep",
            execution_owner_id=None,
            dispatch_status="published",
            dispatch_reserved_at=now_local() - timedelta(minutes=1),
        )
        Dispatcher()._startup_reset()
        row = self._task("dvs_dispatcher_1")
        self.assertEqual("celery-keep", row.celery_task_id)
        self.assertEqual("published", row.dispatch_status)

    def test_stale_loop_keeps_running_task_when_heartbeat_is_fresh(self):
        self._insert_task(
            execution_heartbeat_at=now_local(),
            execution_lease_until=now_local() + timedelta(minutes=5),
        )
        fake_app = _FakeCeleryApp(_healthy_inspect())

        with patch("app.db.get_db", self._get_db), patch("app.celery_app.app", fake_app):
            reset = Dispatcher()._stale_once()

        self.assertEqual(0, reset)
        row = self._task("dvs_dispatcher_1")
        self.assertEqual("running", row.status)
        self.assertEqual("celery-1", row.celery_task_id)

    def test_stale_loop_resets_running_task_when_heartbeat_is_stale(self):
        self._insert_task(
            task_id="dvs_dispatcher_running",
            celery_task_id="celery-running",
            execution_heartbeat_at=now_local() - timedelta(seconds=601),
            execution_lease_until=now_local() - timedelta(seconds=1),
        )
        fake_app = _FakeCeleryApp(_healthy_inspect())

        with patch("app.db.get_db", self._get_db), patch("app.celery_app.app", fake_app), patch(
            "app.service.task_paths.cleanup_task_data"
        ):
            reset = Dispatcher()._stale_once()

        self.assertEqual(1, reset)
        self.assertEqual([("celery-running", True, "SIGKILL")], fake_app.control.revoked)
        row = self._task("dvs_dispatcher_running")
        self.assertEqual("pending", row.status)
        self.assertIsNone(row.celery_task_id)

    def test_aged_pending_dispatch_is_released_when_message_is_missing_and_capacity_is_free(self):
        self._insert_task(
            task_id="dvs_dispatcher_aged",
            status="pending",
            celery_task_id="celery-aged",
            execution_owner_id=None,
            execution_lease_until=None,
            execution_heartbeat_at=None,
            dispatch_status="published",
            dispatch_reserved_at=now_local() - timedelta(seconds=601),
            dispatch_published_at=now_local() - timedelta(seconds=601),
        )
        fake_app = _FakeCeleryApp(_healthy_inspect(capacity=2))

        with patch("app.db.get_db", self._get_db), patch("app.celery_app.app", fake_app):
            reset = Dispatcher()._stale_once()

        self.assertEqual(1, reset)
        row = self._task("dvs_dispatcher_aged")
        self.assertEqual("pending", row.dispatch_status)
        self.assertIsNone(row.celery_task_id)
        self.assertIsNone(row.dispatch_reserved_at)
        self.assertIn("aged out", row.last_dispatch_error)

    def test_aged_pending_dispatch_is_kept_when_celery_knows_the_message(self):
        self._insert_task(
            task_id="dvs_dispatcher_reserved",
            status="pending",
            celery_task_id="celery-reserved",
            execution_owner_id=None,
            execution_lease_until=None,
            execution_heartbeat_at=None,
            dispatch_status="published",
            dispatch_reserved_at=now_local() - timedelta(seconds=601),
        )
        fake_app = _FakeCeleryApp(
            _healthy_inspect(reserved={"worker-a": [{"id": "celery-reserved"}]})
        )

        with patch("app.db.get_db", self._get_db), patch("app.celery_app.app", fake_app):
            reset = Dispatcher()._stale_once()

        self.assertEqual(0, reset)
        row = self._task("dvs_dispatcher_reserved")
        self.assertEqual("celery-reserved", row.celery_task_id)

    def test_aged_pending_dispatch_is_kept_when_celery_is_active(self):
        self._insert_task(
            task_id="dvs_dispatcher_active",
            status="pending",
            celery_task_id="celery-active",
            execution_owner_id=None,
            execution_lease_until=None,
            execution_heartbeat_at=None,
            dispatch_status="published",
            dispatch_reserved_at=now_local() - timedelta(seconds=601),
        )
        fake_app = _FakeCeleryApp(
            _healthy_inspect(active={"worker-a": [{"id": "celery-active"}]}, capacity=2)
        )

        with patch("app.db.get_db", self._get_db), patch("app.celery_app.app", fake_app):
            reset = Dispatcher()._stale_once()

        self.assertEqual(0, reset)
        self.assertEqual("celery-active", self._task("dvs_dispatcher_active").celery_task_id)

    def test_aged_pending_dispatch_is_kept_when_celery_is_scheduled(self):
        self._insert_task(
            task_id="dvs_dispatcher_scheduled",
            status="pending",
            celery_task_id="celery-scheduled",
            execution_owner_id=None,
            execution_lease_until=None,
            execution_heartbeat_at=None,
            dispatch_status="published",
            dispatch_reserved_at=now_local() - timedelta(seconds=601),
        )
        fake_app = _FakeCeleryApp(
            _healthy_inspect(
                scheduled={"worker-a": [{"request": {"id": "celery-scheduled"}}]}
            )
        )

        with patch("app.db.get_db", self._get_db), patch("app.celery_app.app", fake_app):
            reset = Dispatcher()._stale_once()

        self.assertEqual(0, reset)
        self.assertEqual("celery-scheduled", self._task("dvs_dispatcher_scheduled").celery_task_id)

    def test_aged_pending_dispatch_is_kept_when_workers_are_full(self):
        self._insert_task(
            task_id="dvs_dispatcher_full",
            status="pending",
            celery_task_id="celery-full",
            execution_owner_id=None,
            execution_lease_until=None,
            execution_heartbeat_at=None,
            dispatch_status="published",
            dispatch_reserved_at=now_local() - timedelta(seconds=601),
        )
        fake_app = _FakeCeleryApp(
            _healthy_inspect(active={"worker-a": [{"id": "other-job"}]}, capacity=1)
        )

        with patch("app.db.get_db", self._get_db), patch("app.celery_app.app", fake_app):
            reset = Dispatcher()._stale_once()

        self.assertEqual(0, reset)
        self.assertEqual("celery-full", self._task("dvs_dispatcher_full").celery_task_id)

    def test_aged_pending_dispatch_is_kept_when_inspect_fails(self):
        self._insert_task(
            task_id="dvs_dispatcher_inspect_error",
            status="pending",
            celery_task_id="celery-inspect-error",
            execution_owner_id=None,
            execution_lease_until=None,
            execution_heartbeat_at=None,
            dispatch_status="published",
            dispatch_reserved_at=now_local() - timedelta(seconds=601),
        )
        fake_app = _FakeCeleryApp(_FakeInspect(error=RuntimeError("inspect timeout")))

        with patch("app.db.get_db", self._get_db), patch("app.celery_app.app", fake_app):
            reset = Dispatcher()._stale_once()

        self.assertEqual(0, reset)
        self.assertEqual(
            "celery-inspect-error",
            self._task("dvs_dispatcher_inspect_error").celery_task_id,
        )

    def test_old_celery_message_cannot_claim_a_republished_task(self):
        self._insert_task(
            task_id="dvs_dispatcher_republished",
            status="pending",
            celery_task_id="new-dispatch-id",
            execution_owner_id=None,
            execution_lease_until=None,
            dispatch_status="published",
        )
        db = self.SessionLocal()
        try:
            claimed = claim_specific_task(
                db,
                "worker-a",
                "dvs_dispatcher_republished",
                celery_task_id="old-dispatch-id",
            )
            self.assertIsNone(claimed)
            row = db.query(AppDvsTask).filter_by(task_id="dvs_dispatcher_republished").first()
            self.assertEqual("pending", row.status)
            self.assertIsNone(row.execution_owner_id)
        finally:
            db.close()

    def test_current_celery_message_claims_its_reserved_task(self):
        self._insert_task(
            task_id="dvs_dispatcher_current",
            status="pending",
            celery_task_id="current-dispatch-id",
            execution_owner_id=None,
            execution_lease_until=None,
            dispatch_status="published",
        )
        db = self.SessionLocal()
        try:
            claimed = claim_specific_task(
                db,
                "worker-a",
                "dvs_dispatcher_current",
                celery_task_id="current-dispatch-id",
            )
            self.assertIsNotNone(claimed)
            row = db.query(AppDvsTask).filter_by(task_id="dvs_dispatcher_current").first()
            self.assertEqual("worker-a", row.execution_owner_id)
            self.assertEqual("leased", row.dispatch_status)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
