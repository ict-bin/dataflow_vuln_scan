import json
import unittest
from datetime import timedelta
from unittest.mock import Mock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AppDvsTask, Base
from app.dispatcher import Dispatcher, _celery_task_ids
from app.service.execution_coordinator import begin_delivery_handoff, claim_specific_task
from app.time_utils import now_local


class _FakeControl:
    def __init__(self):
        self.revoked: list[tuple[str, bool, str]] = []

    def revoke(self, task_id, terminate=False, signal=None):
        self.revoked.append((task_id, terminate, signal))


class _FakeCeleryApp:
    def __init__(self):
        self.control = _FakeControl()


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
                dispatch_broker_epoch=kwargs.get("dispatch_broker_epoch"),
                dispatch_delivery_started_at=kwargs.get("dispatch_delivery_started_at"),
                dispatch_delivery_worker_id=kwargs.get("dispatch_delivery_worker_id"),
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

    def test_celery_task_ids_reads_kombu_redis_envelopes(self):
        envelope = json.dumps([
            {"headers": {"id": "celery-envelope-id"}, "properties": {}},
            "",
            "dvs",
        ])
        self.assertEqual({"celery-envelope-id"}, _celery_task_ids([envelope]))

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
            "app.dispatcher._current_broker_epoch", return_value="epoch-a"
        ), patch(
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
        self.assertEqual("epoch-a", row.dispatch_broker_epoch)
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
            "app.dispatcher._current_broker_epoch", return_value="epoch-a"
        ), patch(
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
            "app.dispatcher._current_broker_epoch", return_value="epoch-a"
        ), patch(
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
            "app.dispatcher._current_broker_epoch", return_value="epoch-a"
        ), patch(
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
        fake_app = _FakeCeleryApp()

        with patch("app.db.get_db", self._get_db), patch(
            "app.celery_app.app", fake_app
        ), patch("app.dispatcher._current_broker_epoch", return_value="epoch-a"):
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
        fake_app = _FakeCeleryApp()

        with patch("app.db.get_db", self._get_db), patch(
            "app.celery_app.app", fake_app
        ), patch("app.dispatcher._current_broker_epoch", return_value="epoch-a"), patch(
            "app.service.task_paths.cleanup_task_data"
        ):
            reset = Dispatcher()._stale_once()

        self.assertEqual(1, reset)
        self.assertEqual([("celery-running", True, "SIGKILL")], fake_app.control.revoked)
        row = self._task("dvs_dispatcher_running")
        self.assertEqual("pending", row.status)
        self.assertIsNone(row.celery_task_id)

    def test_broker_epoch_change_releases_pending_dispatch_immediately(self):
        self._insert_task(
            task_id="dvs_dispatcher_broker_lost",
            status="pending",
            celery_task_id="celery-broker-lost",
            execution_owner_id=None,
            execution_lease_until=None,
            execution_heartbeat_at=None,
            dispatch_status="published",
            dispatch_reserved_at=now_local(),
            dispatch_broker_epoch="epoch-before-restart",
        )

        with patch("app.db.get_db", self._get_db), patch(
            "app.dispatcher._current_broker_epoch", return_value="epoch-after-restart"
        ):
            reset = Dispatcher()._stale_once()

        self.assertEqual(1, reset)
        row = self._task("dvs_dispatcher_broker_lost")
        self.assertEqual("pending", row.dispatch_status)
        self.assertIsNone(row.celery_task_id)
        self.assertIsNone(row.dispatch_reserved_at)
        self.assertIn("broker epoch changed", row.last_dispatch_error)

    def test_old_published_dispatch_in_ready_queue_is_not_retried(self):
        self._insert_task(
            task_id="dvs_dispatcher_published_waiting",
            status="pending",
            celery_task_id="celery-published-waiting",
            execution_owner_id=None,
            execution_lease_until=None,
            execution_heartbeat_at=None,
            dispatch_status="published",
            dispatch_reserved_at=now_local() - timedelta(hours=1),
            dispatch_published_at=now_local() - timedelta(hours=1),
            dispatch_broker_epoch="epoch-a",
        )

        with patch("app.db.get_db", self._get_db), patch(
            "app.dispatcher._current_broker_epoch", return_value="epoch-a"
        ), patch.object(
            Dispatcher,
            "_observe_published_dispatches",
            return_value={"celery-published-waiting": "queue"},
        ):
            reset = Dispatcher()._stale_once()

        self.assertEqual(0, reset)
        self.assertEqual(
            "celery-published-waiting",
            self._task("dvs_dispatcher_published_waiting").celery_task_id,
        )

    def test_old_published_unacked_dispatch_is_retried_after_two_observations(self):
        self._insert_task(
            task_id="dvs_dispatcher_published_unacked",
            status="pending",
            celery_task_id="celery-published-unacked",
            execution_owner_id=None,
            execution_lease_until=None,
            dispatch_status="published",
            dispatch_reserved_at=now_local() - timedelta(minutes=10),
            dispatch_published_at=now_local() - timedelta(minutes=10),
            dispatch_broker_epoch="epoch-a",
        )
        dispatcher = Dispatcher()
        with patch("app.db.get_db", self._get_db), patch(
            "app.dispatcher._current_broker_epoch", return_value="epoch-a"
        ), patch.object(
            dispatcher,
            "_observe_published_dispatches",
            return_value={"celery-published-unacked": "unacked"},
        ):
            self.assertEqual(0, dispatcher._stale_once())
            self.assertEqual(1, dispatcher._stale_once())

        row = self._task("dvs_dispatcher_published_unacked")
        self.assertIsNone(row.celery_task_id)
        self.assertEqual("pending", row.dispatch_status)
        self.assertIn("published handoff stale", row.last_dispatch_error)

    def test_published_recovery_confirmation_resets_when_message_returns_to_queue(self):
        self._insert_task(
            task_id="dvs_dispatcher_published_flapping",
            status="pending",
            celery_task_id="celery-published-flapping",
            execution_owner_id=None,
            execution_lease_until=None,
            dispatch_status="published",
            dispatch_reserved_at=now_local() - timedelta(minutes=10),
            dispatch_published_at=now_local() - timedelta(minutes=10),
            dispatch_broker_epoch="epoch-a",
        )
        dispatcher = Dispatcher()
        observations = [
            {"celery-published-flapping": "unacked"},
            {"celery-published-flapping": "queue"},
            {"celery-published-flapping": "unacked"},
        ]
        with patch("app.db.get_db", self._get_db), patch(
            "app.dispatcher._current_broker_epoch", return_value="epoch-a"
        ), patch.object(
            dispatcher,
            "_observe_published_dispatches",
            side_effect=observations,
        ):
            self.assertEqual(0, dispatcher._stale_once())
            self.assertEqual(0, dispatcher._stale_once())
            self.assertEqual(0, dispatcher._stale_once())

        self.assertEqual(
            "celery-published-flapping",
            self._task("dvs_dispatcher_published_flapping").celery_task_id,
        )

    def test_legacy_published_with_reservation_is_retried_when_missing(self):
        self._insert_task(
            task_id="dvs_dispatcher_legacy_published",
            status="pending",
            celery_task_id="celery-legacy-published",
            execution_owner_id=None,
            execution_lease_until=None,
            dispatch_status="published",
            dispatch_reserved_at=now_local() - timedelta(minutes=20),
            dispatch_published_at=now_local() - timedelta(minutes=20),
            dispatch_broker_epoch=None,
        )
        dispatcher = Dispatcher()
        with patch("app.db.get_db", self._get_db), patch(
            "app.dispatcher._current_broker_epoch", return_value="epoch-a"
        ), patch.object(
            dispatcher,
            "_observe_published_dispatches",
            return_value={"celery-legacy-published": "missing"},
        ):
            self.assertEqual(0, dispatcher._stale_once())
            self.assertEqual(1, dispatcher._stale_once())

        row = self._task("dvs_dispatcher_legacy_published")
        self.assertIsNone(row.celery_task_id)
        self.assertIn("published handoff stale", row.last_dispatch_error)

    def test_publishing_handoff_timeout_releases_task(self):
        self._insert_task(
            task_id="dvs_dispatcher_publishing_aged",
            status="pending",
            celery_task_id="celery-publishing-aged",
            execution_owner_id=None,
            execution_lease_until=None,
            execution_heartbeat_at=None,
            dispatch_status="publishing",
            dispatch_reserved_at=now_local() - timedelta(seconds=121),
            dispatch_broker_epoch="epoch-a",
        )

        with patch("app.db.get_db", self._get_db), patch(
            "app.dispatcher._current_broker_epoch", return_value="epoch-a"
        ):
            reset = Dispatcher()._stale_once()

        self.assertEqual(1, reset)
        row = self._task("dvs_dispatcher_publishing_aged")
        self.assertIsNone(row.celery_task_id)
        self.assertIn("publishing handoff timed out", row.last_dispatch_error)

    def test_delivering_handoff_timeout_releases_task(self):
        self._insert_task(
            task_id="dvs_dispatcher_delivering_aged",
            status="pending",
            celery_task_id="celery-delivering-aged",
            execution_owner_id=None,
            execution_lease_until=None,
            execution_heartbeat_at=None,
            dispatch_status="delivering",
            dispatch_reserved_at=now_local(),
            dispatch_broker_epoch="epoch-a",
            dispatch_delivery_started_at=now_local() - timedelta(seconds=121),
            dispatch_delivery_worker_id="worker-dead",
        )

        with patch("app.db.get_db", self._get_db), patch(
            "app.dispatcher._current_broker_epoch", return_value="epoch-a"
        ):
            reset = Dispatcher()._stale_once()

        self.assertEqual(1, reset)
        row = self._task("dvs_dispatcher_delivering_aged")
        self.assertIsNone(row.celery_task_id)
        self.assertIn("delivering handoff timed out", row.last_dispatch_error)

    def test_fresh_publishing_and_delivering_handoffs_are_not_retried(self):
        self._insert_task(
            task_id="dvs_dispatcher_publishing_fresh",
            status="pending",
            celery_task_id="celery-publishing-fresh",
            execution_owner_id=None,
            execution_lease_until=None,
            dispatch_status="publishing",
            dispatch_reserved_at=now_local() - timedelta(seconds=119),
            dispatch_broker_epoch="epoch-a",
        )
        self._insert_task(
            task_id="dvs_dispatcher_delivering_fresh",
            status="pending",
            celery_task_id="celery-delivering-fresh",
            execution_owner_id=None,
            execution_lease_until=None,
            dispatch_status="delivering",
            dispatch_reserved_at=now_local(),
            dispatch_broker_epoch="epoch-a",
            dispatch_delivery_started_at=now_local() - timedelta(seconds=119),
        )

        with patch("app.db.get_db", self._get_db), patch(
            "app.dispatcher._current_broker_epoch", return_value="epoch-a"
        ):
            reset = Dispatcher()._stale_once()

        self.assertEqual(0, reset)
        self.assertEqual("celery-publishing-fresh", self._task("dvs_dispatcher_publishing_fresh").celery_task_id)
        self.assertEqual("celery-delivering-fresh", self._task("dvs_dispatcher_delivering_fresh").celery_task_id)

    def test_legacy_aged_pending_dispatch_uses_updated_at_fallback_once(self):
        self._insert_task(
            task_id="dvs_dispatcher_legacy_aged",
            status="pending",
            celery_task_id="celery-legacy-aged",
            execution_owner_id=None,
            execution_lease_until=None,
            execution_heartbeat_at=None,
            dispatch_status="pending",
            dispatch_reserved_at=None,
        )
        db = self.SessionLocal()
        try:
            row = db.query(AppDvsTask).filter_by(task_id="dvs_dispatcher_legacy_aged").first()
            row.updated_at = now_local() - timedelta(seconds=601)
            db.commit()
        finally:
            db.close()
        with patch("app.db.get_db", self._get_db), patch(
            "app.dispatcher._current_broker_epoch", return_value="epoch-a"
        ):
            reset = Dispatcher()._stale_once()

        self.assertEqual(1, reset)
        row = self._task("dvs_dispatcher_legacy_aged")
        self.assertIsNone(row.celery_task_id)
        self.assertIn("legacy dispatch recovery", row.last_dispatch_error)

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

    def test_delivery_handoff_records_worker_before_claim(self):
        self._insert_task(
            task_id="dvs_dispatcher_delivering",
            status="pending",
            celery_task_id="delivery-dispatch-id",
            execution_owner_id=None,
            execution_lease_until=None,
            dispatch_status="published",
        )
        db = self.SessionLocal()
        try:
            self.assertTrue(
                begin_delivery_handoff(
                    db,
                    "worker-a",
                    "dvs_dispatcher_delivering",
                    "delivery-dispatch-id",
                )
            )
            row = db.query(AppDvsTask).filter_by(task_id="dvs_dispatcher_delivering").first()
            self.assertEqual("delivering", row.dispatch_status)
            self.assertEqual("worker-a", row.dispatch_delivery_worker_id)
            self.assertIsNotNone(row.dispatch_delivery_started_at)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
