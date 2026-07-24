import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AppDvsTask, AppDvsTaskEvent, Base
from app.service.execution_coordinator import claim_one_runnable_task
from app.service.task_service import TaskService
class TaskRestartEpochTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.service = TaskService()

    def test_restart_task_resets_epoch_and_next_claim_starts_from_one(self):
        with tempfile.TemporaryDirectory() as td:
            tasks_root = Path(td) / "tasks"
            task_root = tasks_root / "dvs_restart_1"
            run_dir = task_root / "run"
            output_dir = task_root / "output"
            run_dir.mkdir(parents=True, exist_ok=True)
            output_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "stale.txt").write_text("stale\n", encoding="utf-8")
            (output_dir / "stale.txt").write_text("stale\n", encoding="utf-8")

            db = self.SessionLocal()
            try:
                row = AppDvsTask(
                    task_id="dvs_restart_1",
                    project_id="p1",
                    task_name="restart-me",
                    input_path=str(task_root / "input"),
                    output_path=str(tasks_root),
                    prompt_content="analyse",
                    status="failed",
                    error="boom",
                    execution_owner_id="pod-old",
                    execution_epoch=7,
                    execution_lease_until=None,
                    execution_heartbeat_at=None,
                    control_version=4,
                    dispatch_status="failed",
                    task_config_json={
                        "resume": True,
                        "resume_workspace": True,
                        "start_stage": "trace",
                        "keep": "yes",
                    },
                )
                db.add(row)
                db.commit()

                with patch("app.service.task_service._revoke_celery_task", return_value=None), \
                     patch.object(TaskService, "request_cancel", return_value=True), \
                     patch.object(TaskService, "_cleanup_worker_runtime", return_value=0), \
                     patch("app.service.task_service.WorkspaceManager.cleanup_temp_for_task", return_value=None), \
                     patch("app.db.shared_mysql.create_shared_store", return_value=None):
                    payload = self.service.restart_task(db, "dvs_restart_1")

                self.assertEqual("pending", payload["status"])

                refreshed = db.query(AppDvsTask).filter_by(task_id="dvs_restart_1").first()
                self.assertIsNotNone(refreshed)
                self.assertEqual("pending", refreshed.status)
                self.assertEqual(0, refreshed.execution_epoch)
                self.assertIsNone(refreshed.execution_owner_id)
                self.assertEqual("pending", refreshed.dispatch_status)
                self.assertEqual({"keep": "yes"}, refreshed.task_config_json)
                self.assertFalse(run_dir.exists())
                self.assertFalse(output_dir.exists())

                claimed = claim_one_runnable_task(db, "pod-new")
                self.assertIsNotNone(claimed)
                self.assertEqual("dvs_restart_1", claimed.task_id)
                self.assertEqual(1, claimed.epoch)

                db.close()
                db = self.SessionLocal()
                claimed_row = db.query(AppDvsTask).filter_by(task_id="dvs_restart_1").first()
                self.assertEqual(1, claimed_row.execution_epoch)
                self.assertEqual("pod-new", claimed_row.execution_owner_id)
                self.assertEqual("leased", claimed_row.dispatch_status)
            finally:
                db.close()

    def test_cancel_task_preserves_input_config_for_future_restart(self):
        db = self.SessionLocal()
        try:
            row = AppDvsTask(
                task_id="dvs_cancel_keep_input",
                project_id="p1",
                task_name="cancel-keep-input",
                input_path="/tmp/input",
                output_path="/tmp/output",
                source_root_path="/tmp/source-root",
                prompt_content="analyze src/demo.c function demo_func",
                status="running",
                execution_owner_id=None,
                execution_epoch=2,
                control_version=3,
                dispatch_status="running",
                task_config_json={
                    "source_file": "src/demo.c",
                    "function_name": "demo_func",
                    "line_hint": "L42",
                    "keep": "yes",
                },
            )
            db.add(row)
            db.commit()

            with patch("app.service.task_service._revoke_celery_task", return_value=None), \
                 patch.object(TaskService, "request_cancel", return_value=False), \
                 patch.object(TaskService, "_cleanup_worker_runtime", return_value=0):
                payload = self.service.cancel_task(db, "dvs_cancel_keep_input")

            self.assertEqual("cancelled", payload["status"])

            refreshed = db.query(AppDvsTask).filter_by(task_id="dvs_cancel_keep_input").first()
            self.assertIsNotNone(refreshed)
            self.assertEqual("cancelled", refreshed.status)
            self.assertEqual(
                {
                    "source_file": "src/demo.c",
                    "function_name": "demo_func",
                    "line_hint": "L42",
                    "keep": "yes",
                },
                refreshed.task_config_json,
            )
            self.assertEqual("analyze src/demo.c function demo_func", refreshed.prompt_content)
            self.assertIsNone(refreshed.result_json)
            self.assertIsNotNone(refreshed.latest_abnormal_reason_json)

            timeline = self.service.get_task_timeline(db, "dvs_cancel_keep_input")
            event_types = [str(item.get("event_type") or "") for item in timeline.get("events", [])]
            self.assertIn("abnormal_reason_recorded", event_types)
            db_event_types = [
                str(item.event_type or "")
                for item in db.query(AppDvsTaskEvent).filter_by(task_id="dvs_cancel_keep_input").all()
            ]
            self.assertIn("task_cancelled", db_event_types)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
