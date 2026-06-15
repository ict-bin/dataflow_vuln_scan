import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AppDvsTask, Base
from app.service.task_service import TaskService


class DvsTaskConfigDisplayTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.service = TaskService()

    def test_row_to_dict_exposes_frozen_agent_config_snapshots(self):
        db = self.SessionLocal()
        try:
            row = AppDvsTask(
                task_id="dvs_snapshot",
                project_id="p1",
                task_name="snapshot-task",
                input_path="/src/demo.c",
                module_input_path="/src",
                source_root_path="/src",
                prompt_content="analyse demo",
                status="running",
                task_config_json={
                    "agent_task_key": {"id": "atk-1", "prefix": "dvs", "secret": "secret-1"},
                    "agent_auth_json": {
                        "agent_task_key_id": "atk-1",
                        "agent_task_key_name": "dvs-key",
                        "agent_task_key_prefix": "dvs",
                        "agent_task_key_source": "manual",
                        "agent_task_key_secret": "secret-1",
                    },
                    "role_config_snapshot": {
                        "workers": {"default_model": "worker-model"},
                        "judges": {"default_model": "judge-model"},
                    },
                    "provider_runtime_summary": {
                        "workers": {"default_model": "worker-model"},
                        "judges": {"default_model": "judge-model"},
                    },
                    "llm_binding_snapshot": {
                        "version": 1,
                        "agent_runtime_mode": "task_scoped",
                        "roles": {
                            "workers": {"default_model": "worker-model"},
                            "judges": {"default_model": "judge-model"},
                        },
                    },
                },
            )
            db.add(row)
            db.commit()

            payload = self.service._row_to_dict(row)

            self.assertEqual("atk-1", payload["agent_auth_json"]["agent_task_key_id"])
            self.assertEqual("worker-model", payload["role_config_snapshot"]["workers"]["default_model"])
            self.assertEqual("judge-model", payload["provider_runtime_summary"]["judges"]["default_model"])
            self.assertEqual("task_scoped", payload["llm_binding_snapshot"]["agent_runtime_mode"])
            self.assertEqual("task_scoped", payload["agent_runtime_mode"])
        finally:
            db.close()

    def test_row_to_dict_keeps_snapshot_fields_null_for_legacy_task(self):
        db = self.SessionLocal()
        try:
            row = AppDvsTask(
                task_id="dvs_legacy",
                project_id="p1",
                task_name="legacy-task",
                input_path="/src/demo.c",
                module_input_path="/src",
                source_root_path="/src",
                prompt_content="analyse demo",
                status="passed",
                task_config_json={"source_file": "demo.c"},
            )
            db.add(row)
            db.commit()

            payload = self.service._row_to_dict(row)

            self.assertIsNone(payload["agent_auth_json"])
            self.assertIsNone(payload["role_config_snapshot"])
            self.assertIsNone(payload["provider_runtime_summary"])
            self.assertIsNone(payload["llm_binding_snapshot"])
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
