import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.models import RoleConfig, TaskConfig
from app.service import task_service


class DvsAgentConfigSnapshotTests(unittest.TestCase):
    def test_materialize_task_pi_runtime_creates_task_scoped_runtime_when_key_present(self):
        with tempfile.TemporaryDirectory() as task_root, tempfile.TemporaryDirectory() as global_pi:
            global_pi_path = Path(global_pi)
            (global_pi_path / "models.json").write_text(json.dumps({"providers": {"p1": {}}}), encoding="utf-8")
            (global_pi_path / "settings.json").write_text(json.dumps({"mode": "global"}), encoding="utf-8")
            cfg = TaskConfig(
                task="analyse demo",
                workers=RoleConfig(default_model="worker-model", agents=[{"model": "worker-model"}]),
                judges=RoleConfig(default_model="judge-model", agents=[{"model": "judge-model"}]),
            )

            with patch.dict("os.environ", {"PI_CODING_AGENT_DIR": str(global_pi_path)}, clear=False):
                task_pi_dirs, runtime_mode = task_service._materialize_task_pi_runtime(
                    task_root=task_root,
                    agent_task_key={
                        "id": "atk-1",
                        "name": "dvs-key",
                        "prefix": "dvs",
                        "secret": "secret-1",
                        "source": "manual",
                    },
                    cfg=cfg,
                )

            self.assertEqual("task_scoped", runtime_mode)
            self.assertEqual({"workers", "judges"}, set(task_pi_dirs.keys()))
            runtime_dir = Path(task_pi_dirs["workers"])
            self.assertTrue((runtime_dir / "models.json").is_file())
            self.assertTrue((runtime_dir / "settings.json").is_file())
            auth_payload = json.loads((runtime_dir / "auth.json").read_text(encoding="utf-8"))
            self.assertEqual("atk-1", auth_payload["agent_task_key_id"])
            self.assertEqual("secret-1", auth_payload["agent_task_key_secret"])
            settings_payload = json.loads((runtime_dir / "settings.json").read_text(encoding="utf-8"))
            self.assertTrue(settings_payload["compaction"]["enabled"])

    def test_materialize_task_pi_runtime_stays_task_scoped_without_key(self):
        with tempfile.TemporaryDirectory() as task_root:
            cfg = TaskConfig(
                task="analyse demo",
                workers=RoleConfig(default_model="worker-model", agents=[{"model": "worker-model"}]),
                judges=RoleConfig(default_model="judge-model", agents=[{"model": "judge-model"}]),
            )
            task_pi_dirs, runtime_mode = task_service._materialize_task_pi_runtime(
                task_root=task_root,
                agent_task_key=None,
                cfg=cfg,
            )
        self.assertEqual("task_scoped", runtime_mode)
        self.assertEqual({"workers", "judges"}, set(task_pi_dirs.keys()))

    def test_build_runtime_config_snapshots_freezes_workers_and_judges(self):
        cfg = TaskConfig(
            task="analyse demo",
            source_file="demo.c",
            function_name="demo",
            workers=RoleConfig(default_model="worker-model", agents=[{"model": "worker-model"}]),
            judges=RoleConfig(default_model="judge-model", agents=[{"model": "judge-model"}]),
        )
        with tempfile.TemporaryDirectory() as runtime_dir:
            runtime_path = Path(runtime_dir)
            worker_dir = runtime_path / "workers"
            judge_dir = runtime_path / "judges"
            worker_dir.mkdir()
            judge_dir.mkdir()
            (worker_dir / "models.json").write_text(json.dumps({"providers": {"p1": {"models": [{"id": "worker-model"}]}}}), encoding="utf-8")
            (judge_dir / "models.json").write_text(json.dumps({"providers": {"p2": {"models": [{"id": "judge-model"}]}}}), encoding="utf-8")
            (worker_dir / "settings.json").write_text(json.dumps({"mode": "task"}), encoding="utf-8")
            (judge_dir / "settings.json").write_text(json.dumps({"mode": "task"}), encoding="utf-8")
            (worker_dir / "auth.json").write_text(json.dumps({"agent_task_key_id": "atk-1"}), encoding="utf-8")
            (judge_dir / "auth.json").write_text(json.dumps({"agent_task_key_id": "atk-1"}), encoding="utf-8")
            cfg.task_pi_dirs = {"workers": str(worker_dir), "judges": str(judge_dir)}
            cfg.task_pi_dir = cfg.role_pi_dir("workers")

            agent_auth_json, role_config_snapshot, provider_runtime_summary, llm_binding_snapshot = task_service._build_runtime_config_snapshots(
                cfg=cfg,
                agent_task_key={
                    "id": "atk-1",
                    "name": "dvs-key",
                    "prefix": "dvs",
                    "secret": "secret-1",
                    "source": "manual",
                },
                task_pi_dirs=cfg.task_pi_dirs,
                agent_runtime_mode="task_scoped",
            )

        self.assertEqual("atk-1", agent_auth_json["agent_task_key_id"])
        self.assertEqual("worker-model", role_config_snapshot["workers"]["default_model"])
        self.assertEqual("judge-model", provider_runtime_summary["judges"]["default_model"])
        self.assertEqual(str(judge_dir), provider_runtime_summary["judges"]["runtime_dir"])
        self.assertEqual("task_scoped", llm_binding_snapshot["agent_runtime_mode"])
        self.assertIn("workers", llm_binding_snapshot["roles"])
        self.assertIn("runtime_dir", llm_binding_snapshot["roles"]["workers"])


if __name__ == "__main__":
    unittest.main()
