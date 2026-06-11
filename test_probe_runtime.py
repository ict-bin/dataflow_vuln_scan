import os
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

from app.probe_runtime import ProbeRuntime


class ProbeRuntimeTests(unittest.TestCase):
    def test_status_unavailable_when_pid_file_missing(self):
        runtime = ProbeRuntime()
        payload, healthy, ready, startup_ok = runtime._status_payload()
        self.assertFalse(healthy)
        self.assertFalse(ready)
        self.assertFalse(startup_ok)
        self.assertEqual("main_process_missing", payload["status"])

    def test_health_and_ready_pass_before_startup_grace(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pid_file = os.path.join(tmpdir, "main.pid")
            started_at_file = os.path.join(tmpdir, "started_at")
            with open(pid_file, "w", encoding="utf-8") as fh:
                fh.write(str(os.getpid()))
            with open(started_at_file, "w", encoding="utf-8") as fh:
                fh.write(str(time.time()))
            with patch.dict(
                os.environ,
                {
                    "SECFLOW_MAIN_PID_FILE": pid_file,
                    "SECFLOW_MAIN_STARTED_AT_FILE": started_at_file,
                    "SECFLOW_PROBE_STARTUP_GRACE_SECONDS": "30",
                },
                clear=False,
            ):
                runtime = ProbeRuntime()
                _, healthy, ready, startup_ok = runtime._status_payload()
            self.assertTrue(healthy)
            self.assertTrue(ready)
            self.assertFalse(startup_ok)

    def test_startup_passes_after_grace(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pid_file = os.path.join(tmpdir, "main.pid")
            started_at_file = os.path.join(tmpdir, "started_at")
            with open(pid_file, "w", encoding="utf-8") as fh:
                fh.write(str(os.getpid()))
            with open(started_at_file, "w", encoding="utf-8") as fh:
                fh.write(str(time.time() - 31))
            with patch.dict(
                os.environ,
                {
                    "SECFLOW_MAIN_PID_FILE": pid_file,
                    "SECFLOW_MAIN_STARTED_AT_FILE": started_at_file,
                    "SECFLOW_PROBE_STARTUP_GRACE_SECONDS": "30",
                },
                clear=False,
            ):
                runtime = ProbeRuntime()
                _, healthy, ready, startup_ok = runtime._status_payload()
            self.assertTrue(healthy)
            self.assertTrue(ready)
            self.assertTrue(startup_ok)

    def test_sigterm_marks_probe_unready_before_main_process_exits(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pid_file = os.path.join(tmpdir, "main.pid")
            started_at_file = os.path.join(tmpdir, "started_at")
            with open(pid_file, "w", encoding="utf-8") as fh:
                fh.write(str(os.getpid()))
            with open(started_at_file, "w", encoding="utf-8") as fh:
                fh.write(str(time.time() - 31))
            with patch.dict(
                os.environ,
                {
                    "SECFLOW_MAIN_PID_FILE": pid_file,
                    "SECFLOW_MAIN_STARTED_AT_FILE": started_at_file,
                },
                clear=False,
            ):
                runtime = ProbeRuntime()
                runtime._handle_signal(signal.SIGTERM, None)
                _, healthy, ready, startup_ok = runtime._status_payload()
            self.assertTrue(healthy)
            self.assertFalse(ready)
            self.assertFalse(startup_ok)
