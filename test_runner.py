import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app import agent_process
from app import runner
from app.agent_process import AgentProcessHandle
from app.agent_runtime_events import emit_agent_runtime_events


def _fail_if_real_signal(*args, **kwargs):
    raise AssertionError(f"unexpected real signal invocation: args={args}, kwargs={kwargs}")


def _overflow_result() -> runner.AgentResult:
    result = runner.AgentResult()
    result.exit_code = 1
    result.error = (
        "400 litellm.BadRequestError: Hosted_vllmException - "
        '{"error":{"message":"You passed 147421 input tokens and requested 16384 output tokens. '
        "However, the model's context length is only 163804 tokens, resulting in a maximum input "
        'length of 147420 tokens. The proxy reserves 2048 safety-buffer tokens. Please reduce the length of the input prompt."}}'
    )
    return result


class RunAgentPromptFileTests(unittest.TestCase):
    def test_build_args_uses_pi_thinking_flag(self):
        args = runner._build_args(
            ["/usr/bin/pi"],
            "glm-5.2",
            ["read", "bash"],
            "high",
            None,
        )

        self.assertIn("--thinking", args)
        self.assertIn("high", args)
        self.assertNotIn("--thinking-level", args)

    def test_is_fatal_error_ignores_context_overflow_wrapped_as_invalid_request(self):
        result = runner.AgentResult()
        result.error = (
            "400 litellm.BadRequestError: Hosted_vllmException - "
            '{"object":"error","message":"Prefiller\'s maximum context length is 131072 tokens, '
            'however the input has 127564 tokens and the proxy reserves 4096 safety-buffer tokens '
            'after chat template rendering. Please reduce the length of the input.",'
            '"type":"invalid_request_error","code":"prefill_context_length_exceeded"}. '
            "Received Model Group=zai-org/GLM-5.1-180K"
        )
        self.assertTrue(runner._is_context_overflow_error(result.error))
        self.assertFalse(runner._is_fatal_error(result))

    def test_is_fatal_error_still_matches_real_model_config_errors(self):
        result = runner.AgentResult()
        result.error = "model not found"
        self.assertTrue(runner._is_fatal_error(result))

    def test_cleanup_orphan_pi_processes_ignores_live_parent(self):
        orphan = agent_process.AgentProcessInfo(
            pid=101,
            ppid=1,
            pgid=201,
            comm="pi",
            exe="node",
            cwd="/tmp/dfa-task/run",
            cmdline="pi --mode rpc",
            environ={"DVS_TASK_ID": "dvs_1", "DVS_TASK_ROOT": "/tmp/dfa-task"},
        )
        with patch.object(agent_process, "_iter_agent_processes", return_value=[orphan]):
            with patch.object(agent_process.os, "kill", side_effect=_fail_if_real_signal):
                with patch.object(agent_process.os, "killpg", side_effect=_fail_if_real_signal):
                    with patch.object(agent_process, "_kill_process_group", return_value=True) as kill_group:
                        killed = agent_process.cleanup_orphan_pi_processes(lambda _: None, label="test")
        self.assertEqual(killed, 0)
        kill_group.assert_not_called()

    def test_cleanup_task_agent_processes_only_hits_matching_task(self):
        match = agent_process.AgentProcessInfo(
            pid=101,
            ppid=55,
            pgid=201,
            comm="pi",
            exe="node",
            cwd="/tmp/dfa-task/run/epochs/0001",
            cmdline="pi --mode rpc",
            environ={"DVS_TASK_ID": "dvs_match", "DVS_TASK_ROOT": "/tmp/dfa-task"},
        )
        other = agent_process.AgentProcessInfo(
            pid=102,
            ppid=1,
            pgid=202,
            comm="pi",
            exe="node",
            cwd="/tmp/other/run",
            cmdline="pi --mode rpc",
            environ={"DVS_TASK_ID": "dvs_other", "DVS_TASK_ROOT": "/tmp/other"},
        )
        with patch.object(agent_process, "_iter_agent_processes", return_value=[match, other]):
            with patch.object(agent_process.os, "kill", side_effect=_fail_if_real_signal):
                with patch.object(agent_process.os, "killpg", side_effect=_fail_if_real_signal):
                    with patch.object(agent_process, "_kill_process_group", return_value=True) as kill_group:
                        killed = agent_process.cleanup_task_agent_processes(
                            lambda _: None,
                            label="test",
                            task_id="dvs_match",
                            task_root="/tmp/dfa-task",
                            run_root="/tmp/dfa-task/run/epochs/0001",
                        )
        self.assertEqual(killed, 1)
        kill_group.assert_called_once()

    def test_cleanup_worker_runtime_processes_only_targets_agent_processes(self):
        python_helper = agent_process.AgentProcessInfo(
            pid=201,
            ppid=10,
            pgid=301,
            comm="python3",
            exe="python3",
            cwd="/tmp/helper",
            cmdline="python3 helper.py",
            environ={},
        )
        pi_agent = agent_process.AgentProcessInfo(
            pid=202,
            ppid=10,
            pgid=302,
            comm="pi",
            exe="node",
            cwd="/tmp/dfa-task",
            cmdline="npx pi --session /tmp/dfa-task/run/session.jsonl",
            environ={"DVS_TASK_ID": "dvs_1"},
        )
        with patch.object(agent_process, "_iter_agent_processes", return_value=[pi_agent]), \
             patch.object(agent_process, "_iter_runtime_processes", return_value=[python_helper, pi_agent]), \
             patch.object(agent_process, "_read_pgid", return_value=999), \
             patch.object(agent_process.os, "getpid", return_value=100), \
             patch.object(agent_process.os, "getppid", return_value=99), \
             patch.object(agent_process.os, "kill", side_effect=_fail_if_real_signal), \
             patch.object(agent_process.os, "killpg", side_effect=_fail_if_real_signal), \
             patch.object(agent_process, "_kill_process_group", return_value=True) as kill_group:
            killed = agent_process.cleanup_worker_runtime_processes(lambda _: None, label="test")
        self.assertEqual(killed, 1)
        killed_info = kill_group.call_args.kwargs["info"]
        self.assertEqual(202, killed_info.pid)

    def test_agent_process_terminate_tree_force_cleans_group_after_exit(self):
        logs: list[str] = []

        class FakeProc:
            pid = 123

            def poll(self):
                return 0

            def wait(self, timeout=None):
                return 0

        with patch("app.agent_process.process_group_exists", return_value=True):
            with patch("app.agent_process.os.killpg") as killpg:
                handle = AgentProcessHandle(
                    proc=FakeProc(),
                    label="test",
                    logger=logs.append,
                    pgid=456,
                )
                handle.terminate_tree(reason="cleanup")
                killpg.assert_called_once()

        self.assertTrue(any("cleaning leaked pi process group" in msg for msg in logs))

    def test_sleep_with_cancel_stops_early_when_cancelled(self):
        cancel_event = threading.Event()

        def trigger_cancel():
            cancel_event.set()

        timer = threading.Timer(0.01, trigger_cancel)
        timer.start()
        try:
            completed = runner._sleep_with_cancel(5, cancel_event)
        finally:
            timer.cancel()
        self.assertTrue(completed)

    def test_pi_retry_backoff_exits_when_cancelled(self):
        cancel_event = threading.Event()

        def trigger_cancel():
            cancel_event.set()

        timer = threading.Timer(0.01, trigger_cancel)
        timer.start()
        try:
            with patch.object(
                runner,
                "_run_with_api_retry",
                side_effect=runner._PiProcessError("exit_code=-9: killed"),
            ):
                result = runner._run_with_pi_retry(
                    args=["/usr/bin/pi"],
                    cwd=".",
                    env=None,
                    prompt="hello",
                    post_skill_prompt=None,
                    cancel_event=cancel_event,
                    on_stream=None,
                    max_retries=0,
                    retry_delay=0,
                    pi_max_retries=-1,
                    pi_retry_delay=1,
                    model="glm-5.2",
                    thinking_level="off",
                )
        finally:
            timer.cancel()

        self.assertIn("cancelled during pi retry backoff", result.error or "")

    def test_run_agent_returns_before_spawn_when_cancelled(self):
        cancel_event = threading.Event()
        cancel_event.set()

        with patch.object(runner, "_find_pi_command") as find_pi_command:
            with patch.object(runner, "_run_with_pi_retry") as run_with_pi_retry:
                result = runner.run_agent(
                    "hello",
                    model="test-model",
                    tools=["read"],
                    cwd=".",
                    cancel_event=cancel_event,
                )

        find_pi_command.assert_not_called()
        run_with_pi_retry.assert_not_called()
        self.assertEqual(result.error, "cancelled")
        self.assertEqual(result.exit_code, -1)

    def test_run_agent_uses_prompt_file_instead_of_raw_argv(self):
        captured = {}

        def fake_run_with_pi_retry(**kwargs):
            captured["args"] = kwargs["args"]
            captured["prompt_text"] = kwargs["prompt"]
            captured["env"] = kwargs["env"]
            captured["fork_purpose"] = kwargs["fork_purpose"]
            captured["session_file"] = kwargs["session_file"]
            captured["model"] = kwargs["model"]
            captured["thinking_level"] = kwargs["thinking_level"]
            result = runner.AgentResult()
            result.output = "ok"
            result.exit_code = 0
            return result

        long_prompt = "# Task\n\n" + "\n".join(
            f"{idx}. /very/long/path/to/file_{idx}.c" for idx in range(5000)
        )

        with tempfile.TemporaryDirectory() as cwd:
            with patch.object(runner, "_find_pi_command", return_value=["/usr/bin/pi"]):
                with patch.object(runner, "_run_with_pi_retry", side_effect=fake_run_with_pi_retry):
                    result = runner.run_agent(
                        long_prompt,
                        model="test-model",
                        tools=["read"],
                        cwd=cwd,
                        max_retries=0,
                        pi_max_retries=0,
                        task_context={
                            "task_id": "dvs_123",
                            "task_root": "/tmp/dvs_123",
                            "task_run_root": "/tmp/dvs_123/run/epochs/0001",
                            "worker_id": "worker-a",
                            "execution_epoch": 1,
                            "fork_purpose": "taint_analysis",
                        },
                    )

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(captured["prompt_text"], long_prompt)
        self.assertNotIn(long_prompt, captured["args"])
        payload = json.loads(captured["env"]["DVS_TASK_CONTEXT"])
        self.assertEqual(payload["task_id"], "dvs_123")
        self.assertEqual(payload["task_root"], "/tmp/dvs_123")
        self.assertEqual(payload["task_run_root"], "/tmp/dvs_123/run/epochs/0001")
        self.assertEqual(payload["worker_id"], "worker-a")
        self.assertEqual(captured["fork_purpose"], "taint_analysis")
        self.assertIsNone(captured["session_file"])
        self.assertEqual(captured["model"], "test-model")
        self.assertEqual(captured["thinking_level"], "off")

    def test_run_with_api_retry_logs_pi_launch_metadata(self):
        logs: list[tuple] = []

        class _FakePipe:
            def __init__(self, chunks=None):
                self._chunks = list(chunks or [])
                self.closed = False

            def read(self, _size=-1):
                if self._chunks:
                    return self._chunks.pop(0)
                return b""

            def write(self, _data):
                return None

            def flush(self):
                return None

            def close(self):
                self.closed = True

        class _FakeProc:
            def __init__(self):
                self.pid = 4321
                self.stdout = _FakePipe()
                self.stderr = _FakePipe()
                self.stdin = _FakePipe()
                self.returncode = 0

            def wait(self, timeout=None):
                self.returncode = 0
                return 0

            def poll(self):
                return 0

        with patch.object(runner.subprocess, "Popen", return_value=_FakeProc()), \
             patch.object(runner, "_terminate_pi_process_tree", return_value=None), \
             patch.object(runner, "_log_info", side_effect=lambda *args: logs.append(args)), \
             patch.object(runner, "_is_pi_crash", return_value=False), \
             patch.object(runner, "_is_fatal_error", return_value=False), \
             patch.object(runner, "_is_retryable_query_engine_401_error", return_value=False), \
             patch.object(runner, "_is_retryable_api_error", return_value=False):
            result = runner._run_with_api_retry(
                args=["/usr/bin/pi", "--session", "/tmp/demo.jsonl"],
                cwd="/tmp/work",
                env=None,
                prompt="hello",
                post_skill_prompt=None,
                cancel_event=None,
                on_stream=None,
                max_retries=0,
                retry_delay=0,
                timeout_seconds=None,
                model="glm-5.2",
                thinking_level="high",
                session_file="/tmp/demo.jsonl",
                fork_purpose="vuln_mining",
            )

        self.assertEqual(result.exit_code, 0)
        launch_logs = [entry for entry in logs if entry and "started pi process" in entry[0]]
        self.assertEqual(1, len(launch_logs))
        launch = launch_logs[0]
        self.assertIn("session_file=%s", launch[0])
        self.assertEqual("/tmp/demo.jsonl", launch[4])
        self.assertEqual("vuln_mining", launch[5])
        self.assertEqual("glm-5.2", launch[6])
        self.assertEqual("high", launch[7])

    def test_run_agent_triggers_compaction_then_retries_on_context_overflow(self):
        prompts: list[str] = []
        compact_calls: list[dict] = []

        def fake_run_with_pi_retry(**kwargs):
            prompts.append(kwargs["prompt"])
            if len(prompts) == 1:
                return _overflow_result()
            result = runner.AgentResult()
            result.output = "ok"
            result.exit_code = 0
            return result

        with tempfile.TemporaryDirectory() as cwd:
            with patch.object(runner, "_find_pi_command", return_value=["/usr/bin/pi"]):
                with patch.object(runner, "_run_with_pi_retry", side_effect=fake_run_with_pi_retry), patch.object(
                    runner, "_run_pi_compact", side_effect=lambda **kwargs: compact_calls.append(kwargs) or True
                ):
                    result = runner.run_agent(
                        "summary",
                        model="MiniMax/MiniMax-M2.5",
                        tools=["read"],
                        cwd=cwd,
                        session_file="/tmp/test-session.jsonl",
                        max_retries=0,
                        pi_max_retries=0,
                        task_context={"task_pi_dir": "/tmp/runtime/workers", "agent_role": "workers"},
                        env={"PI_CODING_AGENT_DIR": "/tmp/runtime/workers"},
                    )

        self.assertEqual(result.output, "ok")
        self.assertEqual(len(prompts), 2)
        self.assertEqual(prompts[0], "summary")
        self.assertEqual(prompts[1], "summary")
        self.assertEqual(1, len(compact_calls))
        self.assertTrue(result.context_overflow_retrying)
        self.assertEqual(1, result.context_overflow_retry_count)
        self.assertFalse(result.context_overflow_retry_event_due)
        self.assertEqual("/tmp/runtime/workers", result.runtime_dir)
        self.assertEqual("workers", result.agent_role)

    def test_run_agent_preflight_context_overflow_without_session_fast_fails(self):
        long_prompt = "A" * (500000 * 4)

        with patch.object(runner, "_find_pi_command", return_value=["/usr/bin/pi"]):
            with patch.object(runner, "_run_with_pi_retry") as run_with_pi_retry:
                result = runner.run_agent(
                    long_prompt,
                    model="glm-5.1",
                    tools=["read"],
                    cwd=".",
                    max_retries=0,
                    pi_max_retries=0,
                    task_context={"task_pi_dir": "/tmp/runtime/workers", "agent_role": "workers"},
                    env={"PI_CODING_AGENT_DIR": "/tmp/runtime/workers"},
                )

        run_with_pi_retry.assert_not_called()
        self.assertTrue(result.context_budget_exceeded_preflight)
        self.assertTrue(result.context_overflow_failed_after_compaction)
        self.assertEqual("/tmp/runtime/workers", result.runtime_dir)
        self.assertEqual("workers", result.agent_role)

    def test_emit_agent_runtime_events_emits_context_events(self):
        emitted: list[tuple[str, dict]] = []
        result = runner.AgentResult()
        result.runtime_dir = "/tmp/runtime/workers"
        result.context_window = 128000
        result.proxy_reserved_tokens = 4096
        result.compaction_requested = True
        result.compaction_completed = True
        result.context_budget_exceeded_preflight = True
        result.context_overflow_retrying = True
        result.context_overflow_retry_event_due = True
        result.context_overflow_retry_count = 10
        result.context_overflow_failed_after_compaction = True
        result.error = "overflow"

        def emit(event_type: str, **payload):
            emitted.append((event_type, payload))

        emit_agent_runtime_events(
            emit,
            result=result,
            stage="taint_worker",
            role="workers",
            model="glm-5.1",
            extra={"function": "demo"},
        )

        event_types = [item[0] for item in emitted]
        self.assertEqual(
            [
                "task_context_compaction_requested",
                "task_context_compaction_completed",
                "task_context_budget_exceeded_preflight",
                "task_context_overflow_retrying",
                "task_context_overflow_failed_after_compaction",
            ],
            event_types,
        )
        self.assertEqual("/tmp/runtime/workers", emitted[0][1]["runtime_dir"])
        self.assertEqual("glm-5.1", emitted[0][1]["model"])

    def test_dataflow_v2_vuln_mining_keeps_configured_thinking(self):
        from app.dataflow_v2.analysis import TaintAnalysisCallbacks
        from app.dataflow_v2.models import FunctionRecord, TaintParamInfo
        from app.models import RoleConfig, TaskConfig

        cfg = TaskConfig(
            task="demo",
            cwd="/tmp/source",
            task_pi_dirs={"workers": "/tmp/runtime/workers"},
            vuln_mining_thinking_level="high",
            workers=RoleConfig(default_model="glm-5.2", agents=[{"model": "glm-5.2", "tools": ["read"]}]),
        )
        cb = TaintAnalysisCallbacks.__new__(TaintAnalysisCallbacks)
        cb.cfg = cfg
        cb.sessions_dir = Path(tempfile.mkdtemp())
        cb.run_dir = Path(tempfile.mkdtemp())
        cb.vuln_root = Path(tempfile.mkdtemp())
        cb.vuln_root.mkdir(parents=True, exist_ok=True)
        cb.cancel_event = None
        cb.task_id = "dvs_test"
        cb.run_id = "run_1"
        cb.source_root = "/tmp/source"
        cb._vuln_miner_prompt = "mine"
        cb.graph_store = object()
        cb.on_event = None
        cb._format_taint_context = lambda *args, **kwargs: "context"

        func = FunctionRecord(file="demo.c", name="demo", signature="void demo()", start_line=1, end_line=10)
        taint = TaintParamInfo(positions=[0], signature="arg0", names=["input"])
        ctx = SimpleNamespace(depth=1)
        store = SimpleNamespace(
            list_taints_in_function=lambda *_: [],
            list_propagations_from=lambda *_: [],
        )
        captured: dict[str, object] = {}

        def fake_run_agent(*, thinking_level: str, **kwargs):
            captured["thinking_level"] = thinking_level
            result = runner.AgentResult()
            result.output = '{"findings":[]}'
            result.exit_code = 0
            return result

        with patch("app.dataflow_v2.analysis.run_agent", side_effect=fake_run_agent):
            count = cb.mine_vulns(store, func, taint, ctx, base_session="")

        self.assertEqual(0, count)
        self.assertEqual("high", captured["thinking_level"])

    def test_dataflow_v2_infer_external_callees_always_writes_session(self):
        from app.dataflow_v2.analysis import TaintAnalysisCallbacks
        from app.dataflow_v2.models import FunctionRecord
        from app.models import RoleConfig, TaskConfig

        cfg = TaskConfig(
            task="demo",
            cwd="/tmp/source",
            task_pi_dirs={"workers": "/tmp/runtime/workers"},
            workers=RoleConfig(default_model="glm-5.2", agents=[{"model": "glm-5.2", "tools": ["read"]}]),
        )
        cb = TaintAnalysisCallbacks.__new__(TaintAnalysisCallbacks)
        cb.cfg = cfg
        cb.sessions_dir = Path(tempfile.mkdtemp())
        cb.run_dir = Path(tempfile.mkdtemp())
        cb.vuln_root = Path(tempfile.mkdtemp())
        cb.vuln_root.mkdir(parents=True, exist_ok=True)
        cb.cancel_event = None
        cb.task_id = "dvs_test"
        cb.run_id = "run_1"
        cb.source_root = "/tmp/source"
        cb.on_event = None

        func = FunctionRecord(file="demo.c", name="demo", signature="void demo()", start_line=1, end_line=10)
        props = [
            SimpleNamespace(
                target_function="open",
                source_taint_name="request",
                target_taint_name="fd",
            )
        ]
        captured: dict[str, object] = {}

        def fake_run_agent(*, session_file: str | None, **kwargs):
            captured["session_file"] = session_file
            result = runner.AgentResult()
            result.output = '[{"function":"open","inferable":true,"return_taint":"fd","propagation":null,"validation":null}]'
            result.exit_code = 0
            return result

        with patch("app.dataflow_v2.analysis.run_agent", side_effect=fake_run_agent):
            inferred = cb._infer_external_callees(props, func)

        self.assertEqual("fd", inferred["open"]["return_taint"])
        self.assertIsNotNone(captured["session_file"])
        self.assertTrue(str(captured["session_file"]).endswith(".jsonl"))
        self.assertIn(str(cb.sessions_dir), str(captured["session_file"]))

    def test_legacy_dagflow_vuln_mining_is_forced_off(self):
        from app.dagflow.mining_agent import MiningAgent

        cfg = SimpleNamespace(
            cwd="/tmp/source",
            source_root="/tmp/source",
            vuln_mining_thinking_level="high",
            agent_run_timeout_seconds=900,
            agent_timeout_retry_enabled=True,
            agent_timeout_max_retries=20,
            pi_max_retries=3,
            pi_retry_delay=10.0,
            workers=SimpleNamespace(
                agents=[SimpleNamespace(model="glm-5.2", tools=["read"])],
                default_tools=["read"],
            ),
        )
        store = SimpleNamespace(load_dag=lambda *_: object())
        captured: dict[str, object] = {}

        def fake_run_agent(*, thinking_level: str, **kwargs):
            captured["thinking_level"] = thinking_level
            result = runner.AgentResult()
            result.output = '{"findings":[]}'
            result.exit_code = 0
            return result

        with tempfile.TemporaryDirectory() as sessions_dir, tempfile.TemporaryDirectory() as source_root:
            agent = MiningAgent(
                config=cfg,
                store=store,
                sessions_dir=Path(sessions_dir),
                vuln_store=object(),
                run_id="run_1",
                func_lookup=None,
                task_id="dvs_test",
            )
            func = SimpleNamespace(func_id="func_1", file="demo.c", name="demo", start_line=1, end_line=10)
            with patch("app.runner.run_agent", side_effect=fake_run_agent), \
                 patch("app.dagflow.chain_builder.build_chain", return_value=[]), \
                 patch("app.dagflow.dag_tools.get_func_source", return_value="void demo() {}"), \
                 patch("app.dagflow.finding_store.save_findings"):
                findings = agent.mine(func, "arg0")

        self.assertEqual([], findings)
        self.assertEqual("off", captured["thinking_level"])


if __name__ == "__main__":
    unittest.main()
