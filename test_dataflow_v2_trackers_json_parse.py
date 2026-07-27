from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

from app.dataflow_v2.models import FunctionRecord, PropagationRecord
from app.dataflow_v2 import trackers


class _FakeStore:
    def __init__(self, run_dir: Path, functions: list[FunctionRecord]) -> None:
        self.run_dir = str(run_dir)
        self._functions = functions

    def find_function(self, name: str, file: str = "") -> FunctionRecord | None:
        for func in self._functions:
            if func.name == name and (not file or func.file == file):
                return func
        return None

    def list_functions(self) -> list[FunctionRecord]:
        return list(self._functions)


def _make_cfg() -> SimpleNamespace:
    return SimpleNamespace(
        workers=SimpleNamespace(
            agents=[SimpleNamespace(model="demo-model", tools=[])],
            default_tools=[],
        ),
        agent_run_timeout_seconds=30,
        agent_timeout_retry_enabled=True,
        agent_timeout_max_retries=1,
        pi_max_retries=1,
        pi_retry_delay=0.1,
        role_pi_dir=lambda role: "",
    )


def test_resolve_external_emits_recovered_event_for_repaired_confirmed_json(
    tmp_path: Path,
    monkeypatch,
):
    cfg = _make_cfg()
    target = FunctionRecord(
        file="src/reader.c",
        name="reader_func",
        signature="void reader_func(int *p)",
        start_line=1,
        end_line=20,
    )
    func = FunctionRecord(
        file="src/source.c",
        name="source_func",
        signature="void source_func(int *p)",
        start_line=1,
        end_line=20,
    )
    prop = PropagationRecord(
        escape_kind="global",
        carrier="g_state",
        source_taint_name="p",
    )
    store = _FakeStore(tmp_path, [target])
    events: list[tuple[str, dict]] = []

    monkeypatch.setattr(
        trackers,
        "run_agent",
        lambda **kwargs: SimpleNamespace(
            output=(
                "```json\n"
                '{"confirmed":[{"function":"reader_func","taint_param":"arg","reason":"bad\\路径"}]}\n'
                "```"
            ),
            error="",
            exit_code=0,
        ),
    )
    monkeypatch.setattr(trackers, "upsert_session_index_item", lambda **kwargs: "sess")
    monkeypatch.setattr(trackers, "update_session_index_item", lambda **kwargs: None)

    resolved = trackers.resolve_external(
        cfg,
        str(tmp_path),
        tmp_path / "sessions",
        store,
        func,
        prop,
        on_event=lambda etype, **payload: events.append((etype, payload)),
    )

    assert len(resolved) == 1
    recovered = [payload for etype, payload in events if etype == "v2_llm_json_parse_recovered"]
    assert len(recovered) == 1
    assert recovered[0]["stage"] == "external_tracking_v2"
    assert "escape_invalid_backslashes" in recovered[0]["repair_actions"]


def test_resolve_indirect_emits_failed_event_for_unparseable_handlers_json(
    tmp_path: Path,
    monkeypatch,
):
    cfg = _make_cfg()
    func = FunctionRecord(
        file="src/source.c",
        name="source_func",
        signature="void source_func(void)",
        start_line=1,
        end_line=20,
    )
    prop = PropagationRecord(
        target_function="dispatch_handler",
        target_taint_name="cb",
        target_taint_signature="cb",
        source_taint_name="cb",
        call_line=12,
    )
    candidate = FunctionRecord(
        file="src/handler.c",
        name="dispatch_handler_impl",
        signature="void dispatch_handler_impl(void)",
        start_line=1,
        end_line=20,
    )
    store = _FakeStore(tmp_path, [candidate])
    events: list[tuple[str, dict]] = []

    monkeypatch.setattr(
        trackers,
        "run_agent",
        lambda **kwargs: SimpleNamespace(
            output="handlers: definitely not valid json",
            error="",
            exit_code=0,
        ),
    )
    monkeypatch.setattr(trackers, "upsert_session_index_item", lambda **kwargs: "sess")
    monkeypatch.setattr(trackers, "update_session_index_item", lambda **kwargs: None)

    resolved = trackers.resolve_indirect(
        cfg,
        str(tmp_path),
        tmp_path / "sessions",
        store,
        func,
        prop,
        on_event=lambda etype, **payload: events.append((etype, payload)),
    )

    assert resolved == []
    failed = [payload for etype, payload in events if etype == "v2_llm_json_parse_failed"]
    assert len(failed) == 1
    assert failed[0]["stage"] == "indirect_tracking_v2"
    assert failed[0]["required_key"] == "handlers"
