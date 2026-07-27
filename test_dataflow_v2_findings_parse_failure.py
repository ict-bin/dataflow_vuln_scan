from __future__ import annotations

from app.dataflow_v2.analysis import _emit_v2_llm_json_parse_event
from app.parsers import _extract_json_object_with_error, extract_llm_structured_output
from app.dataflow_v2.models import FunctionRecord


def _sample_output() -> str:
    return """前言说明

```json
{
  "findings": [
    {
      "vuln_type": "denial-of-service",
      "severity": "high",
      "title": "demo",
      "summary": "summary",
      "trigger_path": "步骤1: ok\\步骤2: bad"
    }
  ]
}
```
"""


def test_extract_json_object_with_error_reports_invalid_escape():
    obj, error = _extract_json_object_with_error(_sample_output(), "findings")
    assert obj is not None
    assert error is None
    assert obj["findings"][0]["trigger_path"] == "步骤1: ok\\步骤2: bad"


def test_extract_llm_structured_output_supports_array_and_truncated_recovery():
    array_result = extract_llm_structured_output(
        """说明

```json
[
  {"function": "demo", "reason": "ok"}
]
```
""",
        expected_kind="array",
    )
    assert array_result.value == [{"function": "demo", "reason": "ok"}]

    truncated_result = extract_llm_structured_output(
        '{"propagations":[{"target_function":"callee"}',
        required_key="propagations",
        expected_kind="object",
        required_container_type=list,
        allow_truncated_recovery=True,
    )
    assert truncated_result.value is not None
    assert truncated_result.repaired is True
    assert "truncated_recovery" in truncated_result.repair_actions


def test_emit_v2_llm_json_parse_failed_emits_timeline_event():
    events: list[tuple[str, dict]] = []
    func = FunctionRecord(
        func_id="func-1",
        file="src/demo.c",
        name="demo_func",
        signature="void demo_func(void)",
        start_line=1,
        end_line=10,
        description="demo",
    )

    _emit_v2_llm_json_parse_event(
        lambda event_type, **payload: events.append((event_type, payload)),
        event_type="v2_llm_json_parse_failed",
        stage="vuln_mining_v2",
        func=func,
        error='json code block parse failed: Invalid \\escape',
        output_text=_sample_output(),
        required_key="findings",
        expected_kind="object",
    )

    assert events
    event_type, payload = events[-1]
    assert event_type == "v2_llm_json_parse_failed"
    assert payload["level"] == "error"
    assert payload["function"] == "demo_func"
    assert payload["source_file"] == "src/demo.c"
    assert "模型 JSON 解析失败" in payload["message"]
    assert "Invalid \\escape" in payload["error"]
    assert "前言说明" in payload["output_preview"]
