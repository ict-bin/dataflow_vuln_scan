"""Tests for the depth=0 taint-source auto-identification pre-stage."""

from __future__ import annotations

import types

import app.taint_source_identifier as tsi
from app.models import AgentInstanceConfig, RoleConfig, TaskConfig, TokenUsage


def _cfg(**kw) -> TaskConfig:
    base = dict(
        task="对 a.c 的 foo 函数完成数据流漏洞挖掘",
        source_file="a.c",
        function_name="foo",
        workers=RoleConfig(agents=[AgentInstanceConfig(model="test/model")]),
    )
    base.update(kw)
    return TaskConfig(**base)


# ─── needs_taint_autodetect ───────────────────────────────────────────────────

def test_needs_autodetect_when_empty():
    assert tsi.needs_taint_autodetect(_cfg()) is True


def test_needs_autodetect_when_only_all():
    assert tsi.needs_taint_autodetect(_cfg(taint_params=["all"])) is True
    assert tsi.needs_taint_autodetect(_cfg(taint_params=["ALL", "all"])) is True


def test_no_autodetect_when_real_param():
    assert tsi.needs_taint_autodetect(_cfg(taint_params=["aMessage"])) is False


def test_no_autodetect_when_real_detail():
    cfg = _cfg(taint_details=[{"name": "buf", "source_kind": "param"}])
    assert tsi.needs_taint_autodetect(cfg) is False


def test_no_autodetect_when_detail_is_all_but_param_real():
    cfg = _cfg(taint_params=["len"], taint_details=[{"name": "all"}])
    assert tsi.needs_taint_autodetect(cfg) is False


# ─── _parse_taints ────────────────────────────────────────────────────────────

def test_parse_taints_object():
    out = """好的，分析如下：
```json
{"function":"foo","source_file":"a.c","no_external_input":false,
 "taints":[{"symbol":"aMessage","kind":"param","line":"L10","reason":"net"},
           {"symbol":"&buf","kind":"call_argument","line":"L12","reason":"recv"}]}
```"""
    params, details, no_ext = tsi._parse_taints(out)
    assert params == ["aMessage", "buf"]
    assert no_ext is False
    assert details[0]["name"] == "aMessage"
    assert details[1]["source_kind"] == "call_argument"


def test_parse_taints_dedup_and_skip_all():
    out = '```json\n{"taints":[{"symbol":"x"},{"symbol":"x"},{"symbol":"all"}]}\n```'
    params, _details, _ = tsi._parse_taints(out)
    assert params == ["x"]


def test_parse_taints_no_external_input():
    out = '```json\n{"no_external_input":true,"taints":[]}\n```'
    params, details, no_ext = tsi._parse_taints(out)
    assert params == []
    assert details == []
    assert no_ext is True


def test_parse_taints_garbage():
    params, details, no_ext = tsi._parse_taints("no json here at all")
    assert params == []
    assert no_ext is False


# ─── autodetect_taint_sources ─────────────────────────────────────────────────

def _stub_agent_result(output: str, *, error: str | None = None):
    return types.SimpleNamespace(output=output, token_usage=TokenUsage(input=5, output=7), error=error)


def test_autodetect_happy_path(monkeypatch, tmp_path):
    monkeypatch.setattr(tsi, "_extract_function_body", lambda *a, **k: "L1: int foo(char* p){ return *p; }")
    captured = {}

    def fake_run_agent(prompt, **kw):
        captured["prompt"] = prompt
        captured["system_prompt"] = kw.get("system_prompt")
        captured["model"] = kw.get("model")
        return _stub_agent_result('```json\n{"taints":[{"symbol":"p","kind":"param","line":"L1"}]}\n```')

    monkeypatch.setattr(tsi, "run_agent", fake_run_agent)
    res = tsi.autodetect_taint_sources(_cfg(), target_dir=str(tmp_path))
    assert res.taint_params == ["p"]
    assert res.taint_details[0]["name"] == "p"
    assert res.token_usage.input == 5
    assert res.error is None
    # 完整函数体必须嵌入 prompt（需求 2）
    assert "int foo(char* p)" in captured["prompt"]
    assert captured["model"] == "test/model"


def test_autodetect_missing_body(monkeypatch, tmp_path):
    monkeypatch.setattr(tsi, "_extract_function_body", lambda *a, **k: "")
    monkeypatch.setattr(tsi, "run_agent", lambda *a, **k: _stub_agent_result(""))
    res = tsi.autodetect_taint_sources(_cfg(), target_dir=str(tmp_path))
    assert res.taint_params == []
    assert res.error == "function_body_missing"


def test_autodetect_agent_error(monkeypatch, tmp_path):
    monkeypatch.setattr(tsi, "_extract_function_body", lambda *a, **k: "L1: code")
    monkeypatch.setattr(tsi, "run_agent", lambda *a, **k: _stub_agent_result("", error="boom"))
    res = tsi.autodetect_taint_sources(_cfg(), target_dir=str(tmp_path))
    assert res.error == "boom"
    assert res.taint_params == []


def test_autodetect_never_raises(monkeypatch, tmp_path):
    def boom(*a, **k):
        raise RuntimeError("explode")

    monkeypatch.setattr(tsi, "_extract_function_body", boom)
    res = tsi.autodetect_taint_sources(_cfg(), target_dir=str(tmp_path))
    assert res.taint_params == []
    assert "extract_function_body_failed" in (res.error or "")
