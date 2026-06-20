"""Tests for the depth=0 entry-point screening pre-stage."""

from __future__ import annotations

import types

import app.entry_point_screener as eps
from app.models import AgentInstanceConfig, RoleConfig, TaskConfig, TokenUsage


def _cfg(**kw) -> TaskConfig:
    base = dict(
        task="对 a.c 的 foo 函数完成数据流漏洞挖掘",
        source_file="a.c",
        function_name="foo",
        entry_screen_enabled=True,
        workers=RoleConfig(agents=[AgentInstanceConfig(model="test/model")]),
    )
    base.update(kw)
    return TaskConfig(**base)


# ─── needs_entry_screen ───────────────────────────────────────────────────────

def test_needs_entry_screen_default_off():
    cfg = TaskConfig(task="t", source_file="a.c", function_name="foo")
    assert eps.needs_entry_screen(cfg) is False


def test_needs_entry_screen_when_enabled():
    assert eps.needs_entry_screen(_cfg()) is True


# ─── whitelist_hit ────────────────────────────────────────────────────────────

def test_whitelist_hit_substring_default():
    assert eps.whitelist_hit(_cfg(function_name="HandleCommissioningSet")) == "handle"
    assert eps.whitelist_hit(_cfg(function_name="recvPacket")) == "recv"
    assert eps.whitelist_hit(_cfg(function_name="ParseHeader")) == "parse"


def test_whitelist_hit_case_insensitive():
    assert eps.whitelist_hit(_cfg(function_name="READ_BUF")) == "read"


def test_whitelist_hit_cpp_method():
    assert eps.whitelist_hit(_cfg(function_name="Leader::HandleMessage")) == "handle"


def test_whitelist_miss():
    assert eps.whitelist_hit(_cfg(function_name="computeChecksum")) is None
    assert eps.whitelist_hit(_cfg(function_name="getLength")) is None


def test_whitelist_custom_list_overrides_default():
    cfg = _cfg(function_name="myEntry", entry_screen_whitelist=["entry"])
    assert eps.whitelist_hit(cfg) == "entry"
    # default keyword no longer applies when custom list provided
    assert eps.whitelist_hit(_cfg(function_name="recvX", entry_screen_whitelist=["zzz"])) is None


def test_whitelist_empty_falls_back_to_default():
    assert eps.whitelist_hit(_cfg(function_name="recvX", entry_screen_whitelist=[])) == "recv"


# ─── _parse_screen ────────────────────────────────────────────────────────────

def test_parse_screen_entry_true():
    out = '```json\n{"function":"foo","is_entry":true,"confidence":"high","reason":"网络入口"}\n```'
    is_entry, conf, reason = eps._parse_screen(out)
    assert is_entry is True
    assert conf == "high"
    assert reason == "网络入口"


def test_parse_screen_entry_false():
    out = '```json\n{"is_entry":false,"confidence":"medium","reason":"纯日志函数"}\n```'
    is_entry, conf, reason = eps._parse_screen(out)
    assert is_entry is False
    assert reason == "纯日志函数"


def test_parse_screen_bool_as_string():
    out = '```json\n{"is_entry":"false","reason":"getter"}\n```'
    is_entry, _conf, _reason = eps._parse_screen(out)
    assert is_entry is False


def test_parse_screen_unparseable():
    is_entry, _conf, _reason = eps._parse_screen("no json here")
    assert is_entry is None


def test_parse_screen_missing_key():
    is_entry, _conf, _reason = eps._parse_screen('```json\n{"confidence":"high"}\n```')
    assert is_entry is None


# ─── _truncate_body ───────────────────────────────────────────────────────────

def test_truncate_body_short():
    body = "\n".join(f"L{i}: x" for i in range(10))
    out, truncated = eps._truncate_body(body, max_lines=60)
    assert out == body
    assert truncated is False


def test_truncate_body_long():
    body = "\n".join(f"L{i}: x" for i in range(200))
    out, truncated = eps._truncate_body(body, max_lines=60)
    assert truncated is True
    assert "已截断" in out
    assert out.count("\n") <= 62


# ─── screen_entry_point ───────────────────────────────────────────────────────

def _stub_agent_result(output: str, *, error: str | None = None):
    return types.SimpleNamespace(output=output, token_usage=TokenUsage(input=3, output=4), error=error)


def test_screen_whitelist_short_circuits_no_agent(monkeypatch, tmp_path):
    called = {"agent": False, "extract": False}

    def fake_extract(*a, **k):
        called["extract"] = True
        return "code"

    def fake_run(*a, **k):
        called["agent"] = True
        return _stub_agent_result("")

    monkeypatch.setattr(eps, "_extract_function_body", fake_extract)
    monkeypatch.setattr(eps, "run_agent", fake_run)
    res = eps.screen_entry_point(_cfg(function_name="recvData"), target_dir=str(tmp_path))
    assert res.is_entry is True
    assert res.whitelisted is True
    assert res.matched_keyword == "recv"
    assert res.screened_by == "whitelist"
    # 白名单命中绝不调用 agent / 提取函数体（0 token）
    assert called["agent"] is False
    assert called["extract"] is False
    assert res.token_usage.input == 0


def test_screen_agent_says_entry(monkeypatch, tmp_path):
    monkeypatch.setattr(eps, "_extract_function_body", lambda *a, **k: "L1: void foo(Msg& m){}")
    captured = {}

    def fake_run(prompt, **kw):
        captured["prompt"] = prompt
        captured["thinking"] = kw.get("thinking_level")
        return _stub_agent_result('```json\n{"is_entry":true,"confidence":"high","reason":"接收外部消息"}\n```')

    monkeypatch.setattr(eps, "run_agent", fake_run)
    res = eps.screen_entry_point(_cfg(function_name="computeFoo"), target_dir=str(tmp_path))
    assert res.is_entry is True
    assert res.whitelisted is False
    assert res.screened_by == "agent"
    assert res.token_usage.input == 3
    assert captured["thinking"] == "off"
    assert "void foo(Msg& m)" in captured["prompt"]


def test_screen_agent_says_not_entry(monkeypatch, tmp_path):
    monkeypatch.setattr(eps, "_extract_function_body", lambda *a, **k: "L1: int getLen(){return n;}")
    monkeypatch.setattr(
        eps, "run_agent",
        lambda *a, **k: _stub_agent_result('```json\n{"is_entry":false,"confidence":"high","reason":"纯 getter"}\n```'),
    )
    res = eps.screen_entry_point(_cfg(function_name="getLen"), target_dir=str(tmp_path))
    assert res.is_entry is False
    assert res.reason == "纯 getter"
    assert res.screened_by == "agent"


def test_screen_failsafe_on_missing_body(monkeypatch, tmp_path):
    monkeypatch.setattr(eps, "_extract_function_body", lambda *a, **k: "")
    monkeypatch.setattr(eps, "run_agent", lambda *a, **k: _stub_agent_result(""))
    res = eps.screen_entry_point(_cfg(function_name="computeFoo"), target_dir=str(tmp_path))
    assert res.is_entry is True  # 失败安全：当作入口
    assert res.screened_by == "failsafe"
    assert res.error == "function_body_missing"


def test_screen_failsafe_on_unparseable(monkeypatch, tmp_path):
    monkeypatch.setattr(eps, "_extract_function_body", lambda *a, **k: "L1: code")
    monkeypatch.setattr(eps, "run_agent", lambda *a, **k: _stub_agent_result("not json"))
    res = eps.screen_entry_point(_cfg(function_name="computeFoo"), target_dir=str(tmp_path))
    assert res.is_entry is True  # 解析失败 → 当作入口
    assert res.screened_by == "failsafe"
    assert res.error == "screen_output_unparseable"


def test_screen_never_raises(monkeypatch, tmp_path):
    def boom(*a, **k):
        raise RuntimeError("explode")

    monkeypatch.setattr(eps, "_extract_function_body", boom)
    res = eps.screen_entry_point(_cfg(function_name="computeFoo"), target_dir=str(tmp_path))
    assert res.is_entry is True
    assert res.screened_by == "failsafe"
    assert "extract_function_body_failed" in (res.error or "")
