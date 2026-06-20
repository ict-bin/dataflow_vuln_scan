"""Orchestrator-level integration tests for the entry-screening pre-stage.

These exercise the depth=0 root branch of `execute_recursive` WITHOUT any LLM:
- reject path returns early (PASSED + skipped + archived) before BFS/LLM machinery.
- entry / whitelist paths fall through the gate into the normal pipeline.
"""

from __future__ import annotations

import app.orchestrator as orch_mod
from app.entry_point_screener import EntryScreenResult
from app.models import AgentInstanceConfig, RoleConfig, TaskConfig, TaskStatus
from app.orchestrator import Orchestrator


class _Sentinel(Exception):
    """Raised by a patched downstream hook to prove the gate was passed."""


def _cfg(tmp_path, **kw) -> TaskConfig:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / "a.c").write_text("int weird_helper(){ return 0; }\n", encoding="utf-8")
    out = tmp_path / "out"
    base = dict(
        task="对 a.c 的 weird_helper 函数完成数据流漏洞挖掘",
        source_file="a.c",
        function_name="weird_helper",
        cwd=str(src),
        output_dir=str(out),
        archive_dir=str(out),
        result_dir=str(out),
        entry_screen_enabled=True,
        workers=RoleConfig(agents=[AgentInstanceConfig(model="test/model")]),
    )
    base.update(kw)
    return TaskConfig(**base)


def test_orchestration_reject_returns_passed_and_skips(monkeypatch, tmp_path):
    """Agent 判定非入口 → 任务 PASSED + 跳过分析 + 归档注明理由。"""
    monkeypatch.setattr(
        orch_mod, "screen_entry_point",
        lambda cfg, **kw: EntryScreenResult(
            is_entry=False, screened_by="agent", confidence="high", reason="纯日志/调试函数",
        ),
    )
    # 若早退失败、误入后续阶段，sentinel 会暴露问题
    monkeypatch.setattr(orch_mod, "needs_taint_autodetect", lambda cfg: (_ for _ in ()).throw(_Sentinel()))

    events = []
    orch = Orchestrator(config=_cfg(tmp_path), on_event=events.append)
    result = orch.execute_recursive("task-reject")

    assert result.status == TaskStatus.PASSED
    assert result.completion_reason == "not_entry_point"
    assert result.analysis_status == "skipped_not_entry"
    assert "非入口" in (result.final_output or "")
    assert "纯日志/调试函数" in (result.final_output or "")

    out_dir = tmp_path / "out" / "task-reject" / "output"
    assert (out_dir / "flag").read_text(encoding="utf-8") == "1"
    assert (out_dir / "final_report.md").exists()
    # 分析被跳过：不应产出污点图数据库
    assert not (out_dir / "vuln-scan.sqlite").exists()
    # 事件中含 reject 及理由
    rejects = [e for e in events if e.type == "entry_screen_reject"]
    assert rejects and rejects[0].data.get("reason") == "纯日志/调试函数"


def test_orchestration_agent_entry_passes_gate(monkeypatch, tmp_path):
    """Agent 判定为入口 → 不早退，继续进入后续阶段（sentinel 证明越过闸门）。"""
    monkeypatch.setattr(
        orch_mod, "screen_entry_point",
        lambda cfg, **kw: EntryScreenResult(is_entry=True, screened_by="agent", confidence="medium", reason="接收外部消息"),
    )
    monkeypatch.setattr(orch_mod, "needs_taint_autodetect", lambda cfg: (_ for _ in ()).throw(_Sentinel()))

    events = []
    orch = Orchestrator(config=_cfg(tmp_path), on_event=events.append)
    try:
        orch.execute_recursive("task-entry")
        raised = False
    except _Sentinel:
        raised = True
    assert raised, "entry 判定应越过筛查闸门进入后续阶段"
    assert any(e.type == "entry_screen_pass" for e in events)


def test_orchestration_whitelist_passes_gate(monkeypatch, tmp_path):
    """白名单命中 → 不调 agent、不早退，直接越过闸门。"""
    # 不 patch screen_entry_point：走真实白名单逻辑
    monkeypatch.setattr(orch_mod, "needs_taint_autodetect", lambda cfg: (_ for _ in ()).throw(_Sentinel()))

    events = []
    orch = Orchestrator(config=_cfg(tmp_path, function_name="recvData", source_file="a.c"), on_event=events.append)
    # recvData 命中 "recv"
    try:
        orch.execute_recursive("task-wl")
        raised = False
    except _Sentinel:
        raised = True
    assert raised
    wl = [e for e in events if e.type == "entry_screen_whitelisted"]
    assert wl and wl[0].data.get("matched_keyword") == "recv"


def test_orchestration_disabled_skips_screen(monkeypatch, tmp_path):
    """开关关闭 → 完全不做筛查，直接进入后续阶段。"""
    called = {"screen": False}

    def fake_screen(cfg, **kw):
        called["screen"] = True
        return EntryScreenResult(is_entry=True)

    monkeypatch.setattr(orch_mod, "screen_entry_point", fake_screen)
    monkeypatch.setattr(orch_mod, "needs_taint_autodetect", lambda cfg: (_ for _ in ()).throw(_Sentinel()))

    events = []
    orch = Orchestrator(config=_cfg(tmp_path, entry_screen_enabled=False), on_event=events.append)
    try:
        orch.execute_recursive("task-off")
    except _Sentinel:
        pass
    assert called["screen"] is False
    assert not any(e.type.startswith("entry_screen") for e in events)
