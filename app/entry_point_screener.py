"""入口快速筛查（Entry Screening，depth=0 预阶段）。

目的：在进入昂贵的污点追踪 / 漏洞挖掘之前，用一个**廉价的预筛**把明显
不是「模块入口 / 外部输入处理入口」的函数挡掉（如纯工具函数、getter/setter、
日志、数学计算、内部状态机辅助函数），直接以 PASSED 状态结束，并在日志中
注明「非入口」及判断理由。

两级判定（仅 depth=0 根函数生效）：

1. **白名单关键字命中**：函数名（大小写不敏感子串）命中白名单（recv/read/
   proc/handle/...）→ 直接判为入口，**0 token、0 agent 调用**。
2. **未命中** → 拉起一个独立系统提示词的 pi agent，单轮会话、无 Judge、
   thinking off、不写文件，仅依据函数签名 + 函数体头部判断 is_entry。

失败安全（绝不误杀）：函数体提取失败 / agent 出错 / JSON 解析失败 / 拿不准
→ 一律按「是入口」处理（is_entry=True），继续后续分析，不影响任务成败。

实现风格完全对齐 app/taint_source_identifier.py。
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Any, Callable

from .config import load_system_prompts, resolve_system_prompt
from .models import SwarmEvent, TaskConfig, TokenUsage, DEFAULT_ENTRY_WHITELIST
from .runner import run_agent
from .taint_workflow import _extract_function_body
from .vuln_workflow import _extract_json_from_text

logger = logging.getLogger("dvs.entry_screen")

# 默认（仓库内置）入口筛查系统提示词目录，相对仓库根
_DEFAULT_PROMPT_REL = "prompts/entry-screen"
# agent 无显式 workers.agents 时的兜底模型
_FALLBACK_MODEL = "gaiasec/auto"
_FALLBACK_TOOLS = ["read", "bash", "find"]
# agent 输入的函数体最大行数（仅取头部，省 token）
_BODY_HEAD_LINES = 60

# 默认白名单关键字（小写）：与 models.DEFAULT_ENTRY_WHITELIST 单一来源。
# 项目可在前端配置页覆盖此列表。


@dataclass
class EntryScreenResult:
    is_entry: bool = True            # 失败安全默认值：当作入口
    whitelisted: bool = False        # 是否白名单命中直接放行
    matched_keyword: str = ""        # 命中的白名单关键字
    screened_by: str = "agent"       # whitelist | agent | failsafe
    confidence: str = ""             # high | medium | low
    reason: str = ""                 # 判定理由（中文一句话）
    token_usage: TokenUsage = field(default_factory=TokenUsage)
    raw_output: str = ""
    error: str | None = None


def needs_entry_screen(cfg: TaskConfig) -> bool:
    """任务是否启用入口快速筛查。默认关（向后兼容）。"""
    return bool(getattr(cfg, "entry_screen_enabled", False))


def _whitelist(cfg: TaskConfig) -> list[str]:
    raw = list(getattr(cfg, "entry_screen_whitelist", None) or [])
    kws = [str(k).strip().lower() for k in raw if str(k).strip()]
    return kws if kws else list(DEFAULT_ENTRY_WHITELIST)


def whitelist_hit(cfg: TaskConfig) -> str | None:
    """函数名是否命中白名单（大小写不敏感子串匹配）。

    `Class::Method` 形式按完整函数名匹配（含 Class 前缀）。
    返回命中的关键字，未命中返回 None。
    """
    func = str(getattr(cfg, "function_name", "") or "").strip().lower()
    if not func:
        return None
    for kw in _whitelist(cfg):
        if kw and kw in func:
            return kw
    return None


def _resolve_prompt_dir(cfg: TaskConfig) -> str:
    """解析入口筛查系统提示词目录。

    优先级：workers.system_prompt_dir 同级 `entry-screen` 目录 >
    仓库内置 `prompts/entry-screen`。
    """
    workers_dir = str(getattr(getattr(cfg, "workers", None), "system_prompt_dir", "") or "").strip()
    if workers_dir:
        sibling = os.path.join(os.path.dirname(os.path.abspath(workers_dir)), "entry-screen")
        if os.path.isdir(sibling):
            return sibling
    return str(Path(__file__).resolve().parents[1] / _DEFAULT_PROMPT_REL)


def _truncate_body(func_body: str, max_lines: int = _BODY_HEAD_LINES) -> tuple[str, bool]:
    lines = (func_body or "").splitlines()
    if len(lines) <= max_lines:
        return func_body, False
    head = "\n".join(lines[:max_lines])
    return head + "\n// ...（函数体已截断，仅展示头部）...", True


def _build_screen_prompt(cfg: TaskConfig, func_body: str, truncated: bool) -> str:
    trunc_note = "（注意：以下函数体已截断，仅展示头部；若信息不足以判定为纯内部函数，请判 is_entry=true）\n" if truncated else ""
    return (
        "# 入口快速筛查（Entry Screening）\n\n"
        f"目标函数: `{cfg.source_file}::{cfg.function_name}`\n\n"
        "请判断该函数是否是「模块入口 / 外部输入处理入口」。这是一个廉价预筛，"
        "**不要做污点追踪、不要做漏洞分析、不要读其他文件、不要写任何文件**，"
        "在一轮内给出结论。\n\n"
        f"## 函数源码（带绝对行号）\n{trunc_note}```cpp\n{func_body}\n```\n\n"
        "请在最终回复中直接输出一个 JSON 对象（用 ```json 包裹），包含 "
        "function / is_entry / confidence / reason 字段。"
        "保守优先：拿不准就判 is_entry=true。\n"
    )


def _coerce_bool(value: Any, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "y", "entry", "is_entry"}:
        return True
    if text in {"false", "0", "no", "n", "not_entry", "non_entry"}:
        return False
    return default


def _parse_screen(output: str) -> tuple[bool | None, str, str]:
    """解析 agent 输出。返回 (is_entry|None, confidence, reason)。

    is_entry 为 None 表示无法解析（调用方按失败安全处理）。
    """
    obj: Any = _extract_json_from_text(output or "", key="is_entry")
    if obj is None:
        obj = _extract_json_from_text(output or "")
    if not isinstance(obj, dict) or "is_entry" not in obj:
        return None, "", ""
    is_entry = _coerce_bool(obj.get("is_entry"), default=True)
    confidence = str(obj.get("confidence") or "").strip().lower()
    reason = str(obj.get("reason") or obj.get("description") or "").strip()
    return is_entry, confidence, reason


def screen_entry_point(
    cfg: TaskConfig,
    *,
    target_dir: str,
    session_file: str | None = None,
    on_event: Callable[[SwarmEvent], None] | None = None,
    cancel_event: Event | None = None,
) -> EntryScreenResult:
    """对根函数执行入口快速筛查。绝不抛异常（失败一律按「是入口」继续）。"""
    res = EntryScreenResult()

    # ① 白名单命中 → 直接放行，0 token
    hit = whitelist_hit(cfg)
    if hit:
        res.is_entry = True
        res.whitelisted = True
        res.matched_keyword = hit
        res.screened_by = "whitelist"
        res.confidence = "high"
        res.reason = f"函数名命中入口白名单关键字 `{hit}`"
        return res

    # ② agent 判定
    try:
        func_body = _extract_function_body(
            target_dir,
            cfg.source_file,
            cfg.function_name,
            cfg.line_hint,
            funcdb_path=str(getattr(cfg, "funcdb_path", "") or ""),
            func_hash=str(getattr(cfg, "func_hash", "") or ""),
        )
    except Exception as exc:  # pragma: no cover - 防御式
        logger.warning("entry screen: extract function body failed: %s", exc, exc_info=True)
        res.screened_by = "failsafe"
        res.error = f"extract_function_body_failed: {exc}"
        return res
    if not func_body.strip():
        res.screened_by = "failsafe"
        res.error = "function_body_missing"
        return res

    body_for_prompt, truncated = _truncate_body(func_body)

    agents = list(getattr(cfg.workers, "agents", []) or [])
    acfg = agents[0] if agents else None
    model = (str(getattr(acfg, "model", "") or "").strip() if acfg else "") or _FALLBACK_MODEL
    tools = (
        (list(getattr(acfg, "tools", []) or []) if acfg else [])
        or list(getattr(cfg.workers, "default_tools", []) or [])
        or _FALLBACK_TOOLS
    )
    # 入口筛查强制 thinking off（省 token / 省时）；可被 cfg.entry_screen_thinking_level 覆盖
    thinking_level = str(getattr(cfg, "entry_screen_thinking_level", "") or "off").strip() or "off"
    prompt_dir = _resolve_prompt_dir(cfg)
    sys_prompts = load_system_prompts(prompt_dir, 1)
    system_prompt = (
        resolve_system_prompt(0, acfg, sys_prompts)
        if acfg is not None
        else (sys_prompts[0] if sys_prompts else "")
    )
    prompt = _build_screen_prompt(cfg, body_for_prompt, truncated)

    try:
        agent_result = run_agent(
            prompt,
            model=model,
            tools=tools,
            system_prompt=system_prompt,
            cwd=str(target_dir),
            env={**os.environ},
            thinking_level=thinking_level,
            session_file=session_file,
            cancel_event=cancel_event,
            max_retries=int(getattr(cfg, "agent_max_retries", -1)),
            retry_delay=float(getattr(cfg, "agent_retry_delay", 30.0)),
            run_timeout_seconds=int(getattr(cfg, "agent_run_timeout_seconds", 1800)),
            timeout_retry_enabled=bool(getattr(cfg, "agent_timeout_retry_enabled", True)),
            timeout_max_retries=int(getattr(cfg, "agent_timeout_max_retries", 20)),
            pi_max_retries=int(getattr(cfg, "pi_max_retries", 3)),
            pi_retry_delay=float(getattr(cfg, "pi_retry_delay", 10.0)),
            # 复用 Worker 的任务级 pi runtime（同一任务级注入 apiKey / 模型配置）
            task_context={
                "task_id": str(getattr(cfg, "task_name", "") or ""),
                "stage": "entry_screening",
                "agent_role": "workers",
                "task_pi_dir": (cfg.role_pi_dir("workers") if hasattr(cfg, "role_pi_dir") else ""),
            },
        )
    except Exception as exc:  # pragma: no cover - 防御式
        logger.warning("entry screen: run_agent failed: %s", exc, exc_info=True)
        res.screened_by = "failsafe"
        res.error = f"run_agent_failed: {exc}"
        return res

    res.token_usage = agent_result.token_usage
    res.raw_output = agent_result.output or ""
    if agent_result.error and not res.raw_output.strip():
        res.screened_by = "failsafe"
        res.error = str(agent_result.error)
        return res

    is_entry, confidence, reason = _parse_screen(res.raw_output)
    if is_entry is None:
        # 解析失败 → 失败安全：当作入口
        res.screened_by = "failsafe"
        res.error = "screen_output_unparseable"
        res.is_entry = True
        return res

    res.is_entry = bool(is_entry)
    res.confidence = confidence
    res.reason = reason or ("判定为模块入口" if is_entry else "判定为非入口纯内部函数")
    return res
