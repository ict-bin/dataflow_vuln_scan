"""污点源自动识别（depth=0 预阶段）。

当任务未提供污点信息（taint_params/taint_details 均为空），或污点信息仅为
``all`` 哨兵时，使用一个独立系统提示词的 pi agent，在**一轮会话**内、把**完整
函数体**嵌入 prompt，判断该函数中哪些数据来自外部/不可信来源（污点源）。

识别结果由编排器（orchestrator.execute_recursive 根分支）补充到根任务输入
（cfg.taint_params / cfg.taint_details），随后接续现有 BFS 污点追踪流程。

agent 的拉起方式与 Worker 完全一致（run_agent + 系统提示词目录 + workers[0]
模型/工具/思考等级），仅系统提示词和单轮无 Judge 这一点不同。
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Any, Callable

from .config import load_system_prompts, resolve_system_prompt
from .models import SwarmEvent, TaskConfig, TokenUsage
from .runner import run_agent
from .taint_workflow import _extract_function_body
from .vuln_workflow import _extract_json_from_text, _is_likely_external_taint_symbol

logger = logging.getLogger("dvs.taint_source_id")

# 默认（仓库内置）污点源识别系统提示词目录，相对仓库根
_DEFAULT_PROMPT_REL = "prompts/taint-source-id"
# agent 无显式 workers.agents 时的兜底模型
_FALLBACK_MODEL = "gaiasec/auto"
_FALLBACK_TOOLS = ["read", "bash", "find"]


@dataclass
class AutodetectResult:
    taint_params: list[str] = field(default_factory=list)
    taint_details: list[dict[str, str]] = field(default_factory=list)
    token_usage: TokenUsage = field(default_factory=TokenUsage)
    raw_output: str = ""
    no_external_input: bool = False
    error: str | None = None


def needs_taint_autodetect(cfg: TaskConfig) -> bool:
    """任务是否需要自动识别污点源。

    True 当且仅当任务**没有可用的污点信息**：
    - taint_details 中没有任何有效 symbol；且
    - taint_params 为空，或仅包含 ``all`` 哨兵（大小写不敏感）。
    """
    for detail in cfg.taint_details or []:
        if not isinstance(detail, dict):
            continue
        symbol = str(
            detail.get("name")
            or detail.get("taint")
            or detail.get("param")
            or detail.get("symbol")
            or ""
        ).strip()
        if symbol and symbol.lower() != "all":
            return False
    params = [str(p).strip() for p in (cfg.taint_params or []) if str(p).strip()]
    non_all = [p for p in params if p.lower() != "all"]
    if non_all:
        return False
    return True


def _resolve_prompt_dir(cfg: TaskConfig) -> str:
    """解析污点源识别系统提示词目录。

    优先级：workers.system_prompt_dir 同级 `taint-source-id` 目录 >
    仓库内置 `prompts/taint-source-id`。
    """
    workers_dir = str(getattr(getattr(cfg, "workers", None), "system_prompt_dir", "") or "").strip()
    if workers_dir:
        sibling = os.path.join(os.path.dirname(os.path.abspath(workers_dir)), "taint-source-id")
        if os.path.isdir(sibling):
            return sibling
    return str(Path(__file__).resolve().parents[1] / _DEFAULT_PROMPT_REL)


def _build_identify_prompt(cfg: TaskConfig, func_body: str) -> str:
    return (
        "# 污点源识别（Taint Source Identification）\n\n"
        f"目标函数: `{cfg.source_file}::{cfg.function_name}`\n\n"
        "本任务**未提供明确的污点输入信息**。请你仅判断该函数中哪些数据来自"
        "外部 / 不可信来源（污点源）。**不要做污点传播追踪，不要做漏洞分析，"
        "不要写任何文件。**\n\n"
        "## 函数源码（带绝对行号）\n```cpp\n"
        f"{func_body}\n```\n\n"
        "请在最终回复中直接输出一个 JSON 对象（用 ```json 包裹），包含 "
        "function / source_file / no_external_input / taints 字段；"
        "taints 中每个元素包含 symbol / kind / line / reason。\n"
        "若该函数没有任何外部输入，置 no_external_input=true 且 taints 为空数组。\n"
    )


def _parse_taints(output: str) -> tuple[list[str], list[dict[str, str]], bool]:
    obj: Any = _extract_json_from_text(output or "", key="taints")
    if obj is None:
        # 容错：agent 直接输出 taints 数组
        obj = _extract_json_from_text(output or "")
    raw_taints: Any = None
    no_external_input = False
    if isinstance(obj, dict):
        raw_taints = obj.get("taints")
        no_external_input = bool(obj.get("no_external_input"))
    elif isinstance(obj, list):
        raw_taints = obj
    params: list[str] = []
    details: list[dict[str, str]] = []
    for item in raw_taints or []:
        if isinstance(item, dict):
            symbol = str(item.get("symbol") or item.get("name") or item.get("param") or "").strip()
            kind = str(item.get("kind") or item.get("source_kind") or "param").strip() or "param"
            line = str(item.get("line") or item.get("line_hint") or "").strip()
            reason = str(item.get("reason") or item.get("description") or "").strip()
        else:
            symbol = str(item or "").strip()
            kind, line, reason = "param", "", ""
        symbol = symbol.lstrip("&").strip()
        if not symbol or symbol.lower() == "all":
            continue
        if not _is_likely_external_taint_symbol(symbol):
            continue
        if symbol in params:
            continue
        params.append(symbol)
        details.append({
            "name": symbol,
            "source_kind": kind,
            "line": line,
            "description": reason or "污点源自动识别结果",
        })
    return params, details, no_external_input


def autodetect_taint_sources(
    cfg: TaskConfig,
    *,
    target_dir: str,
    session_file: str | None = None,
    on_event: Callable[[SwarmEvent], None] | None = None,
    cancel_event: Event | None = None,
) -> AutodetectResult:
    """对根函数运行一轮 pi agent，识别污点源。绝不抛异常（失败返回带 error 的空结果）。"""
    emit = on_event or (lambda e: None)
    res = AutodetectResult()
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
        logger.warning("taint autodetect: extract function body failed: %s", exc, exc_info=True)
        res.error = f"extract_function_body_failed: {exc}"
        return res
    if not func_body.strip():
        res.error = "function_body_missing"
        return res

    agents = list(getattr(cfg.workers, "agents", []) or [])
    acfg = agents[0] if agents else None
    model = (str(getattr(acfg, "model", "") or "").strip() if acfg else "") or _FALLBACK_MODEL
    tools = (
        (list(getattr(acfg, "tools", []) or []) if acfg else [])
        or list(getattr(cfg.workers, "default_tools", []) or [])
        or _FALLBACK_TOOLS
    )
    thinking_level = (
        (str(getattr(acfg, "thinking_level", "") or "").strip() if acfg else "")
        or str(getattr(cfg.workers, "default_thinking_level", "") or "").strip()
        or "off"
    )
    prompt_dir = _resolve_prompt_dir(cfg)
    sys_prompts = load_system_prompts(prompt_dir, 1)
    system_prompt = (
        resolve_system_prompt(0, acfg, sys_prompts)
        if acfg is not None
        else (sys_prompts[0] if sys_prompts else "")
    )
    prompt = _build_identify_prompt(cfg, func_body)

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
            # 复用 Worker 的任务级 pi runtime（同一任务级注入 apiKey / 模型配置），
            # 与其他 Worker 一致；否则独立 agent 会退回全局占位 key 导致 401。
            task_context={
                "task_id": str(getattr(cfg, "task_name", "") or ""),
                "stage": "taint_source_identification",
                "agent_role": "workers",
                "task_pi_dir": (cfg.role_pi_dir("workers") if hasattr(cfg, "role_pi_dir") else ""),
            },
        )
    except Exception as exc:  # pragma: no cover - 防御式
        logger.warning("taint autodetect: run_agent failed: %s", exc, exc_info=True)
        res.error = f"run_agent_failed: {exc}"
        return res

    res.token_usage = agent_result.token_usage
    res.raw_output = agent_result.output or ""
    if agent_result.error and not res.raw_output.strip():
        res.error = str(agent_result.error)
        return res

    params, details, no_external_input = _parse_taints(res.raw_output)
    res.taint_params = params
    res.taint_details = details
    res.no_external_input = no_external_input
    return res
