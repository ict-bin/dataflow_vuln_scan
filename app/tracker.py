"""LLM tracker fork helpers for unresolvable DVS followups."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .runner import run_agent


TRACKER_PROMPTS: dict[str, str] = {
    "nonlocal": """
你是数据流污点分析中的“非局部变量使用点追踪器”。

目标：不要做完整漏洞分析，只负责找出被污染的全局变量/静态变量/类成员变量后续可能被哪些函数读取或使用。

输入上下文：
- 调用方文件: {caller_file}
- 调用方函数: {caller_func}
- 当前候选函数: {callee_function}
- 当前候选位置: {callee_file} {callee_line}
- 已污染非局部变量(JSON):
```json
{tainted_nonlocal_json}
```
- 原始说明: {description}

任务：
1. 使用 bash/rg 在源码树中搜索这些非局部变量的读取点和使用点。
2. 只输出静态证据明确的函数，不要猜测。
3. 对每个目标给出 file/function/line/tainted_params/reason。
4. 最终只输出 JSON，不要输出 Markdown。

输出格式：
```json
{{
  "tracked_functions": [
    {{"file":"rel/path.c", "function":"Func", "line":"L123", "tainted_params":["g_state.key"], "reason":"读取已污染全局变量 g_state.key"}}
  ]
}}
```
""".strip(),
    "function_pointer": """
你是数据流污点分析中的“函数指针/回调目标追踪器”。

目标：不要做完整漏洞分析，只负责从函数指针、虚函数、hook、dispatch map 中解析可能的真实目标函数。

输入上下文：
- 调用方文件: {caller_file}
- 调用方函数: {caller_func}
- 调用机制: {dispatch_kind}
- 候选 callee 名: {callee_function}
- 调用位置: {callee_file} {callee_line}
- 污点参数: {tainted_params}
- 原始说明: {description}

任务：
1. 若是函数指针字段/表调用，搜索赋值、初始化表、register/add_handler/set_handler 等注册点。
2. 若是 hook/callback，搜索 hook 变量赋值和注册函数。
3. 若是 C++ 虚函数，搜索类定义和 override 实现。
4. 若无法静态确定，输出空 tracked_functions，并在 reason 中说明。
5. 最终只输出 JSON，不要输出 Markdown。

输出格式：
```json
{{
  "tracked_functions": [
    {{"file":"rel/path.c", "function":"ConcreteHandler", "line":"L456", "tainted_params":["arg1"], "reason":"在 handler_table 中注册为 ctrl_id 对应处理函数"}}
  ],
  "reason": "无法解析时说明原因"
}}
```
""".strip(),
}


@dataclass
class TrackerResult:
    functions: list[dict[str, Any]] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""


def _extract_json(text: str) -> dict[str, Any]:
    candidates: list[str] = []
    import re
    for m in re.finditer(r"```(?:json)?\s*\n(.*?)\n\s*```", text, re.S):
        candidates.append(m.group(1))
    candidates.append(text)
    for raw in candidates:
        raw = raw.strip()
        start = raw.find("{")
        end = raw.rfind("}")
        if start >= 0 and end > start:
            try:
                obj = json.loads(raw[start:end + 1])
                return obj if isinstance(obj, dict) else {}
            except Exception:
                pass
    return {}


async def run_tracker(
    tracker_type: str,
    context: dict[str, Any],
    *,
    workspace: Path,
    model: str,
    tools: list[str],
    session_file: str,
    cancel_event=None,
    run_timeout_seconds: float | int = 300,
    pi_max_retries: int = -1,
    pi_retry_delay: float = 10.0,
    task_context: dict[str, object] | None = None,
) -> TrackerResult:
    prompt_template = TRACKER_PROMPTS.get(tracker_type)
    if not prompt_template:
        return TrackerResult(error=f"unknown tracker_type={tracker_type}")
    ctx = dict(context)
    ctx.setdefault("tainted_nonlocal_json", json.dumps(ctx.get("tainted_nonlocal") or [], ensure_ascii=False, indent=2))
    prompt = prompt_template.format(**ctx)
    result = await run_agent(
        prompt=prompt,
        model=model,
        tools=tools,
        cwd=str(workspace),
        session_file=session_file,
        system_prompt=f"你是 DVS {tracker_type} tracker，只输出 JSON。",
        cancel_event=cancel_event,
        run_timeout_seconds=run_timeout_seconds,
        timeout_retry_enabled=False,
        pi_max_retries=pi_max_retries,
        pi_retry_delay=pi_retry_delay,
        task_context=task_context,
    )
    parsed = _extract_json(result.output or "")
    items = parsed.get("tracked_functions") or parsed.get("functions") or []
    if not isinstance(items, list):
        items = []
    return TrackerResult(functions=[x for x in items if isinstance(x, dict)], raw_output=result.output or "", error=result.error or str(parsed.get("reason") or ""))
