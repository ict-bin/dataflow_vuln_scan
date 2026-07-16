"""dagflow 间接调用解析 (LLM + v2_db, 独立于 V2 function_pointer tracker)。

设计: docs/design-taint-analysis.md §9.3 (indirect tracker 解析真实函数 F -> 回填 sink_ref)。
给 TrackerDispatcher.function_resolver 注入: FunctionResolver.resolve(pointer_expr, func_name) -> [func_name]。
LLM agent 用 v2_db 搜指针表达式注册点 (赋值/注册回调) -> 真实处理函数。
"""
from __future__ import annotations
import logging
from pathlib import Path
from typing import Any
from .taint_analyzer import _greedy_json_object

logger = logging.getLogger("dvs.dagflow.function_resolver")


_SYSTEM = """你是数据流污点分析中的函数指针/回调间接调用解析器。
目标: 给定一个间接调用的指针表达式 (如 ctxt->sax->processingInstruction / fp / obj->handler),
找出该指针被赋值/注册为哪个真实函数。
策略:
1. 用 v2_db lookup <源函数名> 读源函数体, 搞清指针表达式的类型 (如 ctxt->sax 是某 struct 的字段)。
2. 用 v2_db 按该字段名/类型搜赋值点 (谁给该字段赋了函数地址 / 注册了回调)。
3. 对每个候选用 v2_db lookup 读体, 确认是否真把某函数赋给了该指针字段。
4. 也可能是函数表/vtable/dispatch_map, 按语义找注册点, 不靠宏名。
5. 只报真实注册到该指针的函数; 不确定不报。
输出 JSON: {"resolved": [{"function": "...", "reason": "..."}]}
  function: 真实处理函数名 (v2_db 里存在); reason: 为何认为该函数注册到此指针。
"""


class FunctionResolver:
    """LLM+v2_db 解析间接调用真实函数。注入 TrackerDispatcher.function_resolver。"""

    def __init__(self, *, config: Any, source_root: str, v2_db_dir: Path,
                 sessions_dir: Path, task_id: str = "", on_event: Any = None,
                 cancel_event: Any = None) -> None:
        self.config = config
        self.source_root = source_root
        self.v2_db_dir = v2_db_dir
        self.sessions_dir = Path(sessions_dir)
        self.task_id = task_id
        self.on_event = on_event
        self.cancel_event = cancel_event
        self._acfg = (config.workers.agents[0] if config.workers.agents else None)

    def resolve(self, pointer_expr: str, origin_func: str) -> list[str]:
        if self._acfg is None:
            return []
        from ..runner import run_agent
        from ..parsers import _extract_json_object
        from .session_naming import session_path
        sp = str(session_path(self.sessions_dir, origin_func[:40],
                              (pointer_expr or "indirect")[:30], kind="track"))
        prompt = (
            f"## 源函数\n{origin_func}\n\n"
            f"## 间接调用指针表达式\n{pointer_expr}\n\n"
            f"请按系统提示词策略, 用 v2_db 搜该指针被赋值/注册为哪个真实函数。\n"
        )
        env = {"DVS_V2_DB_DIR": str(self.v2_db_dir), "DVS_SOURCE_ROOT": str(self.source_root)}
        output = run_agent(
            prompt=prompt, model=self._acfg.model,
            tools=self._acfg.tools or self.config.workers.default_tools,
            cwd=str(self.source_root), env=env, session_file=sp,
            system_prompt=_SYSTEM, cancel_event=self.cancel_event,
            thinking_level="off",
            run_timeout_seconds=min(getattr(self.config, "agent_run_timeout_seconds", 1500), 1600),
            timeout_retry_enabled=getattr(self.config, "agent_timeout_retry_enabled", True),
            timeout_max_retries=getattr(self.config, "agent_timeout_max_retries", 20),
            pi_max_retries=getattr(self.config, "pi_max_retries", 3),
            pi_retry_delay=getattr(self.config, "pi_retry_delay", 10.0),
            task_context={"task_id": self.task_id,
                          "task_root": str(self.sessions_dir.parent.parent.parent),
                          "task_run_root": str(self.sessions_dir.parent),
                          "task_pi_dir": self.config.role_pi_dir("workers"),
                          "agent_role": "workers", "fork_purpose": "external_tracking"},
        )
        text = output.output or ""
        parsed = _extract_json_object(text, "resolved") or _greedy_json_object(text) or {}
        out = []
        for item in (parsed.get("resolved") or []):
            if isinstance(item, dict):
                fn = str(item.get("function", "")).strip()
                if fn and fn != "NOT_FOUND":
                    out.append(fn)
        if self.on_event:
            try:
                self.on_event("v2_dagflow_indirect_resolved_llm", origin=origin_func[:40],
                              expr=pointer_expr, resolved=out, task_id=self.task_id)
            except Exception:
                pass
        return out
