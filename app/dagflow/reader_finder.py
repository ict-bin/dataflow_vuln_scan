"""dagflow escape reader 查找 (LLM + v2_db, 独立于 V2 resolve_external)。

设计: docs/design-taint-analysis.md §9.3 (tracker 找读者, 经中继点接回)。
给 TrackerDispatcher.reader_finder 注入: ReaderFinder.find(escape_info) -> [reader_func_name]。
LLM agent 用 v2_db (lookup/propagations/symbol) 按逃逸语义查读者 (无字符串模式匹配)。
"""
from __future__ import annotations
import json, logging
from pathlib import Path
from typing import Any
from .taint_analyzer import _greedy_json_object

logger = logging.getLogger("dvs.dagflow.reader_finder")


_SYSTEM = """你是数据流污点分析中的外部逃逸下游读者追踪器。
目标: 给定一条从源函数逃逸出的污点 (extern/container 边), 找出会读取到该污点的下游函数。
策略:
1. 用 v2_db lookup <源函数名> 读源函数体, 搞清逃逸涉及的类型 (如结构体 struct X, 载体挂入哪个字段/容器)。
2. 用 v2_db 按该结构体类型查所有接收它的函数 (形参为 struct X* 的函数), 也可按字段名/容器名查访问者。
3. 对每个候选用 v2_db lookup 读体, 判断是否真读取了承载污点的容器/字段 (list_for_each/裸 for/范围 for/索引访问/自定义迭代, 靠语义不靠宏名)。
4. 只报真正会读到这条逃逸污点的函数; 不确定不报。
输出 JSON: {"confirmed": [{"function": "...", "taint_param": "...", "reason": "..."}]}
  function: 读者函数名 (v2_db 里真实存在); taint_param: 读者接收污点的入参名; reason: 为何认为读到。
"""


class ReaderFinder:
    """LLM+v2_db 找 escape 读者。注入 TrackerDispatcher.reader_finder。"""

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

    def find(self, escape_info: dict) -> list[str]:
        """escape_info = {escape_subkind, carrier, escape_via, sink_ref, taints, func} -> [reader_name]。"""
        if self._acfg is None:
            return []
        from ..runner import run_agent
        from ..parsers import _extract_json_object
        from .session_naming import session_path
        sp = str(session_path(self.sessions_dir, escape_info.get("func", "?")[:40],
                              escape_info.get("carrier") or escape_info.get("sink_ref") or "esc",
                              kind="track"))
        prompt = (
            f"## 源函数\n{escape_info.get('func', '?')}\n\n"
            f"## 逃逸信息\n"
            f"- escape_subkind: {escape_info.get('escape_subkind', '')}\n"
            f"- carrier: {escape_info.get('carrier', '')}\n"
            f"- escape_via: {escape_info.get('escape_via', '')}\n"
            f"- sink_ref (外部对象/容器): {escape_info.get('sink_ref', '')}\n"
            f"- taints: {escape_info.get('taints', [])}\n\n"
            f"请按系统提示词策略, 用 v2_db 查找读取这条逃逸污点的下游函数。\n"
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
        parsed = _extract_json_object(text, "confirmed") or _greedy_json_object(text) or {}
        out = []
        for item in (parsed.get("confirmed") or []):
            if isinstance(item, dict):
                fn = str(item.get("function", "")).strip()
                if fn and fn != "NOT_FOUND":
                    out.append(fn)
        if self.on_event:
            try:
                self.on_event("v2_dagflow_readers_found", func=escape_info.get("func", "")[:40],
                              readers=out, taints=escape_info.get("taints", []), task_id=self.task_id)
            except Exception:
                pass
        return out
