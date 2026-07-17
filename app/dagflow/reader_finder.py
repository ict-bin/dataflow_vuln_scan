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

_PROMPT_PATH = Path(__file__).resolve().parent.parent.parent / "prompts" / "dagflow" / "reader-finder.md"
_PROMPT_CACHE: str | None = None


def _system_prompt() -> str:
    global _PROMPT_CACHE
    if _PROMPT_CACHE is None:
        _PROMPT_CACHE = _PROMPT_PATH.read_text(encoding="utf-8")
    return _PROMPT_CACHE


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

    def _read_func_body(self, func_file: str, start: int, end: int) -> str:
        """读源文件, 提取函数体, 加行号前缀。"""
        if not func_file or not start:
            return ""
        from pathlib import Path
        src_path = Path(self.source_root) / func_file
        if not src_path.is_file():
            return ""
        try:
            lines = src_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return ""
        s = max(0, start - 1)
        e = min(len(lines), end) if end else min(len(lines), s + 200)
        result = []
        for i in range(s, e):
            ln = i + 1  # 文件绝对行号 (1-based)
            result.append(f"{ln:>5}│ {lines[i]}")
        return "\n".join(result)

    def find(self, escape_info: dict) -> list[str]:
        """escape_info = {escape_subkind, carrier, escape_via, sink_ref, taints,
        func, func_name, func_file, func_start_line, func_end_line} -> [reader_name]。"""
        if self._acfg is None:
            return []
        from ..runner import run_agent
        from ..parsers import _extract_json_object
        from .session_naming import session_path
        sp = str(session_path(self.sessions_dir, escape_info.get("func", "?")[:40],
                              escape_info.get("carrier") or escape_info.get("sink_ref") or "esc",
                              kind="track"))
        # 内嵌源函数体 (行号标记) — LLM 不需要查 v2_db 就能看到逃逸点
        func_name = escape_info.get('func_name', escape_info.get('func', '?'))
        func_file = escape_info.get('func_file', '')
        func_start = escape_info.get('func_start_line', 0)
        func_end = escape_info.get('func_end_line', 0)
        body_text = self._read_func_body(func_file, func_start, func_end)
        prompt = (
            f"## 源函数\n{func_name} ({func_file}, 行 {func_start}-{func_end})\n\n"
        )
        if body_text:
            prompt += f"## 源函数体 (行号已标记)\n```\n{body_text}\n```\n\n"
        prompt += (
            f"## 逃逸信息\n"
            f"- escape_subkind: {escape_info.get('escape_subkind', '')}\n"
            f"- carrier: {escape_info.get('carrier', '')}\n"
            f"- escape_via: {escape_info.get('escape_via', '')}\n"
            f"- taints: {escape_info.get('taints', [])}\n\n"
            f"请按系统提示词策略, 用 v2_db 查找读取这条逃逸污点的下游函数。\n"
        )
        env = {"DVS_V2_DB_DIR": str(self.v2_db_dir), "DVS_SOURCE_ROOT": str(self.source_root)}
        output = run_agent(
            prompt=prompt, model=self._acfg.model,
            tools=self._acfg.tools or self.config.workers.default_tools,
            cwd=str(self.source_root), env=env, session_file=sp,
            system_prompt=_system_prompt(), cancel_event=self.cancel_event,
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
        parsed = _extract_json_object(text, "readers") or _greedy_json_object(text) or {}
        out = []
        readers = parsed.get("readers") or parsed.get("confirmed") or []
        for item in readers:
            if isinstance(item, dict):
                fn = str(item.get("function", "")).strip()
                if fn and fn != "NOT_FOUND":
                    out.append(fn)
            elif isinstance(item, str):
                if item and item != "NOT_FOUND":
                    out.append(item)
        if self.on_event:
            try:
                self.on_event("v2_dagflow_readers_found", func=escape_info.get("func", "")[:40],
                              readers=out, taints=escape_info.get("taints", []), task_id=self.task_id)
            except Exception:
                pass
        return out
