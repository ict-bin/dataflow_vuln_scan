"""dagflow taint 分析器: LLM 产 DAG (无行号) + JSON 解析。

设计: docs/design-taint-analysis.md §3 (LLM 输出拓扑+语义, 不含行号; 行号由 line_filler 填)。
独立会话 (func-taint, 不 fork 调用链)。复用 run_agent + read_function_body + _extract_json_object。
"""
from __future__ import annotations
import json, logging
from pathlib import Path
from typing import Any
from .models import TaintDAG

logger = logging.getLogger("dvs.dagflow.taint_analyzer")

_PROMPT_PATH = Path(__file__).resolve().parent.parent.parent / "prompts" / "dagflow" / "taint-dag.md"
_PROMPT_CACHE: str | None = None


def _system_prompt() -> str:
    global _PROMPT_CACHE
    if _PROMPT_CACHE is None:
        _PROMPT_CACHE = _PROMPT_PATH.read_text(encoding="utf-8")
    return _PROMPT_CACHE


class TaintAnalyzer:
    """单函数单污点 DAG 分析 (LLM, 无行号)。"""

    def __init__(self, *, config: Any, sessions_dir: Path, on_event: Any = None,
                 task_id: str = "") -> None:
        self.config = config
        self.sessions_dir = Path(sessions_dir)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.on_event = on_event
        self.task_id = task_id
        self.source_root = getattr(config, "cwd", "") or getattr(config, "source_root", "")
        # agent 配置 (复用 workers.agents[0])
        self._acfg = (config.workers.agents[0] if config.workers.agents else None)
        self._default_tools = getattr(config.workers, "default_tools", None)

    def _build_prompt(self, func, body: str, taint_sig: str, is_auto: bool) -> tuple[str, str]:
        """返回 (prompt, session_path)。"""
        taint_desc = ("自行分析（未指定具体污点参数）。识别本函数内所有外部输入源（入参/内部调用产物/被动传递），"
                      "每个源作为 source 节点 (is_source=true) 起 DAG。") if is_auto else \
                     f"入口污点签名: {taint_sig}（从该污点起跟踪传播）"
        prompt = (
            f"# 阶段：单函数污点传播 DAG 分析\n\n"
            f"目标函数: `{func.file}::{func.name}` (行 {func.start_line}-{func.end_line})\n"
            f"{taint_desc}\n\n"
            f"## 函数体\n```c\n{body}\n```\n\n"
            f"按系统提示词要求输出 DAG JSON（顶层唯一一个 ```json 块，最后输出，不含 line）。"
        )
        from .session_naming import session_path
        sp = str(session_path(self.sessions_dir, func.name, taint_sig or "auto",
                              kind="taint", depth=getattr(self, "_cur_depth", -1)))
        return prompt, sp

    def analyze(self, func, taint_sig: str, is_auto: bool = False) -> tuple[TaintDAG, str]:
        """分析 (func, taint) → (DAG 无行号, session_path)。失败 raise (调用方删占位)。"""
        if self._acfg is None:
            raise RuntimeError("no agent configured for dagflow taint_analyzer")
        from ..dataflow_v2.function_extractor import read_function_body
        from ..runner import run_agent
        from ..parsers import _extract_json_object
        import time as _time
        _t0 = _time.time()
        body = read_function_body(self.source_root, func, max_lines=0)  # 全函数体 (不截断, 防 LLM read 补读)
        prompt, sp = self._build_prompt(func, body, taint_sig, is_auto)
        v2_env = {"DVS_SOURCE_ROOT": str(self.source_root),
                  "DVS_V2_DB_DIR": str(self.sessions_dir.parent / "dataflow-v2")}
        logger.info("[dagflow-taint] CALLING run_agent func=%s taint=%s session=%s",
                    func.name, taint_sig, sp[-60:])
        output = run_agent(
            prompt=prompt, model=self._acfg.model,
            tools=self._acfg.tools or self._default_tools or [],
            cwd=str(self.source_root), env=v2_env, session_file=sp,
            system_prompt=_system_prompt(),
            cancel_event=getattr(self, "cancel_event", None),
            thinking_level="off",
            run_timeout_seconds=getattr(self.config, "agent_run_timeout_seconds", 900),
            timeout_retry_enabled=getattr(self.config, "agent_timeout_retry_enabled", True),
            timeout_max_retries=getattr(self.config, "agent_timeout_max_retries", 20),
            pi_max_retries=getattr(self.config, "pi_max_retries", 3),
            pi_retry_delay=getattr(self.config, "pi_retry_delay", 10.0),
            task_context={"task_id": self.task_id, "agent_role": "workers", "fork_purpose": "dagflow_taint_analysis"},
        )
        text = output.output or ""
        parsed = _extract_json_object(text, "nodes")
        if parsed is None:
            parsed = _greedy_json_object(text)
        if not isinstance(parsed, dict) or not isinstance(parsed.get("nodes"), list):
            raise RuntimeError(f"dagflow taint JSON parse failed for {func.name}/{taint_sig}")
        # 注入归属 (LLM 不输出 func_id/taint_signature)
        parsed["func_id"] = func.func_id
        parsed["taint_signature"] = taint_sig or "auto"
        dag = TaintDAG.from_dict(parsed)
        logger.info("[dagflow-taint] DONE func=%s taint=%s duration=%.1fs error=%s output_len=%d",
                    func.name, taint_sig, _time.time() - _t0, (output.error or "")[:100], len(output.output or ""))
        if self.on_event:
            try:
                self.on_event("v2_dagflow_taint_done", function=func.name, taint=taint_sig,
                              nodes=len(dag.nodes), self_contained=dag.self_contained,
                              task_id=self.task_id)
            except Exception:
                pass
        return dag, sp


def _greedy_json_object(text: str) -> dict | None:
    """兜底: 找最后一个 ```json 块或最外层 { ... } 尝试解析。"""
    import re
    m = re.findall(r"```json\s*(.*?)```", text, re.S)
    for blk in reversed(m):
        try:
            import json
            return json.loads(blk.strip())
        except Exception:
            continue
    # 最外层花括号
    s = text.find("{")
    e = text.rfind("}")
    if s >= 0 and e > s:
        try:
            import json
            return json.loads(text[s:e + 1])
        except Exception:
            return None
    return None
