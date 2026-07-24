"""dagflow taint 分析器: LLM 产 DAG (行号引用) + JSON 解析 + 后处理补全。

设计: docs/design-taint-analysis.md §3 (行号为桥梁)。
LLM 读带行号的函数体 → 输出 DAG (含行号) → line_filler 后处理补全 condition/checks/param_taints。
独立会话 (func-taint, 不 fork 调用链)。复用 run_agent + _extract_json_object。
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


def _numbered_body(body: str, start_line: int) -> str:
    """给函数体每行加行号前缀。

    格式: `  765│ code...`
    start_line 是第一行对应的文件行号。
    """
    lines = body.splitlines()
    result = []
    for i, line in enumerate(lines):
        ln = start_line + i
        result.append(f"{ln:>5}│ {line}")
    return "\n".join(result)


class TaintAnalyzer:
    """单函数单污点 DAG 分析 (LLM 输出行号, 脚本后处理)。"""

    def __init__(self, *, config: Any, sessions_dir: Path, on_event: Any = None,
                 task_id: str = "", func_lookup=None,
                 graph_recorder: Any = None) -> None:
        self.config = config
        self.sessions_dir = Path(sessions_dir)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.on_event = on_event
        self.task_id = task_id
        self.func_lookup = func_lookup
        self.graph_recorder = graph_recorder
        self.source_root = getattr(config, "cwd", "") or getattr(config, "source_root", "")
        self._acfg = (config.workers.agents[0] if config.workers.agents else None)
        self._default_tools = getattr(config.workers, "default_tools", None)

    def _build_prompt(self, func, body: str, taint_sig: str, is_auto: bool) -> tuple[str, str]:
        """返回 (prompt, session_path)。函数体带行号。"""
        numbered = _numbered_body(body, func.start_line)
        taint_desc = ("自行分析（未指定具体污点参数）。识别本函数内所有外部输入源（入参/内部调用产物/被动传递），"
                      "每个源作为 source 节点起 DAG。") if is_auto else \
                     f"入口污点签名: {taint_sig}（从该污点起跟踪传播）"
        prompt = (
            f"# 阶段：单函数污点传播 DAG 分析\n\n"
            f"目标函数: `{func.file}::{func.name}` (行 {func.start_line}-{func.end_line})\n"
            f"源码绝对根目录: `{self.source_root}`。`{func.file}` 是相对该根目录的源码路径；如果需要使用 read/find 读取源码，请基于这个绝对根目录定位文件，不要基于当前工作目录拼接路径。\n"
            f"{taint_desc}\n\n"
            f"## 函数体 (行号已标记)\n```\n{numbered}\n```\n\n"
            f"按系统提示词要求输出 DAG JSON（顶层唯一一个 ```json 块，最后输出）。"
        )
        from .session_naming import session_path
        sp = str(session_path(self.sessions_dir, func.name, taint_sig or "auto",
                              kind="taint", depth=getattr(self, "_cur_depth", 0)))
        return prompt, sp

    def analyze(self, func, taint_sig: str, is_auto: bool = False) -> tuple[TaintDAG, str]:
        """分析 (func, taint) → (DAG 含后处理, session_path)。失败 raise (调用方删占位)。"""
        if self._acfg is None:
            raise RuntimeError("no agent configured for dagflow taint_analyzer")
        from ..dataflow_v2.function_extractor import read_function_body
        from ..llm_retry import run_agent_with_design_retry
        from ..parsers import _extract_json_object
        from .line_filler import fill_lines
        import time as _time
        _t0 = _time.time()
        body = read_function_body(self.source_root, func, max_lines=0)
        prompt, sp = self._build_prompt(func, body, taint_sig, is_auto)
        v2_env = {"DVS_SOURCE_ROOT": str(self.source_root),
                  "DVS_V2_DB_DIR": str(self.sessions_dir.parent / "dataflow-v2")}
        logger.info("[dagflow-taint] CALLING run_agent func=%s taint=%s session=%s",
                    func.name, taint_sig, sp[-60:])
        # 记录节点 (discovered)
        if self.graph_recorder:
            self.graph_recorder.record_node(
                func_id=func.func_id, func_name=func.name, file=func.file,
                depth=getattr(self, "_cur_depth", 0), status="analyzing", analysis_status="pending")
        def _parse_check(res, all_texts):
            text = getattr(res, "output", "") or ""
            p = _extract_json_object(text, "nodes")
            if p is None:
                p = _greedy_json_object(text)
            if not isinstance(p, dict) or not isinstance(p.get("nodes"), list):
                return None, f"dagflow taint JSON parse failed for {func.name}/{taint_sig}"
            return p, ""

        output, parsed, _warn = run_agent_with_design_retry(
            prompt, model=self._acfg.model,
            tools=self._acfg.tools or self._default_tools or [],
            cwd=str(self.source_root), env=v2_env, session_file=sp,
            system_prompt=_system_prompt(),
            cancel_event=getattr(self, "cancel_event", None),
            thinking_level="off",
            run_timeout_seconds=getattr(self.config, "agent_run_timeout_seconds", 1500),
            timeout_retry_enabled=getattr(self.config, "agent_timeout_retry_enabled", True),
            timeout_max_retries=getattr(self.config, "agent_timeout_max_retries", 20),
            pi_max_retries=getattr(self.config, "pi_max_retries", 3),
            pi_retry_delay=getattr(self.config, "pi_retry_delay", 10.0),
            task_context={"task_id": self.task_id,
                          "task_root": str(self.sessions_dir.parent.parent.parent),
                          "task_run_root": str(self.sessions_dir.parent),
                          "task_pi_dir": self.config.role_pi_dir("workers"),
                          "agent_role": "workers", "fork_purpose": "taint_analysis"},
            parse_check=_parse_check,
            rollback_session=None,
            error_session_fn=lambda n: str(Path(sp).with_name(Path(sp).stem + f"-error{n}.jsonl")),
            on_event=getattr(self, "on_event", None),
            label=f"dagflow/{func.name}", retry_max=3,
        )
        if not isinstance(parsed, dict) or not isinstance(parsed.get("nodes"), list):
            raise RuntimeError(f"dagflow taint JSON parse failed for {func.name}/{taint_sig}")
        parsed["func_id"] = func.func_id
        parsed["taint_signature"] = taint_sig or "auto"
        dag = TaintDAG.from_dict(parsed)
        # 后处理: 从行号解析源码补全 condition/checks/param_taints/sink_ref
        fill_lines(dag, func, self.source_root, func_lookup=self.func_lookup)
        logger.info("[dagflow-taint] DONE func=%s taint=%s duration=%.1fs error=%s output_len=%d nodes=%d",
                    func.name, taint_sig, _time.time() - _t0, (output.error or "")[:100],
                    len(output.output or ""), len(dag.nodes))
        # 记录节点 (done) + 会话
        if self.graph_recorder:
            self.graph_recorder.record_node(
                func_id=func.func_id, func_name=func.name, file=func.file,
                depth=getattr(self, "_cur_depth", 0), status="done",
                analysis_status="done" if not dag.taint_failed else "failed")
            self.graph_recorder.record_session(
                session_path=sp, node_id=self.graph_recorder._node_id(func.func_id),
                session_role="taint", session_kind=f"d{getattr(self, '_cur_depth', 0):02d}",
                status="done")
        if self.on_event:
            try:
                self.on_event("v2_dagflow_taint_done", function=func.name, taint=taint_sig,
                              nodes=len(dag.nodes), self_contained=dag.self_contained,
                              task_id=self.task_id)
            except Exception:
                logger.warning(
                    "dagflow taint_done event emit failed func=%s taint=%s task_id=%s",
                    func.name,
                    taint_sig,
                    self.task_id,
                    exc_info=True,
                )
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
    s = text.find("{")
    e = text.rfind("}")
    if s >= 0 and e > s:
        try:
            import json
            return json.loads(text[s:e + 1])
        except Exception:
            return None
    return None
