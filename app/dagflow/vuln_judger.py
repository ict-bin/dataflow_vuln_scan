"""Phase 2: 漏洞判断 (LLM Step 1)。

给定完整跨函数链 + 源码, LLM 判断 D1-D4, 只输出候选 candidates。
不生成完整报告 — 报告由 Phase 3 (report_generator) 负责。
"""
from __future__ import annotations
import json, logging, time
from pathlib import Path
from typing import Any

logger = logging.getLogger("dvs.dagflow.vuln_judger")

_PROMPT_PATH = Path(__file__).resolve().parent.parent.parent / "prompts" / "dagflow" / "vuln-judge.md"


def _task_pi_dir(config: Any, role: str) -> str:
    resolver = getattr(config, "role_pi_dir", None)
    return str(resolver(role) or "") if callable(resolver) else ""


def _system_prompt() -> str:
    return _PROMPT_PATH.read_text(encoding="utf-8") if _PROMPT_PATH.exists() else ""


class VulnJudger:
    """Step 1: 判断链上是否存在真实漏洞, 输出候选列表。"""

    def __init__(self, *, config: Any, sessions_dir: Path,
                 on_event: Any = None, task_id: str = "",
                 source_root: str = "") -> None:
        self.config = config
        self.sessions_dir = Path(sessions_dir)
        self.on_event = on_event
        self.task_id = task_id
        self.source_root = source_root
        self._acfg = (config.workers.agents[0] if config.workers.agents else None)
        self._default_tools = getattr(config.workers, "default_tools", None)

    def judge(self, chain: dict, func: Any, source: str,
              session_path: str = "") -> list[dict]:
        """返回 candidates: [{vuln_type, severity, line, reason, dimensions}]"""
        if self._acfg is None:
            return []
        _t0 = time.time()
        prompt = self._build_prompt(chain, func, source)
        from ..llm_retry import run_agent_with_design_retry
        from ..parsers import _extract_json_object
        v2_env = {"DVS_SOURCE_ROOT": str(self.source_root),
                  "DVS_V2_DB_DIR": str(self.sessions_dir.parent / "dataflow-v2")}
        logger.info("[dagflow-judge] CALLING run_agent func=%s session=%s",
                    func.name, session_path[-60:])

        def _parse_check(res, all_texts):
            text = getattr(res, "output", "") or ""
            p = _extract_json_object(text, "candidates")
            if not isinstance(p, dict) or not isinstance(p.get("candidates"), list):
                return None, "dagflow judge JSON parse failed"
            return p, ""

        output, parsed, _warn = run_agent_with_design_retry(
            prompt, model=self._acfg.model,
            tools=self._acfg.tools or self._default_tools or [],
            cwd=str(self.source_root), env=v2_env, session_file=session_path,
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
                          "task_pi_dir": _task_pi_dir(self.config, "workers"),
                          "agent_role": "workers", "fork_purpose": "vuln_judge"},
            parse_check=_parse_check,
            rollback_session=None,
            error_session_fn=lambda n: str(Path(session_path).with_name(Path(session_path).stem + f"-judge-err{n}.jsonl")),
            on_event=self.on_event,
            label=f"dagflow-judge/{func.name}", retry_max=3,
        )
        if parsed is None:
            parsed = {"candidates": []}
        candidates = [c for c in (parsed.get("candidates") or []) if isinstance(c, dict)]
        logger.info("[dagflow-judge] DONE func=%s duration=%.1fs candidates=%d error=%s",
                    func.name, time.time() - _t0, len(candidates), (output.error or "")[:100])
        if self.on_event:
            try:
                self.on_event("v2_dagflow_judged", function=func.name,
                              candidates=len(candidates), task_id=self.task_id)
            except Exception:
                pass
        return candidates

    def _build_prompt(self, chain: dict, func: Any, source: str) -> str:
        chain_json = json.dumps(chain, ensure_ascii=False, indent=2)
        # 截断超长链
        if len(chain_json) > 20000:
            chain_json = chain_json[:20000] + "\n... (截断)"
        return (
            f"# 阶段：漏洞判断 (Step 1)\n\n"
            f"目标函数: `{func.file}::{func.name}` (行 {func.start_line}-{func.end_line})\n"
            f"源码绝对根目录: `{self.source_root}`。\n\n"
            f"## 完整跨函数调用链 (从入口到 sink, 含 checks/conditions/sub_chain)\n"
            f"```json\n{chain_json}\n```\n\n"
            f"## 本函数源码\n```c\n{source}\n```\n\n"
            f"沿链找真实可利用漏洞。默认非漏洞, 找反证。四维度 D1-D4 全过才输出候选。\n"
            f"只输出候选, 不写完整报告字段 (报告在 Step 2 生成)。\n"
            f'输出 JSON: {{"candidates":[{{"vuln_type":"","severity":"","line":"","reason":"","dimensions":{{"D1":{{"pass":true,"reason":""}}}}}}]}}。无候选输出 {{"candidates":[]}}。'
        )
