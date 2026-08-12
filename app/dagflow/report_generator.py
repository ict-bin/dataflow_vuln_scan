"""Phase 3: 报告生成 (LLM Step 2, 复用 V2 SKILL)。

给定确认的 candidates + 完整链 + 源码, LLM 生成完整漏洞报告。
复用 V2 的 mine-dataflow-vulnerability SKILL 约束输出字段。
"""
from __future__ import annotations
import json, logging, time
from pathlib import Path
from typing import Any

from .models import Finding, Dimension

logger = logging.getLogger("dvs.dagflow.report_generator")

_PROMPT_PATH = Path(__file__).resolve().parent.parent.parent / "prompts" / "dagflow" / "vuln-report.md"


def _task_pi_dir(config: Any, role: str) -> str:
    resolver = getattr(config, "role_pi_dir", None)
    return str(resolver(role) or "") if callable(resolver) else ""


def _system_prompt() -> str:
    """系统提示: 内嵌 V2 SKILL (mine-dataflow-vulnerability)。"""
    from ..vuln_report_utils import (
        ATHENA_DATAFLOW_VULN_SKILL_GUIDANCE,
        EMBEDDED_VULN_MINING_SKILL,
        build_v2_system_prompt,
        with_athena_report_env,
    )
    return (
        build_v2_system_prompt(custom="vuln-mining")
        + "\n\n# 内嵌技能：mine-dataflow-vulnerability\n"
          "禁止再读取 skills/mine-dataflow-vulnerability/SKILL.md。\n\n"
        + EMBEDDED_VULN_MINING_SKILL
        + "\n\n"
        + ATHENA_DATAFLOW_VULN_SKILL_GUIDANCE
    )


class ReportGenerator:
    """Step 2: 为确认候选生成完整漏洞报告。"""

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

    def generate(self, candidates: list[dict], chain: dict,
                 func: Any, source: str,
                 session_path: str = "") -> list[Finding]:
        """返回 findings (含全部 V2 字段)。"""
        if self._acfg is None or not candidates:
            return []
        _t0 = time.time()
        prompt = self._build_prompt(candidates, chain, func, source)
        from ..llm_retry import run_agent_with_design_retry
        from ..parsers import _extract_json_object
        v2_env = with_athena_report_env(
            {"DVS_SOURCE_ROOT": str(self.source_root),
             "DVS_V2_DB_DIR": str(self.sessions_dir.parent / "dataflow-v2")},
            str(getattr(self.config, "project_id", "") or ""),
        )
        logger.info("[dagflow-report] CALLING run_agent func=%s candidates=%d session=%s",
                    func.name, len(candidates), session_path[-60:])

        def _parse_check(res, all_texts):
            text = getattr(res, "output", "") or ""
            p = _extract_json_object(text, "findings")
            if not isinstance(p, dict) or not isinstance(p.get("findings"), list):
                return None, "dagflow report JSON parse failed"
            return p, ""

        # 用同一个 session (继承 Step 1 的上下文)
        sp = str(Path(session_path).with_name(Path(session_path).stem + "-report.jsonl")) \
            if session_path else str(self.sessions_dir / f"{func.name}-report.jsonl")

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
                          "task_pi_dir": _task_pi_dir(self.config, "workers"),
                          "agent_role": "workers", "fork_purpose": "vuln_report"},
            parse_check=_parse_check,
            rollback_session=None,
            error_session_fn=lambda n: str(Path(sp).with_name(Path(sp).stem + f"-err{n}.jsonl")),
            on_event=self.on_event,
            label=f"dagflow-report/{func.name}", retry_max=3,
        )
        if parsed is None:
            parsed = {"findings": []}
        findings = self._parse_findings(parsed)
        logger.info("[dagflow-report] DONE func=%s duration=%.1fs findings=%d error=%s",
                    func.name, time.time() - _t0, len(findings), (output.error or "")[:100])
        return findings

    def _build_prompt(self, candidates: list[dict], chain: dict,
                      func: Any, source: str) -> str:
        chain_json = json.dumps(chain, ensure_ascii=False, indent=2)
        if len(chain_json) > 20000:
            chain_json = chain_json[:20000] + "\n... (截断)"
        cand_json = json.dumps(candidates, ensure_ascii=False, indent=2)
        return (
            "# 阶段：漏洞报告生成 (Step 2)\n\n"
            "第一步已确认候选漏洞。请对每个候选产出**完整漏洞报告 JSON** (findings[]), "
            "包含全部字段 (vuln_type/severity/title/summary/source_file/function_name/line/"
            "entry_point/trigger_path/evidence/code_snippet/code_explanation/fix_suggestion/poc/"
            "exploitability/dimensions/confidence)。\n"
            "**必须把下方污点传播上下文合理合并进报告**: "
            "trigger_path/entry_point/evidence/code_snippet 引用链中的真实行号与传播边, 不得凭空编造。\n\n"
            f"## 第一步确认的候选\n```json\n{cand_json}\n```\n\n"
            f"## 完整跨函数调用链 (污点传播上下文)\n```json\n{chain_json}\n```\n\n"
            f"## 本函数源码\n```c\n{source}\n```\n\n"
            '输出 JSON: {"findings":[]}。'
        )

    def _parse_findings(self, parsed: dict) -> list[Finding]:
        out: list[Finding] = []
        for item in (parsed.get("findings") or []):
            if not isinstance(item, dict):
                continue
            loc = item.get("location") or {}
            dims_raw = item.get("dimensions") or {}
            dims = {k: Dimension(pass_=bool(v.get("pass", False)) if isinstance(v, dict) else False,
                                 reason=str(v.get("reason", "")) if isinstance(v, dict) else str(v))
                    for k, v in dims_raw.items()}
            out.append(Finding(
                vuln_type=str(item.get("vuln_type", "unknown")),
                severity=str(item.get("severity", "unknown")),
                title=str(item.get("title", "")),
                summary=str(item.get("summary", "")),
                entry_point=str(item.get("entry_point", "")),
                trigger_path=str(item.get("trigger_path", "")),
                evidence=str(item.get("evidence", "")),
                source_file=str(item.get("source_file", "")),
                function_name=str(item.get("function_name", "")),
                line=str(item.get("line", "")),
                code_snippet=str(item.get("code_snippet", "")),
                code_explanation=str(item.get("code_explanation", "")),
                fix_suggestion=str(item.get("fix_suggestion", "")),
                poc=str(item.get("poc", "")),
                location_func=str(loc.get("function", "")),
                location_line=str(loc.get("line", "")),
                dag_path=list(item.get("dag_path") or []),
                exploitability=item.get("exploitability") or {},
                dimensions=dims,
                confidence=float(item.get("confidence", 0) or 0)))
        return out
