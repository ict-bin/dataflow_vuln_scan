"""共享的漏洞报告工具 (v1 vuln_workflow 与 v2 dataflow_v2 共用)。

抽出这些 helper 是为了让 v2 不依赖 v1 专属的 vuln_workflow 模块 —— 后续完全
剥离 v1 时, 删除 vuln_workflow/orchestrator/taint_workflow 等, 本模块 + v2 保留。
"""
from __future__ import annotations

import hashlib
import json
import logging
import re

logger = logging.getLogger("dvs.vuln_report_utils")
from pathlib import Path
from typing import Any


def read_prompt(path: str) -> str:
    """读取仓库内提示词文件 (相对 app/ 目录)。"""
    try:
        return (Path(__file__).resolve().parents[1] / path).read_text(encoding="utf-8")
    except OSError as e:
        logger.debug("read report template failed (path=%s): %s", path, e)
        return ""


def safe_name(value: str, *, max_len: int = 96) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-") or "item"
    if len(safe) <= max_len:
        return safe
    return f"{safe[:max_len - 9]}-{hashlib.sha1(value.encode()).hexdigest()[:8]}"


def _flow(text: Any) -> str:
    """把 LLM 输出规整成多行, 保证 .md 可读。

    - 拆 `→` 串联的步骤为独立行
    - 把 `步骤N:` / `行 N:` 提到行首 (若被 `→` 黏在一起)
    - 多余空行收敛
    """
    if not text:
        return ""
    s = str(text)
    s = s.replace("→", "\n")
    # 把 `步骤N:` / `行 N:` 提到行首: 仅当它被粘连在非空白字符后 (如 `a步骤2`/`foo行123`) 才拆,
    # 不破坏 `- 行 N:` 项目符号行 (行前是空格) 和已在行首 (行前是\n) 的情况。
    s = re.sub(r'(?<=[^\n\s])(步骤\d+[:：])', r'\n\1', s)
    s = re.sub(r'(?<=[^\n\s])(行\s*\d+[:：])', r'\n\1', s)
    s = re.sub(r'\n{3,}', '\n\n', s)
    return s.strip()


def format_exploitability_md(value: Any) -> str:
    """Render the exploitability field as Markdown (struct or legacy string)."""
    if not value:
        return "未知"
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        pre = str(value.get("preconditions") or value.get("precondition") or "").strip()
        tc = str(value.get("trigger_complexity") or "").strip()
        wci = str(value.get("worst_case_impact") or value.get("impact") or "").strip()
        parts: list[str] = []
        if pre:
            parts.append(f"- **前置条件**: {pre}")
        if tc:
            parts.append(f"- **触发难度**: {tc}")
        if wci:
            parts.append(f"- **最坏后果**: {wci}")
        return "\n".join(parts) if parts else json.dumps(value, ensure_ascii=False, indent=2)
    return json.dumps(value, ensure_ascii=False, indent=2)


_DIM_LABEL = {
    "code_accurate": "代码准确性",
    "path_reachable": "路径可达性",
    "unmitigated": "防御可绕过",
    "security_impact": "实质安全影响",
}


def format_dimensions_md(value: Any) -> str:
    """Render the four-dimension self-check as Markdown ("" when absent)."""
    if not isinstance(value, dict) or not value:
        return ""
    lines: list[str] = ["## 四维度自检", ""]
    rows = []
    for key, label in _DIM_LABEL.items():
        entry = value.get(key)
        if isinstance(entry, dict):
            passed = entry.get("passed")
            if passed is True:
                status = "PASS"
            elif passed is False:
                status = "FAIL"
            else:
                status = "N/A"
            reason = str(entry.get("reason") or entry.get("detail") or "").strip()
        else:
            status = "➖ 未判定"
            reason = str(entry or "").strip()
        rows.append(f"| {label} | {status} | {reason} |")
    if rows:
        lines.append("| 维度 | 结论 | 理由 |")
        lines.append("|------|------|------|")
        lines.extend(rows)
        lines.append("")
        return "\n".join(lines)
    return ""


def format_vuln_report_md(item: dict, finding_id: str, source_file: str,
                          function_name: str, line: str,
                          taint_context: str = "") -> str:
    """Build vulnerability-report.md body.

    - 空字段省略段 (不再印“未提供”): 只渲染 LLM 实际产出的段。
    - 污点传播路径合并为一段 (taint_context), 不再单独写 taint-path-report.md。
    """
    title = str(item.get("title") or finding_id)
    summary = str(item.get("summary") or "")
    entry_point = str(item.get("entry_point") or "")
    trigger_path = str(item.get("trigger_path") or "")
    evidence = str(item.get("evidence") or "")
    vuln_type = str(item.get("vuln_type") or "unknown")
    severity = str(item.get("severity") or "unknown")
    confidence = item.get("confidence")
    code_snippet = str(item.get("code_snippet") or "").strip()
    code_explanation = str(item.get("code_explanation") or "").strip()
    fix_suggestion = str(item.get("fix_suggestion") or "").strip()
    poc = str(item.get("poc") or "").strip()
    taint_ctx = str(taint_context or "").strip()
    sections: list[str] = [f"# {title}", ""]
    if _flow(entry_point):
        sections += ["## 漏洞最初入口", _flow(entry_point), ""]
    sections += ["## 漏洞所在文件", f"`{source_file}`", "",
                 "## 漏洞所在函数", f"`{function_name}`", "",
                 "## 漏洞所在行号", f"`{line or 'unknown'}`", ""]
    if code_snippet:
        sections += ["## 漏洞源码", f"```c\n{code_snippet}\n```", ""]
    if _flow(summary):
        sections += ["## 漏洞概述", _flow(summary), ""]
    if _flow(code_explanation):
        sections += ["## 漏洞结合代码说明", _flow(code_explanation), ""]
    if _flow(evidence):
        sections += ["## 漏洞判断依据", _flow(evidence), ""]
    if _flow(trigger_path):
        sections += ["## 漏洞触发路径", _flow(trigger_path), ""]
    if taint_ctx:
        sections += ["## 污点传播路径", taint_ctx, ""]
    expl_md = format_exploitability_md(item.get("exploitability"))
    if expl_md:
        sections += ["## 漏洞危害", expl_md, ""]
    if _flow(fix_suggestion):
        sections += ["## 修复建议", _flow(fix_suggestion), ""]
    if poc:
        sections += ["## POC（仅供参考）",
                     "> 以下 POC 仅为参考骨架，不可直接运行；实际可用的利用脚本由专门的 POC 生成微服务产出。",
                     poc, ""]
    sections += ["## 漏洞基本信息",
                 f"- **漏洞类型**: `{vuln_type}`",
                 f"- **严重程度**: `{severity}`",
                 f"- **置信度**: `{confidence}`"]
    dim_md = format_dimensions_md(item.get("dimensions"))
    if dim_md:
        sections.append("")
        sections.append("## 四维度判断指标")
        sections.append(dim_md.replace("## 四维度自检", "", 1).strip())
    # 不再插 --- 章节分隔符: 漏洞中心前端用 /\n*---\s*\n[\s\S]*$/ 正则剥脚注,
    # 报告正文若含 --- 会被从首个 --- 贪婪删到结尾 (只剩元数据头+#标题), 故仅靠 ## 标题分章
    return "\n".join(sections) + "\n"


# 内嵌技能文本 (v1 vuln_workflow 与 v2 mine_vulns 共用)
EMBEDDED_VULN_MINING_SKILL = read_prompt("skills/mine-dataflow-vulnerability/SKILL.md")

# V2 数据库使用技能 (所有 v2 LLM 共用, 提前注入 system prompt 减少轮次)
EMBEDDED_V2_DB_SKILL = read_prompt("skills/v2/v2-database/SKILL.md")

# V2 定制技能 (per-LLM, 按需注入)
_V2_CUSTOM_SKILLS = {
    "taint-analysis": read_prompt("skills/v2/custom/taint-analysis.md"),
    "vuln-mining": read_prompt("skills/v2/custom/vuln-mining.md"),
    "tracker": read_prompt("skills/v2/custom/tracker.md"),
}


def build_v2_system_prompt(custom: str | None = None) -> str:
    """构建 V2 LLM 的 system prompt: 通用 DB 技能 + 可选定制定技能。

    Args:
        custom: 定制技能名 (taint-analysis/vuln-mining/tracker), None=不加定制。
    Returns:
        拼接好的 system prompt 片段 (嵌入 DB 技能 + 定制技能)。
    """
    parts = []
    if EMBEDDED_V2_DB_SKILL:
        parts.append(f"# 内嵌技能：v2-database\n"
                     f"以下技能已完整嵌入, 禁止再通过 read/bash 加载 SKILL.md。\n\n"
                     f"{EMBEDDED_V2_DB_SKILL}")
    if custom and custom in _V2_CUSTOM_SKILLS and _V2_CUSTOM_SKILLS[custom]:
        parts.append(f"# 定制技能：{custom}\n\n{_V2_CUSTOM_SKILLS[custom]}")
    return "\n\n".join(parts)
