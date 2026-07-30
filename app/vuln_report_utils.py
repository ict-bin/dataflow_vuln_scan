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
    # 把 `步骤N:` / `行 N:` 提到行首: 仅当被粘连(前面是非换行非`- `的字符)才拆;
    # 不破坏 `- 行 N:` 项目符号行(行前是 `- `) 和已在行首(行前\n)的情况。
    s = re.sub(r'(?<!\n)(?<!- )(步骤\d+[:：])', r'\n\1', s)
    s = re.sub(r'(?<!\n)(?<!- )(行\s*\d+[:：])', r'\n\1', s)
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


def _bulletize(text: Any) -> str:
    """把多行文本每行变成 - 项目符号 (已带符号/空行/代码块内不动), 便于 md 渲染分点。"""
    out: list[str] = []
    in_fence = False
    for ln in str(text or "").split("\n"):
        if ln.strip().startswith("```"):
            in_fence = not in_fence
            out.append(ln)
            continue
        if in_fence:
            out.append(ln)
            continue
        s = ln.rstrip()
        if not s:
            out.append("")
            continue
        st = s.lstrip()
        if st.startswith(("-", "*")) or re.match(r'^\d+[.):]', st):
            out.append(s)  # 已是列表项
        else:
            out.append(f"- {st}")
    return "\n".join(out)


def _split_taint_context(blob: str) -> tuple[str, str]:
    """把污点传播上下文拆成 (函数体源码代码块, 污点传播段)。
    函数体源码 = blob 里 '## 函数体源码' 下的 ```c 代码块; 污点传播段 = 其余
    (函数/校验/污点变量/传播路径/callee), 供报告末尾分两段渲染。"""
    s = str(blob or "")
    m = re.search(r'## 函数体源码[^\n]*:\n(```[a-zA-Z]*\n.*?\n```)', s, re.S)
    if not m:
        return "", s.strip()
    func_body_code = m.group(1)
    propagation = (s[:m.start()] + "\n" + s[m.end():]).strip()
    propagation = re.sub(r'\n{3,}', '\n\n', propagation)
    return func_body_code, propagation


def _restructure_taint(blob: str) -> str:
    """污点传播重组为 ### 污点变量 / ### 传播路径 / ### 前置校验 三小节;
    去掉 ### 函数/功能/入口污点 (它们在 校验提醒 之前, 被排除)。"""
    lines = (blob or "").split("\n")
    idx_check = next((i for i, l in enumerate(lines) if "校验提醒" in l), -1)
    idx_taints = next((i for i, l in enumerate(lines) if re.match(r'^##+ ', l) and "污点变量" in l), -1)
    idx_props = next((i for i, l in enumerate(lines) if re.match(r'^##+ ', l) and "传播路径" in l), -1)
    out = []
    # 污点变量
    if idx_taints >= 0:
        end = idx_props if idx_props > idx_taints else len(lines)
        out += ["### 污点变量"] + lines[idx_taints + 1:end] + [""]
    # 传播路径 (含 callee/注, 到末尾)
    if idx_props >= 0:
        out += ["### 传播路径"] + lines[idx_props + 1:] + [""]
    # 前置校验 (最后): 校验提醒 → 污点变量
    if idx_check >= 0:
        end = idx_taints if idx_taints > idx_check else len(lines)
        out += ["### 前置校验"] + lines[idx_check:end]
    return "\n".join(out).strip() if out else str(blob or "")


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
    _func_body_md, _taint_prop_md = _split_taint_context(taint_ctx)
    # 污点传播上下文里的子标题降为 ### 嵌套到 ## 污点传播路径 下, 层级更清晰
    if _taint_prop_md:
        _taint_prop_md = re.sub(r'^## ', '### ', _taint_prop_md, flags=re.M)
        _taint_prop_md = _restructure_taint(_taint_prop_md)
    sections: list[str] = [f"# {title}", ""]
    # 递进顺序: 基本信息 → 位置(表格) → 最初入口 → 可利用性及影响 → 源码 → 结合代码说明
    #           → 判断依据 → 触发路径 → 修复建议 → POC → 四维度 → 函数体源码(倒二) → 污点传播路径(最后)
    # 概述与可利用性重复, 不单列概述
    sections += ["## 漏洞基本信息",
                 f"- **漏洞类型**: `{vuln_type}`",
                 f"- **严重程度**: `{severity}`",
                 f"- **置信度**: `{confidence}`", "",
                 "## 漏洞位置",
                 "| 文件 | 函数 | 行号 |",
                 "|------|------|------|",
                 f"| `{source_file}` | `{function_name}` | `{line or 'unknown'}` |", ""]
    if _flow(entry_point):
        sections += ["## 漏洞最初入口", _flow(entry_point), ""]
    expl_md = format_exploitability_md(item.get("exploitability"))
    if expl_md:
        sections += ["## 可利用性及影响", expl_md, ""]
    if code_snippet:
        sections += ["## 漏洞源码", f"```c\n{code_snippet}\n```", ""]
    if _flow(code_explanation):
        sections += ["## 漏洞结合代码说明", _flow(code_explanation), ""]
    if _flow(evidence):
        sections += ["## 漏洞判断依据", _bulletize(_flow(evidence)), ""]
    if _flow(trigger_path):
        sections += ["## 漏洞触发路径", _bulletize(_flow(trigger_path)), ""]
    if _flow(fix_suggestion):
        sections += ["## 修复建议", _flow(fix_suggestion), ""]
    if poc:
        sections += ["## POC", poc, ""]
    dim_md = format_dimensions_md(item.get("dimensions"))
    if dim_md:
        sections += ["", "## 四维度判断指标", dim_md.replace("## 四维度自检", "", 1).strip()]
    # 函数体源码 (倒二) + 污点传播路径 (最后): 从 taint 上下文拆出
    if _func_body_md:
        sections += ["", "## 函数体源码", _func_body_md, ""]
    if _taint_prop_md:
        sections += ["", "## 污点传播路径", _taint_prop_md, ""]
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
