"""服务端漏洞 finding 结构化核验门 (debug: DVS_VULN_VERIFIER_ENABLED).

在 vuln-miner fork 产出 finding 之后、提交 vuln-platform intake 之前, 对每条
finding 做确定性结构化核验, 杀掉 LLM 常见的几类假象 (引用不存在的行/调用点、
臆断 callee 内部行为、虚构调用链边、未读 callee 源码就断言行为)。

设计原则 (fail-safe, 不误杀真漏洞):
- 只在出现 **正向假象证据** 时才判 FAIL (例如: 引用行号超过文件总行数; vuln
  函数体里根本没有该 callee 的 CallExpr; finding 声称 callee "内部 realloc 扩容"
  但该 callee 函数体里既无 realloc 也无 reallocarray; trigger_path 里某条调用边
  在 clang call-graph 里不存在)。
- libclang 不可用 / 解析失败 → 该检查记为 "skipped", **不**阻断 finding。只有
  不依赖 clang 的检查 (行存在性 V1、session 工具调用审计 V5) 始终执行。
- 默认 OFF (env DVS_VULN_VERIFIER_ENABLED 未置真)。OFF 时本模块不被调用, 行为与
  主线完全一致。

核验项:
  V1 line_exists        引用行号 ≤ 文件总行数            (无 clang)
  V2 callsite_exists    vuln 函数确有调用声称的 sink/callee (clang)
  V3 callee_behavior    callee 行为断言与真实函数体一致      (clang)
  V4 reachability       trigger_path 调用边在 call-graph 里存在 (clang)
  V5 session_read_audit finding 引用的 callee 在 fork session 里被实际读取过 (无 clang)
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .clang_analyzer import (
    callee_body_contains_token,
    function_calls_callee,
    get_function_callees,
)


def is_enabled() -> bool:
    """Debug switch for the server-side vuln verifier. Default OFF."""
    return str(os.environ.get("DVS_VULN_VERIFIER_ENABLED", "")).strip().lower() in {"1", "true", "yes", "on"}


# ── 解析辅助 ────────────────────────────────────────────────────────────────

_LINE_RE = re.compile(r"L?(\d{1,7})")


def _parse_line(raw: str | None) -> int | None:
    """Extract an integer line number from a value like 'L588', '588', 'L588-590'."""
    if not raw:
        return None
    m = _LINE_RE.search(str(raw))
    return int(m.group(1)) if m else None


def _file_line_count(source_root: str, rel_file: str) -> int | None:
    """Number of lines in source_root/rel_file, or None if unreadable."""
    if not rel_file:
        return None
    p = Path(source_root) / rel_file
    try:
        return len(p.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return None


def _resolve_finding_file(item: dict, fallback: str) -> str:
    return str(item.get("source_file") or item.get("file") or fallback or "")


# ── 行为断言 → 必须出现的源码 token (V3) ──────────────────────────────────
# finding 文本里若对某 callee 出现这些 "行为关键词", 则该 callee 函数体里必须能
# 找到对应 token 之一; 找不到 → 臆断 → FAIL。保守映射, 只覆盖已知高频假象。
_BEHAVIOR_CLAIMS: list[tuple[list[str], list[str]]] = [
    (["realloc", "扩容", "扩展缓冲区", "动态扩", "resize"], ["realloc", "reallocarray"]),
    (["malloc", "分配新", "新分配", "重新分配", "动态分配"], ["malloc", "calloc", "realloc", "strdup", "asprintf", "g_malloc", "kmalloc"]),
    (["memcpy", "memmove", "拷贝数据", "复制数据", "copy into"], ["memcpy", "memmove", "strcpy", "strncpy", "snprintf", "strlcpy", "g_strlcpy"]),
]

# 函数名候选 token 正则: C 标识符后跟 (  —— 粗筛 finding 文本里出现的"被调用函数名"
_FUNC_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _extract_callee_claims(finding_text: str, own_func: str) -> list[tuple[str, list[str]]]:
    """From the finding's free text, return [(callee_name, [claim_keywords])].

    A callee is any `ident(` token in the text that is not the vuln function
    itself and not a common C builtin/control keyword. claim_keywords are the
    behavior keywords co-occurring in a window around the callee mention.
    """
    BUILTINS = {
        "if", "for", "while", "switch", "return", "sizeof", "typeof",
        "memcpy", "memmove", "memset", "strcpy", "strncpy", "snprintf",
        "strlen", "strcmp", "strncmp", "malloc", "calloc", "realloc", "free",
        "printf", "fprintf", "sprintf", "exit", "abort",
    }
    callees: dict[str, set[str]] = {}
    for m in _FUNC_CALL_RE.finditer(finding_text):
        nm = m.group(1)
        if nm == own_func or nm in BUILTINS:
            continue
        window = finding_text[max(0, m.start() - 80): m.end() + 80]
        claims: set[str] = set()
        for kws, _toks in _BEHAVIOR_CLAIMS:
            for kw in kws:
                if kw.lower() in window.lower():
                    claims.add(kw)
                    break
        callees.setdefault(nm, set()).update(claims)
    return [(nm, sorted(cs)) for nm, cs in callees.items() if cs]


# ── session 工具调用审计 (V5) ───────────────────────────────────────────────
# 扫 fork_session.jsonl, 收集 miner 实际用 extract_func/read/grep 读过哪些函数名。
# finding 若对某 callee 做了行为断言但 session 里从未读取该 callee → 臆断 → FAIL。


def _audit_session_reads(fork_session_path: str) -> set[str]:
    """Return the set of function-name-like strings the miner actually read."""
    read_names: set[str] = set()
    p = Path(fork_session_path)
    if not p.is_file():
        return read_names
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            # 通用约定: tool_use 事件名可能是 tool_use / function_call / tool_call
            role = ev.get("role") or ev.get("type") or ""
            name = ev.get("name") or (ev.get("tool") or {}).get("name") or ev.get("tool_name") or ""
            content = ev.get("content") or ev.get("input") or ev.get("arguments") or ""
            if name not in ("extract_func", "read", "grep", "rg", "bash", "cat", "sed"):
                continue
            blob = json.dumps(content, ensure_ascii=False) if not isinstance(content, str) else content
            # 抓取被读取内容里出现的函数名候选 (extract_func 的参数 / read 的路径+正文里的 ident()
            for m in _FUNC_CALL_RE.finditer(blob):
                read_names.add(m.group(1))
            # extract_func 常以参数形式传函数名 (无括号): 抓 "function":"xxx" / "name":"xxx"
            for m in re.finditer(r'["\'](?:function|func|name|symbol|target)["\']\s*[:=]\s*["\']([A-Za-z_][A-Za-z0-9_]*)["\']', blob):
                read_names.add(m.group(1))
    except OSError:
        pass
    return read_names


# ── 主核验入口 ──────────────────────────────────────────────────────────────


def verify_finding(
    finding_rec: Any,
    item: dict,
    source_root: str,
    cache_dir: str | Path | None,
    fork_session_path: str,
) -> dict:
    """Verify one finding structurally. Returns:

        {passed: bool, reasons: [str], checks: {v1..v5: {status, detail}}}

    status ∈ {"pass", "fail", "skipped"}. passed=False 只在至少一项 fail 时。
    """
    checks: dict[str, dict] = {}
    reasons: list[str] = []

    src_file = _resolve_finding_file(item, getattr(finding_rec, "source_file", "") or "")
    func_name = str(item.get("function_name") or item.get("function") or getattr(finding_rec, "function_name", "") or "")
    claimed_line = _parse_line(str(item.get("line") or item.get("line_hint") or item.get("vuln_line") or ""))
    finding_text = "\n".join([
        str(item.get("summary") or ""),
        str(item.get("evidence") or ""),
        str(item.get("trigger_path") or ""),
        str(item.get("entry_point") or ""),
        str(item.get("title") or ""),
    ])

    # ── V1 行存在性 (无 clang, 始终执行) ──
    total = _file_line_count(source_root, src_file)
    if total is not None and claimed_line is not None:
        if claimed_line > total:
            checks["v1_line_exists"] = {"status": "fail",
                                        "detail": f"引用行 {claimed_line} 超过文件总行数 {total} ({src_file})"}
            reasons.append(f"v1_line_exists: 引用行 {claimed_line} 超出文件 {src_file} 总行数 {total}")
        else:
            checks["v1_line_exists"] = {"status": "pass", "detail": f"行 {claimed_line} ≤ 总行 {total}"}
    else:
        checks["v1_line_exists"] = {"status": "skipped", "detail": "无法读取文件或解析行号"}

    # ── V2 sink/callee 调用存在 (clang) ──
    # finding 文本里出现的非内置 callee 中, 若 vuln 函数体根本没调用它 → 幽灵 callee
    own_func = func_name
    cited_callees = [c for c, _ in _extract_callee_claims(finding_text, own_func)]
    v2_detail = ""
    if cited_callees:
        phantom = []
        unverifiable = False
        for cn in cited_callees:
            res = function_calls_callee(source_root, src_file, own_func, cn)
            if res is None:
                unverifiable = True
            elif res is False:
                phantom.append(cn)
        if phantom:
            checks["v2_callsite_exists"] = {"status": "fail",
                                            "detail": f"vuln 函数 {own_func} 未调用声称的 callee: {phantom}"}
            reasons.append(f"v2_callsite_exists: {own_func} 未调用 {phantom}")
        elif unverifiable:
            checks["v2_callsite_exists"] = {"status": "skipped", "detail": "libclang 不可用/解析失败"}
        else:
            v2_detail = f"声称的 callee {cited_callees} 均在 {own_func} 调用图内"
            checks["v2_callsite_exists"] = {"status": "pass", "detail": v2_detail}
    else:
        checks["v2_callsite_exists"] = {"status": "skipped", "detail": "finding 未引用具名 callee"}

    # ── V3 callee 行为引用一致性 (clang) ──
    callee_claims = _extract_callee_claims(finding_text, own_func)
    v3_fail: list[str] = []
    v3_skipped = False
    for cn, kws in callee_claims:
        for kw in kws:
            required_tokens = next((toks for kws2, toks in _BEHAVIOR_CLAIMS if kw in kws2), None)
            if not required_tokens:
                continue
            # 在 callee 的真实函数体里逐 token 查找 (callee 可能跨文件, 这里用 src_file 兜底)
            found_any = False
            tried = False
            for cand_file in {src_file, str(item.get("source_file") or "")}:
                if not cand_file:
                    continue
                for tok in required_tokens:
                    res = callee_body_contains_token(source_root, cand_file, cn, tok)
                    if res is True:
                        found_any = True
                        break
                    if res is None:
                        v3_skipped = True
                    else:
                        tried = True
                if found_any:
                    break
            if not found_any and tried:
                v3_fail.append(f"声称 {cn} '{kw}' 但其函数体无 {required_tokens}")
    if v3_fail:
        checks["v3_callee_behavior"] = {"status": "fail", "detail": "; ".join(v3_fail)}
        reasons.append(f"v3_callee_behavior: " + "; ".join(v3_fail))
    elif v3_skipped and not v3_fail:
        checks["v3_callee_behavior"] = {"status": "skipped", "detail": "libclang 不可用/无法定位 callee 函数体"}
    else:
        checks["v3_callee_behavior"] = {"status": "pass" if callee_claims else "skipped",
                                        "detail": "行为断言与 callee 源码一致" if callee_claims else "无行为断言"}

    # ── V4 调用链可达性 (clang) ──
    # trigger_path / entry_point 里出现的具名 callee, 应在 vuln 函数调用图内 (与 V2 复用)
    # 这里额外检查: 若 finding 同时声称 A 调用 B (跨函数边), 则 A 的调用图里应有 B。
    chain_text = str(item.get("trigger_path") or "") + "\n" + str(item.get("entry_point") or "")
    chain_tokens = [m.group(1) for m in _FUNC_CALL_RE.finditer(chain_text)
                    if m.group(1) != own_func and m.group(1) not in {"memcpy", "memmove", "memset", "malloc", "free", "strlen", "strcpy", "strncpy", "snprintf", "printf", "sizeof"}]
    if chain_tokens:
        edges = get_function_callees(source_root, src_file, own_func)
        if edges is None:
            checks["v4_reachability"] = {"status": "skipped", "detail": "libclang 不可用/解析失败"}
        else:
            called = {c.get("name") for c in edges}
            # 仅当某 token 既出现在 trigger_path 又被 finding 当作中间节点但不在调用图 → fail
            # 保守: 只判 "完全不在调用图且不在 V2 已处理集合" 的, 避免重复
            missing = [t for t in dict.fromkeys(chain_tokens) if t not in called and t not in cited_callees]
            if missing:
                checks["v4_reachability"] = {"status": "fail",
                                             "detail": f"调用链节点 {missing} 不在 {own_func} 调用图内"}
                reasons.append(f"v4_reachability: {missing} 不在 {own_func} 调用图内")
            else:
                checks["v4_reachability"] = {"status": "pass", "detail": "调用链节点均在调用图内"}
    else:
        checks["v4_reachability"] = {"status": "skipped", "detail": "trigger_path 无具名中间节点"}

    # ── V5 session 工具调用审计 (无 clang) ──
    read_set = _audit_session_reads(fork_session_path)
    if callee_claims and read_set:
        not_read = [cn for cn, _ in callee_claims if cn not in read_set]
        if not_read:
            checks["v5_session_read_audit"] = {"status": "fail",
                                                "detail": f"finding 对 {not_read} 做了行为断言但 fork session 从未读取其源码"}
            reasons.append(f"v5_session_read_audit: {not_read} 未在 session 中被读取")
        else:
            checks["v5_session_read_audit"] = {"status": "pass", "detail": "被断言的 callee 均在 session 中读取过"}
    else:
        checks["v5_session_read_audit"] = {"status": "skipped", "detail": "无行为断言或 session 不可读"}

    passed = not any(v["status"] == "fail" for v in checks.values())
    return {"passed": passed, "reasons": reasons, "checks": checks}
