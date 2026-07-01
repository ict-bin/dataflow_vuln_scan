"""dataflow-v2 tracker: 脚本搜索 + LLM 语义判断 (fresh session)。

两个 tracker:
  - resolve_external: 外部变量下游使用追踪 (grep + LLM 判断, 一个函数一个 user)
  - resolve_indirect: 函数指针注册点追踪 (前后缀匹配缩小候选 + LLM 判断)

设计原则:
  - 脚本做搜索 (grep/前后缀匹配, 快)
  - LLM 做语义判断 (fresh session, 父函数信息放 prompt, 可有限探索)
  - tracker 用全新 session (不 fork 父链, 避免膨胀)
"""
from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from typing import Any, Callable

from ..runner import run_agent
from ..vuln_report_utils import safe_name
from ..parsers import _extract_json_object
from .models import FunctionRecord, TaintParamInfo, PropagationRecord
from .store import DataflowStore
from .function_extractor import ensure_file_indexed

logger = logging.getLogger("dvs.dataflow_v2.trackers")


def _grep_variable_refs(source_root: str, var_name: str, timeout: int = 15) -> list[dict]:
    """Python grep 源码树找外部变量引用点 -> [{file, line, context}]"""
    short = var_name.rsplit("->", 1)[-1].split(".")[-1]
    try:
        r = subprocess.run(
            ["grep", "-rn", "--include=*.c", "--include=*.cpp", "--include=*.cc",
             "--include=*.h", "--include=*.hpp", "-w", short, source_root],
            capture_output=True, text=True, timeout=timeout)
        hits = []
        for line in r.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            fpath, lineno, content = parts[0], parts[1], parts[2]
            try:
                rel = str(Path(fpath).relative_to(source_root).as_posix())
            except ValueError:
                continue
            hits.append({"file": rel, "line": int(lineno), "context": content.strip()})
        return hits
    except Exception:
        return []


def _hits_to_candidates(hits: list[dict], store: DataflowStore) -> list[dict]:
    """将 grep 命中点映射到所在函数 + 提取函数体 -> 候选列表"""
    candidates = []
    seen_funcs = set()
    for hit in hits:
        rec = None
        for f in store.list_functions():
            if f.file == hit["file"] and f.start_line <= hit["line"] <= f.end_line:
                rec = f
                break
        if rec is None or rec.func_id in seen_funcs:
            continue
        seen_funcs.add(rec.func_id)
        body = ""
        if rec.body_path and Path(rec.body_path).is_file():
            try:
                body = Path(rec.body_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        candidates.append({
            "function": rec.name, "file": rec.file, "line": hit["line"],
            "context": hit["context"], "body": body[:8000], "func_id": rec.func_id,
        })
    return candidates


def resolve_external(
    cfg, source_root: str, sessions_dir: Path, store: DataflowStore,
    func: FunctionRecord, taint_name: str, taint_description: str,
    cancel_event: Any = None, on_event: Callable = None,
) -> list[tuple[FunctionRecord, TaintParamInfo]]:
    """外部变量下游追踪: 脚本 grep + LLM 语义判断 (fresh session, 一个函数一个 user)"""
    acfg = cfg.workers.agents[0] if cfg.workers.agents else None
    if acfg is None:
        return []
    hits = _grep_variable_refs(source_root, taint_name)
    if not hits:
        return []
    candidates = _hits_to_candidates(hits, store)
    if not candidates:
        return []
    fork_session = sessions_dir / f"{safe_name(func.name)}-track-{safe_name(taint_name)}.jsonl"
    system_prompt = (
        "你是数据流污点分析中的非局部变量使用点追踪器。\n"
        "目标: 判断给定函数是否是外部变量的真实下游使用点。\n"
        "每个 user 消息提供一个候选函数的完整函数体和引用命中点。\n"
        "可以 read/grep 探索 (如 g_1=g_2 链), 但候选已预筛。\n"
        '只输出 JSON: {"confirmed": true/false, "reason": "..."}\n'
    )
    confirmed = []
    for cand in candidates:
        user_msg = (
            f"## 父函数: {func.file}::{func.name}\n"
            f"外部变量: `{taint_name}` ({taint_description})\n\n"
            f"## 候选函数: {cand['function']} ({cand['file']} L{cand['line']})\n"
            f"引用命中: `{cand['context']}`\n\n"
            f"## 函数体:\n```c\n{cand['body']}\n```\n\n"
            f"这个函数是否是 `{taint_name}` 的真实下游污点使用点?"
        )
        output = run_agent(
            prompt=user_msg, model=acfg.model, tools=acfg.tools or cfg.workers.default_tools,
            cwd=source_root, session_file=str(fork_session), system_prompt=system_prompt,
            cancel_event=cancel_event, run_timeout_seconds=min(cfg.agent_run_timeout_seconds, 600),
            timeout_retry_enabled=cfg.agent_timeout_retry_enabled,
            timeout_max_retries=cfg.agent_timeout_max_retries,
            pi_max_retries=cfg.pi_max_retries, pi_retry_delay=cfg.pi_retry_delay,
            task_context={"task_id": "", "task_root": "", "task_run_root": "",
                          "task_pi_dir": "", "agent_role": "workers"},
        )
        parsed = _extract_json_object(output.output, "confirmed") or {}
        if parsed.get("confirmed") is True:
            rec = store.find_function(cand["function"])
            if rec:
                confirmed.append((rec, TaintParamInfo(positions=[], signature="", names=[taint_name])))
    if on_event:
        on_event("v2_external_tracked", function=func.name, var=taint_name,
                 candidates=len(candidates), confirmed=len(confirmed))
    return confirmed


def _extract_fp_key(fp_expr: str) -> list[str]:
    """从函数指针表达式提取关键部分用于前后缀匹配。
    ctxt->sax->processingInstruction -> [processingInstruction, processing, Instruction]
    """
    last = fp_expr.rsplit("->", 1)[-1].rsplit(".", 1)[-1].strip("() ")
    if not last:
        return []
    keys = [last]
    parts = re.findall(r"[A-Z][a-z]*|[a-z]+", last)
    if len(parts) > 1:
        keys.extend("".join(parts[:i+1]) for i in range(len(parts) - 1))
        keys.extend(parts)
    return list(dict.fromkeys(k for k in keys if len(k) >= 3))


def _prefix_suffix_candidates(source_root: str, keys: list[str],
                               store: DataflowStore, timeout: int = 15) -> list[dict]:
    """按前后缀匹配在全局索引中缩小候选范围"""
    candidates = []
    seen = set()
    all_funcs = store.list_functions()
    for f in all_funcs:
        nm = f.name.rsplit("::", 1)[-1]
        for key in keys:
            if nm.lower().startswith(key.lower()) or nm.lower().endswith(key.lower()):
                if f.func_id not in seen:
                    seen.add(f.func_id)
                    candidates.append({"name": f.name, "file": f.file, "func_id": f.func_id})
                break
    for key in keys:
        try:
            r = subprocess.run(
                ["grep", "-rl", "--include=*.c", "--include=*.cpp", "--include=*.h",
                 "-i", f"\\b{key}", source_root],
                capture_output=True, text=True, timeout=timeout)
            for line in r.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    rel = str(Path(line).relative_to(source_root).as_posix())
                except ValueError:
                    continue
                for f in all_funcs:
                    if f.file == rel and f.func_id not in seen:
                        seen.add(f.func_id)
                        candidates.append({"name": f.name, "file": f.file, "func_id": f.func_id})
        except Exception:
            pass
    return candidates


def resolve_indirect(
    cfg, source_root: str, sessions_dir: Path, store: DataflowStore,
    func: FunctionRecord, prop: PropagationRecord,
    cancel_event: Any = None, on_event: Callable = None,
) -> list[tuple[FunctionRecord, TaintParamInfo]]:
    """函数指针注册点追踪: 前后缀匹配缩小候选 + LLM 判断 (fresh session)"""
    acfg = cfg.workers.agents[0] if cfg.workers.agents else None
    if acfg is None:
        return []
    fp_expr = prop.target_function or prop.target_taint_name
    if not fp_expr:
        return []
    keys = _extract_fp_key(fp_expr)
    if not keys:
        return []
    candidates = _prefix_suffix_candidates(source_root, keys, store)
    if not candidates:
        candidates = [{"name": "", "file": "", "func_id": ""}]
    fork_session = sessions_dir / f"{safe_name(func.name)}-fptrack-{safe_name(fp_expr)}.jsonl"
    system_prompt = (
        "你是数据流污点分析中的函数指针/回调目标追踪器。\n"
        "目标: 从候选列表中找出函数指针的真实注册处理函数。\n"
        "可以 read/grep 验证候选, 但候选已前后缀预筛, 优先在候选中判断。\n"
        '输出 JSON: {"handlers": [{"function": "...", "file": "...", "reason": "..."}]}\n'
    )
    cand_info = []
    for c in candidates[:30]:
        rec = store.get_function(c["func_id"]) if c["func_id"] else None
        body = ""
        if rec and rec.body_path and Path(rec.body_path).is_file():
            try:
                body = Path(rec.body_path).read_text(encoding="utf-8", errors="replace")[:4000]
            except OSError:
                pass
        cand_info.append(f"### {c['name']} ({c['file']})\n```c\n{body}\n```")
    prompt = (
        f"## 父函数: {func.file}::{func.name}\n"
        f"函数指针: `{fp_expr}`\n"
        f"污点: {prop.target_taint_name or prop.source_taint_name}\n"
        f"调用点: L{prop.call_line}\n\n"
        f"## 候选函数 (前后缀匹配预筛):\n" + "\n".join(cand_info) + "\n\n"
        f"从候选中找出 `{fp_expr}` 的真实注册处理函数。如果候选中无匹配, 可自行 grep 搜索。"
    )
    output = run_agent(
        prompt=prompt, model=acfg.model, tools=acfg.tools or cfg.workers.default_tools,
        cwd=source_root, session_file=str(fork_session), system_prompt=system_prompt,
        cancel_event=cancel_event, run_timeout_seconds=min(cfg.agent_run_timeout_seconds, 600),
        timeout_retry_enabled=cfg.agent_timeout_retry_enabled,
        timeout_max_retries=cfg.agent_timeout_max_retries,
        pi_max_retries=cfg.pi_max_retries, pi_retry_delay=cfg.pi_retry_delay,
        task_context={"task_id": "", "task_root": "", "task_run_root": "",
                      "task_pi_dir": "", "agent_role": "workers"},
    )
    parsed = _extract_json_object(output.output, "handlers") or {}
    out = []
    for item in parsed.get("handlers") or []:
        if not isinstance(item, dict):
            continue
        fn = str(item.get("function") or "").strip()
        if not fn:
            continue
        rec = store.find_function(fn) or store.find_function(fn, str(item.get("file") or ""))
        if rec is None and item.get("file"):
            ensure_file_indexed(source_root, str(item.get("file")), store)
            rec = store.find_function(fn) or store.find_function(fn, str(item.get("file") or ""))
        if rec is None:
            continue
        out.append((rec, TaintParamInfo(
            positions=[], signature=prop.target_taint_signature,
            names=[prop.target_taint_name or prop.source_taint_name])))
    if on_event:
        on_event("v2_indirect_tracked", function=func.name, fp=fp_expr,
                 candidates=len(candidates), resolved=len(out))
    return out
