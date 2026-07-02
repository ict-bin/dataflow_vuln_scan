"""dataflow-v2 tracker: 数据库驱动 + LLM 语义判断 (fresh session)。

不 grep NFS: 查 functions.db 获取候选函数 + read_function_body 从原源文件按行读函数体。
LLM 只做语义判断 (fresh session, 父函数信息放 prompt, 可有限探索)。

设计约束:
  - 候选上限 20 个 (避免几百个候选逐个 LLM 调用)
  - 批量一次 LLM 调用 (所有候选放一个 prompt, 不是逐个调)
  - 用完整变量名匹配 (如 ctx->buf, 不只取 buf)
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Callable

from ..runner import run_agent
from ..vuln_report_utils import safe_name, build_v2_system_prompt
from ..parsers import _extract_json_object
from .models import FunctionRecord, TaintParamInfo, PropagationRecord
from .store import DataflowStore
from .function_extractor import ensure_file_indexed, read_function_body

logger = logging.getLogger("dvs.dataflow_v2.trackers")

BATCH_SIZE = 10


def _match_patterns(var_name: str) -> list[str]:
    """根据变量名生成匹配模式列表 (考虑作用域)。

    全局变量 g_msg -> ["g_msg"]
    struct 字段 ctx->buf -> ["ctx->buf", "->buf"] (同指针名或同字段访问)
    类成员 this->member -> ["this->member", "->member"]
    简单变量 msg -> ["msg"] (至少 3 字符)
    """
    patterns = []
    clean = var_name.strip("() ")
    if len(clean) >= 3:
        patterns.append(clean)
    # struct/指针字段: ctx->buf -> 也匹配 ->buf (不同指针名访问同字段)
    if "->" in clean:
        field = clean.rsplit("->", 1)[-1]
        if len(field) >= 3:
            patterns.append("->" + field)
    # 类成员: this->member 或 obj.member -> 也匹配 .member
    if "." in clean and "->" not in clean:
        field = clean.rsplit(".", 1)[-1]
        if len(field) >= 3:
            patterns.append("." + field)
    # 去重, 保留顺序
    return list(dict.fromkeys(patterns))


def _find_refs_in_db(source_root: str, var_name: str, store: DataflowStore,
                     exclude_func_id: str = "") -> list[dict]:
    """查数据库所有函数, 读函数体, 找引用 var_name 的候选 (不 grep NFS)。

    用完整变量路径匹配 (考虑作用域):
    - 全局变量 g_msg -> 匹配 g_msg
    - struct 字段 ctx->buf -> 匹配 ctx->buf 或 ->buf
    不限制候选数量, 由 resolve_external 分批处理。
    """
    patterns = _match_patterns(var_name)
    if not patterns:
        return []
    candidates = []
    seen = set()
    for f in store.list_functions():
        if f.func_id == exclude_func_id:
            continue
        body = read_function_body(source_root, f, max_lines=300)
        if not body:
            continue
        # 用完整路径匹配, 任一 pattern 命中即可
        matched_pattern = None
        for p in patterns:
            if p in body:
                matched_pattern = p
                break
        if not matched_pattern:
            continue
        if f.func_id in seen:
            continue
        seen.add(f.func_id)
        # 找引用行
        ref_line = ""
        for i, line in enumerate(body.splitlines(), f.start_line):
            if matched_pattern in line:
                ref_line = f"L{i}: {line.strip()}"
                break
        candidates.append({
            "function": f.name, "file": f.file, "func_id": f.func_id,
            "line": ref_line, "body": body[:3000],
            "matched": matched_pattern,
        })
    return candidates


def resolve_external(
    cfg, source_root: str, sessions_dir: Path, store: DataflowStore,
    func: FunctionRecord, taint_name: str, taint_description: str,
    cancel_event: Any = None, on_event: Callable = None, depth: int = 0,
) -> list[tuple[FunctionRecord, TaintParamInfo]]:
    """外部变量下游追踪: 查数据库 + 分批 LLM 判断 (fresh session, 每批最多 10 个函数)。"""
    acfg = cfg.workers.agents[0] if cfg.workers.agents else None
    if acfg is None:
        return []

    # 1. 查数据库找候选 (不 grep NFS, 不限制数量)
    candidates = _find_refs_in_db(source_root, taint_name, store, exclude_func_id=func.func_id)
    if not candidates:
        return []

    # 2. LLM fresh session, 分批调用 (每批最多 BATCH_SIZE 个候选函数)
    fork_session = sessions_dir / f"d{depth:02d}-{safe_name(func.name)}-track-{safe_name(taint_name)}.jsonl"
    v2_system = build_v2_system_prompt(custom="tracker")
    system_prompt = (v2_system + "\n\n" if v2_system else "") + (
        "你是数据流污点分析中的非局部变量使用点追踪器。\n"
        "目标: 从候选函数列表中判断哪些是外部变量的真实下游使用点。\n"
        "可以 read 验证 (如 g_1=g_2 链), 但候选已从数据库预筛。\n"
        '输出 JSON: {"confirmed": [{"function": "...", "reason": "..."}, ...]}\n'
    )
    v2_env = {"DVS_V2_DB_DIR": str(sessions_dir.parent / "dataflow-v2"),
              "DVS_SOURCE_ROOT": source_root}

    confirmed_names = set()
    total_batches = (len(candidates) + BATCH_SIZE - 1) // BATCH_SIZE
    for batch_idx in range(total_batches):
        batch_start = batch_idx * BATCH_SIZE
        batch = candidates[batch_start:batch_start + BATCH_SIZE]
        cand_info = []
        for i, c in enumerate(batch):
            cand_info.append(
                f"### 候选 {batch_start+i+1}/{len(candidates)}: {c['function']} ({c['file']})\n"
                f"引用命中: `{c['line']}`\n"
                f"```c\n{c['body'][:2000]}\n```"
            )
        prompt = (
            f"## 父函数: {func.file}::{func.name}\n"
            f"外部变量: `{taint_name}` ({taint_description})\n\n"
            f"## 候选函数 (本批 {len(batch)} 个, 共 {len(candidates)} 个, 第 {batch_idx+1}/{total_batches} 批):\n\n"
            + "\n\n".join(cand_info) + "\n\n"
            f"从候选中找出 `{taint_name}` 的真实下游污点使用点。"
        )
        output = run_agent(
            prompt=prompt, model=acfg.model, tools=acfg.tools or cfg.workers.default_tools,
            cwd=source_root, session_file=str(fork_session), system_prompt=system_prompt,
            cancel_event=cancel_event, run_timeout_seconds=min(cfg.agent_run_timeout_seconds, 600),
            timeout_retry_enabled=cfg.agent_timeout_retry_enabled,
            timeout_max_retries=cfg.agent_timeout_max_retries,
            pi_max_retries=cfg.pi_max_retries, pi_retry_delay=cfg.pi_retry_delay,
            env=v2_env,
            task_context={"task_id": "", "task_root": "", "task_run_root": "",
                          "task_pi_dir": "", "agent_role": "workers"},
        )
        parsed = _extract_json_object(output.output, "confirmed") or {}
        for item in parsed.get("confirmed") or []:
            if isinstance(item, dict):
                fn = str(item.get("function") or "").strip()
                if fn:
                    confirmed_names.add(fn)

    confirmed = []
    for name in confirmed_names:
        rec = store.find_function(name)
        if rec:
            confirmed.append((rec, TaintParamInfo(positions=[], signature="", names=[taint_name])))

    if on_event:
        on_event("v2_external_tracked", function=func.name, var=taint_name,
                 candidates=len(candidates), confirmed=len(confirmed))
    return confirmed


def _extract_fp_key(fp_expr: str) -> list[str]:
    """从函数指针表达式提取关键部分用于前后缀匹配。"""
    last = fp_expr.rsplit("->", 1)[-1].rsplit(".", 1)[-1].strip("() ")
    if not last:
        return []
    keys = [last]
    parts = re.findall(r"[A-Z][a-z]*|[a-z]+", last)
    if len(parts) > 1:
        keys.extend("".join(parts[:i+1]) for i in range(len(parts) - 1))
        keys.extend(parts)
    return list(dict.fromkeys(k for k in keys if len(k) >= 3))


def _prefix_suffix_candidates_from_db(source_root: str, keys: list[str],
                                       store: DataflowStore) -> list[dict]:
    """查数据库按前后缀匹配缩小候选范围 (不 grep NFS)。"""
    candidates = []
    seen = set()
    for f in store.list_functions():
        nm = f.name.rsplit("::", 1)[-1]
        for key in keys:
            if nm.lower().startswith(key.lower()) or nm.lower().endswith(key.lower()):
                if f.func_id not in seen:
                    seen.add(f.func_id)
                    body = read_function_body(source_root, f, max_lines=200)
                    candidates.append({
                        "name": f.name, "file": f.file, "func_id": f.func_id, "body": body[:4000],
                    })
                break
    return candidates


def resolve_indirect(
    cfg, source_root: str, sessions_dir: Path, store: DataflowStore,
    func: FunctionRecord, prop: PropagationRecord,
    cancel_event: Any = None, on_event: Callable = None, depth: int = 0,
) -> list[tuple[FunctionRecord, TaintParamInfo]]:
    """函数指针注册点追踪: 数据库前后缀匹配 + LLM 判断 (fresh session)。"""
    acfg = cfg.workers.agents[0] if cfg.workers.agents else None
    if acfg is None:
        return []
    fp_expr = prop.target_function or prop.target_taint_name
    if not fp_expr:
        return []
    keys = _extract_fp_key(fp_expr)
    if not keys:
        return []

    # 1. 查数据库前后缀匹配 (不 grep NFS)
    candidates = _prefix_suffix_candidates_from_db(source_root, keys, store)
    if not candidates:
        candidates = [{"name": "", "file": "", "func_id": "", "body": ""}]

    # 2. LLM fresh session: 从候选中找注册处理函数
    fork_session = sessions_dir / f"d{depth:02d}-{safe_name(func.name)}-fptrack-{safe_name(fp_expr)}.jsonl"
    v2_system = build_v2_system_prompt(custom="tracker")
    system_prompt = (v2_system + "\n\n" if v2_system else "") + (
        "你是数据流污点分析中的函数指针/回调目标追踪器。\n"
        "目标: 从候选列表中找出函数指针的真实注册处理函数。\n"
        "可以 read 验证候选, 但候选已从数据库前后缀预筛, 优先在候选中判断。\n"
        '输出 JSON: {"handlers": [{"function": "...", "file": "...", "reason": "..."}]}\n'
    )
    v2_env = {"DVS_V2_DB_DIR": str(sessions_dir.parent / "dataflow-v2"),
              "DVS_SOURCE_ROOT": source_root}
    cand_info = [f"### {c['name']} ({c['file']})\n```c\n{c['body']}\n```" for c in candidates]
    prompt = (
        f"## 父函数: {func.file}::{func.name}\n"
        f"函数指针: `{fp_expr}`\n"
        f"污点: {prop.target_taint_name or prop.source_taint_name}\n"
        f"调用点: L{prop.call_line}\n\n"
        f"## 候选函数 (数据库前后缀匹配预筛):\n" + "\n".join(cand_info) + "\n\n"
        f"从候选中找出 `{fp_expr}` 的真实注册处理函数。如果候选中无匹配, 可自行 grep 搜索。"
    )
    output = run_agent(
        prompt=prompt, model=acfg.model, tools=acfg.tools or cfg.workers.default_tools,
        cwd=source_root, session_file=str(fork_session), system_prompt=system_prompt,
        cancel_event=cancel_event, run_timeout_seconds=min(cfg.agent_run_timeout_seconds, 600),
        timeout_retry_enabled=cfg.agent_timeout_retry_enabled,
        timeout_max_retries=cfg.agent_timeout_max_retries,
        pi_max_retries=cfg.pi_max_retries, pi_retry_delay=cfg.pi_retry_delay,
        env=v2_env,
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
