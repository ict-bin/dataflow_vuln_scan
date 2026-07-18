"""dataflow-v2 tracker: LLM 驱动的外部逃逸下游读者追踪 + 函数指针解析。

设计原则 (AI 中心): 逃逸语义判定与下游读者搜索都交给 LLM, 脚本不做语义覆盖、
不靠字符串 pattern 搜函数体。tracker LLM fork 拿到逃逸 propagation (escape_kind/
carrier/escape_via/description) + 源函数, 自己用 v2_db 按类型查候选、读体判断。

- resolve_external   外部逃逸 (container/global/field_alias) → 下游读者, 全 LLM + v2_db
- resolve_indirect   函数指针/回调注册点 → 处理函数, 数据库前后缀预筛 + LLM 判断
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


# ── 外部逃逸下游读者追踪 (全 LLM + v2_db, 无字符串 pattern) ──────────────

def resolve_external(
    cfg, source_root: str, sessions_dir: Path, store: DataflowStore,
    func: FunctionRecord, prop: PropagationRecord,
    cancel_event: Any = None, on_event: Callable = None, depth: int = 0,
) -> list[tuple[FunctionRecord, TaintParamInfo]]:
    """外部逃逸下游追踪: LLM fork 用 v2_db 按逃逸语义查读者。

    不依赖 prop.target_taint_name 做字符串匹配; 把逃逸 propagation (escape_kind/
    carrier/escape_via/description) + 源函数交给 LLM, 它自己 v2_db 查类型/找访问者/
    读体判断, 返回确认的读者函数。换任何项目/任何结构体名/任何 alloc 或容器变体,
    LLM 都能自己查出来。
    """
    acfg = cfg.workers.agents[0] if cfg.workers.agents else None
    if acfg is None:
        return []

    fork_session = sessions_dir / f"d{depth:02d}-{safe_name(func.name)}-track-{safe_name(prop.escape_kind or prop.carrier or 'escape')}.jsonl"
    v2_system = build_v2_system_prompt(custom="tracker")
    system_prompt = (v2_system + "\n\n" if v2_system else "") + (
        "你是数据流污点分析中的外部逃逸下游读者追踪器。\n"
        "目标: 给定一条从源函数逃逸出的污点 propagation, 找出会读取到该污点的下游函数。\n"
        "策略:\n"
        "1. 用 v2_db lookup <源函数名> 读源函数体, 搞清逃逸涉及的类型\n"
        "   (如某入参的结构体类型 struct X, 载体挂入了它的哪个字段/容器)。\n"
        "2. 用 v2_db 按该结构体类型查所有接收它的函数 (如形参为 struct X* 的函数),\n"
        "   也可按字段名/容器名查访问者。\n"
        "3. 对每个候选用 v2_db lookup 读体, 判断是否真的读取了承载污点的容器/字段\n"
        "   (遍历链表/查哈希表/访问字段/迭代器, 形式多样, 靠语义判断, 不靠宏名)。\n"
        "4. 容器读取可能是 list_for_each_entry/裸 for/范围 for/索引访问/自定义迭代,\n"
        "   不依赖固定宏名清单。\n"
        "5. 只报真正会读到这条逃逸污点的函数; 不确定的不报。\n"
        "6. 攻击面复核要求: 获取污点的下游函数的前提，都要根据函数的功能，根据污点值的含义，先判断污点以及逃逸的内容属于外部攻击者可控制的内容,以及攻击者可控的内容能够造成安全危害；对攻击者不可控的变量、进程内部状态、纯内部派生值以及其他无法控制的内容，以及不太可能造成安全危害的污点，如简单的类型或者已经经过足够多校验的污点，一律不要作为污点继续跟踪，也不要输出到最终结果，可根据经验进行判断是否属于攻击者可控内容。 \n"
        "7. 如果目标函数和传入的污点，不太可能造成安全问题，或者目标函数功能是没有危险的，也不需要跟踪，也不要输出到最终结果,只有值得接下来分析的污点和目标函数，才需要输出到最终结果中。\n\n"
        '输出 JSON: {"confirmed": [{"function": "...", "taint_param": "...", "reason": "..."}]}\n'
        "  * function: 读者函数名 (须是 v2_db 里存在的真实函数; 找不到可 grep 搜索源码后报)\n"
        "  * taint_param: 读者接收污点的入参名 (供下游 LLM 理解污点来源, 如 http_head)\n"
        "  * reason: 为何认为该函数读到逃逸污点\n"
    )
    v2_env = {"DVS_V2_DB_DIR": str(store.run_dir),
              "DVS_SOURCE_ROOT": source_root}

    prompt = (
        f"## 源函数\n{func.file}::{func.name}\n\n"
        f"## 逃逸 propagation\n"
        f"- escape_kind: {prop.escape_kind or '(未指定)'}\n"
        f"- carrier: {prop.carrier or '(无)'}\n"
        f"- escape_via: {prop.escape_via or '(无)'}\n"
        f"- target_taint: {prop.target_taint_name or '(无)'}\n"
        f"- source_taint: {prop.source_taint_name or '(无)'}\n"
        f"- description: {prop.description or '(无)'}\n\n"
        f"请按系统提示词策略, 用 v2_db 查找读取这条逃逸污点的下游函数。\n"
    )
    output = run_agent(
        prompt=prompt, model=acfg.model, tools=acfg.tools or cfg.workers.default_tools,
        cwd=source_root, session_file=str(fork_session), system_prompt=system_prompt,
        cancel_event=cancel_event, run_timeout_seconds=min(cfg.agent_run_timeout_seconds, 1600),
        timeout_retry_enabled=cfg.agent_timeout_retry_enabled,
        timeout_max_retries=cfg.agent_timeout_max_retries,
        pi_max_retries=cfg.pi_max_retries, pi_retry_delay=cfg.pi_retry_delay,
        env=v2_env,
        thinking_level="off",
        task_context={"task_id": "", "task_root": "", "task_run_root": "",
                      "task_pi_dir": "", "agent_role": "workers",
                      "fork_purpose": "external_tracking"},
    )
    parsed = _extract_json_object(output.output, "confirmed") or {}
    confirmed: list[tuple[FunctionRecord, TaintParamInfo]] = []
    for item in parsed.get("confirmed") or []:
        if not isinstance(item, dict):
            continue
        fn = str(item.get("function") or "").strip()
        if not fn:
            continue
        taint_param = str(item.get("taint_param") or "").strip()
        rec = store.find_function(fn)
        if rec is None:
            # 没索引则 grep 搜源码树 + 建库 (复用现有增量索引)
            from .function_extractor import find_func_in_source
            found = find_func_in_source(fn, Path(source_root))
            if found:
                for rel_def_file, _ in found:
                    try:
                        ensure_file_indexed(source_root, rel_def_file, store)
                    except Exception:
                        logger.debug("track ensure_file_indexed failed for %s", rel_def_file, exc_info=True)
                rec = store.find_function(fn)
        if rec is None:
            continue
        confirmed.append((rec, TaintParamInfo(
            positions=[],
            signature=taint_param or fn,
            names=[taint_param or prop.target_taint_name or prop.carrier or fn],
        )))
    if on_event:
        on_event("v2_external_tracked", function=func.name,
                 escape_kind=prop.escape_kind or "", carrier=prop.carrier or "",
                 confirmed=len(confirmed))
    return confirmed


# ── 间接调用 tracker (函数指针) ──────────────────────────────────────────

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
    """查数据库按前后缀匹配缩小候选范围。"""
    candidates = []
    seen = set()
    for f in store.list_functions():
        nm = f.name.rsplit("::", 1)[-1]
        for key in keys:
            if nm.lower().startswith(key.lower()) or nm.lower().endswith(key.lower()):
                if f.func_id not in seen:
                    seen.add(f.func_id)
                    candidates.append({"name": f.name, "file": f.file, "func_id": f.func_id})
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

    candidates = _prefix_suffix_candidates_from_db(source_root, keys, store)
    if not candidates:
        candidates = [{"name": "", "file": "", "func_id": ""}]

    fork_session = sessions_dir / f"d{depth:02d}-{safe_name(func.name)}-fptrack-{safe_name(fp_expr)}.jsonl"
    v2_system = build_v2_system_prompt(custom="tracker")
    system_prompt = (v2_system + "\n\n" if v2_system else "") + (
        "你是数据流污点分析中的函数指针/回调目标追踪器。\n"
        "目标: 从候选列表中找出函数指针的真实注册处理函数。\n"
        "用 v2_db lookup 读取需要的函数体后判断。\n"
        '输出 JSON: {"handlers": [{"function": "...", "file": "...", "reason": "..."}]}\n'
    )
    v2_env = {"DVS_V2_DB_DIR": str(store.run_dir),
              "DVS_SOURCE_ROOT": source_root}
    # 传路径不传函数体
    cand_info = [f"### {c['name']} ({c['file']})\n(用 `v2_db lookup {c['name']}` 读取函数体)"
                 for c in candidates]
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
        cancel_event=cancel_event, run_timeout_seconds=min(cfg.agent_run_timeout_seconds, 1600),
        timeout_retry_enabled=cfg.agent_timeout_retry_enabled,
        timeout_max_retries=cfg.agent_timeout_max_retries,
        pi_max_retries=cfg.pi_max_retries, pi_retry_delay=cfg.pi_retry_delay,
        env=v2_env,
        thinking_level="off",
        task_context={"task_id": "", "task_root": "", "task_run_root": "",
                      "task_pi_dir": "", "agent_role": "workers",
                      "fork_purpose": "indirect_call_tracking"},
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
