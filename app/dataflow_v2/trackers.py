"""dataflow-v2 tracker: 作用域预筛 + LLM 语义判断 (fresh session)。

4 层防护:
  Layer 1: 脚本校验 (analysis.py, 已实现) — 挡住非外部变量
  Layer 2: 预筛选 (本文件) — include 索引/class 继承图缩小候选
  Layer 3: LLM 上下文 — 传路径+命中行, 不传函数体 (LLM 用 v2_db 按需读)
  Layer 4: LLM 语义判断 — 分批 10 个/次
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
    """根据变量名生成匹配模式列表 (考虑作用域)。"""
    patterns = []
    clean = var_name.strip("() ")
    if len(clean) >= 3:
        patterns.append(clean)
    if "->" in clean:
        field = clean.rsplit("->", 1)[-1]
        if len(field) >= 3:
            patterns.append("->" + field)
    if "." in clean and "->" not in clean:
        field = clean.rsplit(".", 1)[-1]
        if len(field) >= 3:
            patterns.append("." + field)
    return list(dict.fromkeys(patterns))


# ── Layer 2: 预筛选 ──────────────────────────────────────────────────────

def _prefilter_candidates(source_root: str, var_name: str, func: FunctionRecord,
                          store: DataflowStore, all_funcs: list[FunctionRecord]) -> list[FunctionRecord] | None:
    """按变量类型预筛选候选函数, 返回 None 表示无法预筛 (用全库 fallback)。

    变量类型判定:
    - X->Y, base X == "this" → C++ 类成员 → class 继承图预筛
    - X->Y, base X 是参数 → C/C++ 参数 struct 字段 → 类型签名预筛
    - 简单名 → 全局变量 → include 索引预筛 (找声明文件)
    """
    clean = var_name.strip("() ")

    # C++ 类成员: this->member
    if clean.startswith("this->") or clean.startswith("this."):
        member = clean.split("->", 1)[-1].split(".", 1)[-1] if "." in clean else clean.split("->", 1)[-1]
        # 从函数名提取类名: Class::method → Class
        class_name = func.name.split("::")[0] if "::" in func.name else ""
        if class_name:
            method_names = set(store.get_class_scope_methods(class_name, member))
            if method_names:
                return [f for f in all_funcs if f.name in method_names and f.func_id != func.func_id]
        return None  # 无法预筛, fallback

    # C++ 静态成员: ClassName::static_member
    if "::" in clean and "->" not in clean:
        class_name = clean.split("::")[0]
        method_names = set(store.get_class_scope_methods(class_name))
        if method_names:
            return [f for f in all_funcs if f.name in method_names and f.func_id != func.func_id]
        return None

    # X->Y 或 X.Y: 提取 base, 从签名找类型
    base = None
    if "->" in clean:
        base = clean.split("->")[0].strip()
    elif "." in clean:
        base = clean.split(".")[0].strip()

    if base and base != "this":
        # 从函数签名提取 base 的类型
        sig = func.signature or ""
        # 简单提取: 在签名中找 base 前面的类型词
        # e.g., "xmlOutputBuffer *buf" → base="buf", type="xmlOutputBuffer"
        type_match = re.search(rf'(\w[\w\s\*]*?)\s*\**\s*{re.escape(base)}\b', sig)
        if type_match:
            type_name = type_match.group(1).strip().split()[-1]  # 取最后一个词
            # 去掉指针符号
            type_name = type_name.rstrip("*")
            if type_name and len(type_name) >= 3:
                # 查 class 继承图: type_name 可能是 class
                method_names = set(store.get_class_scope_methods(type_name))
                if method_names:
                    return [f for f in all_funcs if f.name in method_names and f.func_id != func.func_id]
                # 查签名含同类型的函数
                sig_funcs = set(store.get_functions_with_type_in_signature(type_name))
                if sig_funcs:
                    return [f for f in all_funcs if f.name in sig_funcs and f.func_id != func.func_id]
        return None  # 无法确定类型, fallback

    # 全局变量: 在父函数文件找声明
    if not base:
        # 尝试在父函数文件中找变量声明
        from .function_extractor import _extract_includes
        parent_file = func.file
        # 简单 regex 在源文件中搜声明
        src_path = Path(source_root) / parent_file
        if src_path.is_file():
            try:
                text = src_path.read_text(encoding="utf-8", errors="replace")
                # 搜全局声明: type g_msg = 或 extern type g_msg
                decl_re = re.compile(rf'(?:extern\s+)?[\w\s\*]+\s+{re.escape(clean)}\s*[=;]', re.MULTILINE)
                if decl_re.search(text):
                    # 找到声明, 用 include 索引预筛
                    files = set(store.get_files_including(parent_file))
                    files.add(parent_file)  # 声明文件本身
                    if files:
                        return [f for f in all_funcs if f.file in files and f.func_id != func.func_id]
            except OSError:
                pass
        return None  # 找不到声明, fallback

    return None


# ── Layer 3+4: LLM 判断 (传路径不传函数体) ──────────────────────────────

def _find_refs_in_db(source_root: str, var_name: str, store: DataflowStore,
                     exclude_func_id: str = "",
                     prefiltered: list[FunctionRecord] | None = None) -> list[dict]:
    """查数据库找候选, 优先用预筛结果。"""
    patterns = _match_patterns(var_name)
    if not patterns:
        return []

    if prefiltered is not None:
        search_funcs = prefiltered
    else:
        search_funcs = store.list_functions()

    candidates = []
    seen = set()
    for f in search_funcs:
        if f.func_id == exclude_func_id:
            continue
        body = read_function_body(source_root, f, max_lines=300)
        if not body:
            continue
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
        ref_line = ""
        for i, line in enumerate(body.splitlines(), f.start_line):
            if matched_pattern in line:
                ref_line = f"L{i}: {line.strip()}"
                break
        candidates.append({
            "function": f.name, "file": f.file, "func_id": f.func_id,
            "line": ref_line, "matched": matched_pattern,
        })
    return candidates


def resolve_external(
    cfg, source_root: str, sessions_dir: Path, store: DataflowStore,
    func: FunctionRecord, taint_name: str, taint_description: str,
    cancel_event: Any = None, on_event: Callable = None, depth: int = 0,
) -> list[tuple[FunctionRecord, TaintParamInfo]]:
    """外部变量下游追踪: 预筛 + 分批 LLM 判断 (传路径不传函数体)。"""
    acfg = cfg.workers.agents[0] if cfg.workers.agents else None
    if acfg is None:
        return []

    all_funcs = store.list_functions()

    # Layer 2: 预筛
    prefiltered = _prefilter_candidates(source_root, taint_name, func, store, all_funcs)
    if prefiltered is not None:
        logger.info("prefiltered %s: %d -> %d candidates", taint_name, len(all_funcs), len(prefiltered))

    # 查候选 (用预筛结果或全库)
    candidates = _find_refs_in_db(source_root, taint_name, store,
                                  exclude_func_id=func.func_id,
                                  prefiltered=prefiltered)
    if not candidates:
        return []

    # Layer 3+4: LLM 分批判断 (传路径+命中行, 不传函数体)
    fork_session = sessions_dir / f"d{depth:02d}-{safe_name(func.name)}-track-{safe_name(taint_name)}.jsonl"
    v2_system = build_v2_system_prompt(custom="tracker")
    system_prompt = (v2_system + "\n\n" if v2_system else "") + (
        "你是数据流污点分析中的非局部变量使用点追踪器。\n"
        "目标: 从候选函数列表中判断哪些是外部变量的真实下游使用点。\n"
        "每个候选只提供函数名、文件路径和引用命中行。用 v2_db lookup <函数名> 按需读取函数体。\n"
        "可以 read 验证 (如 g_1=g_2 链)。\n"
        '输出 JSON: {"confirmed": [{"function": "...", "reason": "..."}, ...]}\n'
    )
    v2_env = {"DVS_V2_DB_DIR": str(sessions_dir.parent / "dataflow-v2"),
              "DVS_SOURCE_ROOT": source_root}

    confirmed_names = set()
    total_batches = (len(candidates) + BATCH_SIZE - 1) // BATCH_SIZE
    for batch_idx in range(total_batches):
        batch_start = batch_idx * BATCH_SIZE
        batch = candidates[batch_start:batch_start + BATCH_SIZE]
        # 只传路径+命中行, 不传函数体
        cand_info = []
        for i, c in enumerate(batch):
            cand_info.append(
                f"### 候选 {batch_start+i+1}/{len(candidates)}: {c['function']}\n"
                f"文件: {c['file']}\n"
                f"引用命中: `{c['line']}`\n"
                f"(用 `v2_db lookup {c['function']}` 读取函数体)"
            )
        prompt = (
            f"## 父函数: {func.file}::{func.name}\n"
            f"外部变量: `{taint_name}` ({taint_description})\n\n"
            f"## 候选函数 (本批 {len(batch)} 个, 共 {len(candidates)} 个, 第 {batch_idx+1}/{total_batches} 批):\n\n"
            + "\n\n".join(cand_info) + "\n\n"
            f"从候选中找出 `{taint_name}` 的真实下游污点使用点。"
            f"用 v2_db lookup 读取需要的函数体后判断。"
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
                 candidates=len(candidates), confirmed=len(confirmed),
                 prefilters=len(prefiltered) if prefiltered else 0)
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
    v2_env = {"DVS_V2_DB_DIR": str(sessions_dir.parent / "dataflow-v2"),
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
