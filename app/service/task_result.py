"""Task result loading, evaluation payload building, input manifest, and config helpers."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session
from sqlalchemy import func
from sqlalchemy.orm.attributes import flag_modified

from app.config import load_service_config
from app.logging_utils import log_event
from app.time_utils import isoformat_local, now_local

from .task_paths import _task_result_path, _task_root, _task_run_root
from .task_session import _write_json_atomic

logger = logging.getLogger("dvs.task_result")

SERVICE_CONFIG_PATH = os.environ.get("SERVICE_CONFIG", "/app/config.json")
ENTRY_CONTEXT_MAX_CHARS = 32000
ENTRY_CONTEXT_MAX_TAINTS = 64
ENTRY_CONTEXT_MAX_DESC_CHARS = 2240


def _load_task_result_json(row) -> dict | None:
    from .task_paths import _task_result_path, _resolve_run_path, _task_root
    path = _task_result_path(row)
    if path and path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                return loaded
        except Exception as exc:
            logger.warning("failed to load task result file %s: %s", path, exc)
    # Fallback: try .run_nfs/ mirror (for API pods during execution)
    root = _task_root(row)
    if root:
        mirror_path = root / ".run_nfs" / "result.json"
        if mirror_path.is_file():
            try:
                loaded = json.loads(mirror_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    return loaded
            except Exception as exc:
                logger.warning("failed to load mirror result file %s: %s", mirror_path, exc)
    return row.result_json if isinstance(row.result_json, dict) else None


def _write_task_result_json(row, payload: dict) -> str | None:
    path = _task_result_path(row)
    if not path:
        return None
    _write_json_atomic(path, payload)
    return str(path)


# ─── Entry analysis context ───────────────────────────────────────────────────

def _build_entry_analysis_context(task_config_json: dict | None) -> str:
    from app.db.models import AppDvsTask as _Task

    cfg = task_config_json if isinstance(task_config_json, dict) else {}
    function_description = str(cfg.get("function_description") or "").strip()
    entry_reason = str(cfg.get("entry_reason") or "").strip()
    taint_details = cfg.get("taint_details") if isinstance(cfg.get("taint_details"), list) else []
    taint_params = [
        str(value).strip()
        for value in (cfg.get("taint_params") or [])
        if str(value).strip()
    ]
    if not function_description and not entry_reason and not taint_details:
        return ""

    lines = ["# 上游入口分析提供的上下文"]
    if function_description:
        fn_source = str(cfg.get("function_description_source") or "").strip()
        fn_suffix = f" [source={fn_source}]" if fn_source else ""
        lines.append(f"- 函数说明{fn_suffix}: {function_description[:ENTRY_CONTEXT_MAX_DESC_CHARS]}")
    if entry_reason:
        reason_source = str(cfg.get("entry_reason_source") or "").strip()
        reason_suffix = f" [source={reason_source}]" if reason_source else ""
        lines.append(f"- 入口判定原因{reason_suffix}: {entry_reason[:ENTRY_CONTEXT_MAX_DESC_CHARS]}")
    if taint_params:
        lines.append(f"- 上游标记的污点参数: {', '.join(taint_params)}")
    if taint_details:
        lines.append("- 污点参数说明:")
        omitted = max(0, len(taint_details) - ENTRY_CONTEXT_MAX_TAINTS)
        for item in taint_details[:ENTRY_CONTEXT_MAX_TAINTS]:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            description = (str(item.get("description") or "").strip() or "上游未提供额外说明。")[:ENTRY_CONTEXT_MAX_DESC_CHARS]
            source_kind = str(item.get("source_kind") or "").strip()
            description_source = str(item.get("description_source") or "").strip()
            suffix_parts = []
            if source_kind:
                suffix_parts.append(f"source_kind={source_kind}")
            if description_source:
                suffix_parts.append(f"source={description_source}")
            suffix = f" ({', '.join(suffix_parts)})" if suffix_parts else ""
            lines.append(f"  - {name}: {description}{suffix}")
        if omitted > 0:
            lines.append(f"  - ... 另有 {omitted} 个 taint 说明被折叠，避免上下文过长。")
    lines.append("以上信息来自上游入口分析，仅作为辅助上下文；若与源码不一致，以源码为准。")
    context = "\n".join(lines)
    if len(context) > ENTRY_CONTEXT_MAX_CHARS:
        context = context[:ENTRY_CONTEXT_MAX_CHARS].rstrip() + "\n...（上游入口分析上下文已截断）"
    return context


# ─── Terminal failure / result persistence ────────────────────────────────────

def _persist_terminal_failure(row, error: str, *, status: str = "error") -> dict:
    from .task_result import _token_usage_dict as _tok_dict  # local ref for self-call

    payload = {
        "task_id": row.task_id,
        "status": status,
        "analysis_status": status,
        "completion_reason": error,
        "task": row.prompt_content or row.task_name or "",
        "error": error,
        "rounds": [],
        "total_duration_ms": 0,
        "total_tokens": _token_usage_dict(None),
    }
    result_file = _write_task_result_json(row, payload)
    row.result_json = _lightweight_result_json(row, payload, result_file)
    row.error = error
    return payload


# ─── Input manifest ───────────────────────────────────────────────────────────

def _input_manifest_path(row) -> Path | None:
    root = _task_root(row)
    return root / "input" / "input_manifest.json" if root else None


def _path_metadata(path_value: str | None) -> dict:
    if not path_value:
        return {"path": None, "exists": False}
    path = Path(path_value)
    try:
        stat = path.stat()
        kind = "directory" if path.is_dir() else "file" if path.is_file() else "other"
        return {
            "path": str(path),
            "real_path": str(path.resolve()),
            "exists": True,
            "kind": kind,
            "size_bytes": stat.st_size if path.is_file() else None,
            "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        }
    except OSError:
        return {
            "path": str(path),
            "real_path": os.path.realpath(os.path.abspath(str(path))),
            "exists": False,
        }


def _validate_fileserver_path(path_value: str, *, fs_root: str, field_name: str, must_exist: bool = True, must_be_dir: bool = False) -> str:
    from fastapi import HTTPException as _HTTPException

    raw = str(path_value or "").strip()
    if not raw:
        raise _HTTPException(400, f"{field_name} 不能为空")
    normalized = os.path.realpath(os.path.abspath(raw))
    normalized_fs = os.path.realpath(os.path.abspath(fs_root))
    if not normalized.startswith(normalized_fs + os.sep) and normalized != normalized_fs:
        raise _HTTPException(400, f"{field_name} 必须位于 {fs_root} 下")
    if must_exist and not os.path.exists(normalized):
        raise _HTTPException(400, f"{field_name} 不存在: {raw}")
    if must_be_dir and os.path.exists(normalized) and not os.path.isdir(normalized):
        raise _HTTPException(400, f"{field_name} 必须是目录: {raw}")
    return normalized


def _normalize_source_file_for_root(source_root_path: str, source_file: str) -> str:
    from fastapi import HTTPException as _HTTPException

    raw = str(source_file or "").strip().replace("\\", "/")
    if not raw:
        return ""
    root = Path(os.path.realpath(os.path.abspath(source_root_path)))
    marker = "/data/files/"
    embedded_absolute = raw[raw.index(marker):] if marker in raw else None
    candidate = Path(embedded_absolute or raw)
    resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    try:
        relative = resolved.relative_to(root)
    except Exception as exc:
        raise _HTTPException(400, f"source_file 超出 source_root_path 范围: {source_file}") from exc
    normalized = relative.as_posix().strip()
    if not normalized or normalized == "." or any(part == ".." for part in relative.parts):
        raise _HTTPException(400, f"source_file 非法: {source_file}")
    if not resolved.is_file():
        raise _HTTPException(400, f"source_file 对应文件不存在: {source_file}")
    return normalized


def _write_input_manifest(row) -> str | None:
    """Write task input metadata only; never copy original input contents."""
    from .task_result import _origin_payload as _orig_payload

    path = _input_manifest_path(row)
    if not path:
        return None
    prompt = row.prompt_content or ""
    payload = {
        "schema_version": 1,
        "generated_at": isoformat_local(now_local()),
        "task": {
            "task_id": row.task_id,
            "project_id": row.project_id,
            "task_name": row.task_name,
            "task_description": row.task_description,
            "created_by": row.created_by,
            "created_at": isoformat_local(row.created_at),
            "started_at": isoformat_local(row.started_at),
        },
        "input": _path_metadata(row.input_path),
        "paths": {
            "module_input_path": row.module_input_path or row.input_path,
            "source_root_path": row.source_root_path or row.input_path,
        },
        "prompt": {
            "template_id": row.prompt_template_id,
            "content_length": len(prompt),
            "content_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest() if prompt else None,
        },
        "origin": _orig_payload(row),
        "config": {
            "has_task_overrides": bool(row.task_config_json),
            "override_keys": sorted((row.task_config_json or {}).keys()),
            "source_file": str((row.task_config_json or {}).get("source_file") or ""),
            "definition_kind": str((row.task_config_json or {}).get("definition_kind") or ""),
        },
    }
    _write_json_atomic(path, payload)
    return str(path)


# ─── Lightweight result / tokens ──────────────────────────────────────────────

def _lightweight_result_json(row, payload: dict | None, result_file: str | None = None) -> dict | None:
    if not isinstance(payload, dict):
        return None
    if payload.get("result_externalized"):
        return {
            **payload,
            "result_file": payload.get("result_file") or result_file or (str(_task_result_path(row)) if _task_result_path(row) else None),
            "result_externalized": True,
        }
    total_tokens = payload.get("total_tokens") if isinstance(payload.get("total_tokens"), dict) else None
    rounds = payload.get("rounds") if isinstance(payload.get("rounds"), list) else []
    return {
        "result_file": result_file or (str(_task_result_path(row)) if _task_result_path(row) else None),
        "result_externalized": True,
        "status": payload.get("status") or row.status,
        "analysis_status": payload.get("analysis_status") or payload.get("status") or row.status,
        "completion_reason": payload.get("completion_reason"),
        "error": payload.get("error"),
        "round_count": len(rounds),
        "total_duration_ms": payload.get("total_duration_ms"),
        "total_tokens": total_tokens,
    }


def _token_usage_dict(value: dict | None) -> dict[str, float | int]:
    usage = value if isinstance(value, dict) else {}
    return {
        "input": int(usage.get("input", 0) or 0),
        "output": int(usage.get("output", 0) or 0),
        "cache_read": int(usage.get("cache_read", 0) or 0),
        "cache_write": int(usage.get("cache_write", 0) or 0),
        "cost": float(usage.get("cost", 0.0) or 0.0),
    }


def _merge_usage(items: list[dict | None]) -> dict[str, float | int]:
    total = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "cost": 0.0}
    for item in items:
        usage = _token_usage_dict(item)
        total["input"] += int(usage["input"])
        total["output"] += int(usage["output"])
        total["cache_read"] += int(usage["cache_read"])
        total["cache_write"] += int(usage["cache_write"])
        total["cost"] += float(usage["cost"])
    return total


def _token_total(usage: dict[str, float | int]) -> int:
    return int(usage.get("input", 0)) + int(usage.get("output", 0)) + int(usage.get("cache_read", 0)) + int(usage.get("cache_write", 0))


def _safe_eval_key(value: str | None, fallback: str) -> str:
    raw = (value or "").strip() or fallback
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in raw)
    return safe.strip("._") or fallback


# ─── Evaluation payload ───────────────────────────────────────────────────────

def _build_evaluation_payload(task_id: str, task_status: str, result_payload: dict) -> tuple[dict | None, list[dict]]:
    rounds_payload = result_payload.get("rounds")
    rounds_payload = rounds_payload if isinstance(rounds_payload, list) else []
    records: list[dict] = []
    function_names: set[str] = set()
    passed_rounds = 0
    total_duration_ms = 0.0
    total_usage = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "cost": 0.0}
    stage_summary: dict[str, dict[str, float | int]] = {}

    for index, item in enumerate(rounds_payload, start=1):
        if not isinstance(item, dict):
            continue
        function_name = str(item.get("function_name") or item.get("function") or item.get("func") or item.get("entry") or "unknown")
        source_path = str(item.get("source_path") or "")
        status = str(item.get("status") or ("passed" if item.get("passed") else "failed"))
        worker_results = item.get("worker_results") if isinstance(item.get("worker_results"), list) else []
        judge_results = item.get("judge_results") if isinstance(item.get("judge_results"), list) else []
        pass_count = int(item.get("pass_count") or 0)
        judge_count = int(item.get("total_judges") or len(judge_results) or 0)
        scores: list[float] = []
        normalized_judges: list[dict] = []
        judge_usages: list[dict] = []
        for judge_index, judge in enumerate(judge_results, start=1):
            if not isinstance(judge, dict):
                continue
            evaluations = judge.get("evaluations") if isinstance(judge.get("evaluations"), list) else []
            score = None
            feedback_excerpt = ""
            passed_flag = False
            if evaluations and isinstance(evaluations[0], dict):
                score = evaluations[0].get("score")
                feedback_excerpt = str(evaluations[0].get("feedback") or "")
                passed_flag = bool(evaluations[0].get("passed"))
            try:
                if score is not None:
                    scores.append(float(score))
            except (TypeError, ValueError):
                pass
            usage = _token_usage_dict(judge.get("token_usage"))
            judge_usages.append(usage)
            normalized_judges.append({
                "judge_id": judge.get("judge_id") or f"judge-{judge_index}",
                "model": judge.get("model") or "",
                "session_file": judge.get("session_file") or "",
                "score": score,
                "passed": passed_flag,
                "feedback_excerpt": feedback_excerpt[:1000],
                "token_usage": usage,
            })

        worker = worker_results[0] if worker_results and isinstance(worker_results[0], dict) else {}
        worker_usage = _token_usage_dict(worker.get("token_usage") if isinstance(worker, dict) else {})
        merged_usage = _merge_usage([worker_usage, *judge_usages])
        review_pass_rate = (pass_count / judge_count) if judge_count else None
        avg_score = (sum(scores) / len(scores)) if scores else None
        passed_by_vote = bool(item.get("passed"))
        record = {
            "task_id": task_id,
            "module_name": function_name,
            "stage": str(item.get("stage") or "analyse"),
            "round": int(item.get("round") or index),
            "stage_round": int(item.get("stage_round") or item.get("round") or index),
            "status": status,
            "started_at": item.get("started_at"),
            "ended_at": item.get("ended_at"),
            "duration_ms": float(item.get("duration_ms") or 0.0),
            "worker": {
                "model": worker.get("model") if isinstance(worker, dict) else "",
                "session_file": worker.get("session_file") if isinstance(worker, dict) else "",
                "token_usage": worker_usage,
                "error": worker.get("error") if isinstance(worker, dict) else None,
                "artifact_paths": [worker.get("dataflow_file")] if isinstance(worker, dict) and worker.get("dataflow_file") else [],
            },
            "judges": normalized_judges,
            "metrics": {
                "review_pass_rate": review_pass_rate,
                "avg_judge_score": avg_score,
                "token_usage": merged_usage,
                "token_total": _token_total(merged_usage),
                "cost": float(merged_usage["cost"]),
                "passed_by_vote": passed_by_vote,
                "pass_count": pass_count,
                "total_judges": judge_count,
            },
            "module_completed": bool(item.get("module_completed") or passed_by_vote),
            "completion_reason": item.get("completion_reason") or ("passed" if passed_by_vote else status),
            "extra": {
                "function_name": function_name,
                "source_path": source_path,
                "feedback_to_workers": item.get("feedback_to_workers"),
                "best_worker_id": item.get("best_worker_id"),
                "worker_count": len(worker_results),
            },
        }
        function_names.add(function_name)
        if passed_by_vote:
            passed_rounds += 1
        total_duration_ms += float(record["duration_ms"] or 0.0)
        total_usage = _merge_usage([total_usage, merged_usage])
        stage = str(record["stage"])
        stage_item = stage_summary.setdefault(stage, {
            "round_count": 0,
            "passed_round_count": 0,
            "review_pass_rate_total": 0.0,
            "review_pass_rate_count": 0,
        })
        stage_item["round_count"] += 1
        stage_item["passed_round_count"] += 1 if passed_by_vote else 0
        if review_pass_rate is not None:
            stage_item["review_pass_rate_total"] += float(review_pass_rate)
            stage_item["review_pass_rate_count"] += 1
        records.append(record)

    if not records:
        return None, []

    latest_by_function: dict[str, dict] = {}
    for record in records:
        function_name = str(record.get("module_name") or "")
        current = latest_by_function.get(function_name)
        if current is None or int(record.get("stage_round") or 0) >= int(current.get("stage_round") or 0):
            latest_by_function[function_name] = record
    completed_function_count = sum(1 for record in latest_by_function.values() if record.get("metrics", {}).get("passed_by_vote"))
    failed_function_count = max(0, len(latest_by_function) - completed_function_count)

    summary = {
        "task_id": task_id,
        "task_status": result_payload.get("status") or task_status,
        "module_count": len(function_names),
        "completed_module_count": completed_function_count,
        "failed_module_count": failed_function_count,
        "round_count": len(records),
        "passed_round_count": passed_rounds,
        "function_count": len(function_names),
        "total_duration_ms": total_duration_ms,
        "avg_duration_ms": (total_duration_ms / len(records)) if records else 0.0,
        "total_token_usage": total_usage,
        "total_tokens": _token_total(total_usage),
        "total_cost": float(total_usage["cost"]),
        "generated_at": isoformat_local(now_local()),
        "stage_summary": {
            stage: {
                "round_count": int(item["round_count"]),
                "passed_round_count": int(item["passed_round_count"]),
                "avg_review_pass_rate": (
                    float(item["review_pass_rate_total"]) / int(item["review_pass_rate_count"])
                ) if int(item["review_pass_rate_count"]) > 0 else None,
            }
            for stage, item in stage_summary.items()
        },
        "effectiveness": {
            "final_round_pass_rate": (completed_function_count / len(latest_by_function)) if latest_by_function else 0.0,
        },
    }
    return summary, records


def _write_task_evaluation_files(row, result_payload: dict) -> None:
    run_root = _task_run_root(row)
    if not run_root:
        return
    summary, rounds = _build_evaluation_payload(row.task_id, row.status, result_payload)
    if summary is None:
        return
    for round_dir in run_root.glob("round_*"):
        if round_dir.is_dir():
            for path in round_dir.glob("*.json"):
                if path.name.endswith(".tmp"):
                    continue
                try:
                    path.unlink()
                except OSError:
                    pass
    for record in rounds:
        round_no = int(record.get("round") or 0)
        round_dir = run_root / f"round_{round_no:03d}"
        module_key = _safe_eval_key(str(record.get("module_name") or ""), "function")
        stage_key = _safe_eval_key(str(record.get("stage") or ""), "stage")
        _write_json_atomic(round_dir / f"{module_key}.{stage_key}.json", record)
    _write_json_atomic(run_root / "evaluation_summary.json", summary)


def _origin_payload(row) -> dict:
    task_origin_type = str(row.task_origin_type or "").strip() or "manual"
    parent_task_type = str(row.parent_task_type or "").strip() or None
    origin_label = (
        "二进制安全-源码扫描"
        if task_origin_type == "binary_security" and parent_task_type == "source"
        else "二进制安全-二进制类扫描"
        if task_origin_type == "binary_security"
        else "手动任务"
    )
    return {
        "task_origin_type": task_origin_type,
        "parent_project_id": row.parent_project_id,
        "parent_task_id": row.parent_task_id,
        "parent_task_type": parent_task_type,
        "parent_stage_name": row.parent_stage_name,
        "parent_stage_item_id": row.parent_stage_item_id,
        "parent_stage_item_key": row.parent_stage_item_key,
        "origin_label": origin_label,
        "parent_task_display": row.parent_task_id,
    }


# ─── Config from DB / file ────────────────────────────────────────────────────

def _load_svc_config():
    for p in [SERVICE_CONFIG_PATH, "/opt/dataflow_vuln_scan/config.example.json"]:
        if os.path.isfile(p):
            return load_service_config(p)
    raise RuntimeError(f"Service config not found: {SERVICE_CONFIG_PATH}")


def _load_svc_config_from_db(db: Session, project_id: str) -> "object":
    """Load the global service config (all projects share one config)."""
    try:
        from app.service.config_service import get_config_service
        from app.models import ServiceConfig as _ServiceConfig
        cfg_dict = get_config_service().get_config(db)
        for _k in ("updated_at", "project_id"):
            cfg_dict.pop(_k, None)
        svc = _ServiceConfig(**cfg_dict)
        if not svc.workers.agents:
            logger.warning("global config has empty worker agents, falling back to file defaults")
            svc.workers = _load_svc_config().workers
        svc.judges.agents = []
        return svc
    except Exception as _exc:
        logger.warning("_load_svc_config_from_db failed: %s, falling back to file", _exc)
        return _load_svc_config()


def _write_models_json_from_db(db: Session) -> None:
    """从配置中心拉取 LLM Provider 并写入 pi 的 models.json。"""
    try:
        from app.config import get_service_yaml
        from app.service.llm_provider_sync import sync_providers_to_pi
        svc_yaml = get_service_yaml()
        sync_providers_to_pi(
            base_url=svc_yaml.configcenter.base_url,
            token=svc_yaml.auth_service.service_machine_token,
            timeout=svc_yaml.configcenter.timeout,
            db=db,
        )
    except Exception as _exc:
        logger.warning("_write_models_json_from_db failed: %s", _exc, exc_info=True)


def generate_prompt_from_path(input_path: str) -> str:
    """Generate a default Chinese data flow analysis prompt from the input path."""
    path_lower = input_path.lower()
    if any(kw in path_lower for kw in (".c", ".cpp", ".cc", "source", "src")):
        subject = "C/C++ 源代码文件"
        action = "重点识别外部输入的污点传播路径、危险函数调用链及潜在注入点"
    elif any(kw in path_lower for kw in (".py", "python", "script")):
        subject = "Python 脚本文件"
        action = "追踪用户输入的数据流向，识别不安全的反序列化、命令注入及SQL注入风险"
    elif any(kw in path_lower for kw in ("firmware", "binary", "elf", "bin")):
        subject = "二进制/固件文件"
        action = "分析数据流传播路径，识别缓冲区溢出、格式字符串漏洞及权限提升路径"
    elif any(kw in path_lower for kw in ("java", ".jar", ".class")):
        subject = "Java 代码文件"
        action = "追踪输入数据流，识别反序列化漏洞、SSRF及XXE等安全风险"
    else:
        subject = "目标文件"
        action = "完成全面的数据流安全分析，识别污点传播路径与潜在漏洞"

    return (
        f"对路径 `{input_path}` 下的{subject}进行数据流安全分析，"
        f"{action}，并输出详细的数据流漏洞挖掘报告。"
    )


def _flush_stages(task_id: str, events: list[dict], owner_id: str | None = None, epoch: int | None = None, control_version: int | None = None) -> None:
    """将实时事件缓冲写入 DB，供前端轮询展示进度。"""
    from app.db.models import AppDvsTask as _Task
    from app.service.task_service import _run_db_write_with_retries

    try:
        def _op(_db: Session, _attempt: int):
            _r = _db.query(_Task).filter_by(task_id=task_id).first()
            if _r:
                if owner_id is not None and epoch is not None and control_version is not None:
                    if not (
                        _r.execution_owner_id == owner_id
                        and int(_r.execution_epoch or 0) == int(epoch)
                        and int(_r.control_version or 0) == int(control_version)
                    ):
                        return None
                _r.stages_json = {"events": [dict(e) for e in events]}
                flag_modified(_r, "stages_json")
                _db.commit()
            return None
        _run_db_write_with_retries("flush_stages", _op)
    except Exception as _exc:
        logger.warning("_flush_stages failed after retries: %s", _exc, exc_info=True)
