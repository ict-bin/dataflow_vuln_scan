"""漏洞 finding 持久化 (完整模式 mine_vulns + 自主模式 report_finding 脚本共用)。

保证两种模式产出格式完全一致: vuln-scan.sqlite 同 schema (finding_id=sha1(func|type|line),
INSERT OR REPLACE)、vulnerabilities/{id}/vulnerability-report.md 同模板、context.jsonl、
intake 上报、MySQL 漏洞计数同步。
"""
from __future__ import annotations

import hashlib
import json
import logging
import shutil
import time
from pathlib import Path
from typing import Any, Callable

from ..vuln_intake_reporter import report_finding_to_intake
from ..vuln_report_utils import format_vuln_report_md
from ..vuln_store import VulnFindingRecord, VulnScanStore
from ..service.task_vuln_stats import sync_vuln_count_from_local_store

logger = logging.getLogger("dvs.dataflow_v2.finding_store")


def _preview_text(value: object, *, limit: int = 160) -> str:
    text = " ".join(str(value or "").strip().split())
    if len(text) <= limit:
        return text
    return f"{text[: limit - 1]}…"


def _emit_finding_event(
    on_event: Callable[..., None] | None,
    event_type: str,
    *,
    level: str = "info",
    message: str,
    finding_id: str,
    function_name: str,
    task_id: str,
    extra: dict[str, Any] | None = None,
) -> None:
    if on_event is None:
        return
    payload = {
        "level": level,
        "message": message,
        "finding_id": finding_id,
        "function": function_name,
        "task_id": task_id,
    }
    if isinstance(extra, dict):
        payload.update(extra)
    try:
        on_event(event_type, **payload)
    except Exception:
        logger.debug("emit finding event failed: %s", event_type, exc_info=True)


def _mirror_finding_to_run_root(*, finding_dir: Path, vuln_root: Path) -> Path | None:
    """Mirror a runtime finding directory to task-root run/vulnerabilities.

    Runtime epoch directories may be symlinked to pod-local /tmp and are not
    directly readable from API pods. Mirror each finding eagerly to the stable
    task-root run/ path so the report endpoint can serve it during execution.
    """
    try:
        parts = vuln_root.parts
        if "run" not in parts or "epochs" not in parts:
            return None
        run_idx = parts.index("run")
        task_root = Path(*parts[:run_idx])
        mirror_dir = task_root / "run" / "vulnerabilities" / finding_dir.name
        if mirror_dir.exists():
            shutil.rmtree(mirror_dir, ignore_errors=True)
        mirror_dir.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(finding_dir, mirror_dir)
        return mirror_dir
    except Exception:
        logger.warning("mirror finding to run/vulnerabilities failed for %s", finding_dir, exc_info=True)
        return None


def _mirror_finding_to_output(*, finding_dir: Path, vuln_root: Path) -> Path | None:
    """Mirror a runtime finding directory to task-root output/vulnerabilities (NFS).

    output/ 在 NFS 上, 跨 pod 可读 (platform-vuln / vuln-verify-v2 / API pod 都能读)。
    run/epochs/NNNN 是符号链接到 worker pod 本地 /tmp, 其他 pod 读不到, 故上报给下游的
    报告路径必须指向 output/, 不能是 run/epochs。
    """
    try:
        parts = vuln_root.parts
        if "run" not in parts or "epochs" not in parts:
            return None
        run_idx = parts.index("run")
        task_root = Path(*parts[:run_idx])
        out_dir = task_root / "output" / "vulnerabilities" / finding_dir.name
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)
        out_dir.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(finding_dir, out_dir)
        return out_dir
    except Exception:
        logger.warning("mirror finding to output/vulnerabilities failed for %s", finding_dir, exc_info=True)
        return None


def persist_finding(
    *,
    graph_store: VulnScanStore,
    run_id: str,
    task_id: str,
    source_root: str,
    vuln_root: Path,
    func_file: str,
    func_name: str,
    func_description: str,
    item: dict,
    context_text: str,
    context_session_path: str,
    cfg_project_id: str = "",
    cfg_task_name: str = "",
    cfg_parent_task_name: str = "",
    cfg_parent_task_id: str = "",
    cfg_parent_task_type: str = "",
    cfg_task_origin_type: str = "",
    on_event: Callable[..., None] | None = None,
) -> str | None:
    """持久化一条 finding (与完整模式 mine_vulns 完全同格式)。

    - finding_id = vuln_<sha1(func|type|line)>[:16] (同完整模式)
    - vulnerabilities/{id}/vulnerability-report.md (format_vuln_report_md, 已合并污点传播路径段)
    - vulnerabilities/{id}/context.jsonl = 复制 context_session_path
    - vuln-scan.sqlite: analysis_runs + taint_nodes (FK) + vulnerability_findings (INSERT OR REPLACE)
    - intake 上报 (退避: 父任务 → 自身 task_id)
    - MySQL vuln 计数同步
    返回 finding_id; 失败返回 None。
    """
    fsrc = str(item.get("source_file") or func_file)
    ffn = str(item.get("function_name") or func_name)
    fline = str(item.get("line") or "")
    # 行号归一为 ±10 行范围 (防同漏洞不同行重复, 又不漏报不同位置的同类漏洞)
    try:
        _line_bucket = str(int(fline) // 10 * 10)  # 每 10 行一个 bucket, 280/281/285 -> 280
    except (ValueError, TypeError):
        _line_bucket = fline  # 非数字行号保留原值
    finding_id = f"vuln_{hashlib.sha1((ffn + '|' + str(item.get('vuln_type') or 'unknown') + '|' + _line_bucket).encode()).hexdigest()[:16]}"
    node = f"{fsrc}::{ffn}"

    fdir = vuln_root / finding_id
    fdir.mkdir(parents=True, exist_ok=True)
    (fdir / "vulnerability-report.md").write_text(
        format_vuln_report_md(item, finding_id, fsrc, ffn, fline, taint_context=context_text), encoding="utf-8")
    try:
        from ..copy_utils import safe_copyfile
        safe_copyfile(context_session_path, str(fdir / "context.jsonl"))
    except Exception as e:
        logger.warning("copy context session failed, write empty (src=%s): %s", context_session_path, e)
        (fdir / "context.jsonl").write_text("", encoding="utf-8")
    mirror_dir = _mirror_finding_to_run_root(finding_dir=fdir, vuln_root=vuln_root)
    output_mirror = _mirror_finding_to_output(finding_dir=fdir, vuln_root=vuln_root)
    # 上报/记录路径优先用 NFS output/ (跨 pod 可读); 退回 run/vulnerabilities 镜像; 再退回 epoch 本地 fdir
    nfs_fdir = output_mirror if output_mirror else (mirror_dir if mirror_dir else fdir)

    _exploit = item.get("exploitability")
    expl_str = json.dumps(_exploit, ensure_ascii=False) if isinstance(_exploit, (dict, list)) else str(_exploit or "")
    rec = VulnFindingRecord(
        finding_id=finding_id, run_id=run_id, node_id=node,
        source_file=fsrc, function_name=ffn, line=fline,
        vuln_type=str(item.get("vuln_type") or "unknown"),
        severity=str(item.get("severity") or "unknown"),
        title=str(item.get("title") or finding_id),
        summary=str(item.get("summary") or ""),
        evidence=str(item.get("evidence") or ""),
        exploitability=expl_str,
        confidence=float(item.get("confidence") or 0),
        output_dir=str(nfs_fdir),
        code_snippet=str(item.get("code_snippet") or ""),
        code_explanation=str(item.get("code_explanation") or ""),
        fix_suggestion=str(item.get("fix_suggestion") or ""))

    data = {
        "finding_id": finding_id,
        "run_id": run_id,
        "node_id": node,
        "source_file": fsrc,
        "function_name": ffn,
        "line": fline,
        "vuln_type": str(item.get("vuln_type") or "unknown"),
        "severity": str(item.get("severity") or "unknown"),
        "title": str(item.get("title") or finding_id),
        "summary": str(item.get("summary") or ""),
        "evidence": str(item.get("evidence") or ""),
        "exploitability": expl_str,
        "confidence": float(item.get("confidence") or 0),
        "output_dir": str(nfs_fdir),
        "code_snippet": str(item.get("code_snippet") or ""),
        "code_explanation": str(item.get("code_explanation") or ""),
        "fix_suggestion": str(item.get("fix_suggestion") or ""),
    }

    # FK 满足 + INSERT (同一 connection, 避免 FK 跨连接不可见)
    try:
        cols = list(data)
        with graph_store.connect() as conn:
            conn.execute("INSERT OR IGNORE INTO analysis_runs (run_id,task_id,root_file,root_function,source_root,status,started_at) VALUES (?,?,?,?,?,?,?)",
                         (run_id, task_id, fsrc, ffn, source_root, "completed", time.time()))
            conn.execute("INSERT OR IGNORE INTO taint_nodes (node_id,source_file,function_name,taint_kind,symbol,line,call_expr,description,parent_node_id,depth,context_session,run_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                         (node, fsrc, ffn, "vuln_site", fline, str(fline), "", func_description or "", "", 0, "", run_id))
            conn.execute(f"INSERT OR REPLACE INTO vulnerability_findings ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
                         [data[c] for c in cols])
    except Exception as exc:
        logger.warning("persist_finding authoritative sqlite insert failed: %s", exc, exc_info=True)
        _emit_finding_event(
            on_event,
            "vuln_finding_persist_failed",
            level="error",
            message=f"漏洞持久化失败: {finding_id}",
            finding_id=finding_id,
            function_name=ffn,
            task_id=task_id,
            extra={
                "error": str(exc),
                "stage": "authoritative_sqlite",
                "line": fline,
                "source_file": fsrc,
            },
        )
        return None

    _emit_finding_event(
        on_event,
        "vuln_finding_persisted",
        level="info",
        message=(
            f"发现漏洞并已落库: {data['title']} | 类型={data['vuln_type']} | "
            f"级别={data['severity']} | 位置={fsrc}:{fline} | 摘要={_preview_text(data['summary']) or '-'}"
        ),
        finding_id=finding_id,
        function_name=ffn,
        task_id=task_id,
        extra={
            "line": fline,
            "source_file": fsrc,
            "title": data["title"],
            "summary": data["summary"],
            "summary_preview": _preview_text(data["summary"]),
            "evidence_preview": _preview_text(data["evidence"]),
            "vuln_type": data["vuln_type"],
            "severity": data["severity"],
            "mirror_dir": str(mirror_dir) if mirror_dir else "",
        },
    )

    # MySQL 双写 finding 行: graph-view 优先读 MySQL dvs_vuln_findings, 缺此则前端漏洞图谱 0 findings
    _mysql = getattr(graph_store, "_mysql", None)
    if _mysql is not None:
        try:
            _mysql.insert_finding(**data)
        except Exception as exc:
            logger.warning("persist_finding mysql insert_finding failed: %s", exc, exc_info=True)
            _emit_finding_event(
                on_event,
                "vuln_finding_mirror_failed",
                level="warning",
                message=f"漏洞镜像写入 MySQL 失败: {finding_id}",
                finding_id=finding_id,
                function_name=ffn,
                task_id=task_id,
                extra={"error": str(exc), "stage": "mysql_mirror"},
            )

    # intake 上报 (退避: 父任务 → 自身; 失败不影响)
    _intake_report(run_id, task_id, source_root, nfs_fdir, rec, finding_id,
                   cfg_project_id, cfg_task_name, cfg_parent_task_name,
                   cfg_parent_task_id, cfg_parent_task_type, cfg_task_origin_type, on_event,
                   graph_store=graph_store)

    # MySQL 漏洞计数同步
    _sync_vuln_count_mysql(graph_store, run_id, task_id, finding_id=finding_id, function_name=ffn, on_event=on_event)
    return finding_id


def _intake_report(run_id, task_id, source_root, report_dir, rec, finding_id,
                   cfg_project_id, cfg_task_name, cfg_parent_task_name,
                   cfg_parent_task_id, cfg_parent_task_type, cfg_task_origin_type, on_event,
                   graph_store=None):
    try:
        res = report_finding_to_intake(
            project_id=cfg_project_id, task_id=task_id,
            task_name=cfg_task_name, parent_task_name=cfg_parent_task_name,
            parent_task_id=cfg_parent_task_id,
            parent_task_type=cfg_parent_task_type,
            task_origin_type=cfg_task_origin_type,
            finding=rec, source_root=source_root,
            report_path=str(report_dir / "vulnerability-report.md"),
            use_self_task_id=False)
        if str(res.get("status") or "") == "reported":
            _record_intake_result(graph_store=graph_store, run_id=run_id, task_id=task_id, finding_id=finding_id, rec=rec, res=res, on_event=on_event)
            return
        if _is_task_id_rejection(res):
            _emit_finding_event(
                on_event,
                "vuln_intake_fallback_self",
                level="warning",
                message=f"漏洞上报主任务被拒，回退自任务重试: {finding_id}",
                finding_id=finding_id,
                function_name=rec.function_name,
                task_id=task_id,
                extra={"stage": "intake_fallback_self", "error": str(res.get('error') or '')},
            )
            res2 = report_finding_to_intake(
                project_id=cfg_project_id, task_id=task_id,
                task_name=cfg_task_name, parent_task_name=cfg_parent_task_name,
                parent_task_id=cfg_parent_task_id, parent_task_type=cfg_parent_task_type,
                task_origin_type=cfg_task_origin_type, finding=rec, source_root=source_root,
                report_path=str(report_dir / "vulnerability-report.md"),
                use_self_task_id=True)
            _record_intake_result(graph_store=graph_store, run_id=run_id, task_id=task_id, finding_id=finding_id, rec=rec, res=res2, on_event=on_event)
            return
        _record_intake_result(graph_store=graph_store, run_id=run_id, task_id=task_id, finding_id=finding_id, rec=rec, res=res, on_event=on_event)
    except Exception as exc:
        logger.warning("persist_finding intake failed for %s: %s", finding_id, exc, exc_info=True)
        _emit_finding_event(
            on_event,
            "vuln_intake_report_failed",
            level="warning",
            message=f"漏洞上报失败: {finding_id}",
            finding_id=finding_id,
            function_name=rec.function_name,
            task_id=task_id,
            extra={"error": str(exc), "stage": "intake_exception"},
        )


def _is_task_id_rejection(res: dict) -> bool:
    if str(res.get("status") or "") != "failed":
        return False
    err = str(res.get("error") or "")
    low = err.lower()
    return ("不存在" in err) or ("does not exist" in low) \
        or ("not exist" in low) or ("not found" in low and "task" in low)


def _record_intake_result(*, graph_store, run_id, task_id, finding_id, rec, res, on_event):
    status = str(res.get("status") or "")
    case_id = str(res.get("case_id") or res.get("report_id") or "")
    # 回写 report_status 到 vuln-scan.sqlite (findings 表)
    if graph_store is not None:
        try:
            graph_store.update_finding_report_status(
                finding_id, status=status, case_id=case_id, task_id=task_id)
        except Exception:
            logger.debug("finding_store update_finding_report_status failed for %s", finding_id, exc_info=True)
    try:
        if on_event:
            duplicate = bool(res.get("duplicate"))
            report_url = str(res.get("url") or "")
            message = (
                f"漏洞上报成功: {rec.title or finding_id} | 类型={rec.vuln_type or 'unknown'} | "
                f"级别={rec.severity or 'unknown'} | 位置={rec.source_file}:{rec.line} | "
                f"case_id={case_id or '-'} | 摘要={_preview_text(rec.summary) or '-'}"
                if status == "reported"
                else (
                    f"漏洞上报失败: {rec.title or finding_id} | 类型={rec.vuln_type or 'unknown'} | "
                    f"级别={rec.severity or 'unknown'} | 位置={rec.source_file}:{rec.line} | "
                    f"status={status or '-'} | error={str(res.get('error') or '-')}"
                )
            )
            on_event(
                "vuln_intake_result",
                finding_id=finding_id,
                function=rec.function_name,
                status=status,
                case_id=case_id,
                duplicate=duplicate,
                report_url=report_url,
                level="info" if status == "reported" else "error",
                message=message,
                error=str(res.get("error") or ""),
                title=rec.title,
                summary=rec.summary,
                summary_preview=_preview_text(rec.summary),
                evidence_preview=_preview_text(rec.evidence),
                vuln_type=rec.vuln_type,
                severity=rec.severity,
                source_file=rec.source_file,
                line=rec.line,
            )
    except Exception:
        logger.warning("finding_store emit vuln_intake_result failed for %s", finding_id, exc_info=True)


def _sync_vuln_count_mysql(
    graph_store: VulnScanStore,
    run_id: str,
    task_id: str,
    *,
    finding_id: str,
    function_name: str,
    on_event: Callable[..., None] | None = None,
):
    try:
        # 直接用手里 local graph_store 计数, 不开 NFS sqlite (避免与周期同步
        # copy2 并发致 run/vuln-scan.sqlite 损坏)
        sync_vuln_count_from_local_store(graph_store, task_id)
    except Exception as exc:
        logger.warning("sync_vuln_count_from_local_store failed (task=%s): %s", task_id, exc, exc_info=True)
        _emit_finding_event(
            on_event,
            "vuln_snapshot_sync_failed",
            level="warning",
            message=f"漏洞任务快照同步失败: {finding_id}",
            finding_id=finding_id,
            function_name=function_name,
            task_id=task_id,
            extra={"error": str(exc), "run_id": run_id, "stage": "task_snapshot_sync"},
        )
