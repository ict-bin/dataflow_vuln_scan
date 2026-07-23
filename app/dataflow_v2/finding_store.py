"""漏洞 finding 持久化 (完整模式 mine_vulns + 自主模式 report_finding 脚本共用)。

保证两种模式产出格式完全一致: vuln-scan.sqlite 同 schema (finding_id=sha1(func|type|line),
INSERT OR REPLACE)、vulnerabilities/{id}/vulnerability-report.md 同模板、context.jsonl、
intake 上报、MySQL 漏洞计数同步。
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Callable

from ..vuln_intake_reporter import report_finding_to_intake
from ..vuln_report_utils import format_vuln_report_md
from ..vuln_store import VulnFindingRecord, VulnScanStore

logger = logging.getLogger("dvs.dataflow_v2.finding_store")


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
    - vulnerabilities/{id}/vulnerability-report.md (format_vuln_report_md 同模板)
    - vulnerabilities/{id}/taint-path-report.md = context_text
    - vulnerabilities/{id}/context.jsonl = 复制 context_session_path
    - vuln-scan.sqlite: analysis_runs + taint_nodes (FK) + vulnerability_findings (INSERT OR REPLACE)
    - intake 上报 (退避: 父任务 → 自身 task_id)
    - MySQL vuln 计数同步
    返回 finding_id; 失败返回 None。
    """
    fsrc = str(item.get("source_file") or func_file)
    ffn = str(item.get("function_name") or func_name)
    fline = str(item.get("line") or "")
    finding_id = f"vuln_{hashlib.sha1((ffn + '|' + str(item.get('vuln_type') or 'unknown') + '|' + fline).encode()).hexdigest()[:16]}"
    node = f"{fsrc}::{ffn}"

    fdir = vuln_root / finding_id
    fdir.mkdir(parents=True, exist_ok=True)
    (fdir / "vulnerability-report.md").write_text(
        format_vuln_report_md(item, finding_id, fsrc, ffn, fline), encoding="utf-8")
    (fdir / "taint-path-report.md").write_text(context_text, encoding="utf-8")
    try:
        from ..copy_utils import safe_copyfile
        safe_copyfile(context_session_path, str(fdir / "context.jsonl"))
    except Exception:
        (fdir / "context.jsonl").write_text("", encoding="utf-8")

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
        output_dir=str(fdir),
        code_snippet=str(item.get("code_snippet") or ""),
        code_explanation=str(item.get("code_explanation") or ""),
        fix_suggestion=str(item.get("fix_suggestion") or ""))

    # FK 满足 + INSERT (同一 connection, 避免 FK 跨连接不可见)
    try:
        data = {'finding_id': finding_id, 'run_id': run_id, 'node_id': node,
                'source_file': fsrc, 'function_name': ffn, 'line': fline,
                'vuln_type': str(item.get('vuln_type') or 'unknown'),
                'severity': str(item.get('severity') or 'unknown'),
                'title': str(item.get('title') or finding_id),
                'summary': str(item.get('summary') or ''),
                'evidence': str(item.get('evidence') or ''),
                'exploitability': expl_str,
                'confidence': float(item.get('confidence') or 0),
                'output_dir': str(fdir),
                'code_snippet': str(item.get('code_snippet') or ''),
                'code_explanation': str(item.get('code_explanation') or ''),
                'fix_suggestion': str(item.get('fix_suggestion') or '')}
        cols = list(data)
        with graph_store.connect() as conn:
            conn.execute("INSERT OR IGNORE INTO analysis_runs (run_id,task_id,root_file,root_function,source_root,status,started_at) VALUES (?,?,?,?,?,?,?)",
                         (run_id, task_id, fsrc, ffn, source_root, "completed", time.time()))
            conn.execute("INSERT OR IGNORE INTO taint_nodes (node_id,source_file,function_name,taint_kind,symbol,line,call_expr,description,parent_node_id,depth,context_session,run_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                         (node, fsrc, ffn, "vuln_site", fline, str(fline), "", func_description or "", "", 0, "", run_id))
            conn.execute(f"INSERT OR REPLACE INTO vulnerability_findings ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
                         [data[c] for c in cols])
    except Exception as _fe:
        logger.warning("persist_finding FK+insert failed: %s", _fe, exc_info=True)

    # MySQL 双写 finding 行: graph-view 优先读 MySQL dvs_vuln_findings, 缺此则前端漏洞图谱 0 findings
    _mysql = getattr(graph_store, "_mysql", None)
    if _mysql is not None:
        try:
            _mysql.insert_finding(**data)
        except Exception as _me:
            logger.debug("persist_finding mysql insert_finding failed: %s", _me, exc_info=True)

    # intake 上报 (退避: 父任务 → 自身; 失败不影响)
    _intake_report(run_id, task_id, source_root, fdir, rec, finding_id,
                   cfg_project_id, cfg_task_name, cfg_parent_task_name,
                   cfg_parent_task_id, cfg_parent_task_type, cfg_task_origin_type, on_event,
                   graph_store=graph_store)

    # MySQL 漏洞计数同步
    _sync_vuln_count_mysql(graph_store, run_id, task_id)
    return finding_id


def _intake_report(run_id, task_id, source_root, fdir, rec, finding_id,
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
            report_path=str(fdir / "vulnerability-report.md"),
            taint_path_report_path=str(fdir / "taint-path-report.md"),
            use_self_task_id=False)
        if str(res.get("status") or "") == "reported":
            _record_intake_result(graph_store=graph_store, run_id=run_id, finding_id=finding_id, rec=rec, res=res, on_event=on_event)
            return
        if _is_task_id_rejection(res):
            res2 = report_finding_to_intake(
                project_id=cfg_project_id, task_id=task_id,
                task_name=cfg_task_name, parent_task_name=cfg_parent_task_name,
                parent_task_id=cfg_parent_task_id, parent_task_type=cfg_parent_task_type,
                task_origin_type=cfg_task_origin_type, finding=rec, source_root=source_root,
                report_path=str(fdir / "vulnerability-report.md"),
                taint_path_report_path=str(fdir / "taint-path-report.md"),
                use_self_task_id=True)
            _record_intake_result(graph_store=graph_store, run_id=run_id, finding_id=finding_id, rec=rec, res=res2, on_event=on_event)
            return
        _record_intake_result(graph_store=graph_store, run_id=run_id, finding_id=finding_id, rec=rec, res=res, on_event=on_event)
    except Exception as exc:
        logger.warning("persist_finding intake failed for %s: %s", finding_id, exc, exc_info=True)


def _is_task_id_rejection(res: dict) -> bool:
    if str(res.get("status") or "") != "failed":
        return False
    err = str(res.get("error") or "")
    low = err.lower()
    return ("不存在" in err) or ("does not exist" in low) \
        or ("not exist" in low) or ("not found" in low and "task" in low)


def _record_intake_result(*, graph_store, run_id, finding_id, rec, res, on_event):
    status = str(res.get("status") or "")
    case_id = str(res.get("case_id") or res.get("report_id") or "")
    # 回写 report_status 到 vuln-scan.sqlite (findings 表)
    if graph_store is not None:
        try:
            graph_store.update_finding_report_status(
                finding_id, status=status, case_id=case_id)
        except Exception:
            logger.debug("finding_store update_finding_report_status failed for %s", finding_id, exc_info=True)
    try:
        if on_event:
            on_event("vuln_intake_result", finding_id=finding_id,
                     function=rec.function_name, status=status, case_id=case_id)
    except Exception:
        pass


def _sync_vuln_count_mysql(graph_store: VulnScanStore, run_id: str, task_id: str):
    try:
        with graph_store.connect() as _conn:
            _tot = _conn.execute("SELECT count(*) FROM vulnerability_findings WHERE run_id=?", (run_id,)).fetchone()[0]
            _rep = _conn.execute("SELECT count(*) FROM vulnerability_findings WHERE run_id=? AND report_status='reported'", (run_id,)).fetchone()[0]
        from app.db import get_db
        from app.db.models import AppDvsTask
        _db = next(get_db())
        try:
            _row = _db.query(AppDvsTask).filter_by(task_id=task_id).first()
            if _row is not None and (_row.vuln_total_count != _tot or _row.vuln_reported_count != _rep):
                _row.vuln_total_count = _tot
                _row.vuln_reported_count = _rep
                _row.vuln_unreported_count = _tot - _rep
                _db.commit()
        finally:
            _db.close()
    except Exception:
        pass
