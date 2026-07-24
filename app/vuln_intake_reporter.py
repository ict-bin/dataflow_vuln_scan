"""Deterministic vulnerability-intake reporting for DVS findings.

This module intentionally performs the reporting in service-side Python code instead of
asking the LLM/agent to call platform APIs.  The LLM only emits a structured finding;
DVS normalizes it and submits it to the SecFlow vulnerability intake service.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from .config import get_service_yaml
from .vuln_store import VulnFindingRecord

SERVICE_NAME = "secflow-app-dataflow-vuln-scan"
SERVICE_VERSION = os.environ.get("BUILD_VERSION", "unknown")
# vuln-platform intake 的 reporter.name 是注册的工具 ID (toolid),
# 取自 secflow-platform-tool-registry 的 Tool.id; 引擎路由按此值匹配
SOURCE_ID = os.environ.get("DVS_VULN_SOURCE_ID", "kg_source_vuln_scan_e2e")
DEFAULT_BASE_URL = os.environ.get("DVS_VULN_ENGINE_BASE_URL", "http://secflow-platform-vuln")
DEFAULT_SUBMIT_PATH = os.environ.get("DVS_VULN_ENGINE_SUBMIT_PATH", "/api/vuln/public/intake/submissions")
DEFAULT_TIMEOUT = float(os.environ.get("DVS_VULN_ENGINE_TIMEOUT_SECONDS", "20"))
REPORTING_ENABLED = os.environ.get("DVS_VULN_ENGINE_REPORT_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_severity(value: Any) -> str:
    """Normalize severity to Literal['critical','high','medium','low'].

    The vuln-platform schema only accepts these four values.
    'info' and unknown values are upgraded to 'low'.
    """
    text = str(value or "").strip().lower()
    if text in {"critical", "high", "medium", "low"}:
        return text
    if text in {"严重", "致命", "critical/high"}:
        return "critical"
    if text in {"高", "高危"}:
        return "high"
    if text in {"中", "中危"}:
        return "medium"
    if text in {"低", "低危", "info"}:
        return "low"
    return "medium"


def _confidence_percent(value: Any) -> int:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 60
    if number <= 1:
        number *= 100
    return max(0, min(100, int(round(number))))


def _read_text(path: str | Path, *, limit: int = 200_000) -> str:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    if len(text) > limit:
        return text[:limit] + "\n\n...[truncated by DVS reporter]"
    return text


def _stable_report_id(*, project_id: str, task_id: str, finding: VulnFindingRecord) -> str:
    raw = "|".join([
        project_id,
        task_id,
        finding.finding_id,
        finding.source_file,
        finding.function_name,
        str(finding.line),
        finding.title,
    ])
    suffix = hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:10].upper()
    return f"DVS-{task_id[-8:]}-{suffix}"


def _artifact_item(
    kind: str,
    name: str,
    content: str,
    *,
    path: str = "",
    media_type: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a single artifact item with size/sha256/encoding computed."""
    content_bytes = content.encode("utf-8", errors="replace")
    return {
        "kind": kind,
        "name": name,
        "path": path,
        "media_type": media_type,
        "encoding": "utf-8",
        "size": len(content_bytes),
        "sha256": hashlib.sha256(content_bytes).hexdigest(),
        "content": content,
        "metadata": metadata or {},
    }


def build_intake_payload(
    *,
    project_id: str,
    task_id: str,
    task_name: str = "",
    parent_task_name: str = "",
    parent_task_id: str = "",
    parent_task_type: str = "",
    task_origin_type: str = "",
    finding: VulnFindingRecord,
    source_root: str = "",
    report_path: str = "",
    taint_path_report_path: str = "",
    use_self_task_id: bool = False,
) -> dict[str, Any]:
    """Convert a stored DVS finding into the vuln-platform intake schema.

    use_self_task_id=True 时强制用 DVS 自身 task_id 作为 metadata.source.task_id
    (父任务被删/不可挂载时的退避重试)。
    """
    # 编排器下发的任务 (task_origin_type != manual) 用 parent_task_id (编排器);
    # 手动创建或退避重试时用 DVS task_id
    if use_self_task_id:
        effective_task_id = task_id
    elif parent_task_id and task_origin_type and task_origin_type != "manual":
        effective_task_id = parent_task_id
    else:
        effective_task_id = task_id
    report_id = _stable_report_id(project_id=project_id, task_id=effective_task_id, finding=finding)
    report_text = _read_text(report_path) if report_path else ""
    taint_text = _read_text(taint_path_report_path, limit=120_000) if taint_path_report_path else ""
    source_file = str(finding.source_file or "").strip()
    function_name = str(finding.function_name or "").strip()
    line = str(finding.line or "").strip()
    locator_parts = [source_file]
    if function_name:
        locator_parts.append(function_name)
    if line:
        locator_parts.append(line)
    locator = ":".join([p for p in locator_parts if p]) or finding.finding_id
    summary = (finding.summary or report_text or finding.title or finding.finding_id).strip()
    evidence = (finding.evidence or "").strip()
    reproduction_hint = (finding.exploitability or "").strip()
    fingerprint_raw = "|".join([project_id, source_file, function_name, line, finding.vuln_type, finding.title, evidence[:512]])
    artifacts: list[dict[str, Any]] = []
    if report_text:
        artifacts.append(_artifact_item(
            kind="report", name="vulnerability-report.md", content=report_text,
            path=report_path, media_type="text/markdown",
            metadata={"finding_id": finding.finding_id, "artifact_role": "vulnerability_report"},
        ))
    if taint_text:
        artifacts.append(_artifact_item(
            kind="report", name="taint-path-report.md", content=taint_text,
            path=taint_path_report_path, media_type="text/markdown",
            metadata={"finding_id": finding.finding_id, "artifact_role": "taint_path"},
        ))
    finding_json = json.dumps(asdict(finding), ensure_ascii=False, indent=2)
    artifacts.append(_artifact_item(
        kind="json", name="dvs-finding.json", content=finding_json,
        media_type="application/json",
        metadata={"finding_id": finding.finding_id, "artifact_role": "structured_finding"},
    ))
    return {
        "project_id": project_id,
        "report_id": report_id,
        "title": str(finding.title or f"DVS 数据流漏洞疑点 {finding.finding_id}")[:256],
        "summary": summary[:4000] if summary else None,
        "severity": _normalize_severity(finding.severity),
        "cvss_score": 0.0,
        "confidence": _confidence_percent(finding.confidence),
        "state": "suspected",
        "category": "dataflow",
        "rule_id": str(finding.vuln_type or "dataflow").strip() or None,
        "rule_name": str(finding.vuln_type or "数据流漏洞").strip() or None,
        "fingerprint": hashlib.sha256(fingerprint_raw.encode("utf-8", errors="replace")).hexdigest(),
        "reported_at": _now_iso(),
        "reporter": {
            "name": SOURCE_ID,
            "version": SERVICE_VERSION,
            "type": "service",
            "endpoint": os.environ.get("DVS_PUBLIC_ENDPOINT", "/api/app/dataflow-vuln-scan"),
            "instance_id": os.environ.get("HOSTNAME") or os.environ.get("POD_NAME") or "dvs-worker",
        },
        "subject": {
            "type": "dataflow_vulnerability",
            "source_root": source_root or "",
            "locator": locator,
            "name": str(finding.title or locator),
            "version": SERVICE_VERSION,
        },
        "evidence": {
            "summary": (evidence or summary or finding.title)[:2000],
            "reproduction_hint": reproduction_hint[:2000],
            "references": [
                {"kind": "source_location", "source_file": source_file, "function_name": function_name, "line": line},
                *([{"kind": "report", "path": report_path}] if report_path else []),
                *([{"kind": "taint_path", "path": taint_path_report_path}] if taint_path_report_path else []),
            ],
        },
        "artifacts": artifacts,
        **({} if not report_text.strip() else {"raw_report": {
            "markdown": report_text,
            "title": str(finding.title or finding.finding_id),
            "report_id": report_id,
            "source": "DVS dataflow_vuln_scan",
            "reported_at": _now_iso(),
        }}),
        "metadata": {
            "source": {
                "service_name": SERVICE_NAME,
                "service_id": SOURCE_ID,
                "task_id": effective_task_id,
                "parent_task_id": parent_task_id,
                "parent_task_name": parent_task_name or task_name or "",
                "task_name": task_name,
                "run_id": finding.run_id,
                "node_id": finding.node_id,
                "finding_id": finding.finding_id,
                "source_root": source_root,
                "source_file": source_file,
                "function_name": function_name,
                "line": line,
                "reported_severity": _normalize_severity(finding.severity),
            },
            "dataflow_vuln_scan": {
                "finding_id": finding.finding_id,
                "function_name": function_name,
                "vuln_type": finding.vuln_type,
                "output_dir": finding.output_dir,
                "reporting_mode": "service_script",
            },
        },
    }


def report_finding_to_intake(
    *,
    project_id: str,
    task_id: str,
    task_name: str = "",
    parent_task_name: str = "",
    parent_task_id: str = "",
    parent_task_type: str = "",
    task_origin_type: str = "",
    finding: VulnFindingRecord,
    source_root: str = "",
    report_path: str = "",
    taint_path_report_path: str = "",
    use_self_task_id: bool = False,
) -> dict[str, Any]:
    """Submit a DVS finding to the vuln-platform intake endpoint.

    use_self_task_id=True 强制用 DVS 自身 task_id (父任务退避重试用)。
    Returns a status dict and never raises for ordinary HTTP/configuration errors.
    """
    if not REPORTING_ENABLED:
        return {"status": "disabled", "enabled": False}
    if not project_id:
        return {"status": "skipped", "enabled": True, "error": "missing project_id"}
    cfg = get_service_yaml()
    token = os.environ.get("DVS_VULN_ENGINE_TOKEN") or cfg.auth_service.service_machine_token
    if not token:
        return {"status": "failed", "enabled": True, "error": "missing service machine token"}
    url = f"{DEFAULT_BASE_URL.rstrip('/')}{DEFAULT_SUBMIT_PATH}"
    payload = build_intake_payload(
        project_id=project_id,
        task_id=task_id,
        task_name=task_name,
        parent_task_name=parent_task_name,
        parent_task_id=parent_task_id,
        parent_task_type=parent_task_type,
        task_origin_type=task_origin_type,
        finding=finding,
        source_root=source_root,
        report_path=report_path,
        taint_path_report_path=taint_path_report_path,
        use_self_task_id=use_self_task_id,
    )
    try:
        with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
            response = client.post(
                url,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=payload,
            )
            response.raise_for_status()
            body = response.json()
        return {
            "status": "reported",
            "enabled": True,
            "report_id": payload.get("report_id"),
            "case_id": body.get("id") or body.get("case_id"),
            "duplicate": bool(body.get("duplicate")),
            "response": body,
        }
    except Exception as exc:
        detail = str(exc)
        try:
            if hasattr(exc, 'response') and exc.response is not None:
                detail += " | body: " + str(exc.response.text)[:500]
        except Exception:
            logger.warning("vuln_intake_reporter: failed to extract response body", exc_info=True)
        return {
            "status": "failed",
            "enabled": True,
            "report_id": payload.get("report_id"),
            "error": detail,
            "url": url,
        }
