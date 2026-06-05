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
DEFAULT_BASE_URL = os.environ.get("DVS_VULN_ENGINE_BASE_URL", "http://secflow-platform-vuln")
DEFAULT_SUBMIT_PATH = os.environ.get("DVS_VULN_ENGINE_SUBMIT_PATH", "/api/vuln/public/intake/submissions")
DEFAULT_TIMEOUT = float(os.environ.get("DVS_VULN_ENGINE_TIMEOUT_SECONDS", "20"))
REPORTING_ENABLED = os.environ.get("DVS_VULN_ENGINE_REPORT_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"critical", "high", "medium", "low"}:
        return text
    if text in {"严重", "致命", "critical/high"}:
        return "critical"
    if text in {"高", "高危"}:
        return "high"
    if text in {"中", "中危"}:
        return "medium"
    if text in {"低", "低危"}:
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
        str(finding.line),
        finding.title,
    ])
    suffix = hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:10].upper()
    return f"DVS-{task_id[-8:]}-{suffix}"


def build_intake_payload(
    *,
    project_id: str,
    task_id: str,
    task_name: str = "",
    finding: VulnFindingRecord,
    source_root: str = "",
    report_path: str = "",
    taint_path_report_path: str = "",
) -> dict[str, Any]:
    """Convert a stored DVS finding into the vuln-platform intake schema."""
    report_id = _stable_report_id(project_id=project_id, task_id=task_id, finding=finding)
    report_text = _read_text(report_path) if report_path else ""
    taint_text = _read_text(taint_path_report_path, limit=120_000) if taint_path_report_path else ""
    source_file = str(finding.source_file or "").strip()
    line = str(finding.line or "").strip()
    locator = f"{source_file}:{line}" if line else source_file or finding.finding_id
    summary = (finding.summary or report_text or finding.title or finding.finding_id).strip()
    evidence = (finding.evidence or "").strip()
    reproduction_hint = (finding.exploitability or "").strip()
    fingerprint_raw = "|".join([project_id, source_file, line, finding.vuln_type, finding.title, evidence[:512]])
    artifacts: list[dict[str, Any]] = []
    if report_text:
        artifacts.append({
            "kind": "report",
            "name": "vulnerability-report.md",
            "path": report_path,
            "media_type": "text/markdown",
            "encoding": "utf-8",
            "content": report_text,
            "metadata": {"finding_id": finding.finding_id, "artifact_role": "vulnerability_report"},
        })
    if taint_text:
        artifacts.append({
            "kind": "report",
            "name": "taint-path-report.md",
            "path": taint_path_report_path,
            "media_type": "text/markdown",
            "encoding": "utf-8",
            "content": taint_text,
            "metadata": {"finding_id": finding.finding_id, "artifact_role": "taint_path"},
        })
    artifacts.append({
        "kind": "json",
        "name": "dvs-finding.json",
        "media_type": "application/json",
        "encoding": "utf-8",
        "content": json.dumps(asdict(finding), ensure_ascii=False, indent=2),
        "metadata": {"finding_id": finding.finding_id, "artifact_role": "structured_finding"},
    })
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
            "name": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "type": "service",
            "endpoint": os.environ.get("DVS_PUBLIC_ENDPOINT", "/api/app/dataflow-vuln-scan"),
            "instance_id": os.environ.get("HOSTNAME") or os.environ.get("POD_NAME") or "dvs-worker",
        },
        "subject": {
            "type": "dataflow_vulnerability",
            "locator": locator,
            "name": str(finding.title or locator),
        },
        "evidence": {
            "summary": (evidence or summary or finding.title)[:2000],
            "reproduction_hint": reproduction_hint[:2000],
            "references": [
                {"kind": "source_location", "source_file": source_file, "line": line},
                *([{"kind": "report", "path": report_path}] if report_path else []),
                *([{"kind": "taint_path", "path": taint_path_report_path}] if taint_path_report_path else []),
            ],
        },
        "artifacts": artifacts,
        "metadata": {
            "source": {
                "service_name": SERVICE_NAME,
                "service_id": SERVICE_NAME,
                "task_id": task_id,
                "task_name": task_name,
                "run_id": finding.run_id,
                "node_id": finding.node_id,
                "finding_id": finding.finding_id,
                "source_root": source_root,
                "source_file": source_file,
                "line": line,
                "reported_severity": _normalize_severity(finding.severity),
            },
            "dataflow_vuln_scan": {
                "graph_storage": "sqlite",
                "finding_id": finding.finding_id,
                "vuln_type": finding.vuln_type,
                "output_dir": finding.output_dir,
                "reporting_mode": "service_script",
            },
        },
    }


async def report_finding_to_intake(
    *,
    project_id: str,
    task_id: str,
    task_name: str = "",
    finding: VulnFindingRecord,
    source_root: str = "",
    report_path: str = "",
    taint_path_report_path: str = "",
) -> dict[str, Any]:
    """Submit a DVS finding to the vuln-platform intake endpoint.

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
        finding=finding,
        source_root=source_root,
        report_path=report_path,
        taint_path_report_path=taint_path_report_path,
    )
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            response = await client.post(
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
        return {
            "status": "failed",
            "enabled": True,
            "report_id": payload.get("report_id"),
            "error": str(exc),
            "url": url,
        }
