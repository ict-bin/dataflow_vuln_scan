"""dagflow finding 存储 + 去重 (兼容现有 vuln_store 上报)。

设计: docs/design-vuln-mining.md §5 (finding_id=func+type+line, 跨段去重 sink 近者优先)。
复用 VulnScanStore (上报层, 非 V2 模式逻辑) 写 vuln-scan.sqlite, 兼容 intake/MySQL count-sync。
"""
from __future__ import annotations
import hashlib, logging
from typing import Any
from .models import Finding

logger = logging.getLogger("dvs.dagflow.finding_store")


def finding_id(function_name: str, vuln_type: str, line: str) -> str:
    """sha1(func|type|line)[:16]. 同漏洞同 id -> INSERT OR REPLACE 去重。"""
    return "vuln_" + hashlib.sha1(
        f"{function_name}|{vuln_type}|{line}".encode()).hexdigest()[:16]


def save_findings(vuln_store: Any, findings: list[Finding], *, run_id: str,
                  node_id: str, func: Any, output_dir: str = "") -> int:
    """落库 findings 到 vuln-scan.sqlite (VulnScanStore, 兼容上报)。

    finding_id 去重 (INSERT OR REPLACE): 同 func+type+line 合并 (跨段 sink 近者优先由调用方保证只报一次)。
    返回保存数。
    """
    from ..vuln_store import VulnFindingRecord
    n = 0
    for f in findings:
        fid = finding_id(f.location_func or getattr(func, "name", ""), f.vuln_type, f.location_line)
        rec = VulnFindingRecord(
            finding_id=fid, run_id=run_id, node_id=node_id,
            source_file=getattr(func, "file", ""), function_name=f.location_func or func.name,
            line=f.location_line, vuln_type=f.vuln_type, severity=f.severity,
            title=f.title, summary=f.summary, evidence=f.evidence,
            exploitability=str(f.exploitability) if not isinstance(f.exploitability, str) else f.exploitability,
            confidence=f.confidence, output_dir=output_dir)
        try:
            vuln_store.add_finding(rec)
            n += 1
        except Exception as e:
            logger.exception("save finding %s failed: %s", fid, e)
    return n
