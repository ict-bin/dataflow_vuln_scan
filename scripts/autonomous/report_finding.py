#!/usr/bin/env python3
"""自主模式服务工具: report_finding '<finding JSON>'

LLM 发现漏洞即调 → 即写即包 (与完整模式 mine_vulns 同格式: vuln-scan.sqlite +
vulnerabilities/{id}/*.md + intake 上报 + MySQL 计数)。复用 finding_store.persist_finding。

环境变量:
  DVS_RUN_DIR        - 任务 run 目录
  DVS_V2_DB_DIR      - dataflow-v2 目录
  DVS_SOURCE_ROOT    - 源码根
  DVS_TASK_ID        - 任务 id
  DVS_RUN_ID         - run id (同 task_id)
  DVS_PROJECT_ID / DVS_TASK_NAME / DVS_PARENT_TASK_ID / DVS_PARENT_TASK_TYPE /
  DVS_PARENT_TASK_NAME / DVS_TASK_ORIGIN_TYPE  - intake 上报元数据
"""
import json
import os
import sys

RUN_DIR = os.environ.get("DVS_RUN_DIR") or ""
V2_DB_DIR = os.environ.get("DVS_V2_DB_DIR") or os.path.join(RUN_DIR, "dataflow-v2")
SOURCE_ROOT = os.environ.get("DVS_SOURCE_ROOT") or "/data/target"
TASK_ID = os.environ.get("DVS_TASK_ID") or ""
RUN_ID = os.environ.get("DVS_RUN_ID") or TASK_ID
GRAPH_DB = os.path.join(RUN_DIR, "vuln-scan.sqlite")
VULN_ROOT = os.path.join(RUN_DIR, "vulnerabilities")
CONTEXT_SESSION = os.environ.get("DVS_CONTEXT_SESSION") or ""


def main():
    if len(sys.argv) < 2:
        print("用法: report_finding '<JSON>' (含 vuln_type/line/function_name/source_file/...)", file=sys.stderr)
        sys.exit(2)
    try:
        item = json.loads(sys.argv[1])
        if not isinstance(item, dict):
            raise ValueError("finding 必须是 JSON 对象")
    except Exception as e:
        print(f"[report_finding] JSON 解析失败: {e}", file=sys.stderr)
        sys.exit(2)
    sys.path.insert(0, "/opt/dataflow_vuln_scan")
    from app.vuln_store import VulnScanStore
    from app.dataflow_v2.finding_store import persist_finding
    from pathlib import Path
    gs = VulnScanStore(GRAPH_DB)
    func_file = str(item.get("source_file") or "")
    func_name = str(item.get("function_name") or "")
    func_desc = str(item.get("function_description") or "")
    fid = persist_finding(
        graph_store=gs, run_id=RUN_ID, task_id=TASK_ID, source_root=SOURCE_ROOT,
        vuln_root=Path(VULN_ROOT), func_file=func_file, func_name=func_name,
        func_description=func_desc, item=item,
        context_text=str(item.get("taint_path") or ""), context_session_path=CONTEXT_SESSION,
        cfg_project_id=os.environ.get("DVS_PROJECT_ID", ""),
        cfg_task_name=os.environ.get("DVS_TASK_NAME", ""),
        cfg_parent_task_name=os.environ.get("DVS_PARENT_TASK_NAME", ""),
        cfg_parent_task_id=os.environ.get("DVS_PARENT_TASK_ID", ""),
        cfg_parent_task_type=os.environ.get("DVS_PARENT_TASK_TYPE", ""),
        cfg_task_origin_type=os.environ.get("DVS_TASK_ORIGIN_TYPE", ""))
    if fid:
        print(json.dumps({"status": "ok", "finding_id": fid}, ensure_ascii=False))
    else:
        print(json.dumps({"status": "failed"}, ensure_ascii=False), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
