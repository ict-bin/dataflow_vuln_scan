#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


REMOTE_QUERY_SCRIPT = r"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from sqlalchemy import text

from app.config import load_service_yaml
from app.db import init_db
from app import db as dbmod


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--fileserver-root", default="/data")
    args = parser.parse_args()

    cfg = load_service_yaml()
    init_db(cfg.database.url, cfg.database.pool_size, cfg.database.max_overflow)

    query = text(
        '''
        SELECT
            task_id,
            project_id,
            task_name,
            status,
            vuln_total_count,
            output_path,
            created_at,
            updated_at
        FROM secflow_app_dvs_tasks
        WHERE is_deleted = 0
          AND task_name LIKE :pattern
        ORDER BY created_at DESC, id DESC
        '''
    )

    items = []
    fileserver_root = Path(str(args.fileserver_root or "/data")).resolve()
    with dbmod._SessionLocal() as db:
        rows = db.execute(query, {"pattern": f"{args.prefix}%"}).mappings().all()
        for row in rows:
            output_path = str(row.get("output_path") or "").strip()
            task_id = str(row.get("task_id") or "").strip()
            vuln_dir = Path(output_path) / task_id / "output" / "vulnerabilities" if output_path and task_id else None
            exists = bool(vuln_dir and vuln_dir.is_dir())
            relative_archive_path = None
            if exists:
                try:
                    relative_archive_path = str(vuln_dir.resolve().relative_to(fileserver_root).as_posix())
                except Exception:
                    relative_archive_path = None
            items.append(
                {
                    "task_id": task_id,
                    "project_id": str(row.get("project_id") or "").strip(),
                    "task_name": str(row.get("task_name") or "").strip(),
                    "status": str(row.get("status") or "").strip(),
                    "vuln_total_count": int(row.get("vuln_total_count") or 0),
                    "output_path": output_path,
                    "vulnerabilities_dir": str(vuln_dir) if vuln_dir else "",
                    "vulnerabilities_dir_exists": exists,
                    "relative_archive_path": relative_archive_path,
                    "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
                    "updated_at": row.get("updated_at").isoformat() if row.get("updated_at") else None,
                }
            )

    print(json.dumps({"prefix": args.prefix, "items": items}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="导出指定 task_name 前缀的 DVS 任务 output/vulnerabilities 目录归档（通过 kubectl 从 env1 读取）。"
    )
    parser.add_argument("--prefix", default="OH_REPO_11", help="按 task_name 前缀筛选，默认 OH_REPO_11")
    parser.add_argument("--kubeconfig", default="/home/runshine/.kube/config", help="目标集群 kubeconfig")
    parser.add_argument("--namespace", default="secflow-ns", help="Kubernetes namespace")
    parser.add_argument("--deployment", default="secflow-app-dataflow-vuln-scan", help="用于 exec 的 deployment 名称")
    parser.add_argument("--fileserver-root", default="/data", help="Pod 内 fileserver 根目录，默认 /data")
    parser.add_argument("--output-dir", default="./exports", help="本地输出目录")
    parser.add_argument("--archive-name", default="", help="本地归档文件名；默认自动生成")
    parser.add_argument("--manifest-name", default="", help="本地 manifest 文件名；默认自动生成")
    parser.add_argument("--dry-run", action="store_true", help="只生成 manifest 和摘要，不实际导出 tar.gz")
    return parser.parse_args()


def run_kubectl_exec(kubeconfig: str, namespace: str, deployment: str, stdin_bytes: bytes, extra_args: list[str]) -> subprocess.CompletedProcess:
    cmd = [
        "kubectl",
        "--kubeconfig",
        kubeconfig,
        "-n",
        namespace,
        "exec",
        "-i",
        f"deploy/{deployment}",
        "--",
        *extra_args,
    ]
    return subprocess.run(cmd, input=stdin_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def query_tasks(args: argparse.Namespace) -> dict:
    payload = REMOTE_QUERY_SCRIPT.encode("utf-8")
    proc = run_kubectl_exec(
        args.kubeconfig,
        args.namespace,
        args.deployment,
        payload,
        [
            "python",
            "-",
            "--prefix",
            args.prefix,
            "--fileserver-root",
            args.fileserver_root,
        ],
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(proc.returncode)
    return json.loads(proc.stdout.decode("utf-8"))


def build_manifest(query_result: dict, fileserver_root: str) -> dict:
    items = list(query_result.get("items") or [])
    exportable = []
    skipped = []
    for item in items:
        rel = item.get("relative_archive_path")
        if item.get("vulnerabilities_dir_exists") and rel:
            exportable.append(item)
        else:
            reason = "missing_vulnerabilities_dir"
            if item.get("vulnerabilities_dir_exists") and not rel:
                reason = "outside_fileserver_root"
            skipped.append(
                {
                    "task_id": item.get("task_id"),
                    "project_id": item.get("project_id"),
                    "task_name": item.get("task_name"),
                    "status": item.get("status"),
                    "vuln_total_count": item.get("vuln_total_count"),
                    "vulnerabilities_dir": item.get("vulnerabilities_dir"),
                    "reason": reason,
                }
            )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "prefix": query_result.get("prefix"),
        "fileserver_root": fileserver_root,
        "matched_task_count": len(items),
        "exportable_task_count": len(exportable),
        "skipped_task_count": len(skipped),
        "exportable_tasks": exportable,
        "skipped_tasks": skipped,
    }


def default_name(prefix: str, suffix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_prefix = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in prefix)
    return f"{safe_prefix.lower()}_dvs_vulnerabilities_{stamp}{suffix}"


def write_manifest(path: Path, manifest: dict) -> None:
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def export_archive(args: argparse.Namespace, manifest: dict, archive_path: Path) -> None:
    rel_paths = []
    for item in manifest["exportable_tasks"]:
        rel = str(item["relative_archive_path"] or "").strip().lstrip("/")
        if rel:
            rel_paths.append(rel)
    rel_paths = sorted(set(rel_paths))
    if not rel_paths:
        raise SystemExit("没有可导出的 vulnerabilities 目录")

    list_payload = ("\n".join(rel_paths) + "\n").encode("utf-8")
    fileserver_root = args.fileserver_root.rstrip("/") or "/"
    tar_cmd = (
        "tmp=$(mktemp); "
        "cat > \"$tmp\"; "
        f"tar -C {shlex.quote(fileserver_root)} -czf - -T \"$tmp\"; "
        "rc=$?; rm -f \"$tmp\"; exit $rc"
    )
    cmd = [
        "kubectl",
        "--kubeconfig",
        args.kubeconfig,
        "-n",
        args.namespace,
        "exec",
        "-i",
        f"deploy/{args.deployment}",
        "--",
        "sh",
        "-lc",
        tar_cmd,
    ]
    with archive_path.open("wb") as handle:
        proc = subprocess.run(cmd, input=list_payload, stdout=handle, stderr=subprocess.PIPE, check=False)
    if proc.returncode != 0:
        archive_path.unlink(missing_ok=True)
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(proc.returncode)


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    query_result = query_tasks(args)
    manifest = build_manifest(query_result, args.fileserver_root)

    manifest_name = args.manifest_name or default_name(args.prefix, ".manifest.json")
    manifest_path = output_dir / manifest_name
    write_manifest(manifest_path, manifest)

    print(
        json.dumps(
            {
                "prefix": args.prefix,
                "matched_task_count": manifest["matched_task_count"],
                "exportable_task_count": manifest["exportable_task_count"],
                "skipped_task_count": manifest["skipped_task_count"],
                "manifest_path": str(manifest_path),
            },
            ensure_ascii=False,
            indent=2,
        )
    )

    if args.dry_run:
        return 0

    archive_name = args.archive_name or default_name(args.prefix, ".tar.gz")
    archive_path = output_dir / archive_name
    export_archive(args, manifest, archive_path)
    print(json.dumps({"archive_path": str(archive_path)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
