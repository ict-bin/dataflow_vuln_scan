#!/opt/venv/bin/python
"""回填历史 SQLite findings → per-source-dir MySQL dvs_vuln_findings。

目标:
  - 只补 MySQL 图谱镜像, 不改 SQLite authoritative 数据
  - 支持单任务 / 单项目 / 全量扫描
  - 支持 dry-run, 先看差异再落库
  - 与线上写入语义对齐: task_id + finding_id 唯一, upsert 更新

示例:
  python scripts/backfill_findings_to_mysql.py --task-id dvs_xxx --dry-run
  python scripts/backfill_findings_to_mysql.py --task-id dvs_xxx
  python scripts/backfill_findings_to_mysql.py --project-id 44f9029d00650a10
  python scripts/backfill_findings_to_mysql.py /data/files
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import sqlite3
import sys
import time
from dataclasses import dataclass

import pymysql

MYSQL_HOST = os.environ.get("DVS_MYSQL_HOST", "secflow-app-dataflow-vuln-scan-mysql")
MYSQL_USER = os.environ.get("DVS_MYSQL_USER", "root")
MYSQL_PWD = os.environ.get("DVS_MYSQL_PASSWORD", "Huawei12#$")
MYSQL_PORT = int(os.environ.get("DVS_MYSQL_PORT", "3306"))

SQLITE_COLS = [
    "finding_id", "run_id", "node_id", "edge_id", "source_file", "function_name", "line",
    "vuln_type", "severity", "title", "summary", "evidence", "exploitability", "confidence",
    "output_dir", "report_status", "report_case_id", "code_snippet", "code_explanation",
    "fix_suggestion", "created_at",
]
MYSQL_COLS = [
    "finding_id", "run_id", "task_id", "node_id", "edge_id", "source_file", "function_name", "line",
    "vuln_type", "severity", "title", "summary", "evidence", "exploitability", "confidence",
    "output_dir", "report_status", "report_case_id", "code_snippet", "code_explanation",
    "fix_suggestion", "created_at",
]
SEL = ",".join(SQLITE_COLS)
UPSERT = (
    f"INSERT INTO dvs_vuln_findings ({','.join(MYSQL_COLS)}) "
    f"VALUES ({','.join(['%s'] * len(MYSQL_COLS))}) "
    "ON DUPLICATE KEY UPDATE "
    + ",".join(
        f"{col}=VALUES({col})" for col in MYSQL_COLS if col not in {"task_id", "finding_id"}
    )
)
AR_UPSERT = (
    "INSERT INTO dvs_analysis_runs (run_id,task_id,root_file,root_function,source_root,status,started_at) "
    "VALUES (%s,%s,%s,%s,%s,%s,%s) "
    "ON DUPLICATE KEY UPDATE task_id=VALUES(task_id), root_file=VALUES(root_file), "
    "root_function=VALUES(root_function), source_root=VALUES(source_root), "
    "status=VALUES(status), started_at=VALUES(started_at)"
)


@dataclass
class TaskBackfillStats:
    sqlite_count: int = 0
    mysql_before_count: int = 0
    mysql_after_count: int = 0
    inserted_or_updated: int = 0
    analysis_runs_synced: int = 0


def clean(value):
    if not isinstance(value, str):
        return value
    return value.encode("utf-8", "replace").decode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Backfill DVS findings from SQLite into MySQL mirror.")
    parser.add_argument("root", nargs="?", default="/data/files", help="DVS 根目录, 默认 /data/files")
    parser.add_argument("--task-id", dest="task_id", default="", help="只回填指定 dvs task")
    parser.add_argument("--project-id", dest="project_id", default="", help="只回填指定项目")
    parser.add_argument("--dry-run", action="store_true", help="只统计差异, 不写 MySQL")
    parser.add_argument("--verbose", action="store_true", help="打印更多明细")
    return parser.parse_args()


def find_source_root(task_dir: str) -> str:
    manifests = [
        os.path.join(task_dir, "input", "input-manifest.json"),
        os.path.join(task_dir, "input", "input_manifest.json"),
    ]
    manifest = next((path for path in manifests if os.path.exists(path)), "")
    if manifest:
        try:
            with open(manifest, encoding="utf-8") as handle:
                data = json.load(handle)
            for key in ("source_root_path", "source_root", "input_path"):
                value = data.get(key)
                if value:
                    return str(value)
            for container_key in ("paths", "input", "task"):
                container = data.get(container_key)
                if not isinstance(container, dict):
                    continue
                for key in ("source_root_path", "source_root", "input_path", "path", "real_path"):
                    value = container.get(key)
                    if value and container_key != "input":
                        return str(value)
        except Exception:
            pass
    return ""


def collect_task_dirs(root: str, *, task_id: str, project_id: str) -> list[str]:
    task_dirs: list[str] = []
    normalized_task_id = str(task_id or "").strip()
    normalized_project_id = str(project_id or "").strip()
    if normalized_task_id:
        pattern = os.path.join(root, "*", "app", "secflow-app-dataflow-vuln-scan", normalized_task_id)
        return sorted(path for path in glob.glob(pattern) if os.path.isdir(path))
    for dirpath, dirs, _ in os.walk(root):
        if dirpath == root:
            continue
        if dirpath.count(os.sep) - root.count(os.sep) > 4:
            dirs[:] = []
            continue
        if normalized_project_id and os.path.basename(dirpath) != normalized_project_id and dirpath.count(os.sep) - root.count(os.sep) == 1:
            dirs[:] = []
            continue
        for name in dirs:
            if name.startswith("dvs_"):
                task_dirs.append(os.path.join(dirpath, name))
    return sorted(set(task_dirs))


def connect_mysql(*, database: str | None = None):
    return pymysql.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PWD,
        port=MYSQL_PORT,
        database=database,
        charset="utf8mb4",
        autocommit=False,
    )


def available_mysql_dbs() -> set[str]:
    conn = connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute("SHOW DATABASES")
            return {row[0] for row in cur.fetchall() if row[0].startswith("dvs_") and row[0] != "dvs_init"}
    finally:
        conn.close()


def normalize_created_at(value) -> str:
    if isinstance(value, (int, float)) and value > 0:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(value))
    if value is None or value == "":
        return time.strftime("%Y-%m-%dT%H:%M:%S")
    return clean(str(value))


def sqlite_paths_for_task(task_dir: str) -> list[str]:
    candidates = glob.glob(os.path.join(task_dir, "run", "epochs", "*", "vuln-scan.sqlite"))
    candidates += [
        os.path.join(task_dir, "run", "vuln-scan.sqlite"),
        os.path.join(task_dir, "output", "vuln-scan.sqlite"),
    ]
    return [path for path in candidates if os.path.exists(path)]


def count_mysql_findings(cur, task_id: str) -> int:
    cur.execute("SELECT count(*) FROM dvs_vuln_findings WHERE task_id=%s", (task_id,))
    row = cur.fetchone()
    return int(row[0] or 0) if row else 0


def load_sqlite_findings(task_dir: str) -> tuple[str, list[tuple], list[tuple]]:
    task_id_from_runs = ""
    all_findings: dict[tuple[str, str], list] = {}
    analysis_runs: dict[str, tuple] = {}
    for sqlite_path in sqlite_paths_for_task(task_dir):
        conn = sqlite3.connect(sqlite_path)
        try:
            cur = conn.cursor()
            try:
                for row in cur.execute(
                    "SELECT run_id,task_id,root_file,root_function,source_root,status,started_at FROM analysis_runs"
                ).fetchall():
                    run_id = str(row[0] or "")
                    analysis_runs[run_id] = row
                    if row[1]:
                        task_id_from_runs = str(row[1])
            except Exception:
                pass
            try:
                available_cols = [str(row[1]) for row in cur.execute("PRAGMA table_info(vulnerability_findings)").fetchall()]
                select_cols = [col for col in SQLITE_COLS if col in available_cols]
                rows = cur.execute(f"SELECT {','.join(select_cols)} FROM vulnerability_findings").fetchall()
            except Exception:
                continue
            for row in rows:
                row_map = {col: row[idx] for idx, col in enumerate(select_cols)}
                values = [row_map.get(col, "" if col not in {"confidence", "created_at"} else 0) for col in SQLITE_COLS]
                finding_id = str(values[0] or "")
                run_id = str(values[1] or "")
                key = (run_id, finding_id)
                all_findings[key] = values
        finally:
            conn.close()
    return task_id_from_runs, list(all_findings.values()), list(analysis_runs.values())


def backfill_task(cur, task_dir: str, *, dry_run: bool = False) -> TaskBackfillStats:
    stats = TaskBackfillStats()
    fallback_task_id = os.path.basename(task_dir)
    task_id_from_runs, sqlite_rows, analysis_runs = load_sqlite_findings(task_dir)
    task_id = str(task_id_from_runs or fallback_task_id)
    stats.sqlite_count = len(sqlite_rows)
    stats.mysql_before_count = count_mysql_findings(cur, task_id)

    if not dry_run:
        for run_row in analysis_runs:
            run_row = list(run_row)
            run_id = str(run_row[0] or "")
            task_id_for_run = str(run_row[1] or task_id or run_id)
            payload = (
                run_id,
                task_id_for_run,
                clean(str(run_row[2] or "")),
                clean(str(run_row[3] or "")),
                clean(str(run_row[4] or "")),
                clean(str(run_row[5] or "")),
                run_row[6] if run_row[6] is not None else 0,
            )
            cur.execute(AR_UPSERT, payload)
            stats.analysis_runs_synced += cur.rowcount

        for row in sqlite_rows:
            values = list(row)
            run_id = str(values[1] or "")
            task_id_for_finding = task_id
            mysql_values = [values[0], run_id, task_id_for_finding] + values[2:]
            for index, value in enumerate(mysql_values):
                if isinstance(value, str):
                    mysql_values[index] = clean(value)
            mysql_values[-1] = normalize_created_at(mysql_values[-1])
            cur.execute(UPSERT, mysql_values)
            stats.inserted_or_updated += cur.rowcount

    stats.mysql_after_count = count_mysql_findings(cur, task_id) if not dry_run else stats.mysql_before_count
    return stats


def group_tasks_by_sid(task_dirs: list[str]) -> tuple[dict[str, list[str]], int]:
    grouped: dict[str, list[str]] = {}
    missing_source_root = 0
    for task_dir in task_dirs:
        source_root = find_source_root(task_dir)
        if not source_root:
            missing_source_root += 1
            continue
        sid = hashlib.sha1(source_root.encode("utf-8")).hexdigest()[:16]
        grouped.setdefault(sid, []).append(task_dir)
    return grouped, missing_source_root


def main() -> int:
    args = parse_args()
    task_dirs = collect_task_dirs(args.root, task_id=args.task_id, project_id=args.project_id)
    print(f"扫描到 {len(task_dirs)} 个任务目录")
    if not task_dirs:
        return 0

    dbs = available_mysql_dbs()
    by_sid, missing_source_root = group_tasks_by_sid(task_dirs)
    print(f"sid 分组: {len(by_sid)} 个库, 无 source_root 跳过 {missing_source_root}")

    total_inserted = 0
    total_tasks = 0
    total_sqlite = 0
    total_mysql_before = 0
    total_mysql_after = 0

    for sid, dirs in sorted(by_sid.items()):
        database = f"dvs_{sid}"
        if database not in dbs:
            print(f"  跳过 {database} (MySQL 无此库)")
            continue
        conn = connect_mysql(database=database)
        try:
            with conn.cursor() as cur:
                db_inserted = 0
                db_tasks = 0
                for task_dir in dirs:
                    stats = backfill_task(cur, task_dir, dry_run=args.dry_run)
                    task_id = os.path.basename(task_dir)
                    total_sqlite += stats.sqlite_count
                    total_mysql_before += stats.mysql_before_count
                    total_mysql_after += stats.mysql_after_count
                    db_inserted += stats.inserted_or_updated
                    if stats.sqlite_count > 0:
                        db_tasks += 1
                        print(
                            f"    {task_id}: sqlite={stats.sqlite_count}, "
                            f"mysql_before={stats.mysql_before_count}, "
                            f"mysql_after={stats.mysql_after_count}, "
                            f"writes={stats.inserted_or_updated}, "
                            f"analysis_runs={stats.analysis_runs_synced}"
                        )
                if args.dry_run:
                    conn.rollback()
                else:
                    conn.commit()
                cur.execute("SELECT count(*) FROM dvs_vuln_findings")
                db_total = int(cur.fetchone()[0] or 0)
            print(f"  {database}: writes={db_inserted}, tasks={db_tasks}, 库内共 {db_total}")
            total_inserted += db_inserted
            total_tasks += db_tasks
        finally:
            conn.close()

    mode = "dry-run" if args.dry_run else "写入"
    print(
        f"=== 回填{mode}完成: task_dirs={len(task_dirs)}, sqlite_total={total_sqlite}, "
        f"mysql_before_total={total_mysql_before}, mysql_after_total={total_mysql_after}, "
        f"writes={total_inserted}, tasks={total_tasks} ==="
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
