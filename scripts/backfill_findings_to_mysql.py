#!/opt/venv/bin/python
"""回填历史 SQLite findings → per-source-dir MySQL dvs_vuln_findings。

背景: v2/自主模式 persist_finding 旧版只写 SQLite, graph-view 优先读 MySQL,
导致老任务 findings 不进 MySQL → 前端漏洞图谱空。d46016c 已修 (新 run 双写),
本脚本处理**已存在的老 findings**: 扫描各任务目录的 vuln-scan.sqlite, 按
source_root 计算 sid → 对应 dvs_<sid> MySQL 库, sanitize 后 INSERT IGNORE。

幂等 (INSERT IGNORE + DELETE 去重), 可重复运行。在三模式任一部署区域 worker pod 跑:
  python scripts/backfill_findings_to_mysql.py [DVS_ROOT]
默认 DVS_ROOT=/data/files (扫所有项目)。

环境变量:
  DVS_MYSQL_HOST (默认 secflow-app-dataflow-vuln-scan-mysql)
  DVS_MYSQL_USER / DVS_MYSQL_PASSWORD (默认 root / Huawei12#$)
"""
from __future__ import annotations
import sqlite3, glob, os, sys, time, json, hashlib
import pymysql

MYSQL_HOST = os.environ.get("DVS_MYSQL_HOST", "secflow-app-dataflow-vuln-scan-mysql")
MYSQL_USER = os.environ.get("DVS_MYSQL_USER", "root")
MYSQL_PWD = os.environ.get("DVS_MYSQL_PASSWORD", "Huawei12#$")

SQLITE_COLS = ['finding_id','run_id','node_id','edge_id','source_file','function_name','line',
               'vuln_type','severity','title','summary','evidence','exploitability','confidence',
               'output_dir','report_status','report_case_id','created_at']
MYSQL_COLS = ['finding_id','run_id','task_id','node_id','edge_id','source_file','function_name','line',
              'vuln_type','severity','title','summary','evidence','exploitability','confidence',
              'output_dir','report_status','report_case_id','created_at']
SEL = ','.join(SQLITE_COLS)
INS = f"INSERT IGNORE INTO dvs_vuln_findings ({','.join(MYSQL_COLS)}) VALUES ({','.join(['%s']*len(MYSQL_COLS))})"
AR_SQL = "INSERT IGNORE INTO dvs_analysis_runs (run_id,task_id,root_file,root_function,source_root,status,started_at) VALUES (%s,%s,%s,%s,%s,%s,%s)"


def clean(s):
    """strip surrogate-escape / 坏字节 (旧 SQLite GBK mojibake), 保证 JSON 可序列化。"""
    if not isinstance(s, str):
        return s
    return s.encode('utf-8', 'replace').decode('utf-8')


def find_source_root(task_dir: str) -> str:
    """从 input/input-manifest.json 读 source_root_path; 回退扫父层。"""
    mf = os.path.join(task_dir, "input", "input-manifest.json")
    if os.path.exists(mf):
        try:
            d = json.load(open(mf, encoding="utf-8"))
            for k in ("source_root_path", "source_root", "input_path"):
                v = d.get(k)
                if v:
                    return str(v)
        except Exception:
            pass
    return ""


def backfill_task(cur, task_dir: str, sid: str) -> int:
    sps = glob.glob(task_dir + '/run/epochs/*/vuln-scan.sqlite') + \
          [task_dir + '/output/vuln-scan.sqlite', task_dir + '/run/vuln-scan.sqlite']
    sps = [s for s in sps if os.path.exists(s)]
    if not sps:
        return 0
    n = 0
    for sp in sps:
        try:
            sc = sqlite3.connect(sp); scur = sc.cursor()
            try:
                for r in scur.execute('SELECT run_id,task_id,root_file,root_function,source_root,status,started_at FROM analysis_runs').fetchall():
                    try: cur.execute(AR_SQL, r)
                    except Exception: pass
            except Exception:
                pass
            try:
                rows = scur.execute(f'SELECT {SEL} FROM vulnerability_findings').fetchall()
            except Exception:
                sc.close(); continue
            for r in rows:
                r = list(r); rid = r[1]
                mv = [r[0], rid, rid] + r[2:]
                for i in range(len(mv)):
                    if isinstance(mv[i], str):
                        mv[i] = clean(mv[i])
                if isinstance(mv[18], (int, float)) and mv[18] > 0:
                    mv[18] = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(mv[18]))
                elif mv[18] is None:
                    mv[18] = time.strftime('%Y-%m-%dT%H:%M:%S')
                try:
                    cur.execute(INS, mv); n += cur.rowcount
                except Exception:
                    pass
            sc.close()
        except Exception:
            pass
    return n


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "/data/files"
    # 扫所有 dvs_<tid> 任务目录 (跨项目)
    task_dirs = []
    for dirpath, dirs, _ in os.walk(root):
        if dirpath == root:
            continue
        for d in dirs:
            if d.startswith("dvs_"):
                task_dirs.append(os.path.join(dirpath, d))
        # 限制深度避免扫过深
        if dirpath.count(os.sep) - root.count(os.sep) > 4:
            dirs[:] = []
    task_dirs = sorted(set(task_dirs))
    print(f"扫描到 {len(task_dirs)} 个任务目录")

    admin = pymysql.connect(host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PWD, port=3306, charset='utf8mb4')
    acur = admin.cursor()
    acur.execute('SHOW DATABASES')
    dbs = {r[0] for r in acur.fetchall() if r[0].startswith('dvs_') and r[0] != 'dvs_init'}
    admin.close()

    # 按 sid 分组 (一个 mysql 连接一个库)
    by_sid = {}
    no_sr = 0
    for td in task_dirs:
        sr = find_source_root(td)
        if not sr:
            no_sr += 1; continue
        sid = hashlib.sha1(sr.encode("utf-8")).hexdigest()[:16]
        by_sid.setdefault(sid, []).append(td)
    print(f"sid 分组: {len(by_sid)} 个库, 无 source_root 跳过 {no_sr}")

    tot_find = 0; tot_tasks = 0
    for sid, tds in by_sid.items():
        db = f"dvs_{sid}"
        if db not in dbs:
            print(f"  跳过 {db} (MySQL 无此库, 任务可能未在该区域建过图)")
            continue
        c = pymysql.connect(host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PWD, port=3306, database=db, charset='utf8mb4')
        cur = c.cursor()
        n_find = 0; n_tasks = 0
        for td in tds:
            k = backfill_task(cur, td, sid)
            if k > 0:
                n_find += k; n_tasks += 1
        c.commit()
        cur.execute('SELECT count(*) FROM dvs_vuln_findings')
        cur_f = cur.fetchone()[0]
        c.close()
        print(f"  {db}: +{n_find} findings ({n_tasks} 任务), 库内共 {cur_f}")
        tot_find += n_find; tot_tasks += n_tasks
    print(f"=== 回填完成: +{tot_find} findings, {tot_tasks} 任务 ===")


if __name__ == "__main__":
    main()
