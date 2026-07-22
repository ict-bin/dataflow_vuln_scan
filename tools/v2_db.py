#!/opt/venv/bin/python3
"""v2_db — V2 数据流数据库查询工具 (供 LLM 通过 bash 调用)

用法:
  v2_db lookup <function_name>           # 查函数库→返回函数体 (从原源文件按行读)
  v2_db taints <func_name>               # 查污点库→返回函数的污点变量
  v2_db propagations <func_name>          # 查传播库→返回函数的传播路径
  v2_db orchestration <func_name>         # 查编排库→返回调用链
  v2_db index <file_path>                 # 索引新文件到函数库 (查不到时用)
  v2_db symbol <name>                     # 查宏定义/typedef/struct/enum (grep 全盘 .h/.c)

环境变量:
  DVS_V2_DB_DIR    — dataflow-v2 目录路径 (含 functions.db 等四库)
  DVS_SOURCE_ROOT  — 源码根目录

流程:
  1. LLM 需要函数源码 → v2_db lookup <name>
  2. 查到 → 返回函数体 (从原源文件 start_line~end_line 读取)
  3. 查不到 → 提示用 v2_db index <file> 建库后再查
  4. 需要宏/typedef/struct 定义 → v2_db symbol <name> (一次 grep 全盘)
"""
import json
import re
import os
import shlex
import sqlite3
import sys
import time
from pathlib import Path

# 确保 app 包可导入: v2_db 可能被安装为 /usr/local/bin/v2_db (cp 副本, 非 symlink),
# 此时 __file__ 解析为 /usr/local/bin → __file__ 相对路径错 (/usr/local 无 app 包)。
# 用 DVS_APP_DIR (默认 /opt/dataflow_vuln_scan) 显式定位 app 包, 不依赖 __file__。
_APP_DIR = os.environ.get("DVS_APP_DIR", "/opt/dataflow_vuln_scan")
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

# ── 日志 (写 /tmp/v2db.log, 不污染 LLM stdout) ──────────────────────────────
import logging
_logger = logging.FileHandler('/tmp/v2db.log')
_logger.setFormatter(logging.Formatter('[v2db %(asctime)s] %(message)s', datefmt='%H:%M:%S'))
log = logging.getLogger('v2db')
log.addHandler(_logger)
log.setLevel(logging.INFO)
log.propagate = False


def _db_dir() -> Path:
    d = os.environ.get("DVS_V2_DB_DIR", "")
    if not d:
        print("ERROR: DVS_V2_DB_DIR 环境变量未设置", file=sys.stderr)
        sys.exit(1)
    p = Path(d)
    if not p.is_dir():
        print(f"ERROR: 数据库目录不存在: {d}", file=sys.stderr)
        sys.exit(1)
    return p


def _source_root() -> str:
    r = os.environ.get("DVS_SOURCE_ROOT", "")
    if not r:
        print("ERROR: DVS_SOURCE_ROOT 环境变量未设置", file=sys.stderr)
        sys.exit(1)
    return r


def _query(db_name: str, sql: str, params: tuple = ()) -> list[dict]:
    db = _db_dir() / db_name
    if not db.exists():
        print(f"ERROR: 数据库不存在: {db_name}", file=sys.stderr)
        return []
    try:
        conn = sqlite3.connect(db, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        conn.close()
        return rows
    except sqlite3.OperationalError as e:
        log.warning("query failed db=%s: %s", db_name, e)
        return []
    except Exception as e:
        log.warning("query error db=%s: %s", db_name, e)
        return []


_mysql_store = None

def _get_mysql_store():
    """懒加载 SharedMysqlStore (SQLite 查不到时 fallback 到 MySQL)。"""
    global _mysql_store
    if _mysql_store is not None:
        return _mysql_store
    try:
        import hashlib
        sr = _source_root()
        sid = hashlib.sha1(sr.encode("utf-8")).hexdigest()[:16]
        tid = os.environ.get("DVS_TASK_ID", "")
        db_cfg_url = os.environ.get("DVS_MYSQL_URL", "")
        if not db_cfg_url:
            db_cfg_url = "mysql+pymysql://root:Huawei12%23$@secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local:3306"
        from app.db.shared_mysql import SharedMysqlStore
        pid = os.environ.get("DVS_PROJECT_ID", "")
        _mysql_store = SharedMysqlStore(db_cfg_url, "complete", sr, tid, project_id=pid)
        return _mysql_store
    except Exception as e:
        log.warning("mysql store init failed: %s", e)
        return None

def _mysql_query_functions(name: str, file: str = "") -> list[dict]:
    """MySQL fallback: 查 functions 表 (按名, 支持 short/tail/suffix 匹配)。"""
    ms = _get_mysql_store()
    if ms is None:
        return []
    recs = ms.read_functions(name, file)
    return [{"func_id": r.func_id, "file": r.file, "name": r.name,
             "signature": r.signature, "start_line": r.start_line,
             "end_line": r.end_line, "func_hash": r.func_hash,
             "description": r.description} for r in recs]

def _mysql_query_taints(func_name: str) -> list[dict]:
    """MySQL fallback: 查 taints 表 (按 function 名)。"""
    ms = _get_mysql_store()
    if ms is None:
        return []
    recs = ms.read_functions(func_name)
    if not recs:
        recs = ms.read_functions(func_name.split("::")[-1])
    out = []
    for r in recs:
        taints = ms.read_taints_in_function(r.func_id)
        for t in taints:
            out.append({"taint_id": t.taint_id, "func_id": t.func_id,
                        "name": t.name, "signature": t.signature,
                        "file": t.file, "function": t.function,
                        "next_propagations": t.next_propagations,
                        "description": t.description})
    return out

def _mysql_query_propagations(func_name: str) -> list[dict]:
    """MySQL fallback: 查 propagations 表 (按 func_name → func_id → propagations)。"""
    ms = _get_mysql_store()
    if ms is None:
        return []
    recs = ms.read_functions(func_name)
    if not recs:
        recs = ms.read_functions(func_name.split("::")[-1])
    out = []
    for r in recs:
        props = ms.read_propagations_from(r.func_id)
        for p in props:
            out.append({"prop_id": p.prop_id, "source_func_id": p.source_func_id,
                        "source_taint_signature": p.source_taint_signature,
                        "target_taint_signature": p.target_taint_signature,
                        "target_func_id": p.target_func_id,
                        "target_function": p.target_function,
                        "target_file": p.target_file,
                        "call_line": p.call_line, "condition": p.condition,
                        "is_external": p.is_external,
                        "description": p.description})
    return out

def _mysql_query_orchestration(func_name: str) -> list[dict]:
    """MySQL fallback: 查 orchestration 表 (按 source/target function)。"""
    ms = _get_mysql_store()
    if ms is None:
        return []
    from sqlalchemy import text as sa_text
    try:
        with ms._engine.connect() as conn:
            rows = conn.execute(sa_text(
                "SELECT * FROM orchestration WHERE source_dir_id=:sid AND "
                "(source_function=:fn OR target_function=:fn) ORDER BY edge_order"),
                {"sid": ms.source_dir_id, "fn": func_name}).fetchall()
            return [dict(r._mapping) for r in rows]
    except Exception as e:
        log.warning("mysql orchestration query failed: %s", e)
        return []

def _mysql_is_indexed(rel_file: str) -> bool:
    ms = _get_mysql_store()
    if ms is None:
        return False
    return ms.read_is_indexed(rel_file)

def _mysql_is_indexing(rel_file: str) -> bool:
    ms = _get_mysql_store()
    if ms is None:
        return False
    return ms.read_is_indexing(rel_file)

def _find_func(name: str) -> dict | None:
    """查函数库, 支持短名后缀匹配 (C++ Class::Method)。"""
    # MySQL 优先
    mrows = _mysql_query_functions(name)
    if mrows:
        return mrows[0]
    rows = _query("functions.db", "SELECT * FROM functions WHERE name = ?", (name,))
    if rows:
        return rows[0]
    rows = _query("functions.db", "SELECT * FROM functions WHERE name LIKE ?", (f"%{name}",))
    return rows[0] if rows else None

def _read_body(func: dict) -> str:
    """从原源文件按 start_line/end_line 读取函数体, 带行号前缀。"""
    src = Path(_source_root()) / func["file"]
    if not src.is_file():
        return f"// 源文件不可读: {func['file']}"
    try:
        lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(0, func["start_line"] - 1)
        end = min(len(lines), func["end_line"])
        return "\n".join(f"{func['start_line']+i:4d} | {line}" for i, line in enumerate(lines[start:end]))
    except OSError as e:
        return f"// 读取失败: {e}"


def _find_func_in_source_v2db(name: str, src_root: Path) -> list[tuple[str, str]]:
    """在源码树中搜索函数定义所在文件 (grep)。
    返回 [(rel_file, matched_name), ...] 或 []。
    """
    import subprocess, re
    # 搜索函数定义模式: name 后跟 (
    pattern = rf'\b{re.escape(name)}\s*\('
    log.info("grep src_root=%s pattern=%r", src_root, pattern)
    try:
        r = subprocess.run(
            ["/usr/bin/grep", "-rl", "-E", "--include=*.c", "--include=*.cpp", "--include=*.cc",
             "--include=*.h", "--include=*.hpp", "--include=*.hxx",
             pattern, str(src_root)],
            capture_output=True, text=True, timeout=15)
        results: list[tuple[str, str]] = []
        for line in r.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                rel = str(Path(line).relative_to(src_root)).replace("\\", "/")
                results.append((rel, name))
            except ValueError:
                continue
        log.info("grep rc=%d stdout_lines=%d found=%d stderr=%s",
                 r.returncode, len(r.stdout.strip().split("\n")), len(results), r.stderr[:200] if r.stderr else "")
        return results
    except Exception as e:
        log.warning("grep exception: %s", e)
        pass
    return []


def _log_trajectory(func: dict, query: str) -> None:
    """自主模式 (DVS_RUN_DIR 设了): 记 v2_db lookup 到 path.log (服务感知探索路径)。
    完整模式不设 DVS_RUN_DIR → 不记 (不影响)。"""
    run_dir = os.environ.get("DVS_RUN_DIR", "").strip()
    if not run_dir:
        return
    step = {"ts": time.time(), "func": func.get("name", ""), "file": func.get("file", ""),
            "start_line": func.get("start_line"), "end_line": func.get("end_line"),
            "signature": func.get("signature", ""), "query": query, "via": "v2_db_lookup"}
    try:
        with open(os.path.join(run_dir, "path.log"), "a", encoding="utf-8") as f:
            f.write(json.dumps(step, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _print_function_result(name, file, start_line, end_line, signature, body):
    """打印函数查询结果。"""
    print(f"function: {name}")
    print(f"file: {file}")
    print(f"lines: {start_line}-{end_line}")
    print(f"signature: {signature}")
    print(f"description:")
    print(f"---")
    print(body)


def _read_body_from_source(src_root, rel_file, start_line, end_line):
    """从源文件按行号读函数体, 带行号前缀。"""
    src_path = Path(src_root) / rel_file
    if not src_path.is_file():
        return ""
    lines = src_path.read_text(encoding="utf-8", errors="replace").splitlines()
    body = lines[max(0, start_line-1):min(len(lines), end_line)]
    return "\n".join(f"{start_line+i:4d} | {line}" for i, line in enumerate(body))


def _async_index_file(src_root, rel_file, db_dir):
    """异步入库: 后台线程执行 ensure_file_indexed。"""
    import threading
    def _do():
        try:
            sys.path.insert(0, os.environ.get("DVS_APP_DIR", "/opt/dataflow_vuln_scan"))
            from app.dataflow_v2.function_extractor import ensure_file_indexed
            from app.dataflow_v2.store import DataflowStore
            store = DataflowStore(db_dir)
            ensure_file_indexed(str(src_root), rel_file, store)
            store.close()
        except Exception as e:
            log.warning("async index failed file=%s: %s", rel_file, e)
    t = threading.Thread(target=_do, daemon=True, name=f"dvs-idx-{rel_file[-30:]}")
    t.start()


def cmd_lookup(name: str) -> None:
    """查函数体:
    1. 查 DB -> 有就返回
    2. grep 找到所有候选文件
    3. 遍历每个文件:
       a. 文件在索引中? -> tree-sitter 直接搜, 跳过 DB 写入
       b. 文件在 DB 中? -> 函数不在该文件, skip
       c. tree-sitter 解析 -> 搜函数定义 -> 找到 -> 返回 (异步入库)
       d. 没找到 -> 继续 (异步入库)
    """
    _t0 = time.time()
    log.info("lookup START name=%s db_dir=%s source_root=%s",
             name, os.environ.get("DVS_V2_DB_DIR", "(unset)"), os.environ.get("DVS_SOURCE_ROOT", "(unset)"))

    # 1. 查 DB
    func = _find_func(name)
    if func:
        log.info("db HIT name=%s file=%s", name, func.get("file", ""))
        _log_trajectory(func, name)
        body = _read_body(func)
        _print_function_result(func["name"], func["file"], func["start_line"],
                              func["end_line"], func["signature"], body)
        return

    log.info("db MISS name=%s", name)

    # 2. grep 找到所有候选文件
    src_root = Path(_source_root())
    found = __import__("app.dataflow_v2.function_extractor", fromlist=["find_func_in_source"]).find_func_in_source(name, src_root)
    log.info("find_func_in_source returned %d candidates", len(found))
    if not found:
        if _try_underscore_fallback(name, src_root):
            return
        _print_prefix_candidates(name, src_root)
        return

    db_dir = str(_db_dir())
    sys.path.insert(0, os.environ.get("DVS_APP_DIR", "/opt/dataflow_vuln_scan"))
    from app.dataflow_v2.function_extractor import find_function_in_file

    # 3. 遍历每个候选文件
    for rel_file, _ in found:
        # 3a. 文件是否在索引中?
        try:
            idx_rows = _query("functions.db", "SELECT 1 FROM indexing_files WHERE file_path=?", (rel_file,))
            if not idx_rows:
                idx_rows = [{"1": 1}] if _mysql_is_indexed(rel_file) else []
            is_indexing = len(idx_rows) > 0
        except Exception:
            is_indexing = False

        if is_indexing:
            log.info("file=%s being indexed by another process, tree-sitter only", rel_file)
            # 5. tree-sitter 直接搜 (不写 DB)
            result = find_function_in_file(str(src_root), rel_file, name)
            if result:
                start_line, end_line, sig = result
                log.info("found (indexing) name=%s file=%s lines=%s-%s", name, rel_file, start_line, end_line)
                body = _read_body_from_source(src_root, rel_file, start_line, end_line)
                _print_function_result(name, rel_file, start_line, end_line, sig, body)
                return
            # 6. 跳过异步入库 (另一进程在索引)
            continue

        # 3b. 文件是否在 DB 中?
        try:
            db_rows = _query("functions.db", "SELECT 1 FROM functions WHERE file=? LIMIT 1", (rel_file,))
            in_db = len(db_rows) > 0
        except Exception:
            in_db = False

        if in_db:
            log.info("file=%s already in DB, function not here, skip", rel_file)
            continue  # 函数定义不在该文件

        # 5. tree-sitter 解析文件, 搜函数定义
        log.info("tree-sitter search file=%s", rel_file)
        result = find_function_in_file(str(src_root), rel_file, name)
        if result:
            start_line, end_line, sig = result
            log.info("found name=%s file=%s lines=%s-%s duration=%.2fs",
                     name, rel_file, start_line, end_line, time.time() - _t0)
            body = _read_body_from_source(src_root, rel_file, start_line, end_line)
            _print_function_result(name, rel_file, start_line, end_line, sig, body)
            # 6. 异步入库 (不阻塞返回)
            _async_index_file(str(src_root), rel_file, db_dir)
            return

        # 没找到, 继续, 异步入库
        _async_index_file(str(src_root), rel_file, db_dir)

    # 所有文件都搜完, 未找到
    log.warning("NOT_FOUND name=%s duration=%.2fs", name, time.time() - _t0)
    if _try_underscore_fallback(name, src_root):
        return
    _print_prefix_candidates(name, src_root)


def _try_underscore_fallback(name: str, src_root: Path) -> bool:
    """前导下划线 fallback: 精确查找失败时, 尝试有/无前导 _ 的变体名。

    C 项目常有混合命名: 内部 static 函数带 _ (如 _http_head_parse),
    公开 API 函数不带 _ (如 http_head_get_url)。LLM 混淆时会用错前缀。
    此函数在精确查找全流程失败后, 用变体名重试 DB + grep + tree-sitter。
    找到则打印结果并返回 True; 未找到返回 False (继续走 prefix candidates)。
    """
    alt = name[1:] if name.startswith("_") else "_" + name
    if alt == name or len(alt) < 2:
        return False
    log.info("underscore fallback: trying %s -> %s", name, alt)
    # 1. DB 查变体名
    func = _find_func(alt)
    if func:
        log.info("fallback DB HIT: %s -> %s file=%s", name, alt, func.get("file", ""))
        _log_trajectory(func, alt)
        body = _read_body(func)
        _print_function_result(func["name"], func["file"], func["start_line"],
                              func["end_line"], func["signature"], body)
        return True
    # 2. grep + tree-sitter 查变体名
    import importlib
    fe = importlib.import_module("app.dataflow_v2.function_extractor")
    found = fe.find_func_in_source(alt, src_root)
    log.info("fallback find_func_in_source: alt=%s candidates=%d", alt, len(found))
    if not found:
        return False
    db_dir = str(_db_dir())
    for rel_file, _ in found:
        result = fe.find_function_in_file(str(src_root), rel_file, alt)
        if result:
            start_line, end_line, sig = result
            log.info("fallback found: %s -> %s file=%s lines=%s-%s",
                     name, alt, rel_file, start_line, end_line)
            body = _read_body_from_source(src_root, rel_file, start_line, end_line)
            _print_function_result(alt, rel_file, start_line, end_line, sig, body)
            _async_index_file(str(src_root), rel_file, db_dir)
            return True
        _async_index_file(str(src_root), rel_file, db_dir)
    return False


def _print_prefix_candidates(name: str, src_root) -> None:
    """精确未找到时: 按前缀/包含查候选函数名, 返回给 LLM 用全名再查。

    修: LLM 常传截断名 (如 _dns_server_resolve_callback_reply_p 缺 assthrough),
    精确匹配 (grep \\bname\\s*\\( + SQL name=?) 漏 → NOT_FOUND, LLM 又得改用 raw grep 找。
    现在前缀匹配: SQL name LIKE 'name%' + 源码 grep \\bname (不需 \\s*\\() 索引候选 →
    返回候选函数名清单, LLM 用全名再 lookup。不再直接 NOT_FOUND。
    """
    import subprocess, re as _re
    db_dir = _db_dir()
    # 1) db 前缀/包含匹配
    cands = _query("functions.db", "SELECT name, file, start_line, end_line FROM functions WHERE name LIKE ? OR name LIKE ? ORDER BY length(name) LIMIT 20",
                   (f"{name}%", f"%{name}%"))
    log.info("prefix candidates: db_cands=%d", len(cands))
    # 2) db 无候选 → 源码前缀 grep (\\bname 不需 \\s*\\(, 拓宽) + 增量索引
    if not cands:
        try:
            pat = _re.escape(name)
            r = subprocess.run(
                ["/usr/bin/grep", "-rl", "-E", rf"\b{pat}",
                 "--include=*.c", "--include=*.cpp", "--include=*.cc", "--include=*.cxx",
                 "--include=*.h", "--include=*.hpp", "--include=*.hxx", str(src_root)],
                capture_output=True, text=True, timeout=20)
            log.info("prefix grep rc=%d stdout_lines=%d", r.returncode, len(r.stdout.strip().split("\n")))
            sys.path.insert(0, os.environ.get("DVS_APP_DIR", "/opt/dataflow_vuln_scan"))
            from app.dataflow_v2.function_extractor import ensure_file_indexed
            from app.dataflow_v2.store import DataflowStore
            indexed = []
            for line in r.stdout.strip().split("\n")[:8]:
                if not line: continue
                try: rel = str(Path(line).relative_to(src_root)).replace("\\", "/")
                except ValueError: continue
                if rel in indexed: continue
                try:
                    store = DataflowStore(db_dir); ensure_file_indexed(str(src_root), rel, store); store.close()
                    indexed.append(rel)
                except Exception as e:
                    log.warning("prefix index failed file=%s: %s", rel, e)
            if indexed:
                cands = _query("functions.db", "SELECT name, file, start_line, end_line FROM functions WHERE name LIKE ? OR name LIKE ? ORDER BY length(name) LIMIT 20",
                               (f"{name}%", f"%{name}%"))
        except Exception:
            pass
    if cands:
        print(f"NOT_FOUND_EXACT: 未精确找到 '{name}'。以下 {len(cands)} 个相似函数 (用全名再查 read_function/v2_db lookup):")
        for c in cands:
            print(f"  - {c['name']} ({c['file']} 行 {c['start_line']}-{c['end_line']})")
    else:
        print(f"NOT_FOUND: 函数 '{name}' 在源码树中未找到。该函数可能是外部库函数或系统 API，定义不在当前源码树中，不需要查找其源码。")


def cmd_taints(func_name: str) -> None:
    """查污点库: 返回函数的污点变量。"""
    # MySQL 优先
    rows = _mysql_query_taints(func_name)
    if not rows:
        rows = _query("taints.db", "SELECT * FROM taints WHERE function = ?", (func_name,))
    if not rows:
        rows = _query("taints.db", "SELECT * FROM taints WHERE function LIKE ?", (f"%{func_name}",))
    if not rows:
        alt = func_name[1:] if func_name.startswith("_") else "_" + func_name
        if alt != func_name and len(alt) >= 2:
            rows = _query("taints.db", "SELECT * FROM taints WHERE function = ?", (alt,))
            if rows:
                log.info("taints underscore fallback: %s -> %s", func_name, alt)
    if rows:
        for r in rows:
            print(f"taint: {r['name']} (signature: {r['signature']})")
            print(f"  function: {r['function']}")
            print(f"  description: {r.get('description', '')}")
    else:
        print(f"NOT_FOUND: 函数 '{func_name}' 在污点库中未找到。")


def _print_props(rows: list[dict]) -> None:
    for r in rows:
        src = r.get('source_taint_name', '') or r.get('source_taint_signature', '')
        tgt = r.get('target_taint_name', '') or r.get('target_taint_signature', '')
        print(f"propagation: {src} → {tgt}")
        print(f"  target_function: {r.get('target_function', '')}")
        print(f"  call_line: {r.get('call_line', 0)}")
        print(f"  is_external: {r.get('is_external', 0)}")
        print(f"  description: {r.get('description', '')}")

def cmd_propagations(func_name: str) -> None:
    """查传播库: 返回函数的传播路径。"""
    # 先查 functions.db 拿 func_id, 再查 propagations.db (两库分离, 不能跨库子查询)
    # MySQL 优先: 直接查 propagations
    mrows = _mysql_query_propagations(func_name)
    if mrows:
        _print_props(mrows)
        return
    func_rows = _query("functions.db", "SELECT func_id FROM functions WHERE name = ?", (func_name,))
    if not func_rows:
        func_rows = _query("functions.db", "SELECT func_id FROM functions WHERE name LIKE ?", (f"%{func_name}",))
    if not func_rows:
        # 前导下划线 fallback
        alt = func_name[1:] if func_name.startswith("_") else "_" + func_name
        if alt != func_name and len(alt) >= 2:
            func_rows = _query("functions.db", "SELECT func_id FROM functions WHERE name = ?", (alt,))
            if func_rows:
                log.info("propagations underscore fallback: %s -> %s", func_name, alt)
    if not func_rows:
        print(f"NOT_FOUND: 函数 '{func_name}' 在函数库中未找到。")
        return
    func_ids = [r["func_id"] for r in func_rows]
    placeholders = ",".join("?" * len(func_ids))
    rows = _query("propagations.db", f"SELECT * FROM propagations WHERE source_func_id IN ({placeholders})", tuple(func_ids))
    if rows:
        for r in rows:
            print(f"propagation: {r['source_taint_name']} → {r['target_taint_name']}")
            print(f"  target_function: {r['target_function']}")
            print(f"  call_line: {r['call_line']}")
            print(f"  is_external: {r['is_external']}")
            print(f"  description: {r.get('description', '')}")
    else:
        print(f"NOT_FOUND: 函数 '{func_name}' 在传播库中未找到。")


def cmd_orchestration(func_name: str) -> None:
    """查编排库: 返回调用链。"""
    # MySQL 优先
    rows = _mysql_query_orchestration(func_name)
    if not rows:
        rows = _query("orchestration.db", "SELECT * FROM orchestration WHERE source_function = ? OR target_function = ?", (func_name, func_name))
    if rows:
        for r in rows:
            print(f"edge: {r['source_function']} → {r['target_function']}")
            print(f"  depth: {r['depth']}")
            print(f"  taint_params: {r['taint_params']}")
            print(f"  status: {r['status']}")
    else:
        print(f"NOT_FOUND: 函数 '{func_name}' 在编排库中未找到。")


def cmd_index(file_path: str) -> None:
    """索引新文件到函数库 (tree-sitter 函数提取 + include + class)。"""
    src_root = _source_root()
    sys.path.insert(0, os.environ.get("DVS_APP_DIR", "/opt/dataflow_vuln_scan"))
    from app.dataflow_v2.function_extractor import ensure_file_indexed
    from app.dataflow_v2.store import DataflowStore
    store = DataflowStore(_db_dir())
    ensure_file_indexed(src_root, file_path, store)
    store.close()
    print(f"INDEXED: {file_path}")


def cmd_symbol(name: str) -> None:
    """查符号在 C/C++ 源树中的出现位置。"""
    import subprocess

    globs = ["*.hpp", "*.h", "*.c", "*.cc"]

    def _shell_join(argv: list[str]) -> str:
        return " ".join(shlex.quote(part) for part in argv)

    executed_commands: list[str] = []

    def _run_symbol_search(argv: list[str], *, limit: int | None = None) -> list[str]:
        executed_commands.append(_shell_join(argv))
        try:
            r = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except Exception:
            return []
        rows = [line for line in r.stdout.strip().split("\n") if line]
        if limit is not None:
            rows = rows[:limit]
        return rows

    src = os.environ.get("DVS_SOURCE_ROOT", "")
    if not src:
        print("ERROR: DVS_SOURCE_ROOT 未设置")
        return
    log.info("symbol START name=%s src=%s", name, src)
    grep_argv = ["/usr/bin/grep", "-rn"]
    for glob in globs:
        grep_argv.append(f"--include={glob}")
    grep_argv.extend([name, src])
    results = _run_symbol_search(grep_argv, limit=20)
    log.info("symbol aggregated grep results=%d", len(results))
    print(f"DVS_SOURCE_ROOT={src}")
    print("EXECUTED_COMMANDS:")
    for command in executed_commands:
        print(f"  {command}")
    if results:
        print(f"SYMBOL: {name} 找到 {len(results)} 个匹配: 不要自己尝试在源码文件夹进行grep寻找，本命令就是最终查找结果，本命令执行的命令没有截断")
        for line in results[:20]:
            print(f"  {line}")
    else:
        print(f"NOT_FOUND: 符号 '{name}' 在源码中未找到。该符号可能定义在外部库/系统头文件中；注意不要自己尝试在源码文件夹进行grep寻找，本命令就是最终查找结，本命令执行的命令没有截断")


def main():
    if len(sys.argv) < 2:
        print("Usage: v2_db <command> [args]")
        print("Commands: lookup, taints, propagations, orchestration, index, symbol")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "lookup" and len(sys.argv) >= 3:
        cmd_lookup(sys.argv[2])
    elif cmd == "taints" and len(sys.argv) >= 3:
        cmd_taints(sys.argv[2])
    elif cmd == "propagations" and len(sys.argv) >= 3:
        cmd_propagations(sys.argv[2])
    elif cmd == "orchestration" and len(sys.argv) >= 3:
        cmd_orchestration(sys.argv[2])
    elif cmd == "index" and len(sys.argv) >= 3:
        cmd_index(sys.argv[2])
    elif cmd == "symbol" and len(sys.argv) >= 3:
        cmd_symbol(sys.argv[2])
    else:
        print(f"Unknown command: {cmd}")
        print("Commands: lookup, taints, propagations, orchestration, index, symbol")
        sys.exit(1)


if __name__ == "__main__":
    main()
