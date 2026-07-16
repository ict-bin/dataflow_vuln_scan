#!/usr/bin/env python3
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
        conn = sqlite3.connect(db, timeout=10)
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        conn.close()
        return rows
    except sqlite3.OperationalError as e:
        log.warning("query failed db=%s: %s", db_name, e)
        return []
    except Exception as e:
        log.warning("query error db=%s: %s", db_name, e)
        return []


def _find_func(name: str) -> dict | None:
    """查函数库, 支持短名后缀匹配 (C++ Class::Method)。"""
    rows = _query("functions.db", "SELECT * FROM functions WHERE name = ?", (name,))
    if rows:
        return rows[0]
    rows = _query("functions.db", "SELECT * FROM functions WHERE name LIKE ?", (f"%{name}",))
    return rows[0] if rows else None


def _read_body(func: dict) -> str:
    """从原源文件按 start_line/end_line 读取函数体。"""
    src = Path(_source_root()) / func["file"]
    if not src.is_file():
        return f"// 源文件不可读: {func['file']}"
    try:
        lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(0, func["start_line"] - 1)
        end = min(len(lines), func["end_line"])
        return "\n".join(lines[start:end])
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


def cmd_lookup(name: str) -> None:
    """查函数体: db 查 → 找不到 → grep 找文件 → tree-sitter 索引入库 → 返回。"""
    _t0 = time.time()
    log.info("lookup START name=%s db_dir=%s source_root=%s",
             name, os.environ.get("DVS_V2_DB_DIR", "(unset)"), os.environ.get("DVS_SOURCE_ROOT", "(unset)"))

    func = _find_func(name)
    if func:
        log.info("db HIT name=%s func_id=%s file=%s lines=%s-%s",
                 name, func.get("func_id", "")[:12], func.get("file", ""), func.get("start_line"), func.get("end_line"))
        _log_trajectory(func, name)
        body = _read_body(func)
        print(f"function: {func['name']}")
        print(f"file: {func['file']}")
        print(f"lines: {func['start_line']}-{func['end_line']}")
        print(f"signature: {func['signature']}")
        print(f"description: {func.get('description', '')}")
        print(f"---")
        print(body)
        return

    log.info("db MISS name=%s — trying find_func_in_source", name)

    # db 没找到 → 在源码树中搜索函数定义所在文件
    src_root = Path(_source_root())
    found = __import__("app.dataflow_v2.function_extractor", fromlist=["find_func_in_source"]).find_func_in_source(name, src_root)
    log.info("find_func_in_source returned %d candidates: %s", len(found), [(f, n) for f, n in found[:5]])
    if not found:
        # 精确源码搜未中 → 前缀候选 (LLM 截断名场景)
        _print_prefix_candidates(name, src_root)
        return

    # find_func_in_source 返回 list[tuple[str,str]]; 索引每个候选文件后重查
    db_dir = _db_dir()
    sys.path.insert(0, os.environ.get("DVS_APP_DIR", "/opt/dataflow_vuln_scan"))
    try:
        from app.dataflow_v2.function_extractor import ensure_file_indexed, extract_file_functions
        from app.dataflow_v2.store import DataflowStore
        store = DataflowStore(db_dir)
        indexing_files = []  # 文件正在被另一进程索引
        for rel_file, matched_name in found:
            try:
                log.info("indexing file=%s", rel_file)
                status = ensure_file_indexed(str(src_root), rel_file, store)
                if status == "indexing":
                    log.info("file=%s is being indexed by another process, will do own extraction", rel_file)
                    indexing_files.append(rel_file)
            except Exception as e:
                log.warning("index failed file=%s: %s", rel_file, e)
                print(f"INDEX_ERROR: 索引文件 {rel_file} 失败: {e}")
        store.close()
    except Exception as e:
        log.warning("index setup failed: %s", e)
        print(f"INDEX_ERROR: 索引失败: {e}")
        return

    # 再查 db
    func = _find_func(name)
    if func:
        log.info("db HIT (after index) name=%s duration=%.2fs", name, time.time() - _t0)
        _log_trajectory(func, name)
        body = _read_body(func)
        print(f"function: {func['name']}")
        print(f"file: {func['file']}")
        print(f"lines: {func['start_line']}-{func['end_line']}")
        print(f"signature: {func['signature']}")
        print(f"description: {func.get('description', '')}")
        print(f"---")
        print(body)
        return
    log.warning("db MISS (after index) name=%s duration=%.2fs", name, time.time() - _t0)

    # 某些文件正在被另一进程索引 → 自行 tree-sitter 提取, 直接搜函数 (不依赖 DB)
    if indexing_files:
        log.info("trying own tree-sitter extraction for %d files", len(indexing_files))
        try:
            from app.dataflow_v2.function_extractor import extract_file_functions
            from app.dataflow_v2.store import DataflowStore
            store2 = DataflowStore(db_dir)
            for rel_file in indexing_files:
                try:
                    records = extract_file_functions(str(src_root), rel_file, store2)
                    for rec in records:
                        if rec.name == name or name in rec.name or rec.name in name:
                            log.info("found via own extraction: name=%s file=%s lines=%s-%s",
                                     rec.name, rec.file, rec.start_line, rec.end_line)
                            # 读函数体直接返回
                            src_path = Path(src_root) / rec.file
                            if src_path.is_file():
                                lines = src_path.read_text(encoding="utf-8", errors="replace").splitlines()
                                body = "\n".join(lines[max(0, rec.start_line-1):min(len(lines), rec.end_line)])
                                print(f"function: {rec.name}")
                                print(f"file: {rec.file}")
                                print(f"lines: {rec.start_line}-{rec.end_line}")
                                print(f"signature: {rec.signature}")
                                print(f"description: {rec.description or ''}")
                                print(f"---")
                                print(body)
                                store2.close()
                                return
                except Exception as e:
                    log.warning("own extraction failed file=%s: %s", rel_file, e)
            store2.close()
        except Exception as e:
            log.warning("own extraction setup failed: %s", e)

    # 精确未找到 → 前缀/模糊匹配候选 (LLM 常传截断的长 C 函数名, 精确匹配会漏)
    _print_prefix_candidates(name, src_root)


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
    rows = _query("taints.db", "SELECT * FROM taints WHERE function = ?", (func_name,))
    if not rows:
        # 尝试模糊匹配
        rows = _query("taints.db", "SELECT * FROM taints WHERE function LIKE ?", (f"%{func_name}",))
    if rows:
        for r in rows:
            print(f"taint: {r['name']} (signature: {r['signature']})")
            print(f"  function: {r['function']}")
            print(f"  description: {r.get('description', '')}")
    else:
        print(f"NOT_FOUND: 函数 '{func_name}' 在污点库中未找到。")


def cmd_propagations(func_name: str) -> None:
    """查传播库: 返回函数的传播路径。"""
    # 先查 functions.db 拿 func_id, 再查 propagations.db (两库分离, 不能跨库子查询)
    func_rows = _query("functions.db", "SELECT func_id FROM functions WHERE name = ?", (func_name,))
    if not func_rows:
        func_rows = _query("functions.db", "SELECT func_id FROM functions WHERE name LIKE ?", (f"%{func_name}",))
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
    """查宏定义/typedef/struct/enum (grep 全盘 .h 优先, .c 补充)。"""
    import subprocess
    src = os.environ.get("DVS_SOURCE_ROOT", "")
    if not src:
        print("ERROR: DVS_SOURCE_ROOT 未设置")
        return
    log.info("symbol START name=%s src=%s", name, src)
    is_macro = name.isupper() or "_" in name and name.replace("_", "").isalnum()
    # 宏定义优先搜 .h, typedef/struct/enum 同时搜 .h+.c
    if is_macro:
        patterns = [f"#define[[:space:]]+{re.escape(name)}"]
    else:
        patterns = [
            f"#define[[:space:]]+{re.escape(name)}",
            f"typedef[[:space:]].*{re.escape(name)}",
            f"struct[[:space:]]+{re.escape(name)}",
            f"enum[[:space:]]+{re.escape(name)}",
        ]
    results = []
    # 先搜 .h (定义通常在头文件)
    for pattern in patterns:
        try:
            r = subprocess.run(
                ["/usr/bin/grep", "-rn", "-E", "--include=*.h",
                 pattern, src],
                capture_output=True, text=True, timeout=10)
            for line in r.stdout.strip().split("\n"):
                if line:
                    results.append(line)
        except Exception:
            pass
    log.info("symbol .h pattern search results=%d", len(results))
    # .h 未中 → 补搜 .c
    if not results:
        for pattern in patterns:
            try:
                r = subprocess.run(
                    ["/usr/bin/grep", "-rn", "-E", "--include=*.c",
                     pattern, src],
                    capture_output=True, text=True, timeout=10)
                for line in r.stdout.strip().split("\n"):
                    if line:
                        results.append(line)
            except Exception:
                pass
        log.info("symbol .c pattern search results=%d", len(results))
    # pattern 搜未中 → fallback: 纯名字搜 .h (看使用上下文, 如 struct field)
    if not results:
        log.info("symbol fallback: simple name search in .h")
        try:
            r = subprocess.run(
                ["/usr/bin/grep", "-rn", "--include=*.h",
                 name, src],
                capture_output=True, text=True, timeout=10)
            for line in r.stdout.strip().split("\n")[:20]:
                if line:
                    results.append(line)
            log.info("symbol fallback .h results=%d", len(results))
        except Exception:
            pass
    # .h fallback 未中 → 最后搜 .c
    if not results:
        log.info("symbol fallback: simple name search in .c")
        try:
            r = subprocess.run(
                ["/usr/bin/grep", "-rn", "--include=*.c",
                 name, src],
                capture_output=True, text=True, timeout=10)
            for line in r.stdout.strip().split("\n")[:20]:
                if line:
                    results.append(line)
            log.info("symbol fallback .c results=%d", len(results))
        except Exception:
            pass
    if results:
        print(f"SYMBOL: {name} 找到 {len(results)} 个匹配:")
        for line in results[:20]:
            print(f"  {line}")
    else:
        print(f"NOT_FOUND: 符号 '{name}' 在源码中未找到。该符号可能定义在外部库/系统头文件中。")


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
