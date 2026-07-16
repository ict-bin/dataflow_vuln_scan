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
import os
import sqlite3
import sys
from pathlib import Path

# 确保 app 包可导入: v2_db 可能被安装为 /usr/local/bin/v2_db (cp 副本, 非 symlink),
# 此时 __file__ 解析为 /usr/local/bin → __file__ 相对路径错 (/usr/local 无 app 包)。
# 用 DVS_APP_DIR (默认 /opt/dataflow_vuln_scan) 显式定位 app 包, 不依赖 __file__。
_APP_DIR = os.environ.get("DVS_APP_DIR", "/opt/dataflow_vuln_scan")
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)


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
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    conn.close()
    return rows


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
        return results
    except Exception:
        pass
    return []


def _log_trajectory(func: dict, query: str) -> None:
    """自主模式 (DVS_RUN_DIR 设了): 记 v2_db lookup 到 path.log (服务感知探索路径)。
    完整模式不设 DVS_RUN_DIR → 不记 (不影响)。"""
    run_dir = os.environ.get("DVS_RUN_DIR", "").strip()
    if not run_dir:
        return
    import time, json
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
    func = _find_func(name)
    if func:
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

    # db 没找到 → 在源码树中搜索函数定义所在文件
    src_root = Path(_source_root())
    found = __import__("app.dataflow_v2.function_extractor", fromlist=["find_func_in_source"]).find_func_in_source(name, src_root)
    if not found:
        # 精确源码搜未中 → 前缀候选 (LLM 截断名场景)
        _print_prefix_candidates(name, src_root)
        return

    # find_func_in_source 返回 list[tuple[str,str]]; 索引每个候选文件后重查
    db_dir = _db_dir()
    sys.path.insert(0, os.environ.get("DVS_APP_DIR", "/opt/dataflow_vuln_scan"))
    try:
        from app.dataflow_v2.function_extractor import ensure_file_indexed
        from app.dataflow_v2.store import DataflowStore
        store = DataflowStore(db_dir)
        for rel_file, matched_name in found:
            try:
                ensure_file_indexed(str(src_root), rel_file, store)
            except Exception as e:
                print(f"INDEX_ERROR: 索引文件 {rel_file} 失败: {e}")
        store.close()
    except Exception as e:
        print(f"INDEX_ERROR: 索引失败: {e}")
        return

    # 再查 db
    func = _find_func(name)
    if func:
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
    # 精确未找到 → 前缀/模糊匹配候选 (LLM 常传截断的长 C 函数名, 精确匹配会漏)
    _print_prefix_candidates(name, src_root)


def _print_prefix_candidates(name: str, src_root) -> None:
    """精确未找到时: 按前缀/包含查候选函数名, 返回给 LLM 用全名再查。

    修: LLM 常传截断名 (如 _dns_server_resolve_callback_reply_p 缺 assthrough),
    精确匹配 (grep \bname\s*\( + SQL name=?) 漏 → NOT_FOUND, LLM 又得改用 raw grep 找。
    现在前缀匹配: SQL name LIKE 'name%' + 源码 grep \bname (不需 \s*\() 索引候选 →
    返回候选函数名清单, LLM 用全名再 lookup。不再直接 NOT_FOUND。
    """
    import subprocess, re as _re
    db_dir = _db_dir()
    # 1) db 前缀/包含匹配
    cands = _query("functions.db", "SELECT name, file, start_line, end_line FROM functions WHERE name LIKE ? OR name LIKE ? ORDER BY length(name) LIMIT 20",
                   (f"{name}%", f"%{name}%"))
    # 2) db 无候选 → 源码前缀 grep (\bname 不需 \s*\(, 拓宽) + 增量索引
    if not cands:
        try:
            pat = _re.escape(name)
            r = subprocess.run(
                ["/usr/bin/grep", "-rl", "-E", rf"\b{pat}",
                 "--include=*.c", "--include=*.cpp", "--include=*.cc", "--include=*.cxx",
                 "--include=*.h", "--include=*.hpp", "--include=*.hxx", str(src_root)],
                capture_output=True, text=True, timeout=20)
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
                except Exception: pass
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


def cmd_taints(name: str) -> None:
    func = _find_func(name)
    if not func:
        print(f"NOT_FOUND: 函数 '{name}' 不在数据库中。该函数可能是外部库函数或系统 API，定义不在当前源码树中，不需要查找其源码。")
        return
    rows = _query("taints.db", "SELECT * FROM taints WHERE func_id = ?", (func["func_id"],))
    if not rows:
        print(f"函数 '{name}' 无污点变量记录。")
        return
    for r in rows:
        print(f"- {r['name']} ({r['signature']}): {r.get('description', '')}")


def cmd_propagations(name: str) -> None:
    func = _find_func(name)
    if not func:
        print(f"NOT_FOUND: 函数 '{name}' 不在数据库中。该函数可能是外部库函数或系统 API，定义不在当前源码树中，不需要查找其源码。")
        return
    rows = _query("propagations.db",
                  "SELECT * FROM propagations WHERE source_func_id = ?", (func["func_id"],))
    if not rows:
        print(f"函数 '{name}' 无传播路径记录。")
        return
    for r in rows:
        tgt = r.get("target_function") or "(外部变量)"
        ext = " [external]" if r.get("is_external") else ""
        print(f"- {r['source_taint_name']} → {tgt}({r['target_taint_name']}) @L{r.get('call_line','')} "
              f"[{r.get('condition','')}]{ext} {r.get('description','')}")


def cmd_orchestration(name: str) -> None:
    func = _find_func(name)
    if not func:
        print(f"NOT_FOUND: 函数 '{name}' 不在数据库中。该函数可能是外部库函数或系统 API，定义不在当前源码树中，不需要查找其源码。")
        return
    rows = _query("orchestration.db",
                  "SELECT * FROM orchestration WHERE source_func_id = ? ORDER BY path_id, edge_order",
                  (func["func_id"],))
    if not rows:
        print(f"函数 '{name}' 无调用链记录。")
        return
    for r in rows:
        print(f"- path={r['path_id'][:8]} order={r['edge_order']} depth={r['depth']} "
              f"→ {r['target_function']} [{r.get('status','')}]")


def cmd_index(file_path: str) -> None:
    """索引新文件到函数库。"""
    src_root = _source_root()
    # 归一化相对路径
    p = Path(file_path)
    if p.is_absolute():
        try:
            rel = str(p.relative_to(src_root)).replace("\\", "/")
        except ValueError:
            print(f"ERROR: 文件不在源码根目录下: {file_path}", file=sys.stderr)
            sys.exit(1)
    else:
        rel = file_path.replace("\\", "/")

    src_file = Path(src_root) / rel
    if not src_file.is_file():
        print(f"ERROR: 源文件不存在: {src_file}", file=sys.stderr)
        sys.exit(1)

    # 用 tree-sitter 索引
    db_dir = _db_dir()
    db_path = db_dir / "functions.db"
    conn = sqlite3.connect(db_path)

    # 检查是否已索引
    existing = conn.execute("SELECT COUNT(*) FROM functions WHERE file = ?", (rel,)).fetchone()[0]
    if existing > 0:
        print(f"文件 '{rel}' 已索引 ({existing} 个函数)。无需重复建库。")
        conn.close()
        return

    # 动态导入 function_extractor (app 包路径已由顶部 sys.path 确保)
    try:
        from app.dataflow_v2.function_extractor import extract_file_functions
        from app.dataflow_v2.store import DataflowStore
        store = DataflowStore(db_dir)
        recs = extract_file_functions(src_root, rel, store)
        print(f"已索引 '{rel}': {len(recs)} 个函数。")
        for r in recs:
            print(f"  - {r.name} (L{r.start_line}-{r.end_line})")
    except ImportError as e:
        # fallback: 简单的正则提取
        print(f"WARNING: tree-sitter 不可用 ({e}), 使用简化提取。")
        _simple_index(conn, rel, src_file)
    conn.close()


def _simple_index(conn, rel: str, src_file: Path):
    """无 tree-sitter 时的简化函数提取 (正则)。"""
    import re
    source = src_file.read_bytes()
    # 简单匹配 C 函数定义: type name(...) {
    pattern = rb'(?:^|\n)[\w\s\*]+?\b(\w+)\s*\([^)]*\)\s*\{'
    count = 0
    for m in re.finditer(pattern, source):
        name = m.group(1).decode("utf-8", "replace")
        if name in ("if", "for", "while", "switch", "return", "sizeof"):
            continue
        start_line = source[:m.start()].count(b"\n") + 1
        # 简单找结束括号
        depth = 0
        pos = m.end() - 1
        while pos < len(source):
            if source[pos:pos+1] == b"{":
                depth += 1
            elif source[pos:pos+1] == b"}":
                depth -= 1
                if depth == 0:
                    break
            pos += 1
        end_line = source[:pos].count(b"\n") + 1
        func_id = f"{rel}__{name}__{start_line}"
        conn.execute(
            "INSERT OR IGNORE INTO functions (func_id,file,name,signature,start_line,end_line,body_path,func_hash,description,processed_taints) VALUES (?,?,?,?,?,?,?,'','','[]')",
            (func_id, rel, name, f"{name}(...)", start_line, end_line, ""))
        count += 1
    conn.commit()
    print(f"简化索引 '{rel}': {count} 个函数。")


def cmd_symbol(name: str) -> None:
    """查宏定义/typedef/struct/enum — 一次 grep 全盘 .h/.c 文件。"""
    import subprocess, os
    src = os.environ.get("DVS_SOURCE_ROOT", "")
    if not src:
        print("ERROR: DVS_SOURCE_ROOT 未设置")
        return
    # grep 搜索 #define / typedef / struct / enum 定义
    patterns = [
        f"#define\\s+{name}\\b",
        f"typedef\\s+.*\\b{name}\\b",
        f"struct\\s+{name}\\b",
        f"enum\\s+{name}\\b",
        f"{name}\\s*=.*;".replace(f"{name}\\s*=.*;", f"\\b{name}\\s*="),  # enum member
    ]
    results = []
    for pattern in patterns:
        try:
            r = subprocess.run(
                ["grep", "-rn", "--include=*.h", "--include=*.c", "--include=*.cpp",
                 "-E", pattern, src],
                capture_output=True, text=True, timeout=15)
            for line in r.stdout.strip().split("\n"):
                if line and line not in results:
                    results.append(line)
        except Exception:
            pass
    if results:
        for line in results[:20]:
            print(line)
    else:
        print(f"NOT_FOUND: 符号 '{name}' 在源码中未找到定义。")
        print(f"提示: 可能是外部库/系统头文件中的符号, 用 grep -rn {name} /usr/include 搜索。")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
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
        print(f"未知命令: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
