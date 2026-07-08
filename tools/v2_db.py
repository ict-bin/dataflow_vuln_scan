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


def cmd_lookup(name: str) -> None:
    func = _find_func(name)
    if not func:
        print(f"NOT_FOUND: 函数 '{name}' 不在数据库中。")
        print(f"提示: 用 `v2_db index <file_path>` 索引该函数所在的源文件, 然后重新 lookup。")
        return
    body = _read_body(func)
    print(f"function: {func['name']}")
    print(f"file: {func['file']}")
    print(f"lines: {func['start_line']}-{func['end_line']}")
    print(f"signature: {func['signature']}")
    print(f"description: {func.get('description', '')}")
    print(f"---")
    print(body)


def cmd_taints(name: str) -> None:
    func = _find_func(name)
    if not func:
        print(f"NOT_FOUND: 函数 '{name}' 不在数据库中。")
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
        print(f"NOT_FOUND: 函数 '{name}' 不在数据库中。")
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
        print(f"NOT_FOUND: 函数 '{name}' 不在数据库中。")
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

    # 动态导入 function_extractor (在容器内 app 包路径)
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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
