#!/usr/bin/env python3
"""自主模式服务工具: read_function <name|file:line>

读函数体 + 记录探索轨迹 (trajectory) + 新文件增量建库。
- agent 经 bash 调用 → 服务侧感知 (写 path.log) → 流式记录探索路径。
- 不读非函数的任意文件 (受限: 只读已索引/可索引的函数定义), 避免绕过读源码。

环境变量:
  DVS_RUN_DIR        - 任务 run 目录 (path.log/vuln-scan.sqlite 所在)
  DVS_V2_DB_DIR      - dataflow-v2 目录 (functions.db)
  DVS_SOURCE_ROOT    - 源码根
"""
import json
import os
import sys
import time
from pathlib import Path

RUN_DIR = os.environ.get("DVS_RUN_DIR") or ""
V2_DB_DIR = os.environ.get("DVS_V2_DB_DIR") or os.path.join(RUN_DIR, "dataflow-v2")
SOURCE_ROOT = os.environ.get("DVS_SOURCE_ROOT") or "/data/target"
PATH_LOG = os.path.join(RUN_DIR, "path.log") if RUN_DIR else ""


def _store():
    sys.path.insert(0, "/opt/dataflow_vuln_scan")
    from app.dataflow_v2.store import DataflowStore
    return DataflowStore(V2_DB_DIR)


def _resolve(rec_name: str, store):
    """name 或 file:line → FunctionRecord (三级回退, 复用 function_extractor)。"""
    from app.dataflow_v2.function_extractor import find_func_in_source, ensure_file_indexed
    # 1) 直查 (name 可能在多文件; 先按名)
    rec = store.find_function(rec_name)
    if rec:
        return rec
    # 2) file:line 形式
    if ":" in rec_name:
        fpart, _, lpart = rec_name.rpartition(":")
        rec = store.find_function("", fpart)
        if rec:
            return rec
    # 3) on-demand: 源码树搜定义 → 增量建库 → 再查
    found = find_func_in_source(rec_name, Path(SOURCE_ROOT))
    if found:
        rel_file, _ = found
        try:
            ensure_file_indexed(SOURCE_ROOT, rel_file, store)
        except Exception:
            pass
        rec = store.find_function(rec_name) or store.find_function("", rel_file)
        if rec:
            return rec
    return None


def main():
    if len(sys.argv) < 2:
        print("用法: read_function <函数名|file:line> [start-end]", file=sys.stderr)
        sys.exit(2)
    query = sys.argv[1].strip()
    line_range = sys.argv[2].strip() if len(sys.argv) >= 3 else ""  # 形如 100-120 / 100-
    if not RUN_DIR:
        print("[read_function] DVS_RUN_DIR 未设置", file=sys.stderr)
        sys.exit(1)
    try:
        store = _store()
        rec = _resolve(query, store)
        if rec is None:
            print(f"[read_function] 未找到函数: {query}", file=sys.stderr)
            sys.exit(1)
        from app.dataflow_v2.function_extractor import read_function_body
        body = read_function_body(SOURCE_ROOT, rec, max_lines=500)
        # 行范围裁剪 (cat-like 部分读)
        ranged = False
        if line_range:
            try:
                a, _, b = line_range.partition("-")
                a_i = int(a) if a else rec.start_line
                b_i = int(b) if b else rec.end_line
                a_i = max(a_i, rec.start_line); b_i = min(b_i, rec.end_line)
                body_lines = body.splitlines()
                # body 第 1 行 = rec.start_line
                offset = a_i - rec.start_line
                body = "\n".join(body_lines[offset: offset + (b_i - a_i + 1)])
                ranged = True
                disp_start, disp_end = a_i, b_i
            except Exception:
                ranged = False
        # 记 trajectory (流式)
        step = {"ts": time.time(), "func": rec.name, "file": rec.file,
                "start_line": rec.start_line, "end_line": rec.end_line,
                "signature": rec.signature, "query": query,
                "line_range": line_range or None, "via": "read_function"}
        if PATH_LOG:
            with open(PATH_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(step, ensure_ascii=False) + "\n")
        # 输出给 LLM
        if ranged:
            print(f"## {rec.file}::{rec.name} 行 {disp_start}-{disp_end} (函数 {rec.start_line}-{rec.end_line})")
        else:
            print(f"## {rec.file}::{rec.name} (行 {rec.start_line}-{rec.end_line})")
        print(f"签名: {rec.signature}")
        if rec.description:
            print(f"功能: {rec.description}")
        print("```c")
        print(body)
        print("```")
    except Exception as e:
        print(f"[read_function] 错误: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
