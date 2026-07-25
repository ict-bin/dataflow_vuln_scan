#!/opt/venv/bin/python
"""自主模式服务工具: grep_function <pattern> [-n N]

搜源码, 返回**包含该 pattern 的函数名清单**(不返回函数体)。
LLM 想看内容必须再调 read_function (记 path) -> 闭环, 无法绕过日志。
- pattern 出现在哪个函数的行范围内 → 报那个函数名 + 命中行号。
- 记 path.log (搜了什么 + 命中哪些函数)。

环境变量: DVS_RUN_DIR / DVS_V2_DB_DIR / DVS_SOURCE_ROOT
用法: grep_function "memcpy" -n 20
"""
import json
import logging
import os
import re
import subprocess
import sys

logger = logging.getLogger("dvs.autonomous.grep_function")
from pathlib import Path

RUN_DIR = os.environ.get("DVS_RUN_DIR", "")
V2_DB_DIR = os.environ.get("DVS_V2_DB_DIR") or os.path.join(RUN_DIR, "dataflow-v2")
SOURCE_ROOT = os.environ.get("DVS_SOURCE_ROOT") or "/data/target"
PATH_LOG = os.path.join(RUN_DIR, "path.log") if RUN_DIR else ""


def _functions_by_file(store):
    """file -> [(start, end, name, signature)]"""
    import sqlite3
    c = sqlite3.connect(os.path.join(V2_DB_DIR, "functions.db"))
    c.row_factory = sqlite3.Row
    by_file = {}
    for r in c.execute("SELECT name, file, start_line, end_line, signature FROM functions"):
        by_file.setdefault(r["file"], []).append(
            (r["start_line"], r["end_line"], r["name"], r["signature"]))
    c.close()
    return by_file


def _grep(pattern, limit):
    """受限 grep source_root, 返回 [(file, line_no, line_text)]"""
    src = Path(SOURCE_ROOT)
    hits = []
    try:
        # 递归搜, 排除常见非源目录
        cmd = ["grep", "-rnE", pattern, str(src),
               "--include=*.c", "--include=*.cpp", "--include=*.cc", "--include=*.cxx",
               "--include=*.h", "--include=*.hpp", "--include=*.hxx"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                             cwd=str(src), errors="replace").stdout
        for line in out.splitlines():
            # 格式: file:lineno:content  (file 相对 src? grep -n 给相对/绝对看 cwd)
            m = re.match(r"^(.+?):(\d+):(.*)$", line)
            if m:
                f, ln, txt = m.group(1), int(m.group(2)), m.group(3)
                # 相对化
                try:
                    f = str(Path(f).relative_to(src))
                except Exception as e:
                    logger.debug("relativize grep hit path failed (f=%s): %s", f, e)
                hits.append((f, ln, txt))
                if len(hits) >= limit:
                    break
    except Exception as e:
        logger.warning("grep_function scan failed: %s", e)
    return hits


def _find_func_for_line(by_file, file, line):
    """行号落在哪个函数的 [start,end] 内"""
    for (s, e, name, sig) in by_file.get(file, []):
        if s <= line <= e:
            return (name, s, e, sig)
    return None


def main():
    logging.basicConfig(level=os.environ.get("DVS_LOG_LEVEL", "INFO"), stream=sys.stderr,
                        format="%(levelname)s %(name)s: %(message)s")
    if len(sys.argv) < 2:
        print("用法: grep_function <pattern> [-n N]", file=sys.stderr)
        sys.exit(2)
    pattern = sys.argv[1]
    limit = 30
    if "-n" in sys.argv:
        i = sys.argv.index("-n")
        if i + 1 < len(sys.argv):
            try: limit = int(sys.argv[i + 1])
            except Exception as e: logger.debug("parse -n limit failed, keep default: %s", e)
    sys.path.insert(0, "/opt/dataflow_vuln_scan")
    # 增量索引保证 functions.db 有数据
    try:
        from app.dataflow_v2.store import DataflowStore
        store = DataflowStore(V2_DB_DIR)
        by_file = _functions_by_file(store)
        store.close()
    except Exception as e:
        print(f"[grep_function] 索引读取失败: {e}", file=sys.stderr)
        by_file = {}

    hits = _grep(pattern, limit)
    # 映射到函数
    matched = {}  # name -> {file, lines:[(lineno,txt)], range, sig}
    for (f, ln, txt) in hits:
        fi = _find_func_for_line(by_file, f, ln)
        if fi:
            name, s, e, sig = fi
            d = matched.setdefault(name, {"file": f, "start": s, "end": e, "sig": sig, "lines": []})
            d["lines"].append((ln, txt.strip()[:80]))
        else:
            # 不在任何已索引函数内 (宏/全局代码) -> 单列
            matched.setdefault(f"<global:{f}:{ln}>", {"file": f, "start": ln, "end": ln, "sig": "", "lines": [(ln, txt.strip()[:80])]})

    # 记 path.log (搜了什么 + 命中哪些函数)
    if PATH_LOG and matched:
        import time
        step = {"ts": time.time(), "via": "grep_function", "query": pattern,
                "matched_funcs": list(matched.keys())[:50]}
        try:
            with open(PATH_LOG, "a", encoding="utf-8") as fp:
                fp.write(json.dumps(step, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.warning("append path.log failed: %s", e)

    # 输出给 LLM: 函数名清单 + 命中行 (不给函数体)
    if not matched:
        print(f"无匹配: pattern '{pattern}' 在源码中未找到。")
        return
    print(f"grep '{pattern}' 命中 {len(matched)} 个函数 (要看函数体请调 read_function <函数名>):")
    for name, d in list(matched.items())[:limit]:
        print(f"\n## {name} ({d['file']} 行 {d['start']}-{d['end']})")
        if d['sig']:
            print(f"签名: {d['sig'][:120]}")
        for (ln, txt) in d['lines'][:5]:
            print(f"  L{ln}: {txt}")


if __name__ == "__main__":
    main()
