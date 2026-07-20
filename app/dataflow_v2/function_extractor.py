"""tree-sitter 函数提取 + 作用域索引: 函数/include/class 继承图。

冷启动全量索引源码目录:
  - 函数: 提取所有函数到 functions.db (不存函数体文件, 按行读源文件)
  - include 索引: 提取 #include 指令, 建传递闭包 (C 作用域)
  - class 继承图: 提取 class/struct 定义, 基类, 成员变量 (C++ 作用域)
"""
from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Any

from .models import FunctionRecord
from .store import DataflowStore

logger = logging.getLogger("dvs.dataflow_v2.function_extractor")

_TS_AVAILABLE = False
try:
    import tree_sitter as _ts
    _TS_AVAILABLE = True
except ImportError:
    _TS_AVAILABLE = False

_LANG_CACHE: dict[str, Any] = {}
_PARSER_CACHE: dict[str, Any] = {}

# C++ 关键字线索: .h 头文件按内容判 C/C++ (C++ 头含 namespace/template/class/std::)
_CPP_HINTS = (b"namespace ", b"namespace\n", b"template ", b"template<", b"class ",
              b"std::", b"::", b"using namespace", b"public:", b"private:",
              b"protected:", b"virtual ", b"throw(", b"operator ")


def _parser_for(path: Path, source: bytes | None = None):
    """按后缀+内容选 parser。.h 头可能是 C 或 C++, 按内容判 (含 namespace/template/class
    等用 C++ parser, 否则 C)。避免 C parser 解析 C++ 头误提 namespace 为函数/漏模板函数。"""
    ext = path.suffix.lower()
    if ext in (".cpp", ".cc", ".cxx", ".hpp"):
        return _parser_cached("cpp")
    if ext == ".c":
        return _parser_cached("c")
    if ext == ".h":
        src = source if source is not None else b""
        if not src and path.is_file():
            try:
                src = path.read_bytes()
            except OSError:
                src = b""
        is_cpp = any(h in src for h in _CPP_HINTS)
        return _parser_cached("cpp" if is_cpp else "c")
    return None


def _parser_cached(kind: str):
    if kind not in _PARSER_CACHE:
        try:
            if kind == "cpp":
                import tree_sitter_cpp as _cpp
                lang = _ts.Language(_cpp.language())
            else:
                import tree_sitter_c as _c
                lang = _ts.Language(_c.language())
        except ImportError:
            return None
        _PARSER_CACHE[kind] = _ts.Parser(lang)
    return _PARSER_CACHE[kind]


def _function_name_candidates(name: str) -> list[str]:
    """生成函数名候选集。

    兼容 C++ 命名空间/类限定名: `A::B::func` 会展开为
    `A::B::func`, `B::func`, `func`，用于高召回的源码树定位。
    """
    normalized = str(name or "").strip()
    if not normalized:
        return []
    parts = [part.strip() for part in normalized.split("::") if part.strip()]
    if len(parts) <= 1:
        return [normalized]
    candidates: list[str] = []
    for idx in range(len(parts)):
        candidate = "::".join(parts[idx:])
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _func_signature(node: Any, source: bytes) -> str:
    body = node.child_by_field_name("body")
    end = body.start_byte if body is not None else node.end_byte
    sig = source[node.start_byte:end].decode("utf-8", "replace").strip()
    return sig[:500]


def read_function_body(source_root: str, func: FunctionRecord, max_lines: int = 0) -> str:
    """从原源文件按 start_line/end_line 读取函数体, 带行号前缀。"""
    src_path = Path(source_root) / func.file
    if not src_path.is_file():
        return f"// 源文件不可读: {func.file}\n// 行 {func.start_line}-{func.end_line}"
    try:
        lines = src_path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(0, func.start_line - 1)
        end = min(len(lines), func.end_line)
        body_lines = lines[start:end]
        if max_lines > 0 and len(body_lines) > max_lines:
            body_lines = body_lines[:max_lines]
        return "\n".join(f"{func.start_line+i:4d} | {line}" for i, line in enumerate(body_lines))
    except OSError as e:
        return f"// 读取失败: {e}\n// 行 {func.start_line}-{func.end_line}"


def extract_file_functions(source_root: str, rel_file: str, store: DataflowStore) -> list[FunctionRecord]:
    """解析单个源文件, 提取所有函数, 存入 functions.db (不写 body 文件)。"""
    if not _TS_AVAILABLE:
        return []
    src_path = Path(source_root) / rel_file
    if not src_path.is_file():
        return []
    source = src_path.read_bytes()
    try:
        parser = _parser_for(src_path, source)
        if parser is None:
            return []
        tree = parser.parse(source)
    except Exception:
        return []

    records: list[FunctionRecord] = []
    root = tree.root_node

    def walk(node: Any) -> None:
        if node.type == "function_definition":
            name_node = node.child_by_field_name("declarator")
            nm = ""
            cur = name_node
            while cur is not None:
                ct = cur.type
                if ct in ("identifier", "type_identifier"):
                    nm = cur.text.decode("utf-8", "replace"); break
                if ct in ("scoped_identifier", "qualified_identifier", "namespace_qualified_name"):
                    nm = cur.text.decode("utf-8", "replace"); break
                cur = cur.child_by_field_name("declarator") or (cur.children[0] if cur.children else None)
            start_line = int(node.start_point[0]) + 1
            end_line = int(node.end_point[0]) + 1
            signature = _func_signature(node, source)
            body_bytes = source[node.start_byte:node.end_byte]
            func_hash = hashlib.sha1(body_bytes).hexdigest()[:16]
            rec = FunctionRecord(
                file=rel_file, name=nm or "_unknown_", signature=signature,
                start_line=start_line, end_line=end_line,
                body_path="", func_hash=func_hash,
            )
            records.append(rec)
            for _attempt in range(3):
                try:
                    store.upsert_function(rec)
                    break
                except Exception:
                    if _attempt < 2:
                        import time as _time
                        _time.sleep(0.1)
                    # ON CONFLICT DO UPDATE is idempotent; if all 3 attempts fail,
                    # another process likely already wrote this function
        for child in node.children:
            walk(child)

    walk(root)
    return records


def ensure_file_indexed(source_root: str, rel_file: str, store: DataflowStore) -> str:
    """确保某文件已索引。返回值:
      "indexed"  - 已完成索引 (之前或本次)
      "indexing"  - 另一进程正在索引此文件 (部分函数可能已入库, 但不完整)
    """
    existing = [f for f in store.list_functions() if f.file == rel_file]
    # 检查是否正在被另一进程索引
    # MySQL 优先: 查 indexing 状态
    if store._mysql:
        is_indexing = [{}] if store._mysql.read_is_indexing(rel_file) else []
    else:
        is_indexing = store._q("functions", "SELECT 1 FROM indexing_files WHERE file_path=?", (rel_file,))
    if is_indexing:
        # 另一进程正在索引: 不重复索引, 但告知调用方状态
        return "indexing"
    if existing and not is_indexing:
        return "indexed"  # 已完整索引
    # MySQL 优先: 查是否已索引
    if store._mysql and store._mysql.read_is_indexed(rel_file) and not existing:
        return "indexed"
    if not existing and store._mysql and store._mysql.read_is_indexed(rel_file):
        return "indexed"
    # 标记为正在索引
    import time
    store._exec("functions", "INSERT OR REPLACE INTO indexing_files (file_path, started_at) VALUES (?, ?)",
                (rel_file, time.time()))
    if store._mysql:
        store._mysql.add_indexing_file(rel_file)
    try:
        # 1) tree-sitter 函数提取
        extract_file_functions(source_root, rel_file, store)
        # 2) include 索引 (该文件的直接 include → 入库)
        incs = _extract_includes(source_root, rel_file)
        if incs:
            for header in incs:
                store.add_include(header, rel_file)
        # 3) class 继承图 + member (该文件的 class 定义 → 入库)
        if _TS_AVAILABLE:
            _extract_class_info_for_file(source_root, rel_file, store)
    finally:
        # 完成后删除标记
        store._exec("functions", "DELETE FROM indexing_files WHERE file_path=?", (rel_file,))
        if store._mysql:
            store._mysql.finish_indexing_file(rel_file)
    return "indexed"


def find_function_in_file(source_root: str, rel_file: str, name: str) -> tuple[int, int, str] | None:
    """在源文件中用 tree-sitter 查找函数定义, 不依赖 DB。

    返回 (start_line, end_line, signature) 或 None。
    纯读取, 无写入, 无 SQLite, 无并发问题。
    """
    from pathlib import Path
    src_path = Path(source_root) / rel_file
    if not src_path.is_file():
        import sys; print(f"[v2db-ffi] file not found {rel_file}", file=sys.stderr, flush=True)
        return None
    source = src_path.read_bytes()
    parser = _parser_for(src_path, source)
    if parser is None:
        import sys; print(f"[v2db-ffi] parser None {rel_file}", file=sys.stderr, flush=True)
        return None
    try:
        tree = parser.parse(source)
    except Exception as e:
        import sys; print(f"[v2db-ffi] parse failed {rel_file}: {e}", file=sys.stderr, flush=True)
        return None

    func_count = [0]
    matched = [None]

    def walk(node):
        if node.type == "function_definition":
            name_node = node.child_by_field_name("declarator")
            nm = ""
            cur = name_node
            while cur is not None:
                ct = cur.type
                if ct in ("identifier", "type_identifier", "scoped_identifier", "qualified_identifier", "namespace_qualified_name"):
                    nm = cur.text.decode("utf-8", "replace"); break
                cur = cur.child_by_field_name("declarator") or (cur.children[0] if cur.children else None)
            func_count[0] += 1
            if nm == name:
                start_line = int(node.start_point[0]) + 1
                end_line = int(node.end_point[0]) + 1
                sig = _func_signature(node, source)
                matched[0] = (start_line, end_line, sig)
                return
        for child in node.children:
            walk(child)
            if matched[0]:
                return

    walk(tree.root_node)
    import sys; print(f"[v2db-ffi] {rel_file} found {func_count[0]} funcs match={matched[0] is not None}", file=sys.stderr, flush=True)
    return matched[0]

# ── include 索引 (C 作用域) ──────────────────────────────────────────────

_INCLUDE_RE = re.compile(r'^\s*#\s*include\s+[<"]([^>"]+)[>"]', re.MULTILINE)


def _extract_includes(source_root: str, rel_file: str) -> list[str]:
    """提取文件的 #include 指令 (直接 include, 非传递)。"""
    src_path = Path(source_root) / rel_file
    if not src_path.is_file():
        return []
    try:
        text = src_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return _INCLUDE_RE.findall(text)


def _resolve_header_path(source_root: str, header: str) -> str | None:
    """尝试在源码树中找到 header 的相对路径。"""
    # header 可能是 "path/to/header.h" 或 <header.h>
    candidates = [
        header,
        header.lstrip("/"),
    ]
    for c in candidates:
        p = Path(source_root) / c
        if p.is_file():
            return c
    # 搜同名文件
    name = Path(header).name
    for p in Path(source_root).rglob(name):
        return str(p.relative_to(source_root)).replace("\\", "/")
    return None


def _build_include_index(source_root: str, store: DataflowStore) -> int:
    """建 include 传递闭包索引: (header, file) 对。

    对于每个 .c/.cpp 文件, 计算它传递性 include 的所有 header, 存入 include_index。
    """
    src = Path(source_root)
    exts = {".c", ".cpp", ".cc", ".cxx"}
    # 1) 收集所有文件的直接 include
    file_includes: dict[str, list[str]] = {}  # rel_file -> [headers]
    for path in src.rglob("*"):
        if path.suffix.lower() not in exts and path.suffix.lower() not in {".h", ".hpp"}:
            continue
        try:
            rel = str(path.relative_to(src)).replace("\\", "/")
        except ValueError:
            continue
        incs = _extract_includes(source_root, rel)
        if incs:
            file_includes[rel] = incs

    # 2) 对每个 .c/.cpp 文件, 计算传递闭包
    count = 0
    for rel_file, direct_incs in file_includes.items():
        if not any(rel_file.endswith(ext) for ext in exts):
            continue  # 只对 .c/.cpp 文件建索引
        # BFS 传递闭包
        visited: set[str] = set()
        queue = list(direct_incs)
        while queue:
            header = queue.pop(0)
            if header in visited:
                continue
            visited.add(header)
            # 解析 header 在源码树中的路径, 获取它的 includes
            resolved = _resolve_header_path(source_root, header)
            if resolved and resolved in file_includes:
                for sub_inc in file_includes[resolved]:
                    if sub_inc not in visited:
                        queue.append(sub_inc)
        # 存入 include_index
        for header in visited:
            store.add_include(header, rel_file)
        count += 1

    logger.info("include index: %d files, %d entries", count,
                len(store._q("functions", "SELECT COUNT(*) as c FROM include_index")))
    return count


# ── class 继承图 (C++ 作用域) ────────────────────────────────────────────

def _extract_class_info(source: bytes, tree: Any, rel_file: str) -> list[dict]:
    """从 AST 提取 class/struct 定义: 类名, 基类, 成员变量。"""
    classes: list[dict] = []

    def walk(node: Any) -> None:
        # C++ class_definition 或 struct_specifier (C struct with body)
        if node.type in ("class_definition", "struct_specifier", "union_specifier"):
            name = ""
            # 类名: child_by_field_name("name")
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                name = name_node.text.decode("utf-8", "replace")
            if not name:
                for child in node.children:
                    if child.type in ("identifier", "type_identifier"):
                        name = child.text.decode("utf-8", "replace")
                        break
            if not name:
                for child in node.children:
                    walk(child)
                return
            # 基类: base_class_clause
            bases: list[str] = []
            for child in node.children:
                if child.type == "base_class_clause":
                    # base_class_clause 的子节点是 base_class 节点
                    for bc in child.children:
                        if bc.type in ("base_class", "qualified_identifier", "identifier"):
                            txt = bc.text.decode("utf-8", "replace").strip()
                            if txt and txt not in ("public", "private", "protected", "virtual", ":"):
                                bases.append(txt)
            # 成员变量: field_declaration (不是 function)
            members: list[tuple[str, str]] = []
            body = node.child_by_field_name("body")
            if body is not None:
                for child in body.children:
                    if child.type == "field_declaration" or child.type == "field_declaration_list":
                        # 提取成员名: 最后一个 identifier
                        field_name = ""
                        field_type = ""
                        for fc in child.children:
                            if fc.type in ("identifier", "field_identifier", "type_identifier"):
                                field_name = fc.text.decode("utf-8", "replace")
                            elif fc.type in ("type_descriptor", "primitive_type", "sized_type_specifier"):
                                field_type = fc.text.decode("utf-8", "replace")
                        if field_name:
                            members.append((field_name, field_type))
            classes.append({
                "name": name, "bases": bases, "members": members, "file": rel_file,
            })
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return classes


def _extract_class_info_for_file(source_root: str, rel_file: str, store: DataflowStore) -> None:
    """对单个文件提取 class 继承图 + member (增量, 不全量扫描)。"""
    if not _TS_AVAILABLE:
        return
    path = Path(source_root) / rel_file
    if not path.is_file():
        return
    source = path.read_bytes()
    try:
        parser = _parser_for(path, source)
        if parser is None:
            return
        tree = parser.parse(source)
    except Exception:
        return
    classes = _extract_class_info(source, tree, rel_file)
    for cls in classes:
        store.add_class(cls["name"], cls["bases"], cls["file"])
        for member_name, member_type in cls["members"]:
            store.add_class_member(cls["name"], member_name, member_type, cls["file"])


def _build_class_hierarchy(source_root: str, store: DataflowStore) -> int:
    """建 class 继承图 + member 索引。"""
    if not _TS_AVAILABLE:
        return 0
    src = Path(source_root)
    exts = {".h", ".hpp", ".cpp", ".cc", ".cxx"}
    count = 0
    for path in src.rglob("*"):
        if path.suffix.lower() not in exts:
            continue
        try:
            rel = str(path.relative_to(src)).replace("\\", "/")
        except ValueError:
            continue
        source = path.read_bytes()
        try:
            parser = _parser_for(path, source)
            if parser is None:
                continue
            tree = parser.parse(source)
        except Exception:
            continue
        classes = _extract_class_info(source, tree, rel)
        for cls in classes:
            store.add_class(cls["name"], cls["bases"], cls["file"])
            for member_name, member_type in cls["members"]:
                store.add_class_member(cls["name"], member_name, member_type, cls["file"])
            count += 1

    logger.info("class hierarchy: %d classes", count)
    return count


# ── 全量索引入口 ──────────────────────────────────────────────────────────

def index_source_tree(source_root: str, store: DataflowStore) -> int:
    """全量索引源码目录 (冷启动): 函数 + include 索引 + class 继承图。"""
    if not _TS_AVAILABLE:
        logger.warning("tree-sitter 不可用, 跳过源码索引")
        return 0
    # 1) 函数索引
    count = 0
    src = Path(source_root)
    exts = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"}
    for path in src.rglob("*"):
        if path.suffix.lower() not in exts:
            continue
        try:
            rel = str(path.relative_to(src)).replace("\\", "/")
        except ValueError:
            continue
        extract_file_functions(source_root, rel, store)
        count += 1
    logger.info("indexed %d source files, %d functions", count, len(store.list_functions()))
    # 2) include 索引
    _build_include_index(source_root, store)
    # 3) class 继承图
    _build_class_hierarchy(source_root, store)
    return count


def find_func_in_source(name: str, src_root) -> list[tuple[str, str]]:
    """在源码树中搜索函数定义所在文件 (grep)。
    返回 (rel_file, matched_name) 或 None。
    用于 callee 不在 functions.db 时, on-demand 定位其定义文件并增量索引。
    搜 .c/.cpp/.cc/.cxx + .h/.hpp/.hxx (C++ 方法/模板常定义在头文件)。
    """
    import subprocess, re
    from pathlib import Path
    src_root = Path(src_root)
    try:
        results: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for candidate in _function_name_candidates(name):
            pattern = rf'\b{re.escape(candidate)}\s*\('
            r = subprocess.run(
                ["/usr/bin/grep", "-rl", "-E",
                 "--include=*.c", "--include=*.cpp", "--include=*.cc", "--include=*.cxx",
                 "--include=*.h", "--include=*.hpp", "--include=*.hxx",
                 pattern, str(src_root)],
                capture_output=True, text=True, timeout=15)
            for line in r.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    rel = str(Path(line).relative_to(src_root)).replace("\\", "/")
                except ValueError:
                    continue
                key = (rel, candidate)
                if key in seen:
                    continue
                seen.add(key)
                results.append((rel, candidate))
        return results
    except Exception:
        pass
    return []
