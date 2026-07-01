"""tree-sitter 函数提取: 全量索引源码目录所有函数到 functions.db。

不单独存函数体文件 (避免拷贝整份源码)。数据库存 file + start_line + end_line,
需要函数体时用 read_function_body() 从原源文件按行读取。
"""
from __future__ import annotations

import hashlib
import logging
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


def _parser_for(path: Path):
    ext = path.suffix.lower()
    if ext not in _LANG_CACHE:
        if ext in (".c", ".h"):
            try:
                import tree_sitter_c as _c
                lang = _ts.Language(_c.language())
            except ImportError:
                return None
        elif ext in (".cpp", ".cc", ".cxx", ".hpp"):
            try:
                import tree_sitter_cpp as _cpp
                lang = _ts.Language(_cpp.language())
            except ImportError:
                return None
        else:
            return None
        _LANG_CACHE[ext] = lang
    lang = _LANG_CACHE[ext]
    if lang not in _PARSER_CACHE:
        _PARSER_CACHE[lang] = _ts.Parser(lang)
    return _PARSER_CACHE[lang]


def _func_signature(node: Any, source: bytes) -> str:
    body = node.child_by_field_name("body")
    end = body.start_byte if body is not None else node.end_byte
    sig = source[node.start_byte:end].decode("utf-8", "replace").strip()
    return sig[:500]


def read_function_body(source_root: str, func: FunctionRecord, max_lines: int = 0) -> str:
    """从原源文件按 start_line/end_line 读取函数体 (不依赖 body_path 文件)。"""
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
        return "\n".join(body_lines)
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
        parser = _parser_for(src_path)
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
            store.upsert_function(rec)
        for child in node.children:
            walk(child)

    walk(root)
    return records


def ensure_file_indexed(source_root: str, rel_file: str, store: DataflowStore) -> None:
    """确保某文件已索引 (如跟入函数所在文件尚未索引)。"""
    existing = [f for f in store.list_functions() if f.file == rel_file]
    if existing:
        return
    extract_file_functions(source_root, rel_file, store)


def index_source_tree(source_root: str, store: DataflowStore) -> int:
    """全量索引源码目录 (冷启动)。返回索引的文件数。"""
    if not _TS_AVAILABLE:
        logger.warning("tree-sitter 不可用, 跳过源码索引")
        return 0
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
    return count
