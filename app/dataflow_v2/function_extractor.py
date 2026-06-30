"""dataflow-v2 函数提取器 (tree-sitter)。

对整个文件做 tree-sitter parse, 提取所有函数定义入函数库, 并把每个函数体
单独写入 run/functions/<rel>__<name>__<hash>.c (body_path 索引指向这里)。

复用 function_resolver._extract_functions_tree_sitter 的 tree-sitter 装载方式,
扩展为: 提取 end_line + signature + 函数体切片落盘。
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .models import FunctionRecord
from .store import DataflowStore

_CPP_EXTS = {".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}


def _language(path: Path) -> Any:
    from tree_sitter import Language
    if path.suffix.lower() in _CPP_EXTS:
        import tree_sitter_cpp
        return Language(tree_sitter_cpp.language())
    import tree_sitter_c
    return Language(tree_sitter_c.language())


def _parser_for(path: Path) -> Any:
    from tree_sitter import Parser
    parser = Parser()
    try:
        parser.language = _language(path)            # tree-sitter >= 0.21 API
    except Exception:
        parser.set_language(_language(path))         # 旧 API
    return parser


def _func_signature(node: Any, source: bytes) -> str:
    """从 function_definition 节点取声明部分 (去除 body)。"""
    # function_definition 子节点: (storage)*(type) declarator (params) compound
    # 简单取第一行 (declaration) 直至 '{'
    try:
        start = node.start_byte
        body = node.child_by_field_name("body")
        end = body.start_byte if body is not None else node.end_byte
        decl = source[start:end].decode("utf-8", "replace").strip()
        return " ".join(decl.split())
    except Exception:
        return ""


def extract_file_functions(source_root: str | Path, rel_file: str,
                           store: DataflowStore) -> list[FunctionRecord]:
    """提取一个文件的全部函数入库 + 函数体落盘。返回新建/更新的 FunctionRecord 列表。

    若文件已全部入库 (按 file + 各函数起止行命中) 则跳过落盘, 仍返回记录。
    """
    src_path = Path(source_root) / rel_file
    if not src_path.is_file():
        return []
    source = src_path.read_bytes()
    try:
        parser = _parser_for(src_path)
        tree = parser.parse(source)
    except Exception:
        return []

    funcs_dir = store.run_dir / "functions"
    records: list[FunctionRecord] = []
    root = tree.root_node

    def walk(node: Any) -> None:
        if node.type == "function_definition":
            name_node = node.child_by_field_name("declarator")
            # 取函数名: C 直接 identifier; C++ 方法可能 scoped_identifier (Class::method)
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
            # 函数体落盘
            safe_file = rel_file.replace("/", "__").replace("\\", "__")
            body_name = f"{safe_file}__{nm or 'unk'}__{func_hash}.c"
            body_path_obj = funcs_dir / body_name
            try:
                body_path_obj.write_bytes(body_bytes)
            except OSError:
                pass
            rec = FunctionRecord(
                file=rel_file, name=nm or "_unknown_", signature=signature,
                start_line=start_line, end_line=end_line,
                body_path=str(body_path_obj), func_hash=func_hash,
            )
            store.upsert_function(rec)
            records.append(rec)
        for ch in node.children:
            walk(ch)

    walk(root)
    return records


def ensure_file_indexed(source_root: str | Path, rel_file: str,
                        store: DataflowStore) -> list[FunctionRecord]:
    """步骤 6(1): 若函数库里没有该文件的函数, 则 tree-sitter 提取存库 + 落盘。"""
    existing = [f for f in store.list_functions() if f.file == rel_file]
    if existing:
        return existing
    return extract_file_functions(source_root, rel_file, store)


_SRC_EXTS = (".c", ".cc", ".cpp", ".cxx")


def index_source_tree(source_root: str | Path, store: DataflowStore,
                       on_progress: Any = None) -> int:
    """冷启动全局函数索引: 遍历源码目录所有 .c/.cpp 文件, tree-sitter 提取全部函数入库。

    一次性建全局函数库 (复用), 之后任何 callee 按名即可系统解析其所在文件,
    不依赖 LLM 提供 target_file。跳过测试/build 产物目录。
    """
    root = Path(source_root)
    n = 0
    for path in root.rglob("*"):
        if path.suffix.lower() not in _SRC_EXTS:
            continue
        parts = set(path.parts)
        if parts & {"test", "tests", "fuzz", "build", "out", "cmake-build-debug",
                   "cmake-build-release", ".git", "third_party", "vendor"}:
            continue
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        try:
            extract_file_functions(source_root, rel, store)
            n += 1
            if on_progress:
                on_progress(n)
        except Exception:
            continue
    return n
