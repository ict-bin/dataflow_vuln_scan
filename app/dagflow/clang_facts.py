"""dagflow clang 事实提取器 (不复用 V2 clang_analyzer, 自行设计)。

设计: docs/design-taint-analysis.md §3 — clang 先出结构事实, 注入 prompt, LLM 用事实构建 DAG。

clang 解析函数 AST → 提取:
  1. 调用点表: 每个 CallExpr → callee 名, line, 实参列表, 分支路径
  2. 分支结构: if/else/switch → condition 文本, line, then/else 行范围
  3. 校验点: if-statement → condition 文本, line, 检查的变量名

clang parse 失败 → 返回 None (调用方回退纯 LLM)。
"""
from __future__ import annotations
import hashlib, logging, threading
from pathlib import Path
from typing import Any

logger = logging.getLogger("dvs.dagflow.clang_facts")

_cindex = None
_ready = False
_tried = False
_lock = threading.Lock()
_TU_CACHE: dict[str, Any] = {}
_TU_CACHE_MAX = 50


def _ensure_clang() -> bool:
    """加载 libclang (libclang PyPI 包自带)。线程安全。"""
    global _cindex, _ready, _tried
    if _tried:
        return _ready
    with _lock:
        if _tried:
            return _ready
        _tried = True
        try:
            from clang import cindex
            _cindex = cindex
            idx = cindex.Index.create()
            _ready = True
            logger.info("libclang ready")
        except Exception as e:
            logger.warning("libclang unavailable: %s", e)
    return _ready


def _parse_args(source_root: str, path: Path) -> list[str]:
    ext = path.suffix.lower()
    if ext in (".cpp", ".cc", ".cxx", ".hpp"):
        lang = ["-x", "c++"]
    elif ext in (".h", ".hpp", ".hxx"):
        src = path.read_bytes() if path.is_file() else b""
        is_cpp = any(h in src for h in (b"namespace ", b"class ", b"template ", b"std::", b"::"))
        lang = ["-x", "c++"] if is_cpp else ["-x", "c"]
    else:
        lang = ["-x", "c"]
    return lang + [
        "-fsyntax-only", "-ffreestanding", "-fno-builtin", "-Wno-everything",
        f"-I{source_root}",
        f"-I{Path(source_root) / "src"}",
        f"-I{Path(source_root) / "include"}",
    ]


def _get_tu(source_root: str, source_file: str) -> Any | None:
    """解析翻译单元, 缓存。"""
    if not _ensure_clang():
        return None
    path = Path(source_root) / source_file
    if not path.is_file():
        return None
    key = str(path.resolve())
    with _lock:
        cached = _TU_CACHE.get(key)
        if cached is not None:
            _TU_CACHE.pop(key, None)
            _TU_CACHE[key] = cached
            return cached
    try:
        index = _cindex.Index.create()
        tu = index.parse(str(path), args=_parse_args(source_root, path),
                         options=_cindex.TranslationUnit.PARSE_NONE)
    except Exception as e:
        logger.warning("clang TU parse failed %s: %s", path.name, e)
        return None
    with _lock:
        _TU_CACHE[key] = tu
        if len(_TU_CACHE) > _TU_CACHE_MAX:
            _TU_CACHE.pop(next(iter(_TU_CACHE)), None)
    return tu


def _line(cursor: Any) -> int:
    try:
        return int(cursor.extent.start.line)
    except Exception as e:
        logger.debug("clang cursor.extent.start.line unavailable: %s", e)
        return 0


def _text(cursor: Any, source_lines: list[str]) -> str:
    try:
        ext = cursor.extent
        s, e = int(ext.start.line), int(ext.end.line)
        if s < 1 or e < s or e > len(source_lines):
            return ""
        return "\n".join(source_lines[s - 1:e]).strip()
    except Exception as e:
        logger.debug("clang cursor text decode failed: %s", e)
        return ""


def _group_id(cursor: Any) -> str:
    try:
        ext = cursor.extent
        raw = f"{ext.start.line}:{ext.start.column}:{ext.end.line}:{ext.end.column}"
    except Exception as e:
        logger.debug("clang cursor extent for group_id unavailable, fallback to id: %s", e)
        raw = str(id(cursor))
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def _find_func_cursor(tu: Any, func_name: str) -> Any | None:
    """在 TU 里找函数定义。"""
    CK = _cindex.CursorKind
    for cursor in tu.cursor.walk_preorder():
        if cursor.kind in (CK.FUNCTION_DECL, CK.CXX_METHOD) and cursor.spelling == func_name:
            if cursor.is_definition():
                return cursor
    # 回退: 模糊匹配 (含 :: 的限定名)
    short = func_name.split("::")[-1]
    for cursor in tu.cursor.walk_preorder():
        if cursor.kind in (CK.FUNCTION_DECL, CK.CXX_METHOD) and cursor.spelling == short:
            if cursor.is_definition():
                return cursor
    return None


def _walk(cursor: Any, branch_stack: list[dict], source_lines: list[str],
          callsites: list[dict], checks: list[dict]) -> None:
    """递归遍历 Stmt, 跟踪分支栈, 收集 CallExpr + if-statement 校验点。"""
    CK = _cindex.CursorKind
    kind = cursor.kind

    # if 语句: 记录校验点 + push then/else 分支
    if kind == CK.IF_STMT:
        children = list(cursor.get_children())
        if not children:
            return
        cond = children[0]
        then_child = children[1] if len(children) >= 2 else None
        else_child = children[2] if len(children) >= 3 else None
        cond_text = _text(cond, source_lines)
        cond_line = _line(cursor)
        # 记录 if-statement 为校验点候选 (LLM 判是否约束污点)
        checks.append({
            "line": cond_line,
            "condition": cond_text,
            "checks_var": _extract_check_var(cond_text),
        })
        # walk condition (不含分支)
        _walk(cond, branch_stack, source_lines, callsites, checks)
        gid = _group_id(cursor)
        if then_child is not None:
            branch_stack.append({"group_id": gid, "arm": "then", "line": cond_line,
                                 "condition": cond_text, "kind": "if"})
            _walk(then_child, branch_stack, source_lines, callsites, checks)
            branch_stack.pop()
        if else_child is not None:
            branch_stack.append({"group_id": gid, "arm": "else", "line": cond_line,
                                 "condition": cond_text, "kind": "if"})
            _walk(else_child, branch_stack, source_lines, callsites, checks)
            branch_stack.pop()
        return

    # switch 语句
    if kind == CK.SWITCH_STMT:
        children = list(cursor.get_children())
        gid = _group_id(cursor)
        sw_line = _line(cursor)
        cond = children[0] if children else None
        cond_text = _text(cond, source_lines) if cond else ""
        if cond:
            _walk(cond, branch_stack, source_lines, callsites, checks)
        body = children[1] if len(children) >= 2 else None
        if body is not None:
            branch_stack.append({"group_id": gid, "arm": "switch", "line": sw_line,
                                 "condition": cond_text, "kind": "switch"})
            _walk(body, branch_stack, source_lines, callsites, checks)
            branch_stack.pop()
        return

    # case/default
    if kind in (CK.CASE_STMT, CK.DEFAULT_STMT):
        gid = branch_stack[-1]["group_id"] if branch_stack else ""
        arm = _text(cursor, source_lines) or ("default" if kind == CK.DEFAULT_STMT else "case")
        branch_stack.append({"group_id": gid, "arm": arm, "line": _line(cursor),
                             "condition": "", "kind": "case"})
        for ch in cursor.get_children():
            _walk(ch, branch_stack, source_lines, callsites, checks)
        branch_stack.pop()
        return

    # CallExpr: 记录调用点
    if kind == CK.CALL_EXPR:
        ref = cursor.referenced
        name = ref.spelling if ref is not None else ""
        if not name:
            kids = list(cursor.get_children())
            if kids:
                name = kids[0].spelling or ""
        if not name:
            name = _text(cursor, source_lines).split("(")[0].strip().split()[-1] if _text(cursor, source_lines) else ""
        if name:
            kids = list(cursor.get_children())
            arg_cursors = kids[1:] if len(kids) >= 1 else []
            callsites.append({
                "callee": name,
                "line": _line(cursor),
                "args": [_text(a, source_lines) for a in arg_cursors],
                "branch": _branch_to_condition(branch_stack),
            })

    # 递归子节点
    for child in cursor.get_children():
        _walk(child, branch_stack, source_lines, callsites, checks)


def _extract_check_var(cond_text: str) -> str:
    """从条件表达式提取被检查的变量名 (第一个标识符 token)。"""
    if not cond_text:
        return ""
    import re
    m = re.match(r"([A-Za-z_][\w:.\->\[\]]*)", cond_text.strip().lstrip("!("))
    return m.group(1) if m else ""


def _branch_to_condition(branch_stack: list[dict]) -> str:
    """分支栈 → 人类可读的条件路径 (注入 prompt 给 LLM)。

    e.g. [{"arm":"then","condition":"a->cmd==1"}] → "if(a->cmd==1) then"
    """
    if not branch_stack:
        return ""
    parts = []
    for b in branch_stack:
        cond = b.get("condition", "")
        arm = b.get("arm", "")
        if cond and arm in ("then", "else"):
            parts.append(f"if({cond}) {arm}")
        elif arm == "switch":
            parts.append("switch")
        elif arm.startswith("case"):
            parts.append(arm)
        else:
            parts.append(arm)
    return " > ".join(parts)


def extract_facts(source_root: str, source_file: str, func_name: str) -> dict | None:
    """提取 clang 结构事实 (调用点表 + 分支结构 + 校验点)。

    返回 None = clang 不可用/解析失败 (调用方回退纯 LLM)。
    返回 dict = 事实, 注入 prompt。
    """
    tu = _get_tu(source_root, source_file)
    if tu is None:
        return None
    func_cursor = _find_func_cursor(tu, func_name)
    if func_cursor is None:
        logger.warning("clang: function %s not found in %s", func_name, source_file)
        return None
    path = Path(source_root) / source_file
    try:
        source_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        logger.warning("read source for clang facts failed (path=%s): %s", path, e)
        return None

    callsites: list[dict] = []
    checks: list[dict] = []
    _walk(func_cursor, [], source_lines, callsites, checks)

    return {
        "callsites": callsites,
        "checks": checks,
        "func_line_start": _line(func_cursor),
    }
