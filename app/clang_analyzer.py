"""libclang-based callsite + mutual-exclusion branch analyzer.

Used by the orchestrator AFTER a worker reports followups (tainted.list
callees) for a function, to:

1. Validate each reported callee has a real CallExpr in the caller's body
   (kills phantom edges like "http1_1 -> http3_0 @ L588" where L588 isn't
   even in the caller's file).
2. Extract the governing if/else-if/switch branch arm for each call site,
   so mutually-exclusive alternative arms are NOT chained as sequential
   state dependencies.

Design constraints (per project direction):
- One clang parse per (caller_file, caller_func); result cached as JSON in
  run/clang-cache/ (run/ is pod-local before completion, not NFS).
- TU parse is in-process LRU by file (one parse per file, reused across
  functions in the same file).
- Graceful degradation: if libclang is unavailable or parse fails fatally,
  return empty results so the orchestrator falls back to current behavior
  (no mutex info, no phantom-edge rejection).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("dvs.clang_analyzer")

# ── libclang bootstrap ───────────────────────────────────────────────────────

_LIBCLANG_CANDIDATES = [
    "/usr/lib/x86_64-linux-gnu/libclang-19.so.1",
    "/usr/lib/x86_64-linux-gnu/libclang-19.so",
    "/usr/lib/x86_64-linux-gnu/libclang.so.1",
    "/usr/lib/x86_64-linux-gnu/libclang.so",
    "/usr/lib/llvm-19/lib/libclang-19.so.1",
    "/usr/lib/llvm-19/lib/libclang-19.so.1",
]
_LIBCLANG_DIR_CANDIDATES = [
    "/usr/lib/llvm-19/lib",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/llvm-15/lib",
    "/usr/lib/llvm-14/lib",
]

_cindex: Any = None
_libclang_ready: bool = False
_libclang_lock = threading.Lock()
_init_attempted = False


def _ensure_libclang() -> bool:
    """Load libclang once. Thread-safe. Returns True if usable."""
    global _cindex, _libclang_ready, _init_attempted
    if _init_attempted:
        return _libclang_ready
    with _libclang_lock:
        if _init_attempted:
            return _libclang_ready
        _init_attempted = True
        try:
            import clang.cindex as cindex  # type: ignore
            _cindex = cindex
        except ImportError:
            logger.warning("clang.cindex unavailable (no 'clang' pip package); mutex branch analysis disabled")
            return False
        for p in _LIBCLANG_CANDIDATES:
            if os.path.exists(p):
                try:
                    cindex.Config.set_library_file(p)
                    _libclang_ready = True
                    logger.info("libclang loaded: %s", p)
                    return True
                except Exception as exc:
                    logger.warning("libclang set_library_file(%s) failed: %s", p, exc)
        for d in _LIBCLANG_DIR_CANDIDATES:
            if os.path.isdir(d):
                try:
                    cindex.Config.set_library_path(d)
                    _libclang_ready = True
                    logger.info("libclang loaded from dir: %s", d)
                    return True
                except Exception as exc:
                    logger.warning("libclang set_library_path(%s) failed: %s", d, exc)
        logger.warning("libclang native library not found; mutex branch analysis disabled")
        return False


# ── TU parse cache (in-process, per file) ────────────────────────────────────

_CPP_EXTS = {".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}
_TU_CACHE: dict[str, Any] = {}
_TU_CACHE_LOCK = threading.Lock()
_TU_CACHE_MAX = 16


def _language_arg(path: Path) -> list[str]:
    return ["-x", "c++" if path.suffix.lower() in _CPP_EXTS else "c"]


def _parse_args(source_root: str, path: Path) -> list[str]:
    return _language_arg(path) + [
        "-fsyntax-only",
        "-ffreestanding",
        "-fno-builtin",
        "-Wno-everything",
        "-I" + str(source_root),
        "-I" + str(Path(source_root) / "src"),
        "-I" + str(Path(source_root) / "include"),
    ]


def _get_tu(source_root: str, source_file: str) -> Any | None:
    """Parse a translation unit, cached per file. Returns TU or None."""
    if not _ensure_libclang():
        return None
    path = Path(source_root) / source_file
    if not path.is_file():
        return None
    key = str(path.resolve())
    with _TU_CACHE_LOCK:
        cached = _TU_CACHE.get(key)
        if cached is not None:
            # move to end (LRU)
            _TU_CACHE.pop(key, None)
            _TU_CACHE[key] = cached
            return cached
    try:
        tu = _cindex.TranslationUnit.create_from_source_file(
            str(path),
            args=_parse_args(source_root, path),
            options=_cindex.TranslationUnit.PARSE_NONE,
        )
    except Exception as exc:
        logger.warning("clang TU parse failed for %s: %s", path, exc)
        return None
    with _TU_CACHE_LOCK:
        _TU_CACHE[key] = tu
        if len(_TU_CACHE) > _TU_CACHE_MAX:
            # evict oldest
            oldest = next(iter(_TU_CACHE))
            _TU_CACHE.pop(oldest, None)
    return tu


# ── AST helpers ──────────────────────────────────────────────────────────────

def _line(cursor: Any) -> int:
    try:
        return int(cursor.extent.start.line)
    except Exception:
        return 0


def _node_group_id(cursor: Any) -> str:
    """Stable id for a branch statement (if/switch), shared by its arms."""
    try:
        ext = cursor.extent
        start, end = ext.start, ext.end
        raw = f"{start.file.name if start.file else ''}:{start.line}:{start.column}:{end.line}:{end.column}"
    except Exception:
        raw = str(id(cursor))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _cursor_text(cursor: Any, source_lines: list[str]) -> str:
    try:
        ext = cursor.extent
        s, e = int(ext.start.line), int(ext.end.line)
        if s < 1 or e < s or e > len(source_lines):
            return ""
        return "\n".join(source_lines[s - 1:e]).strip()
    except Exception:
        return ""


def _function_def_cursor(tu: Any, func_name: str) -> Any | None:
    """Locate the FunctionDecl definition matching func_name."""
    short = func_name.rsplit("::", 1)[-1]
    found: Any | None = None
    for cur in tu.cursor.get_children():
        if cur.kind == _cindex.CursorKind.FUNCTION_DECL and cur.is_definition():
            if cur.spelling == short or cur.spelling == func_name:
                found = cur
                break
    return found


# ── branch-aware CallExpr collection ─────────────────────────────────────────

@dataclass
class _CallHit:
    name: str
    call_line: int
    call_expr: str
    actual_args: list[str] = field(default_factory=list)
    branch_path: list[dict] = field(default_factory=list)


def _walk(cursor: Any, branch_stack: list[dict], source_lines: list[str],
          callee_names: set[str], hits: list[_CallHit]) -> None:
    """Recursively walk the Stmt tree, tracking enclosing branch arms."""
    kind = cursor.kind

    if kind == _cindex.CursorKind.IF_STMT:
        children = list(cursor.get_children())
        if not children:
            return
        gid = _node_group_id(cursor)
        cond_line = _line(cursor)
        # C IfStmt children order: [condition, then, (else)?]
        # Be defensive: condition = children[0], then = children[1], else = children[2] if present
        cond = children[0]
        then_child = children[1] if len(children) >= 2 else None
        else_child = children[2] if len(children) >= 3 else None
        _walk(cond, branch_stack, source_lines, callee_names, hits)
        if then_child is not None:
            branch_stack.append({"group_id": gid, "arm": "then", "line": cond_line, "kind": "if"})
            _walk(then_child, branch_stack, source_lines, callee_names, hits)
            branch_stack.pop()
        if else_child is not None:
            branch_stack.append({"group_id": gid, "arm": "else", "line": cond_line, "kind": "if"})
            _walk(else_child, branch_stack, source_lines, callee_names, hits)
            branch_stack.pop()
        return

    if kind == _cindex.CursorKind.SWITCH_STMT:
        gid = _node_group_id(cursor)
        sw_line = _line(cursor)
        children = list(cursor.get_children())
        # [condition, body]
        if children:
            _walk(children[0], branch_stack, source_lines, callee_names, hits)
        body = children[1] if len(children) >= 2 else None
        if body is not None:
            branch_stack.append({"group_id": gid, "arm": "switch", "line": sw_line, "kind": "switch"})
            _walk(body, branch_stack, source_lines, callee_names, hits)
            branch_stack.pop()
        return

    if kind in (_cindex.CursorKind.CASE_STMT, _cindex.CursorKind.DEFAULT_STMT):
        gid = branch_stack[-1]["group_id"] if branch_stack else ""
        arm = _cursor_text(cursor, source_lines) or ("default" if kind == _cindex.CursorKind.DEFAULT_STMT else "case")
        branch_stack.append({"group_id": gid, "arm": arm, "line": _line(cursor), "kind": "case"})
        for ch in cursor.get_children():
            _walk(ch, branch_stack, source_lines, callee_names, hits)
        branch_stack.pop()
        return

    if kind == _cindex.CursorKind.CALL_EXPR:
        ref = cursor.referenced
        name = ref.spelling if ref is not None else ""
        if name and name in callee_names:
            children = list(cursor.get_children())
            # children: [callee_expr, arg0, arg1, ...]
            arg_cursors = children[1:] if len(children) >= 1 else []
            hits.append(_CallHit(
                name=name,
                call_line=_line(cursor),
                call_expr=_cursor_text(cursor, source_lines),
                actual_args=[_cursor_text(a, source_lines) for a in arg_cursors],
                branch_path=[dict(f) for f in branch_stack],
            ))
        # args may contain nested calls; keep recursing
        for ch in cursor.get_children():
            _walk(ch, branch_stack, source_lines, callee_names, hits)
        return

    # default: recurse
    for ch in cursor.get_children():
        _walk(ch, branch_stack, source_lines, callee_names, hits)


# ── mutex sibling computation ────────────────────────────────────────────────

def _compute_mutex(call_hits: list[_CallHit], callee_names: list[str]) -> None:
    """Two hits are mutually exclusive iff they share a branch group_id and
    the arm at that group differs. Tag each hit's mutex siblings."""
    name_to_siblings: dict[str, set[str]] = {n: set() for n in callee_names}
    for i, a in enumerate(call_hits):
        for b in call_hits[i + 1:]:
            # find common group with different arm
            a_groups = {f["group_id"]: f["arm"] for f in a.branch_path if f.get("group_id")}
            b_groups = {f["group_id"]: f["arm"] for f in b.branch_path if f.get("group_id")}
            common = set(a_groups) & set(b_groups)
            mutex = any(a_groups[g] != b_groups[g] for g in common)
            if mutex:
                name_to_siblings.setdefault(a.name, set()).add(b.name)
                name_to_siblings.setdefault(b.name, set()).add(a.name)
    # stash on hits via attribute for the caller to read
    for h in call_hits:
        h._mutex_siblings = sorted(name_to_siblings.get(h.name, set()))  # type: ignore[attr-defined]


# ── JSON result cache (run/clang-cache/, pod-local) ──────────────────────────

def _cache_path(cache_dir: Path, source_file: str, func_name: str) -> Path:
    key = hashlib.sha1(f"{source_file}::{func_name}".encode("utf-8")).hexdigest()[:24]
    return cache_dir / f"{key}.json"


def _read_cache(cache_dir: Path, source_file: str, func_name: str,
                source_mtime: float) -> dict | None:
    p = _cache_path(cache_dir, source_file, func_name)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if float(data.get("source_mtime") or 0) != source_mtime:
            return None
        return data
    except Exception:
        return None


def _write_cache(cache_dir: Path, source_file: str, func_name: str,
                 source_mtime: float, payload: dict) -> None:
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        p = _cache_path(cache_dir, source_file, func_name)
        payload = {"source_file": source_file, "func_name": func_name,
                   "source_mtime": source_mtime, **payload}
        p.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        logger.warning("clang cache write failed: %s", exc)


# ── public entry ─────────────────────────────────────────────────────────────

def analyze_function_callsites(
    source_root: str,
    caller_file: str,
    caller_func: str,
    callee_names: list[str],
    cache_dir: Path | str | None = None,
) -> dict[str, dict]:
    """Return {callee_name: CallsiteInfo-dict} for each callee found in the
    caller function's body.

    dict fields: validated, call_line, call_expr, actual_args, branch_path,
    branch_group_id, branch_arm_id, mutex_siblings.

    Callees not found in the body are OMITTED from the result (caller treats
    absence as "not validated / phantom"). Returns {} if libclang unavailable
    or parse fails (caller falls back to current behavior).
    """
    if not callee_names:
        return {}
    path = Path(source_root) / caller_file
    if not path.is_file():
        return {}
    try:
        source_mtime = path.stat().st_mtime
    except OSError:
        source_mtime = 0.0

    if cache_dir is not None:
        cached = _read_cache(Path(cache_dir), caller_file, caller_func, source_mtime)
        if cached is not None:
            return cached.get("callsites", {})

    tu = _get_tu(source_root, caller_file)
    if tu is None:
        return {}

    func_cursor = _function_def_cursor(tu, caller_func)
    if func_cursor is None:
        # function not found in TU (parse residual / macro-wrapped) -> bail
        return {}

    try:
        source_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        source_lines = []

    callee_set = {n.rsplit("::", 1)[-1] for n in callee_names} | set(callee_names)
    hits: list[_CallHit] = []
    _walk(func_cursor, [], source_lines, callee_set, hits)
    _compute_mutex(hits, callee_names)

    # pick the best hit per callee (prefer the one with a branch path, i.e.
    # inside a conditional -- more informative; else first)
    best_by_name: dict[str, _CallHit] = {}
    for h in hits:
        cur = best_by_name.get(h.name)
        if cur is None or (len(h.branch_path) > len(cur.branch_path)):
            best_by_name[h.name] = h

    result: dict[str, dict] = {}
    for name in callee_names:
        short = name.rsplit("::", 1)[-1]
        hit = best_by_name.get(name) or best_by_name.get(short)
        if hit is None:
            continue  # not found -> caller treats as phantom
        bp = hit.branch_path
        inner = bp[-1] if bp else {}
        result[name] = {
            "validated": True,
            "call_line": hit.call_line,
            "call_expr": hit.call_expr,
            "actual_args": hit.actual_args,
            "branch_path": bp,
            "branch_group_id": inner.get("group_id", ""),
            "branch_arm_id": inner.get("arm", ""),
            "mutex_siblings": list(getattr(hit, "_mutex_siblings", [])),
        }

    if cache_dir is not None:
        _write_cache(Path(cache_dir), caller_file, caller_func, source_mtime,
                     {"callsites": result})
    return result


# ── vuln-verifier 原子能力 (debug: DVS_VULN_VERIFIER_ENABLED) ────────────────
# 以下函数供 app/vuln_verifier.py 服务端结构化核验使用; 全部 fail-safe:
# libclang 不可用或解析失败时返回 None, 调用方按 "无法核验→跳过(不阻断)" 处理。

def _collect_all_calls(func_cursor: Any, source_lines: list[str]) -> list[dict]:
    """Walk func body, collect every CallExpr {name, call_line} (call-graph edges)."""
    out: list[dict] = []

    def walk(cur: Any) -> None:
        if cur.kind == _cindex.CursorKind.CALL_EXPR:
            ref = cur.referenced
            nm = ref.spelling if ref is not None else ""
            if not nm:
                kids = list(cur.get_children())
                if kids:
                    nm = kids[0].spelling or _cursor_text(cur, source_lines) or ""
            out.append({"name": nm, "call_line": _line(cur)})
            for ch in cur.get_children():
                walk(ch)
            return
        for ch in cur.get_children():
            walk(ch)

    walk(func_cursor)
    return out


def get_function_callees(source_root: str, caller_file: str, caller_func: str,
                         cache_dir: Path | str | None = None) -> list[dict] | None:
    """All callees actually called in caller_func (call-graph edges from this node).

    Returns list of {name, call_line}; None when libclang unavailable / parse
    fails (verifier treats None as "skipped", never blocks)."""
    path = Path(source_root) / caller_file
    if not path.is_file():
        return None
    tu = _get_tu(source_root, caller_file)
    if tu is None:
        return None
    fc = _function_def_cursor(tu, caller_func)
    if fc is None:
        return None
    try:
        source_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        source_lines = []
    return _collect_all_calls(fc, source_lines)


def get_function_line_range(source_root: str, caller_file: str,
                             caller_func: str) -> tuple[int, int] | None:
    """(start_line, end_line) of caller_func's definition, or None."""
    path = Path(source_root) / caller_file
    if not path.is_file():
        return None
    tu = _get_tu(source_root, caller_file)
    if tu is None:
        return None
    fc = _function_def_cursor(tu, caller_func)
    if fc is None:
        return None
    try:
        return (fc.extent.start.line, fc.extent.end.line)
    except Exception:
        return None


def callee_body_text(source_root: str, callee_file: str,
                      callee_func: str) -> str | None:
    """Return the callee function body as text (line-range slice), or None."""
    rng = get_function_line_range(source_root, callee_file, callee_func)
    if rng is None:
        return None
    path = Path(source_root) / callee_file
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    s, e = rng
    return "\n".join(lines[max(0, s - 1):e])


def function_calls_callee(source_root: str, caller_file: str, caller_func: str,
                           callee_name: str) -> bool | None:
    """True if caller_func actually calls callee_name; None if unverifiable."""
    calls = get_function_callees(source_root, caller_file, caller_func)
    if calls is None:
        return None
    short = callee_name.rsplit("::", 1)[-1]
    return any(c.get("name") in (callee_name, short) for c in calls)


def callee_body_contains_token(source_root: str, callee_file: str,
                                callee_func: str, token: str) -> bool | None:
    """True if callee_func's body contains `token` (case-sensitive substring);
    None if unverifiable. Used for behavior-claim consistency (e.g. 'realloc')."""
    body = callee_body_text(source_root, callee_file, callee_func)
    if body is None:
        return None
    return token in body


def libclang_available() -> bool:
    """Test-only / observability: is libclang loaded or loadable?"""
    return _ensure_libclang()


def is_enabled() -> bool:
    """Debug switch for the clang-based mutex-branch analysis.

    Default OFF (env unset / falsy): the orchestrator MUST run the original
    pre-clang code path verbatim — no clang parse, no phantom-callsite
    rejection, no mutex P0 partition. Only when explicitly enabled does the
    new code path execute. This keeps mainline behavior 100% unchanged until
    the switch is turned on for testing.
    """
    return str(os.environ.get("DVS_CLANG_MUTEX_ENABLED", "")).strip().lower() in {"1", "true", "yes", "on"}
