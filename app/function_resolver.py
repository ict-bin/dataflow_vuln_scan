"""Function resolution for DVS followup scheduling.

EA funcdb is authoritative. When EA has not generated a source-root-wide index yet,
DVS builds a best-effort fallback index per source root under the DVS app output path.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .global_cache import source_root_key, GlobalCache

_SOURCE_EXTS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}
_CPP_EXTS = {".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}
_EXCLUDE_PARTS = {".git", "build", "out", "cmake-build-debug", "cmake-build-release", "node_modules"}


@dataclass(frozen=True)
class FunctionResolution:
    status: str
    function_name: str
    source_file: str = ""
    line: int = 0
    func_hash: str = ""
    source: str = ""
    reason: str = ""

    @property
    def resolved(self) -> bool:
        return self.status == "resolved" and bool(self.source_file)


def _safe_rel(path: str | Path, root: str | Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path(root).resolve())).replace("\\", "/")
    except Exception:
        return str(path).replace("\\", "/")


def _is_in_root(path: str | Path, root: str | Path) -> bool:
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except Exception:
        return False


def _iter_funcdb_files(funcdb_path: str) -> list[Path]:
    root = Path(str(funcdb_path or "").strip())
    if root.is_file():
        return [root]
    if root.is_dir():
        return sorted(root.glob("*_functions.db")) + sorted(root.glob("*.sqlite")) + sorted(root.glob("*.db"))
    return []


def _row_file(row: dict) -> str:
    return str(row.get("file_path") or row.get("rel_path") or row.get("original_path") or "").replace("\\", "/")


def _score(row: dict, function_name: str, source_file_hint: str = "", line_hint: str = "") -> int:
    short = function_name.split("::")[-1]
    name = str(row.get("name") or "")
    score = 0
    if name == function_name:
        score += 1200
    elif name == short:
        score += 1000
    elif name.endswith("::" + short):
        score += 800
    fp = _row_file(row)
    hint = str(source_file_hint or "").replace("\\", "/")
    if hint and fp:
        if fp == hint or fp.endswith("/" + hint) or hint.endswith("/" + fp):
            score += 500
        elif os.path.basename(fp) == os.path.basename(hint):
            score += 120
    try:
        ln = int(str(line_hint or "").lstrip("Ll") or "0")
    except ValueError:
        ln = 0
    if ln:
        start = int(row.get("start_line") or 0)
        end = int(row.get("end_line") or 0)
        if start and (not end or start <= ln <= end):
            score += 250
        elif start:
            score -= min(abs(start - ln), 200)
    return score


class FunctionResolver:
    def __init__(self, source_root: str, *, funcdb_path: str = "", cache_root: str = "") -> None:
        self.source_root = str(Path(source_root).resolve())
        self.funcdb_path = str(funcdb_path or "").strip()
        self.cache_root = str(cache_root or os.environ.get("DVS_FUNCDB_CACHE_ROOT") or "")

    def resolve(self, function_name: str, *, source_file_hint: str = "", line_hint: str = "") -> FunctionResolution:
        name = str(function_name or "").strip().strip("`")
        if not re.match(r"^[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*$", name):
            return FunctionResolution("unresolved", name, reason="invalid_name")
        hit = self._resolve_ea_funcdb(name, source_file_hint=source_file_hint, line_hint=line_hint)
        if hit.resolved:
            return hit
        if hit.reason == "out_of_source_root":
            return hit
        fallback_db = self.ensure_fallback_funcdb()
        if fallback_db:
            hit = self._resolve_sqlite_file(fallback_db, name, source_file_hint=source_file_hint, line_hint=line_hint, source="dvs_fallback_funcdb")
            if hit.resolved:
                return hit
        return FunctionResolution("unresolved", name, reason="not_in_source_root_funcdb")

    def _resolve_ea_funcdb(self, name: str, *, source_file_hint: str = "", line_hint: str = "") -> FunctionResolution:
        hit = FunctionResolution("unresolved", name, reason="not_in_ea_funcdb")
        for db_file in _iter_funcdb_files(self.funcdb_path):
            hit = self._resolve_sqlite_file(db_file, name, source_file_hint=source_file_hint, line_hint=line_hint, source="ea_funcdb")
            if hit.resolved or hit.reason == "out_of_source_root":
                return hit
        return hit

    def _resolve_sqlite_file(self, db_file: Path, name: str, *, source_file_hint: str, line_hint: str, source: str) -> FunctionResolution:
        short = name.split("::")[-1]
        try:
            conn = sqlite3.connect(str(db_file))
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    """SELECT f.*, COALESCE(f.file_path, f.rel_path, fm.rel_path, fm.original_path, '') AS file_path,
                              fm.original_path AS original_path
                       FROM functions f LEFT JOIN file_meta fm ON (fm.file_hash=f.file_hash OR fm.id=f.file_id)
                       WHERE f.name=? OR f.name=? OR f.name LIKE ?""",
                    (name, short, f"%::{short}"),
                ).fetchall()
            except sqlite3.OperationalError:
                rows = conn.execute(
                    "SELECT * FROM functions WHERE name=? OR name=? OR name LIKE ?",
                    (name, short, f"%::{short}"),
                ).fetchall()
            candidates = [dict(r) for r in rows]
        except Exception:
            return FunctionResolution("unresolved", name, reason="funcdb_read_failed")
        finally:
            try:
                conn.close()
            except Exception:
                pass
        if not candidates:
            return FunctionResolution("unresolved", name, reason=f"not_in_{source}")
        candidates.sort(key=lambda r: _score(r, name, source_file_hint, line_hint), reverse=True)
        best = candidates[0]
        rel = _row_file(best)
        abs_path = Path(rel)
        if not abs_path.is_absolute():
            abs_path = Path(self.source_root) / rel
        if not _is_in_root(abs_path, self.source_root):
            return FunctionResolution("unresolved", name, reason="out_of_source_root")
        return FunctionResolution(
            "resolved",
            str(best.get("name") or name),
            _safe_rel(abs_path, self.source_root),
            int(best.get("start_line") or 0),
            str(best.get("func_hash") or ""),
            source,
            "",
        )

    def ensure_fallback_funcdb(self) -> Path | None:
        cache_root = self.cache_root
        if not cache_root:
            cache_root = str(GlobalCache(self.source_root).funcdb_root / "dvs-fallback")
        else:
            cache_root = str(Path(cache_root))
        digest = hashlib.sha1(self.source_root.encode("utf-8", errors="replace")).hexdigest()[:16]
        db_path = Path(cache_root) / digest / "dvs-fallback-functions.db"
        marker = cache_root / digest / "source-root.txt"
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text(self.source_root, encoding="utf-8")
            if db_path.exists() and db_path.stat().st_size > 0:
                return db_path
            self._build_fallback_db(db_path)
            return db_path if db_path.exists() else None
        except Exception:
            return None

    def _build_fallback_db(self, db_path: Path) -> None:
        rows: list[tuple[str, str, int, str]] = []
        root = Path(self.source_root)
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in _SOURCE_EXTS:
                continue
            if any(part in _EXCLUDE_PARTS for part in path.parts):
                continue
            try:
                rows.extend(_extract_functions_tree_sitter(path, root))
            except Exception:
                continue
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS functions (name TEXT, file_path TEXT, start_line INTEGER, func_hash TEXT)")
            conn.execute("CREATE INDEX IF NOT EXISTS ix_functions_name ON functions(name)")
            conn.executemany("INSERT INTO functions(name,file_path,start_line,func_hash) VALUES(?,?,?,?)", rows)
            conn.commit()
        finally:
            conn.close()


def _ts_language(path: Path):
    from tree_sitter import Language
    if path.suffix.lower() in _CPP_EXTS:
        import tree_sitter_cpp
        return Language(tree_sitter_cpp.language())
    import tree_sitter_c
    return Language(tree_sitter_c.language())


def _node_text(node, data: bytes) -> str:
    return data[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _first_identifier(node, data: bytes) -> str:
    if node.type in {"identifier", "field_identifier", "qualified_identifier", "operator_name", "destructor_name"}:
        return _node_text(node, data)
    for child in node.children:
        value = _first_identifier(child, data)
        if value:
            return value
    return ""


def _function_name_from_definition(node, data: bytes) -> str:
    declarator = node.child_by_field_name("declarator")
    while declarator is not None:
        if declarator.type == "function_declarator":
            inner = declarator.child_by_field_name("declarator")
            return _first_identifier(inner, data) if inner is not None else ""
        next_decl = declarator.child_by_field_name("declarator")
        if next_decl is None or next_decl == declarator:
            break
        declarator = next_decl
    return ""


def _extract_functions_tree_sitter(path: Path, root: Path) -> list[tuple[str, str, int, str]]:
    from tree_sitter import Parser
    data = path.read_bytes()
    parser = Parser()
    parser.language = _ts_language(path)
    tree = parser.parse(data)
    rel = _safe_rel(path, root)
    rows: list[tuple[str, str, int, str]] = []

    def visit(node) -> None:
        if node.type == "function_definition":
            name = _function_name_from_definition(node, data).strip()
            if name:
                line = int(node.start_point[0]) + 1
                fh = hashlib.sha1(f"{rel}:{line}:{name}".encode()).hexdigest()
                rows.append((name, rel, line, fh))
        for child in node.children:
            visit(child)

    visit(tree.root_node)
    return rows


def normalize_taint_params(raw_params: Iterable[str] | str | None) -> tuple[list[str], str]:
    if raw_params is None:
        items: list[str] = []
    elif isinstance(raw_params, str):
        items = [x.strip() for x in raw_params.split(",")]
    else:
        items = [str(x).strip() for x in raw_params]
    args: set[str] = set()
    for i, raw in enumerate(items):
        text = raw.strip()
        if not text or text in {"*", "无"}:
            continue
        low = text.lower()
        if low in {"all", "所有参数", "全部参数"}:
            args.add("all")
            continue
        # Explicit positional notation
        m = re.search(r"(?:arg|param|参数|第)\s*([0-9]+)", low)
        if m:
            args.add(f"arg{int(m.group(1))}")
            continue
        # Strip leading noise (C++ qualifiers, ampersands) and extract the symbol
        text = re.sub(r"^[^A-Za-z_&*]*", "", text)
        text = text.lstrip("&").strip()
        m = re.match(r"\*?\s*([A-Za-z_]\w*)", text)
        if m:
            sym = m.group(1)
            if sym.startswith("v") and sym[1:].isdigit():
                args.add("unknown")
            else:
                # Fallback to positional index so that different variable names
                # passed to the same parameter slot produce the same signature.
                args.add(f"arg{i + 1}")
        else:
            args.add("unknown")
    norm = sorted(args)
    return norm, "+".join(norm) if norm else "none"
