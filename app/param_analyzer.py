"""Parameter-passing semantics analyzer for followup scheduling.

Determines whether a callee's tainted parameters are passed by value
(isolated, safe to parallelise) or by non-const pointer/reference
(shared state, requires sequential DFS execution).

Uses fast regex/tree-sitter heuristics as primary path, falling back to
a lightweight one-shot LLM call for ambiguous cases.
"""
from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ─── types ────────────────────────────────────────────────────────────────────

@dataclass
class ParamSemantics:
    param_name: str = ""
    is_value_type: bool = False
    is_const_qualified: bool = False
    is_pointer: bool = False
    is_reference: bool = False
    effect: str = "unknown"  # reads_only | modifies | validates | unknown
    evidence: str = ""

    @property
    def is_isolated(self) -> bool:
        """True when the callee CANNOT modify the caller's data through this param."""
        return self.is_value_type or (self.is_pointer and self.is_const_qualified)

    @property
    def needs_sequential(self) -> bool:
        return not self.is_isolated

    @property
    def priority(self) -> int:
        """0=P0(modifies), 1=P1(validates/reads_only), 2=P2(isolated)"""
        if self.is_isolated:
            return 2
        if self.effect in ("validates", "reads_only"):
            return 1
        return 0


@dataclass
class FollowupSemantics:
    followup_id: str = ""
    callee_function: str = ""
    callee_file: str = ""
    params: list[ParamSemantics] = field(default_factory=list)
    needs_sequential: bool = False
    reason: str = ""
    source: str = "script"  # "script" | "llm_fallback" | "conservative"
    highest_priority: int = 0  # 0=P0, 1=P1, 2=P2


# ─── fast heuristic helpers ───────────────────────────────────────────────────

_VALUE_TYPE_RE = re.compile(
    r"^\s*[-+]?\d+$|"                                         # integer literal
    r"^\s*[-+]?\d+\.\d*[fF]?$|"                               # float literal
    r"^\s*(true|false)\s*$|"                                   # bool
    r"^\s*(?:sizeof|offsetof)\s*\(|$"                           # compile-time expr (but not a simple var)
    r"^\s*[A-Z_]\w*(?:_[A-Z_]\w*)+$"                            # MACRO_CONSTANT style
)

_TAKE_ADDRESS_RE = re.compile(r"^\s*&\s*([A-Za-z_]\w*(?:\.|->)?[A-Za-z_\[\].\w]*)\s*$")
_FIELD_ACCESS_RE = re.compile(r"^\s*([A-Za-z_]\w*(?:\.|->)[A-Za-z_\[\].\w]*)\s*$")
_POINTER_RE = re.compile(r"(?:^\s*[*]|->)")
_CONST_RE = re.compile(r"\bconst\b")


# ─── function declaration cache ───────────────────────────────────────────────

def _read_first_lines(path: Path, max_lines: int = 30) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = []
            for _ in range(max_lines):
                line = fh.readline()
                if not line:
                    break
                lines.append(line)
            return "".join(lines)
    except OSError:
        return ""


def _extract_param_decl(source: str, func_name: str, arg_index: int) -> str:
    """Best-effort extraction of the N-th parameter declaration from function source."""
    short = func_name.rsplit("::", 1)[-1]
    pat = re.compile(
        r"((?:static\s+|inline\s+|virtual\s+|const\s+)*"
        r"(?:[\w:*&<>\s]+)\s+" + re.escape(short) +
        r"\s*\(([^)]*)\))",
        re.MULTILINE | re.DOTALL,
    )
    # Find ALL matches, prefer the one with richest parameter types (definition over call)
    matches = list(pat.finditer(source))
    if not matches:
        return ""
    # Score: prefer match with more type information (containing * or keywords)
    def _score(m) -> int:
        params = m.group(2)
        s = 0
        if "*" in params or "const" in params:
            s += 10  # likely a declaration/definition
        if "void" in params and params.strip() == "void":
            s -= 5  # void param, less useful
        return s
    best = max(matches, key=_score)
    params_text = best.group(2)
    params = [p.strip() for p in params_text.split(",")]
    if 0 <= arg_index - 1 < len(params):
        return params[arg_index - 1]
    return ""


def _resolve_function_file(
    func_name: str, hint_file: str, source_root: str
) -> Path | None:
    """Locate the file containing function definition/declaration."""
    root = Path(source_root)
    short = func_name.rsplit("::", 1)[-1]
    candidates: list[Path] = []

    if hint_file:
        p = root / hint_file
        if p.exists():
            candidates.append(p)

    # Quick grep for function definition
    try:
        import subprocess
        proc = subprocess.run(
            ["rg", "-l", f"\\b{re.escape(short)}\\b", str(root)],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=str(root),
        )
        for line in proc.stdout.splitlines():
            p = root / line.strip()
            if p.exists() and p not in candidates:
                candidates.append(p)
    except Exception:
        pass

    return candidates[0] if candidates else None


def _lookup_param_decl(
    func_name: str,
    arg_index: int,
    hint_file: str,
    source_root: str,
) -> str:
    """Look up the parameter declaration for a given callee + argument position."""
    file_path = _resolve_function_file(func_name, hint_file, source_root)
    if not file_path:
        return ""
    source = _read_first_lines(file_path, max_lines=60)
    return _extract_param_decl(source, func_name, arg_index)


_VALIDATES_PREFIX = re.compile(r"^(?:check_|validate_|verify_|test_|assert_|is_|has_|can_)")


def _infer_effect(func_name: str, is_const: bool, is_ptr: bool) -> str:
    """Infer parameter modification effect from function name and const-ness."""
    short = func_name.rsplit("::", 1)[-1]
    if not is_ptr:
        return "reads_only"  # value type
    if is_const:
        return "reads_only"  # const pointer
    if _VALIDATES_PREFIX.search(short):
        return "validates"
    return "modifies"


# ─── main classifier ──────────────────────────────────────────────────────────

def _classify_arg(
    arg_text: str,
    arg_index: int = 1,
    *,
    func_name: str = "",
    hint_file: str = "",
    source_root: str = "",
) -> ParamSemantics:
    """Classify a single function argument's passing semantics."""
    text = arg_text.strip()

    # Rule 1: numeric / bool / enum literal → value
    if _VALUE_TYPE_RE.match(text):
        return ParamSemantics(
            param_name=text,
            is_value_type=True,
            evidence=f"literal or simple identifier: {text}",
        )

    # Rule 2: &var → address taken, pointer, callee may modify
    m = _TAKE_ADDRESS_RE.match(text)
    if m:
        return ParamSemantics(
            param_name=m.group(1),
            is_pointer=True,
            is_const_qualified=False,
            effect="modifies",
            evidence=f"address-of: {text} → callee may modify pointed-to object",
        )

    # Rule 3: p->field or p.field → pointer/struct, check const
    if _FIELD_ACCESS_RE.match(text) or _POINTER_RE.search(text):
        decl = ""
        if func_name and source_root:
            decl = _lookup_param_decl(
                func_name, arg_index,
                hint_file=hint_file, source_root=source_root,
            )
        is_const = bool(decl and _CONST_RE.search(decl))
        effect = _infer_effect(func_name, is_const, True)
        return ParamSemantics(
            param_name=text,
            is_pointer=True,
            is_const_qualified=is_const,
            effect=effect,
            evidence=f"decl: {decl}" if decl else f"pointer access: {text}",
        )

    # Rule 4: simple variable name → need declaration to decide
    if re.match(r"^[A-Za-z_]\w*$", text):
        decl = ""
        if func_name and source_root and Path(source_root).exists():
            decl = _lookup_param_decl(
                func_name, arg_index,
                hint_file=hint_file, source_root=source_root,
            )
        if decl:
            is_ptr = "*" in decl or _POINTER_RE.search(decl)
            is_const = bool(decl and _CONST_RE.search(decl))
            effect = _infer_effect(func_name, is_const, is_ptr)
            return ParamSemantics(
                param_name=text,
                is_pointer=is_ptr,
                is_const_qualified=is_const,
                is_value_type=not is_ptr,
                effect=effect,
                evidence=f"decl: {decl}",
            )
        # No declaration found → conservative if source_root is valid
        if source_root and Path(source_root).exists():
            return ParamSemantics(
                param_name=text,
                is_pointer=True,
                is_const_qualified=False,
                effect="modifies",
                evidence=f"no declaration found for {text}, assume pointer",
            )
        # No source_root available → assume value type for simple names
        return ParamSemantics(
            param_name=text,
            is_value_type=True,
            effect="reads_only",
            evidence=f"simple identifier: {text} (no source root)",
        )

    # Rule 5: complex expression → conservative
    return ParamSemantics(
        param_name=text,
        is_pointer=True,
        is_const_qualified=False,
        effect="modifies",
        evidence=f"complex expression: {text[:60]}",
    )


def analyze(callee_name: str, callee_file: str,
            tainted_params: list[str],
            callsite_args: list[str],
            source_root: str,
            ) -> FollowupSemantics:
    """Entry point: classify all tainted parameters of a followup call."""

    params: list[ParamSemantics] = []
    for idx, arg in enumerate(callsite_args, start=1):
        p = _classify_arg(
            arg,
            arg_index=idx,
            func_name=callee_name,
            hint_file=callee_file,
            source_root=source_root,
        )
        # Match this arg to a tainted param: either exact match, or
        # the base variable of a field-access expression (ctx->data → ctx).
        base_var = re.sub(r'\s*->.*|\s*\..*|\s*\[.*', '', p.param_name or arg.strip())
        if base_var in tainted_params or p.param_name in tainted_params or arg.strip() in tainted_params:
            p.param_name = base_var
            params.append(p)

    if not params:
        # No tainted params mapped → conservative
        return FollowupSemantics(
            callee_function=callee_name,
            callee_file=callee_file,
            needs_sequential=True,
            reason="could not map tainted params to actual args, conservative",
            source="conservative",
        )

    needs_seq = any(p.needs_sequential for p in params)
    max_pri = max((p.priority for p in params), default=2)
    reason_parts: list[str] = []
    for p in params:
        if p.priority == 0:
            tag = "P0: may modify"
        elif p.priority == 1:
            tag = f"P1: {p.effect}"
        else:
            tag = "P2: isolated"
        reason_parts.append(f"  {p.param_name}: {tag} ({p.evidence[:80]})")
    reason = "\n".join(reason_parts)

    return FollowupSemantics(
        callee_function=callee_name,
        callee_file=callee_file,
        params=params,
        needs_sequential=needs_seq,
        highest_priority=max_pri,
        reason=reason,
        source="script",
    )


def mark_ambiguous(sem: FollowupSemantics) -> bool:
    """Return True when heuristics are inconclusive and LLM fallback should run."""
    return sem.source == "conservative" or (
        sem.needs_sequential
        and any(not p.evidence for p in sem.params)
    )


async def analyze_with_llm_fallback(
    sem: FollowupSemantics,
    *,
    source_root: str,
    model: str,
    tools: list[str],
    runner,  # run_agent callback (injected to avoid circular import)
) -> FollowupSemantics:
    """LLM fallback for ambiguous parameter semantics."""
    prompt = f"""你是 C/C++ 参数语义分析器。判断以下函数调用中，被污染的参数是否可能在函数内部被修改。

被调用函数: {sem.callee_function}
源码文件: {sem.callee_file}
污染参数: {json.dumps([p.param_name for p in sem.params], ensure_ascii=False)}

源码根目录: {source_root}

任务：
1. 用 bash 搜索函数声明/定义
2. 判断每个污染参数的传递方式：值传递 / const 指针 / 非const 指针 / 引用
3. 判断函数是否可能修改这些参数的内容

输出 JSON:
{{"params":[{{"param_name":"x","is_isolated":true,"evidence":"const char*"}}],
  "needs_sequential":false,"reason":"..."}}

仅输出 JSON，不要 Markdown。
"""
    try:
        result = await runner(
            prompt=prompt,
            model=model,
            tools=tools,
            cwd=source_root,
            system_prompt="仅输出 JSON。",
            run_timeout_seconds=120,
            timeout_retry_enabled=False,
        )
        parsed = _extract_json(result.output or "")
        if isinstance(parsed, dict) and "params" in parsed:
            new_params = []
            for item in parsed.get("params", []):
                if not isinstance(item, dict):
                    continue
                new_params.append(ParamSemantics(
                    param_name=str(item.get("param_name", "")),
                    is_value_type=bool(item.get("is_isolated", False)),
                    is_pointer=not bool(item.get("is_isolated", True)),
                    is_const_qualified=bool(item.get("is_isolated", False)),
                    evidence=str(item.get("evidence", "llm fallback")),
                ))
            needs_seq = bool(parsed.get("needs_sequential", True))
            return FollowupSemantics(
                followup_id=sem.followup_id,
                callee_function=sem.callee_function,
                callee_file=sem.callee_file,
                params=new_params,
                needs_sequential=needs_seq,
                reason=str(parsed.get("reason", "llm fallback")),
                source="llm_fallback",
            )
    except Exception:
        pass
    # On any failure, keep the original conservative result
    sem.source = "conservative (llm fallback failed)"
    return sem


def _extract_json(text: str) -> dict[str, Any]:
    candidates: list[str] = []
    for m in re.finditer(r"```(?:json)?\s*\n(.*?)\n\s*```", text, re.S):
        candidates.append(m.group(1))
    candidates.append(text)
    for raw in candidates:
        raw = raw.strip()
        start = raw.find("{")
        end = raw.rfind("}")
        if start >= 0 and end > start:
            try:
                obj = json.loads(raw[start:end + 1])
                return obj if isinstance(obj, dict) else {}
            except Exception:
                pass
    return {}
