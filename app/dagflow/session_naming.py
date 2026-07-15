"""dagflow 会话命名 (NN 自增, 不覆盖)。

设计: 独立会话 (func-taint), 不 fork 调用链。
文件名: d{depth}-{func}-taint-{taint}-{NN}.jsonl (taint) / -vuln-{NN}.jsonl (vuln)。
depth=-1 表示 tracker 产生的会话 (非主链深度)。
"""
from __future__ import annotations
from pathlib import Path


def session_path(sessions_dir: Path, func_name: str, taint_name: str,
                 kind: str = "taint", depth: int = -1) -> Path:
    """返回自增 NN 的会话路径 (不覆盖既有)。

    kind: "taint" | "vuln" | "track"。
    """
    safe_func = func_name.replace("::", "_").replace("/", "_")[:60]
    safe_taint = (taint_name or "auto").replace("::", "_").replace("/", "_").replace(" ", "")[:40]
    prefix = f"d{depth}-{safe_func}-{kind}-{safe_taint}"
    n = 0
    while (sessions_dir / f"{prefix}-{n:02d}.jsonl").exists():
        n += 1
    return sessions_dir / f"{prefix}-{n:02d}.jsonl"
