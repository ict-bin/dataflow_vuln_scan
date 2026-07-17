"""dagflow 会话命名 (NN 自增, 不覆盖)。

设计: 独立会话 (func-taint), 不 fork 调用链。
文件名: d{depth:02d}-{func}-{kind}-{taint}-{NN}.jsonl
depth 统一非负, 零填充 2 位: 主链 d00/d01/d02..., tracker/escape/indirect/mining 用 d01。
"""
from __future__ import annotations
from pathlib import Path


def session_path(sessions_dir: Path, func_name: str, taint_name: str,
                 kind: str = "taint", depth: int = 1) -> Path:
    """返回自增 NN 的会话路径 (不覆盖)。

    kind: "taint" | "vuln" | "track"。
    depth: 非负, 零填充 2 位。主链传 0/1/2..., tracker/mining 默认 1。
    负值归一为 1 (兼容旧调用)。
    """
    safe_func = func_name.replace("::", "_").replace("/", "_")[:60]
    safe_taint = (taint_name or "auto").replace("::", "_").replace("/", "_").replace(" ", "")[:40]
    d = depth if depth >= 0 else 1
    prefix = f"d{d:02d}-{safe_func}-{kind}-{safe_taint}"
    n = 0
    while (sessions_dir / f"{prefix}-{n:02d}.jsonl").exists():
        n += 1
    return sessions_dir / f"{prefix}-{n:02d}.jsonl"
