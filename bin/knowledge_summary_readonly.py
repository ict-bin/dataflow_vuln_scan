"""Execute a small read-only command grammar inside authorized roots."""

from __future__ import annotations

import argparse
import base64
import os
import shlex
import subprocess
import sys
from pathlib import Path

ALLOWED = {"cat", "find", "grep", "head", "tail", "sed", "wc"}
FORBIDDEN = {"bash", "sh", "python", "python3", "rm", "mv", "cp", "chmod", "curl", "wget"}


def _roots() -> list[Path]:
    return [Path(value).resolve() for value in os.environ.get("DVS_READONLY_ROOTS", "").split(":") if value]


def _under(path: Path, roots: list[Path]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--command", required=True)
    args = parser.parse_args()
    roots = _roots()
    if not roots:
        print("no authorized read roots", file=sys.stderr)
        return 2
    command = base64.b64decode(args.command.encode("ascii"), validate=True).decode("utf-8")
    if any(token in command for token in (";", "|", ">", "<", "`", "$", "&&", "||")):
        print("shell composition is forbidden", file=sys.stderr)
        return 2
    tokens = shlex.split(command)
    if not tokens or tokens[0] not in ALLOWED or any(token in FORBIDDEN for token in tokens):
        print("command is not read-only", file=sys.stderr)
        return 2
    normalized: list[str] = [tokens[0]]
    for token in tokens[1:]:
        if token.startswith("-"):
            normalized.append(token)
            continue
        candidate = Path(token).resolve() if token.startswith("/") else (Path.cwd() / token).resolve()
        if candidate.exists():
            if not _under(candidate, roots):
                print(f"path outside authorized roots: {token}", file=sys.stderr)
                return 2
            normalized.append(str(candidate))
        elif tokens[0] in {"cat", "head", "tail", "sed", "wc", "find"}:
            if tokens[0] == "find" and not normalized[1:]:
                normalized.append(str(roots[0]))
            else:
                normalized.append(token)
        else:
            normalized.append(token)
    try:
        result = subprocess.run(normalized, cwd=str(roots[0]), shell=False, check=False, timeout=60)
    except subprocess.TimeoutExpired:
        print("read command timed out", file=sys.stderr)
        return 124
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
