from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any


def path_exists_logged(path: Path, *, logger: logging.Logger, purpose: str) -> bool:
    try:
        exists = path.exists()
        if not exists:
            logger.warning("file access missing: purpose=%s path=%s", purpose, str(path))
        else:
            logger.debug("file access exists: purpose=%s path=%s", purpose, str(path))
        return exists
    except Exception as exc:
        logger.warning("file access exists-check failed: purpose=%s path=%s error=%s", purpose, str(path), exc, exc_info=True)
        return False


def path_is_file_logged(path: Path, *, logger: logging.Logger, purpose: str) -> bool:
    try:
        is_file = path.is_file()
        if not is_file:
            logger.warning("file access not-file: purpose=%s path=%s", purpose, str(path))
        else:
            logger.debug("file access is-file: purpose=%s path=%s", purpose, str(path))
        return is_file
    except Exception as exc:
        logger.warning("file access is-file check failed: purpose=%s path=%s error=%s", purpose, str(path), exc, exc_info=True)
        return False


def resolve_path_logged(path: Path, *, logger: logging.Logger, purpose: str) -> Path:
    try:
        resolved = path.resolve()
        logger.debug("file access resolve ok: purpose=%s path=%s resolved=%s", purpose, str(path), str(resolved))
        return resolved
    except Exception as exc:
        logger.warning("file access resolve failed: purpose=%s path=%s error=%s", purpose, str(path), exc, exc_info=True)
        raise


def read_text_logged(
    path: Path,
    *,
    logger: logging.Logger,
    purpose: str,
    encoding: str = "utf-8",
    errors: str = "strict",
) -> str:
    logger.debug("file access read-text start: purpose=%s path=%s", purpose, str(path))
    try:
        text = path.read_text(encoding=encoding, errors=errors)
        logger.debug("file access read-text ok: purpose=%s path=%s size=%d", purpose, str(path), len(text))
        return text
    except Exception as exc:
        logger.warning("file access read-text failed: purpose=%s path=%s error=%s", purpose, str(path), exc, exc_info=True)
        raise


def read_bytes_logged(path: Path, *, logger: logging.Logger, purpose: str) -> bytes:
    logger.debug("file access read-bytes start: purpose=%s path=%s", purpose, str(path))
    try:
        payload = path.read_bytes()
        logger.debug("file access read-bytes ok: purpose=%s path=%s size=%d", purpose, str(path), len(payload))
        return payload
    except Exception as exc:
        logger.warning("file access read-bytes failed: purpose=%s path=%s error=%s", purpose, str(path), exc, exc_info=True)
        raise


def read_json_logged(path: Path, *, logger: logging.Logger, purpose: str, encoding: str = "utf-8") -> Any:
    raw = read_text_logged(path, logger=logger, purpose=purpose, encoding=encoding)
    try:
        payload = json.loads(raw)
        logger.debug("file access read-json ok: purpose=%s path=%s", purpose, str(path))
        return payload
    except Exception as exc:
        logger.warning("file access read-json failed: purpose=%s path=%s error=%s", purpose, str(path), exc, exc_info=True)
        raise


def stat_logged(path: Path, *, logger: logging.Logger, purpose: str):
    try:
        stat = path.stat()
        logger.debug("file access stat ok: purpose=%s path=%s", purpose, str(path))
        return stat
    except Exception as exc:
        logger.warning("file access stat failed: purpose=%s path=%s error=%s", purpose, str(path), exc, exc_info=True)
        raise


def sqlite_connect_logged(
    path: Path,
    *,
    logger: logging.Logger,
    purpose: str,
    **connect_kwargs,
) -> sqlite3.Connection:
    logger.debug("file access sqlite-connect start: purpose=%s path=%s", purpose, str(path))
    try:
        conn = sqlite3.connect(path, **connect_kwargs)
        logger.debug("file access sqlite-connect ok: purpose=%s path=%s", purpose, str(path))
        return conn
    except Exception as exc:
        logger.warning("file access sqlite-connect failed: purpose=%s path=%s error=%s", purpose, str(path), exc, exc_info=True)
        raise
