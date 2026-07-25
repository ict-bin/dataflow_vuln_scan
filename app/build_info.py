from __future__ import annotations

import json
import logging
from pathlib import Path

from .config import get_service_yaml

logger = logging.getLogger("dvs.build_info")


BUILD_META_PATH = Path(__file__).resolve().parents[1] / "build_meta.json"


def _read_build_version() -> str | None:
    try:
        payload = json.loads(BUILD_META_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        logger.debug("read build_meta.json failed: %s", e)
        return None
    value = payload.get("build_version")
    normalized = str(value or "").strip()
    return normalized or None


def build_service_meta() -> dict[str, str | None]:
    registry = get_service_yaml().registry
    return {
        "service_id": registry.service_id,
        "service_name": registry.service_name,
        "build_version": _read_build_version(),
    }
