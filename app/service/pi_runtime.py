"""Global PI runtime materialization.

Each Pod runs exactly one task at a time.  Before a task starts the global
PI config (~/.pi/agent/models.json & settings.json) is regenerated.
_write_models_json_from_db() pulls fresh providers from the config center
into models.json before materialize_pi_runtime() is called.

materialize_pi_runtime():
  - secret present  → inject secret into ALL providers' apiKey
  - no secret       → leave models.json as-is (config center keys)
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger("dvs.pi_runtime")

_GLOBAL_PI_DIR = Path(os.environ.get("PI_CODING_AGENT_DIR", "/root/.pi/agent"))

_PI_COMPACTION_SETTINGS = {
    "defaultThinkingLevel": "off",
    "compaction": {
        "enabled": True,
        "reserveTokens": 8192,
        "keepRecentTokens": 50000,
    },
}


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _inject_secret_into_models(secret: str) -> int:
    """Read the CURRENT models.json and inject secret into every provider.

    Returns the number of providers updated.
    """
    models_path = _GLOBAL_PI_DIR / "models.json"
    data = _read_json(models_path)
    if not isinstance(data, dict):
        return 0
    providers = data.get("providers")
    if not isinstance(providers, dict):
        return 0
    injected = 0
    for _key, cfg in providers.items():
        if isinstance(cfg, dict):
            cfg["apiKey"] = secret
            injected += 1
    _write_json(models_path, data)
    return injected


# ── settings.json ─────────────────────────────────────────────────────────────

_ORIGINAL_SETTINGS: dict[str, Any] | None = None


def _ensure_original_settings_saved() -> None:
    global _ORIGINAL_SETTINGS
    if _ORIGINAL_SETTINGS is not None:
        return
    path = _GLOBAL_PI_DIR / "settings.json"
    _ORIGINAL_SETTINGS = _read_json(path) or {}


def regenerate_settings_json() -> None:
    _ensure_original_settings_saved()
    merged = dict(_ORIGINAL_SETTINGS)
    merged.update(_PI_COMPACTION_SETTINGS)
    _write_json(_GLOBAL_PI_DIR / "settings.json", merged)
    logger.info("regenerated global settings.json")


# ── public entry point ────────────────────────────────────────────────────────

def materialize_pi_runtime(*, secret: str) -> None:
    """Regenerate global PI config for the current task.

    Called once per task after _write_models_json_from_db() has written
    fresh providers from the config center.

    - secret present → inject secret into ALL providers' apiKey
    - no secret      → leave models.json as-is (use config center keys)
    """
    _GLOBAL_PI_DIR.mkdir(parents=True, exist_ok=True)
    regenerate_settings_json()
    if not secret:
        logger.info("global PI runtime materialized — no secret, using config center keys")
        return
    injected = _inject_secret_into_models(secret)
    logger.info("global PI runtime materialized — apiKey injected into %d providers", injected)
