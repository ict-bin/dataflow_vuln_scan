"""Global PI runtime materialization.

Each Pod runs exactly one task at a time.  Before a task starts the global
PI config (~/.pi/agent/models.json & settings.json) is regenerated with
the task's API key.  No task-scoped PI directories needed.
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


# ── models.json ───────────────────────────────────────────────────────────────

_ORIGINAL_MODELS: dict[str, Any] | None = None


def _ensure_original_models_saved() -> None:
    """On first call, save a copy of the pristine models.json so we can
    restore it between tasks.  We only overwrite apiKey, never structure."""
    global _ORIGINAL_MODELS
    if _ORIGINAL_MODELS is not None:
        return
    models_path = _GLOBAL_PI_DIR / "models.json"
    original = _read_json(models_path) or {"providers": {}}
    _ORIGINAL_MODELS = json.loads(json.dumps(original))  # deep copy
    logger.info("saved pristine models.json snapshot")


def regenerate_models_json(secret: str) -> None:
    """Write the global models.json with apiKey injected into every provider.

    Only apiKey is touched; all other fields are preserved from the original.
    """
    _ensure_original_models_saved()
    data = json.loads(json.dumps(_ORIGINAL_MODELS))
    providers = data.get("providers") if isinstance(data, dict) else None
    if not isinstance(providers, dict):
        return
    injected = 0
    for _key, cfg in providers.items():
        if isinstance(cfg, dict):
            cfg["apiKey"] = secret
            injected += 1
    _write_json(_GLOBAL_PI_DIR / "models.json", data)
    logger.info("regenerated global models.json — apiKey injected into %d providers", injected)


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
    """Regenerate global PI config with the task's API key.

    Called once per task before execution starts.
    """
    if not secret:
        logger.warning("no api key for task, keeping current PI config")
        return
    _GLOBAL_PI_DIR.mkdir(parents=True, exist_ok=True)
    regenerate_models_json(secret)
    regenerate_settings_json()
    logger.info("global PI runtime materialized")
