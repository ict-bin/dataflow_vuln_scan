"""Global config service for secflow-app-dataflow-vuln-scan.

All projects share a single configuration.  Config is loaded from the config
center on startup and cached locally.  Updates are pushed to the config center.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict

import httpx

from app.config import get_service_yaml, load_service_config
from app.models import normalize_max_rounds_exceeded_review_strategy

logger = logging.getLogger("dvs.config_service")

_CONFIG_CACHE_FILE = Path(os.environ.get("DVS_CONFIG_CACHE", "/tmp/dvs-global-config.json"))


# ── deep merge helpers ────────────────────────────────────────────────────────

def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(base)
    for key, val in override.items():
        base_val = result.get(key)
        if isinstance(base_val, dict) and not isinstance(val, dict):
            continue
        if isinstance(base_val, dict) and isinstance(val, dict):
            result[key] = _deep_merge(base_val, val)
        else:
            result[key] = val
    return result


# ── default config (loaded from file / config center, overridable) ────────────

def _service_config_paths() -> list[str]:
    paths = []
    configured = os.environ.get("SERVICE_CONFIG")
    if configured:
        paths.append(configured)
    paths.append("/opt/dataflow_vuln_scan/config.example.json")
    return paths


def _load_file_default() -> Dict[str, Any]:
    for path in _service_config_paths():
        if not os.path.isfile(path):
            continue
        try:
            return load_service_config(path).model_dump(mode="json")
        except Exception as exc:
            logger.warning("failed to load config from %s: %s", path, exc)
    # 不会走到这里——config.example.json 一定存在于镜像中
    raise RuntimeError("no config file found")


def _normalize_config(data: Dict[str, Any]) -> Dict[str, Any]:
    data = dict(data)
    data["max_rounds_exceeded_review_strategy"] = normalize_max_rounds_exceeded_review_strategy(
        data.get("max_rounds_exceeded_review_strategy")
    )
    data["pass_threshold"] = 0
    workers = data.setdefault("workers", {})
    if isinstance(workers, dict) and not workers.get("agents"):
        workers["agents"] = [{"model": "gaiasec/auto"}]
        workers.setdefault("default_tools", ["read", "bash", "edit", "write", "find"])
        workers.setdefault("default_thinking_level", "off")
        workers.setdefault("stage_models", {})
    judges = data.setdefault("judges", {})
    if isinstance(judges, dict):
        judges["agents"] = []
        judges.setdefault("default_tools", ["read", "bash", "find"])
        judges.setdefault("default_thinking_level", "off")
        judges.setdefault("stage_models", {})
    return data


# ── cached global config ──────────────────────────────────────────────────────

_global_config: Dict[str, Any] | None = None
_lock = threading.Lock()


def _load_cached() -> Dict[str, Any]:
    """Try to load a previously-cached config blob (written by config center sync)."""
    try:
        if _CONFIG_CACHE_FILE.is_file():
            return json.loads(_CONFIG_CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def get_global_config(*, force_reload: bool = False) -> Dict[str, Any]:
    """Return the current global configuration.

    Priority: cached blob > config-center blob > file defaults.
    """
    global _global_config
    if _global_config is not None and not force_reload:
        return dict(_global_config)

    with _lock:
        if _global_config is not None and not force_reload:
            return dict(_global_config)

        file_defaults = _load_file_default()
        cached = _load_cached()

        # cached blob from config center takes precedence over file defaults
        merged = _deep_merge(file_defaults, cached)

        _global_config = _normalize_config(merged)
        return dict(_global_config)


def refresh_from_config_center() -> bool:
    """Pull global config from config center and persist to local cache.

    Returns True on success, False on failure (existing config is kept).
    """
    try:
        svc_yaml = get_service_yaml()
        base_url = svc_yaml.configcenter.base_url.rstrip("/")
        token = svc_yaml.auth_service.service_machine_token
        timeout = svc_yaml.configcenter.timeout
    except Exception as exc:
        logger.warning("cannot read service.yaml for config center URL: %s", exc)
        return False

    url = f"{base_url}/service/dvs/global-config"
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    try:
        resp = httpx.get(url, headers=headers, timeout=timeout)
        if resp.status_code != 200:
            logger.warning("config center returned HTTP %s, keeping current config", resp.status_code)
            return False

        remote = resp.json()
        config_blob = remote.get("config") if isinstance(remote, dict) else remote
        if not isinstance(config_blob, dict):
            logger.warning("config center returned non-dict payload, keeping current config")
            return False

        # Strip fields that belong to the transport layer
        for _k in ("project_id", "updated_at", "created_at"):
            config_blob.pop(_k, None)

        # Persist to local cache
        _CONFIG_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CONFIG_CACHE_FILE.write_text(
            json.dumps(config_blob, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        # Invalidate cache so next get_global_config reads from disk
        global _global_config
        _global_config = None

        logger.info("global config refreshed from config center")
        return True

    except httpx.RequestError as exc:
        logger.warning("config center unreachable, keeping current config: %s", exc)
        return False
    except Exception as exc:
        logger.exception("unexpected error refreshing from config center: %s", exc)
        return False


def push_to_config_center(config_blob: Dict[str, Any]) -> bool:
    """Push updated global config to the config center.

    On success the local cache is also updated.  Returns True → config persisted.
    """
    try:
        svc_yaml = get_service_yaml()
        base_url = svc_yaml.configcenter.base_url.rstrip("/")
        token = svc_yaml.auth_service.service_machine_token
        timeout = svc_yaml.configcenter.timeout
    except Exception as exc:
        logger.warning("cannot read service.yaml for config center URL: %s", exc)
        return False

    # Normalize before pushing
    blob = _normalize_config(dict(config_blob))
    # Strip readonly fields
    for role_key in ("workers", "judges"):
        if isinstance(blob.get(role_key), dict):
            blob[role_key] = {k: v for k, v in blob[role_key].items()
                              if k != "system_prompt_dir"}

    url = f"{base_url}/service/dvs/global-config"
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    try:
        resp = httpx.put(url, json={"config": blob}, headers=headers, timeout=timeout)
        if resp.status_code not in (200, 201, 204):
            logger.warning("config center rejected PUT with HTTP %s", resp.status_code)
            return False

        # Also persist locally
        _CONFIG_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CONFIG_CACHE_FILE.write_text(
            json.dumps(blob, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        global _global_config
        _global_config = _normalize_config(blob)
        logger.info("global config pushed to config center")
        return True

    except httpx.RequestError as exc:
        logger.warning("config center unreachable during push: %s", exc)
        return False
    except Exception as exc:
        logger.exception("unexpected error pushing to config center: %s", exc)
        return False


# ── public API (used by route layer and task creation) ────────────────────────

class ConfigService:
    """Thin facade — all config is global."""

    def get_config(self) -> dict:
        cfg = get_global_config()
        cfg["project_id"] = ""  # no longer project-scoped
        return cfg

    def save_config(self, config_data: dict) -> dict:
        """Save global config.  Pushes to config center + updates local cache."""
        blob = {k: v for k, v in config_data.items() if k not in ("project_id", "updated_at")}
        push_to_config_center(blob)
        return self.get_config()


_config_service: ConfigService | None = None


def get_config_service() -> ConfigService:
    global _config_service
    if _config_service is None:
        _config_service = ConfigService()
    return _config_service
