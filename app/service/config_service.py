"""Global config service for secflow-app-dataflow-vuln-scan.

All projects share a single configuration sourced from the config center.
In-memory cache with file-defaults fallback when config center is unreachable.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict

import httpx

from app.config import get_service_yaml, load_service_config
from app.models import normalize_max_rounds_exceeded_review_strategy

logger = logging.getLogger("dvs.config_service")


# ── file defaults (ultimate fallback) ─────────────────────────────────────────

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


# ── config center client ──────────────────────────────────────────────────────

def _config_center_url() -> tuple[str, str, int]:
    svc = get_service_yaml()
    return (
        svc.configcenter.base_url.rstrip("/"),
        svc.auth_service.service_machine_token,
        svc.configcenter.timeout,
    )


def _fetch_from_config_center() -> Dict[str, Any] | None:
    """GET /service/dvs/global-config from config center.  Returns None on failure."""
    try:
        base_url, token, timeout = _config_center_url()
    except Exception as exc:
        logger.warning("cannot read config center URL from service.yaml: %s", exc)
        return None

    url = f"{base_url}/service/dvs/global-config"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        resp = httpx.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            blob = data.get("config") if isinstance(data, dict) else data
            if isinstance(blob, dict):
                for _k in ("project_id", "updated_at", "created_at"):
                    blob.pop(_k, None)
                return blob
        logger.warning("config center returned HTTP %s", resp.status_code)
    except httpx.RequestError as exc:
        logger.warning("config center unreachable: %s", exc)
    except Exception as exc:
        logger.exception("unexpected error fetching from config center: %s", exc)
    return None


def _push_to_config_center(config_blob: Dict[str, Any]) -> bool:
    """PUT /service/dvs/global-config to config center."""
    try:
        base_url, token, timeout = _config_center_url()
    except Exception as exc:
        logger.warning("cannot read config center URL: %s", exc)
        return False

    blob = _normalize_config(dict(config_blob))
    for role_key in ("workers", "judges"):
        if isinstance(blob.get(role_key), dict):
            blob[role_key] = {k: v for k, v in blob[role_key].items()
                              if k != "system_prompt_dir"}

    url = f"{base_url}/service/dvs/global-config"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        resp = httpx.put(url, json={"config": blob}, headers=headers, timeout=timeout)
        ok = resp.status_code in (200, 201, 204)
        if not ok:
            logger.warning("config center rejected PUT with HTTP %s", resp.status_code)
        return ok
    except httpx.RequestError as exc:
        logger.warning("config center unreachable during PUT: %s", exc)
        return False
    except Exception as exc:
        logger.exception("unexpected error pushing to config center: %s", exc)
        return False


# ── in-memory cache ───────────────────────────────────────────────────────────

_global_config: Dict[str, Any] | None = None
_lock = threading.Lock()


def get_global_config(*, force_reload: bool = False) -> Dict[str, Any]:
    """Return the current global config.

    Priority: in-memory cache → config center → file defaults.
    """
    global _global_config
    if _global_config is not None and not force_reload:
        return dict(_global_config)

    with _lock:
        if _global_config is not None and not force_reload:
            return dict(_global_config)

        # Try config center first
        remote = _fetch_from_config_center()
        if remote:
            _global_config = _normalize_config(remote)
            logger.info("global config loaded from config center")
            return dict(_global_config)

        # Fallback to file defaults
        logger.warning("config center unavailable, using file defaults")
        _global_config = _normalize_config(_load_file_default())
        return dict(_global_config)


# ── public API ────────────────────────────────────────────────────────────────

class ConfigService:
    """Global config — all projects share the same configuration."""

    def get_config(self) -> dict:
        cfg = get_global_config()
        cfg["project_id"] = ""  # no longer project-scoped
        return cfg

    def save_config(self, config_data: dict) -> dict:
        """Save global config to config center, then reload cache."""
        blob = {k: v for k, v in config_data.items()
                if k not in ("project_id", "updated_at")}
        if _push_to_config_center(blob):
            # Reload from config center to confirm
            get_global_config(force_reload=True)
        # Even if push failed, return current in-memory (best-effort)
        return self.get_config()


_config_service: ConfigService | None = None


def get_config_service() -> ConfigService:
    global _config_service
    if _config_service is None:
        _config_service = ConfigService()
    return _config_service
