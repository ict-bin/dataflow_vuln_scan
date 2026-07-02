"""Global config service for secflow-app-dataflow-vuln-scan.

All projects share a single configuration stored in the database.
Uses a sentinel project_id="" to store the global config.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict

from sqlalchemy.orm import Session

from app.config import load_service_config
from app.db.models import AppDvsDebugConfig, AppDvsProjectConfig
from app.models import normalize_max_rounds_exceeded_review_strategy

logger = logging.getLogger("dvs.config_service")

_GLOBAL_PROJECT_ID = ""


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


class ConfigService:
    """Global config — all projects share the same row (project_id="")."""

    def get_config(self, db: Session) -> dict:
        base = _load_file_default()
        row = db.query(AppDvsProjectConfig).filter_by(project_id=_GLOBAL_PROJECT_ID).first()
        if row and row.config_json:
            data = _deep_merge(base, row.config_json)
            updated_at = row.updated_at.isoformat() if row.updated_at else None
        else:
            data = dict(base)
            updated_at = None
        data = _normalize_config(data)
        data["project_id"] = _GLOBAL_PROJECT_ID
        data["updated_at"] = updated_at
        return data

    def save_config(self, db: Session, config_data: dict) -> dict:
        base = _load_file_default()
        blob = {k: v for k, v in config_data.items()
                if k not in ("project_id", "updated_at")}
        blob = _normalize_config(blob)
        for role_key in ("workers", "judges"):
            if isinstance(blob.get(role_key), dict):
                blob[role_key] = {k: v for k, v in blob[role_key].items()
                                  if k != "system_prompt_dir"}

        row = db.query(AppDvsProjectConfig).filter_by(project_id=_GLOBAL_PROJECT_ID).first()
        if row:
            row.config_json = blob
        else:
            row = AppDvsProjectConfig(project_id=_GLOBAL_PROJECT_ID, config_json=blob)
            db.add(row)
        db.commit()
        db.refresh(row)

        result = _normalize_config(_deep_merge(base, blob))
        result["project_id"] = _GLOBAL_PROJECT_ID
        result["updated_at"] = row.updated_at.isoformat() if row.updated_at else None
        return result


    # ── 失败调试模型配置 ──────────────────────────────────────────────────
    _FAILURE_DEBUG_KEY = "failure_debug"

    def get_failure_debug_config(self, db: Session) -> dict:
        try:
            row = db.query(AppDvsDebugConfig).filter_by(config_key=self._FAILURE_DEBUG_KEY).first()
        except Exception:
            return {"model": None, "updated_at": None}
        if row and row.config_json:
            data = dict(row.config_json)
        else:
            data = {"model": None}
        data["updated_at"] = row.updated_at.isoformat() if (row and row.updated_at) else None
        return data

    def save_failure_debug_config(self, db: Session, model: str) -> dict:
        blob = {"model": (model or "").strip()}
        try:
            row = db.query(AppDvsDebugConfig).filter_by(config_key=self._FAILURE_DEBUG_KEY).first()
            if row:
                row.config_json = blob
            else:
                row = AppDvsDebugConfig(config_key=self._FAILURE_DEBUG_KEY, config_json=blob)
                db.add(row)
            db.commit()
            db.refresh(row)
        except Exception as exc:
            logger.error("Failed to save failure_debug config: %s", exc)
            db.rollback()
            raise
        result = dict(blob)
        result["updated_at"] = row.updated_at.isoformat() if row.updated_at else None
        return result


_config_service: ConfigService | None = None


def get_config_service() -> ConfigService:
    global _config_service
    if _config_service is None:
        _config_service = ConfigService()
    return _config_service
