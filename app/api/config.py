"""Global config API routes for dataflow-vuln-scan.

All projects share a single configuration, managed via config center.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import Depends, HTTPException
from pydantic import BaseModel

from app.service.config_service import get_config_service

from . import router

logger = logging.getLogger("dvs.api.config")


class ConfigSaveRequest(BaseModel):
    config: Dict[str, Any]


@router.get("/config")
def get_config():
    """Return the global (all-project) configuration."""
    try:
        return get_config_service().get_config()
    except Exception as exc:
        logger.error("get_config failed: %s", exc)
        raise HTTPException(status_code=503, detail="获取配置失败，请稍后重试") from exc


@router.put("/config")
def save_config(body: ConfigSaveRequest):
    """Update the global configuration and push to config center."""
    try:
        return get_config_service().save_config(body.config)
    except Exception as exc:
        logger.error("save_config failed: %s", exc)
        raise HTTPException(status_code=503, detail="保存配置失败，请稍后重试") from exc
