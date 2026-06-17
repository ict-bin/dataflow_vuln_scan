"""Global config API routes for dataflow-vuln-scan.

All projects share a single configuration.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db import get_db
from app.service.config_service import get_config_service

from . import router

logger = logging.getLogger("dvs.api.config")


class ConfigSaveRequest(BaseModel):
    config: Dict[str, Any]


@router.get("/config")
def get_config(db: Session = Depends(get_db)):
    try:
        return get_config_service().get_config(db)
    except SQLAlchemyError as exc:
        logger.error("get_config failed: %s", exc)
        raise HTTPException(status_code=503, detail="数据库暂时不可用，请稍后重试") from exc


@router.put("/config")
def save_config(body: ConfigSaveRequest, db: Session = Depends(get_db)):
    try:
        return get_config_service().save_config(db, body.config)
    except SQLAlchemyError as exc:
        logger.error("save_config failed: %s", exc)
        raise HTTPException(status_code=503, detail="保存失败，数据库暂时不可用") from exc
