"""API router package for secflow-app-dataflow-vuln-scan."""

from fastapi import APIRouter

router = APIRouter(prefix="/api/app/dataflow-vuln-scan")

from . import tasks, config, prompts, failure_debug, knowledge_summary  # noqa: E402, F401
