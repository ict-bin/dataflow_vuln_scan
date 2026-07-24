"""Service package for secflow-app-dataflow-vuln-scan."""

from __future__ import annotations

from typing import Any

__all__ = ["generate_prompt_from_path", "get_task_service", "TaskService"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from .task_service import TaskService, generate_prompt_from_path, get_task_service

        exports = {
            "TaskService": TaskService,
            "generate_prompt_from_path": generate_prompt_from_path,
            "get_task_service": get_task_service,
        }
        return exports[name]
    raise AttributeError(name)
