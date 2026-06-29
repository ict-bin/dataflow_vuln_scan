from __future__ import annotations

from typing import Any

from .models import SwarmEvent


def coerce_swarm_event(*args: Any, default_task_id: str = "", **kwargs: Any) -> SwarmEvent:
    if len(args) == 1 and isinstance(args[0], SwarmEvent) and not kwargs:
        return args[0]

    if len(args) > 1:
        raise TypeError(f"unsupported runtime event args: {args!r}")

    event_type = ""
    event_data: dict[str, Any] = {}
    task_id = default_task_id

    if args:
        first = args[0]
        if not isinstance(first, str):
            raise TypeError(f"unsupported runtime event payload: {first!r}")
        event_type = first.strip()
        event_data.update(kwargs)
        task_id = str(event_data.pop("task_id", default_task_id) or default_task_id)
    else:
        event_data.update(kwargs)
        event_type = str(event_data.pop("event_type", "") or "").strip()
        task_id = str(event_data.pop("task_id", default_task_id) or default_task_id)

    if not event_type:
        raise TypeError("runtime event_type is required")

    return SwarmEvent(type=event_type, task_id=task_id, data=event_data)
