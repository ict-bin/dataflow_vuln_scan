from __future__ import annotations

import os
from collections.abc import Callable

import pytest


def _guard_kill(name: str, original: Callable):
    def _wrapped(target: int, sig: int, *args, **kwargs):
        # Keep probe-style existence checks working in tests.
        if int(sig) == 0:
            return original(target, sig, *args, **kwargs)
        raise AssertionError(
            f"real process signal blocked during tests: {name}(target={target}, sig={sig})"
        )

    return _wrapped


@pytest.fixture(autouse=True)
def _block_real_process_signals(monkeypatch: pytest.MonkeyPatch):
    import app.agent_process as agent_process
    import app.runner_helpers as runner_helpers
    import app.service.agent_observability as agent_observability

    monkeypatch.setattr(
        agent_process.os,
        "kill",
        _guard_kill("app.agent_process.os.kill", os.kill),
    )
    monkeypatch.setattr(
        agent_process.os,
        "killpg",
        _guard_kill("app.agent_process.os.killpg", os.killpg),
    )
    monkeypatch.setattr(
        agent_observability.os,
        "kill",
        _guard_kill("app.service.agent_observability.os.kill", os.kill),
    )
    monkeypatch.setattr(
        agent_observability.os,
        "killpg",
        _guard_kill("app.service.agent_observability.os.killpg", os.killpg),
    )
    monkeypatch.setattr(
        runner_helpers.os,
        "killpg",
        _guard_kill("app.runner_helpers.os.killpg", os.killpg),
    )
