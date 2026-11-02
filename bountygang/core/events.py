"""Event bus: decouples producers (pipeline stages) from consumers (Telegram, logs).

Kept dependency-free and synchronous-safe so it works in both asyncio and plain
threads. Telegram notification tasks subscribe to events of interest.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

Handler = Callable[["Event"], Any]


@dataclass
class Event:
    kind: str                      # e.g. "program.discovered", "idor.confirmed"
    payload: dict[str, Any] = field(default_factory=dict)
    ts: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class EventBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = {}
        self._history: list[Event] = []

    def subscribe(self, kind: str, handler: Handler) -> None:
        self._handlers.setdefault(kind, []).append(handler)

    def publish(self, kind: str, **payload: Any) -> Event:
        ev = Event(kind=kind, payload=payload)
        self._history.append(ev)
        for h in self._handlers.get(kind, []) + self._handlers.get("*", []):
            try:
                result = h(ev)
                # allow async handlers when a loop is running
                if asyncio.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        asyncio.run(result)
            except Exception:  # never let a consumer break the pipeline
                import logging
                logging.getLogger("bountygang.bus").exception(
                    "event handler failed for %s", kind
                )
        return ev

    @property
    def history(self) -> list[Event]:
        return list(self._history)


# module-level default bus
bus = EventBus()
