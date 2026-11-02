"""Platform adapter protocol + shared HTTP fetch helper."""
from __future__ import annotations

from typing import Protocol

import httpx

from bountygang.config import get_settings
from bountygang.core.domain import ProgramInfo
from bountygang.logging_setup import get_logger

log = get_logger("discovery.base")


class PlatformAdapter(Protocol):
    """Each bug-bounty platform implements this interface."""

    name: str

    async def discover(self) -> list[ProgramInfo]:
        """Return all publicly-listed programs with policy/scope data."""
        ...


async def fetch_json(url: str, params: dict | None = None) -> object | None:
    """GET JSON with polite UA & timeout; None on any failure (never raises)."""
    s = get_settings()
    if s.discovery_offline_mode:
        return None
    headers = {"User-Agent": "BountyGang/0.1 (research agent; contact via program policy)"}
    try:
        async with httpx.AsyncClient(timeout=s.discovery_fetch_timeout,
                                    follow_redirects=True, headers=headers) as client:
            r = await client.get(url, params=params)
            if r.status_code == 200:
                return r.json()
            log.debug("fetch %s -> HTTP %s", url, r.status_code)
    except Exception as e:  # network offline etc — discovery degrades gracefully
        log.debug("fetch %s failed: %s", url, e)
    return None
