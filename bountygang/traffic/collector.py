"""HTTP traffic collector: pulls exchanges from Burp API or Playwright listener,
normalizes them into ``HttpExchange`` DTOs, mines object references and records
endpoints in the DB. Only *authorized* hosts (approved targets) are analyzed."""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl, urlparse

from bountygang.automation.burp import BurpAutomation
from bountygang.core.domain import EndpointCandidate, HttpExchange, ObjectReference
from bountygang.core.events import bus
from bountygang.db.repositories import EndpointRepo
from bountygang.db.session import session_scope
from bountygang.logging_setup import get_logger
from bountygang.scope.validator import _asset_matches
from bountygang.traffic.objects import mine_exchange
from bountygang.utils.sanitize import sanitize_headers, sanitize_text

log = get_logger("traffic.collector")

STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
              ".woff", ".woff2", ".ttf", ".map")


def normalize_burp_item(item: dict[str, Any]) -> HttpExchange | None:
    """Convert one Burp proxy-history entry into an HttpExchange (sanitized)."""
    try:
        url = item.get("url") or item.get("host", "") + item.get("path", "")
        parsed = urlparse(url)
        if not parsed.netloc:
            return None
        raw_request = item.get("request") or ""
        raw_response = item.get("response") or ""
        headers = {k.lower(): v for k, v in (item.get("headers") or {}).items()} \
            if isinstance(item.get("headers"), dict) else {}
        status = item.get("status") or item.get("response_status")
        ex = HttpExchange(
            host=parsed.netloc,
            path=parsed.path or "/",
            method=(item.get("method") or "GET").upper(),
            query=dict(parse_qsl(parsed.query)),
            request_headers=sanitize_headers(headers),
            request_body=sanitize_text(raw_request)[:50_000],
            status=int(status) if status is not None else None,
            response_headers=sanitize_headers(
                {k.lower(): v for k, v in (item.get("response_headers") or {}).items()}
                if isinstance(item.get("response_headers"), dict) else {}),
            response_body=sanitize_text(raw_response)[:100_000],
            source="burp",
            context_label=item.get("context", "default"),
        )
        return ex
    except Exception as e:  # malformed history rows must never crash capture
        log.debug("skip burp item: %s", e)
        return None


def normalize_playwright_request(req: dict[str, Any]) -> HttpExchange | None:
    parsed = urlparse(req.get("url", ""))
    if not parsed.netloc:
        return None
    return HttpExchange(
        host=parsed.netloc,
        path=parsed.path or "/",
        method=(req.get("method") or "GET").upper(),
        query=dict(parse_qsl(parsed.query)),
        request_headers=sanitize_headers({k.lower(): str(v)
                                          for k, v in (req.get("headers") or {}).items()}),
        source="playwright",
    )


class TrafficCollector:
    def __init__(self, burp: BurpAutomation | None = None) -> None:
        self.burp = burp or BurpAutomation()

    async def collect(self, allowed_hosts: list[str]) -> list[HttpExchange]:
        """Fetch Burp HTTP history, keep only authorized hosts, sanitize & store.

        Falls back to no-op when the Burp API is unavailable; the pipeline also
        feeds Playwright-captured requests via ``ingest_playwright_requests``.
        """
        items = await self.burp.get_proxy_history()
        exchanges: list[HttpExchange] = []
        for it in items:
            ex = normalize_burp_item(it)
            if ex and self._authorized(ex.host, allowed_hosts):
                exchanges.append(ex)
        self._persist(exchanges)
        return exchanges

    def ingest_playwright_requests(self, reqs: list[dict[str, Any]],
                                   allowed_hosts: list[str]) -> list[HttpExchange]:
        exchanges = []
        for r in reqs:
            ex = normalize_playwright_request(r)
            if ex and self._authorized(ex.host, allowed_hosts):
                exchanges.append(ex)
        self._persist(exchanges)
        return exchanges

    @staticmethod
    def _authorized(host: str, allowed_hosts: list[str]) -> bool:
        return any(_asset_matches(host, a) for a in allowed_hosts)

    def _persist(self, exchanges: list[HttpExchange]) -> list[EndpointCandidate]:
        candidates: list[EndpointCandidate] = []
        new_endpoints = 0
        with session_scope() as s:
            repo = EndpointRepo(s)
            for ex in exchanges:
                if ex.path.lower().endswith(STATIC_EXT):
                    continue
                refs: list[ObjectReference] = mine_exchange(ex)
                params = sorted(set(list(ex.query.keys())
                                    + [r.name for r in refs if r.location != "path"]))
                ep = repo.record(
                    host=ex.host, path=ex.path, method=ex.method,
                    params=params,
                    object_refs=[r.model_dump() for r in refs],
                )
                if ep.hit_count == 1:
                    new_endpoints += 1
                    bus.publish("endpoint.discovered", host=ep.host, path=ep.path,
                                method=ep.method, object_refs=len(refs))
                candidates.append(EndpointCandidate(
                    host=ex.host, path=ex.path, method=ex.method, params=params,
                    object_refs=refs, sample_status=ex.status,
                ))
        log.info("Persisted %d exchanges (%d new endpoints)", len(exchanges), new_endpoints)
        return candidates
