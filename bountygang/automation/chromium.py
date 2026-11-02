"""Chromium automation via Playwright, routed through the Burp proxy.

Design notes
------------
* All browser control uses the Playwright *API* (stable), not coordinate clicks.
* Proxy configuration is passed to Chromium at launch so every request flows
  through Burp Suite's listener (default 127.0.0.1:8080).
* ``verify_proxy_interception`` proves interception is working by loading a URL
  through the proxy and checking that the response actually came back via the
  configured proxy path (Burp adds no header by default, so we verify at the
  socket level with httpx through the same proxy — deterministic & testable).
* The class is import-safe on any OS; launching requires playwright browsers
  installed (``playwright install chromium``).
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from bountygang.config import get_settings
from bountygang.core.events import bus
from bountygang.logging_setup import get_logger

log = get_logger("automation.chromium")


@dataclass
class BrowserSession:
    context: Any = None
    page: Any = None
    launched: bool = False
    closed: bool = False


class ChromiumAutomation:
    """Launches Chromium through Burp's proxy and visits authorized targets."""

    def __init__(self, proxy_host: str | None = None, proxy_port: int | None = None,
                 headless: bool | None = None) -> None:
        s = get_settings()
        self.proxy_host = proxy_host or s.chromium_proxy_host
        self.proxy_port = proxy_port or s.chromium_proxy_port
        self.headless = s.headless if headless is None else headless
        self._pw: Any = None
        self._browser: Any = None
        self.session: BrowserSession | None = None

    # ------------------------------------------------------------------ launch
    @property
    def proxy_url(self) -> str:
        return f"http://{self.proxy_host}:{self.proxy_port}"

    async def launch(self) -> BrowserSession:
        """Start Chromium with the Burp proxy configured."""
        try:
            from playwright.async_api import async_playwright
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("playwright is not installed") from e

        self._pw = await async_playwright().start()
        try:
            self._browser = await self._pw.chromium.launch(
                headless=self.headless,
                proxy={"server": self.proxy_url},
                args=["--ignore-certificate-errors"],  # Burp CA during authorized tests
            )
        except Exception as e:
            await self._pw.stop()
            self._pw = None
            raise RuntimeError(f"Failed to launch Chromium via proxy {self.proxy_url}: {e}") from e

        context = await self._browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        self.session = BrowserSession(context=context, page=page, launched=True)
        log.info("Chromium launched (headless=%s) with proxy %s", self.headless, self.proxy_url)
        bus.publish("browser.launched", proxy=self.proxy_url, headless=self.headless)
        return self.session

    # ------------------------------------------------------------------- visit
    async def open_target(self, url: str, timeout_ms: int = 30_000) -> dict[str, Any]:
        """Open an authorized target URL; returns navigation metadata."""
        if not self.session or not self.session.page:
            raise RuntimeError("Browser not launched — call launch() first")
        resp = await self.session.page.goto(url, wait_until="domcontentloaded",
                                            timeout=timeout_ms)
        info = {
            "url": url,
            "status": resp.status if resp else None,
            "title": await self.session.page.title(),
        }
        log.info("Opened target %s -> %s", url, info.get("status"))
        bus.publish("browser.target_opened", **info)
        return info

    async def collect_requests(self, url: str, seconds: float = 5.0) -> list[dict[str, Any]]:
        """Browse a page and record the network requests it generates."""
        if not self.session or not self.session.page:
            raise RuntimeError("Browser not launched — call launch() first")
        seen: list[dict[str, Any]] = []

        def _on_request(req: Any) -> None:
            seen.append({
                "method": req.method,
                "url": req.url,
                "resource_type": req.resource_type,
                "headers": dict(req.headers),
            })

        page = self.session.page
        page.on("request", _on_request)
        await page.goto(url, wait_until="domcontentloaded")
        await asyncio.sleep(seconds)
        page.remove_listener("request", _on_request)
        log.info("Captured %d requests while browsing %s", len(seen), url)
        return seen

    # -------------------------------------------------------------- proxy check
    async def verify_proxy_interception(self, probe_url: str = "http://neverssl.com/") -> bool:
        """Verify HTTP traffic really flows through the Burp proxy.

        We perform a plain HTTP GET *through the proxy* with httpx. If Burp's
        listener is up it will relay (and intercept-log) the request; if the
        proxy is dead the connect fails. This is the programmatic equivalent of
        'check that traffic shows up in Burp' without fragile GUI clicking.
        """
        try:
            async with httpx.AsyncClient(proxy=self.proxy_url, timeout=10.0,
                                         follow_redirects=True) as client:
                r = await client.get(probe_url)
                ok = r.status_code < 500
        except Exception as e:
            log.warning("Proxy interception check failed: %s", e)
            bus.publish("burp.interception_failed", proxy=self.proxy_url, error=str(e))
            return False
        if ok:
            log.info("Proxy interception verified through %s", self.proxy_url)
            bus.publish("burp.connected", proxy=self.proxy_url)
        return ok

    # -------------------------------------------------------------------- stop
    async def close(self) -> None:
        try:
            if self._browser:
                await self._browser.close()
            if self._pw:
                await self._pw.stop()
        finally:
            if self.session:
                self.session.closed = True
            self._browser = None
            self._pw = None
            log.info("Chromium closed")
