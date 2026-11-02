"""Burp Suite control.

Strategy (per the "no fragile coordinate automation" requirement):

1. **Preferred:** Burp's built-in REST API (http://127.0.0.1:9866, mounted by
   an Bundler/Extender-style extension or Burp 2023+ "Burp Integrator"-style
   local API). Used for proxy history, config checks and project status.
2. **Fallback on Windows:** launch the Burp JAR with ``subprocess`` and, if
   ``pywinauto`` is available, attach to the window *by title/class* (not mouse
   coordinates) purely to verify the GUI came up and optionally toggle a known
   checkbox via UIA element access.

The module imports safely on Linux/macOS (pywinauto simply isn't used), which
keeps the whole backend testable cross-platform.
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx

from bountygang.config import get_settings
from bountygang.core.events import bus
from bountygang.logging_setup import get_logger

log = get_logger("automation.burp")

IS_WINDOWS = False
try:  # pragma: no cover - exercised only on Windows
    import platform

    IS_WINDOWS = platform.system() == "Windows"
except Exception:
    pass


class BurpAutomation:
    def __init__(self) -> None:
        s = get_settings()
        self.api_url = s.burp_api_url.rstrip("/")
        self.api_token = s.burp_api_token
        self.jar_path = Path(s.burp_jar_path) if s.burp_jar_path else None
        self.project_file = Path(s.burp_project_file) if s.burp_project_file else None
        self.proxy_host = s.chromium_proxy_host
        self.proxy_port = s.chromium_proxy_port
        self._proc: subprocess.Popen | None = None

    # ------------------------------------------------------------- launching
    def find_jar(self) -> Path | None:
        """Locate the Burp JAR from settings or common Windows install paths."""
        candidates: list[Path] = []
        if self.jar_path:
            candidates.append(self.jar_path)
        pf = "%ProgramFiles%"
        candidates += [
            Path(rf"C:\Program Files\BurpSuiteCommunity\burpsuite_community.jar"),
            Path(rf"C:\Program Files\BurpSuiteProfessional\burpsuite_pro.jar"),
        ]
        env_pf = shutil.os.environ.get("ProgramFiles", r"C:\Program Files")
        candidates = [Path(str(c).replace("%ProgramFiles%", env_pf)) for c in candidates]
        for c in candidates:
            if c.exists():
                return c
        return None

    async def launch(self, headless_check_timeout: float = 60.0) -> bool:
        """Start Burp Suite (java -jar) and wait until its API/proxy respond.

        Returns True when Burp is reachable; never relies on pixel clicking.
        """
        jar = self.find_jar()
        java = shutil.which("java")
        if jar and java:
            args = [java, "-jar", str(jar)]
            if self.project_file:
                args += ["--project-file", str(self.project_file)]
            log.info("Launching Burp Suite: %s", " ".join(args))
            self._proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            bus.publish("burp.launching", jar=str(jar))
        elif IS_WINDOWS:
            log.warning("Burp JAR/java not found; trying pywinauto attach to running instance")
        else:
            log.info("No local Burp install detected (non-Windows dev box); "
                     "will only probe the API endpoint.")

        deadline = time.monotonic() + headless_check_timeout
        while time.monotonic() < deadline:
            if await self.is_running():
                bus.publish("burp.connected", api=self.api_url,
                            proxy=f"{self.proxy_host}:{self.proxy_port}")
                log.info("Burp Suite is up (api=%s)", self.api_url)
                return True
            await asyncio.sleep(2.0)
        log.warning("Burp did not become reachable within %.0fs", headless_check_timeout)
        bus.publish("burp.start_failed", api=self.api_url)
        return False

    # ------------------------------------------------------------ window check
    def gui_window_present(self) -> bool:
        """On Windows, confirm the Burp window exists using pywinauto UIA —
        element-based (title/class), NOT coordinate based."""
        if not IS_WINDOWS:
            return False
        try:  # pragma: no cover - Windows only
            from pywinauto import Desktop

            win = Desktop(backend="uia").window(title_re=".*Burp Suite.*")
            return bool(win.exists(timeout=2))
        except Exception:
            return False

    # ------------------------------------------------------------------- API
    async def _api_get(self, path: str) -> dict[str, Any] | None:
        headers = {}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"{self.api_url}{path}", headers=headers)
                if r.status_code == 200:
                    try:
                        return r.json()
                    except ValueError:
                        return {"text": r.text}
        except Exception:
            return None
        return None

    async def is_running(self) -> bool:
        """Burp considered running if its local API answers OR the proxy port accepts TCP."""
        if await self._api_get("/burp/version") is not None:
            return True
        return await self.proxy_listening()

    async def proxy_listening(self) -> bool:
        """TCP-connect check against Burp's proxy listener."""
        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.proxy_host, self.proxy_port), timeout=2.0
            )
            return True
        except (OSError, asyncio.TimeoutError):
            return False
        finally:
            if writer:
                try:
                    writer.close()
                except Exception:
                    pass

    async def get_proxy_history(self, limit: int = 500) -> list[dict[str, Any]]:
        """Fetch HTTP history from the Burp API (extension-provided endpoint).

        Returns [] when the API is unavailable — callers can fall back to the
        Playwright request listener so capture never silently breaks.
        """
        data = await self._api_get(f"/burp/proxy/history?limit={limit}")
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            return data["items"]
        if isinstance(data, list):
            return data
        return []

    async def shutdown(self) -> None:
        if self._proc and self._proc.poll() is None:
            log.info("Terminating Burp process (pid=%s)", self._proc.pid)
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover
                self._proc.kill()
        self._proc = None
