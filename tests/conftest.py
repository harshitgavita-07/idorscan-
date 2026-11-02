"""Shared pytest fixtures: temp DB, offline settings, fake Burp proxy."""
from __future__ import annotations

import asyncio
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


@pytest.fixture()
def tmp_env(tmp_path, monkeypatch):
    """Point all settings at a temp dir; force offline discovery + no telegram."""
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("LOG_FILE", str(tmp_path / "logs" / "bg.log"))
    monkeypatch.setenv("DISCOVERY_OFFLINE_MODE", "true")
    monkeypatch.setenv("TELEGRAM_ENABLED", "false")
    monkeypatch.setenv("LLM_PROVIDER", "none")
    from bountygang.config import reload_settings

    s = reload_settings()
    s.ensure_dirs()
    from bountygang.db.session import init_db

    init_db(s.db_path)
    yield s
    reload_settings()


class _VulnHandler(BaseHTTPRequestHandler):
    """Tiny vulnerable app for IDOR tests.

    /api/orders/<id> returns the order JSON if it exists.
    Ownership table: order 1001 belongs to acctB, 2002 to acctA.
    Header X-Api-Key identifies the caller in this fixture world.
    """

    ORDERS = {
        "1001": {"order_id": 1001, "owner": "acctB", "total": 42.5},
        "2002": {"order_id": 2002, "owner": "acctA", "total": 7.0},
    }

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        import json

        if self.path.startswith("/api/orders/"):
            oid = self.path.rsplit("/", 1)[-1]
            order = self.ORDERS.get(oid)
            if not order:
                self.send_response(404)
                self.end_headers()
                return
            # VULNERABLE on purpose: no object-level authorization check
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps(order).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/proxy-check":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture()
def vuln_server():
    srv = HTTPServer(("127.0.0.1", 0), _VulnHandler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    host, port = srv.server_address
    yield f"http://{host}:{port}"
    srv.shutdown()


class FakeBurpHandler(_VulnHandler):
    """Adds /burp/version and /burp/proxy/history endpoints like a Burp extension API."""

    HISTORY = [
        {
            "url": "http://PLACEHOLDER/api/orders/1001?user_id=1001",
            "method": "GET",
            "status": 200,
            "headers": {"Cookie": "session=SECRETVALUE123", "User-Agent": "x"},
            "response_headers": {"content-type": "application/json"},
            "request": "GET /api/orders/1001 HTTP/1.1\r\nCookie: session=SECRETVALUE123\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\n\r\n{\"order_id\":1001}",
        },
        {
            "url": "http://PLACEHOLDER/static/app.js",
            "method": "GET",
            "status": 200,
            "headers": {},
            "response_headers": {},
            "request": "",
            "response": "",
        },
    ]

    def do_GET(self):
        import json

        if self.path.startswith("/burp/version"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"version":"2024.11-fake"}')
        elif self.path.startswith("/burp/proxy/history"):
            items = []
            for it in self.HISTORY:
                d = dict(it)
                d["url"] = it["url"].replace("PLACEHOLDER", self.headers.get("X-Host", ""))
                items.append(d)
            payload = json.dumps({"items": items}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
        else:
            super().do_GET()


@pytest.fixture()
def fake_burp_server():
    srv = HTTPServer(("127.0.0.1", 0), FakeBurpHandler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    host, port = srv.server_address
    yield f"http://{host}:{port}"
    srv.shutdown()
