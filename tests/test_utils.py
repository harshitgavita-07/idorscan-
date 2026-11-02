"""Unit tests: sanitization, ids, config."""
from bountygang.utils.ids import report_id
from bountygang.utils.sanitize import (
    sanitize_headers,
    sanitize_request_line,
    sanitize_text,
)


def test_redacts_bearer_and_cookies():
    t = sanitize_text("Authorization: Bearer abcdef1234567890xyz")
    assert "abcdef1234567890xyz" not in t
    h = sanitize_headers({"cookie": "session=supersecret", "accept": "application/json"})
    assert h["cookie"] == "[REDACTED]"
    assert h["accept"] == "application/json"


def test_redacts_api_keys_jwt_email_phone():
    assert "sk-" not in sanitize_text("key sk-abcdefghijklmnopqrstuvwxyz12")
    assert "eyJ" not in sanitize_text(
        "token eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123_xyz-99")
    out = sanitize_text("contact jane.doe@example.com or 555-123-4567")
    assert "jane.doe@example.com" not in out and "[REDACTED-EMAIL]" in out
    assert "555-123-4567" not in out


def test_sanitize_raw_http():
    raw = ("GET /x HTTP/1.1\r\nHost: a\r\nCookie: sid=leakme123\r\n"
           "\r\n{\"password\": \"hunter22\"}")
    out = sanitize_request_line(raw)
    assert "leakme123" not in out and "hunter22" not in out


def test_report_id_format():
    rid = report_id()
    assert rid.startswith("BG-") and len(rid.split("-")) == 3
