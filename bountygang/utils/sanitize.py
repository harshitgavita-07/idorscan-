"""Sanitization helpers — strip secrets/PII before storage, reporting or Telegram."""
from __future__ import annotations

import re

# Header names whose values must never leave the local machine.
SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "apikey", "x-auth-token", "auth-token",
    "x-csrf-token", "csrf-token", "password", "token",
}

_SECRET_PATTERNS = [
    # Bearer / basic tokens
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9\-._~+/]{8,}=*"), r"\1 [REDACTED]"),
    # Common key formats
    (re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"), "[REDACTED-API-KEY]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED-TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "[REDACTED-GH-PAT]"),
    # JWTs
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
     "[REDACTED-JWT]"),
    # key=value style secrets in bodies/queries
    (re.compile(
        r"(?i)\b(password|passwd|secret|client_secret|access_token|refresh_token|api_key|apikey|token)"
        r"(['\"]?\s*[:=]\s*)['\"]?[^\s'\"&,}]+"), r"\1\2[REDACTED]"),
    # emails & phones (PII)
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "[REDACTED-EMAIL]"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
     "[REDACTED-PHONE]"),
]


def sanitize_text(text: str) -> str:
    """Redact credentials, tokens and PII from arbitrary text."""
    if not text:
        return text
    out = text
    for pattern, repl in _SECRET_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return headers with sensitive values replaced by a redaction marker."""
    out: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            out[k] = "[REDACTED]"
        else:
            out[k] = sanitize_text(v)
    return out


def sanitize_request_line(raw: str) -> str:
    """Sanitize a raw HTTP request/response blob (headers + body)."""
    if not raw:
        return raw
    lines = raw.splitlines()
    out: list[str] = []
    in_headers = True
    for line in lines:
        m = re.match(r"^([A-Za-z0-9\-_]+)\s*:\s*(.*)$", line)
        if in_headers and m and m.group(1).lower() in SENSITIVE_HEADERS:
            out.append(f"{m.group(1)}: [REDACTED]")
            continue
        if line == "":
            in_headers = False
        out.append(sanitize_text(line))
    return "\n".join(out)
