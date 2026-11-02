"""ID generation helpers."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone


def report_id() -> str:
    """Human-friendly unique report id, e.g. BG-20261103-7f3a9c."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"BG-{ts}-{uuid.uuid4().hex[:6]}"


def short_uid(n: int = 8) -> str:
    return uuid.uuid4().hex[:n]
