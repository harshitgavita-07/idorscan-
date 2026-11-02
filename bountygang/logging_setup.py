"""Structured logging for BountyGang (console + rotating file)."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from bountygang.config import get_settings

_FMT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"


def setup_logging(level: str | None = None) -> logging.Logger:
    settings = get_settings()
    lvl = getattr(logging, (level or settings.log_level), logging.INFO)
    root = logging.getLogger("bountygang")
    root.setLevel(lvl)
    if root.handlers:  # idempotent
        return root
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter(_FMT))
    root.addHandler(console)
    try:
        settings.ensure_dirs()
        fh = RotatingFileHandler(settings.log_file, maxBytes=2_000_000, backupCount=3)
        fh.setFormatter(logging.Formatter(_FMT))
        root.addHandler(fh)
    except OSError:  # pragma: no cover - e.g. read-only fs in CI
        pass
    root.propagate = False
    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"bountygang.{name}")
