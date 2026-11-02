"""SQLAlchemy ORM models for BountyGang."""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# ------------------------------- enums --------------------------------------

class ScopeClassification(str, enum.Enum):
    APPROVED = "APPROVED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    BLOCKED = "BLOCKED"


class ApprovalStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"


class FindingClassification(str, enum.Enum):
    CONFIRMED_IDOR = "CONFIRMED_IDOR"
    LIKELY_IDOR = "LIKELY_IDOR"
    POSSIBLE_IDOR = "POSSIBLE_IDOR"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"


class ScanState(str, enum.Enum):
    IDLE = "IDLE"
    DISCOVERING = "DISCOVERING"
    VALIDATING_SCOPE = "VALIDATING_SCOPE"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    LAUNCHING_BROWSER = "LAUNCHING_BROWSER"
    CAPTURING = "CAPTURING"
    ANALYZING = "ANALYZING"
    VALIDATING_IDOR = "VALIDATING_IDOR"
    REPORTING = "REPORTING"
    NOTIFYING = "NOTIFYING"
    DONE = "DONE"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


# ------------------------------ tables ---------------------------------------

class Program(Base):
    """A publicly listed bug bounty program and its extracted policy data."""

    __tablename__ = "programs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    platform: Mapped[str] = mapped_column(String(64), index=True)      # hackerone...
    slug: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(String(512), default="")
    bounty_min: Mapped[float | None] = mapped_column(Float, nullable=True)
    bounty_max: Mapped[float | None] = mapped_column(Float, nullable=True)
    policy_text: Mapped[str] = mapped_column(Text, default="")
    in_scope_assets: Mapped[str] = mapped_column(Text, default="[]")   # JSON list
    out_of_scope_assets: Mapped[str] = mapped_column(Text, default="[]")
    idor_eligible: Mapped[bool] = mapped_column(Boolean, default=False)
    automation_allowed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    rate_limit_rpm: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_json: Mapped[str] = mapped_column(Text, default="{}")
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    targets: Mapped[list["Target"]] = relationship(back_populates="program")
    findings: Mapped[list["Finding"]] = relationship(back_populates="program")
    reports: Mapped[list["Report"]] = relationship(back_populates="program")


class Target(Base):
    """An individual asset derived from a program's scope, with validation state."""

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"), index=True)
    asset: Mapped[str] = mapped_column(String(512))           # e.g. api.example.com
    asset_type: Mapped[str] = mapped_column(String(32), default="domain")
    classification: Mapped[ScopeClassification] = mapped_column(
        Enum(ScopeClassification), default=ScopeClassification.REVIEW_REQUIRED
    )
    approval_status: Mapped[ApprovalStatus] = mapped_column(
        Enum(ApprovalStatus), default=ApprovalStatus.PENDING
    )
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    program: Mapped["Program"] = relationship(back_populates="targets")


class Endpoint(Base):
    """An HTTP endpoint discovered from captured traffic."""

    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id"), nullable=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    path: Mapped[str] = mapped_column(String(1024))
    method: Mapped[str] = mapped_column(String(16), default="GET")
    params: Mapped[str] = mapped_column(Text, default="[]")          # JSON list
    object_refs: Mapped[str] = mapped_column(Text, default="[]")     # JSON list
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    hit_count: Mapped[int] = mapped_column(Integer, default=1)


class Finding(Base):
    """An IDOR/BOLA candidate produced by the detection engine."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int | None] = mapped_column(ForeignKey("programs.id"), index=True)
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoints.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(512), default="")
    vulnerability_type: Mapped[str] = mapped_column(String(64), default="BOLA/IDOR")
    endpoint: Mapped[str] = mapped_column(String(1024), default="")
    method: Mapped[str] = mapped_column(String(16), default="GET")
    parameter: Mapped[str] = mapped_column(String(255), default="")
    severity: Mapped[str] = mapped_column(String(32), default="UNKNOWN")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    classification: Mapped[FindingClassification] = mapped_column(
        Enum(FindingClassification), default=FindingClassification.POSSIBLE_IDOR
    )
    validation_status: Mapped[str] = mapped_column(String(64), default="UNVERIFIED")
    evidence: Mapped[str] = mapped_column(Text, default="{}")        # JSON, sanitized
    description: Mapped[str] = mapped_column(Text, default="")
    ai_analysis: Mapped[str] = mapped_column(Text, default="")
    reproducible: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    program: Mapped["Program"] = relationship(back_populates="findings")


class Report(Base):
    """A generated HackerOne-style report (never auto-submitted)."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # BG-xxxx
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True)
    program_id: Mapped[int | None] = mapped_column(ForeignKey("programs.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(512), default="")
    markdown_path: Mapped[str] = mapped_column(String(1024), default="")
    json_path: Mapped[str] = mapped_column(String(1024), default="")
    html_path: Mapped[str] = mapped_column(String(1024), default="")
    submitted_externally: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    program: Mapped["Program"] = relationship(back_populates="reports")


class ScanRun(Base):
    """Record of a pipeline run for status reporting."""

    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    state: Mapped[ScanState] = mapped_column(Enum(ScanState), default=ScanState.IDLE)
    message: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
