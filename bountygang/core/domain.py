"""Pydantic domain models shared across packages (transport-independent DTOs)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


class Asset(BaseModel):
    value: str
    type: Literal["domain", "cidr", "url", "mobile_app", "other"] = "domain"


class ProgramInfo(BaseModel):
    """Normalized program record produced by any platform adapter."""

    platform: str
    slug: str
    name: str
    url: str = ""
    bounty_min: float | None = None
    bounty_max: float | None = None
    policy_text: str = ""
    in_scope_assets: list[Asset] = Field(default_factory=list)
    out_of_scope_assets: list[Asset] = Field(default_factory=list)
    idor_eligible: bool = False
    automation_allowed: bool | None = None
    rate_limit_rpm: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    def to_db_dict(self) -> dict[str, Any]:
        import json

        return {
            "platform": self.platform,
            "slug": self.slug,
            "name": self.name,
            "url": self.url,
            "bounty_min": self.bounty_min,
            "bounty_max": self.bounty_max,
            "policy_text": self.policy_text,
            "in_scope_assets": json.dumps([a.model_dump() for a in self.in_scope_assets]),
            "out_of_scope_assets": json.dumps([a.model_dump() for a in self.out_of_scope_assets]),
            "idor_eligible": self.idor_eligible,
            "automation_allowed": self.automation_allowed,
            "rate_limit_rpm": self.rate_limit_rpm,
            "raw_json": json.dumps(self.raw)[:200_000],
        }


class HttpExchange(BaseModel):
    """A single captured HTTP request/response pair (sanitized before persisting)."""

    host: str
    path: str
    method: str = "GET"
    query: dict[str, str] = Field(default_factory=dict)
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    status: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str = ""
    source: str = "burp"          # burp | playwright | replay
    context_label: str = "default"  # which researcher account/session made it
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ObjectReference(BaseModel):
    """An identifier-like value that may be an object reference (IDOR candidate)."""

    location: Literal["query", "path", "body", "header"]
    name: str
    value: str
    kind: Literal["numeric_id", "uuid", "ulid", "email", "username", "hash", "opaque"]
    in_path_pattern: str = ""


class EndpointCandidate(BaseModel):
    host: str
    path: str
    method: str
    params: list[str] = Field(default_factory=list)
    object_refs: list[ObjectReference] = Field(default_factory=list)
    sample_status: int | None = None


class TestAccount(BaseModel):
    """Researcher-controlled account used for cross-context validation."""

    label: str                      # e.g. "acctA"
    base_url: str
    auth_header: dict[str, str] = Field(default_factory=dict)   # never reported
    cookies: dict[str, str] = Field(default_factory=dict)       # never reported
    owned_resources: list[str] = Field(default_factory=list)    # resource ids we own
    foreign_resource_ids: list[str] = Field(default_factory=list)  # ids of OUR second account


class ValidationContext(BaseModel):
    """Two controlled accounts + their test resources for IDOR checks."""

    account_a: TestAccount
    account_b: TestAccount
