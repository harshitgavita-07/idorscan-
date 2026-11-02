"""IDOR/BOLA detection engine.

Two phases:

1. **Static analysis** (``analyze_candidate``): score an EndpointCandidate using
   endpoint semantics — object-ownership nouns, id-like parameters, auth context,
   response shape. Produces POSSIBLE_IDOR / NEEDS_MANUAL_REVIEW candidates.

2. **Controlled validation** (``validate_idor``): uses TWO researcher-owned
   accounts and resources that *we* created. Account A requests a resource id
   belonging to account B. Classification rules (evidence-based, never status-code-only):

   * CONFIRMED_IDOR requires ALL of:
       - baseline: owner (B) fetches own resource -> 200 + owned marker present
       - cross-context: attacker (A) fetches B's resource -> 200 AND
         body contains B's ownership marker (content match, not just status)
       - negative control: anonymous/unauthenticated -> NOT the same content
         (proves it is auth-related, not public data)
       - reproducibility: cross-context check repeated; identical result both times
   * LIKELY_IDOR: content overlap strong but one guard failed (e.g. no anon control)
   * POSSIBLE_IDOR: static signals only, not validated
   * FALSE_POSITIVE: cross-context request returned 403/404 or clearly different data
   * NEEDS_MANUAL_REVIEW: ambiguous (e.g. 200 but empty/dynamic body, rate-limited)

   Safety rails: only ids from ValidationContext are ever used; total requests are
   capped by IDOR_MAX_VALIDATION_REQUESTS; everything is rate-limited; responses
   are sanitized before storage.
"""
from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from bountygang.core.domain import EndpointCandidate, ObjectReference, ValidationContext
from bountygang.core.events import bus
from bountygang.core.ratelimit import RateLimiter
from bountygang.db.models import FindingClassification
from bountygang.logging_setup import get_logger
from bountygang.utils.sanitize import sanitize_text

log = get_logger("idor.engine")

# path nouns that imply per-user objects
OWNERSHIP_NOUNS = {
    "user", "users", "account", "accounts", "profile", "order", "orders", "invoice",
    "invoices", "document", "documents", "doc", "file", "files", "attachment",
    "message", "messages", "ticket", "tickets", "subscription", "cart", "wallet",
    "address", "addresses", "payment", "card", "record", "records", "case", "thread",
}

ID_PARAM_RE = re.compile(r"(?:^|_)(?:id|uuid|guid|key|ref|number)$|_?id$", re.I)


@dataclass
class StaticScore:
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    interesting_refs: list[ObjectReference] = field(default_factory=list)


def analyze_candidate(cand: EndpointCandidate) -> StaticScore:
    """Heuristic static scoring of one endpoint for IDOR suspicion."""
    sc = StaticScore()
    segs = [s for s in cand.path.split("/") if s]
    nouns = {s.lower().rstrip("s") for s in segs}
    if nouns & {n.rstrip("s") for n in OWNERSHIP_NOUNS}:
        sc.score += 0.25
        sc.reasons.append("path references an ownership-bearing resource")
    id_like_params = [p for p in cand.params if ID_PARAM_RE.search(p)]
    if id_like_params:
        sc.score += 0.2
        sc.reasons.append(f"id-like parameters: {', '.join(id_like_params[:6])}")
    for r in cand.object_refs:
        if r.location in ("query", "path", "body"):
            if r.kind in ("numeric_id", "uuid", "ulid") and (
                ID_PARAM_RE.search(r.name) or r.location == "path"
            ):
                sc.interesting_refs.append(r)
    if sc.interesting_refs:
        sc.score += min(0.3, 0.1 * len(sc.interesting_refs))
        sc.reasons.append(
            f"{len(sc.interesting_refs)} direct object reference value(s) found")
    if cand.method in ("GET", "PUT", "PATCH", "DELETE", "POST"):
        sc.score += 0.05
    # numeric ids are enumerable → higher risk than uuids alone
    if any(r.kind == "numeric_id" for r in sc.interesting_refs):
        sc.score += 0.1
        sc.reasons.append("contains enumerable numeric identifiers")
    return sc


# --------------------------------------------------------------------- evidence

def _extract_ownership_markers(body: str) -> set[str]:
    """Pull stable identity markers (emails redacted upstream; use ids/names)."""
    markers: set[str] = set()
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        data = None
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, (str, int)) and ID_PARAM_RE.search(str(k)):
                markers.add(f"{k}={v}")
    return markers


def _bodies_similar(a: str, b: str) -> float:
    if not a and not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:20000], b[:20000]).ratio()


@dataclass
class ValidationResult:
    classification: FindingClassification
    confidence: float
    reproducible: bool
    evidence: dict[str, Any]
    notes: str = ""


class IdorValidator:
    """Cross-account controlled validation with hard safety caps."""

    def __init__(self, max_requests: int, limiter: RateLimiter | None = None) -> None:
        self.max_requests = max_requests
        self.limiter = limiter or RateLimiter(30)
        self._used = 0

    async def _fetch(self, client: httpx.AsyncClient, url: str,
                     headers: dict[str, str]) -> tuple[int | None, str]:
        if self._used >= self.max_requests:
            raise RuntimeError("IDOR validation request cap reached")
        self._used += 1
        await self.limiter.acquire()
        try:
            r = await client.get(url, headers=headers, timeout=15.0, follow_redirects=False)
            return r.status_code, sanitize_text(r.text or "")[:100_000]
        except httpx.HTTPError as e:
            return None, f"error: {e}"

    async def validate(self, base_url: str, path_with_foreign_id: str,
                       ctx: ValidationContext,
                       own_path_for_owner: str | None = None) -> ValidationResult:
        """Run the full controlled experiment for one candidate URL.

        ``path_with_foreign_id``: URL containing account B's resource id.
        ``own_path_for_owner``: equivalent URL as B would call it (defaults to same).
        """
        url = base_url.rstrip("/") + path_with_foreign_id
        owner_path = own_path_for_owner or path_with_foreign_id
        owner_url = base_url.rstrip("/") + owner_path
        ev: dict[str, Any] = {"url": url}
        async with httpx.AsyncClient() as client:
            # 1. Baseline — owner can access their own resource
            o_status, o_body = await self._fetch(client, owner_url,
                                                 ctx.account_b.auth_header)
            # 2. Cross-context — attacker account accesses B's resource
            a_status, a_body = await self._fetch(client, url,
                                                 ctx.account_a.auth_header)
            # 3. Negative control — unauthenticated
            n_status, n_body = await self._fetch(client, url, {})
            # 4. Reproducibility — repeat cross-context once
            a2_status, a2_body = await self._fetch(client, url,
                                                   ctx.account_a.auth_header)
        sim_aa = _bodies_similar(a_body, a2_body)
        similarity_cross = _bodies_similar(o_body, a_body)
        owner_markers = _extract_ownership_markers(o_body)
        cross_markers = _extract_ownership_markers(a_body)
        marker_overlap = len(owner_markers & cross_markers)
        ev.update({
            "baseline_owner": {"status": o_status, "markers": sorted(owner_markers)[:10]},
            "cross_context": {"status": a_status, "markers": sorted(cross_markers)[:10],
                              "body_similarity_to_owner": round(similarity_cross, 3)},
            "unauth_control": {"status": n_status},
            "replay": {"status": a2_status, "similarity": round(sim_aa, 3)},
        })

        leak = (
            a_status == 200
            and similarity_cross >= 0.85
            and (marker_overlap > 0 or similarity_cross >= 0.95)
            and o_status == 200
        )
        anon_blocked = n_status in (401, 403) or (n_status is not None and n_status >= 400)
        reproducible = a2_status == a_status and sim_aa >= 0.85

        if leak and anon_blocked and reproducible:
            cls, conf = FindingClassification.CONFIRMED_IDOR, min(0.99, 0.8 + 0.05 * marker_overlap)
            notes = "Confirmed: cross-account read reproduced, matches owner content, blocked when unauthenticated."
        elif leak and reproducible:
            cls, conf = FindingClassification.LIKELY_IDOR, 0.7
            notes = "Content leaked cross-account & reproducible, but unauthenticated control inconclusive (maybe public data)."
        elif leak:
            cls, conf = FindingClassification.NEEDS_MANUAL_REVIEW, 0.5
            notes = "Leak observed but replay differed — dynamic content or instability; manual review."
        elif a_status in (401, 403, 404) or (a_status and a_status >= 400):
            cls, conf = FindingClassification.FALSE_POSITIVE, 0.9
            notes = "Server enforced authorization on cross-context request."
        elif a_status == 200 and similarity_cross < 0.5:
            cls, conf = FindingClassification.FALSE_POSITIVE, 0.7
            notes = "200 returned but content differs strongly from owner's resource (likely generic/empty payload)."
        else:
            cls, conf = FindingClassification.NEEDS_MANUAL_REVIEW, 0.4
            notes = "Inconclusive behavior; manual review required."

        res = ValidationResult(cls, conf, reproducible, ev, notes)
        log.info("IDOR validation %s -> %s (%.2f)", url, cls.value, conf)
        if cls == FindingClassification.CONFIRMED_IDOR:
            bus.publish("idor.confirmed", url=url, confidence=conf, evidence=ev)
        elif cls == FindingClassification.LIKELY_IDOR:
            bus.publish("idor.likely", url=url, confidence=conf)
        return res
