"""Scope validator: classify each in-scope asset APPROVED / REVIEW_REQUIRED / BLOCKED.

Classification rules (conservative by design):
* asset matches an explicit OUT-OF-SCOPE pattern  -> BLOCKED
* wildcard/domain/cidr match against in-scope list AND automation not forbidden
  AND program is IDOR-eligible                                  -> APPROVED
* anything ambiguous (automation unclear, no scope list, non-matching)
                                                                -> REVIEW_REQUIRED
Active testing additionally requires a *human* approval flag on the target
(see ApprovalStatus + the pipeline's approval gate).
"""
from __future__ import annotations

import ipaddress
import json
import re
from fnmatch import fnmatch

from bountygang.core.events import bus
from bountygang.db.models import Program, ScopeClassification, Target
from bountygang.db.repositories import TargetRepo
from bountygang.db.session import session_scope
from bountygang.logging_setup import get_logger
from bountygang.scope.policy import extract_rate_limit, has_testing_restrictions

log = get_logger("scope.validator")


def _asset_matches(asset: str, pattern: str) -> bool:
    """Match an observed asset against a scope pattern (wildcards, cidr, url prefix)."""
    a = asset.lower().strip()
    p = pattern.lower().strip()
    if not p:
        return False
    # CIDR
    if "/" in p:
        try:
            net = ipaddress.ip_network(p, strict=False)
            host = a.split("/")[0].split(":")[0]
            return ipaddress.ip_address(host) in net
        except ValueError:
            pass
    # strip scheme for url patterns
    p_clean = re.sub(r"^https?://", "", p).rstrip("/")
    a_clean = re.sub(r"^https?://", "", a)
    if "*" in p_clean or "?" in p_clean:
        return fnmatch(a_clean, p_clean) or fnmatch(a_clean.split("/")[0], p_clean)
    if a_clean == p_clean or a_clean.startswith(p_clean + "/"):
        return True
    # domain suffix semantics: *.example.com style entries given as example.com
    host_a = a_clean.split("/")[0]
    host_p = p_clean.split("/")[0]
    if host_a == host_p or host_a.endswith("." + host_p):
        return True
    return False


def classify_asset(program: Program, asset: str) -> tuple[ScopeClassification, str]:
    in_scope = [x.get("value", "") for x in json.loads(program.in_scope_assets or "[]")]
    out_scope = [x.get("value", "") for x in json.loads(program.out_of_scope_assets or "[]")]

    for oos in out_scope:
        if _asset_matches(asset, oos):
            return ScopeClassification.BLOCKED, f"Matches explicit out-of-scope '{oos}'"

    matched = next((p for p in in_scope if _asset_matches(asset, p)), None)
    if matched is None:
        return (ScopeClassification.REVIEW_REQUIRED,
                "Asset not found in explicit scope list — manual policy review needed")

    if program.automation_allowed is False:
        return (ScopeClassification.REVIEW_REQUIRED,
                f"In scope ('{matched}') but policy restricts automation — manual review")
    if not program.idor_eligible:
        return (ScopeClassification.REVIEW_REQUIRED,
                f"In scope ('{matched}') but IDOR/BOLA not clearly eligible per policy")
    restrictions = has_testing_restrictions(program.policy_text)
    note = ""
    if restrictions:
        note = " Note restrictions: " + "; ".join(restrictions)
    return (ScopeClassification.APPROVED,
            f"Matches in-scope pattern '{matched}'; IDOR eligible; automation OK.{note}")


def validate_program_targets(program_id: int) -> list[Target]:
    """Create/refresh Target rows for every in-scope asset of one program."""
    created: list[Target] = []
    with session_scope() as s:
        prog = s.get(Program, program_id)
        if prog is None:
            raise KeyError(f"program {program_id} not found")
        trepo = TargetRepo(s)
        assets = [x.get("value", "") for x in json.loads(prog.in_scope_assets or "[]")]
        for asset in assets:
            if not asset:
                continue
            cls, reason = classify_asset(prog, asset)
            if not trepo.exists(prog.id, asset):
                t = trepo.add(program_id=prog.id, asset=asset,
                              classification=cls, reason=reason)
                created.append(t)
                if cls == ScopeClassification.APPROVED:
                    bus.publish("scope.passed", program=prog.name, platform=prog.platform,
                                asset=asset, reason=reason)
                elif cls == ScopeClassification.BLOCKED:
                    bus.publish("scope.blocked", program=prog.name, asset=asset,
                                reason=reason)
        # refresh rate limit from policy text if missing
        if prog.rate_limit_rpm is None:
            prog.rate_limit_rpm = extract_rate_limit(prog.policy_text)
    log.info("Validated %d targets for program #%s", len(created), program_id)
    return created


def approve_target(target_id: int, approved: bool, by: str = "cli") -> Target | None:
    """Human approval gate — called from CLI or Telegram after explicit consent."""
    from bountygang.db.models import ApprovalStatus

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return None
        t.approval_status = ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
        t.reason += f" | {'APPROVED' if approved else 'DENIED'} by {by}"
        s.flush()
        bus.publish("target.approved" if approved else "target.denied",
                    target_id=t.id, asset=t.asset, by=by)
        return t
