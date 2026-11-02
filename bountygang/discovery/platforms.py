"""Intigriti & YesWeHack discovery adapters.

Both platforms expose public program-listing JSON used by their own frontends:
  * Intigriti: https://api.intigriti.com/core/rewardAndHallOfFame/programs?limit=&offset=
    (public scope details at https://intigriti.com/programs/<slug>)
  * YesWeHack: https://yeswehack.com/api/programs (public programs directory)

Parsing is defensive: unknown shapes yield zero programs instead of crashing,
and offline mode returns [] cleanly.
"""
from __future__ import annotations

from typing import Any

from bountygang.core.domain import Asset, ProgramInfo
from bountygang.discovery.base import fetch_json
from bountygang.logging_setup import get_logger
from bountygang.scope.policy import infer_idor_eligible, infer_automation_allowed

log = get_logger("discovery.other_platforms")


def _assets_from_scope(scope_items: Any) -> tuple[list[Asset], list[Asset]]:
    in_assets: list[Asset] = []
    oos_assets: list[Asset] = []
    if not isinstance(scope_items, list):
        return in_assets, oos_assets
    for s in scope_items:
        if not isinstance(s, dict):
            continue
        val = s.get("target") or s.get("endpoint") or s.get("uri") or s.get("asset") or ""
        if not val:
            continue
        kind = "url" if str(val).startswith("http") else "domain"
        oos_flag = bool(s.get("out_of_scope")) or s.get("type") == "out-of-scope" \
            or str(s.get("scopeType", "")).upper() == "OUT"
        (oos_assets if oos_flag else in_assets).append(Asset(value=str(val), type=kind))
    return in_assets, oos_assets


class IntigritiAdapter:
    name = "intigriti"

    async def discover(self) -> list[ProgramInfo]:
        url = "https://api.intigriti.com/core/rewardAndHallOfFame/programs"
        payload = await fetch_json(url, params={"limit": 100, "offset": 0})
        out: list[ProgramInfo] = []
        items: list[Any] = []
        if isinstance(payload, dict):
            items = payload.get("items") or payload.get("programs") or payload.get("data") or []
        elif isinstance(payload, list):
            items = payload
        for it in items:
            if not isinstance(it, dict):
                continue
            slug = it.get("internalId") or it.get("slug") or it.get("id") or ""
            name = it.get("name") or str(slug)
            if not slug:
                continue
            policy = it.get("description") or it.get("briefDescription") or ""
            in_a, oos_a = _assets_from_scope(it.get("scope") or [])
            max_b = it.get("maximumBounty") or it.get("maxBounty")
            out.append(ProgramInfo(
                platform="intigriti",
                slug=str(slug),
                name=name,
                url=f"https://intigriti.com/programs/{slug}",
                bounty_max=float(max_b) if isinstance(max_b, (int, float)) else None,
                policy_text=policy,
                in_scope_assets=in_a,
                out_of_scope_assets=oos_a,
                idor_eligible=infer_idor_eligible(policy + " " + " ".join(a.value for a in in_a)),
                automation_allowed=infer_automation_allowed(policy),
                raw={"hackathon": it.get("hackathon"), "status": it.get("status")},
            ))
        log.info("Intigriti: discovered %d programs", len(out))
        return out


class YesWeHackAdapter:
    name = "yeswehack"

    async def discover(self) -> list[ProgramInfo]:
        payload = await fetch_json("https://yeswehack.com/api/programs",
                                   params={"page": 1, "per_page": 100})
        out: list[ProgramInfo] = []
        items: list[Any] = []
        if isinstance(payload, dict):
            items = payload.get("programs") or payload.get("data") or payload.get("results") or []
        elif isinstance(payload, list):
            items = payload
        for it in items:
            if not isinstance(it, dict):
                continue
            slug = it.get("slug") or it.get("id") or ""
            name = it.get("name") or str(slug)
            if not slug:
                continue
            policy = it.get("description") or it.get("policy") or ""
            in_a, oos_a = _assets_from_scope(it.get("scopes") or it.get("scope") or [])
            bmin = it.get("bounty_min") or it.get("minimumAward")
            bmax = it.get("bounty_max") or it.get("maximumAward")
            out.append(ProgramInfo(
                platform="yeswehack",
                slug=str(slug),
                name=name,
                url=f"https://yeswehack.com/programs/{slug}",
                bounty_min=float(bmin) if isinstance(bmin, (int, float)) else None,
                bounty_max=float(bmax) if isinstance(bmax, (int, float)) else None,
                policy_text=policy,
                in_scope_assets=in_a,
                out_of_scope_assets=oos_a,
                idor_eligible=infer_idor_eligible(policy + " " + " ".join(a.value for a in in_a)),
                automation_allowed=infer_automation_allowed(policy),
                raw={"platform": it.get("platform")},
            ))
        log.info("YesWeHack: discovered %d programs", len(out))
        return out
