"""HackerOne discovery adapter.

Uses HackerOne's public directory JSON endpoints:
  * https://hackerone.com/directory/programs  (public programs list)
  * https://api.hackerone.com/v1/hacker/bounties is authenticated — not used.
Scope/policy extraction from the directory payload + program page slug.
IDOR eligibility is inferred from policy text keywords (see scope.policy).
"""
from __future__ import annotations

from typing import Any

from bountygang.core.domain import Asset, ProgramInfo
from bountygang.discovery.base import fetch_json
from bountygang.logging_setup import get_logger
from bountygang.scope.policy import infer_idor_eligible, infer_automation_allowed

log = get_logger("discovery.hackerone")

DIRECTORY_URL = "https://hackerone.com/directory/programs"


def _bounty_range(item: dict[str, Any]) -> tuple[float | None, float | None]:
    br = item.get("bounty_range") or {}
    if isinstance(br, list) and len(br) == 2:
        return float(br[0]), float(br[1])
    if isinstance(br, dict):
        return br.get("minimum"), br.get("maximum")
    return None, None


def parse_directory(payload: Any) -> list[ProgramInfo]:
    """Parse the public directory JSON into normalized ProgramInfo records."""
    items: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        # payloads differ over time: {"data": [...]} / {"programs": [...]} / list at root
        for key in ("data", "programs", "results"):
            if isinstance(payload.get(key), list):
                items = payload[key]
                break
    elif isinstance(payload, list):
        items = payload

    out: list[ProgramInfo] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        handle = it.get("handle") or it.get("slug") or ""
        if not handle:
            continue
        name = it.get("name") or handle
        policy = it.get("short_description") or it.get("policy") or ""
        scopes_raw = it.get("scopes") or it.get("in_scope_scopes") or []
        in_assets: list[Asset] = []
        for sc in scopes_raw:
            val = sc.get("asset") if isinstance(sc, dict) else str(sc)
            typ = sc.get("asset_type", "domain") if isinstance(sc, dict) else "domain"
            if val:
                in_assets.append(Asset(value=val, type=_map_asset_type(typ)))
        oos_raw = it.get("out_of_scope_scopes") or []
        out_assets = [Asset(value=str(s), type="other") for s in oos_raw if s]
        lo, hi = _bounty_range(it)
        out.append(ProgramInfo(
            platform="hackerone",
            slug=handle,
            name=name,
            url=f"https://hackerone.com/{handle}",
            bounty_min=lo,
            bounty_max=hi,
            policy_text=policy,
            in_scope_assets=in_assets,
            out_of_scope_assets=out_assets,
            idor_eligible=infer_idor_eligible(policy + " " + " ".join(a.value for a in in_assets)),
            automation_allowed=infer_automation_allowed(policy),
            raw={k: it[k] for k in list(it)[:40]},
        ))
    return out


def _map_asset_type(t: str) -> str:
    t = (t or "").lower()
    if "url" in t:
        return "url"
    if "cidr" in t or "range" in t:
        return "cidr"
    if "mobile" in t or "app" in t and "web" not in t:
        return "mobile_app"
    if t in ("domain", "wildcard", "root domain", "subdomain"):
        return "domain"
    return "other"


class HackerOneAdapter:
    name = "hackerone"

    async def discover(self) -> list[ProgramInfo]:
        payload = await fetch_json(DIRECTORY_URL)
        if payload is None:
            log.info("HackerOne directory unavailable (offline mode?) — skipping live fetch")
            return []
        programs = parse_directory(payload)
        log.info("HackerOne: discovered %d programs", len(programs))
        return programs
