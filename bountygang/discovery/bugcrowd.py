"""Bugcrowd discovery adapter.

Uses Bugcrowd's public JSON endpoints (no auth required):
  * https://bugcrowd.com/engagements.json?sort=promoted&page=N  (public program list)
Each engagement carries brief_description, targets (scope) and bounty ranges.
"""
from __future__ import annotations

from typing import Any

from bountygang.core.domain import Asset, ProgramInfo
from bountygang.discovery.base import fetch_json
from bountygang.logging_setup import get_logger
from bountygang.scope.policy import infer_idor_eligible, infer_automation_allowed

log = get_logger("discovery.bugcrowd")

ENGAGEMENTS_URL = "https://bugcrowd.com/engagements.json"
MAX_PAGES = 5


def parse_engagements(payload: Any) -> list[ProgramInfo]:
    out: list[ProgramInfo] = []
    if not isinstance(payload, dict):
        return out
    data = payload.get("data") or {}
    results = data.get("results") or []
    for it in results:
        if not isinstance(it, dict):
            continue
        slug = it.get("uuid") or it.get("handle") or ""
        if not slug:
            continue
        policy = it.get("brief_description") or ""
        targets_raw = it.get("targets") or []
        in_assets: list[Asset] = []
        oos_assets: list[Asset] = []
        for t in targets_raw:
            if not isinstance(t, dict):
                continue
            tgt = t.get("target") or {}
            val = tgt.get("identifier") or ""
            typ = "url" if val.startswith("http") else "domain"
            if not val:
                continue
            if tgt.get("type") == "out-of-scope":
                oos_assets.append(Asset(value=val, type="other"))
            else:
                in_assets.append(Asset(value=val, type=typ))
        rewards = (it.get("rewards") or {}).get("breakdown") or {}
        bounties = [v for v in rewards.values() if isinstance(v, (int, float))] if rewards else []
        out.append(ProgramInfo(
            platform="bugcrowd",
            slug=str(slug),
            name=it.get("name") or str(slug),
            url=it.get("url") or f"https://bugcrowd.com/{slug}",
            bounty_min=min(bounties) if bounties else None,
            bounty_max=max(bounties) if bounties else None,
            policy_text=policy,
            in_scope_assets=in_assets,
            out_of_scope_assets=oos_assets,
            idor_eligible=infer_idor_eligible(policy + " " + " ".join(a.value for a in in_assets)),
            automation_allowed=infer_automation_allowed(policy),
            raw={"visibility": it.get("visibility"), "program_type": it.get("program_type")},
        ))
    return out


class BugcrowdAdapter:
    name = "bugcrowd"

    async def discover(self) -> list[ProgramInfo]:
        programs: list[ProgramInfo] = []
        seen_slugs: set[str] = set()
        for page in range(1, MAX_PAGES + 1):
            payload = await fetch_json(ENGAGEMENTS_URL, params={"sort": "promoted", "page": page})
            batch = parse_engagements(payload)
            if not batch:
                break
            for p in batch:
                if p.slug not in seen_slugs:
                    seen_slugs.add(p.slug)
                    programs.append(p)
        log.info("Bugcrowd: discovered %d programs", len(programs))
        return programs
