"""Discovery service: fans out to enabled adapters and persists programs."""
from __future__ import annotations

from bountygang.config import get_settings
from bountygang.core.domain import ProgramInfo
from bountygang.core.events import bus
from bountygang.db.models import Program
from bountygang.db.repositories import ProgramRepo
from bountygang.db.session import session_scope
from bountygang.discovery.base import PlatformAdapter
from bountygang.discovery.bugcrowd import BugcrowdAdapter
from bountygang.discovery.hackerone import HackerOneAdapter
from bountygang.discovery.platforms import IntigritiAdapter, YesWeHackAdapter
from bountygang.logging_setup import get_logger

log = get_logger("discovery.service")

ADAPTERS: dict[str, type[PlatformAdapter]] = {
    "hackerone": HackerOneAdapter,
    "bugcrowd": BugcrowdAdapter,
    "intigriti": IntigritiAdapter,
    "yeswehack": YesWeHackAdapter,
}


async def discover_programs(platforms: list[str] | None = None) -> list[ProgramInfo]:
    """Run all enabled adapters, store results, emit events. Returns new+updated."""
    settings = get_settings()
    wanted = [p.lower() for p in (platforms or settings.platforms)]
    collected: list[ProgramInfo] = []
    for name in wanted:
        adapter_cls = ADAPTERS.get(name)
        if adapter_cls is None:
            log.warning("Unknown platform adapter: %s", name)
            continue
        try:
            found = await adapter_cls().discover()
        except Exception as e:  # one bad platform must not kill discovery
            log.error("Adapter %s failed: %s", name, e)
            continue
        collected.extend(found)

    new_count = 0
    with session_scope() as s:
        repo = ProgramRepo(s)
        existing = {f"{p.platform}/{p.slug}" for p in repo.list_all()}
        for info in collected:
            repo.upsert(info.to_db_dict())
            key = f"{info.platform}/{info.slug}"
            if key not in existing:
                new_count += 1
                existing.add(key)
                bus.publish(
                    "program.discovered",
                    platform=info.platform, slug=info.slug, name=info.name,
                    url=info.url, idor_eligible=info.idor_eligible,
                    assets=len(info.in_scope_assets),
                )
    log.info("Discovery complete: %d programs fetched, %d new stored",
             len(collected), new_count)
    return collected
