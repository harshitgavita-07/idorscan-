"""Pipeline orchestrator: the end-to-end BountyGang workflow.

Discover → Validate scope → (human approval gate) → Launch Burp → Launch Chromium
→ Capture traffic → Analyze endpoints/object refs → Controlled IDOR validation
→ AI analysis (best-effort) → Reports → Telegram notifications via events.

The orchestrator is asyncio-based, keeps a ScanRun row for /status, and can be
stopped safely with request_stop() (checked between stages and between requests).
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from bountygang.ai.providers import build_endpoint_prompt, make_provider
from bountygang.automation.burp import BurpAutomation
from bountygang.automation.chromium import ChromiumAutomation
from bountygang.config import get_settings
from bountygang.core.domain import EndpointCandidate, ValidationContext
from bountygang.core.events import bus
from bountygang.core.ratelimit import RateLimiter
from bountygang.db.models import (
    FindingClassification,
    Program,
    ScanState,
    ScopeClassification,
)
from bountygang.db.repositories import (
    EndpointRepo,
    FindingRepo,
    ProgramRepo,
    ScanRunRepo,
    TargetRepo,
)
from bountygang.db.session import session_scope
from bountygang.discovery.service import discover_programs
from bountygang.idor.engine import IdorValidator, analyze_candidate
from bountygang.logging_setup import get_logger
from bountygang.reporting.generator import generate_report
from bountygang.scope.validator import validate_program_targets
from bountygang.traffic.collector import TrafficCollector

log = get_logger("core.pipeline")


class Pipeline:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.burp = BurpAutomation()
        self.browser = ChromiumAutomation()
        self.collector = TrafficCollector(self.burp)
        self.limiter = RateLimiter(self.settings.max_requests_per_minute)
        self._stop = asyncio.Event()
        self.state = ScanState.IDLE
        self.current_run_id: int | None = None

    # ------------------------------------------------------------------ status
    def _set_state(self, run, state: ScanState, msg: str = "") -> None:
        self.state = state
        with session_scope() as s:
            ScanRunRepo(s).update(run, state, msg or state.value)

    def request_stop(self) -> None:
        """Safe stop: finishes current step then unwinds."""
        log.info("Stop requested")
        self._stop.set()

    def _check_stop(self) -> None:
        if self._stop.is_set():
            raise _Stopped()

    # ------------------------------------------------------------- discovery
    async def stage_discover(self, run) -> list[Program]:
        self._set_state(run, ScanState.DISCOVERING, "discovering programs")
        await discover_programs()
        self._check_stop()
        with session_scope() as s:
            return ProgramRepo(s).list_all()

    # ----------------------------------------------------------------- scope
    async def stage_validate_scope(self, run, program_ids: list[int]) -> None:
        self._set_state(run, ScanState.VALIDATING_SCOPE, "validating scope")
        for pid in program_ids:
            self._check_stop()
            validate_program_targets(pid)
        self._check_stop()

    # -------------------------------------------------------------- approval
    async def stage_approval(self, run) -> list[Any]:
        """Gate: only APPROVED+human-approved targets proceed. Otherwise emit
        an AWAITING_APPROVAL event (Telegram pings the user) and return []."""
        with session_scope() as s:
            ready = TargetRepo(s).scan_ready()
            pending = TargetRepo(s).pending_approval()
        if not ready:
            self._set_state(run, ScanState.AWAITING_APPROVAL,
                            f"{len(pending)} target(s) awaiting human approval")
            bus.publish("approval.requested", pending=[
                {"id": t.id, "asset": t.asset} for t in pending[:20]])
            return []
        return ready

    # ------------------------------------------------------------ automation
    async def stage_launch_stack(self, run) -> bool:
        self._set_state(run, ScanState.LAUNCHING_BROWSER, "launching burp + chromium")
        burp_up = await self.burp.launch(headless_check_timeout=30)
        proxy_ok = await self.browser.verify_proxy_interception()
        if not (burp_up or proxy_ok):
            log.warning("Neither Burp API nor proxy reachable — capture will use "
                        "Playwright's own request listener only")
        try:
            await self.browser.launch()
            return True
        except Exception as e:
            log.error("Chromium launch failed: %s", e)
            bus.publish("browser.launch_failed", error=str(e))
            return False

    # ------------------------------------------------------------- capturing
    async def stage_capture(self, run, targets: list[Any]) -> list[EndpointCandidate]:
        self._set_state(run, ScanState.CAPTURING, "capturing authorized traffic")
        allowed = [t.asset for t in targets]
        # 1) Burp history first (if available)
        exchanges = await self.collector.collect(allowed)
        # 2) browse each approved target through the proxy; collect via playwright
        for t in targets:
            self._check_stop()
            url = t.asset if t.asset.startswith("http") else f"https://{t.asset}"
            try:
                reqs = await self.browser.collect_requests(url, seconds=3)
                ex2 = self.collector.ingest_playwright_requests(reqs, allowed)
                exchanges.extend(ex2)
            except Exception as e:
                log.warning("Browsing %s failed: %s", url, e)
        self._set_state(run, ScanState.ANALYZING, "analyzing endpoints")
        with session_scope() as s:
            eps = EndpointRepo(s).list_all()
        candidates: list[EndpointCandidate] = []
        for ep in eps:
            from bountygang.core.domain import ObjectReference
            candidates.append(EndpointCandidate(
                host=ep.host, path=ep.path, method=ep.method,
                params=json.loads(ep.params or "[]"),
                object_refs=[ObjectReference(**r) for r in json.loads(ep.object_refs or "[]")],
            ))
        return candidates

    # -------------------------------------------------------------- idor pass
    async def stage_idor(self, run, candidates: list[EndpointCandidate],
                         ctx: ValidationContext | None) -> list[int]:
        self._set_state(run, ScanState.VALIDATING_IDOR, "IDOR detection & validation")
        finding_ids: list[int] = []
        provider = make_provider(self.settings)
        for cand in candidates:
            self._check_stop()
            score = analyze_candidate(cand)
            if score.score < 0.45:
                continue
            classification = FindingClassification.POSSIBLE_IDOR
            confidence = min(0.6, score.score)
            reproducible = False
            evidence: dict[str, Any] = {"static_reasons": score.reasons,
                                        "object_refs": [r.model_dump()
                                                        for r in score.interesting_refs[:8]]}
            # controlled validation ONLY when we have researcher accounts configured
            if ctx and score.interesting_refs:
                validator = IdorValidator(self.settings.idor_max_validation_requests,
                                          limiter=self.limiter)
                ref = score.interesting_refs[0]
                foreign_id = ref.value
                for fid in ctx.account_b.foreign_resource_ids:
                    probe_path = cand.path.replace(foreign_id, fid) if foreign_id else cand.path
                    try:
                        res = await validator.validate(
                            f"https://{cand.host}", probe_path, ctx)
                        classification = res.classification
                        confidence = res.confidence
                        reproducible = res.reproducible
                        evidence["validation"] = res.evidence
                        evidence["notes"] = res.notes
                        break
                    except RuntimeError as e:  # request cap
                        log.info("Validation stopped early: %s", e)
                        break
            # AI assist (best effort, never authoritative)
            ai_text = ""
            if provider.name != "none":
                ai_text = await provider.complete(build_endpoint_prompt(
                    cand.host, cand.path, cand.method, evidence)) or ""
            sev = _severity_for(classification, cand)
            with session_scope() as s:
                f = FindingRepo(s).add(
                    program_id=None, endpoint_id=None,
                    title=f"{classification.value}: {cand.method} https://{cand.host}{cand.path}",
                    vulnerability_type="BOLA/IDOR",
                    endpoint=f"{cand.host}{cand.path}", method=cand.method,
                    parameter=",".join(r.name for r in score.interesting_refs[:3]),
                    severity=sev, confidence=confidence,
                    classification=classification,
                    validation_status=classification.value,
                    evidence=json.dumps(evidence), description=_describe(cand, score),
                    ai_analysis=ai_text, reproducible=reproducible,
                )
                finding_ids.append(f.id)
            if classification in (FindingClassification.CONFIRMED_IDOR,
                                  FindingClassification.LIKELY_IDOR):
                bus.publish("idor.potential" if classification ==
                            FindingClassification.LIKELY_IDOR else "idor.confirmed",
                            endpoint=f"{cand.method} https://{cand.host}{cand.path}",
                            classification=classification.value, confidence=confidence)
        return finding_ids

    # --------------------------------------------------------------- reports
    async def stage_report(self, run, finding_ids: list[int]) -> list[dict]:
        self._set_state(run, ScanState.REPORTING, "generating reports")
        out = []
        for fid in finding_ids:
            self._check_stop()
            rep = generate_report(fid)
            if rep:
                out.append(rep)
        return out

    # ------------------------------------------------------------------- main
    async def run(self, program_ids: list[int] | None = None,
                  ctx: ValidationContext | None = None,
                  skip_browser: bool = False) -> dict[str, Any]:
        """Full pipeline. Returns summary dict. Safe to call repeatedly."""
        self._stop.clear()
        with session_scope() as s:
            run = ScanRunRepo(s).start("pipeline run")
        summary: dict[str, Any] = {"run_id": run.id, "reports": [], "findings": []}
        try:
            programs = await self.stage_discover(run)
            wanted = [p.id for p in programs if p.id in program_ids] if program_ids \
                else [p.id for p in programs if p.idor_eligible][:5]
            await self.stage_validate_scope(run, wanted)
            targets = await self.stage_approval(run)
            if not targets:
                summary["result"] = "AWAITING_APPROVAL"
                self._finish(run, ScanState.DONE, "awaiting human approval")
                return summary
            if not skip_browser:
                browser_ok = await self.stage_launch_stack(run)
            else:
                browser_ok = False
            candidates = await self.stage_capture(run, targets)
            fids = await self.stage_idor(run, candidates, ctx)
            reps = await self.stage_report(run, fids)
            summary.update({"endpoints": len(candidates), "findings": fids,
                            "reports": reps})
            self._finish(run, ScanState.DONE, "completed")
            bus.publish("scan.finished", **{k: v for k, v in summary.items()
                                            if k != "reports"},
                        reports=len(reps))
        except _Stopped:
            self._finish(run, ScanState.STOPPED, "stopped by user")
            bus.publish("scan.stopped", run_id=run.id)
            summary["result"] = "STOPPED"
        except Exception as e:
            log.exception("pipeline failed")
            self._finish(run, ScanState.FAILED, str(e)[:500])
            bus.publish("scan.failed", error=str(e)[:300])
            summary["result"] = "FAILED"
            summary["error"] = str(e)[:300]
        finally:
            await self.browser.close()
            await self.burp.shutdown()
        return summary

    def _finish(self, run, state: ScanState, msg: str) -> None:
        self.state = state
        with session_scope() as s:
            ScanRunRepo(s).finish(run, state, msg)


class _Stopped(Exception):
    pass


def _severity_for(cls: FindingClassification, cand: EndpointCandidate) -> str:
    has_write = cand.method in ("PUT", "PATCH", "DELETE", "POST")
    if cls == FindingClassification.CONFIRMED_IDOR:
        return "HIGH" if has_write else "MEDIUM"
    if cls == FindingClassification.LIKELY_IDOR:
        return "MEDIUM"
    if cls == FindingClassification.POSSIBLE_IDOR:
        return "LOW"
    return "UNKNOWN"


def _describe(cand: EndpointCandidate, score) -> str:
    return (f"The endpoint {cand.method} https://{cand.host}{cand.path} accepts direct "
            f"object references ({', '.join(score.reasons)}). Missing object-level "
            f"authorization checks could allow one authenticated account to access "
            f"another account's objects. Status: candidate pending/requiring controlled "
            f"cross-account validation.")
