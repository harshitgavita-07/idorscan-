"""Repositories: thin data-access layer over SQLAlchemy models."""
from __future__ import annotations

import json
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from bountygang.db.models import (
    ApprovalStatus,
    Endpoint,
    Finding,
    Program,
    Report,
    ScanRun,
    ScanState,
    ScopeClassification,
    Target,
)


class ProgramRepo:
    def __init__(self, session: Session):
        self.s = session

    def upsert(self, data: dict[str, Any]) -> Program:
        prog = self.s.scalar(
            select(Program).where(
                Program.platform == data["platform"], Program.slug == data["slug"]
            )
        )
        if prog is None:
            prog = Program(**data)
            self.s.add(prog)
        else:
            for k, v in data.items():
                setattr(prog, k, v)
        self.s.flush()
        return prog

    def list_all(self) -> list[Program]:
        return list(self.s.scalars(select(Program).order_by(Program.platform, Program.slug)))

    def get(self, program_id: int) -> Program | None:
        return self.s.get(Program, program_id)


class TargetRepo:
    def __init__(self, session: Session):
        self.s = session

    def add(self, **data: Any) -> Target:
        t = Target(**data)
        self.s.add(t)
        self.s.flush()
        return t

    def exists(self, program_id: int, asset: str) -> bool:
        return (
            self.s.scalar(
                select(Target.id).where(
                    Target.program_id == program_id, Target.asset == asset
                )
            )
            is not None
        )

    def set_classification(self, target: Target, cls: ScopeClassification, reason: str) -> Target:
        target.classification = cls
        target.reason = reason
        self.s.flush()
        return target

    def set_approval(self, target: Target, status: ApprovalStatus) -> Target:
        target.approval_status = status
        self.s.flush()
        return target

    def scan_ready(self) -> list[Target]:
        """Targets that may be actively tested: APPROVED + APPROVED-by-human."""
        return list(
            self.s.scalars(
                select(Target).where(
                    Target.classification == ScopeClassification.APPROVED,
                    Target.approval_status == ApprovalStatus.APPROVED,
                )
            )
        )

    def pending_approval(self) -> list[Target]:
        return list(
            self.s.scalars(
                select(Target).where(
                    Target.classification == ScopeClassification.APPROVED,
                    Target.approval_status == ApprovalStatus.PENDING,
                )
            )
        )

    def list_all(self) -> list[Target]:
        return list(self.s.scalars(select(Target).order_by(Target.id)))


class EndpointRepo:
    def __init__(self, session: Session):
        self.s = session

    def record(self, host: str, path: str, method: str, params: list[str],
               object_refs: list[dict], target_id: int | None = None) -> Endpoint:
        ep = self.s.scalar(
            select(Endpoint).where(
                Endpoint.host == host, Endpoint.path == path, Endpoint.method == method.upper()
            )
        )
        if ep is None:
            ep = Endpoint(
                host=host, path=path, method=method.upper(), target_id=target_id,
                params=json.dumps(params), object_refs=json.dumps(object_refs),
            )
            self.s.add(ep)
        else:
            from bountygang.db.models import utcnow
            ep.last_seen = utcnow()
            ep.hit_count += 1
        self.s.flush()
        return ep

    def list_all(self) -> list[Endpoint]:
        return list(self.s.scalars(select(Endpoint).order_by(Endpoint.id)))


class FindingRepo:
    def __init__(self, session: Session):
        self.s = session

    def add(self, **data: Any) -> Finding:
        f = Finding(**data)
        self.s.add(f)
        self.s.flush()
        return f

    def list_all(self) -> list[Finding]:
        return list(self.s.scalars(select(Finding).order_by(Finding.id.desc())))

    def get(self, finding_id: int) -> Finding | None:
        return self.s.get(Finding, finding_id)


class ReportRepo:
    def __init__(self, session: Session):
        self.s = session

    def add(self, **data: Any) -> Report:
        r = Report(**data)
        self.s.add(r)
        self.s.flush()
        return r

    def list_all(self) -> list[Report]:
        return list(self.s.scalars(select(Report).order_by(Report.id.desc())))


class ScanRunRepo:
    def __init__(self, session: Session):
        self.s = session

    def start(self, message: str = "") -> ScanRun:
        run = ScanRun(state=ScanState.IDLE, message=message)
        self.s.add(run)
        self.s.flush()
        return run

    def update(self, run: ScanRun, state: ScanState, message: str | None = None) -> ScanRun:
        run.state = state
        if message is not None:
            run.message = message
        self.s.flush()
        return run

    def finish(self, run: ScanRun, state: ScanState, message: str = "") -> ScanRun:
        from bountygang.db.models import utcnow
        run.state = state
        run.message = message
        run.finished_at = utcnow()
        self.s.flush()
        return run

    def latest(self) -> ScanRun | None:
        return self.s.scalar(select(ScanRun).order_by(ScanRun.id.desc()))
