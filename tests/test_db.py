"""DB models + repositories round-trip tests."""
import json

from bountygang.db.models import ApprovalStatus, ScopeClassification
from bountygang.db.repositories import ProgramRepo, TargetRepo
from bountygang.db.session import session_scope


def test_program_upsert_and_list(tmp_env):
    data = {
        "platform": "hackerone", "slug": "testco", "name": "Test Co",
        "url": "https://hackerone.com/testco", "policy_text": "IDOR eligible",
        "in_scope_assets": json.dumps([{"value": "*.api.test.co", "type": "domain"}]),
        "out_of_scope_assets": "[]", "idor_eligible": True,
        "automation_allowed": None, "rate_limit_rpm": None, "raw_json": "{}",
    }
    with session_scope() as s:
        repo = ProgramRepo(s)
        p1 = repo.upsert(data)
        pid = p1.id
        p2 = repo.upsert({**data, "name": "Test Co Updated"})
        assert p1.id == p2.id  # upsert dedupes
        progs = repo.list_all()
        assert len(progs) == 1 and progs[0].name == "Test Co Updated"
    with session_scope() as s:
        assert ProgramRepo(s).get(pid).idor_eligible is True


def test_target_state_machine(tmp_env):
    with session_scope() as s:
        prog = ProgramRepo(s).upsert({
            "platform": "bugcrowd", "slug": "x", "name": "X", "url": "",
            "policy_text": "", "in_scope_assets": "[]", "out_of_scope_assets": "[]",
            "idor_eligible": True, "automation_allowed": True,
            "rate_limit_rpm": None, "raw_json": "{}"})
        trepo = TargetRepo(s)
        t = trepo.add(program_id=prog.id, asset="app.x.com",
                      classification=ScopeClassification.APPROVED)
        assert t.approval_status == ApprovalStatus.PENDING
        assert trepo.pending_approval()[0].id == t.id
        assert not trepo.scan_ready()
        trepo.set_approval(t, ApprovalStatus.APPROVED)
        assert trepo.scan_ready()[0].asset == "app.x.com"
