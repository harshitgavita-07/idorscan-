"""Policy text intelligence: extract safety-relevant signals from program policies.

Pure functions — fully unit-testable without network. The heuristics are
deliberately conservative: when in doubt we downgrade to REVIEW_REQUIRED and
let the human decide.
"""
from __future__ import annotations

import re

# Keywords that suggest IDOR/BOLA is a *rewarded* vulnerability class here.
_IDOR_POSITIVE = [
    "idor", "insecure direct object reference", "bola", "broken object level",
    "business logic bypass", "access control", "authorization", "privilege escalation",
    "cross-tenant", "tenant isolation",
]
_IDOR_NEGATIVE = [
    "no idor", "idor will not be rewarded", "not eligible: idor",
    "without actual impact on other users", "self-xss",
]

_AUTOMATION_ALLOWED = [
    "automation allowed", "you may use automated tools", "automated scanning is allowed",
    "security scanners are permitted", "burp suite community is allowed",
    "you can use tools like burp",
]
_AUTOMATION_DENIED = [
    "no automated", "automated tools are not allowed", "do not use automated",
    "scanner", "brute force", "denial of service", "ddos", "high volume",
    "no bots", "automated scanning is prohibited",
]

_RATE_LIMIT_RE = re.compile(
    r"(?:max(?:imum)?|limit(?:ed)?)\s*(?:to)?\s*(\d{1,4})\s*(?:requests|reqs?|hits?|queries|rpm)"
    r"|(?:per|\/)\s*minute", re.I)
_NUM_PER_MIN = re.compile(r"(\d{1,4})\s*(?:requests|reqs|hits|queries)\s*(?:per|/|a)\s*min", re.I)

_TESTING_RESTRICTIONS = [
    "only test with your own accounts", "use demo accounts", "test accounts only",
    "do not access other users", "privacy violation", "must not view real user data",
    "social engineering is not allowed",
]


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower())


def infer_idor_eligible(policy_text: str) -> bool:
    t = _norm(policy_text)
    if any(n in t for n in _IDOR_NEGATIVE):
        return False
    return any(p in t for p in _IDOR_POSITIVE)


def infer_automation_allowed(policy_text: str) -> bool | None:
    """True=explicitly allowed, False=explicitly restricted, None=unclear."""
    t = _norm(policy_text)
    if any(a in t for a in _AUTOMATION_ALLOWED):
        return True
    if any(d in t for d in _AUTOMATION_DENIED):
        return False
    return None


def extract_rate_limit(policy_text: str) -> int | None:
    t = policy_text or ""
    m = _NUM_PER_MIN.search(t)
    if m:
        try:
            return max(1, int(m.group(1)))
        except ValueError:
            pass
    m = _RATE_LIMIT_RE.search(t)
    if m and m.group(1):
        try:
            return max(1, int(m.group(1)))
        except ValueError:
            pass
    return None


def has_testing_restrictions(policy_text: str) -> list[str]:
    t = _norm(policy_text)
    return [r for r in _TESTING_RESTRICTIONS if r in t]


def mentions_out_of_scope_method(policy_text: str, method: str) -> bool:
    """Crude check whether e.g. 'brute force' / 'dos' is explicitly forbidden."""
    t = _norm(policy_text)
    return f"no {method.lower()}" in t or f"{method.lower()} is not allowed" in t \
        or f"do not {method.lower()}" in t
