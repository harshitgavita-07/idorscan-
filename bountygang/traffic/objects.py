"""Object-reference mining: find values that look like direct object references.

Detects numeric ids, UUIDs, ULIDs, emails, usernames and opaque tokens in
query strings, JSON bodies and URL paths. Pure functions → unit-testable.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from bountygang.core.domain import HttpExchange, ObjectReference

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
NUMERIC_RE = re.compile(r"^\d{1,15}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$|^[0-9a-zA-Z_-]{40,128}$")

# Parameter/path-segment names strongly associated with object ownership.
IDISH_NAMES = {
    "id", "uid", "user_id", "userid", "user", "account_id", "accountid", "acct",
    "customer_id", "customerid", "order_id", "orderid", "doc_id", "docid",
    "document_id", "invoice_id", "profile_id", "org_id", "orgid", "tenant_id",
    "group_id", "project_id", "thread_id", "post_id", "file_id", "attachment_id",
    "email", "uuid", "guid", "key", "ref", "reference", "number", "token_id",
    "subscription_id", "cart_id", "ticket_id", "case_id", "record_id", "resource",
}


def classify_value(value: str) -> str:
    if UUID_RE.match(value):
        return "uuid"
    if ULID_RE.match(value):
        return "ulid"
    if NUMERIC_RE.match(value):
        return "numeric_id"
    if EMAIL_RE.match(value):
        return "email"
    if HASH_RE.match(value):
        return "hash"
    return "opaque"


def _is_idish(name: str) -> bool:
    n = name.lower().strip("_-")
    return n in IDISH_NAMES or n.endswith("_id") or n.endswith("id") and len(n) > 2 \
        or n.endswith("_uuid") or n.endswith("_guid")


def mine_query(url: str) -> list[ObjectReference]:
    q = urlparse(url).query
    refs: list[ObjectReference] = []
    for chunk in q.split("&"):
        if "=" not in chunk:
            continue
        k, _, v = chunk.partition("=")
        v = v.strip()
        if not v:
            continue
        kind = classify_value(v)
        if _is_idish(k) or kind in ("uuid", "ulid", "numeric_id"):
            refs.append(ObjectReference(location="query", name=k, value=v, kind=kind))
    return refs


def mine_path(url: str) -> list[ObjectReference]:
    path = urlparse(url).path
    segs = [s for s in path.split("/") if s]
    refs: list[ObjectReference] = []
    for i, seg in enumerate(segs):
        kind = classify_value(seg)
        if kind == "opaque":
            continue
        # a bare id-like segment; use previous segment as the name when possible
        name = segs[i - 1] if i > 0 else "path_segment"
        refs.append(ObjectReference(location="path", name=name, value=seg,
                                    kind=kind, in_path_pattern="/" + "/".join(
                                        "{%s}" % (segs[j] if classify_value(segs[j]) != "opaque" else segs[j])
                                        for j in range(len(segs)))))
    return refs


def _walk_json(obj, prefix: str = "", out: list | None = None) -> list:
    out = out if out is not None else []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                _walk_json(v, key, out)
            elif isinstance(v, (str, int)):
                sval = str(v)
                kind = classify_value(sval)
                if kind != "opaque" or _is_idish(str(k)):
                    if sval:
                        out.append((key, sval, kind))
    elif isinstance(obj, list):
        for item in obj[:50]:
            _walk_json(item, prefix + "[]", out)
    return out


def mine_body(exchange: HttpExchange) -> list[ObjectReference]:
    body = exchange.request_body or ""
    ct = (exchange.request_headers.get("content-type")
          or exchange.request_headers.get("Content-Type") or "").lower()
    refs: list[ObjectReference] = []
    if "json" in ct or body.lstrip().startswith(("{", "[")):
        try:
            data = json.loads(body)
        except ValueError:
            return refs
        for key, val, kind in _walk_json(data):
            name = key.split(".")[-1].replace("[]", "")
            if _is_idish(name) or kind in ("uuid", "ulid", "numeric_id", "email"):
                refs.append(ObjectReference(location="body", name=key, value=val, kind=kind))
    elif body:  # form-encoded
        from urllib.parse import parse_qsl
        for k, v in parse_qsl(body):
            kind = classify_value(v)
            if v and (_is_idish(k) or kind in ("uuid", "ulid", "numeric_id")):
                refs.append(ObjectReference(location="body", name=k, value=v, kind=kind))
    return refs


def mine_exchange(exchange: HttpExchange) -> list[ObjectReference]:
    """All object-reference candidates across query, path and body."""
    url = f"https://{exchange.host}{exchange.path}"
    refs = mine_query(url) + mine_path(url) + mine_body(exchange)
    # de-dup by (location,name,value)
    seen: set[tuple[str, str, str]] = set()
    out: list[ObjectReference] = []
    for r in refs:
        k = (r.location, r.name, r.value)
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out
