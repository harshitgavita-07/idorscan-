"""HackerOne-style report generator: Markdown, JSON and HTML. Never submits anywhere."""
from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from bountygang.config import get_settings
from bountygang.core.events import bus
from bountygang.db.models import Finding, Program
from bountygang.db.repositories import ReportRepo
from bountygang.db.session import session_scope
from bountygang.logging_setup import get_logger
from bountygang.utils.ids import report_id as new_report_id
from bountygang.utils.sanitize import sanitize_text

log = get_logger("reporting")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def _fmt_http(exchange: dict[str, Any]) -> str:
    req = exchange.get("request", "")
    resp = exchange.get("response", "")
    return f"Request:\n```\n{sanitize_text(req)}\n```\n\nResponse:\n```\n{sanitize_text(resp)}\n```"


def build_markdown(fields: dict[str, Any]) -> str:
    ev = fields.get("evidence", {})
    lines = [
        f"# {fields['title']}",
        "",
        f"**Report ID:** `{fields['report_id']}`  ",
        f"**Program:** {fields['program_name']} ({fields['platform']})  ",
        f"**Authorized target:** `{fields['target']}`  ",
        f"**Endpoint:** `{fields['method']} https://{fields['host']}{fields['path']}`  ",
        f"**Vulnerability type:** {fields['vuln_type']}  ",
        f"**Severity:** {fields['severity']}  ",
        f"**Validation status:** {fields['classification']} (confidence "
        f"{fields['confidence']:.0%}, reproducible: {fields['reproducible']})  ",
        f"**Generated:** {fields['generated_at']} (BountyGang {fields['tool_version']})",
        "",
        "## Summary",
        fields.get("description", ""),
        "",
        "## Prerequisites",
        "* Two researcher-controlled accounts (A and B) registered per program policy.",
        "* Test resources created exclusively by those accounts.",
        "* Session established through the authorized proxy path.",
        "",
        "## Reproduction steps",
    ]
    for i, step in enumerate(fields.get("steps", []), 1):
        lines.append(f"{i}. {step}")
    lines += [
        "",
        "## Expected vs actual behavior",
        f"* **Expected:** {fields.get('expected', 'Account A must not access account B\\'s resource (403/404).')}",
        f"* **Actual:** {fields.get('actual', 'See evidence below.')}",
        "",
        "## Evidence (sanitized)",
        "```json",
        json.dumps(ev, indent=2)[:20_000],
        "```",
        "",
        "## Security impact",
        fields.get("impact", ""),
        "",
        "## Remediation",
        fields.get("remediation", ""),
        "",
        "## References",
        "* OWASP API3:2023 – Broken Object Level Authorization (BOLA)",
        f"* Program policy: {fields.get('policy_url', '')}",
        "",
        "---",
        "_This report was generated locally by BountyGang. It has NOT been submitted "
        "to the platform. All traffic was limited to authorized scope with human approval._",
    ]
    return "\n".join(lines)


def build_html(md: str, fields: dict[str, Any]) -> str:
    body = html.escape(md)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{html.escape(fields['title'])}</title>
<style>body{{font-family:Segoe UI,Arial;max-width:900px;margin:2em auto}}
pre{{background:#f5f5f5;padding:1em;overflow-x:auto;white-space:pre-wrap}}</style>
</head><body><pre style="font-family:inherit;background:none">{body}</pre></body></html>"""


def generate_report(finding_id: int) -> dict[str, Any] | None:
    """Build MD/JSON/HTML files + DB row for a stored finding. Returns paths & id."""
    settings = get_settings()
    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            return None
        prog = s.get(Program, f.program_id) if f.program_id else None
        rid = new_report_id()
        fields = {
            "report_id": rid,
            "title": f.title or f"IDOR candidate on {f.endpoint}",
            "program_name": prog.name if prog else "Unknown program",
            "platform": prog.platform if prog else "unknown",
            "policy_url": prog.url if prog else "",
            "target": f.endpoint.split("/")[0] if f.endpoint else "",
            "host": f.endpoint.split("/")[0] if f.endpoint else "",
            "path": "/" + "/".join(f.endpoint.split("/")[1:]) if "/" in f.endpoint else f.endpoint,
            "method": f.method,
            "vuln_type": f.vulnerability_type,
            "severity": f.severity,
            "classification": f.classification.value,
            "confidence": f.confidence,
            "reproducible": f.reproducible,
            "description": f.description,
            "generated_at": f.created_at.isoformat(),
            "tool_version": "0.1.0",
            "evidence": json.loads(f.evidence or "{}"),
            "ai_analysis": f.ai_analysis,
            "steps": [
                f"As account B (owner), GET {f.endpoint} — record baseline response.",
                f"As account A (different researcher account), GET {f.endpoint}.",
                "Compare bodies/ownership markers — identical content indicates missing OLA.",
                "Repeat to confirm reproducibility; check unauthenticated control.",
            ],
            "impact": ("An authenticated user can read objects belonging to another user, "
                       "violating object-level authorization (OWASP API3)."
                       if f.classification.value in ("CONFIRMED_IDOR", "LIKELY_IDOR")
                       else "Potential object-level authorization weakness; impact pending validation."),
            "remediation": ("Enforce per-object authorization checks on the server for every "
                            "request (compare the authenticated principal/tenant against the "
                            "resource owner before returning data)."),
        }
        md = build_markdown(fields)
        if f.ai_analysis:
            md += "\n\n## AI research analysis\n" + f.ai_analysis

        reports_dir = Path(settings.reports_dir)
        reports_dir.mkdir(parents=True, exist_ok=True)
        md_path = reports_dir / f"{rid}.md"
        json_path = reports_dir / f"{rid}.json"
        html_path = reports_dir / f"{rid}.html"
        md_path.write_text(md, encoding="utf-8")
        json_path.write_text(json.dumps(fields, indent=2, default=str), encoding="utf-8")
        html_path.write_text(build_html(md, fields), encoding="utf-8")

        rec = ReportRepo(s).add(
            report_id=rid, finding_id=f.id, program_id=f.program_id,
            title=fields["title"], markdown_path=str(md_path),
            json_path=str(json_path), html_path=str(html_path),
        )
        bus.publish("report.generated", report_id=rid, title=fields["title"],
                    classification=f.classification.value, md_path=str(md_path))
        log.info("Report %s written (%s)", rid, md_path)
        return {"report_id": rid, "markdown_path": str(md_path),
                "json_path": str(json_path), "html_path": str(html_path),
                "db_id": rec.id}
