"""Telegram bot: the ONLY user-facing interface.

* Outbound notifications subscribe to the EventBus (program discovered, scope
  passed, browser launched, burp connected, endpoints found, IDOR likely/confirmed,
  scan finished/failed, approval requested).
* Inbound slash commands (restricted to TELEGRAM_ALLOWED_USER_IDS):
  /start /help /status /programs /findings /reports /scan /stop /approve <id>
* On a confirmed finding: sends summary + full sanitized Markdown report as a
  document attachment.
* Never sends credentials/cookies/API keys — everything routed through sanitize.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from bountygang.config import get_settings
from bountygang.core.events import Event, bus
from bountygang.db.models import ApprovalStatus, FindingClassification
from bountygang.db.repositories import (
    FindingRepo,
    ProgramRepo,
    ReportRepo,
    ScanRunRepo,
    TargetRepo,
)
from bountygang.db.session import session_scope
from bountygang.logging_setup import get_logger
from bountygang.utils.sanitize import sanitize_text

log = get_logger("telegram")

HELP_TEXT = (
    "BountyGang commands:\n"
    "/start – initialize bot\n"
    "/help – this help\n"
    "/status – current scanner status\n"
    "/programs – list discovered programs\n"
    "/findings – list detected vulnerabilities\n"
    "/reports – list generated reports\n"
    "/scan – show approved scan targets\n"
    "/stop – safely stop the current scan\n"
    "/approve <target_id> – approve a target for active testing\n"
    "/deny <target_id> – deny a target\n"
)


def _truncate(text: str, n: int = 3800) -> str:
    return text if len(text) <= n else text[: n - 20] + "\n…[truncated]"


class TelegramNotifier:
    """Thin wrapper around python-telegram-bot; degrades to no-op when disabled."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.app = None
        self.bot = None
        self._queue: asyncio.Queue[tuple[str, dict]] = asyncio.Queue()
        self.enabled = bool(self.settings.telegram_enabled
                            and self.settings.telegram_bot_token
                            and self.settings.telegram_chat_id)

    # ------------------------------------------------------------ subscriptions
    def attach_to_bus(self) -> None:
        mapping = {
            "program.discovered": "🔍 New program discovered",
            "scope.passed": "✅ Scope validation passed",
            "browser.launched": "🌐 Chromium launched",
            "burp.connected": "🛡 Burp Suite connected",
            "endpoint.discovered": "🧭 New endpoint discovered",
            "idor.potential": "⚠️ Potential IDOR identified",
            "idor.confirmed": "🚨 IDOR CONFIRMED",
            "scan.finished": "🏁 Scan finished",
            "scan.failed": "❌ Scan failed",
            "scan.stopped": "⏹ Scan stopped",
            "approval.requested": "🔐 Approval required",
            "report.generated": "📄 Report generated",
        }
        for kind, header in mapping.items():
            bus.subscribe(kind, self._make_handler(kind, header))

    def _make_handler(self, kind: str, header: str):
        def handler(ev: Event) -> None:
            if not self.enabled:
                log.debug("[telegram-off] %s: %s", header, ev.payload)
                return
            self._queue.put_nowait((header, ev.payload))
        return handler

    # ---------------------------------------------------------------- senders
    def _format(self, header: str, payload: dict[str, Any]) -> str:
        lines = [header]
        for k, v in payload.items():
            lines.append(f"{k}: {v}")
        return _truncate(sanitize_text("\n".join(lines)))

    async def send_message(self, text: str) -> bool:
        if not (self.enabled and self.bot):
            log.info("[telegram-dry] %s", text.splitlines()[0] if text else "")
            return False
        try:
            await self.bot.send_message(chat_id=self.settings.telegram_chat_id,
                                        text=text)
            return True
        except Exception as e:
            log.error("telegram send failed: %s", e)
            return False

    async def send_report_document(self, md_path: str, caption: str) -> bool:
        if not (self.enabled and self.bot):
            log.info("[telegram-dry] would send document %s", md_path)
            return False
        try:
            p = Path(md_path)
            if not p.exists():
                return False
            await self.bot.send_document(chat_id=self.settings.telegram_chat_id,
                                         document=p.read_bytes(),
                                         filename=p.name,
                                         caption=_truncate(caption, 900))
            return True
        except Exception as e:
            log.error("telegram document send failed: %s", e)
            return False

    async def worker(self) -> None:
        """Background consumer draining event queue into Telegram."""
        while True:
            header, payload = await self._queue.get()
            text = self._format(header, payload)
            await self.send_message(text)
            # confirmed findings also ship the full markdown report file
            if header.startswith("🚨") and payload.get("report_md_path"):
                await self.send_report_document(payload["report_md_path"], text)
            elif header.startswith("📄") and payload.get("md_path"):
                await self.send_report_document(
                    payload["md_path"], f"Report {payload.get('report_id', '')} "
                                        f"({payload.get('classification', '')})")

    # -------------------------------------------------------------- app setup
    def build_app(self):
        from telegram.ext import ApplicationBuilder, CommandHandler

        app = (ApplicationBuilder().token(self.settings.telegram_bot_token)
               .build())
        handlers = {
            "start": cmd_start, "help": cmd_help, "status": cmd_status,
            "programs": cmd_programs, "findings": cmd_findings,
            "reports": cmd_reports, "scan": cmd_scan, "stop": cmd_stop,
            "approve": cmd_approve, "deny": cmd_deny,
        }
        for name, fn in handlers.items():
            app.add_handler(CommandHandler(name, make_guarded(fn, self)))
        return app

    async def start(self, pipeline=None) -> None:
        """Run polling loop (blocking until cancelled)."""
        global PIPELINE_REF
        PIPELINE_REF = pipeline
        NOTIFIER_REF = self
        if not self.enabled:
            log.warning("Telegram disabled or missing token/chat id — "
                        "notifications go to logs only")
            return
        self.app = self.build_app()
        await self.app.initialize()
        await self.app.start()
        await self.app.updater.start_polling(drop_pending_updates=True)
        log.info("Telegram bot polling started (chat=%s)", self.settings.telegram_chat_id)


# --------------------------------------------------------------------- guards

NOTIFIER_REF: TelegramNotifier | None = None
PIPELINE_REF: Any = None


def make_guarded(fn, notifier: TelegramNotifier):
    """Restrict every command to TELEGRAM_ALLOWED_USER_IDS."""

    async def wrapper(update, context, *args, **kwargs):
        user = update.effective_user
        allowed = get_settings().allowed_telegram_users
        if user is None or (allowed and user.id not in allowed):
            uid = user.id if user else "?"
            log.warning("Unauthorized telegram user tried %s: %s",
                        getattr(context, "_tg_name", "?"), uid)
            if allowed:  # don't leak anything to strangers
                return
        return await fn(update, context, *args, **kwargs)

    return wrapper


# -------------------------------------------------------------------- commands

async def cmd_start(update, context):
    await update.message.reply_text(
        "BountyGang online 🔫\nBackend autonomous IDOR research agent.\n" + HELP_TEXT)


async def cmd_help(update, context):
    await update.message.reply_text(HELP_TEXT)


async def cmd_status(update, context):
    with session_scope() as s:
        run = ScanRunRepo(s).latest()
    state = run.state.value if run else "IDLE"
    msg = run.message if run else "no runs yet"
    pipe_state = getattr(PIPELINE_REF, "state", None)
    live = pipe_state.value if pipe_state is not None and hasattr(pipe_state, "value") else state
    await update.message.reply_text(f"Status: {live}\nLast message: {sanitize_text(msg)}")


async def cmd_programs(update, context):
    with session_scope() as s:
        progs = ProgramRepo(s).list_all()[:30]
    if not progs:
        await update.message.reply_text("No programs yet — run discovery.")
        return
    rows = [f"[{p.id}] {p.platform}/{p.slug} — {p.name}"
            f"{' 🎯IDOR' if p.idor_eligible else ''}" for p in progs]
    await update.message.reply_text(_truncate("Programs:\n" + "\n".join(rows)))


async def cmd_findings(update, context):
    with session_scope() as s:
        fs = FindingRepo(s).list_all()[:25]
    if not fs:
        await update.message.reply_text("No findings yet.")
        return
    rows = [f"[{f.id}] {f.classification.value} {f.severity} "
            f"{f.method} https://{f.endpoint} ({f.confidence:.0%})" for f in fs]
    await update.message.reply_text(_truncate("Findings:\n" + "\n".join(rows)))


async def cmd_reports(update, context):
    with session_scope() as s:
        rs = ReportRepo(s).list_all()[:25]
    if not rs:
        await update.message.reply_text("No reports yet.")
        return
    rows = [f"{r.report_id} — {r.title[:60]}" for r in rs]
    await update.message.reply_text(_truncate("Reports:\n" + "\n".join(rows)))


async def cmd_scan(update, context):
    with session_scope() as s:
        ready = TargetRepo(s).scan_ready()
        pending = TargetRepo(s).pending_approval()
    lines = ["Approved scan targets:"]
    lines += [f"[T{t.id}] {t.asset} (program {t.program_id})" for t in ready] or ["(none)"]
    if pending:
        lines.append("\nAwaiting approval (use /approve <id>):")
        lines += [f"[T{t.id}] {t.asset}" for t in pending[:15]]
    await update.message.reply_text(_truncate("\n".join(lines)))


async def cmd_stop(update, context):
    if PIPELINE_REF is not None:
        PIPELINE_REF.request_stop()
        await update.message.reply_text("⏹ Safe stop requested — finishing current step.")
    else:
        await update.message.reply_text("No pipeline instance attached to this bot.")


async def cmd_approve(update, context):
    await _decide(update, context, approved=True)


async def cmd_deny(update, context):
    await _decide(update, context, approved=False)


async def _decide(update, context, approved: bool) -> None:
    try:
        target_id = int(context.args[0])
    except (IndexError, ValueError):
        await update.message.reply_text(f"Usage: /{'approve' if approved else 'deny'} <target_id>")
        return
    from bountygang.scope.validator import approve_target

    t = approve_target(target_id, approved, by=f"telegram:{update.effective_user.id}")
    if t is None:
        await update.message.reply_text(f"Target {target_id} not found.")
    else:
        await update.message.reply_text(
            f"Target {t.id} ({t.asset}) {'APPROVED ✅' if approved else 'DENIED ⛔'}. "
            "Active scanning may proceed." if approved else
            f"Target {t.id} ({t.asset}) DENIED ⛔ — will never be actively tested.")
