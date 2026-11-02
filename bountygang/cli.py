"""BountyGang CLI (Typer). Local, backward-compatible control surface."""
from __future__ import annotations

import asyncio
import json

import typer
from rich.console import Console
from rich.table import Table

from bountygang import __version__
from bountygang.config import get_settings
from bountygang.db.session import init_db, session_scope
from bountygang.logging_setup import setup_logging

app = typer.Typer(help="BountyGang — autonomous bug bounty IDOR research agent "
                       "(backend-only; Telegram is the UI).")
console = Console()


def _boot() -> None:
    settings = get_settings()
    settings.ensure_dirs()
    setup_logging()
    init_db(settings.db_path)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        console.print(f"[bold]BountyGang v{__version__}[/] — use --help for commands.")


@app.command()
def version():
    """Show version."""
    console.print(f"bountygang {__version__}")


@app.command()
def discover(platforms: str = typer.Option("", help="comma-separated platform list")):
    """Discover public bug bounty programs and store them."""
    _boot()
    from bountygang.discovery.service import discover_programs

    plist = [p for p in platforms.split(",") if p] or None
    found = asyncio.run(discover_programs(plist))
    console.print(f"[green]Discovery done:[/] {len(found)} programs fetched/stored.")


@app.command()
def programs():
    """List stored programs."""
    _boot()
    from bountygang.db.repositories import ProgramRepo

    with session_scope() as s:
        rows = ProgramRepo(s).list_all()
    t = Table("id", "platform", "slug", "name", "IDOR?", "assets")
    for p in rows[:60]:
        n_assets = len(json.loads(p.in_scope_assets or "[]"))
        t.add_row(str(p.id), p.platform, p.slug[:28], p.name[:30],
                  "✅" if p.idor_eligible else "-", str(n_assets))
    console.print(t)


@app.command()
def validate(program_id: int = typer.Option(..., help="program id to scope-validate")):
    """Classify a program's in-scope assets (APPROVED/REVIEW_REQUIRED/BLOCKED)."""
    _boot()
    from bountygang.scope.validator import validate_program_targets

    targets = validate_program_targets(program_id)
    for tg in targets:
        console.print(f"T{tg.id} {tg.asset} -> {tg.classification.value}: {tg.reason}")


@app.command()
def approve(target_id: int, yes: bool = typer.Option(False, "--yes",
              help="I explicitly authorize active testing of this target")):
    """Human approval gate for active testing of a target."""
    _boot()
    if not yes:
        console.print("[red]Refusing:[/] pass --yes to confirm you authorize "
                      "active testing of this in-scope asset.")
        raise typer.Exit(2)
    from bountygang.scope.validator import approve_target

    t = approve_target(target_id, True, by="cli")
    console.print(f"Target {t.id} ({t.asset}) approval={t.approval_status.value}"
                  if t else "not found")


@app.command()
def scan(dry_run: bool = typer.Option(True, "--dry-run/--live",
          help="dry-run never launches browsers or sends packets beyond discovery"),
       program_id: int = typer.Option(0), skip_browser: bool = typer.Option(
           False, help="skip Chromium/Burp launch (analysis-only mode)")):
    """Run the full pipeline over approved targets."""
    _boot()
    from bountygang.core.pipeline import Pipeline

    pipe = Pipeline()
    pids = [program_id] if program_id else None
    summary = asyncio.run(pipe.run(program_ids=pids, skip_browser=skip_browser or dry_run))
    console.print_json(json.dumps(summary, default=str))


@app.command()
def status():
    """Show latest scan run + counts."""
    _boot()
    from bountygang.db.repositories import (
        EndpointRepo, FindingRepo, ProgramRepo, ReportRepo, ScanRunRepo, TargetRepo)

    with session_scope() as s:
        run = ScanRunRepo(s).latest()
        console.print(f"Last run: #{run.id} state={run.state.value} msg={run.message}"
                      if run else "No runs yet.")
        console.print(f"programs={len(ProgramRepo(s).list_all())} "
                      f"targets={len(TargetRepo(s).list_all())} "
                      f"endpoints={len(EndpointRepo(s).list_all())} "
                      f"findings={len(FindingRepo(s).list_all())} "
                      f"reports={len(ReportRepo(s).list_all())}")


@app.command()
def reports():
    """List generated reports."""
    _boot()
    from bountygang.db.repositories import ReportRepo

    with session_scope() as s:
        for r in ReportRepo(s).list_all():
            console.print(f"{r.report_id} | {r.title} | {r.markdown_path}")


@app.command()
def bot():
    """Run the Telegram bot loop (notifications + remote commands)."""
    _boot()
    from bountygang.telegram_bot.bot import TelegramNotifier

    notifier = TelegramNotifier()
    notifier.attach_to_bus()

    async def _main():
        await notifier.start()
        if notifier.enabled:
            asyncio.create_task(notifier.worker())
            while True:
                await asyncio.sleep(3600)

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        console.print("Bot stopped.")


@app.command()
def run(interval_minutes: int = typer.Option(
    0, help="if >0, loop discovery+pipeline every N minutes; 0 = single pass")):
    """Full background operation: pipeline + Telegram notifications."""
    _boot()
    from bountygang.core.pipeline import Pipeline
    from bountygang.telegram_bot.bot import TelegramNotifier

    async def _main():
        notifier = TelegramNotifier()
        notifier.attach_to_bus()
        await notifier.start()
        worker_task = asyncio.create_task(notifier.worker()) if notifier.enabled else None
        pipe = Pipeline()
        while True:
            summary = await pipe.run()
            console.print_json(json.dumps(summary, default=str))
            if interval_minutes <= 0:
                break
            await asyncio.sleep(interval_minutes * 60)
        if worker_task:
            worker_task.cancel()

    asyncio.run(_main())


if __name__ == "__main__":
    app()
