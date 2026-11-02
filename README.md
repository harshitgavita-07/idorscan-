# BountyGang

**BountyGang** is a backend-only, autonomous AI bug-bounty research and IDOR (Insecure
Direct Object Reference / BOLA) detection agent for **Windows**. There is no frontend,
dashboard or web UI — **Telegram is the only user-facing interface** for notifications,
reports and remote commands.

> ⚠️ **Authorized use only.** BountyGang strictly limits active testing to assets that are
> explicitly in-scope for a public bug bounty program AND that you have personally approved.
> It never submits reports automatically and never enumerates other users' data.

---

## High-level workflow

```
Discover programs → Extract policies → Validate scope → Request approval (Telegram)
→ Launch Chromium (Playwright) → Launch Burp Suite (pywinauto) → Configure proxy
→ Capture authorized HTTP traffic → Discover endpoints → Analyze object references
→ Identify authorization weaknesses → Safely validate with controlled accounts
→ Classify findings → Generate reports (MD/JSON/HTML) → Deliver everything to Telegram
```

## Project layout (modular backend packages)

```
bountygang/
├── __init__.py
├── cli.py                  # Typer CLI entry point: `python -m bountygang ...`
├── config.py               # Pydantic settings (env vars / .env)
├── logging_setup.py        # Structured console + file logging
├── core/                   # Orchestration, task manager, state machine
├── discovery/              # Bug bounty program discovery (HackerOne/Bugcrowd/...)
├── scope/                  # Scope & policy validation + approval gate
├── automation/             # Chromium (Playwright) + Burp Suite (pywinauto) control
├── traffic/                # HTTP traffic collection (Burp API/proxy) & parsing
├── idor/                   # IDOR/BOLA detection engine + controlled validation
├── ai/                     # Pluggable LLM providers (OpenAI/Claude/Gemini/Ollama)
├── reporting/              # HackerOne-style report generation (MD/JSON/HTML)
├── telegram_bot/           # Notifications + slash commands (only UI)
├── db/                     # SQLAlchemy models, repositories, SQLite session
└── utils/                  # Sanitization, identifiers, async helpers
tests/                      # pytest suite (unit + integration)
```

## Requirements

* Python **3.11+** (developed/tested on 3.12)
* Windows 10/11 for the desktop-automation features (`pywinauto` is Windows-only;
  every other module runs cross-platform and is fully testable on any OS)
* [Burp Suite](https://portswigger.net/burp) Community/Professional installed
* Playwright Chromium (`playwright install chromium`)

## Installation

```bat
py -3.11 -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
playwright install chromium
copy .env.example .env   &:: then edit .env
```

## Configuration

All configuration comes from environment variables or a `.env` file
(see `.env.example`). Key variables:

| Variable | Meaning |
|---|---|
| `TELEGRAM_ENABLED` | Turn Telegram notifications/commands on/off |
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | Your chat id (target of all notifications) |
| `TELEGRAM_ALLOWED_USER_IDS` | Comma-separated user ids allowed to run commands |
| `BURP_API_URL` / `BURP_API_TOKEN` | Burp Suite built-in API (Proxy/Collaborator) |
| `CHROMIUM_PROXY_HOST` / `CHROMIUM_PROXY_PORT` | Where Burp listens (default 127.0.0.1:8080) |
| `LLM_PROVIDER` | `openai` \| `anthropic` \| `gemini` \| `ollama` \| `none` |
| `DB_PATH` | SQLite path (default `./data/bountygang.db`) |

## CLI

```bat
python -m bountygang discover          :: discover & store public programs
python -m bountygang programs          :: list discovered programs
python -m bountygang scan --program-id N --dry-run
python -m bountygang status            :: current pipeline state
python -m bountygang bot               :: run the Telegram bot loop
python -m bountygang run               :: full background pipeline
```

The CLI remains the backward-compatible local interface; Telegram mirrors it remotely.

## Milestones

| # | Milestone | Status |
|---|---|---|
| 0 | Repo audit, project scaffold, config, DB, logging, CLI skeleton | ✅ Done |
| 1 | Chromium + Burp Suite automation (Playwright/pywinauto, proxy verify) | ✅ Done |
| 2 | Bug bounty program discovery (platform adapters, offline-safe) | ✅ Done |
| 3 | Scope intelligence & approval gate | ✅ Done |
| 4 | HTTP traffic analysis (capture, parse, endpoint/object-reference mining) | ✅ Done |
| 5 | IDOR detection & controlled validation | ✅ Done |
| 6 | AI research integration (pluggable providers) | ✅ Done |
| 7 | Telegram bot & report delivery | ✅ Done |
| 8 | End-to-end integration & tests | ✅ Done |

See `CHANGELOG.md` for details per milestone.

## Safety model

1. **Scope-first:** nothing is tested unless its asset matches an in-scope pattern of a
   known program policy *and* classification is `APPROVED`.
2. **Explicit human approval:** active scans require your approval (CLI flag or Telegram).
3. **Controlled resources only:** IDOR validation uses researcher-owned accounts/test
   objects; responses are compared between *your own* contexts. No third-party data.
4. **Evidence-based classification:** a status-code delta alone never confirms an IDOR;
   confirmation requires reproducible cross-context evidence (see `idor/` docs).
5. **Sanitization everywhere:** secrets, cookies, tokens and PII are redacted before
   storage/reporting/Telegram.
6. **No auto-submission:** reports are written locally and sent to *you* only.
