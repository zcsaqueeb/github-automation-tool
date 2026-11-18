"""
config.py — Centralised, environment-driven configuration.

All secrets are loaded from environment variables or a local `.env` file.
Nothing sensitive is hard-coded here.  Create a `.env` next to this file
(copy `.env.example`) and fill in the required values:

    BOT_TOKEN=123456789:ABC-your-telegram-bot-token
    ADMIN_CHAT_ID=123456789
    DATA_ENCRYPTION_KEY=<generated with `python -c "from security import generate_key; print(generate_key())">`

Optional:
    ADMIN_IDS=111111111,222222222   # comma-separated extra admin IDs
    DB_FILE=users.json
    LOG_FILE=bot.log
    LOG_LEVEL=INFO
    HTTP_TIMEOUT=15
    HTTP_MAX_RETRIES=3
    GIT_BLOB_WORKERS=12          # parallel GitHub blob uploads per repository (1-16)
    BULK_REPO_WORKERS=2          # repositories uploaded simultaneously (1-3)
    BULK_DOWNLOAD_WORKERS=3      # repositories downloaded simultaneously (1-4)
    BOT_REPLY_DELETE_SECONDS=30
"""

from __future__ import annotations

import os
import sys
from typing import List

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv is optional — env vars can still be provided by the OS.
    pass


# ── Helpers ──────────────────────────────────────────────────────────────

def _get_int_list(raw: str) -> List[int]:
    """Parse a comma-separated string of integers, silently skipping blanks."""
    result: List[int] = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            result.append(int(part))
    return result


def _get_int(raw: str, default: int = 0) -> int:
    """Parse an integer env var, returning *default* on any malformed input
    instead of letting a typo crash the whole process at import time."""
    raw = (raw or "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


# ── Telegram ─────────────────────────────────────────────────────────────

BOT_TOKEN: str = os.getenv("BOT_TOKEN", "").strip()

# ── Admins ───────────────────────────────────────────────────────────────

_admin_chat_id_raw: str = os.getenv("ADMIN_CHAT_ID", "0").strip()
ADMIN_CHAT_ID: int = _get_int(_admin_chat_id_raw, default=0)
# Track whether the raw value was actually numeric, so validate() can tell
# "not set" apart from "set to something that isn't a number" and give a
# more specific error message for the latter.
_admin_chat_id_malformed: bool = bool(_admin_chat_id_raw) and _admin_chat_id_raw != "0" and ADMIN_CHAT_ID == 0

_extra_admins: List[int] = _get_int_list(os.getenv("ADMIN_IDS", ""))
ADMIN_IDS: List[int] = (
    sorted({ADMIN_CHAT_ID, *_extra_admins}) if ADMIN_CHAT_ID else _extra_admins
)

# ── Storage / security ───────────────────────────────────────────────────

DB_FILE: str = os.getenv("DB_FILE", "users.json")
DATA_ENCRYPTION_KEY: str = os.getenv("DATA_ENCRYPTION_KEY", "").strip()

# ── Logging ──────────────────────────────────────────────────────────────

LOG_FILE: str = os.getenv("LOG_FILE", "bot.log")
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

# ── Networking ───────────────────────────────────────────────────────────

# Clamp >= 1: HTTP_TIMEOUT=0 would make requests time out instantly and
# look like a total outage instead of a config typo.
HTTP_TIMEOUT: int = max(1, _get_int(os.getenv("HTTP_TIMEOUT", "15"), default=15))
HTTP_MAX_RETRIES: int = _get_int(os.getenv("HTTP_MAX_RETRIES", "3"), default=3)
GIT_BLOB_WORKERS: int = max(1, min(16, _get_int(os.getenv("GIT_BLOB_WORKERS", "12"), default=12)))
BULK_REPO_WORKERS: int = max(1, min(3, _get_int(os.getenv("BULK_REPO_WORKERS", "2"), default=2)))
BULK_DOWNLOAD_WORKERS: int = max(1, min(4, _get_int(os.getenv("BULK_DOWNLOAD_WORKERS", "3"), default=3)))
BOT_REPLY_DELETE_SECONDS: int = max(
    0, _get_int(os.getenv("BOT_REPLY_DELETE_SECONDS", "30"), default=30)
)


# ── Validation ───────────────────────────────────────────────────────────

def validate(exit_on_error: bool = True) -> List[str]:
    """
    Validate required configuration values.

    Returns a list of human-readable problem descriptions.
    When *exit_on_error* is True (the default) the process exits with
    status 1 if any problems are found, printing them to stderr first.
    """
    problems: List[str] = []

    if not BOT_TOKEN or ":" not in BOT_TOKEN:
        problems.append(
            "BOT_TOKEN is missing or malformed.\n"
            "  Get a token from @BotFather on Telegram and set it in .env:\n"
            "    BOT_TOKEN=123456789:ABC-your-token"
        )

    if _admin_chat_id_malformed:
        problems.append(
            f"ADMIN_CHAT_ID is set to '{_admin_chat_id_raw}', which isn't a valid "
            "numeric Telegram user ID.\n"
            "  Message @userinfobot on Telegram to find your numeric user ID, then:\n"
            "    ADMIN_CHAT_ID=123456789"
        )
    elif not ADMIN_CHAT_ID:
        problems.append(
            "ADMIN_CHAT_ID is missing.\n"
            "  Message @userinfobot on Telegram to find your numeric user ID, then:\n"
            "    ADMIN_CHAT_ID=123456789"
        )

    if not DATA_ENCRYPTION_KEY:
        problems.append(
            "DATA_ENCRYPTION_KEY is missing — GitHub tokens and AI keys will be\n"
            "  stored in plaintext. Generate a key and add it to .env:\n"
            "    python -c \"from security import generate_key; print(generate_key())\"\n"
            "  Then: DATA_ENCRYPTION_KEY=<paste output here>"
        )
    else:
        try:
            from cryptography.fernet import Fernet
            Fernet(DATA_ENCRYPTION_KEY.encode())
        except Exception:
            problems.append(
                "DATA_ENCRYPTION_KEY is set but isn't a valid Fernet key, so it "
                "can't be used — GitHub tokens and AI keys will be stored in\n"
                "  plaintext until this is fixed. Generate a fresh one:\n"
                "    python -c \"from security import generate_key; print(generate_key())\"\n"
                "  Then replace the value in .env. (Note: rotating the key makes any\n"
                "  data encrypted under the old key permanently unreadable.)"
            )

    if problems and exit_on_error:
        print(
            "\n[CONFIG ERROR] Fix the following before starting the bot:\n",
            file=sys.stderr,
        )
        for i, p in enumerate(problems, 1):
            print(f"  {i}. {p}\n", file=sys.stderr)
        sys.exit(1)

    return problems
