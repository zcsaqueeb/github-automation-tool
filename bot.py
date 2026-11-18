"""GitHub AI Repo Bot.\n\nAuthor: Saqueeb\n"""

import base64
import hashlib
import io
import json
import os
import re
import shutil
import sys
import time as _time
import threading
import urllib.parse as _urllib_parse
# ── RAR support: rarfile with an auto-detected system tool ──
_RARFILE_OK    = False
_rarfile_mod   = None   # 'rarfile' package (needs external tool: unrar / 7z)
_ucffi_rf      = None   # Kept for compatibility with archive helper branches.

try:
    import rarfile as _rarfile_mod
    import os as _os, shutil as _shutil

    # Auto-detect 7-zip / WinRAR / unrar in common Windows & Unix paths
    _tool_candidates = {
        "7z": [
            r"C:\Program Files\7-Zip\7z.exe",
            r"C:\Program Files (x86)\7-Zip\7z.exe",
            "7z", "7zz",
        ],
        "unrar": [
            r"C:\Program Files\WinRAR\UnRAR.exe",
            r"C:\Program Files (x86)\WinRAR\UnRAR.exe",
            r"C:\Program Files\WinRAR\Rar.exe",
            "unrar", "unar",
        ],
    }
    for _kind, _paths in _tool_candidates.items():
        for _p in _paths:
            if _shutil.which(_p) or _os.path.isfile(_p):
                if _kind == "7z":
                    _rarfile_mod.SEVENZIP_TOOL  = _p
                    _rarfile_mod.SEVENZIP2_TOOL = _p
                else:
                    _rarfile_mod.UNRAR_TOOL = _p
                break

    _RARFILE_OK = True
except Exception:
    _rarfile_mod = None
    _RARFILE_OK  = False
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests
import telebot
from telebot.types import (
    BotCommand,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

import cli_log as log
import ai_providers as ai
import github_api   as gh
import security
import config
import gh_actions
from ai_providers import PROVIDERS, FREE_PROVIDERS
from localization import LANGUAGES, normalize_language, translate

_github_upload_session = requests.Session()
# Git Data blob creation is parallelized during archive uploads. Keep enough
# pooled connections for those workers so requests do not serialize internally.
_github_upload_adapter = requests.adapters.HTTPAdapter(
    pool_connections=32, pool_maxsize=32, max_retries=0,
)
_github_upload_session.mount("https://", _github_upload_adapter)

config.validate()
BOT_TOKEN, ADMIN_CHAT_ID, ADMIN_IDS = config.BOT_TOKEN, config.ADMIN_CHAT_ID, config.ADMIN_IDS
_APP_STARTED_AT = _time.time()

# ─────────────────────────────────────────────────────────────
#  File helpers  (no redaction — files uploaded exactly as-is)
# ─────────────────────────────────────────────────────────────
#  Sensitive-data scanner
#  Scans filenames and file contents before any upload and raises
#  a structured warning that the user must explicitly acknowledge.
# ─────────────────────────────────────────────────────────────

# ── Filename patterns that almost certainly contain secrets ──
_SENSITIVE_FILENAME_PATTERNS: list = [
    re.compile(r, re.IGNORECASE) for r in [
        r"(^|[\\/])\.env(\.|$)",          # .env, .env.local, .env.production …
        r"(^|[\\/])\.env\b",              # plain .env
        r"secrets?\.(json|yaml|yml|toml|ini|cfg|conf|txt)$",
        r"credentials?\.(json|yaml|yml|toml|ini|cfg|conf|txt)$",
        r"config\.(json|yaml|yml|toml|ini|cfg|conf)$",
        r"settings\.(json|yaml|yml|toml|ini|cfg|conf)$",
        r"(^|[\\/])(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\.pub)?$",  # SSH keys
        r"(^|[\\/]).*\.pem$",             # TLS/SSL private key
        r"(^|[\\/]).*\.key$",             # generic key file
        r"(^|[\\/]).*\.p12$",             # PKCS#12 certificate bundle
        r"(^|[\\/]).*\.pfx$",             # Windows cert store
        r"(^|[\\/])google-services\.json$", # Android/Firebase app config
        r"(^|[\\/])GoogleService-Info\.plist$", # iOS/Firebase app config
        r"(^|[\\/])AuthKey_[A-Z0-9]+\.p8$", # Apple APNs/App Store Connect key
        r"(^|[\\/]).*\.p8$",              # Apple private key container
        r"(^|[\\/])keystore\.(jks|p12|bks)$",
        r"(^|[\\/])\.netrc$",             # curl/ftp credential file
        r"(^|[\\/])\.pgpass$",            # PostgreSQL password file
        r"(^|[\\/])\.my\.cnf$",           # MySQL credential file
        r"(^|[\\/])wp-config\.php$",      # WordPress secrets
        r"(^|[\\/])database\.yml$",       # Rails DB config (often has prod creds)
        r"(^|[\\/])terraform\.tfvars$",   # Terraform variable values (may have secrets)
        r"(^|[\\/])\.terraformrc$",
        r"(^|[\\/])kubeconfig$",          # Kubernetes cluster credentials
        r"(^|[\\/])\.kube[\\/]config$",
        r"(^|[\\/])service[-_]?account.*\.json$",   # GCP service account JSON
        r"(^|[\\/])gcloud.*credentials.*\.json$",
        r"(^|[\\/])firebase[-_]?adminsdk.*\.json$",
        r"(^|[\\/]).*authtoken$",
    ]
]

# ── Content patterns — regex → human-readable label ──────────
_SENSITIVE_CONTENT_RULES: list = [
    # ── API & service keys ──
    (re.compile(r"(?i)(api[_\-]?key|api[_\-]?secret|app[_\-]?secret)\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{16,}"), "API key/secret"),
    (re.compile(r"(?i)(secret[_\-]?key|private[_\-]?key|client[_\-]?secret)\s*[=:]\s*['\"]?[A-Za-z0-9\-_./+]{16,}"), "Secret/private key value"),
    (re.compile(r"(?i)(token|access[_\-]?token|auth[_\-]?token|bearer[_\-]?token)\s*[=:]\s*['\"]?[A-Za-z0-9\-_.]{20,}"), "Auth/access token"),
    (re.compile(r"(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._\-~+/]+=*"), "Bearer access token"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT token"),
    (re.compile(r"(?im)(EXPO_TOKEN|EAS_TOKEN|SENTRY_AUTH_TOKEN|ONESIGNAL_REST_API_KEY|FCM_SERVER_KEY)\s*[=:]\s*['\"]?[^\s'\"]{16,}"), "Mobile service token"),
    (re.compile(r"(?im)(APNS|APPLE|IOS|ANDROID|MOBILE)[_\-]?(API[_\-]?KEY|SECRET|TOKEN)\s*[=:]\s*['\"]?[^\s'\"]{16,}"), "Mobile API credential"),
    # ── GitHub ──
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "GitHub Personal Access Token"),
    (re.compile(r"github[_\-]?token\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}"), "GitHub token"),
    # ── AWS ──
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+]{40}"), "AWS Secret Access Key"),
    (re.compile(r"(?i)aws[_\-]?session[_\-]?token\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{100,}"), "AWS Session Token"),
    # ── Google / GCP ──
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API Key"),
    (re.compile(r"(?i)\"private_key\"\s*:\s*\"-----BEGIN"), "GCP/Firebase service account private key"),
    (re.compile(r"(?i)\"type\"\s*:\s*\"service_account\""), "GCP service account credential file"),
    # ── Stripe ──
    (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "Stripe live secret key"),
    (re.compile(r"rk_live_[0-9a-zA-Z]{24,}"), "Stripe restricted key"),
    # ── Slack ──
    (re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "Slack token"),
    (re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[a-zA-Z0-9]+"), "Slack Webhook URL"),
    # ── Telegram ──
    (re.compile(r"\d{8,10}:[A-Za-z0-9_\-]{35,46}"), "Telegram Bot Token"),
    # ── OpenAI / Anthropic ──
    (re.compile(r"sk-[A-Za-z0-9]{32,}"), "OpenAI API key"),
    (re.compile(r"sk-ant-[A-Za-z0-9\-_]{32,}"), "Anthropic API key"),
    # ── Groq / Mistral / Together / Gemini ──
    (re.compile(r"gsk_[A-Za-z0-9]{32,}"), "Groq API key"),
    (re.compile(r"hf_[A-Za-z0-9]{30,}"), "Hugging Face access token"),
    (re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"), "GitLab access token"),
    (re.compile(r"npm_[A-Za-z0-9]{30,}"), "npm access token"),
    (re.compile(r"pypi-[A-Za-z0-9_\-]{30,}"), "PyPI API token"),
    (re.compile(r"SG\.[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}"), "SendGrid API key"),
    (re.compile(r"(?i)(xox[baprs]-[0-9A-Za-z\-]{10,})"), "Slack token"),
    (re.compile(r"(?i)gemini[_\-]?api[_\-]?key\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}"), "Gemini API key"),
    # ── Database URLs ──
    (re.compile(r"(?i)(postgres|postgresql|mysql|mongodb|redis|amqp|rabbitmq)://[^:\s]+:[^@\s]+@"), "Database connection string with credentials"),
    (re.compile(r"(?i)(db[_\-]?password|database[_\-]?password|db[_\-]?pass)\s*[=:]\s*['\"]?\S{6,}"), "Database password"),
    # ── Cryptocurrency / wallet credentials ──
    (re.compile(r"(?i)(ethereum|eth|evm|wallet)[_\-]?(private[_\-]?key|secret)\s*[=:]\s*['\"]?0x[a-f0-9]{64}"), "Blockchain private key"),
    (re.compile(r"(?<![A-Za-z0-9])(0x[a-fA-F0-9]{64})(?![A-Za-z0-9])"), "Blockchain private key"),
    (re.compile(r"(?i)(xprv|tprv)[1-9A-HJ-NP-Za-km-z]{80,120}"), "Bitcoin extended private key"),
    (re.compile(r"(?im)(wallet[_\-]?seed|seed[_\-]?phrase|mnemonic)\s*[=:]\s*['\"]?[^\r\n'\"]{20,}"), "Cryptocurrency seed phrase"),
    (re.compile(r"(?im)(BINANCE|COINBASE|KRAKEN|KUCOIN|OKX|BYBIT|GEMINI)[_\-]?(API[_\-]?KEY|API[_\-]?SECRET|SECRET)\s*[=:]\s*['\"]?[^\s'\"]{16,}"), "Crypto exchange credential"),
    (re.compile(r"(?im)(ALCHEMY|INFURA|QUICKNODE|MORALIS)[_\-]?(API[_\-]?KEY|API[_\-]?SECRET|SECRET)\s*[=:]\s*['\"]?[^\s'\"]{16,}"), "Blockchain RPC credential"),
    # ── Generic password patterns ──
    (re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?\S{8,}"), "Password value"),
    (re.compile(r"(?i)(private[_\-]?key|privatekey)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{20,}"), "Private key value"),
    # ── SSH / TLS private keys (inline) ──
    (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private key (PEM block)"),
    # ── .env assignments with likely-sensitive names ──
    (re.compile(r"(?im)^(export\s+)?(GITHUB_TOKEN|BOT_TOKEN|TELEGRAM_TOKEN|OPENAI_KEY|GROQ_KEY|ANTHROPIC_KEY|STRIPE_SECRET|SENDGRID_KEY|TWILIO_AUTH|MAILGUN_KEY|FIREBASE_KEY)\s*=\s*.{4,}"), ".env secret assignment"),
    # ── Encryption key material ──
    (re.compile(r"DATA_ENCRYPTION_KEY\s*[=:]\s*[A-Za-z0-9=_\-]{30,}"), "Encryption key"),
    (re.compile(r"(?i)fernet[_\-]?key\s*[=:]\s*['\"]?[A-Za-z0-9=_\-]{30,}"), "Fernet encryption key"),
]

# Max bytes of each file to scan (avoids scanning huge binary blobs)
_SCAN_MAX_BYTES = 64_000
# Max files to deep-scan per upload (fast-fail for giant archives)
_SCAN_MAX_FILES = 200
_MAX_FINDINGS_PER_FILE = 5


def _security_severity(reason: str, findings: list[dict]) -> str:
    """Classify a finding without exposing its credential value."""
    if reason == "filename":
        return "medium"
    labels = {finding.get("label", "") for finding in findings}
    critical_terms = ("private key", "seed phrase", "credential", "password")
    return "critical" if any(term in label.lower() for label in labels for term in critical_terms) else "high"


def _safe_security_path(path: str) -> str:
    """Format an untrusted filename safely for a Markdown warning."""
    path = str(path or "(unnamed file)").replace("`", "'").replace("\n", " ").replace("\r", " ")
    return path[:180] + ("..." if len(path) > 180 else "")


def _is_sensitive_filename(fname: str) -> bool:
    """Return True if *fname* matches a pattern known to contain secrets."""
    for pat in _SENSITIVE_FILENAME_PATTERNS:
        if pat.search(fname):
            return True
    return False


def _scan_content(content: str) -> list[dict]:
    """\n    Scan *content* for secret patterns.\n\n    Returns a list of findings, each a dict with keys:\n      - ``label``   — human-readable description of the secret type\n      - ``snippet`` — redacted snippet showing where in the content it matched\n    """
    findings: list[dict] = []
    seen_labels: set[str] = set()
    for pattern, label in _SENSITIVE_CONTENT_RULES:
        if label in seen_labels:
            continue
        m = pattern.search(content)
        if m:
            seen_labels.add(label)
            raw = m.group(0)
            # Redact the middle of the matched value for display
            if len(raw) > 20:
                snippet = raw[:3] + "·" * 8 + raw[-2:]
            else:
                snippet = raw[:2] + "······"
            findings.append({"label": label, "snippet": snippet})
    return findings


# ── Main scan entry-point used before every upload ───────────

def scan_files_for_secrets(files: list) -> dict:
    """\n    Scan a list of ``{path, content_b64}`` dicts for sensitive data.\n\n    Returns a summary dict::\n\n        {\n            "flagged_files": [\n                {\n                    "path": "config/settings.py",\n                    "reason": "filename",          # or "content"\n                    "findings": [                  # populated for content hits\n                        {"label": "...", "snippet": "..."},\n                    ]\n                },\n                ...\n            ],\n            "total_scanned": int,\n            "skipped_binary": int,\n        }\n    """
    flagged: list = []
    total_scanned = 0
    skipped_binary = 0
    truncated_files = max(0, len(files) - _SCAN_MAX_FILES)

    for i, f in enumerate(files):
        if i >= _SCAN_MAX_FILES:
            break
        # Archives use ``path`` while direct Telegram uploads use ``name``.
        # Checking both prevents filename rules being bypassed outside archives.
        path = str(f.get("path") or f.get("name") or "")
        total_scanned += 1

        # 1 — filename check (always fast)
        if _is_sensitive_filename(path):
            flagged.append({"path": path, "reason": "filename", "findings": [], "severity": "medium"})
            continue

        # 2 — content check (text files only, limited size)
        try:
            encoded = f.get("content_b64")
            if encoded is not None:
                raw_bytes = base64.b64decode(encoded, validate=True)
            elif f.get("source") in ("binary", "archive_binary"):
                raw_bytes = base64.b64decode(f.get("content", ""), validate=True)
            else:
                # Direct and manually-created files keep their text as
                # ``content`` rather than base64; scan the exact text that
                # will be pushed to GitHub.
                raw_bytes = str(f.get("content", "")).encode("utf-8")
            # Skip binary files. Valid UTF-8 means TEXT — CJK/emoji files
            # must still be scanned (the old >30%-bytes-over-126 heuristic
            # classified any file with heavy multi-byte content as binary,
            # which silently bypassed the secret scan). Fall back to the
            # byte heuristic only when the content is not valid UTF-8.
            sample  = raw_bytes[:512]
            payload = raw_bytes[:_SCAN_MAX_BYTES]
            try:
                payload.decode("utf-8")
                is_binary = False
            except UnicodeDecodeError:
                non_printable = sum(1 for b in sample if b < 9 or (13 < b < 32))
                is_binary = (len(sample) > 0 and non_printable / len(sample) > 0.30) or (0 in sample)
            if is_binary:
                skipped_binary += 1
                continue
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            skipped_binary += 1
            continue

        findings = _scan_content(text)
        if findings:
            findings = findings[:_MAX_FINDINGS_PER_FILE]
            flagged.append({"path": path, "reason": "content", "findings": findings,
                            "severity": _security_severity("content", findings)})

    return {
        "flagged_files": flagged,
        "total_scanned": total_scanned,
        "skipped_binary": skipped_binary,
        "truncated_files": truncated_files,
    }


def _format_security_warning(scan_result: dict, repo_name: str = "") -> str:
    """\n    Build the Telegram warning message shown before an upload.\n    Returns a Markdown string.\n    """
    flagged = scan_result["flagged_files"]
    total = scan_result["total_scanned"]
    header  = (
        "🚨 *Security Warning*\n\n"
        f"Upload blocked: possible secrets found in *{len(flagged)}* file(s) "
        f"out of {total} scanned"
        + (f" for `{repo_name}`" if repo_name else "")
        + ".\n\n"
        "No secret value is shown here. A private repository does not make an exposed credential safe.\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "⚠️ *Flagged files:*\n\n"
    )
    lines: list[str] = []
    for item in flagged[:10]:  # cap at 10 to keep the message readable
        path = _safe_security_path(item["path"])
        severity = item.get("severity", "high").upper()
        if item["reason"] == "filename":
            lines.append(f"[{severity}] `{path}`\n   Sensitive filename")
        else:
            finding_lines = []
            for find in item["findings"][:3]:
                finding_lines.append(f"   • {find['label']}: `{find['snippet']}`")
            lines.append(f"[{severity}] `" + path + "`\n" + "\n".join(finding_lines))
    if len(flagged) > 10:
        lines.append(f"_…and {len(flagged) - 10} more flagged file(s)_")

    footer = (
        "\n━━━━━━━━━━━━━━━━━━━━\n\n"
        "💡 *Recommended actions:*\n"
        "• Remove secrets from files and use environment variables instead\n"
        "• Add secret files to `.gitignore` before uploading\n"
        "• Revoke and rotate any credential that was committed or shared\n\n"
        "Choose *Edit* to remove/re-upload the flagged files, or explicitly choose *Upload anyway*."
    )
    limits = []
    if scan_result.get("skipped_binary"):
        limits.append(f"{scan_result['skipped_binary']} binary file(s) were not content-scanned")
    if scan_result.get("truncated_files"):
        limits.append(f"{scan_result['truncated_files']} file(s) exceeded the {_SCAN_MAX_FILES}-file scan limit")
    if limits:
        footer += "\n\n*Scan limits:* " + "; ".join(limits) + "."
    return header + "\n\n".join(lines) + footer

# ─────────────────────────────────────────────────────────────
#  Startup
# ─────────────────────────────────────────────────────────────

log.print_banner()
flog = log.setup_file_logger(config.LOG_FILE, config.LOG_LEVEL)

if not BOT_TOKEN or ":" not in BOT_TOKEN:
    log.critical("Invalid BOT_TOKEN in config.py")
    sys.exit(1)

log.info("Initializing Telegram bot...")

# Log polling and handler exceptions. Transient failures use TeleBot's retry
# path; a Telegram 409 is handled separately below because retrying cannot
# succeed while another process owns getUpdates.
_polling_conflict = False


class _VisibleErrorHandler(telebot.ExceptionHandler):
    def handle(self, exception) -> bool:
        global _polling_conflict
        log.error("Telebot exception", f"{type(exception).__name__}: {exception}")
        # Telegram permits only one active getUpdates consumer per bot token.
        # infinity_polling retries API exceptions forever, which otherwise hides
        # this configuration error and floods the logs. Stop cleanly so the
        # operator can remove the duplicate process/replica.
        if getattr(exception, "error_code", None) == 409:
            _polling_conflict = True
            bot.stop_polling()
            return True
        return False

def _is_entity_parse_error(ex: Exception) -> bool:
    """True when Telegram rejected a message because of Markdown entities."""
    return getattr(ex, "error_code", None) == 400 and "can't parse entities" in str(ex).lower()


def _strip_markdown(text: str) -> str:
    """Plain-text version of a Markdown string for the no-parse-mode fallback."""
    if not text:
        return text
    text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r"\1 (\2)", text)
    text = text.replace("*", "").replace("`", "")
    text = re.sub(r"(?<!\\)_", "", text)
    text = text.replace("\\_", "_").replace("\\*", "*").replace("\\[", "[").replace("\\`", "`")
    return text


class _SafeTeleBot(telebot.TeleBot):
    """TeleBot wrapper that never lets a Markdown entity error silently kill a
    UI screen.  Repo descriptions, file paths, and history entries are
    user-controlled; when Telegram rejects their entities, the message is
    resent without parse_mode so buttons keep responding."""

    def _send_plain(self, fn, *args, **kwargs):
        # TeleBot re-applies self.parse_mode when the parse_mode argument is
        # falsy, so temporarily disable the global default for the retry.
        saved = self.parse_mode
        self.parse_mode = None
        try:
            return fn(*args, **kwargs)
        finally:
            self.parse_mode = saved

    def send_message(self, chat_id, text, **kwargs):
        try:
            return super().send_message(chat_id, text, **kwargs)
        except telebot.apihelper.ApiTelegramException as ex:
            if _is_entity_parse_error(ex):
                kwargs.pop("parse_mode", None)
                return self._send_plain(super().send_message, chat_id,
                                        _strip_markdown(text), **kwargs)
            raise

    def edit_message_text(self, text, chat_id=None, message_id=None,
                          inline_message_id=None, **kwargs):
        try:
            return super().edit_message_text(text, chat_id=chat_id, message_id=message_id,
                                             inline_message_id=inline_message_id, **kwargs)
        except telebot.apihelper.ApiTelegramException as ex:
            if _is_entity_parse_error(ex) and inline_message_id is None:
                kwargs.pop("parse_mode", None)
                return self._send_plain(super().edit_message_text, _strip_markdown(text),
                                        chat_id=chat_id, message_id=message_id, **kwargs)
            raise

    def edit_message_caption(self, caption, chat_id=None, message_id=None,
                             inline_message_id=None, **kwargs):
        try:
            return super().edit_message_caption(caption, chat_id=chat_id, message_id=message_id,
                                                inline_message_id=inline_message_id, **kwargs)
        except telebot.apihelper.ApiTelegramException as ex:
            if _is_entity_parse_error(ex) and inline_message_id is None:
                kwargs.pop("parse_mode", None)
                return self._send_plain(super().edit_message_caption, _strip_markdown(caption),
                                        chat_id=chat_id, message_id=message_id, **kwargs)
            raise

    def send_document(self, chat_id, document, **kwargs):
        try:
            return super().send_document(chat_id, document, **kwargs)
        except telebot.apihelper.ApiTelegramException as ex:
            if _is_entity_parse_error(ex):
                caption = kwargs.get("caption")
                if caption:
                    kwargs["caption"] = _strip_markdown(caption)
                kwargs.pop("parse_mode", None)
                return self._send_plain(super().send_document, chat_id, document, **kwargs)
            raise


try:
    bot = _SafeTeleBot(
        BOT_TOKEN,
        threaded          = True,
        parse_mode        = "Markdown",
        exception_handler = _VisibleErrorHandler(),
    )
except Exception as e:
    log.critical("Telegram init failed", str(e))
    sys.exit(1)

log.ok("Telegram bot initialized")


# Telegram displays these in its native slash-command picker. Keep this list
# limited to safe, user-facing shortcuts; administration remains permission
# checked and intentionally undiscoverable to ordinary users.
_COMMAND_MENU = (
    ("start", "Open the bot"),
    ("menu", "Show the main menu"),
    ("cancel", "Cancel the current action"),
    ("help", "Command help"),
    ("status", "Account and bot status"),
    ("setgithub", "Connect GitHub (private chat)"),
    ("accounts", "Manage multiple GitHub accounts"),
    ("disconnectgithub", "Remove saved GitHub connection"),
    ("setai", "Connect an AI provider (private chat)"),
    ("list_repos", "List your repositories"),
    ("create_new_repo", "Create a repository"),
    ("delete_repo", "Delete a repository"),
    ("replace_repo", "Clear a repo's files, keep the repo"),
    ("upload", "Upload files/folders into a repo"),
    ("preview", "Live preview of a repo's website"),
    ("import_repo", "Fork/import a repository"),
    ("star_repo", "Star a GitHub repository"),
    ("models", "View available AI models"),
    ("support", "Contact support"),
    ("language", "Change language"),
    ("timezone", "Set your timezone"),
)


def _register_command_menu() -> None:
    """Best-effort native command menu registration; never blocks startup."""
    try:
        bot.set_my_commands([BotCommand(command, description) for command, description in _COMMAND_MENU])
        log.ok("Telegram command menu registered", f"{len(_COMMAND_MENU)} commands")
    except Exception as exc:
        log.warn("Could not register Telegram command menu", f"{type(exc).__name__}: {exc}")


def _safe_user_error(uid: int, operation: str, exc: Exception | None = None,
                     message_id: int | None = None) -> None:
    """Log diagnostics privately and show users no internal error details."""
    if exc is not None:
        log.error(f"{operation} failed", f"{type(exc).__name__}: {exc}")
    text = (
        f"⚠️ {operation} could not be completed right now.\n\n"
        "Please try again in a moment. If it continues, contact support with the time it happened."
    )
    try:
        if message_id:
            bot.edit_message_text(text, uid, message_id, reply_markup=kb_home_only(uid))
        else:
            bot.send_message(uid, text, reply_markup=kb_home_only(uid))
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────
#  State machine
# ─────────────────────────────────────────────────────────────

class State(str, Enum):
    IDLE                      = "idle"
    # ── Create New Repo ──────────────────────────────────────
    CREATE_NAME               = "create_name"
    CREATE_DESC               = "create_desc"
    CREATE_DESC_AWAIT         = "create_desc_await"
    CREATE_VISIBILITY         = "create_visibility"
    CREATE_FILES              = "create_files"
    CREATE_FILES_UPLOAD       = "create_files_upload"
    CREATE_FILES_NAME         = "create_files_name"
    CREATE_FILES_CONTENT      = "create_files_content"
    CREATE_FILES_MULTI_NAMES  = "create_files_multi_names"
    CREATE_FILES_MULTI_CONTENT= "create_files_multi_content"
    CREATE_AI_FILES           = "create_ai_files"
    CREATE_CONFIRM            = "create_confirm"
    # ── Archive Upload — Single ───────────────────────────────
    ARCHIVE_UPLOAD            = "archive_upload"       # waiting for 1 archive file
    ARCHIVE_NAME              = "archive_name"         # waiting for repo name
    ARCHIVE_DESC              = "archive_desc"         # waiting for description
    ARCHIVE_DESC_AWAIT        = "archive_desc_await"   # waiting for AI rewrite choice
    ARCHIVE_VISIBILITY        = "archive_visibility"   # waiting for visibility choice
    ARCHIVE_AI_README         = "archive_ai_readme"    # waiting for README rewrite choice
    ARCHIVE_CONFIRM           = "archive_confirm"      # final confirm before push
    ARCHIVE_PASSWORD          = "archive_password"        # waiting for password (single)
    ARCHIVE_MULTI_PASSWORD    = "archive_multi_password"  # waiting for password (multi)
    # ── Archive Upload — Multiple ─────────────────────────────
    ARCHIVE_MULTI_COLLECT     = "archive_multi_collect"  # collecting multiple archives
    ARCHIVE_MULTI_NAME        = "archive_multi_name"     # asking name for current archive
    ARCHIVE_MULTI_DESC        = "archive_multi_desc"     # asking description for current archive
    ARCHIVE_MULTI_DESC_AWAIT  = "archive_multi_desc_await" # waiting AI rewrite for multi
    ARCHIVE_MULTI_README      = "archive_multi_readme"   # asking README choice for current archive
    ARCHIVE_MULTI_VIS         = "archive_multi_vis"      # asking visibility for current archive
    # ── Fork Repo ─────────────────────────────────────────────
    FORK_MODE_PICK            = "fork_mode_pick"
    IMPORT_URL                = "import_url"
    IMPORT_CONFIRM            = "import_confirm"
    FORK_MULTI_URLS           = "fork_multi_urls"
    # ── Delete Repo ───────────────────────────────────────────
    DELETE_PICK               = "delete_pick"
    DELETE_CONFIRM            = "delete_confirm"
    # ── Replace Repo Contents (clear without deleting repo) ──
    REPLACE_PICK              = "replace_pick"            # picking a repo to replace
    REPLACE_MENU              = "replace_menu"            # repo chosen: clear-only or clear+upload
    REPLACE_CLEAR_CONFIRM     = "replace_clear_confirm"   # typing the repo name to confirm clearing
    REPLACE_UPLOAD            = "replace_upload"          # waiting for the new archive file
    REPLACE_PASSWORD          = "replace_password"        # password for a protected archive (replace flow)
    # ── Upload to Repo (send files/folders into an existing repo) ─
    UPLOAD_PICK               = "upload_pick"             # picking a repo to upload into
    UPLOAD_PATH               = "upload_path"             # typing the target folder path (optional)
    UPLOAD_MODE               = "upload_mode"             # choosing add-to-repo vs replace-repo files
    UPLOAD_COLLECT            = "upload_collect"          # collecting files/folders for the upload
    # ── Live Preview (GitHub Pages / HTML preview) ────────────
    PREVIEW_PICK              = "preview_pick"            # picking a repo for live preview
    SEC_WARN_UPLOAD           = "sec_warn_upload"         # security warning shown before a direct upload
    # ── Setup ─────────────────────────────────────────────────
    SETUP_GITHUB              = "setup_github"
    SETAI_KEY                 = "setai_key"            # waiting for AI API key after picking provider via button
    # ── Multi-Account Manager (several GitHub accounts, one chat) ─
    ACCOUNTS_ADD_TOKEN        = "accounts_add_token"   # awaiting the token of a NEW GitHub account
    ACCOUNTS_RENAME           = "accounts_rename"      # awaiting a new label for a saved account
    # ── Archive AI name/desc suggest ─────────────────────────
    ARCHIVE_AI_SUGGEST        = "archive_ai_suggest"   # single: choosing from AI suggestions
    ARCHIVE_AI_CUSTOM         = "archive_ai_custom"    # single: typing custom name after AI
    ARCHIVE_AI_DESC_PREVIEW   = "archive_ai_desc_preview"  # single: full description preview before confirm
    ARCHIVE_AI_DESC_EDIT      = "archive_ai_desc_edit"     # single: editing an AI suggestion before confirm
    ARCHM_AI_SUGGEST          = "archm_ai_suggest"     # multi: choosing from AI suggestions
    ARCHM_AI_CUSTOM           = "archm_ai_custom"      # multi: typing custom name after AI
    ARCHM_AI_DESC_PREVIEW     = "archm_ai_desc_preview"    # multi: full description preview before confirm
    ARCHM_AI_DESC_EDIT        = "archm_ai_desc_edit"       # multi: editing an AI suggestion before confirm

    DOWNLOAD_PICK             = "download_pick"         # browsing repo list to download

    DOWNLOAD_CONFIRM          = "download_confirm"      # single download confirm

    # ── Security warning gate ─────────────────────────────────
    SEC_WARN_ARCHIVE          = "sec_warn_archive"      # security warning shown before archive push
    SEC_WARN_CREATE           = "sec_warn_create"       # security warning shown before repo create
    # ── AI Suggestion flow ────────────────────────────────────
    AI_SUGGEST_IDEA           = "ai_suggest_idea"        # waiting for project idea text
    AI_SUGGEST_CONFIRM        = "ai_suggest_confirm"     # reviewing AI suggestions before push
    # ── Edit Repo ─────────────────────────────────────────────
    EDIT_REPO_PICK            = "edit_repo_pick"          # picking a repo to edit
    EDIT_REPO_MENU            = "edit_repo_menu"          # repo edit menu (files/settings)
    EDIT_BROWSE               = "edit_browse"             # browsing repo files/folders
    EDIT_FILE_VIEW            = "edit_file_view"          # viewing file content
    EDIT_FILE_EDIT            = "edit_file_edit"          # editing file content (awaiting text)
    EDIT_FILE_NEW_NAME        = "edit_file_new_name"      # awaiting new file name
    EDIT_FILE_NEW_CONTENT     = "edit_file_new_content"   # awaiting new file content
    EDIT_FILE_MOVE_DEST       = "edit_file_move_dest"     # awaiting move destination path
    EDIT_FOLDER_NEW_NAME      = "edit_folder_new_name"    # awaiting folder name for new folder
    EDIT_FOLDER_FIRST_FILE    = "edit_folder_first_file"  # awaiting first file in new folder
    EDIT_REPO_RENAME          = "edit_repo_rename"        # awaiting new repo name
    EDIT_REPO_DESC            = "edit_repo_desc_edit"     # awaiting new description
    EDIT_REPO_HOMEPAGE        = "edit_repo_homepage"      # awaiting new homepage URL
    EDIT_REPO_TOPICS          = "edit_repo_topics"        # awaiting new topics
    EDIT_BRANCH_NEW           = "edit_branch_new"         # awaiting new branch name
    EDIT_COMMIT_MSG           = "edit_commit_msg"         # awaiting custom commit message
    # ── Admin: support ticket reply (via button, not /reply) ──
    ADMIN_TICKET_REPLY        = "admin_ticket_reply"      # admin's next message is the reply text

# ─────────────────────────────────────────────────────────────
#  Database
# ─────────────────────────────────────────────────────────────

DB_FILE = config.DB_FILE
_PRIVATE_FIELDS = (
    "github_username", "first_name", "last_name", "username",
    "_pending_github_prompt_id", "_pending_ai_prompt_id",
    "_pending_accounts_prompt_id",
)
_SECRET_FIELDS = ("github_token", "ai_key")
_db_lock = threading.RLock()
_runtime_uids: set[int] = set()


def _user_key(uid: int) -> str:
    """Return a stable one-way identifier for persistence."""
    salt = config.DATA_ENCRYPTION_KEY or "local-privacy-salt"
    digest = hashlib.sha256(f"{salt}:{int(uid)}".encode()).hexdigest()
    return f"u_{digest}"


_ACCOUNTS_FIELD = "github_accounts"   # encrypted-at-rest list of saved GitHub accounts


def _persistable_record(rec: dict) -> dict:
    """Encrypt credentials and omit transient/direct profile data before disk I/O."""
    persisted = {
        key: value for key, value in rec.items()
        if key not in _PRIVATE_FIELDS and key not in _SECRET_FIELDS
           and key != _ACCOUNTS_FIELD
    }
    for key in _SECRET_FIELDS:
        value = rec.get(key)
        if value:
            persisted[key] = security.encrypt(str(value))
    # The multi-account list embeds one token per entry, so it is encrypted
    # as a single blob (JSON) exactly like the other secret fields.
    accounts = rec.get(_ACCOUNTS_FIELD)
    if accounts:
        try:
            persisted[_ACCOUNTS_FIELD] = security.encrypt(json.dumps(accounts, ensure_ascii=False))
        except (TypeError, ValueError):
            pass
    return persisted


def _restore_record(rec: dict) -> dict:
    """Restore runtime credentials from encrypted fields in users.json."""
    restored = {key: value for key, value in rec.items() if key not in _PRIVATE_FIELDS}
    for key in _SECRET_FIELDS:
        encrypted = rec.get(key)
        value = security.decrypt(encrypted) if encrypted else None
        if encrypted and str(encrypted).startswith("enc:") and value is None:
            log.warn(f"Could not decrypt saved {key}; check that DATA_ENCRYPTION_KEY is unchanged")
        restored[key] = value
    accounts_blob = rec.get(_ACCOUNTS_FIELD)
    accounts: list = []
    if accounts_blob:
        try:
            decrypted = security.decrypt(accounts_blob)
            loaded = json.loads(decrypted) if decrypted else []
            if isinstance(loaded, list):
                accounts = [
                    acct for acct in loaded
                    if isinstance(acct, dict) and acct.get("token")
                ]
        except (json.JSONDecodeError, TypeError, ValueError):
            accounts = []
        if accounts_blob.startswith("enc:") and not accounts:
            log.warn("Could not decrypt saved github_accounts; check that DATA_ENCRYPTION_KEY is unchanged")
    restored[_ACCOUNTS_FIELD] = accounts
    restored.setdefault("github_active", None)
    return restored


def _delete_pending_prompt(uid: int, field: str) -> None:
    """Delete a temporary credential prompt after the user responds."""
    u = get_user(uid)
    prompt_id = u.pop(field, None)
    if prompt_id:
        try:
            bot.delete_message(uid, prompt_id)
        except Exception:
            pass
        save_user(uid, u)


def _load() -> dict:
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            payload = f.read()
        # New format: the entire database is one authenticated Fernet
        # ciphertext.  Older JSON files are accepted once and migrated on the
        # next save so upgrades do not lose user records.
        if payload.startswith("enc:"):
            decrypted = security.decrypt(payload)
            if decrypted is None:
                log.error("Cannot decrypt users database; DATA_ENCRYPTION_KEY may have changed")
                # Fail closed: returning an empty database here would cause the
                # startup save to overwrite recoverable encrypted user data.
                raise RuntimeError("Cannot decrypt users.json; restore the original DATA_ENCRYPTION_KEY")
            raw = json.loads(decrypted)
        else:
            raw = json.loads(payload)
        cleaned = {}
        for raw_uid, rec in raw.items():
            # Migrate legacy numeric keys and restore encrypted credentials.
            key = _user_key(int(raw_uid)) if str(raw_uid).isdigit() else str(raw_uid)
            cleaned[key] = _restore_record(rec)
        return cleaned
    except (json.JSONDecodeError, OSError) as e:
        log.warn("Corrupted users.json — backing up and resetting", str(e))
        try:
            if os.path.exists(DB_FILE):
                os.replace(DB_FILE, f"{DB_FILE}.corrupt.{int(_time.time())}.bak")
        except OSError:
            pass
        return {}

def _save(data: dict) -> None:
    """Atomically write an authenticated, encrypted database to disk."""
    persisted = {str(uid): _persistable_record(rec) for uid, rec in data.items()}
    if not security.is_enabled():
        # Config validation normally prevents this; never silently downgrade
        # the whole user database to readable plaintext if configuration drifts.
        raise RuntimeError("DATA_ENCRYPTION_KEY is required to save users.json securely")
    payload = security.encrypt(json.dumps(persisted, ensure_ascii=False))
    tmp_path = f"{DB_FILE}.tmp.{os.getpid()}"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, DB_FILE)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
    flog.debug("DB saved")

with _db_lock:
    _db: dict = _load()
            # Migrate legacy raw IDs and rewrite credentials as ciphertext.
    _save(_db)
if not security.is_enabled():
    log.warn("DATA_ENCRYPTION_KEY not set — secrets will be stored in PLAINTEXT.",
              "Run: python -c \"from security import generate_key; print(generate_key())\"")
log.ok(f"Database loaded", f"{len(_db)} users")

def get_user(uid: int) -> dict:
    key = _user_key(uid)
    _runtime_uids.add(int(uid))
    with _db_lock:
        if key not in _db:
            _db[key] = {
                "welcomed":        False,
                "github_token":    None,
                "github_username": None,
                "github_accounts": [],      # multi-account manager: every saved account
                "github_active":   None,    # label of the currently active account
                "ai_provider":     None,
                "ai_key":          None,
                "ai_model":        None,
                "state":           State.IDLE,
                "draft":         {},
                "history":          [],
                "repos_created":     0,
                "repos_deleted":     0,
                "nav_stack":         [],
                "repos_forked":      0,
                "repos_starred":     0,
                "archives_uploaded": 0,
                "files_pushed":      0,
                "pending_tickets":   [],
                "language":          "en",
                "language_selected": False,
                "time_zone":         "UTC",
                "created_at":        datetime.now(timezone.utc).isoformat(),
            }
            _save(_db)
        else:
            # Restore optional fields for older records.
            record = _db[key]
            record.setdefault("github_token", None)
            record.setdefault("github_username", None)
            record.setdefault("github_accounts", [])
            record.setdefault("github_active", None)
            record.setdefault("ai_key", None)
            record.setdefault("ai_provider", None)
            record.setdefault("ai_model", None)
            record.setdefault("language", "en")
            record.setdefault("language_selected", False)
            record.setdefault("time_zone", "UTC")
            # Keys handlers index DIRECTLY (not via .get) — a legacy record
            # missing any of these would crash add_history / nav_push /
            # cmd_start / the state machine.
            record.setdefault("welcomed", False)
            record.setdefault("state", State.IDLE)
            record.setdefault("draft", {})
            record.setdefault("history", [])
            record.setdefault("nav_stack", [])
            record.setdefault("pending_tickets", [])
        return _db[key]


def _tr(uid: int, key: str, **values) -> str:
    """Translate a UI string using the user's saved language."""
    language = get_user(uid).get("language", "en") if uid else "en"
    return translate(language, key, **values)


def _user_timezone(uid: int) -> ZoneInfo:
    try:
        return ZoneInfo(get_user(uid).get("time_zone", "UTC"))
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")

def save_user(uid: int, data: dict) -> None:
    with _db_lock:
        _runtime_uids.add(int(uid))
        _db[_user_key(uid)] = data
        _save(_db)

def add_history(uid: int, entry: str) -> None:
    u  = get_user(uid)
    u["history"].append({
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "text": str(entry),
    })
    u["history"] = u["history"][-50:]
    save_user(uid, u)

def _bump(uid: int, key: str, by: int = 1) -> None:
    """Atomically increment a stats counter (thread-safe read-modify-write)."""
    with _db_lock:
        u = get_user(uid)
        u[key] = u.get(key, 0) + by
        save_user(uid, u)


# ─────────────────────────────────────────────────────────────
#  Admin helpers
# ─────────────────────────────────────────────────────────────

def is_admin(uid: int) -> bool:
    """Return True if uid is in the admin list."""
    return uid in ADMIN_IDS


def _public_user_stats(uid: int) -> dict:
    """\n    Return account status and usage counts for the admin panel.\n    User-configured integrations, profile data, history, and drafts are excluded.\n    """
    u = get_user(uid)
    return {
        "uid":           uid,
        "repos_created": u.get("repos_created", 0),
        "repos_deleted": u.get("repos_deleted", 0),
        "repos_forked":  u.get("repos_forked", 0),
        "archives_up":   u.get("archives_uploaded", 0),
        "banned":        is_banned(uid),
        "is_admin":      u.get("is_admin", False) or (uid in ADMIN_IDS),
        "created_at":    u.get("created_at", "")[:10],
    }


def promote_admin(uid: int) -> None:
    """Grant admin role to a user (runtime list + stored flag)."""
    if uid not in ADMIN_IDS:
        ADMIN_IDS.append(uid)
    u = get_user(uid)
    u["is_admin"] = True
    save_user(uid, u)


def demote_admin(uid: int) -> None:
    """Remove admin role (cannot remove primary ADMIN_CHAT_ID)."""
    if uid == ADMIN_CHAT_ID:
        return  # primary admin is permanent
    if uid in ADMIN_IDS:
        ADMIN_IDS.remove(uid)
    u = get_user(uid)
    u["is_admin"] = False
    save_user(uid, u)


_BAN_DURATIONS = {
    "1h": (60 * 60, "1 hour"),
    "24h": (24 * 60 * 60, "24 hours"),
    "7d": (7 * 24 * 60 * 60, "7 days"),
    "permanent": (None, "permanently"),
}


def ban_user(uid: int, duration_seconds: Optional[int] = None) -> None:
    u = get_user(uid)
    u["banned"] = True
    u["banned_until"] = _time.time() + duration_seconds if duration_seconds else None
    save_user(uid, u)


def unban_user(uid: int) -> None:
    u = get_user(uid)
    u["banned"] = False
    u.pop("banned_until", None)
    save_user(uid, u)


def is_banned(uid: int) -> bool:
    u = get_user(uid)
    if not u.get("banned", False):
        return False
    expires_at = u.get("banned_until")
    if expires_at is not None and expires_at <= _time.time():
        unban_user(uid)
        return False
    return True


# ─────────────────────────────────────────────────────────────
#  Ban gate — call at top of every handler
# ─────────────────────────────────────────────────────────────

def _check_banned(uid: int) -> bool:
    """Send banned message and return True if user is banned."""
    if is_banned(uid):
        try:
            bot.send_message(uid,
                "🚫 *Your account has been suspended.*\n\n"
                "Contact support if you believe this is a mistake.",
                parse_mode="Markdown")
        except Exception:
            pass
        return True
    return False

# Each entry: {"state": str, "data": callback_data_str, "label": display_label}
# "data"  = the callback_data that re-renders that screen
# "label" = human-readable name shown in log

def nav_push(uid: int, data: str, label: str = "") -> None:
    """Push the current screen onto the navigation stack."""
    u     = get_user(uid)
    stack = u.get("nav_stack", [])
    entry = {"data": data, "label": label or data}
    # Avoid duplicate consecutive entries
    if not stack or stack[-1]["data"] != data:
        stack.append(entry)
    # Keep stack bounded
    if len(stack) > 20:
        stack = stack[-20:]
    u["nav_stack"] = stack
    save_user(uid, u)


def nav_pop(uid: int) -> Optional[dict]:
    """Pop and return the last entry; returns None if stack is empty."""
    u     = get_user(uid)
    stack = u.get("nav_stack", [])
    if not stack:
        return None
    entry = stack.pop()
    u["nav_stack"] = stack
    save_user(uid, u)
    return entry


def nav_clear(uid: int) -> None:
    """Clear the entire navigation stack (used on Home/Cancel)."""
    u = get_user(uid)
    u["nav_stack"] = []
    save_user(uid, u)


def nav_peek(uid: int) -> Optional[dict]:
    """Peek at the top of the stack without popping."""
    u     = get_user(uid)
    stack = u.get("nav_stack", [])
    return stack[-1] if stack else None


def set_state(uid: int, state: State, draft: Optional[dict] = None) -> None:
    u = get_user(uid)
    u["state"] = state
    if draft is not None:
        u["draft"] = draft
    save_user(uid, u)

def get_state(uid: int) -> State:
    return State(get_user(uid).get("state", State.IDLE))

# ─────────────────────────────────────────────────────────────
#  Keyboards
# ─────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────
#  Admin keyboards
# ─────────────────────────────────────────────────────────────

def kb_admin_main() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("👥 User List",       callback_data="admin_users_0"),
        InlineKeyboardButton("📊 Bot Stats",        callback_data="admin_stats"),
        InlineKeyboardButton("📢 Broadcast",        callback_data="admin_broadcast"),
        InlineKeyboardButton("🎫 Support Tickets",  callback_data="admin_tickets"),
        InlineKeyboardButton("🩺 System Health",    callback_data="admin_health"),
        InlineKeyboardButton("📈 Analytics",        callback_data="admin_analytics"),
        InlineKeyboardButton("🔄 Refresh",          callback_data="admin_panel"),
        InlineKeyboardButton("🏠 Home",             callback_data="menu_home"),
    )
    return kb

def kb_admin_user(uid: int, viewer_uid: int = 0, return_page: int = 0) -> InlineKeyboardMarkup:
    kb  = InlineKeyboardMarkup(row_width=2)
    u   = get_user(uid)
    banned = is_banned(uid)
    ban_label    = "✅ Unban"   if banned else "🚫 Ban"
    ban_cb       = f"admin_unban_{uid}_{return_page}" if banned else f"admin_ban_{uid}_{return_page}"
    is_adm       = u.get("is_admin", False) or (uid in ADMIN_IDS)
    adm_label    = "⬇️ Demote Admin" if is_adm else "⬆️ Promote Admin"
    adm_cb       = f"admin_demote_{uid}_{return_page}" if is_adm else f"admin_promote_{uid}_{return_page}"
    row = [InlineKeyboardButton(ban_label, callback_data=ban_cb)]
    # Only the primary admin can grant/revoke admin rights — showing this
    # button to other admins would just produce an "access denied" tap.
    if viewer_uid == ADMIN_CHAT_ID and uid != ADMIN_CHAT_ID:
        row.append(InlineKeyboardButton(adm_label, callback_data=adm_cb))
    kb.add(*row)
    kb.add(
        InlineKeyboardButton("◀ Back",  callback_data=f"admin_users_{return_page}"),
        InlineKeyboardButton("🏠 Home", callback_data="menu_home"),
    )
    return kb


def kb_admin_ban_durations(uid: int, return_page: int = 0) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    labels = {"1h": "1 hour", "24h": "24 hours", "7d": "7 days", "permanent": "Permanent"}
    for code, label in labels.items():
        kb.add(InlineKeyboardButton(label, callback_data=f"admin_banfor_{code}_{uid}_{return_page}"))
    kb.add(
        InlineKeyboardButton("◀ Cancel", callback_data=f"admin_view_{uid}_{return_page}"),
        InlineKeyboardButton("🏠 Home", callback_data="menu_home"),
    )
    return kb

def kb_admin_back() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("◀ Back to Admin", callback_data="admin_panel"),
        InlineKeyboardButton("🏠 Home",          callback_data="menu_home"),
    )
    return kb


def _admin_bar(value: int, maximum: int, width: int = 12) -> str:
    """Small fixed-width graph for Telegram; never includes private data."""
    maximum = max(1, maximum)
    filled = max(0, min(width, round(width * max(0, value) / maximum)))
    return "█" * filled + "░" * (width - filled)


def _admin_analytics_text() -> str:
    """Build aggregate, privacy-safe admin analytics and host storage health."""
    with _db_lock:
        users = list(_db.values())
    total = len(users)
    banned = sum(bool(user.get("banned")) for user in users)
    tickets = sum(bool(user.get("pending_tickets")) for user in users)
    github_ready = sum(bool(user.get("github_token")) for user in users)
    ai_ready = sum(bool(user.get("ai_provider") and user.get("ai_key")) for user in users)
    actions = [
        int(user.get("repos_created", 0) or 0) + int(user.get("archives_uploaded", 0) or 0)
        for user in users
    ]
    active = sum(action > 0 for action in actions)
    total_actions = sum(actions)
    db_bytes = os.path.getsize(DB_FILE) if os.path.exists(DB_FILE) else 0
    disk = shutil.disk_usage(os.path.dirname(os.path.abspath(DB_FILE)) or ".")
    used_pct = round((disk.used / max(1, disk.total)) * 100)
    uptime = int(_time.time() - _APP_STARTED_AT)
    scale = max(total, active, github_ready, ai_ready, banned, tickets, 1)
    return (
        "📈 *Admin Analytics*\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        "*User usage*\n"
        f"Active users  `{_admin_bar(active, scale)}` *{active}/{total}*\n"
        f"GitHub ready  `{_admin_bar(github_ready, scale)}` *{github_ready}/{total}*\n"
        f"AI ready      `{_admin_bar(ai_ready, scale)}` *{ai_ready}/{total}*\n"
        f"Banned        `{_admin_bar(banned, scale)}` *{banned}*\n"
        f"Tickets       `{_admin_bar(tickets, scale)}` *{tickets}*\n\n"
        "*Bot and server*\n"
        f"Repository actions: *{total_actions}*\n"
        f"Database ciphertext: *{db_bytes / 1024:.1f} KB*\n"
        f"Host disk used: `{_admin_bar(used_pct, 100)}` *{used_pct}%*\n"
        f"Bot uptime: `{uptime // 3600}h {(uptime % 3600) // 60}m`\n\n"
        "_Graphs use aggregate counters only; no user secrets, file names, tokens, or message content are analyzed._"
    )


def kb_admin_tickets() -> InlineKeyboardMarkup:
    """List every user with at least one open (unanswered) support ticket."""
    kb = InlineKeyboardMarkup(row_width=1)
    open_tickets = [
        (known_uid, get_user(known_uid).get("pending_tickets", []))
        for known_uid in sorted(_runtime_uids)
        if get_user(known_uid).get("pending_tickets")
    ]
    if not open_tickets:
        kb.add(InlineKeyboardButton("✅ No open tickets", callback_data="admin_noop"))
    else:
        # Oldest first, so the ticket that's waited longest surfaces at the top.
        open_tickets.sort(key=lambda t: t[1][0].get("created_at", ""))
        for target_uid, tickets in open_tickets[:25]:
            label = f"🎫 {target_uid}  ({len(tickets)} msg{'s' if len(tickets) != 1 else ''})"
            kb.add(InlineKeyboardButton(label, callback_data=f"admin_ticket_view_{target_uid}"))
    kb.add(
        InlineKeyboardButton("◀ Back to Admin", callback_data="admin_panel"),
        InlineKeyboardButton("🏠 Home",          callback_data="menu_home"),
    )
    return kb


def kb_admin_ticket_detail(target_uid: int) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("💬 Reply", callback_data=f"admin_ticket_reply_{target_uid}"),
        InlineKeyboardButton("🗑 Dismiss (no reply)", callback_data=f"admin_ticket_dismiss_{target_uid}"),
        InlineKeyboardButton("◀ Back to Tickets", callback_data="admin_tickets"),
        InlineKeyboardButton("🏠 Home", callback_data="menu_home"),
    )
    return kb

def kb_admin_users(page: int = 0) -> InlineKeyboardMarkup:
    kb         = InlineKeyboardMarkup(row_width=1)
    all_uids   = sorted(_runtime_uids)
    page_size  = 10
    start      = page * page_size
    end        = min(start + page_size, len(all_uids))
    for raw_uid in all_uids[start:end]:
        s     = _public_user_stats(raw_uid)
        badge = "🚫" if s["banned"] else ("👑" if s["is_admin"] else "👤")
        label = f"{badge} {s['uid']} · 📦{s['repos_created']}"
        kb.add(InlineKeyboardButton(label, callback_data=f"admin_view_{raw_uid}_{page}"))
    total_pages = max(1, (len(all_uids) + page_size - 1) // page_size)
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("◀ Prev", callback_data=f"admin_users_{page-1}"))
    nav.append(InlineKeyboardButton(f"📄 {page+1}/{total_pages}", callback_data="admin_noop"))
    if end < len(all_uids):
        nav.append(InlineKeyboardButton("Next ▶", callback_data=f"admin_users_{page+1}"))
    if nav:
        kb.row(*nav)
    kb.add(
        InlineKeyboardButton("◀ Back", callback_data="admin_panel"),
        InlineKeyboardButton("🏠 Home", callback_data="menu_home"),
    )
    return kb


def kb_home_only(uid: int = 0) -> InlineKeyboardMarkup:
    """Single 🏠 Home button — used on result screens."""
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton(f"🏠 {_tr(uid, 'home')}", callback_data="menu_home"))
    return kb


def kb_language_picker(uid: int) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    for code, label in LANGUAGES.items():
        kb.add(InlineKeyboardButton(label, callback_data=f"lang_{code}"))
    kb.add(InlineKeyboardButton(f"🏠 {_tr(uid, 'home')}", callback_data="menu_home"))
    return kb

_TIME_ZONE_OPTIONS = {
    "UTC": "UTC",
    "Asia/Kolkata": "India (Kolkata)",
    "Asia/Dhaka": "Bangladesh (Dhaka)",
    "Asia/Karachi": "Pakistan (Karachi)",
    "Asia/Dubai": "UAE (Dubai)",
    "Asia/Tokyo": "Japan (Tokyo)",
    "Europe/London": "UK (London)",
    "Europe/Paris": "Central Europe (Paris)",
    "Africa/Cairo": "Egypt (Cairo)",
    "America/New_York": "US Eastern (New York)",
    "America/Chicago": "US Central (Chicago)",
    "America/Los_Angeles": "US Pacific (Los Angeles)",
    "Australia/Sydney": "Australia (Sydney)",
}


def kb_timezone_picker(uid: int) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    for zone, label in _TIME_ZONE_OPTIONS.items():
        kb.add(InlineKeyboardButton(label, callback_data=f"tz_{zone}"))
    kb.add(InlineKeyboardButton(_tr(uid, "home"), callback_data="menu_home"))
    return kb


def _kb_main_body(kb: InlineKeyboardMarkup, uid: int) -> InlineKeyboardMarkup:
    """Shared button layout for the main menu, grouped into clear sections\n    instead of one flat undifferentiated grid. Used by both kb_main (which\n    adds a Home row on top) and kb_main_noback (which doesn't)."""
    # ── Repo actions — the core, most-used workflows ────────────
    kb.row(
        InlineKeyboardButton(f"📦 {_tr(uid, 'new_repo')}", callback_data="menu_create"),
        InlineKeyboardButton(f"✨ {_tr(uid, 'ai_suggest')}", callback_data="menu_ai_suggest"),
    )
    kb.row(
        InlineKeyboardButton(f"📦 {_tr(uid, 'archive')}", callback_data="files_archive_upload"),
        InlineKeyboardButton(f"📥 {_tr(uid, 'fork')}", callback_data="menu_import"),
    )
    kb.row(
        InlineKeyboardButton(f"📤 {_tr(uid, 'upload_files')}", callback_data="menu_upload_files"),
        InlineKeyboardButton(f"👁 {_tr(uid, 'live_preview')}", callback_data="menu_live_preview"),
    )
    kb.row(
        InlineKeyboardButton(f"📋 {_tr(uid, 'my_repos')}", callback_data="menu_repos"),
        InlineKeyboardButton(f"✏️ {_tr(uid, 'edit_repo')}", callback_data="menu_edit_repo"),
    )
    kb.row(
        InlineKeyboardButton(f"⬇️ {_tr(uid, 'download')}", callback_data="menu_download"),
        InlineKeyboardButton(f"⭐ {_tr(uid, 'star')}", callback_data="menu_star"),
    )
    kb.row(
        InlineKeyboardButton(f"🗑 {_tr(uid, 'delete')}", callback_data="menu_delete"),
        InlineKeyboardButton(f"♻️ {_tr(uid, 'replace')}", callback_data="menu_replace_repo"),
    )

    # ── Info & AI — reference material, no side effects ─────────
    kb.row(
        InlineKeyboardButton(f"📊 {_tr(uid, 'status')}", callback_data="menu_status"),
        InlineKeyboardButton(f"👥 {_tr(uid, 'accounts')}", callback_data="menu_accounts"),
    )
    kb.row(
        InlineKeyboardButton(f"🤖 {_tr(uid, 'models')}", callback_data="menu_models"),
        InlineKeyboardButton(f"🧩 {_tr(uid, 'extras')}", callback_data="menu_extras"),
    )
    kb.row(InlineKeyboardButton(f"📜 {_tr(uid, 'history')}", callback_data="menu_history"))
    kb.row(
        InlineKeyboardButton(f"📚 {_tr(uid, 'help')}", callback_data="menu_help"),
        InlineKeyboardButton(f"📖 {_tr(uid, 'guide')}", callback_data="menu_guide"),
    )

    # ── Account — setup & support ────────────────────────────────
    kb.row(
        InlineKeyboardButton(f"⚙️ {_tr(uid, 'setup')}", callback_data="menu_setup"),
        InlineKeyboardButton(f"🎫 {_tr(uid, 'support')}", callback_data="menu_support"),
    )
    kb.row(InlineKeyboardButton(f"🌐 {_tr(uid, 'language')}", callback_data="menu_language"))
    kb.row(InlineKeyboardButton(_tr(uid, "timezone"), callback_data="menu_timezone"))
    if uid and is_admin(uid):
        kb.row(InlineKeyboardButton(f"🛡 {_tr(uid, 'admin')}", callback_data="admin_panel"))
    return kb


def kb_main(uid: int = 0) -> InlineKeyboardMarkup:
    """Main menu. Do not add a Home button to the Home screen itself."""
    kb = InlineKeyboardMarkup(row_width=2)
    return _kb_main_body(kb, uid)

def kb_main_noback(uid: int = 0) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    return _kb_main_body(kb, uid)

def kb_visibility() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup()
    kb.add(
        InlineKeyboardButton("🌍 Public",  callback_data="vis_public"),
        InlineKeyboardButton("🔒 Private", callback_data="vis_private"),
    )
    return kb

def kb_archive_visibility() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("🌍 Public",  callback_data="arch_vis_public"),
        InlineKeyboardButton("🔒 Private", callback_data="arch_vis_private"),
    )
    kb.add(
        InlineKeyboardButton("◀ Back",  callback_data="files_archive_upload"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb

def kb_archive_multi_visibility() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("🌍 Public",  callback_data="archm_vis_public"),
        InlineKeyboardButton("🔒 Private", callback_data="archm_vis_private"),
    )
    kb.add(
        InlineKeyboardButton("◀ Back",  callback_data="files_archive_upload"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb

def kb_ai_files(has_readme: bool = False) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup()
    if has_readme:
        kb.add(InlineKeyboardButton("✍️ Rewrite README + generate .gitignore", callback_data="ai_yes"))
        kb.add(InlineKeyboardButton("✍️ Rewrite README only",                   callback_data="ai_readme_only"))
    else:
        kb.add(InlineKeyboardButton("✨ Generate README + .gitignore",           callback_data="ai_yes"))
        kb.add(InlineKeyboardButton("📄 Generate README only",                   callback_data="ai_readme_only"))
    kb.add(InlineKeyboardButton("⏭ Skip — no AI files",                         callback_data="ai_no"))
    return kb

def kb_confirm(action: str) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(InlineKeyboardButton("✅ Confirm", callback_data=f"confirm_{action}"))
    kb.add(
        InlineKeyboardButton("◀ Back",  callback_data="cancel"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb

def kb_repo_picker(repos: list, action: str, selected: set = None) -> InlineKeyboardMarkup:
    kb       = InlineKeyboardMarkup(row_width=1)
    selected = selected or set()
    for r in repos[:15]:
        vis  = "🔒" if r["private"] else "🌍"
        name = r["name"]
        tick = "✅ " if name in selected else ""
        kb.add(InlineKeyboardButton(f"{tick}{vis} {name}", callback_data=f"{action}_repo_{name}"))
    if action == "del":
        all_names = {r["name"] for r in repos[:15]}
        if selected >= all_names:
            kb.add(InlineKeyboardButton("☑️ Deselect All", callback_data="del_deselect_all"))
        else:
            kb.add(InlineKeyboardButton("☑️ Select All",   callback_data="del_select_all"))
        if selected:
            kb.add(InlineKeyboardButton(f"🗑 Delete Selected ({len(selected)})", callback_data="del_confirm_selected"))
        kb.add(
            InlineKeyboardButton("◀ Back",    callback_data="menu_delete"),
            InlineKeyboardButton("🏠 Home",      callback_data="menu_home"),
        )
    else:
        kb.add(InlineKeyboardButton("\U0001f3e0 Home", callback_data="menu_home"))
    return kb


# ─────────────────────────────────────────────────────────────
#  Download Repo — keyboards
# ─────────────────────────────────────────────────────────────

_DL_PAGE_SIZE = 8   # repos shown per page

def kb_download_picker(repos: list, page: int, selected: set) -> InlineKeyboardMarkup:
    """\n    Paginated repo picker for download.\n    Each repo shown as a tappable button.  Selected ones have ✅.\n    Nav: ◀ Prev / Next ▶, Select All / Deselect All, ⬇️ Download, Home.\n    """
    kb        = InlineKeyboardMarkup(row_width=1)
    total     = len(repos)
    start     = page * _DL_PAGE_SIZE
    end       = min(start + _DL_PAGE_SIZE, total)
    page_repos = repos[start:end]

    for r in page_repos:
        vis  = "🔒" if r.get("private") else "🌍"
        name = r["name"]
        tick = "✅ " if name in selected else ""
        kb.add(InlineKeyboardButton(
            f"{tick}{vis} {name}",
            callback_data=f"dl_toggle_{name}",
        ))

    # Pagination row
    total_pages = max(1, (total + _DL_PAGE_SIZE - 1) // _DL_PAGE_SIZE)
    nav_btns = []
    if page > 0:
        nav_btns.append(InlineKeyboardButton("◀ Prev", callback_data=f"dl_page_{page-1}"))
    nav_btns.append(InlineKeyboardButton(f"📄 {page+1}/{total_pages}", callback_data="dl_noop"))
    if end < total:
        nav_btns.append(InlineKeyboardButton("Next ▶", callback_data=f"dl_page_{page+1}"))
    kb.row(*nav_btns)

    # Select all / deselect all
    all_names = {r["name"] for r in repos}
    if selected >= all_names:
        kb.add(InlineKeyboardButton("☑️ Deselect All", callback_data="dl_deselect_all"))
    else:
        kb.add(InlineKeyboardButton("☑️ Select All",   callback_data="dl_select_all"))

    # Action row
    if selected:
        lbl = f"⬇️ Download ({len(selected)})" if len(selected) > 1 else "⬇️ Download"
        kb.add(InlineKeyboardButton(lbl, callback_data="dl_execute"))
    kb.add(InlineKeyboardButton("\U0001f3e0 Home", callback_data="menu_home"))
    return kb

def kb_download_result() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("⬇️ Download More", callback_data="menu_download"),
        InlineKeyboardButton("🏠 Home",          callback_data="menu_home"),
    )
    return kb

def kb_desc_choice() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup()
    kb.add(
        InlineKeyboardButton("🤖 Rewrite with AI", callback_data="desc_ai_rewrite"),
        InlineKeyboardButton("✅ Use original",     callback_data="desc_use_original"),
    )
    return kb

def kb_archive_desc_step() -> InlineKeyboardMarkup:
    """Shown right after repo name in archive flow — mirror of create-repo desc step."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("✏️ Type description",  callback_data="arch_desc_type"),
        InlineKeyboardButton("⏭ Skip",               callback_data="arch_desc_skip"),
        InlineKeyboardButton("◀ Back",             callback_data="files_archive_upload"),
        InlineKeyboardButton("🏠 Home",               callback_data="menu_home"),
    )
    return kb

def kb_archive_desc_choice() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup()
    kb.add(
        InlineKeyboardButton("🤖 Rewrite with AI", callback_data="arch_desc_ai_rewrite"),
        InlineKeyboardButton("✅ Use original",     callback_data="arch_desc_use_original"),
    )
    return kb

def kb_archive_multi_desc_choice() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup()
    kb.add(
        InlineKeyboardButton("🤖 Rewrite with AI", callback_data="archm_desc_ai"),
        InlineKeyboardButton("✅ Use original",     callback_data="archm_desc_keep"),
    )
    return kb

def kb_desc_step() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("✏️ Type description",  callback_data="desc_type"),
        InlineKeyboardButton("⏭ Skip",              callback_data="desc_skip"),
        InlineKeyboardButton("◀ Back",            callback_data="menu_create"),
        InlineKeyboardButton("🏠 Home",              callback_data="menu_home"),
    )
    return kb

def kb_files_step() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("📤 Upload File(s)",  callback_data="files_upload"),
        InlineKeyboardButton("📝 Create new file", callback_data="files_create"),
        InlineKeyboardButton("⏭ Skip",            callback_data="files_skip"),
        InlineKeyboardButton("◀ Back",          callback_data="menu_create"),
        InlineKeyboardButton("🏠 Home",            callback_data="menu_home"),
    )
    return kb

def kb_files_more() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("📤 Upload another",   callback_data="files_upload"),
        InlineKeyboardButton("📝 Create another",   callback_data="files_create"),
        InlineKeyboardButton("✅ Done — next step", callback_data="files_done"),
        InlineKeyboardButton("🏠 Home",             callback_data="menu_home"),
    )
    return kb

def kb_files_continue() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("✅ Done — next step", callback_data="files_done"),
        InlineKeyboardButton("🏠 Home",             callback_data="menu_home"),
    )
    return kb

def kb_create_mode() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("📄 Single File",    callback_data="create_single"),
        InlineKeyboardButton("📚 Multiple Files", callback_data="create_multi"),
        InlineKeyboardButton("◀ Back",          callback_data="menu_create"),
        InlineKeyboardButton("🏠 Home",            callback_data="menu_home"),
    )
    return kb

def kb_multi_next(current: int, total: int) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton(f"⏭ Skip this file ({current}/{total})", callback_data="multi_skip_file"),
        InlineKeyboardButton("🏠 Home", callback_data="menu_home"),
    )
    return kb

# ── Archive upload mode picker ───────────────────────────────
def kb_archive_mode() -> InlineKeyboardMarkup:
    """Shown when user clicks Archive Upload — pick Single or Multiple.\n    AI assistance is asked as a separate Yes/No question right after this."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("📁 Single Archive",                callback_data="arch_mode_single"),
        InlineKeyboardButton("📚 Multiple Archives (up to 100)", callback_data="arch_mode_multi"),
        InlineKeyboardButton("\U0001f3e0 Home", callback_data="menu_home"),
    )
    return kb

def kb_archive_use_ai(target: str) -> InlineKeyboardMarkup:
    """Yes/No confirmation: 'Do you want to use AI assistance for this upload?'\n    `target` is 'single' or 'multi' — never forces AI on the user."""
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("🤖 Yes, use AI", callback_data=f"arch_ai_confirm:{target}:yes"),
        InlineKeyboardButton("🚫 No, skip AI", callback_data=f"arch_ai_confirm:{target}:no"),
    )
    kb.add(InlineKeyboardButton("◀ Back", callback_data="files_archive_upload"))
    return kb

def kb_archive_single_prompt() -> InlineKeyboardMarkup:
    """Shown in Single Archive Upload — waiting for file."""
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("◀ Back",  callback_data="files_archive_upload"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb

def kb_archive_multi_collecting(count: int) -> InlineKeyboardMarkup:
    """Shown while user is sending archives in multi mode."""
    kb = InlineKeyboardMarkup(row_width=1)
    if count > 0:
        kb.add(InlineKeyboardButton(f"✅ Done — Process {count} Archive(s)", callback_data="archm_done_collecting"))
    kb.add(
        InlineKeyboardButton("◀ Back",  callback_data="files_archive_upload"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb

def kb_archive_multi_name_step() -> InlineKeyboardMarkup:
    """Shown right after archive info in multi-archive flow — ask for repo name."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("✏️ Type repo name",   callback_data="archm_name_type"),
        InlineKeyboardButton("◀ Back",            callback_data="files_archive_upload"),
        InlineKeyboardButton("🏠 Home",              callback_data="menu_home"),
    )
    return kb

def kb_archive_multi_desc_step() -> InlineKeyboardMarkup:
    """Shown after repo name in multi-archive flow — match single archive style."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("✏️ Type description",  callback_data="archm_desc_type"),
        InlineKeyboardButton("⏭ Skip",               callback_data="archm_desc_skip_now"),
        InlineKeyboardButton("◀ Back",             callback_data="files_archive_upload"),
        InlineKeyboardButton("🏠 Home",               callback_data="menu_home"),
    )
    return kb

def kb_archive_multi_readme(has_readme: bool) -> InlineKeyboardMarkup:
    """README choice in multi-archive flow."""
    kb = InlineKeyboardMarkup(row_width=1)
    if has_readme:
        kb.add(InlineKeyboardButton("✍️ Rewrite README with AI",  callback_data="archm_readme_rewrite"))
        kb.add(InlineKeyboardButton("📄 Keep original README",    callback_data="archm_readme_keep"))
    kb.add(InlineKeyboardButton("✨ Generate README with AI",      callback_data="archm_readme_generate"))
    kb.add(InlineKeyboardButton("⏭ Skip — no README",             callback_data="archm_readme_skip"))
    kb.add(
        InlineKeyboardButton("◀ Back",  callback_data="files_archive_upload"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb

def kb_archive_readme_choice() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("✍️ Rewrite with AI",         callback_data="arch_readme_rewrite"),
        InlineKeyboardButton("📄 Keep original",           callback_data="arch_readme_keep"),
        InlineKeyboardButton("✨ Generate new README",     callback_data="arch_readme_generate"),
    )
    return kb

def kb_archive_no_readme() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("✨ Generate README with AI",  callback_data="arch_readme_generate"),
        InlineKeyboardButton("⏭ Skip",                     callback_data="arch_readme_skip"),
    )
    return kb

def kb_archive_confirm() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("🚀 Upload to GitHub", callback_data="confirm_archive"),
        InlineKeyboardButton("◀ Back",           callback_data="files_archive_upload"),
        InlineKeyboardButton("🏠 Home",             callback_data="menu_home"),
    )
    return kb

def kb_sec_warn_archive() -> InlineKeyboardMarkup:
    """Actions available after reviewing an archive security report."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("✏️ Edit / re-upload files", callback_data="sec_warn_archive_edit"),
        InlineKeyboardButton("⚠️ Upload anyway", callback_data="sec_warn_archive_proceed"),
        InlineKeyboardButton("❌ Cancel upload", callback_data="sec_warn_cancel"),
    )
    return kb

def kb_sec_warn_create() -> InlineKeyboardMarkup:
    """Actions available after reviewing a repository security report."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("✏️ Edit files", callback_data="sec_warn_create_edit"),
        InlineKeyboardButton("⚠️ Upload anyway", callback_data="sec_warn_create_proceed"),
        InlineKeyboardButton("❌ Cancel", callback_data="sec_warn_cancel"),
    )
    return kb

def _short_label(text: str, limit: int = 42) -> str:
    """Trim text for use as a button label only (full text is always shown elsewhere)."""
    text = " ".join(text.split())  # collapse whitespace
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


GITHUB_DESC_MAX = 350  # GitHub's hard limit on repo "About" descriptions


def _length_badge(text: str) -> str:
    """Small status line showing character count vs. GitHub's 350-char cap."""
    n = len(text)
    if n > GITHUB_DESC_MAX:
        return f"⚠️ {n}/{GITHUB_DESC_MAX} chars — too long, please enter a shorter description"
    if n > GITHUB_DESC_MAX - 40:
        return f"🟡 {n}/{GITHUB_DESC_MAX} chars"
    return f"🟢 {n}/{GITHUB_DESC_MAX} chars"


def _annotate_name_availability(u: dict, names: list) -> dict:
    """\n    Best-effort check of which suggested names are already taken on the user's\n    GitHub account. Returns {name: True/False/None}. Never raises — on any\n    problem (no token, network error, rate limit) all names come back None\n    ("unknown"), so the UI simply omits the badge rather than blocking anything.\n    Bounded to a small overall time budget so a slow/rate-limited API can\n    never meaningfully delay showing the suggestion screen.\n    """
    result = {n: None for n in names}
    token    = u.get("github_token")
    username = u.get("github_username")
    if not token or not username:
        return result
    deadline = _time.monotonic() + 4.0  # hard cap regardless of per-call timeout
    for n in names[:5]:
        if _time.monotonic() >= deadline:
            break
        try:
            result[n] = gh.repo_name_available(token, username, n, timeout=3)
        except Exception:
            result[n] = None
    return result


def kb_archive_ai_suggest(names: list, descs: list, availability: dict | None = None) -> InlineKeyboardMarkup:
    """Show AI-suggested repo names for single archive.\n    availability: optional {name: True/False/None} from _annotate_name_availability."""
    kb = InlineKeyboardMarkup(row_width=1)
    availability = availability or {}
    for i, n in enumerate(names[:5]):
        badge = ""
        av = availability.get(n)
        if av is True:
            badge = " ✅"
        elif av is False:
            badge = " ⚠️taken"
        kb.add(InlineKeyboardButton(f"📦 {i+1}. {n}{badge}", callback_data=f"arch_ai_name_{i}"))
    kb.add(InlineKeyboardButton("✏️ Type custom name", callback_data="arch_ai_custom"))
    kb.add(
        InlineKeyboardButton("🔀 Reorganize", callback_data="arch_ai_reorder"),
        InlineKeyboardButton("🔄 Regenerate",  callback_data="arch_ai_regen"),
    )
    kb.add(InlineKeyboardButton("◀ Back", callback_data="arch_mode_single"))
    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    return kb


def kb_archive_ai_desc(descs: list, chosen_name: str) -> InlineKeyboardMarkup:
    """Show AI-suggested repo descriptions for single archive (short labels; full\n    text is shown in a preview screen after tapping — see arch_ai_desc_<i>)."""
    kb = InlineKeyboardMarkup(row_width=1)
    for i, d in enumerate(descs[:5]):
        kb.add(InlineKeyboardButton(f"📝 {i+1}. {_short_label(d)}", callback_data=f"arch_ai_desc_{i}"))
    kb.add(InlineKeyboardButton("✏️ Type custom description", callback_data="arch_ai_desc_custom"))
    kb.add(InlineKeyboardButton("⏭ Skip description",        callback_data="arch_ai_desc_skip"))
    kb.add(
        InlineKeyboardButton("🔀 Reorganize", callback_data="arch_ai_desc_reorder"),
        InlineKeyboardButton("🔄 Regenerate",  callback_data="arch_ai_desc_regen"),
    )
    kb.add(InlineKeyboardButton("◀ Back", callback_data="arch_ai_back_names"))
    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    return kb


def kb_archive_ai_desc_preview(idx: int) -> InlineKeyboardMarkup:
    """Confirm/cancel screen shown after tapping a description suggestion,\n    displaying the FULL text above these buttons."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton("✅ Use this description", callback_data=f"arch_ai_desc_confirm_{idx}"))
    kb.add(InlineKeyboardButton("✏️ Edit before using",   callback_data=f"arch_ai_desc_edit_{idx}"))
    kb.add(InlineKeyboardButton("◀ Back to list", callback_data="arch_ai_desc_back_list"))
    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    return kb


def kb_archm_ai_suggest(names: list, descs: list, availability: dict | None = None) -> InlineKeyboardMarkup:
    """Show AI-suggested repo names for multi-archive (per archive)."""
    kb = InlineKeyboardMarkup(row_width=1)
    availability = availability or {}
    for i, n in enumerate(names[:5]):
        badge = ""
        av = availability.get(n)
        if av is True:
            badge = " ✅"
        elif av is False:
            badge = " ⚠️taken"
        kb.add(InlineKeyboardButton(f"📦 {i+1}. {n}{badge}", callback_data=f"archm_ai_name_{i}"))
    kb.add(InlineKeyboardButton("✏️ Type custom name", callback_data="archm_ai_custom"))
    kb.add(
        InlineKeyboardButton("🔀 Reorganize", callback_data="archm_ai_reorder"),
        InlineKeyboardButton("🔄 Regenerate",  callback_data="archm_ai_regen"),
    )
    kb.add(InlineKeyboardButton("◀ Back", callback_data="files_archive_upload"))
    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    return kb


def kb_archm_ai_desc(descs: list) -> InlineKeyboardMarkup:
    """Show AI-suggested descriptions for multi-archive (per archive); short labels,\n    full text shown in a preview screen after tapping."""
    kb = InlineKeyboardMarkup(row_width=1)
    for i, d in enumerate(descs[:5]):
        kb.add(InlineKeyboardButton(f"📝 {i+1}. {_short_label(d)}", callback_data=f"archm_ai_desc_{i}"))
    kb.add(InlineKeyboardButton("✏️ Type custom description", callback_data="archm_ai_desc_custom"))
    kb.add(InlineKeyboardButton("⏭ Skip description",        callback_data="archm_ai_desc_skip"))
    kb.add(
        InlineKeyboardButton("🔀 Reorganize", callback_data="archm_ai_desc_reorder"),
        InlineKeyboardButton("🔄 Regenerate",  callback_data="archm_ai_desc_regen"),
    )
    kb.add(InlineKeyboardButton("◀ Back", callback_data="archm_ai_back_names"))
    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    return kb


def kb_archm_ai_desc_preview(idx: int) -> InlineKeyboardMarkup:
    """Confirm/cancel screen shown after tapping a description suggestion (multi-mode),\n    displaying the FULL text above these buttons."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton("✅ Use this description", callback_data=f"archm_ai_desc_confirm_{idx}"))
    kb.add(InlineKeyboardButton("✏️ Edit before using",   callback_data=f"archm_ai_desc_edit_{idx}"))
    kb.add(InlineKeyboardButton("◀ Back to list", callback_data="archm_ai_desc_back_list"))
    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    return kb


def kb_fork_mode() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("🔗 Single",            callback_data="fork_mode_single"),
        InlineKeyboardButton("🔗🔗 Multiple",         callback_data="fork_mode_multi"),
        InlineKeyboardButton("\U0001f3e0 Home", callback_data="menu_home"),
    )
    return kb

def kb_fork_confirm(owner: str, repo: str) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton(f"✅ Fork  {owner}/{repo}", callback_data="fork_confirm"),
        InlineKeyboardButton("✏️ Edit URL",              callback_data="fork_edit"),
        InlineKeyboardButton("◀ Back",                callback_data="menu_import"),
        InlineKeyboardButton("🏠 Home",                  callback_data="menu_home"),
    )
    return kb

def kb_fork_single_prompt() -> InlineKeyboardMarkup:
    """Shown in Fork Single Mode — return to fork picker."""
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("◀ Back",  callback_data="menu_import"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb

def kb_fork_multi_collecting() -> InlineKeyboardMarkup:
    """Shown in Fork Multi Mode while collecting URLs — return to fork picker."""
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("◀ Back",  callback_data="menu_import"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb

def kb_fork_multi_done() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("✅ Fork All Now",  callback_data="fork_multi_execute"),
        InlineKeyboardButton("◀ Back",        callback_data="menu_import"),
        InlineKeyboardButton("🏠 Home",          callback_data="menu_home"),
    )
    return kb

def kb_provider_picker() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    for pid, pinfo in PROVIDERS.items():
        badge = " 🆓" if pinfo["free"] else " 💳"
        kb.add(InlineKeyboardButton(f"{pinfo['emoji']} {pinfo['name']}{badge}", callback_data=f"pick_provider_{pid}"))
    kb.add(
        InlineKeyboardButton("◀ Back",  callback_data="menu_setup"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb


# ═══════════════════════════════════════════════════════════
#  EDIT REPO — Keyboards
# ═══════════════════════════════════════════════════════════

_EDIT_PAGE_SIZE = 8   # repos per page in Edit Repo picker

def kb_edit_repo_picker(repos: list, page: int) -> InlineKeyboardMarkup:
    """Scrollable paginated repo picker for Edit Repo."""
    kb         = InlineKeyboardMarkup(row_width=1)
    total      = len(repos)
    start      = page * _EDIT_PAGE_SIZE
    end        = min(start + _EDIT_PAGE_SIZE, total)
    page_repos = repos[start:end]

    for i, r in enumerate(page_repos):
        vis  = "🔒" if r.get("private") else "🌍"
        name = r["name"]
        # Index-based callback: repo names can be long enough to overflow
        # Telegram's 64-byte callback_data limit, which would make the whole
        # picker screen fail to render.
        kb.add(InlineKeyboardButton(f"{vis} {name}", callback_data=f"er_pick_{start + i}"))

    total_pages = max(1, (total + _EDIT_PAGE_SIZE - 1) // _EDIT_PAGE_SIZE)
    nav_btns = []
    if page > 0:
        nav_btns.append(InlineKeyboardButton("◀ Prev", callback_data=f"er_page_{page-1}"))
    nav_btns.append(InlineKeyboardButton(f"📄 {page+1}/{total_pages}", callback_data="er_noop"))
    if end < total:
        nav_btns.append(InlineKeyboardButton("Next ▶", callback_data=f"er_page_{page+1}"))
    if nav_btns:
        kb.row(*nav_btns)

    kb.add(InlineKeyboardButton("\U0001f3e0 Home", callback_data="menu_home"))
    return kb


def kb_edit_repo_menu(repo_name: str, is_private: bool, branch: str = "main") -> InlineKeyboardMarkup:
    """Main edit menu for a selected repo."""
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("📂 Browse Files & Folders", callback_data=f"er_browse_{repo_name}|"),
    )
    kb.add(
        InlineKeyboardButton("📄 New File",         callback_data=f"er_newfile_{repo_name}|"),
        InlineKeyboardButton("📁 New Folder",       callback_data=f"er_newfolder_{repo_name}"),
    )
    kb.add(
        InlineKeyboardButton("✏️ Rename Repo",      callback_data=f"er_rename_{repo_name}"),
        InlineKeyboardButton("📝 Edit Description", callback_data=f"er_desc_{repo_name}"),
    )
    vis_toggle = "🔓 Make Public" if is_private else "🔒 Make Private"
    vis_cb     = f"er_vis_toggle_{repo_name}"
    kb.add(
        InlineKeyboardButton(vis_toggle,             callback_data=vis_cb),
        InlineKeyboardButton("🌐 Set Homepage",      callback_data=f"er_homepage_{repo_name}"),
    )
    kb.add(
        InlineKeyboardButton("🏷 Edit Topics",       callback_data=f"er_topics_{repo_name}"),
        InlineKeyboardButton("🔀 New Branch",        callback_data=f"er_newbranch_{repo_name}"),
    )
    kb.add(
        InlineKeyboardButton("📊 Repo Info",         callback_data=f"er_info_{repo_name}"),
        InlineKeyboardButton("🔍 Search Files",      callback_data=f"er_search_{repo_name}"),
    )
    kb.add(InlineKeyboardButton("👁 Live Preview", callback_data="er_preview"))
    kb.add(
        InlineKeyboardButton("◀ Back", callback_data="menu_edit_repo"),
        InlineKeyboardButton("🏠 Home",   callback_data="menu_home"),
    )
    return kb


def kb_browse_dir(repo_name: str, path: str, items: list, page: int = 0) -> InlineKeyboardMarkup:
    """Browse a directory: show folders then files with pagination."""
    kb       = InlineKeyboardMarkup(row_width=1)
    PAGE_SZ  = 10
    folders  = [i for i in items if i.get("type") == "dir"]
    files    = [i for i in items if i.get("type") == "file"]
    all_items = folders + files
    total    = len(all_items)
    start    = page * PAGE_SZ
    end      = min(start + PAGE_SZ, total)

    for item in all_items[start:end]:
        if item["type"] == "dir":
            sub_path = item["path"]
            kb.add(InlineKeyboardButton(
                f"📁 {item['name']}/",
                callback_data=f"er_browse_{repo_name}|{sub_path}",
            ))
        else:
            file_path = item["path"]
            kb.add(InlineKeyboardButton(
                f"📄 {item['name']}",
                callback_data=f"er_file_{repo_name}|{file_path}",
            ))

    total_pages = max(1, (total + PAGE_SZ - 1) // PAGE_SZ)
    if total_pages > 1:
        nav_btns = []
        if page > 0:
            nav_btns.append(InlineKeyboardButton("◀ Prev", callback_data=f"er_bpage_{repo_name}|{path}|{page-1}"))
        nav_btns.append(InlineKeyboardButton(f"📄 {page+1}/{total_pages}", callback_data="er_noop"))
        if end < total:
            nav_btns.append(InlineKeyboardButton("Next ▶", callback_data=f"er_bpage_{repo_name}|{path}|{page+1}"))
        kb.row(*nav_btns)

    # Add new file/folder in current dir
    kb.add(
        InlineKeyboardButton("📄 + New File Here",   callback_data=f"er_newfile_{repo_name}|{path}"),
        InlineKeyboardButton("📁 + New Folder Here", callback_data=f"er_newfolder_{repo_name}|{path}"),
    )
    # Back button: go up one level
    parent = "/".join(path.rstrip("/").split("/")[:-1]) if path and "/" in path else ""
    if path:
        kb.add(InlineKeyboardButton(
            "⬆️ Up a Level",
            callback_data=f"er_browse_{repo_name}|{parent}",
        ))
    kb.add(
        InlineKeyboardButton("◀ Repo Menu",  callback_data=f"er_repomenu_{repo_name}"),
        InlineKeyboardButton("🏠 Home",       callback_data="menu_home"),
    )
    return kb


def kb_file_actions(repo_name: str, file_path: str) -> InlineKeyboardMarkup:
    """Actions available on a specific file."""
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(InlineKeyboardButton("✏️ Edit Content",     callback_data=f"er_edit_{repo_name}|{file_path}"))
    kb.add(
        InlineKeyboardButton("📋 View Raw",           callback_data=f"er_view_{repo_name}|{file_path}"),
        InlineKeyboardButton("✂️ Move/Rename",        callback_data=f"er_move_{repo_name}|{file_path}"),
    )
    kb.add(InlineKeyboardButton("🗑 Delete File",       callback_data=f"er_del_file_{repo_name}|{file_path}"))
    # Back: go to parent folder
    parent = "/".join(file_path.split("/")[:-1])
    kb.add(
        InlineKeyboardButton("◀ Back to Folder",  callback_data=f"er_browse_{repo_name}|{parent}"),
        InlineKeyboardButton("🏠 Home",             callback_data="menu_home"),
    )
    return kb


def kb_edit_cancel(repo_name: str, back_path: str = "") -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("◀ Back",  callback_data=f"er_browse_{repo_name}|{back_path}"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb


def kb_confirm_del_file(repo_name: str, file_path: str) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton(
        f"⚠️ Yes, delete {file_path.split('/')[-1]}",
        callback_data=f"er_del_confirm_{repo_name}|{file_path}",
    ))
    kb.add(
        InlineKeyboardButton("❌ Cancel",   callback_data=f"er_file_{repo_name}|{file_path}"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb


# ── Replace Repo Contents keyboards ──────────────────────────

_REPLACE_PAGE_SIZE = 8   # repos shown per page in the replace picker
_UPLOAD_PAGE_SIZE  = 8   # repos shown per page in the upload picker
_PREVIEW_PAGE_SIZE = 8   # repos shown per page in the live-preview picker


def kb_replace_picker(repos: list, page: int) -> InlineKeyboardMarkup:
    """Scrollable paginated repo picker for Replace Repo.

    Callbacks carry a positional index into the draft-cached repo list so a
    long repository name can never exceed Telegram's 64-byte callback_data
    limit (the same trick the download picker would need).
    """
    kb         = InlineKeyboardMarkup(row_width=1)
    total      = len(repos)
    start      = page * _REPLACE_PAGE_SIZE
    end        = min(start + _REPLACE_PAGE_SIZE, total)
    page_repos = repos[start:end]

    for i, r in enumerate(page_repos):
        vis = "🔒" if r.get("private") else "🌍"
        kb.add(InlineKeyboardButton(f"{vis} {r['name']}", callback_data=f"rr_pick_{start + i}"))

    total_pages = max(1, (total + _REPLACE_PAGE_SIZE - 1) // _REPLACE_PAGE_SIZE)
    nav_btns = []
    if page > 0:
        nav_btns.append(InlineKeyboardButton("◀ Prev", callback_data=f"rr_page_{page-1}"))
    nav_btns.append(InlineKeyboardButton(f"📄 {page+1}/{total_pages}", callback_data="rr_noop"))
    if end < total:
        nav_btns.append(InlineKeyboardButton("Next ▶", callback_data=f"rr_page_{page+1}"))
    if nav_btns:
        kb.row(*nav_btns)

    kb.add(InlineKeyboardButton("\U0001f3e0 Home", callback_data="menu_home"))
    return kb


def kb_replace_menu() -> InlineKeyboardMarkup:
    """Action menu for the chosen repo (resolved from the draft, not the callback)."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton("♻️ Clear All Files + Upload My Archive", callback_data="rr_replace_ask"))
    kb.add(InlineKeyboardButton("🧹 Clear All Files Only (keep repo)",    callback_data="rr_clear_confirm"))
    kb.add(
        InlineKeyboardButton("◀ Change Repo", callback_data="menu_replace_repo"),
        InlineKeyboardButton("🏠 Home",          callback_data="menu_home"),
    )
    return kb


def kb_replace_clear_confirm() -> InlineKeyboardMarkup:
    """Keyboard while the user must type the repo name to confirm clearing."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton("❌ Cancel — keep my files", callback_data="rr_clear_cancel"))
    kb.add(InlineKeyboardButton("🏠 Home",                    callback_data="menu_home"))
    return kb


def kb_replace_confirm() -> InlineKeyboardMarkup:
    """Final confirmation before clearing the repo and uploading new files."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton("🚀 Clear & Upload Now", callback_data="rr_replace_go"))
    kb.add(InlineKeyboardButton("📦 Send a different archive", callback_data="rr_replace_ask"))
    kb.add(
        InlineKeyboardButton("◀ Change Repo", callback_data="menu_replace_repo"),
        InlineKeyboardButton("🏠 Home",          callback_data="menu_home"),
    )
    return kb


# ── Upload to Repo keyboards ─────────────────────────────────

def kb_upload_picker(repos: list, page: int) -> InlineKeyboardMarkup:
    """Scrollable paginated repo picker for Upload to Repo.

    Callbacks carry a positional index into the draft-cached repo list so a
    long repository name can never exceed Telegram's 64-byte callback_data
    limit (same trick as the replace picker)."""
    kb         = InlineKeyboardMarkup(row_width=1)
    total      = len(repos)
    start      = page * _UPLOAD_PAGE_SIZE
    end        = min(start + _UPLOAD_PAGE_SIZE, total)
    page_repos = repos[start:end]

    for i, r in enumerate(page_repos):
        vis = "🔒" if r.get("private") else "🌍"
        kb.add(InlineKeyboardButton(f"{vis} {r['name']}", callback_data=f"up_pick_{start + i}"))

    total_pages = max(1, (total + _UPLOAD_PAGE_SIZE - 1) // _UPLOAD_PAGE_SIZE)
    nav_btns = []
    if page > 0:
        nav_btns.append(InlineKeyboardButton("◀ Prev", callback_data=f"up_page_{page-1}"))
    nav_btns.append(InlineKeyboardButton(f"📄 {page+1}/{total_pages}", callback_data="up_noop"))
    if end < total:
        nav_btns.append(InlineKeyboardButton("Next ▶", callback_data=f"up_page_{page+1}"))
    if nav_btns:
        kb.row(*nav_btns)

    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    return kb


def kb_upload_path() -> InlineKeyboardMarkup:
    """Ask where inside the repo the files should land."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton("📁 Repository root (/)", callback_data="up_root"))
    kb.add(InlineKeyboardButton("✍️ Type a folder path (e.g. docs/)", callback_data="up_path_type"))
    kb.add(
        InlineKeyboardButton("◀ Change Repo", callback_data="menu_upload_files"),
        InlineKeyboardButton("🏠 Home",          callback_data="menu_home"),
    )
    return kb


def kb_upload_mode() -> InlineKeyboardMarkup:
    """Add vs Replace chooser shown after the destination folder is picked."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton(
        "➕ Add files — keep what's in the repo", callback_data="up_mode_add"))
    kb.add(InlineKeyboardButton(
        "🔄 Replace files — delete old, upload new", callback_data="up_mode_replace"))
    kb.add(
        InlineKeyboardButton("◀ Change destination", callback_data="up_back_dest"),
        InlineKeyboardButton("🏠 Home",              callback_data="menu_home"),
    )
    return kb


def kb_upload_collect(count: int) -> InlineKeyboardMarkup:
    """Keyboard while collecting files for Upload to Repo."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton(
        f"✅ Done — Upload {count} file{'s' if count != 1 else ''}",
        callback_data="up_done"))
    kb.add(InlineKeyboardButton("🗑 Clear all & start over", callback_data="up_reset"))
    kb.add(
        InlineKeyboardButton("◀ Change Repo", callback_data="menu_upload_files"),
        InlineKeyboardButton("🏠 Home",          callback_data="menu_home"),
    )
    return kb


def kb_upload_result() -> InlineKeyboardMarkup:
    """Shown after files are pushed into an existing repo."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton("👁 Live Preview", callback_data="lp_open"))
    kb.add(InlineKeyboardButton("📤 Upload more files",   callback_data="menu_upload_files"))
    kb.add(InlineKeyboardButton("🏠 Home",               callback_data="menu_home"))
    return kb


def kb_sec_warn_upload() -> InlineKeyboardMarkup:
    """Actions after a security warning on a direct Upload-to-Repo batch."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton("✂️ Remove flagged files & continue", callback_data="sec_warn_upload_edit"))
    kb.add(InlineKeyboardButton("⚠️ Upload anyway",  callback_data="sec_warn_upload_proceed"))
    kb.add(InlineKeyboardButton("❌ Cancel upload",  callback_data="sec_warn_cancel"))
    return kb


# ── Live Preview keyboards ───────────────────────────────────

def kb_preview_picker(repos: list, page: int) -> InlineKeyboardMarkup:
    """Scrollable paginated repo picker for Live Preview."""
    kb         = InlineKeyboardMarkup(row_width=1)
    total      = len(repos)
    start      = page * _PREVIEW_PAGE_SIZE
    end        = min(start + _PREVIEW_PAGE_SIZE, total)
    page_repos = repos[start:end]

    for i, r in enumerate(page_repos):
        vis = "🔒" if r.get("private") else "🌍"
        kb.add(InlineKeyboardButton(f"{vis} {r['name']}", callback_data=f"lp_pick_{start + i}"))

    total_pages = max(1, (total + _PREVIEW_PAGE_SIZE - 1) // _PREVIEW_PAGE_SIZE)
    nav_btns = []
    if page > 0:
        nav_btns.append(InlineKeyboardButton("◀ Prev", callback_data=f"lp_page_{page-1}"))
    nav_btns.append(InlineKeyboardButton(f"📄 {page+1}/{total_pages}", callback_data="lp_noop"))
    if end < total:
        nav_btns.append(InlineKeyboardButton("Next ▶", callback_data=f"lp_page_{page+1}"))
    if nav_btns:
        kb.row(*nav_btns)

    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    return kb


def kb_live_preview(pages_url: str = "", quick_url: str = "",
                    pages_ready: bool = False, enable_btn: bool = True) -> InlineKeyboardMarkup:
    """Live Preview screen buttons.

    `pages_url` and `quick_url` are plain URLs — Telegram renders them as link
    buttons with no callback-data length limit. `enable_btn` adds the
    'Enable GitHub Pages' action when Pages is not set up yet."""
    kb = InlineKeyboardMarkup(row_width=1)
    if pages_url:
        kb.add(InlineKeyboardButton("🌐 Open Live Site", url=pages_url))
    if quick_url:
        kb.add(InlineKeyboardButton("⚡ Instant HTML Preview", url=quick_url))
    if enable_btn:
        kb.add(InlineKeyboardButton("🚀 Enable GitHub Pages", callback_data="lp_enable"))
    kb.add(
        InlineKeyboardButton("🔄 Refresh", callback_data="lp_open"),
        InlineKeyboardButton("📦 Another Repo", callback_data="menu_live_preview"),
    )
    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    return kb


def kb_preview_added_menu() -> InlineKeyboardMarkup:
    """Small helper row added to upload/replace success messages."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton("👁 Live Preview", callback_data="lp_open"))
    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    return kb


# ═══════════════════════════════════════════════════════════
#  EDIT REPO — Helper Functions
# ═══════════════════════════════════════════════════════════

def _show_edit_repo_picker(uid: int, edit_msg_id: int = None, page: int = 0) -> None:
    """Load all repos and show the Edit Repo picker (scrollable)."""
    u = get_user(uid)
    if edit_msg_id:
        try:
            bot.edit_message_text("⏳ Loading repositories ·", uid, edit_msg_id)
        except Exception:
            edit_msg_id = bot.send_message(uid, "⏳ Loading repositories ·").message_id
        loading_id = edit_msg_id
    else:
        loading_id = bot.send_message(uid, "⏳ Loading repositories ·").message_id

    repos = _animate(uid, loading_id, "Loading repositories",
                     gh.list_all_repos, u["github_token"])
    if not repos:
        bot.edit_message_text(
            "📦 *No repositories found.*\n\n_Create one first._",
            uid, loading_id, reply_markup=kb_home_only(uid),
        )
        set_state(uid, State.IDLE)
        return

    repo_list = [{"name": r["name"], "private": r.get("private", False)} for r in repos]
    set_state(uid, State.EDIT_REPO_PICK, draft={
        "er_repos": repo_list,
        "er_page":  page,
    })
    total = len(repo_list)
    bot.edit_message_text(
        f"✏️ *Edit Repository*\n\nSelect a repository to edit.\n🌍 Public · 🔒 Private · Total: *{total}*\n\n_Choose a repo to browse files, edit code, rename, and more._",
        uid, loading_id,
        reply_markup=kb_edit_repo_picker(repo_list, page),
    )


def _show_edit_repo_menu(uid: int, repo_name: str, msg_id: int) -> None:
    """Show the edit menu for a selected repo."""
    u     = get_user(uid)
    token = u.get("github_token")
    owner = u.get("github_username") or (gh.get_user(token) or {}).get("login", "")
    if not owner:
        bot.edit_message_text("❌ Could not fetch GitHub username.", uid, msg_id, reply_markup=kb_home_only(uid))
        return
    # Cache owner for later use
    u["draft"]["er_owner"]    = owner
    u["draft"]["er_repo"]     = repo_name
    u["draft"]["er_path"]     = ""
    save_user(uid, u)

    info = gh.get_repo_info(token, owner, repo_name)
    if not info:
        bot.edit_message_text("❌ Could not fetch repo info.", uid, msg_id, reply_markup=kb_home_only(uid))
        return

    is_private = info.get("private", False)
    branch     = info.get("default_branch", "main")
    stars      = info.get("stargazers_count", 0)
    forks      = info.get("forks_count", 0)
    lang       = info.get("language") or "—"
    desc       = info.get("description") or "—"
    vis_txt    = "🔒 Private" if is_private else "🌍 Public"
    size       = info.get("size", 0)

    set_state(uid, State.EDIT_REPO_MENU, draft=u["draft"])

    text = (
        f"✏️ *Edit Repo — `{repo_name}`*\n\n🏷 {vis_txt}  ·  🌿 `{branch}`  ·  💾 {size} KB\n⭐ {stars}  🍴 {forks}  🛠 {lang}\n📝 _{_escape_md(desc)}_\n\n_What would you like to do?_"
    )
    try:
        bot.edit_message_text(text, uid, msg_id, reply_markup=kb_edit_repo_menu(repo_name, is_private, branch))
    except Exception:
        bot.send_message(uid, text, reply_markup=kb_edit_repo_menu(repo_name, is_private, branch))


def _browse_path(uid: int, repo_name: str, path: str, msg_id: int) -> None:
    """Browse a directory path in the repo."""
    u     = get_user(uid)
    token = u.get("github_token")
    owner = u["draft"].get("er_owner", "")
    if not owner:
        info = gh.get_user(token)
        owner = info.get("login", "") if info else ""
        u["draft"]["er_owner"] = owner
        save_user(uid, u)

    try:
        bot.edit_message_text(f"⏳ Loading `{'/' + path if path else '/'}` ···", uid, msg_id)
    except Exception:
        pass

    contents = gh.get_repo_contents(token, owner, repo_name, path)
    if contents is None:
        bot.edit_message_text(
            f"❌ Could not load `/{path or ''}`. Path may not exist.",
            uid, msg_id, reply_markup=kb_edit_cancel(repo_name, ""),
        )
        return

    if isinstance(contents, dict):
        # It's a file, not a dir
        _show_file_actions(uid, repo_name, path, msg_id)
        return

    # Sort: dirs first, then files
    items = sorted(contents, key=lambda x: (0 if x["type"] == "dir" else 1, x["name"].lower()))
    u["draft"]["er_path"]         = path
    u["draft"]["er_browse_items"] = items
    save_user(uid, u)
    set_state(uid, State.EDIT_BROWSE)

    path_display = "/" + path if path else "/"
    text = (
        f"📂 *Browse — `{repo_name}`*\n\n"
        f"📍 Path: `{path_display}`\n"
        f"📁 {sum(1 for i in items if i['type']=='dir')} folders  "
        f"📄 {sum(1 for i in items if i['type']=='file')} files\n\n"
        "_Tap a folder to open, tap a file to edit._"
    )
    try:
        bot.edit_message_text(text, uid, msg_id, reply_markup=kb_browse_dir(repo_name, path, items))
    except Exception:
        bot.send_message(uid, text, reply_markup=kb_browse_dir(repo_name, path, items))


def _show_file_actions(uid: int, repo_name: str, file_path: str, msg_id: int) -> None:
    """Show file action menu with preview."""
    u     = get_user(uid)
    token = u.get("github_token")
    owner = u["draft"].get("er_owner", "")

    try:
        bot.edit_message_text(f"⏳ Loading `{file_path}` ···", uid, msg_id)
    except Exception:
        pass

    file_data = gh.get_file_content(token, owner, repo_name, file_path)
    if not file_data:
        bot.edit_message_text(
            f"❌ Could not load file `{file_path}`.",
            uid, msg_id, reply_markup=kb_home_only(uid),
        )
        return

    import base64 as _b64
    content_b64 = file_data.get("content", "").replace("\n", "")
    try:
        raw_content = _b64.b64decode(content_b64).decode("utf-8", errors="replace")
    except Exception:
        raw_content = "(binary file)"

    # Store in draft for editing
    u["draft"]["er_file_path"]    = file_path
    u["draft"]["er_file_sha"]     = file_data.get("sha", "")
    u["draft"]["er_file_content"] = raw_content
    save_user(uid, u)
    set_state(uid, State.EDIT_FILE_VIEW)

    size    = file_data.get("size", 0)
    fname   = file_path.split("/")[-1]
    preview = raw_content[:400]
    if len(raw_content) > 400:
        preview += f"\n… _(+{len(raw_content)-400} more chars)_"

    text = (
        f"📄 *File: `{fname}`*\n"
        f"📍 `{file_path}`  ·  💾 {size} bytes\n\n"
        f"```\n{preview}\n```"
    )
    try:
        bot.edit_message_text(text, uid, msg_id, reply_markup=kb_file_actions(repo_name, file_path))
    except Exception:
        bot.send_message(uid, text, reply_markup=kb_file_actions(repo_name, file_path))


# ═══════════════════════════════════════════════════════════
#  EDIT REPO — State-based text handlers (called from handle_text)
# ═══════════════════════════════════════════════════════════

def _er_handle_text(uid: int, text: str, msg: "Message") -> bool:
    """\n    Handle Edit-Repo text input states.\n    Returns True if consumed, False otherwise.\n    """
    state = get_state(uid)
    u     = get_user(uid)
    token = u.get("github_token")
    owner = u["draft"].get("er_owner", "")
    repo  = u["draft"].get("er_repo", "")

    # ── Editing file content ──────────────────────────────────
    if state == State.EDIT_FILE_EDIT:
        file_path  = u["draft"].get("er_file_path", "")
        sha        = u["draft"].get("er_file_sha",  "")
        commit_msg = u["draft"].get("er_commit_msg", f"Update {file_path.split('/')[-1]} via GitHub Bot")
        loading_id = bot.send_message(uid, f"⏳ Saving `{file_path}` ···").message_id
        ok = gh.update_file(token, owner, repo, file_path, text, sha, commit_msg)
        parent = "/".join(file_path.split("/")[:-1])
        if ok:
            add_history(uid, f"Edited file {repo}/{file_path}")
            bot.edit_message_text(
                f"✅ *File updated!*\n\n`{file_path}` saved to `{repo}`.",
                uid, loading_id,
                reply_markup=kb_file_actions(repo, file_path),
            )
            # Refresh SHA
            updated = gh.get_file_content(token, owner, repo, file_path)
            if updated:
                u["draft"]["er_file_sha"]     = updated.get("sha", "")
                u["draft"]["er_file_content"] = text
                save_user(uid, u)
        else:
            bot.edit_message_text(
                f"❌ Failed to update `{file_path}`. Check token permissions.",
                uid, loading_id,
                reply_markup=kb_file_actions(repo, file_path),
            )
        set_state(uid, State.EDIT_FILE_VIEW, draft=u["draft"])
        return True

    # ── New file: awaiting name ───────────────────────────────
    if state == State.EDIT_FILE_NEW_NAME:
        base_path = u["draft"].get("er_new_base_path", "")
        fname     = text.strip().lstrip("/")
        full_path = f"{base_path}/{fname}".lstrip("/") if base_path else fname
        u["draft"]["er_new_file_path"] = full_path
        save_user(uid, u)
        set_state(uid, State.EDIT_FILE_NEW_CONTENT, draft=u["draft"])
        bot.send_message(
            uid,
            f"📄 *New file:* `{full_path}`\n\n"
            "Now send the *file content*.\n\n"
            "_Paste code, text, JSON — anything._\n\n"
            "Tip: For empty file send a single space.",
        )
        return True

    # ── New file: awaiting content ────────────────────────────
    if state == State.EDIT_FILE_NEW_CONTENT:
        file_path  = u["draft"].get("er_new_file_path", "")
        commit_msg = f"Create {file_path.split('/')[-1]} via GitHub Bot"
        loading_id = bot.send_message(uid, f"⏳ Creating `{file_path}` ···").message_id
        ok = gh.create_file(token, owner, repo, file_path, text, commit_msg)
        parent = "/".join(file_path.split("/")[:-1])
        if ok:
            add_history(uid, f"Created file {repo}/{file_path}")
            bot.edit_message_text(
                f"✅ *File created!*\n\n`{file_path}` added to `{repo}`.",
                uid, loading_id,
                reply_markup=kb_edit_cancel(repo, parent),
            )
        else:
            bot.edit_message_text(
                f"❌ Failed to create `{file_path}`. File may already exist.",
                uid, loading_id,
                reply_markup=kb_edit_cancel(repo, parent),
            )
        set_state(uid, State.EDIT_REPO_MENU, draft=u["draft"])
        return True

    # ── New folder: awaiting folder name ─────────────────────
    if state == State.EDIT_FOLDER_NEW_NAME:
        base_path   = u["draft"].get("er_new_base_path", "")
        fname       = text.strip().strip("/")
        folder_path = f"{base_path}/{fname}".lstrip("/") if base_path else fname
        u["draft"]["er_new_folder_path"] = folder_path
        save_user(uid, u)
        set_state(uid, State.EDIT_FOLDER_FIRST_FILE, draft=u["draft"])
        bot.send_message(
            uid,
            f"📁 *New folder:* `{folder_path}/`\n\n"
            "GitHub requires at least one file in a folder.\n\n"
            "Send the *first file name* (e.g. `README.md`):",
        )
        return True

    # ── New folder: awaiting first file name ──────────────────
    if state == State.EDIT_FOLDER_FIRST_FILE:
        folder_path = u["draft"].get("er_new_folder_path", "")
        fname       = text.strip().lstrip("/")
        full_path   = f"{folder_path}/{fname}"
        u["draft"]["er_new_file_path"] = full_path
        save_user(uid, u)
        set_state(uid, State.EDIT_FILE_NEW_CONTENT, draft=u["draft"])
        bot.send_message(
            uid,
            f"📄 *File:* `{full_path}`\n\nNow send the file content:",
        )
        return True

    # ── Rename repo ───────────────────────────────────────────
    if state == State.EDIT_REPO_RENAME:
        new_name   = text.strip().lower().replace(" ", "-")
        loading_id = bot.send_message(uid, f"⏳ Renaming `{repo}` → `{new_name}` ···").message_id
        result     = gh.rename_repo(token, owner, repo, new_name)
        if result:
            add_history(uid, f"Renamed repo {repo} → {new_name}")
            u["draft"]["er_repo"] = new_name
            save_user(uid, u)
            bot.edit_message_text(
                f"✅ *Repo renamed!*\n\n`{repo}` → `{new_name}`",
                uid, loading_id,
                reply_markup=kb_edit_repo_menu(new_name, result.get("private", False)),
            )
        else:
            bot.edit_message_text(
                f"❌ Failed to rename `{repo}`. Name may already exist or be invalid.",
                uid, loading_id,
                reply_markup=kb_edit_repo_menu(repo, False),
            )
        set_state(uid, State.EDIT_REPO_MENU, draft=u["draft"])
        return True

    # ── Edit description ──────────────────────────────────────
    if state == State.EDIT_REPO_DESC:
        desc       = text.strip()
        loading_id = bot.send_message(uid, f"⏳ Updating description ···").message_id
        result     = gh.update_repo_settings(token, owner, repo, description=desc)
        if result:
            add_history(uid, f"Updated description of {repo}")
            bot.edit_message_text(
                f"✅ *Description updated!*\n\n`{repo}`: _{_escape_md(desc)}_",
                uid, loading_id,
                reply_markup=kb_edit_repo_menu(repo, result.get("private", False)),
            )
        else:
            bot.edit_message_text(
                f"❌ Failed to update description.",
                uid, loading_id,
                reply_markup=kb_edit_repo_menu(repo, False),
            )
        set_state(uid, State.EDIT_REPO_MENU, draft=u["draft"])
        return True

    # ── Set homepage ──────────────────────────────────────────
    if state == State.EDIT_REPO_HOMEPAGE:
        homepage   = text.strip() if text.strip() != "-" else ""
        loading_id = bot.send_message(uid, f"⏳ Updating homepage ···").message_id
        result     = gh.update_repo_settings(token, owner, repo, homepage=homepage)
        if result:
            add_history(uid, f"Set homepage of {repo} to {homepage}")
            bot.edit_message_text(
                f"✅ *Homepage updated!*\n\n`{repo}`: {homepage or '_(removed)_'}",
                uid, loading_id,
                reply_markup=kb_edit_repo_menu(repo, result.get("private", False)),
            )
        else:
            bot.edit_message_text(
                f"❌ Failed to update homepage.",
                uid, loading_id,
                reply_markup=kb_edit_repo_menu(repo, False),
            )
        set_state(uid, State.EDIT_REPO_MENU, draft=u["draft"])
        return True

    # ── Set topics ────────────────────────────────────────────
    if state == State.EDIT_REPO_TOPICS:
        raw_topics = [t.strip().lower().replace(" ", "-") for t in re.split(r"[,\n\s]+", text) if t.strip()]
        loading_id = bot.send_message(uid, f"⏳ Updating topics ···").message_id
        ok = gh.set_repo_topics(token, owner, repo, raw_topics)
        if ok:
            add_history(uid, f"Updated topics of {repo}")
            bot.edit_message_text(
                f"✅ *Topics updated!*\n\n`{repo}`: " + " ".join(f"`{t}`" for t in raw_topics),
                uid, loading_id,
                reply_markup=kb_edit_repo_menu(repo, False),
            )
        else:
            bot.edit_message_text(
                f"❌ Failed to update topics.",
                uid, loading_id,
                reply_markup=kb_edit_repo_menu(repo, False),
            )
        set_state(uid, State.EDIT_REPO_MENU, draft=u["draft"])
        return True

    # ── New branch ────────────────────────────────────────────
    if state == State.EDIT_BRANCH_NEW:
        branch_name = text.strip().replace(" ", "-")
        loading_id  = bot.send_message(uid, f"⏳ Creating branch `{branch_name}` ···").message_id
        ok = gh.create_branch(token, owner, repo, branch_name)
        if ok:
            add_history(uid, f"Created branch {branch_name} in {repo}")
            bot.edit_message_text(
                f"✅ *Branch created!*\n\n`{branch_name}` in `{repo}`",
                uid, loading_id,
                reply_markup=kb_edit_repo_menu(repo, False),
            )
        else:
            bot.edit_message_text(
                f"❌ Failed to create branch `{branch_name}`. It may already exist.",
                uid, loading_id,
                reply_markup=kb_edit_repo_menu(repo, False),
            )
        set_state(uid, State.EDIT_REPO_MENU, draft=u["draft"])
        return True

    # ── Move/rename file: awaiting destination ────────────────
    if state == State.EDIT_FILE_MOVE_DEST:
        file_path = u["draft"].get("er_file_path", "")
        new_path  = text.strip().lstrip("/")
        loading_id = bot.send_message(uid, f"⏳ Moving `{file_path}` → `{new_path}` ···").message_id
        ok = gh.move_file(token, owner, repo, file_path, new_path)
        parent = "/".join(new_path.split("/")[:-1])
        if ok:
            add_history(uid, f"Moved {repo}/{file_path} → {new_path}")
            bot.edit_message_text(
                f"✅ *File moved!*\n\n`{file_path}` → `{new_path}`",
                uid, loading_id,
                reply_markup=kb_edit_cancel(repo, parent),
            )
        else:
            bot.edit_message_text(
                f"❌ Failed to move file. Check the destination path.",
                uid, loading_id,
                reply_markup=kb_file_actions(repo, file_path),
            )
        set_state(uid, State.EDIT_REPO_MENU, draft=u["draft"])
        return True

    return False


# ─────────────────────────────────────────────────────────────
#  /start
# ─────────────────────────────────────────────────────────────

def _auto_delete_command(m: Message) -> None:
    """Best-effort removal of incoming slash commands from the chat.

    Only user-authored messages are removed. When a command function is
    invoked through a menu BUTTON, `m` is the bot's own menu screen; deleting
    it would wipe every other button the user can still tap."""
    try:
        if getattr(m.from_user, "is_bot", False):
            return
        bot.delete_message(m.chat.id, m.message_id)
    except Exception:
        pass


def _require_private_chat(m: Message, action: str) -> bool:
    """Keep credential-bearing flows out of groups and forwarded chats."""
    if getattr(getattr(m, "chat", None), "type", "private") == "private":
        return True
    _auto_delete_command(m)
    bot.send_message(m.chat.id, f"🔒 `{action}` can only be used in a private chat with this bot.",
                     parse_mode="Markdown")
    return False


def _send_temporary_reply(chat_id: int, text: str, **kwargs):
    """Send a short-lived notice and remove it later; leave actionable messages alone."""
    sent = bot.send_message(chat_id, text, **kwargs)
    delay = config.BOT_REPLY_DELETE_SECONDS
    if delay > 0:
        def _delete_later() -> None:
            try:
                bot.delete_message(chat_id, sent.message_id)
            except Exception:
                pass

        timer = threading.Timer(delay, _delete_later)
        timer.daemon = True
        timer.start()
    return sent


@bot.message_handler(commands=["start"])
def cmd_start(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    u   = get_user(uid)
    if not u.get("language_selected"):
        detected = normalize_language(getattr(m.from_user, "language_code", None))
        if u.get("language") != detected:
            u["language"] = detected
            save_user(uid, u)
    log.user(f"{log.mask_user_id(uid, m.from_user.first_name)} /start")
    if not u["welcomed"]:
        text = _tr(uid, "welcome")
        u["welcomed"] = True
        save_user(uid, u)
    else:
        text = _tr(uid, "home_title")
    bot.send_message(uid, text, reply_markup=kb_main_noback(uid))


@bot.message_handler(commands=["menu", "home"])
def cmd_menu(m: Message) -> None:
    """A predictable shortcut back to the main menu from any workflow."""
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    set_state(uid, State.IDLE, draft={})
    bot.send_message(uid, _tr(uid, "home_title"), reply_markup=kb_main_noback(uid))


@bot.message_handler(commands=["cancel"])
def cmd_cancel(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    set_state(uid, State.IDLE, draft={})
    bot.send_message(uid, "✅ Current action cancelled.", reply_markup=kb_main_noback(uid))


# ─────────────────────────────────────────────────────────────
#  /help  /guide  /models
# ─────────────────────────────────────────────────────────────

def _show_language_picker(uid: int, message_id: int = None) -> None:
    current = LANGUAGES.get(normalize_language(get_user(uid).get("language")), "English")
    text = f"{_tr(uid, 'language_title')}\n{_tr(uid, 'language_current', language=current)}"
    markup = kb_language_picker(uid)
    if message_id is None:
        bot.send_message(uid, text, reply_markup=markup)
        return
    try:
        bot.edit_message_text(text, uid, message_id, reply_markup=markup)
    except Exception as exc:
        if "message is not modified" in str(exc).lower():
            return
        bot.send_message(uid, text, reply_markup=markup)


@bot.message_handler(commands=["language"])
def cmd_language(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    _show_language_picker(uid)


def _show_timezone_picker(uid: int, message_id: int = None) -> None:
    current = _user_timezone(uid).key
    text = (
        f"{_tr(uid, 'timezone_title')}\n"
        f"{_tr(uid, 'timezone_current', zone=current)}\n\n"
        f"{_tr(uid, 'timezone_hint')}"
    )
    markup = kb_timezone_picker(uid)
    if message_id is None:
        bot.send_message(uid, text, reply_markup=markup, disable_web_page_preview=True)
        return
    try:
        bot.edit_message_text(text, uid, message_id, reply_markup=markup,
                              disable_web_page_preview=True)
    except Exception as exc:
        if "message is not modified" in str(exc).lower():
            return
        bot.send_message(uid, text, reply_markup=markup, disable_web_page_preview=True)


def _save_timezone(uid: int, zone_name: str) -> str | None:
    try:
        zone = ZoneInfo(zone_name.strip())
    except (ZoneInfoNotFoundError, ValueError):
        return None
    user = get_user(uid)
    user["time_zone"] = zone.key
    save_user(uid, user)
    return zone.key


@bot.message_handler(commands=["timezone"])
def cmd_timezone(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    parts = (m.text or "").strip().split(maxsplit=1)
    if len(parts) == 1:
        _show_timezone_picker(uid)
        return
    zone_name = _save_timezone(uid, parts[1])
    if zone_name is None:
        bot.send_message(uid, _tr(uid, "timezone_invalid"),
                         reply_markup=kb_timezone_picker(uid),
                         parse_mode="Markdown")
        return
    bot.send_message(uid, _tr(uid, "timezone_saved", zone=zone_name),
                     reply_markup=kb_home_only(uid))


@bot.message_handler(commands=["help"])
def cmd_help(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    kb_h = InlineKeyboardMarkup(row_width=2)
    kb_h.add(
        InlineKeyboardButton(f"\U0001f4d6 {_tr(uid, 'guide')}", callback_data="menu_guide"),
        InlineKeyboardButton(f"\U0001f3e0 {_tr(uid, 'home')}", callback_data="menu_home"),
    )
    help_text = _tr(uid, "help_text") + f"\n\n/language - {_tr(uid, 'language')}\n/timezone Area/City - {_tr(uid, 'timezone')}"
    if is_admin(uid):
        help_text += _tr(uid, "admin_help")
    bot.send_message(uid, help_text, parse_mode="Markdown", reply_markup=kb_h,
                     disable_web_page_preview=True)


@bot.message_handler(commands=["guide"])
def cmd_guide(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    kb_g = InlineKeyboardMarkup(row_width=2)
    kb_g.add(
        InlineKeyboardButton(_tr(uid, "help"), callback_data="menu_help"),
        InlineKeyboardButton(f"\U0001f3e0 {_tr(uid, 'home')}", callback_data="menu_home"),
    )
    bot.send_message(uid, _tr(uid, "guide_text"), parse_mode="Markdown",
                     reply_markup=kb_g, disable_web_page_preview=True)


@bot.message_handler(commands=["models"])
def cmd_models(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    lines = [_tr(uid, "models_title") + "\n"]
    for pid, provider in PROVIDERS.items():
        badge = _tr(uid, "free") if provider.get("free") else _tr(uid, "paid")
        lines.append(f"{provider['emoji']} *{provider['name']}* - {badge}")
        lines.append(f"  {_tr(uid, 'suggested')}: `{provider['default']}`")
        alternatives = [model for model in provider.get("models", []) if model != provider["default"]][:3]
        if alternatives:
            lines.append(f"  {_tr(uid, 'also')}: " + ", ".join(f"`{model}`" for model in alternatives))
        lines.append(f"  {_tr(uid, 'set_model')}: `/setai {pid} YOUR_KEY [MODEL_ID]`\n")
    kb_m = InlineKeyboardMarkup(row_width=2)
    kb_m.add(InlineKeyboardButton(_tr(uid, "home"), callback_data="menu_home"))
    bot.send_message(uid, "\n".join(lines), reply_markup=kb_m)


@bot.message_handler(commands=["status"])
def cmd_status(m: Message) -> None:
    _auto_delete_command(m)
    if not _require_private_chat(m, "/status"):
        return
    uid = m.chat.id
    if _check_banned(uid):
        return
    u   = get_user(uid)

    # ── Animated loading ────────────────────────────────────
    msg = bot.send_message(uid, "⏳ Loading status ·")
    _t  = _time.time()

    gh_line      = f"❌ {_tr(uid, 'not_set')}"
    gh_extra     = ""
    gh_profile   = None
    if u.get("github_token"):
        try:
            info = _animate(uid, msg.message_id, "Fetching GitHub info", gh.get_user, u["github_token"])
        except Exception:
            info = None
        if info:
            login         = info["login"]
            live_repos    = info.get("public_repos", 0)
            private_count = info.get("total_private_repos", 0)
            followers     = info.get("followers", 0)
            following     = info.get("following", 0)
            disk_usage    = info.get("disk_usage", 0)
            bio           = _escape_md(str(info.get("bio") or ""))
            name          = _escape_md(str(info.get("name") or login))
            gh_profile    = f"https://github.com/{login}"
            # Contributions (public events count as proxy)
            gh_line  = f"✅ [{login}]({gh_profile})"
            gh_extra = (
                f"\n   👤 *{name}*" +
                (f"\n   _\"{bio}\"_" if bio else "") +
                f"\n\n   🌍 Public repos: *{live_repos}*"
                f"\n   🔒 Private repos: *{private_count}*"
                f"\n   👥 Followers: *{followers}*  ·  Following: *{following}*"
                f"\n   💾 Disk usage: *{disk_usage // 1024 if disk_usage >= 1024 else disk_usage}{'MB' if disk_usage >= 1024 else 'KB'}*"
            )
        else:
            gh_line = f"⚠️ {_tr(uid, 'token_invalid')}"
    else:
        try:
            bot.edit_message_text("⏳ Loading status ··", uid, msg.message_id)
        except Exception:
            pass

    ai_line = f"❌ {_tr(uid, 'not_configured')}"
    if u.get("ai_provider"):
        p      = PROVIDERS.get(u["ai_provider"], {})
        badge  = _tr(uid, "free") if p.get("free") else _tr(uid, "paid")
        model = u.get("ai_model") or p.get("default") or "Default model"
        ai_line = f"✅ {badge} *{u['ai_provider']}* · `{model}`"

    # ── Multi-account summary ─────────────────────────────────
    accounts      = _normalize_accounts(uid, u)
    accounts_line = ""
    if accounts:
        active_lbl    = _active_account_label(u, accounts)
        accounts_line = (
            f"👥 Accounts: *{len(accounts)}* · "
            f"active: *{_escape_md(active_lbl) or '—'}*\n\n"
        )

    protection_line = "✅ Encrypted at rest" if security.is_enabled() else "⚠️ Encryption unavailable"
    setup_items = []
    if not u.get("github_token"):
        setup_items.append("Connect GitHub with /setgithub")
    if not u.get("ai_provider"):
        setup_items.append("Connect AI with /setai")
    setup_line = "✅ Ready to create repositories" if not setup_items else " • ".join(setup_items)

    # ── Pull stats ──────────────────────────────────────────
    def _status_count(key: str) -> int:
        try:
            return max(0, int(u.get(key, 0) or 0))
        except (TypeError, ValueError):
            return 0

    created      = _status_count("repos_created")
    deleted      = _status_count("repos_deleted")
    forked       = _status_count("repos_forked")
    starred      = _status_count("repos_starred")
    archives     = _status_count("archives_uploaded")
    cleared      = _status_count("repos_cleared")
    files_pushed = _status_count("files_pushed")
    since        = u.get("created_at", "")[:10]
    elapsed      = _time.time() - _t

    # Build contribution bar (visual progress)
    total_actions = created + deleted + forked + starred + archives + cleared
    bar_filled  = min(10, total_actions)
    bar_empty   = 10 - bar_filled
    contrib_bar = "🟩" * bar_filled + "⬜" * bar_empty

    status_text = (
        f"📊 *{_tr(uid, 'status_title')}*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔑 *{_tr(uid, 'github')}:* {gh_line}{gh_extra}\n\n"
        f"{accounts_line}"
        f"🤖 *{_tr(uid, 'ai_provider')}:* {ai_line}\n\n"
        f"🛡 *Privacy:* {protection_line}\n"
        f"⚙️ *Next step:* {setup_line}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📈 *{_tr(uid, 'activity_stats')}*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📦 {_tr(uid, 'repos_created')}: *{created}*\n"
        f"🗑 {_tr(uid, 'repos_deleted')}: *{deleted}*\n"
        f"🧹 {_tr(uid, 'repos_cleared')}: *{cleared}*\n"
        f"🍴 {_tr(uid, 'repos_forked')}: *{forked}*\n"
        f"⭐ {_tr(uid, 'repos_starred')}: *{starred}*\n"
        f"📦 {_tr(uid, 'archives_uploaded')}: *{archives}*\n"
        f"📄 {_tr(uid, 'files_pushed')}: *{files_pushed}*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🌱 *{_tr(uid, 'contributions')}*\n"
        f"{contrib_bar}  *{total_actions}* {_tr(uid, 'total_actions')}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🕐 *{_tr(uid, 'member_since')}:* `{since}`\n"
        f"{_tr(uid, 'timezone')}: `{_user_timezone(uid).key}`\n"
        f"⏱ _{_tr(uid, 'loaded_in')} `{elapsed:.1f}s`_"
    )
    kb_status = InlineKeyboardMarkup(row_width=2)
    if gh_profile:
        kb_status.add(InlineKeyboardButton("👤 View GitHub Profile", url=gh_profile))
    if not u.get("github_token"):
        kb_status.add(InlineKeyboardButton("🔑 Connect GitHub", callback_data="github_token_setup"))
    if not u.get("ai_provider"):
        kb_status.add(InlineKeyboardButton("🤖 Connect AI", callback_data="pick_provider_groq"))
    kb_status.add(InlineKeyboardButton("👥 " + _tr(uid, "accounts"), callback_data="menu_accounts"))
    kb_status.add(InlineKeyboardButton(_tr(uid, "home"), callback_data="menu_home"))

    # ── Try to send avatar as photo + caption ────────────────
    try:
        bot.edit_message_text(status_text, uid, msg.message_id,
                              parse_mode="Markdown", reply_markup=kb_status,
                              disable_web_page_preview=True)
    except Exception as exc:
        if "message is not modified" in str(exc).lower():
            return
        bot.send_message(uid, status_text, parse_mode="Markdown",
                         reply_markup=kb_status, disable_web_page_preview=True)

# ─────────────────────────────────────────────────────────────
#  /history
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["history"])
def cmd_history(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    text, page, pages = _render_history(uid, 0)
    bot.send_message(uid, text, reply_markup=kb_history(uid, page, pages),
                     parse_mode="Markdown", disable_web_page_preview=True)


_HISTORY_PAGE_SIZE = 10


def _render_history(uid: int, page: int) -> tuple[str, int, int]:
    history = get_user(uid).get("history", [])
    total = len(history)
    pages = max(1, (total + _HISTORY_PAGE_SIZE - 1) // _HISTORY_PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    if not history:
        return f"{_tr(uid, 'history_title')}\n\n{_tr(uid, 'history_empty')}", page, pages

    start = max(0, total - (page + 1) * _HISTORY_PAGE_SIZE)
    end = total - page * _HISTORY_PAGE_SIZE
    entries = history[start:end]
    summary = _tr(uid, "history_summary", start=start + 1, end=end,
                  total=total, page=page + 1, pages=pages)
    zone_name = _user_timezone(uid).key
    rows = []
    for entry in reversed(entries):
        if isinstance(entry, dict):
            line = _format_history_entry(entry, uid)
        else:
            line = _format_legacy_history_entry(str(entry), uid)
        line = " ".join(line.split())
        escaped = _escape_md(line)
        truncated = len(escaped) > 350
        if truncated:
            escaped = escaped[:350].rstrip("\\")
        rows.append(f"\u2022 {escaped}" + ("\u2026" if truncated else ""))
    zone_line = _tr(uid, "timezone_current", zone=zone_name)
    return f"{_tr(uid, 'history_title')}\n{summary}\n{zone_line}\n\n" + "\n".join(rows), page, pages


def _format_history_entry(entry: dict, uid: int) -> str:
    text = str(entry.get("text", "Activity"))
    try:
        timestamp = datetime.fromisoformat(str(entry.get("at", "")).replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        local_time = timestamp.astimezone(_user_timezone(uid)).strftime("%Y-%m-%d %H:%M")
        return f"[{local_time}] {text}"
    except (TypeError, ValueError, OverflowError):
        return text


def _format_legacy_history_entry(entry: str, uid: int) -> str:
    match = re.match(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}) UTC\]\s*(.*)$", entry)
    if not match:
        return entry
    try:
        timestamp = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
        local_time = timestamp.astimezone(_user_timezone(uid)).strftime("%Y-%m-%d %H:%M")
        return f"[{local_time}] {match.group(2)}"
    except (ValueError, OverflowError):
        return entry


def kb_history(uid: int, page: int, pages: int) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(_tr(uid, "previous"), callback_data=f"history_page_{page - 1}"))
    if page + 1 < pages:
        nav.append(InlineKeyboardButton(_tr(uid, "next"), callback_data=f"history_page_{page + 1}"))
    if nav:
        kb.row(*nav)
    if not get_user(uid).get("history"):
        kb.add(InlineKeyboardButton(_tr(uid, "history_create"), callback_data="menu_create"))
    kb.add(InlineKeyboardButton(f"\U0001f3e0 {_tr(uid, 'home')}", callback_data="menu_home"))
    return kb


@bot.message_handler(commands=["suggest"])
def cmd_suggest(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    u = get_user(uid)
    if not u.get("github_token"):
        _send_github_token_guide(uid)
        return
    if not u.get("ai_provider") or not u.get("ai_key"):
        bot.send_message(uid,
            "🤖 *AI not configured.*\n\nRun /setai to pick a provider and add your key.",
            parse_mode="Markdown")
        return
    set_state(uid, State.AI_SUGGEST_IDEA)
    bot.send_message(uid,
        "✨ *AI Repo Suggester*\n\n"
        "Describe your project idea in plain English — even a rough phrase is fine.\n\n"
        "_Examples:_\n"
        "• `a CLI tool that converts markdown to PDF`\n"
        "• `discord bot for managing study sessions`\n"
        "• `react dashboard for monitoring server stats`\n\n"
        "I'll generate a repo name, description, README, and .gitignore for you! 🚀",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup().add(
            InlineKeyboardButton("❌ Cancel", callback_data="menu_home")
        ),
    )


# ─────────────────────────────────────────────────────────────
#  /admin  — Admin Panel (admin-only command)
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["admin"])
def cmd_admin(m: Message, edit_message_id: int = None) -> None:
    _auto_delete_command(m)
    if not _require_private_chat(m, "/admin"):
        return
    uid = m.chat.id
    if _check_banned(uid):
        return
    if not is_admin(uid):
        bot.send_message(uid, "🚫 *Access denied.* Admin only.", parse_mode="Markdown")
        return
    total_users  = len(_db)
    banned_count = sum(1 for u in _db.values() if u.get("banned"))
    admin_count  = len(ADMIN_IDS)
    total_repos  = sum(u.get("repos_created", 0) for u in _db.values())
    open_tickets = sum(1 for u in _db.values() if u.get("pending_tickets"))
    encrypted_db = "✅ Active" if security.is_enabled() else "⚠️ Unavailable"
    uptime = int(_time.time() - _APP_STARTED_AT)
    text = (
        "🛡 *Admin Panel*\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        f"👥 Total users:     *{total_users}*\n"
        f"🚫 Banned users:    *{banned_count}*\n"
        f"👑 Admins:          *{admin_count}*\n"
        f"📦 Total repos created: *{total_repos}*\n"
        f"🎫 Open tickets: *{open_tickets}*\n\n"
        f"🔐 Database encryption: *{encrypted_db}*\n"
        f"⏱ Uptime: `{uptime // 3600}h {(uptime % 3600) // 60}m`\n\n"
        "_Sensitive data (tokens/keys/history) is never shown here._"
    )
    if edit_message_id:
        try:
            bot.edit_message_text(text, uid, edit_message_id,
                                  parse_mode="Markdown", reply_markup=kb_admin_main())
            return
        except Exception:
            pass
    bot.send_message(uid, text, parse_mode="Markdown", reply_markup=kb_admin_main())


# ─────────────────────────────────────────────────────────────
#  /addadmin USER_ID  — Promote a user to admin
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["addadmin"])
def cmd_addadmin(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    if not is_admin(uid):
        bot.send_message(uid, "🚫 *Access denied.*", parse_mode="Markdown")
        return
    parts = m.text.strip().split()
    if len(parts) < 2 or not parts[1].isdigit():
        bot.send_message(uid, "Usage: `/addadmin USER_ID`", parse_mode="Markdown")
        return
    target = int(parts[1])
    if target == uid:
        bot.send_message(uid, "ℹ️ You're already an admin.", parse_mode="Markdown")
        return
    promote_admin(target)
    bot.send_message(uid, f"✅ User `{target}` promoted to admin.", parse_mode="Markdown")
    try:
        bot.send_message(target, "✅ *You have been granted admin access.*", parse_mode="Markdown")
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────
#  /removeadmin USER_ID  — Demote admin
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["removeadmin"])
def cmd_removeadmin(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    if not is_admin(uid):
        bot.send_message(uid, "🚫 *Access denied.*", parse_mode="Markdown")
        return
    parts = m.text.strip().split()
    if len(parts) < 2 or not parts[1].isdigit():
        bot.send_message(uid, "Usage: `/removeadmin USER_ID`", parse_mode="Markdown")
        return
    target = int(parts[1])
    if target == ADMIN_CHAT_ID:
        bot.send_message(uid, "🚫 Cannot demote the primary admin.", parse_mode="Markdown")
        return
    demote_admin(target)
    bot.send_message(uid, f"✅ User `{target}` removed from admin.", parse_mode="Markdown")
    try:
        bot.send_message(target, "ℹ️ *Your admin access has been removed.*", parse_mode="Markdown")
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────
#  /ban USER_ID  /unban USER_ID
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["ban"])
def cmd_ban(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if not is_admin(uid):
        _send_temporary_reply(uid, "🚫 *Access denied.*", parse_mode="Markdown")
        return
    parts = m.text.strip().split()
    if len(parts) < 2 or not parts[1].isdigit():
        _send_temporary_reply(uid, "Usage: `/ban USER_ID`", parse_mode="Markdown")
        return
    target = int(parts[1])
    if target in ADMIN_IDS:
        _send_temporary_reply(uid, "🚫 Cannot ban an admin.", parse_mode="Markdown")
        return
    ban_user(target)
    _send_temporary_reply(uid, f"✅ User `{target}` has been banned.", parse_mode="Markdown")
    try:
        bot.send_message(target,
            "🚫 *Your account has been suspended.*\n\nContact support if you think this is a mistake.",
            parse_mode="Markdown")
    except Exception:
        pass


@bot.message_handler(commands=["unban"])
def cmd_unban(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if not is_admin(uid):
        _send_temporary_reply(uid, "🚫 *Access denied.*", parse_mode="Markdown")
        return
    parts = m.text.strip().split()
    if len(parts) < 2 or not parts[1].isdigit():
        _send_temporary_reply(uid, "Usage: `/unban USER_ID`", parse_mode="Markdown")
        return
    target = int(parts[1])
    unban_user(target)
    _send_temporary_reply(uid, f"✅ User `{target}` has been unbanned.", parse_mode="Markdown")
    try:
        bot.send_message(target,
            "✅ *Your account has been reinstated. Welcome back!*",
            parse_mode="Markdown")
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────
#  /broadcast MESSAGE  — Send message to all users (admin only)
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["broadcast"])
def cmd_broadcast(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if not is_admin(uid):
        bot.send_message(uid, "🚫 *Access denied.*", parse_mode="Markdown")
        return
    parts = m.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        bot.send_message(uid,
            "Usage: `/broadcast YOUR MESSAGE`\n\nSends to all non-banned users.",
            parse_mode="Markdown")
        return
    msg_text = parts[1]
    sent = 0
    failed = 0
    all_uids = sorted(_runtime_uids)
    status_msg = bot.send_message(uid, f"📢 Broadcasting to {len(all_uids)} users…")
    for target in all_uids:
        if is_banned(target):
            continue
        try:
            bot.send_message(target,
                f"📢 *Announcement from Admin*\n\n{msg_text}",
                parse_mode="Markdown")
            sent += 1
        except Exception:
            failed += 1
    bot.edit_message_text(
        f"📢 *Broadcast complete*\n\n"
        f"✅ Sent: *{sent}*\n"
        f"❌ Failed: *{failed}*",
        uid, status_msg.message_id,
        parse_mode="Markdown",
        reply_markup=kb_admin_back(),
    )


# ─────────────────────────────────────────────────────────────
#  /support MESSAGE  — User sends support ticket to admin
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["support"])
def cmd_support(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    parts = m.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        kb_sp = InlineKeyboardMarkup(row_width=2)
        kb_sp.add(InlineKeyboardButton("\U0001f3e0 Home", callback_data="menu_home"))
        bot.send_message(uid,
            "🎫 *Support*\n\nUsage: `/support YOUR MESSAGE`\n\n"
            "Example: `/support I cannot connect my GitHub token`",
            parse_mode="Markdown", reply_markup=kb_sp)
        return
    ticket_text = parts[1]
    u = get_user(uid)

    # Persist the ticket on the user's own record — this is what makes the
    # admin "🎫 Support Tickets" inbox and the pending-ticket count on the
    # main admin panel actually work, instead of only firing a live
    # notification that's lost if no admin is online to see it.
    ticket = {
        "text": ticket_text,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    u.setdefault("pending_tickets", [])
    u["pending_tickets"].append(ticket)
    # Cap history so a user can't grow their record unbounded by spamming
    # /support — oldest unanswered tickets are dropped first.
    u["pending_tickets"] = u["pending_tickets"][-20:]
    save_user(uid, u)

    # Notify all admins live (best-effort — the persisted ticket above is
    # the source of truth regardless of whether this succeeds).
    admin_msg = (
        f"🎫 *New Support Ticket*\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"👤 User ID: `{uid}`\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"{_escape_md(ticket_text)}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"Reply: `/reply {uid} YOUR REPLY`"
    )
    notified = False
    for admin_id in ADMIN_IDS:
        try:
            bot.send_message(admin_id, admin_msg, parse_mode="Markdown")
            notified = True
        except Exception:
            pass
    if notified:
        bot.send_message(uid,
            "✅ *Your support ticket has been submitted.*\n\n"
            "An admin will respond shortly.",
            parse_mode="Markdown",
            reply_markup=kb_home_only(uid))
    else:
        bot.send_message(uid,
            "⚠️ Could not reach an admin live right now, but your ticket has "
            "been saved and an admin will see it in their inbox.",
            parse_mode="Markdown",
            reply_markup=kb_home_only(uid))


# ─────────────────────────────────────────────────────────────
#  /reply USER_ID MESSAGE  — Admin replies to a support ticket
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["reply"])
def cmd_reply(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if not is_admin(uid):
        bot.send_message(uid, "🚫 *Access denied.*", parse_mode="Markdown")
        return
    parts = m.text.strip().split(maxsplit=2)
    if len(parts) < 3 or not parts[1].isdigit():
        bot.send_message(uid,
            "Usage: `/reply USER_ID YOUR MESSAGE`",
            parse_mode="Markdown")
        return
    target = int(parts[1])
    reply_text = parts[2]
    try:
        bot.send_message(target,
            f"🎫 *Support Reply*\n\n{_escape_md(reply_text)}",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup().add(
                InlineKeyboardButton("🎫 Reply again", callback_data="menu_support"),
                InlineKeyboardButton("🏠 Home", callback_data="menu_home"),
            ))
        # A reply resolves that user's pending tickets — clear them so the
        # inbox and pending-count don't keep showing already-answered items.
        tu = get_user(target)
        if tu.get("pending_tickets"):
            tu["pending_tickets"] = []
            save_user(target, tu)
        bot.send_message(uid, f"✅ Reply sent to `{target}`.", parse_mode="Markdown")
    except Exception as e:
        _safe_user_error(uid, "Support reply", e)


# ─────────────────────────────────────────────────────────────
#  /setgithub
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["setgithub"])
def cmd_setgithub(m: Message) -> None:
    _auto_delete_command(m)
    if not _require_private_chat(m, "/setgithub"):
        return
    parts = m.text.strip().split(maxsplit=1)
    uid   = m.chat.id
    if _check_banned(uid):
        return
    if len(parts) < 2:
        set_state(uid, State.SETUP_GITHUB)
        prompt = bot.send_message(uid, "🔑 Send your GitHub Personal Access Token now:")
        u = get_user(uid)
        u["_pending_github_prompt_id"] = prompt.message_id
        save_user(uid, u)
        return
    token = parts[1].strip()
    _scrub_secret_message(uid, m.message_id)
    _apply_github_token(uid, token)


def _apply_github_token(uid: int, token: str) -> None:
    msg = bot.send_message(uid, "⏳ Verifying token ·")
    _t  = _time.time()
    info = _animate(uid, msg.message_id, "Verifying token", gh.get_user, token)
    if info:
        u = get_user(uid)
        u["github_token"]    = token
        u["github_username"] = info.get("login", "")
        u["state"]           = State.IDLE
        save_user(uid, u)
        login = info["login"]
        # Multi-account: keep the saved account list in sync with /setgithub.
        sync_status = _sync_token_into_accounts(uid, u, token, login)
        full_note = (
            "\n⚠️ _Account list is full ("
            + str(_ACCOUNTS_MAX) + ") — this token is connected but NOT saved "
            "as an account. Remove one via /accounts to save it._"
            if sync_status == "full" else ""
        )
        bot.edit_message_text(
            f"✅ GitHub connected as *{login}*  ⏱ `{(_time.time()-_t):.1f}s`\n"
            f"📦 {info.get('public_repos', 0)} public repos{full_note}",
            uid, msg.message_id,
        )
        add_history(uid, f"GitHub token saved for {login}")
    else:
        bot.edit_message_text(
            "❌ *Token verification failed.*\n\n"
            "Make sure your token:\n• Has the `repo` scope\n• Is not expired\n• Starts with `ghp_`",
            uid, msg.message_id,
        )


def _send_github_token_guide(uid: int) -> None:
    """Show the same safe setup guide wherever GitHub access is required."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("🔗 Open GitHub token settings", url="https://github.com/settings/tokens"),
        InlineKeyboardButton("🔑 Connect token", callback_data="github_token_setup"),
        InlineKeyboardButton("🏠 Home", callback_data="menu_home"),
    )
    try:
        bot.send_message(
            uid,
            "🔑 *GitHub connection required*\n\n"
            "To use repository features, connect a GitHub Personal Access Token.\n\n"
            "*Quick setup*\n"
            "1. Open [GitHub token settings](https://github.com/settings/tokens).\n"
            "2. Create a token with access only to repositories you want this bot to manage.\n"
            "3. For fine-grained tokens, grant repository access and the permissions required for the action you plan to use (for example, repository contents).\n"
            "4. Return to this *private chat* and tap *Connect token*.\n\n"
            "💡 Already have several GitHub accounts? `/accounts` saves them all in "
            "this one chat and switches between them with one tap.\n\n"
            "🛡 _Never send a token in a group. The bot verifies it, encrypts it at rest, and attempts to delete the submitted message._",
            parse_mode="Markdown", reply_markup=kb, disable_web_page_preview=True,
        )
    except Exception:
        # Plain-text fallback so the guide still arrives if Markdown is rejected.
        bot.send_message(
            uid,
            "🔑 GitHub connection required\n\n"
            "To use repository features, connect a GitHub Personal Access Token.\n\n"
            "Quick setup\n"
            "1. Open the GitHub token settings page: https://github.com/settings/tokens\n"
            "2. Create a token with access only to repositories you want this bot to manage.\n"
            "3. Grant the permissions required for the action you plan to use (for example, repository contents).\n"
            "4. Return to this private chat and tap Connect token.\n\n"
            "Tip: already have several GitHub accounts? /accounts saves them all in this one "
            "chat and switches between them with one tap.\n\n"
            "Never send a token in a group. The bot verifies it, encrypts it at rest, and attempts to delete the submitted message.",
            reply_markup=kb,
        )


@bot.message_handler(commands=["disconnectgithub", "removegithub"])
def cmd_disconnectgithub(m: Message) -> None:
    """Ask before removing locally stored GitHub credentials."""
    _auto_delete_command(m)
    if not _require_private_chat(m, "/disconnectgithub"):
        return
    uid = m.chat.id
    if _check_banned(uid):
        return
    if not get_user(uid).get("github_token"):
        bot.send_message(uid, "ℹ️ No GitHub token is currently connected.", reply_markup=kb_home_only(uid))
        return
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("🗑 Remove saved GitHub token", callback_data="github_token_remove_confirm"),
        InlineKeyboardButton("◀ Keep connection", callback_data="menu_home"),
    )
    bot.send_message(
        uid,
        "🔐 *Disconnect GitHub?*\n\n"
        "This removes ALL saved GitHub accounts and tokens (including the multi-account "
        "list) from this bot only. It does not revoke any token or change your GitHub repositories.",
        parse_mode="Markdown", reply_markup=kb,
    )


# ─────────────────────────────────────────────────────────────
#  Multi-Account Manager  (/accounts)
#
#  Connect several GitHub accounts to ONE Telegram chat and
#  switch between them with a single tap — no second Telegram
#  account or bot instance needed.  The active account's token
#  stays in u["github_token"], so every existing feature keeps
#  working unchanged on whichever account is active.
# ─────────────────────────────────────────────────────────────

_ACCOUNTS_MAX = 10


def _normalize_accounts(uid: int, u: dict) -> list:
    """Return the user's saved account list, cleaning shapes and migrating
    a legacy single-token connection into the list on first use."""
    accounts = u.get("github_accounts")
    if not isinstance(accounts, list):
        accounts = []
    cleaned = []
    for acct in accounts:
        if isinstance(acct, dict) and acct.get("token"):
            cleaned.append({
                "label":    str(acct.get("label") or acct.get("username") or "account")[:64],
                "token":    str(acct["token"]),
                "username": str(acct.get("username") or ""),
                "added_at": str(acct.get("added_at") or ""),
            })
    migrated = False
    if not cleaned and u.get("github_token"):
        # First run after the upgrade: adopt the already-connected account.
        login = u.get("github_username") or "account"
        cleaned.append({
            "label":    login,
            "token":    u["github_token"],
            "username": login,
            "added_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
        if not u.get("github_active"):
            u["github_active"] = login
        migrated = True
    elif len(cleaned) != len(accounts):
        migrated = True
    if migrated:
        u["github_accounts"] = cleaned
        save_user(uid, u)
    return cleaned


def _active_account_label(u: dict, accounts: list) -> str:
    """Label of the account whose token is currently active."""
    token = u.get("github_token")
    for acct in accounts:
        if acct["token"] == token:
            return acct["label"]
    return u.get("github_active") or ""


def _activate_account(uid: int, u: dict, acct: dict) -> None:
    """Make *acct* the account every feature operates on. Any in-progress
    draft belongs to the previous account, so it is reset."""
    u["github_token"]    = acct["token"]
    u["github_username"] = acct["username"] or acct["label"]
    u["github_active"]   = acct["label"]
    set_state(uid, State.IDLE, draft={})
    save_user(uid, u)


def _sync_token_into_accounts(uid: int, u: dict, token: str, login: str) -> str:
    """Keep /setgithub results and the account list in sync.

    A brand-new token is added as an account; a re-submitted token for a
    known identity refreshes that entry and activates it.
    Returns "existing", "refreshed", "added" or "full" (list was full, so the
    new token is active but NOT saved as an account).
    """
    accounts = _normalize_accounts(uid, u)
    for acct in accounts:
        if acct["token"] == token:
            acct["username"] = login
            if acct["label"] in ("", "account"):
                acct["label"] = login
            u["github_accounts"] = accounts
            u["github_active"]   = acct["label"]
            save_user(uid, u)
            return "existing"
    for acct in accounts:
        if acct.get("username") == login:
            # Same GitHub identity, fresh token — replace the stored token.
            acct["token"] = token
            u["github_accounts"] = accounts
            u["github_active"]   = acct["label"]
            save_user(uid, u)
            return "refreshed"
    if len(accounts) >= _ACCOUNTS_MAX:
        return "full"   # active token works, but is not saved as an account
    accounts.append({
        "label":    login,
        "token":    token,
        "username": login,
        "added_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    u["github_accounts"] = accounts
    u["github_active"]   = login
    save_user(uid, u)
    return "added"


def _accounts_text(uid: int, u: dict, accounts: list, note: str = "") -> str:
    active_lbl = _escape_md(_active_account_label(u, accounts)) or "—"
    lines = [
        "👥 *My GitHub Accounts*",
        "━━━━━━━━━━━━━━━━━━━━",
        "",
        f"Connected accounts: *{len(accounts)}* / {_ACCOUNTS_MAX}",
        f"Active account: *{active_lbl}*",
        "",
        "Run several GitHub accounts from this ONE chat — tap an account below "
        "to switch instantly. No second Telegram account is needed; every "
        "feature works on whichever account is active.",
    ]
    if note:
        lines += ["", note]
    lines += [
        "",
        "🔐 Tokens are encrypted at rest and are never shown in chat.",
    ]
    return "\n".join(lines)


def _accounts_kb(uid: int, u: dict, accounts: list) -> InlineKeyboardMarkup:
    active = u.get("github_token")
    kb = InlineKeyboardMarkup(row_width=1)
    for i, acct in enumerate(accounts):
        mark  = "✅" if acct["token"] == active else "▫️"
        label = acct["label"]
        if acct.get("username") and acct["username"] != label:
            label = f"{label} ({acct['username']})"
        kb.add(InlineKeyboardButton(f"{mark} {label}", callback_data=f"accsw_{i}"))
    if accounts:
        kb.row(
            InlineKeyboardButton("➕ Add account", callback_data="accadd"),
            InlineKeyboardButton("✏️ Rename",      callback_data="accrename"),
        )
        kb.add(InlineKeyboardButton("🗑 Remove account", callback_data="accdel"))
    else:
        kb.add(InlineKeyboardButton("➕ Connect your first account", callback_data="accadd"))
    kb.add(InlineKeyboardButton(f"🏠 {_tr(uid, 'home')}", callback_data="menu_home"))
    return kb


def _accounts_back_kb(uid: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(row_width=1).add(
        InlineKeyboardButton("👥 Back to accounts", callback_data="menu_accounts"),
        InlineKeyboardButton(f"🏠 {_tr(uid, 'home')}", callback_data="menu_home"),
    )


def _render_accounts(uid: int, message_id: int | None = None, note: str = "") -> None:
    """Draw (or refresh) the My Accounts screen."""
    u        = get_user(uid)
    accounts = _normalize_accounts(uid, u)
    text     = _accounts_text(uid, u, accounts, note=note)
    markup   = _accounts_kb(uid, u, accounts)
    if message_id:
        try:
            bot.edit_message_text(text, uid, message_id,
                                  parse_mode="Markdown", reply_markup=markup)
            return
        except Exception as exc:
            if "message is not modified" in str(exc).lower():
                return
    bot.send_message(uid, text, parse_mode="Markdown", reply_markup=markup)


@bot.message_handler(commands=["accounts"])
def cmd_accounts(m: Message) -> None:
    """Open the multi-account manager."""
    _auto_delete_command(m)
    if not _require_private_chat(m, "/accounts"):
        return
    uid = m.chat.id
    if _check_banned(uid):
        return
    _render_accounts(uid)


def _handle_account_token_input(uid: int, token: str, message_id: int | None) -> None:
    """User sent a token for a NEW account (Accounts ▸ Add account)."""
    token = (token or "").strip()
    set_state(uid, State.IDLE)
    if len(token) < 20 or re.search(r"\s", token):
        bot.send_message(
            uid,
            "❌ That doesn't look like a GitHub Personal Access Token.\n\n"
            "Send the token text itself — no spaces, no quotes.",
            reply_markup=_accounts_back_kb(uid),
        )
        return
    msg = bot.send_message(uid, "⏳ Verifying new account ·")
    try:
        info = _animate(uid, msg.message_id, "Verifying token", gh.get_user, token)
    except Exception:
        info = None
    if not info:
        bot.edit_message_text(
            "❌ *Token verification failed.*\n\nMake sure the token:\n"
            "• Has the `repo` scope\n• Is not expired\n"
            "• Belongs to the account you want to add",
            uid, msg.message_id, parse_mode="Markdown",
            reply_markup=_accounts_back_kb(uid),
        )
        return
    u        = get_user(uid)
    login    = info.get("login", "account")
    accounts = _normalize_accounts(uid, u)
    for acct in accounts:
        if acct["token"] == token:
            # The token already belongs to a saved account. Do NOT flip
            # github_active here: the active token still belongs to another
            # account, so only touching the label would corrupt the state.
            # The user can switch from 👥 My Accounts when they want it.
            bot.edit_message_text(
                f"ℹ️ That token is already saved as *{_escape_md(acct['label'])}* — nothing was added.",
                uid, msg.message_id, parse_mode="Markdown",
                reply_markup=_accounts_back_kb(uid),
            )
            return
    for acct in accounts:
        if acct.get("username") == login:
            # Same GitHub identity with a fresh token — refresh and activate.
            acct["token"]         = token
            u["github_accounts"]  = accounts
            u["github_active"]    = acct["label"]
            u["github_token"]     = token
            u["github_username"]  = login
            set_state(uid, State.IDLE, draft={})
            save_user(uid, u)
            add_history(uid, f"Token refreshed for GitHub account {login}")
            bot.edit_message_text(
                f"🔄 Token updated for *{_escape_md(login)}* and set as the active account.",
                uid, msg.message_id, parse_mode="Markdown",
                reply_markup=_accounts_back_kb(uid),
            )
            return
    if len(accounts) >= _ACCOUNTS_MAX:
        bot.edit_message_text(
            f"⚠️ You can save up to *{_ACCOUNTS_MAX}* accounts.\n"
            "Remove one first, then add the new token.",
            uid, msg.message_id, parse_mode="Markdown",
            reply_markup=_accounts_back_kb(uid),
        )
        return
    new_acct = {
        "label":    login,
        "token":    token,
        "username": login,
        "added_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    accounts.append(new_acct)
    u["github_accounts"] = accounts
    _activate_account(uid, u, new_acct)
    add_history(uid, f"Added GitHub account {login}")
    bot.edit_message_text(
        f"✅ *{_escape_md(login)}* added and set as the active account.\n\n"
        f"📦 {info.get('public_repos', 0)} public repos · "
        f"{len(accounts)}/{_ACCOUNTS_MAX} accounts connected.\n\n"
        "Switch anytime from 👥 My Accounts.",
        uid, msg.message_id, parse_mode="Markdown",
        reply_markup=_accounts_back_kb(uid),
    )


def _handle_account_rename_input(uid: int, label: str, message_id: int | None) -> None:
    """User sent a new label for a saved account (Accounts ▸ Rename)."""
    u     = get_user(uid)
    draft = u.get("draft") or {}
    idx   = draft.get("acc_rename_idx")
    set_state(uid, State.IDLE, draft={})
    accounts = _normalize_accounts(uid, u)
    if not isinstance(idx, int) or not (0 <= idx < len(accounts)):
        bot.send_message(uid, "⚠️ That account no longer exists.",
                         reply_markup=_accounts_back_kb(uid))
        return
    label = (label or "").strip()
    if not label or len(label) > 32 or "\n" in label or label.startswith("/"):
        bot.send_message(
            uid,
            "❌ Invalid name. Use 1-32 characters (no newlines), then try again — "
            "tap ✏️ Rename in the accounts screen.",
            reply_markup=_accounts_back_kb(uid),
        )
        return
    old                   = accounts[idx]["label"]
    accounts[idx]["label"] = label
    u["github_accounts"]   = accounts
    if u.get("github_active") == old:
        u["github_active"] = label
    save_user(uid, u)
    add_history(uid, f"Renamed GitHub account {old} to {label}")
    bot.send_message(
        uid,
        f"✏️ Renamed *{_escape_md(old)}* to *{_escape_md(label)}*.",
        parse_mode="Markdown",
        reply_markup=_accounts_back_kb(uid),
    )


# ─────────────────────────────────────────────────────────────
#  /setai
# ─────────────────────────────────────────────────────────────

def _apply_setai(uid: int, provider: str, api_key: str, model: str | None = None) -> bool:
    """Validate + save an AI provider/key for a user. Shared by /setai and the\n    button-driven provider picker. Sends its own progress + result messages.\n    Returns True on success."""
    provider = (provider or "").lower().strip()
    api_key  = (api_key or "").strip()
    pinfo    = PROVIDERS.get(provider)
    if not pinfo:
        known = ", ".join(f"`{p}`" for p in PROVIDERS)
        bot.send_message(uid, f"❌ Unknown provider `{provider}`.\n\nAvailable: {known}",
                         parse_mode="Markdown")
        return False
    if not api_key:
        bot.send_message(uid, "❌ No API key received. Try /setai again.")
        return False
    model = (model or pinfo["default"]).strip()
    if not re.fullmatch(r"[A-Za-z0-9~][A-Za-z0-9._:/~+-]{0,119}", model):
        bot.send_message(uid, "❌ Invalid model ID. Use letters, numbers, and . _ : / ~ + - only.")
        return False
    # Groq model availability can change independently of this bot release
    # and can differ by account. Resolve against the key's live model list so
    # setup never tests a stale hard-coded model.
    if provider == "groq":
        try:
            model = ai.resolve_groq_model(api_key, model)
        except ai.AIError as e:
            bot.send_message(uid, e.message, reply_markup=kb_home_only(uid))
            return False
    badge = "🆓 FREE" if pinfo["free"] else "💳"
    msg   = bot.send_message(uid, f"⏳ Testing {pinfo['emoji']} {pinfo['name']} ·")
    _t    = _time.time()
    text, err = _animate(
        uid, msg.message_id, f"Testing {pinfo['name']}",
        ai.generate_safe, provider, api_key, model, "Reply with just: OK", max_tokens=10,
    )
    if text:
        u = get_user(uid)
        u["ai_provider"] = provider
        u["ai_key"]      = api_key
        u["ai_model"]    = model
        u.pop("_pending_provider", None)
        save_user(uid, u)
        bot.edit_message_text(
            f"✅ AI configured!  ⏱ `{(_time.time()-_t):.1f}s`\n\n"
            f"{pinfo['emoji']} *{pinfo['name']}* {badge}\nModel: `{model}`",
            uid, msg.message_id, parse_mode="Markdown", reply_markup=kb_home_only(uid),
        )
        add_history(uid, f"AI set: {provider}/{model}")
        return True
    bot.edit_message_text(err or "❌ Unknown error.", uid, msg.message_id,
                          reply_markup=kb_home_only(uid))
    return False


@bot.message_handler(commands=["setai"])
def cmd_setai(m: Message) -> None:
    _auto_delete_command(m)
    if not _require_private_chat(m, "/setai"):
        return
    parts = m.text.strip().split()
    uid   = m.chat.id
    # No provider given → show the tappable provider picker (button-driven flow).
    if len(parts) < 2:
        bot.send_message(uid,
            "🤖 *Choose your AI provider*\n\n"
            "Tap one below to set it up — I'll ask for your API key next.\n"
            "Or type it directly: `/setai PROVIDER YOUR_KEY [MODEL]`",
            parse_mode="Markdown", reply_markup=kb_provider_picker())
        return
    # Provider given but no key → start the key prompt for that provider.
    if len(parts) < 3:
        provider = parts[1].lower()
        if provider not in PROVIDERS:
            known = ", ".join(f"`{p}`" for p in PROVIDERS)
            bot.send_message(uid, f"❌ Unknown provider `{provider}`.\n\nAvailable: {known}",
                             parse_mode="Markdown", reply_markup=kb_provider_picker())
            return
        _prompt_for_ai_key(uid, provider)
        return
    # Provider and key both given inline — capture, scrub, then apply.
    provider_arg = parts[1].lower()
    key_arg      = parts[2]
    model_arg    = parts[3] if len(parts) >= 4 else None
    _scrub_secret_message(uid, m.message_id)
    _apply_setai(uid, provider_arg, key_arg, model_arg)


def _prompt_for_ai_key(uid: int, provider: str) -> None:
    """Store the chosen provider and ask the user to send their API key."""
    pinfo = PROVIDERS.get(provider)
    if not pinfo:
        return
    u = get_user(uid)
    u["_pending_provider"] = provider
    save_user(uid, u)
    set_state(uid, State.SETAI_KEY)
    badge = "🆓 FREE" if pinfo["free"] else "💳"
    hint  = pinfo.get("key_hint", "")
    hint_line = f"\n\n_Keys usually look like:_ `{hint}`" if hint else ""
    prompt = bot.send_message(uid,
        f"🔑 *Send your {pinfo['emoji']} {pinfo['name']} API key* {badge}\n\n"
        f"Paste it in your next message.{hint_line}\n\nTap /cancel to abort.",
        parse_mode="Markdown")
    u = get_user(uid)
    u["_pending_ai_prompt_id"] = prompt.message_id
    save_user(uid, u)


# ─────────────────────────────────────────────────────────────
#  /list_repos
# ─────────────────────────────────────────────────────────────

_MY_REPOS_PAGE_SIZE = 8  # repos per page in My Repos list

def _show_my_repos(uid: int, msg_id: int, page: int = 0, t_start: float = None) -> None:
    """Show paginated repo list."""
    u     = get_user(uid)
    repos = u["draft"].get("my_repos_list", [])
    total = len(repos)
    PAGE  = _MY_REPOS_PAGE_SIZE
    start = page * PAGE
    end   = min(start + PAGE, total)
    page_repos = repos[start:end]

    text = f"📋 *Your Repositories* ({total} total)\n\n"
    for r in page_repos:
        vis   = "🔒" if r.get("private") else "🌍"
        stars = r.get("stargazers_count", 0)
        lang  = r.get("language") or "—"
        text += f"{vis} [`{r['name']}`]({r['html_url']})\n"
        text += f"   ⭐ {stars}  🛠 {lang}\n\n"

    total_pages = max(1, (total + PAGE - 1) // PAGE)
    if t_start:
        text += f"⏱ Loaded in `{(_time.time()-t_start):.1f}s`"

    kb = InlineKeyboardMarkup(row_width=3)
    nav_btns = []
    if page > 0:
        nav_btns.append(InlineKeyboardButton("◀ Prev", callback_data=f"myrepos_page_{page-1}"))
    nav_btns.append(InlineKeyboardButton(f"📄 {page+1}/{total_pages}", callback_data="myrepos_noop"))
    if end < total:
        nav_btns.append(InlineKeyboardButton("Next ▶", callback_data=f"myrepos_page_{page+1}"))
    if nav_btns and total > PAGE:
        kb.row(*nav_btns)
    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))

    try:
        bot.edit_message_text(text, uid, msg_id,
                              disable_web_page_preview=True, reply_markup=kb)
    except Exception:
        bot.send_message(uid, text, disable_web_page_preview=True, reply_markup=kb)


@bot.message_handler(commands=["list_repos"])
def cmd_list_repos(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    u   = get_user(uid)
    if not u.get("github_token"):
        _send_github_token_guide(uid)
        return
    _t    = _time.time()
    msg   = bot.send_message(uid, "⏳ Fetching repositories ·")
    repos = _animate(uid, msg.message_id, "Fetching repositories",
                     gh.list_all_repos, u["github_token"])
    if not repos:
        bot.edit_message_text("📦 No repositories found.", uid, msg.message_id,
                              reply_markup=kb_home_only(uid))
        return
    u["draft"]["my_repos_list"] = repos
    u["draft"]["my_repos_page"] = 0
    save_user(uid, u)
    _show_my_repos(uid, msg.message_id, page=0, t_start=_t)


# ─────────────────────────────────────────────────────────────
#  /create_new_repo
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["create_new_repo"])
def cmd_create_repo(m: Message) -> None:
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    u   = get_user(uid)
    if not u.get("github_token"):
        _send_github_token_guide(uid)
        return
    set_state(uid, State.CREATE_NAME, draft={})
    bot.send_message(
        uid,
        "📦 *Create Repository*\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        "🔤 *Step 1/5 — Name*\n\n"
        "What should the repository be called?\n\n"
        "_Lowercase · hyphens · no spaces_\n\n"
        "Example: `my-awesome-project`",
    )


# ─────────────────────────────────────────────────────────────
#  Delete Repo — V19: Select All, multi-select, Cancel
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["delete_repo"])
def cmd_delete_repo(m: Message) -> None:
    _auto_delete_command(m)
    uid   = m.chat.id
    if _check_banned(uid):
        return
    u     = get_user(uid)
    parts = m.text.strip().split(maxsplit=1)
    if not u.get("github_token"):
        _send_github_token_guide(uid)
        return
    if len(parts) >= 2:
        _confirm_delete(uid, parts[1].strip())
        return
    _show_delete_picker(uid)


@bot.message_handler(commands=["replace_repo"])
def cmd_replace_repo(m: Message) -> None:
    """Clear every file/folder in an existing repo (repo itself is kept)
    and optionally upload a fresh archive in its place."""
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    if not _require_private_chat(m, "replace repo contents"):
        return
    u = get_user(uid)
    if not u.get("github_token"):
        _send_github_token_guide(uid)
        return
    nav_push(uid, "menu_replace_repo", "Replace Repo Contents")
    _show_replace_picker(uid)


@bot.message_handler(commands=["upload"])
def cmd_upload(m: Message) -> None:
    """Upload files/folders into an existing repo (add or replace mode)."""
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    if not _require_private_chat(m, "upload files"):
        return
    u = get_user(uid)
    if not u.get("github_token"):
        _send_github_token_guide(uid)
        return
    nav_push(uid, "menu_upload_files", "Upload to Repo")
    _show_upload_picker(uid)


@bot.message_handler(commands=["preview"])
def cmd_preview(m: Message) -> None:
    """Show the Live Preview screen for one of your repos."""
    _auto_delete_command(m)
    uid = m.chat.id
    if _check_banned(uid):
        return
    if not _require_private_chat(m, "open live preview"):
        return
    u = get_user(uid)
    if not u.get("github_token"):
        _send_github_token_guide(uid)
        return
    nav_push(uid, "menu_live_preview", "Live Preview")
    _show_preview_picker(uid)



# ─────────────────────────────────────────────────────────────
#  Download Repo — helpers
# ─────────────────────────────────────────────────────────────

def _show_download_picker(uid: int, edit_msg_id: int = None, page: int = 0) -> None:
    """Load ALL user repos (public + private) and show the paginated picker."""
    u = get_user(uid)
    # Show loading animation
    if edit_msg_id:
        try:
            bot.edit_message_text("⏳ Loading repositories ·", uid, edit_msg_id)
        except Exception:
            edit_msg_id = bot.send_message(uid, "⏳ Loading repositories ·").message_id
        loading_id = edit_msg_id
    else:
        loading_id = bot.send_message(uid, "⏳ Loading repositories ·").message_id

    repos = _animate(uid, loading_id, "Loading repositories",
                     gh.list_all_repos, u["github_token"])
    if not repos:
        bot.edit_message_text(
            "📦 *No repositories found.*\n\n_Create one first._",
            uid, loading_id, reply_markup=kb_home_only(uid),
        )
        set_state(uid, State.IDLE)
        return

    # Cache repo list and init state
    set_state(uid, State.DOWNLOAD_PICK, draft={
        "dl_repos":    [{"name": r["name"], "private": r.get("private", False)} for r in repos],
        "dl_selected": [],
        "dl_page":     page,
    })
    u = get_user(uid)
    selected = set(u["draft"].get("dl_selected", []))
    total    = len(repos)

    try:
        bot.edit_message_text(
            f"⬇️ *Download Repository*\n\n"
            f"Select one or more repositories to download as ZIP.\n"
            f"🌍 Public · 🔒 Private · Total: *{total}*\n\n"
            f"_Tap to select · ☑️ Select All · ⬇️ Download_",
            uid, loading_id,
            reply_markup=kb_download_picker(u["draft"]["dl_repos"], page, selected),
        )
    except Exception:
        bot.send_message(
            uid,
            f"⬇️ *Download Repository*\n\n"
            f"Select repos to download.  Total: *{total}*",
            reply_markup=kb_download_picker(u["draft"]["dl_repos"], page, selected),
        )


def _execute_download(uid: int, msg_id: int) -> None:
    """Download selected repos as ZIP files and send them to the user."""
    u        = get_user(uid)
    repos    = u["draft"].get("dl_repos", [])
    selected = list(u["draft"].get("dl_selected", []))
    token    = u["github_token"]
    if not selected:
        bot.edit_message_text("Choose at least one repository to download.", uid, msg_id,
                              reply_markup=kb_download_picker(repos, 0, set()))
        return

    info = gh.get_user(token)
    if not info:
        bot.edit_message_text("❌ GitHub token invalid.", uid, msg_id)
        return
    owner = info["login"]

    # Animate start
    try:
        bot.edit_message_text(
            f"⬇️ *Downloading {len(selected)} repo(s)…*\n\n_Please wait, this may take a moment._",
            uid, msg_id,
        )
    except Exception:
        pass

    import concurrent.futures
    repo_by_name = {r.get("name"): r for r in repos if isinstance(r, dict)}

    def _download_one(repo_name: str):
        repo_info = repo_by_name.get(repo_name, {})
        vis_icon = "🔒" if repo_info.get("private", False) else "🌍"
        try:
            repo_meta = gh.get_repo_info(token, owner, repo_name)
            branch = (repo_meta or {}).get("default_branch", "HEAD")
            zip_bytes = gh.download_repo_zipball(token, owner, repo_name, branch)
            if not zip_bytes:
                return False, repo_name, "GitHub returned an empty archive"

            import zipfile
            import io as _io
            import shutil as _shutil
            raw_io = _io.BytesIO(zip_bytes)
            out_io = _io.BytesIO()
            with zipfile.ZipFile(raw_io, "r") as zin:
                namelist = zin.namelist()
                root_prefix = namelist[0].split("/")[0] + "/" if namelist else ""
                with zipfile.ZipFile(out_io, "w", zipfile.ZIP_DEFLATED,
                                     compresslevel=1) as zout:
                    for item in zin.infolist():
                        new_name = item.filename
                        if root_prefix and new_name.startswith(root_prefix):
                            new_name = repo_name + "/" + new_name[len(root_prefix):]
                        if not new_name or new_name.endswith("/"):
                            continue
                        with zin.open(item, "r") as source, zout.open(new_name, "w") as target:
                            _shutil.copyfileobj(source, target, length=1024 * 1024)

            final_bytes = out_io.getvalue()
            fname = f"{repo_name}.zip"
            bot.send_document(
                uid,
                (fname, final_bytes),
                caption=(
                    f"📥 *{vis_icon} {repo_name}*\n"
                    f"📄 `{fname}`  ·  `{len(final_bytes) / 1024:.0f} KB`\n"
                    f"🌿 Branch: `{branch}`\n"
                    f"👤 Owner: `{owner}`"
                ),
                parse_mode="Markdown",
            )
            return True, repo_name, None
        except Exception as ex:
            log.error(f"Download failed for {repo_name}", str(ex)[:100])
            return False, repo_name, str(ex)[:100]

    success = []
    failed = []
    # Keep parallel transfers bounded to avoid exhausting memory or Telegram's
    # per-chat send limits when a user selects many large repositories.
    worker_count = min(config.BULK_DOWNLOAD_WORKERS, len(selected))
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = {pool.submit(_download_one, name): name for name in selected}
        for done, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            try:
                ok, repo_name, error = future.result()
            except Exception as ex:
                ok, repo_name, error = False, futures[future], str(ex)[:100]
            (success if ok else failed).append(repo_name)
            try:
                bot.edit_message_text(
                    f"⏳ Processed {done}/{len(selected)} repositories ⏳",
                    uid, msg_id,
                )
            except Exception:
                pass

    # Final summary
    lines = [f"⬇️ *Download Complete*\n"]
    if success:
        lines.append(f"✅ *{len(success)} downloaded:*")
        for n in success:
            lines.append(f"  • `{n}.zip`")
        lines.append("")
    if failed:
        lines.append(f"❌ *{len(failed)} failed:*")
        for n in failed:
            lines.append(f"  • `{n}`")
        lines.append("")
    lines.append("_All files sent above._")

    try:
        bot.edit_message_text(
            "\n".join(lines),
            uid, msg_id,
            reply_markup=kb_download_result(),
        )
    except Exception:
        bot.send_message(uid, "\n".join(lines), reply_markup=kb_download_result())

    set_state(uid, State.IDLE, draft={})

def _show_delete_picker(uid: int, edit_msg_id: int = None) -> None:
    u        = get_user(uid)
    selected = set(u.get("draft", {}).get("del_selected", []))
    set_state(uid, State.DELETE_PICK, draft={"del_selected": list(selected)})
    if edit_msg_id:
        try:
            bot.edit_message_text("⏳ Loading repositories ·", uid, edit_msg_id)
        except Exception:
            edit_msg_id = bot.send_message(uid, "⏳ Loading repositories ·").message_id
        loading_id = edit_msg_id
    else:
        loading_id = bot.send_message(uid, "⏳ Loading repositories ·").message_id
    repos = _animate(uid, loading_id, "Loading repositories", gh.list_repos, u["github_token"])
    if not repos:
        bot.edit_message_text("📦 No repositories found.\n\n_Create one first._", uid, loading_id)
        set_state(uid, State.IDLE)
        return
    u = get_user(uid)
    u["draft"]["del_repos_cache"] = [{"name": r["name"], "private": r.get("private", False)} for r in repos[:15]]
    save_user(uid, u)
    selected = set(u["draft"].get("del_selected", []))
    try:
        bot.edit_message_text(
            "🗑 *Delete Repository*\n\n"
            "Choose a repository to delete:\n"
            "_Tap multiple to select · ☑️ Select All · then 🗑 Delete Selected_",
            uid, loading_id,
            reply_markup=kb_repo_picker(repos, "del", selected),
        )
    except Exception:
        bot.send_message(
            uid, "🗑 *Delete Repository*\n\nChoose a repository to delete:\n"
            "_Tap multiple to select · ☑️ Select All · then 🗑 Delete Selected_",
            reply_markup=kb_repo_picker(repos, "del", selected),
        )


def _confirm_delete(uid: int, repo_name: str, edit_msg_id: int = None) -> None:
    u    = get_user(uid)
    info = gh.get_user(u["github_token"])
    if not info:
        bot.send_message(uid, "❌ GitHub token invalid.")
        return
    owner = info["login"]
    u["draft"] = {"del_repo": repo_name, "del_owner": owner}
    save_user(uid, u)
    set_state(uid, State.DELETE_CONFIRM)
    confirm_text = (
        f"⚠️ *Confirm Deletion*\n\n"
        f"Are you sure you want to delete `{owner}/{repo_name}`?\n\n"
        f"_This is permanent and cannot be undone._"
    )
    kb = kb_confirm("delete")
    if edit_msg_id:
        try:
            bot.edit_message_text(confirm_text, uid, edit_msg_id, reply_markup=kb)
            return
        except Exception:
            pass
    bot.send_message(uid, confirm_text, reply_markup=kb)


def _confirm_delete_multiple(uid: int, repo_names: list, edit_msg_id: int = None) -> None:
    u    = get_user(uid)
    info = gh.get_user(u["github_token"])
    if not info:
        bot.send_message(uid, "❌ GitHub token invalid.")
        return
    owner = info["login"]
    u["draft"]["del_repos_multi"] = repo_names
    u["draft"]["del_owner"]       = owner
    save_user(uid, u)
    set_state(uid, State.DELETE_CONFIRM)
    names_text   = "\n".join(f"  • `{owner}/{n}`" for n in repo_names)
    confirm_text = (
        f"⚠️ *Confirm Deletion of {len(repo_names)} repos*\n\n"
        f"{names_text}\n\n"
        f"_This is permanent and cannot be undone._"
    )
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton(f"🗑 Delete All {len(repo_names)}", callback_data="confirm_delete_multi"),
    )
    kb.add(
        InlineKeyboardButton("◀ Back",  callback_data="menu_delete"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    if edit_msg_id:
        try:
            bot.edit_message_text(confirm_text, uid, edit_msg_id, reply_markup=kb)
            return
        except Exception:
            pass
    bot.send_message(uid, confirm_text, reply_markup=kb)


def _execute_delete(uid: int, msg_id: int) -> None:
    u         = get_user(uid)
    repo_name = u["draft"].get("del_repo", "")
    owner     = u["draft"].get("del_owner", "")
    _t        = _time.time()
    try:
        ok = _animate(uid, msg_id, f"Deleting `{owner}/{repo_name}`",
                     gh.delete_repo, u["github_token"], owner, repo_name)
    except Exception as ex:
        bot.edit_message_text(
            f"❌ *Failed to delete* `{repo_name}`\n\n`{ex}`\n\n"
            "Make sure your token has the `delete_repo` scope.",
            uid, msg_id,
        )
        u["draft"] = {}
        save_user(uid, u)
        set_state(uid, State.IDLE)
        bot.send_message(uid, "↩️ Back to menu:", reply_markup=kb_main())
        return
    elapsed = _time.time() - _t
    if ok:
        bot.edit_message_text(
            f"✅ *Deleted* `{repo_name}`\n⏱ Done in `{elapsed:.1f}s`\n\n_Repository permanently removed._",
            uid, msg_id,
        )
        add_history(uid, f"Deleted repo: {repo_name}")
        _bump(uid, "repos_deleted")
    else:
        bot.edit_message_text(
            f"❌ *Failed to delete* `{repo_name}`\n\nMake sure your token has the `delete_repo` scope.",
            uid, msg_id,
        )
    u["draft"] = {}
    save_user(uid, u)
    set_state(uid, State.IDLE)
    _show_delete_picker(uid)


def _execute_delete_multiple(uid: int, msg_id: int) -> None:
    u          = get_user(uid)
    owner      = u["draft"].get("del_owner", "")
    repo_names = u["draft"].get("del_repos_multi", [])
    token      = u["github_token"]
    results    = []
    _t         = _time.time()
    for i, repo_name in enumerate(repo_names):
        try:
            bot.edit_message_text(f"⏳ Deleting `{owner}/{repo_name}` ({i+1}/{len(repo_names)}) ···", uid, msg_id)
        except Exception:
            pass
        try:
            ok = gh.delete_repo(token, owner, repo_name)
            results.append((repo_name, ok, None))
            if ok:
                add_history(uid, f"Deleted repo: {repo_name}")
                _bump(uid, "repos_deleted")
        except Exception as ex:
            results.append((repo_name, False, str(ex)))
        _time.sleep(0.3)
    elapsed  = _time.time() - _t
    failed   = [r for r in results if not r[1]]
    lines    = [f"🗑 *Deletion Complete* — ⏱ `{elapsed:.1f}s`\n"]
    for name, ok, err in results:
        lines.append(f"{'✅' if ok else '❌'} `{owner}/{name}`" + (f" — `{err}`" if err else ""))
    if failed:
        lines.append(f"\n⚠️ {len(failed)} failed — check `delete_repo` scope.")
    try:
        bot.edit_message_text("\n".join(lines), uid, msg_id)
    except Exception:
        bot.send_message(uid, "\n".join(lines))
    u["draft"] = {}
    save_user(uid, u)
    set_state(uid, State.IDLE)
    _show_delete_picker(uid)


# ─────────────────────────────────────────────────────────────
#  Replace Repo Contents — clear every file/folder of an
#  existing repo WITHOUT deleting the repo, then optionally
#  upload a fresh archive in its place ("archive-style" reset).
# ─────────────────────────────────────────────────────────────

def _edit_or_send(uid: int, msg_id: int, text: str, **kwargs):
    """Edit a message, falling back to a fresh send when the target message
    can no longer be edited (deleted, too old, etc.)."""
    if msg_id:
        try:
            return bot.edit_message_text(text, uid, msg_id, **kwargs)
        except Exception as exc:
            if "message is not modified" in str(exc).lower():
                return None
    return bot.send_message(uid, text, **kwargs)


def _show_replace_picker(uid: int, edit_msg_id: int = None, page: int = 0) -> None:
    """Load all repos and show the Replace Repo picker (scrollable)."""
    u = get_user(uid)
    if edit_msg_id:
        try:
            bot.edit_message_text("⏳ Loading repositories ·", uid, edit_msg_id)
        except Exception:
            edit_msg_id = bot.send_message(uid, "⏳ Loading repositories ·").message_id
        loading_id = edit_msg_id
    else:
        loading_id = bot.send_message(uid, "⏳ Loading repositories ·").message_id

    repos = _animate(uid, loading_id, "Loading repositories",
                     gh.list_all_repos, u["github_token"])
    if not repos:
        bot.edit_message_text(
            "📦 *No repositories found.*\n\n_Create one first._",
            uid, loading_id, reply_markup=kb_home_only(uid),
        )
        set_state(uid, State.IDLE)
        return

    repo_list = [{"name": r["name"], "private": r.get("private", False)} for r in repos]
    u          = get_user(uid)
    u["draft"]["replace_repos_cache"] = repo_list
    u["draft"]["replace_page"]        = page
    save_user(uid, u)
    set_state(uid, State.REPLACE_PICK, draft=u["draft"])
    total = len(repo_list)
    _edit_or_send(
        uid, loading_id,
        "♻️ *Replace Repo Contents*\n\n"
        "Select the repository whose files you want to wipe.\n"
        "🌍 Public · 🔒 Private · Total: *" + str(total) + "*\n\n"
        "_The repo itself is NOT deleted — stars, settings, URL and history "
        "stay. Only the files and folders on the default branch are removed._",
        reply_markup=kb_replace_picker(repo_list, page),
    )


def _show_replace_menu(uid: int, msg_id: int) -> None:
    """Show the action menu for the chosen repo (clear-only / clear+upload)."""
    u      = get_user(uid)
    target = u["draft"].get("replace_target", "")
    token  = u.get("github_token")
    owner  = u.get("github_username") or (gh.get_user(token) or {}).get("login", "")
    if not target or not owner:
        bot.edit_message_text(
            "⚠️ *Session expired.*\n\nPick the repository again:",
            uid, msg_id,
        )
        _show_replace_picker(uid)
        return
    u["draft"]["replace_owner"] = owner
    save_user(uid, u)

    info = gh.get_repo_info(token, owner, target)
    if not info:
        bot.edit_message_text(
            f"❌ Could not load `{owner}/{target}`. It may have been deleted — "
            "pick another repository.",
            uid, msg_id, reply_markup=kb_home_only(uid),
        )
        return

    vis_txt  = "🔒 Private" if info.get("private") else "🌍 Public"
    branch   = info.get("default_branch") or "main"
    desc     = info.get("description") or "—"
    try:
        tree_items = _animate(uid, msg_id, "Counting files",
                              gh.get_repo_tree, token, owner, target, branch)
    except Exception:
        tree_items = []
    file_count = len(tree_items) if tree_items else 0

    set_state(uid, State.REPLACE_MENU, draft=u["draft"])
    if file_count:
        contents_line = f"📁 *Files on `{branch}`:* {file_count} (all will be removed)"
    else:
        contents_line = f"📁 *Files on `{branch}`:* 0 — repo is already empty"
    text = (
        f"♻️ *Replace Repo — `{target}`*\n\n"
        f"🏷 {vis_txt}  ·  🌿 `{branch}`\n"
        f"📝 _{_escape_md(desc)}_\n"
        f"{contents_line}\n\n"
        "_What would you like to do?_"
    )
    try:
        bot.edit_message_text(text, uid, msg_id, reply_markup=kb_replace_menu())
    except Exception:
        bot.send_message(uid, text, reply_markup=kb_replace_menu())


def _show_replace_clear_warning(uid: int, msg_id: int) -> None:
    """Danger screen: clearing requires typing the repo name (GitHub-style)."""
    u      = get_user(uid)
    target = u["draft"].get("replace_target", "")
    if not target:
        bot.edit_message_text("⚠️ *Session expired.*\n\nPick the repository again:", uid, msg_id)
        _show_replace_picker(uid)
        return
    set_state(uid, State.REPLACE_CLEAR_CONFIRM, draft=u["draft"])
    text = (
        "🧹 *Clear ALL repository contents?*\n\n"
        f"`{target}` will lose *every file and folder* on its default branch.\n\n"
        "✅ The repository itself stays (URL, stars, settings, history)\n"
        "❌ All current files are removed in one commit\n"
        "ℹ️ Old versions remain reachable in the commit history\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        f"✍️ *Type `{target}` below to confirm.*\n"
        "_Any other text cancels nothing — only the exact repo name proceeds._"
    )
    try:
        bot.edit_message_text(text, uid, msg_id, reply_markup=kb_replace_clear_confirm())
    except Exception:
        bot.send_message(uid, text, reply_markup=kb_replace_clear_confirm())


def _execute_replace_clear(uid: int, msg_id: int) -> None:
    """Wipe every tracked file/folder from the repo, keeping the repo alive."""
    u      = get_user(uid)
    target = u["draft"].get("replace_target", "")
    owner  = u["draft"].get("replace_owner") or \
             u.get("github_username") or (gh.get_user(u["github_token"]) or {}).get("login", "")
    token  = u["github_token"]
    _t     = _time.time()
    if not target:
        bot.edit_message_text("⚠️ Session expired. Start again with ♻️ Replace Repo.",
                              uid, msg_id, reply_markup=kb_home_only(uid))
        set_state(uid, State.IDLE, draft={})
        return

    try:
        cleared = _animate(uid, msg_id, f"Clearing `{owner}/{target}`",
                           gh.clear_repo_contents, token, owner, target)
    except Exception as ex:
        _safe_user_error(uid, "Repository clearing", ex, msg_id)
        return

    elapsed = _time.time() - _t
    if cleared:
        bot.edit_message_text(
            "🧹 *Repository cleared!*\n\n"
            f"📦 [`{owner}/{target}`](https://github.com/{owner}/{target})\n"
            f"⏱ Done in `{elapsed:.1f}s`\n\n"
            "All files and folders were removed in one commit.\n"
            "_The repository itself was NOT deleted — you can push new files "
            "whenever you like (e.g. with 📦 Archive Upload → or ♻️ Replace Repo)._",
            uid, msg_id, parse_mode="Markdown", disable_web_page_preview=True,
            reply_markup=kb_home_only(uid),
        )
        add_history(uid, f"Cleared all contents of repo: {target}")
        _bump(uid, "repos_cleared")
        log.ok(f"Cleared repository contents: {owner}/{target}", f"done in {elapsed:.1f}s")
    else:
        bot.edit_message_text(
            f"ℹ️ *Nothing to clear*\n\n`{owner}/{target}` has no commits yet — "
            "it is already empty.",
            uid, msg_id, reply_markup=kb_home_only(uid),
        )
    u["draft"] = {}
    save_user(uid, u)
    set_state(uid, State.IDLE)


def _ask_replace_archive(uid: int, msg_id: int = None) -> None:
    """Ask the user to send the archive that will replace the repo contents."""
    u      = get_user(uid)
    target = u["draft"].get("replace_target", "")
    if not target:
        if msg_id:
            try:
                bot.edit_message_text("⚠️ *Session expired.*\n\nPick the repository again:", uid, msg_id)
            except Exception:
                pass
        _show_replace_picker(uid)
        return
    u["draft"].pop("replace_files", None)
    u["draft"].pop("replace_filename", None)
    u["draft"].pop("replace_readme", None)
    save_user(uid, u)
    set_state(uid, State.REPLACE_UPLOAD, draft=u["draft"])
    text = (
        f"♻️ *Replace contents of `{target}`*\n\n"
        "📦 Send your archive now — ZIP · RAR · tar.gz\n\n"
        "When you confirm:\n"
        f"1️⃣ Every file/folder currently on `{target}` is deleted\n"
        "2️⃣ Your archive is extracted and pushed in its place\n\n"
        "_Folders inside the archive keep their structure. If one wrapper "
        "folder holds every file (e.g. a zipped project folder), it is "
        "unwrapped so files sit at the repository root. "
        "Send /cancel to abort._"
    )
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("◀ Back", callback_data="rr_repomenu"),
        InlineKeyboardButton("🏠 Home",   callback_data="menu_home"),
    )
    if msg_id:
        try:
            bot.edit_message_text(text, uid, msg_id, reply_markup=kb)
            return
        except Exception:
            pass
    bot.send_message(uid, text, reply_markup=kb)


def _store_replace_files(uid: int, files: list, fname: str) -> None:
    """Save extracted archive files into the replace draft and show confirm."""
    u = get_user(uid)
    u["draft"]["replace_files"]    = files
    u["draft"]["replace_filename"] = fname
    readme_file    = next((f for f in files if _is_root_readme(f)), None)
    readme_content = ""
    if readme_file:
        try:
            readme_content = base64.b64decode(readme_file["content_b64"]).decode("utf-8", errors="replace")
        except Exception:
            pass
    u["draft"]["replace_readme"] = readme_content
    save_user(uid, u)
    set_state(uid, State.REPLACE_MENU, draft=u["draft"])
    _show_replace_confirm(uid)


def _show_replace_confirm(uid: int, msg_id: int = None) -> None:
    """Summary + security scan before the destructive replace executes."""
    u      = get_user(uid)
    target = u["draft"].get("replace_target", "")
    fname  = u["draft"].get("replace_filename", "archive.zip")
    files  = u["draft"].get("replace_files", [])

    if not target or not files:
        text = "⚠️ *Session expired.*\n\nPick the repository again:"
        kb   = InlineKeyboardMarkup().add(
            InlineKeyboardButton("♻️ Replace Repo", callback_data="menu_replace_repo"),
            InlineKeyboardButton("🏠 Home",           callback_data="menu_home"),
        )
        if msg_id:
            try:
                bot.edit_message_text(text, uid, msg_id, reply_markup=kb)
            except Exception:
                bot.send_message(uid, text, reply_markup=kb)
        else:
            bot.send_message(uid, text, reply_markup=kb)
        return

    scan = scan_files_for_secrets(files)
    flagged_count = len(scan["flagged_files"])
    security_note = (
        f"🛡 Sensitive data detected in {flagged_count} file(s). "
        "The upload will be blocked until those files are fixed.\n\n"
        if flagged_count else "✅ No sensitive data detected.\n\n"
    )
    text = (
        "━━━━━━━━━━━━━━━━━━━━\n\n♻️ *Confirm Replace*\n\n"
        f"📦 *Repo:* `{target}` — ALL current files will be deleted\n"
        f"🗂 *New archive:* `{fname}`\n"
        f"📁 *New files:* {len(files)}\n\n"
        + security_note +
        "_The repo itself is kept. Ready to clear & upload?_"
    )
    if msg_id:
        try:
            bot.edit_message_text(text, uid, msg_id, reply_markup=kb_replace_confirm())
            return
        except Exception:
            pass
    bot.send_message(uid, text, reply_markup=kb_replace_confirm())


def _handle_replace_archive(uid: int, m: "Message") -> None:
    """Replace-flow archive intake: download → extract → confirm screen."""
    u     = get_user(uid)
    target = u["draft"].get("replace_target", "")
    fname  = m.document.file_name or "archive.zip"
    fname_lower = fname.lower()
    msg    = bot.send_message(uid, f"📦 Downloading `{fname}` ·")
    if not any(fname_lower.endswith(ext) for ext in _ARCHIVE_EXTS):
        _bot_notify(uid, msg.message_id,
                    "⚠️ That file doesn't look like an archive.\n\n"
                    "Supported: ZIP, tar.gz, tgz, tar.bz2, tar.xz, RAR\n\n"
                    "_Send an archive, or tap ◀ Back._")
        return
    if not target:
        _bot_notify(uid, msg.message_id,
                    "⚠️ Session expired — start again with ♻️ Replace Repo.")
        set_state(uid, State.IDLE, draft={})
        return
    try:
        file_info = bot.get_file(m.document.file_id)
        raw       = _animate(uid, msg.message_id, f"Downloading `{fname}`",
                             bot.download_file, file_info.file_path)
        _bot_notify(uid, msg.message_id, f"⏳ Extracting `{fname}` ···")
        try:
            files = _extract_archive(raw, fname, password=None)
        except ArchivePasswordRequired:
            u["draft"].update({
                "replace_raw_b64":  base64.b64encode(raw).decode(),
                "replace_filename": fname,
                "replace_pw_tries": 0,
            })
            save_user(uid, u)
            set_state(uid, State.REPLACE_PASSWORD)
            bot.edit_message_text(
                f"🔐 *Password Required*\n\n"
                f"`{fname}` is encrypted.\n\n"
                "Please send the archive password:\n"
                "_(3 attempts allowed)_",
                uid, msg.message_id,
            )
            return
        except ArchivePasswordWrong:
            tries = u["draft"].get("replace_pw_tries", 0) + 1
            u["draft"]["replace_pw_tries"] = tries
            save_user(uid, u)
            remaining = 3 - tries
            if remaining <= 0:
                set_state(uid, State.IDLE, draft={})
                bot.edit_message_text(
                    "❌ *Wrong password — 3 attempts used.*\n\nReplace cancelled.",
                    uid, msg.message_id, reply_markup=kb_main(),
                )
            else:
                set_state(uid, State.REPLACE_PASSWORD)
                bot.edit_message_text(
                    f"❌ *Wrong password!* ({remaining} attempt{'s' if remaining != 1 else ''} left)\n\n"
                    "Please send the correct password:",
                    uid, msg.message_id,
                )
            return

        ignored_git = _archive_git_metadata_count(files)
        files  = _preserve_archive_paths(files)
        files  = _strip_archive_wrapper(files, fname)
        if not files:
            _bot_notify(uid, msg.message_id, "❌ Archive is empty or contains no extractable files.")
            return
        log.event(
            f"{log.mask_user_id(uid)} replace-archive for `{target}`: {fname}, "
            f"{_archive_file_count_note(len(files), ignored_git)}"
        )
        _store_replace_files(uid, files, fname)
        u = get_user(uid)
        bot.edit_message_text(
            "✅ *Archive extracted!*\n\n"
            f"📦 `{fname}` → *{len(files)} files*\n\n"
            "━━━━━━━━━━━━━━━━━━━━\n\nReview and confirm below 👇",
            uid, msg.message_id,
        )
    except Exception as ex:
        _safe_user_error(uid, "Archive processing", ex, msg.message_id)


def _execute_replace_upload(uid: int, msg_id: int) -> None:
    """Clear the repo and push the new archive files in its place.

    Primary path: ONE atomic Git Data commit built without ``base_tree`` —
    old files dropped and new files added in the same commit, so there is no
    moment where the repo sits half-updated.
    Fallback (git data unavailable): explicit empty-tree clear commit first,
    then the regular archive push pipeline (bulk + per-file retry).
    """
    u      = get_user(uid)
    target = u["draft"].get("replace_target", "")
    files  = list(u["draft"].get("replace_files", []))
    token  = u["github_token"]
    owner  = u["draft"].get("replace_owner") or \
             u.get("github_username") or (gh.get_user(token) or {}).get("login", "")
    _t     = _time.time()

    if not target or not files:
        bot.edit_message_text(
            "⚠️ *Replacement session expired.*\n\nStart again with ♻️ Replace Repo.",
            uid, msg_id, reply_markup=kb_home_only(uid),
        )
        set_state(uid, State.IDLE, draft={})
        return
    if not owner:
        bot.edit_message_text("❌ Could not determine GitHub username.", uid, msg_id)
        return

    if _block_if_sensitive_files(uid, msg_id, files, target, archive=True):
        return

    try:
        bot.edit_message_text(f"♻️ Replacing contents of `{target}` ·", uid, msg_id)
    except Exception:
        pass

    failed_names, ok_count, fail_count, ignored_git = [], 0, 0, 0
    method_note = ""
    replaced = None
    try:
        replaced = _push_files_git_data(token, owner, target, files, msg_id, uid,
                                        show_progress=True, replace=True)
    except Exception as e:
        log.warn(f"Git Data replace errored ({str(e)[:80]}) — trying clear-then-push fallback")

    if replaced is not None:
        ok_count, fail_count, failed_names = replaced
        # Retry any missed blobs one-by-one through the Contents API.
        if failed_names:
            by_path = {f["path"]: f for f in files}
            still_failed = []
            for path in failed_names:
                fobj = by_path.get(path)
                if fobj and _push_one_file(token, owner, target, path, fobj["content_b64"]):
                    ok_count += 1
                else:
                    still_failed.append(path)
            failed_names = still_failed
            fail_count   = len(still_failed)
    else:
        # ── Fallback: clear first, then push through the archive pipeline ──
        try:
            cleared = _animate(uid, msg_id, f"Clearing `{target}`",
                               gh.clear_repo_contents, token, owner, target)
        except Exception as ex:
            _safe_user_error(uid, "Repository clearing", ex, msg_id)
            return
        ok_count, fail_count, failed_names, ignored_git = _push_archive_files(
            token, owner, target, files, msg_id, uid)
        method_note = "\n_Git bulk replace unavailable — used clear-then-upload fallback._"

    elapsed  = _time.time() - _t
    repo_url = f"https://github.com/{owner}/{target}"
    source_file_count = len(files)

    failed_lines = ""
    if fail_count and failed_names:
        names_str = "\n".join(f"  • `{n}`" for n in failed_names[:20])
        if len(failed_names) > 20:
            names_str += f"\n  • … and {len(failed_names) - 20} more"
        failed_lines = f"\n❌ Failed: *{fail_count}* files\n{names_str}\n"

    title = "🎉 *Repo Contents Replaced!*"
    if fail_count:
        title = "⚠️ *Replace Incomplete*"
    lines = [
        title,
        "",
        f"📦 [`{owner}/{target}`]({repo_url})",
        f"⏱ Done in `{elapsed:.1f}s`",
        "",
        f"🧹 Old files: removed",
        f"✅ Uploaded: *{ok_count}* of *{source_file_count}* files",
    ]
    if ignored_git:
        lines.append(f"Local `.git` metadata omitted: *{ignored_git}*")
    lines += [failed_lines, method_note, "", f"🔗 [Open on GitHub]({repo_url})"]
    result_text = "\n".join(lines)

    try:
        bot.edit_message_text(result_text, uid, msg_id, parse_mode="Markdown",
                              disable_web_page_preview=True,
                              reply_markup=kb_preview_added_menu())
    except Exception:
        bot.send_message(uid, result_text, parse_mode="Markdown",
                         disable_web_page_preview=True,
                         reply_markup=kb_preview_added_menu())

    add_history(uid, f"Replaced contents of repo: {target} ({ok_count} files)")
    u["files_pushed"] = u.get("files_pushed", 0) + ok_count
    u["draft"] = {"preview_target": target, "preview_owner": owner}
    save_user(uid, u)
    set_state(uid, State.IDLE)
    log.ok(f"Replaced contents of {owner}/{target}", f"{ok_count} files in {elapsed:.1f}s")


# ─────────────────────────────────────────────────────────────
#  Live Preview — GitHub Pages + instant HTML preview
# ─────────────────────────────────────────────────────────────

_PREVIEW_STATUS_TAG = {
    "building": "🟡 building",
    "built":    "🟢 live",
    "errored":  "🔴 errored",
}


def _show_preview_picker(uid: int, edit_msg_id: int = None, page: int = 0) -> None:
    """Load all repos and show the Live Preview picker (scrollable)."""
    u = get_user(uid)
    if edit_msg_id:
        try:
            bot.edit_message_text("⏳ Loading repositories ·", uid, edit_msg_id)
        except Exception:
            edit_msg_id = bot.send_message(uid, "⏳ Loading repositories ·").message_id
        loading_id = edit_msg_id
    else:
        loading_id = bot.send_message(uid, "⏳ Loading repositories ·").message_id

    repos = _animate(uid, loading_id, "Loading repositories",
                     gh.list_all_repos, u["github_token"])
    if not repos:
        bot.edit_message_text(
            "📦 *No repositories found.*\n\n_Create one first._",
            uid, loading_id, reply_markup=kb_home_only(uid),
        )
        set_state(uid, State.IDLE)
        return

    repo_list = [{"name": r["name"], "private": r.get("private", False)} for r in repos]
    u          = get_user(uid)
    u["draft"]["preview_repos_cache"] = repo_list
    u["draft"]["preview_page"]        = page
    u["draft"].pop("preview_target", None)
    save_user(uid, u)
    set_state(uid, State.PREVIEW_PICK, draft=u["draft"])
    total = len(repo_list)
    _edit_or_send(
        uid, loading_id,
        "👁 *Live Preview*\n\n"
        "Select the repository to preview as a live website.\n"
        "🌍 Public · 🔒 Private · Total: *" + str(total) + "*\n\n"
        "_Shows GitHub Pages status and an instant HTML preview for repos "
        "that contain `index.html` or any `.html` page._",
        reply_markup=kb_preview_picker(repo_list, page),
    )


def _lp_resolve_owner(uid: int, token: str) -> str:
    """Best-effort owner login for the Live Preview screens."""
    u = get_user(uid)
    owner = u["draft"].get("preview_owner") or u.get("github_username")
    if not owner:
        info  = gh.get_user(token)
        owner = (info or {}).get("login", "")
    return owner


def _show_live_preview(uid: int, msg_id: int) -> None:
    """Analyze a repo (branch, HTML entry file, Pages status) and render the
    Live Preview screen with Open / Enable actions."""
    u     = get_user(uid)
    token = u.get("github_token")
    if not token:
        _send_github_token_guide(uid)
        return
    repo = u["draft"].get("preview_target") or ""
    if not repo:
        _show_preview_picker(uid, edit_msg_id=msg_id)
        return
    owner = _lp_resolve_owner(uid, token)
    if not owner:
        bot.edit_message_text("❌ Could not determine GitHub username.", uid, msg_id,
                              reply_markup=kb_home_only(uid))
        return

    try:
        try:
            bot.edit_message_text(f"👁 Analyzing `{repo}` ···", uid, msg_id)
        except Exception:
            pass

        info    = gh.get_repo_info(token, owner, repo)
        if not info:
            u["draft"].pop("preview_target", None)
            save_user(uid, u)
            bot.edit_message_text(
                f"⚠️ Couldn't load `{repo}`.\n\n_The repo may have been renamed or deleted — pick another one._",
                uid, msg_id, reply_markup=kb_home_only(uid))
            return
        branch  = info.get("default_branch") or "main"
        private = bool(info.get("private"))

        tree       = gh.get_repo_tree(token, owner, repo, branch) or []
        html_path  = gh.find_html_entry(tree)
        pages      = gh.get_pages_info(token, owner, repo)
        pages_url  = ((pages or {}).get("html_url")
                      or f"https://{owner}.github.io/{repo}/")
        pages_status = (pages or {}).get("status", "")

        # Persist context so Refresh / Enable Pages callbacks can reuse it.
        u = get_user(uid)
        u["draft"]["preview_owner"]   = owner
        u["draft"]["preview_target"]  = repo
        u["draft"]["preview_branch"]  = branch
        u["draft"]["preview_html"]    = html_path or ""
        u["draft"]["preview_private"] = private
        save_user(uid, u)

        quick_url = ""
        if html_path and not private:
            blob = (f"https://github.com/{owner}/{repo}/blob/{branch}/"
                    f"{_urllib_parse.quote(html_path)}")
            quick_url = f"https://htmlpreview.github.io/?{blob}"

        vis = "🔒 Private" if private else "🌍 Public"
        lines = [
            "👁 *Live Preview*",
            "",
            f"📦 [`{owner}/{repo}`](https://github.com/{owner}/{repo})  ·  {vis}",
            f"🌿 Branch: `{branch}`",
            f"📄 Entry file: `{html_path}`" if html_path
            else "📄 No HTML entry file found (looking for `index.html`)",
            "",
        ]
        if pages:
            lines.append(f"🌐 *GitHub Pages:* {_PREVIEW_STATUS_TAG.get(pages_status, '🟢 live')}")
            lines.append(f"🔗 {pages_url}")
            if pages_status == "building":
                lines.append("_First build can take 1–2 minutes — tap 🔄 Refresh in a moment._")
        else:
            lines.append("⚪ GitHub Pages: *not enabled*")
            if private:
                lines.append("\n_Quick HTML preview can't render private files. "
                             "Pages works on public repos (free plan) or with GitHub Pro._")
            elif html_path:
                lines.append("_Enable Pages below to publish a permanent live site — "
                             "or open the instant preview right now._")
            else:
                lines.append("_Add an `index.html`, then enable Pages to publish your site._")
        text = "\n".join(lines)
        kb = kb_live_preview(
            pages_url=pages_url if pages else "",
            quick_url=quick_url,
            pages_ready=bool(pages),
            enable_btn=not bool(pages),
        )
        try:
            bot.edit_message_text(text, uid, msg_id, parse_mode="Markdown",
                                  disable_web_page_preview=True, reply_markup=kb)
        except Exception:
            bot.send_message(uid, text, parse_mode="Markdown",
                             disable_web_page_preview=True, reply_markup=kb)
        log.event(f"{log.mask_user_id(uid)} live preview: {owner}/{repo} "
                  f"(pages={'on' if pages else 'off'}, html={html_path or 'none'})")
    except Exception as ex:
        _safe_user_error(uid, "Live Preview", ex, msg_id)


def _lp_enable_pages(uid: int, msg_id: int) -> None:
    """Turn on GitHub Pages for the repo cached in the draft and show the
    live URL. Handles the free-plan/private restriction gracefully."""
    u      = get_user(uid)
    token  = u.get("github_token")
    owner  = u["draft"].get("preview_owner")
    repo   = u["draft"].get("preview_target")
    branch = u["draft"].get("preview_branch") or "main"
    if not token or not repo:
        _show_preview_picker(uid, edit_msg_id=msg_id)
        return
    if not owner:
        owner = _lp_resolve_owner(uid, token)
    if not owner:
        bot.edit_message_text("❌ Could not determine GitHub username.", uid, msg_id)
        return

    try:
        try:
            bot.edit_message_text(f"🚀 Enabling GitHub Pages for `{repo}` ···", uid, msg_id)
        except Exception:
            pass
        ok, why = gh.enable_pages(token, owner, repo, branch)
        pages_url = f"https://{owner}.github.io/{repo}/"
        if ok:
            if why == "exists":
                text = (f"🟢 GitHub Pages is *already enabled* for `{repo}`.\n\n"
                        f"🔗 {pages_url}\n\n"
                        "_If the site looks empty, the first build may still be running — "
                        "try again in a minute._")
            else:
                text = (f"🎉 *GitHub Pages enabled!*\n\n"
                        f"📦 `{owner}/{repo}`\n"
                        f"🌐 Live site: {pages_url}\n\n"
                        "_The first build usually takes 1–2 minutes. Open Live Preview "
                        "again to check the status._")
                add_history(uid, f"Enabled GitHub Pages on: {repo}")
            kb = kb_live_preview(pages_url=pages_url, enable_btn=False)
            try:
                bot.edit_message_text(text, uid, msg_id, parse_mode="Markdown",
                                      disable_web_page_preview=True, reply_markup=kb)
            except Exception:
                bot.send_message(uid, text, parse_mode="Markdown",
                                 disable_web_page_preview=True, reply_markup=kb)
            return
        if why == "private":
            text = (f"🔒 *Pages can't be enabled right now*\n\n"
                    f"GitHub Pages for `{repo}` needs the repository to be public "
                    "(free plan) or a paid GitHub plan for private repositories.\n\n"
                    "_Tip: make the repo public via ✏️ Edit Repo → visibility toggle, then retry._")
            try:
                bot.edit_message_text(text, uid, msg_id, parse_mode="Markdown",
                                      reply_markup=kb_live_preview(enable_btn=True))
            except Exception:
                bot.send_message(uid, text, parse_mode="Markdown",
                                 reply_markup=kb_live_preview(enable_btn=True))
            return
        _safe_user_error(uid, "Enabling GitHub Pages", None, msg_id)
    except Exception as ex:
        _safe_user_error(uid, "Enabling GitHub Pages", ex, msg_id)


# ─────────────────────────────────────────────────────────────
#  Upload to Repo — send files/folders into an existing repo
# ─────────────────────────────────────────────────────────────

_UPLOAD_MAX_FILES    = 150                # per-batch cap (security scan friendly)
_UPLOAD_MAX_TG_BYTES = 19 * 1024 * 1024   # Bot API refuses downloads over 20 MB

_ALLOWED_FOLDER_RE = re.compile(r"^[\w.\- /]+$")


def _show_upload_picker(uid: int, edit_msg_id: int = None, page: int = 0) -> None:
    """Load all repos and show the Upload-to-Repo picker (scrollable)."""
    u = get_user(uid)
    if edit_msg_id:
        try:
            bot.edit_message_text("⏳ Loading repositories ·", uid, edit_msg_id)
        except Exception:
            edit_msg_id = bot.send_message(uid, "⏳ Loading repositories ·").message_id
        loading_id = edit_msg_id
    else:
        loading_id = bot.send_message(uid, "⏳ Loading repositories ·").message_id

    repos = _animate(uid, loading_id, "Loading repositories",
                     gh.list_all_repos, u["github_token"])
    if not repos:
        bot.edit_message_text(
            "📦 *No repositories found.*\n\n_Create one first._",
            uid, loading_id, reply_markup=kb_home_only(uid),
        )
        set_state(uid, State.IDLE)
        return

    repo_list = [{"name": r["name"], "private": r.get("private", False)} for r in repos]
    u          = get_user(uid)
    u["draft"]["upload_repos_cache"] = repo_list
    u["draft"]["upload_page"]        = page
    u["draft"].pop("upload_target", None)
    u["draft"].pop("upload_folder", None)
    u["draft"].pop("upload_replace", None)
    u["draft"].pop("upload_files", None)
    u["draft"].pop("upload_status_msg_id", None)
    save_user(uid, u)
    set_state(uid, State.UPLOAD_PICK, draft=u["draft"])
    total = len(repo_list)
    _edit_or_send(
        uid, loading_id,
        "📤 *Upload to Repo*\n\n"
        "Select the repository to upload into.\n"
        "🌍 Public · 🔒 Private · Total: *" + str(total) + "*\n\n"
        "_You'll pick ➕ Add (keep existing files) or 🔄 Replace (delete old "
        "files first) in the next step._",
        reply_markup=kb_upload_picker(repo_list, page),
    )


def _show_upload_path_step(uid: int, msg_id: int) -> None:
    """Ask where inside the repo the queued files should land."""
    u      = get_user(uid)
    target = u["draft"].get("upload_target", "")
    if not target:
        _show_upload_picker(uid, edit_msg_id=msg_id)
        return
    set_state(uid, State.UPLOAD_PATH, draft=u["draft"])
    try:
        bot.edit_message_text(
            "📤 *Upload to Repo*\n\n"
            f"📦 Target: `{target}`\n\n"
            "Where should the files go?\n"
            "• Tap *Repository root* to upload at `/`\n"
            "• Or type a folder path — e.g. `docs` or `assets/images`\n"
            "  _The folder is created automatically if it doesn't exist._",
            uid, msg_id, parse_mode="Markdown", reply_markup=kb_upload_path())
    except Exception:
        bot.send_message(
            uid,
            "📤 *Upload to Repo*\n\n"
            f"📦 Target: `{target}`\n\n"
            "Where should the files go?\n"
            "• Tap *Repository root* to upload at `/`\n"
            "• Or type a folder path — e.g. `docs` or `assets/images`",
            parse_mode="Markdown", reply_markup=kb_upload_path())


def _normalize_upload_folder(text: str):
    """Validate + normalize a user-typed destination folder.

    Returns '' for the repo root, the cleaned relative path on success, or
    None when the input is unsafe (traversal, control chars, too long)."""
    raw = text or ""
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        return None
    p = raw.strip().strip("/")
    p = p.replace("\\", "/")
    p = "/".join(seg.strip() for seg in p.split("/") if seg.strip() not in ("", "."))
    if not p or p == ".":
        return ""
    if ".." in p.split("/"):
        return None
    if len(p) > 300 or not _ALLOWED_FOLDER_RE.match(p):
        return None
    if any(seg == "" for seg in p.split("/")):
        return None
    return p


def _upload_mode_label(u: dict) -> str:
    """Human-readable mode line for the Upload-to-Repo screens."""
    if u["draft"].get("upload_replace"):
        folder = (u["draft"].get("upload_folder") or "").strip("/")
        scope  = f"`/{folder}/`" if folder else "the whole repository"
        return f"🔄 Replace — existing files in {scope} are deleted first"
    return "➕ Add — existing repo files are kept"


def _show_upload_mode_step(uid: int, msg_id: int = None) -> None:
    """Ask whether the upload should ADD to the repo or REPLACE its files.

    Replace semantics (one atomic commit, repo never half-updated):
    • destination = repository root → the repo ends up containing exactly the
      uploaded files (every old file/folder is deleted)
    • destination = a folder → only that folder is emptied, the rest of the
      repo stays untouched
    """
    u      = get_user(uid)
    target = u["draft"].get("upload_target", "")
    if not target:
        _show_upload_picker(uid, edit_msg_id=msg_id)
        return
    folder = (u["draft"].get("upload_folder") or "").strip("/")
    dest   = f"`/{folder}/`" if folder else "`/` (repository root)"
    set_state(uid, State.UPLOAD_MODE, draft=u["draft"])
    text = (
        "📤 *Upload to Repo* — how should we upload?\n\n"
        f"📦 Repo: `{target}`\n"
        f"📁 Destination: {dest}\n\n"
        "➕ *Add files* — your files are added on top of the current "
        "contents; nothing is deleted. Same-named files are updated to your "
        "new version.\n\n"
        "🔄 *Replace files* — existing files are deleted first, then your "
        "upload is pushed. At repository root this syncs the whole repo to "
        "your files; inside a folder only that folder is emptied.\n\n"
        "_Pick a mode below — you can still change the repo or destination after._"
    )
    if msg_id:
        try:
            bot.edit_message_text(text, uid, msg_id, reply_markup=kb_upload_mode())
            return
        except Exception:
            pass
    bot.send_message(uid, text, reply_markup=kb_upload_mode())


def _start_upload_collect(uid: int, msg_id: int = None) -> None:
    """Enter the file-collection stage: user sends files, bot queues them."""
    u = get_user(uid)
    u["draft"].setdefault("upload_replace", False)
    u["draft"]["upload_files"]         = []
    u["draft"]["upload_status_msg_id"] = None
    save_user(uid, u)
    set_state(uid, State.UPLOAD_COLLECT, draft=u["draft"])
    target = u["draft"].get("upload_target", "")
    folder = (u["draft"].get("upload_folder") or "").strip("/")
    dest   = f"`/{folder}/`" if folder else "`/`"
    text   = (
        "📤 *Upload to Repo*\n\n"
        f"📦 Repo: `{target}`\n"
        f"📁 Destination: {dest}\n"
        f"{ _upload_mode_label(u) }\n\n"
        "Now send me the files:\n"
        "• 📄 Any document — code, text, config, PDF, images…\n"
        "• 🖼 Photos (queued as `photo_….jpg`)\n"
        "• 🗜 Archives (ZIP/RAR/tar) are extracted automatically — "
        "folder structure is kept, and a single wrapper folder around all "
        "files is unwrapped so they land right in the chosen folder\n\n"
        "_Send as many as you like, then tap ✅ Done._"
    )
    if msg_id:
        try:
            bot.edit_message_text(text, uid, msg_id, reply_markup=kb_upload_collect(0))
            return
        except Exception:
            pass
    bot.send_message(uid, text, reply_markup=kb_upload_collect(0))


def _upload_show_status(uid: int, note: str = "") -> None:
    """Keep ONE status message updated as files arrive (no message spam)."""
    u        = get_user(uid)
    files    = u["draft"].get("upload_files", [])
    count    = len(files)
    status_id = u["draft"].get("upload_status_msg_id")
    text = (f"📥 *{count} file{'s' if count != 1 else ''} queued*"
            + (f" — {note}" if note else "")
            + "\n\n_Send more, or tap ✅ Done._")
    if status_id:
        try:
            bot.edit_message_text(text, uid, status_id, reply_markup=kb_upload_collect(count))
            return
        except Exception:
            pass
    msg = bot.send_message(uid, text, reply_markup=kb_upload_collect(count))
    u["draft"]["upload_status_msg_id"] = msg.message_id
    save_user(uid, u)


def _handle_upload_file(uid: int, m: "Message") -> None:
    """Queue a photo/document/archive sent by the user into the upload draft."""
    u     = get_user(uid)
    files = u["draft"].setdefault("upload_files", [])
    if len(files) >= _UPLOAD_MAX_FILES:
        bot.send_message(
            uid,
            f"⚠️ *Batch limit reached* ({_UPLOAD_MAX_FILES} files).\n\n"
            "Tap ✅ Done to upload what you have, or 🗑 Clear all & start over.",
            reply_markup=kb_upload_collect(len(files)))
        return
    folder = (u["draft"].get("upload_folder") or "").strip("/")
    prefix = f"{folder}/" if folder else ""

    # ── Photos ────────────────────────────────────────────────
    if m.photo:
        try:
            photo     = max(m.photo, key=lambda p: (p.file_size or 0))
            file_info = bot.get_file(photo.file_id)
            raw       = bot.download_file(file_info.file_path)
            name      = prefix + _time.strftime("photo_%Y%m%d_%H%M%S.jpg")
            files.append({"path":      name,
                          "content_b64": base64.b64encode(raw).decode(),
                          "name":      name.split("/")[-1]})
            u["draft"]["upload_files"] = files
            save_user(uid, u)
            _upload_show_status(uid, f"🖼 last: `{name.split('/')[-1]}`")
        except Exception as ex:
            _safe_user_error(uid, "Photo download", ex)
        return

    doc = m.document
    if not doc:
        return
    fname = (doc.file_name or "file").replace("\\", "/").split("/")[-1] or "file"
    if (doc.file_size or 0) > _UPLOAD_MAX_TG_BYTES:
        bot.send_message(
            uid,
            f"⚠️ `{fname}` is larger than ~19 MB — Telegram's download limit.\n\n"
            "_Tip: compress it, split it, or use the 📦 Archive Upload flow._")
        return
    fname_lower = fname.lower()

    # ── Archives: extract and queue with folder prefix ────────
    if any(fname_lower.endswith(ext) for ext in _ARCHIVE_EXTS):
        msg = bot.send_message(uid, f"🗜 Extracting `{fname}` ···")
        try:
            file_info = bot.get_file(doc.file_id)
            raw       = bot.download_file(file_info.file_path)
            extracted = _extract_archive(raw, fname)
            extracted = _preserve_archive_paths(extracted)
            had_wrapper = bool(_common_dir_prefix([f.get("path", "") for f in extracted]))
            extracted = _strip_archive_wrapper(extracted, fname)
            if not extracted:
                bot.edit_message_text(
                    f"⚠️ `{fname}` is empty — nothing extracted.",
                    uid, msg.message_id, reply_markup=kb_upload_collect(len(files)))
                return
            added = 0
            for f in extracted:
                rel = (f.get("path") or "").lstrip("/")
                if not rel or rel.endswith("/"):
                    continue
                files.append({"path":      prefix + rel,
                              "content_b64": f["content_b64"],
                              "name":      rel.split("/")[-1]})
                added += 1
            u["draft"]["upload_files"] = files[:_UPLOAD_MAX_FILES]
            save_user(uid, u)
            total = len(u["draft"]["upload_files"])
            note = ("\n_Files placed at the destination root — no extra wrapper folder._"
                    if had_wrapper else "")
            bot.edit_message_text(
                f"✅ *`{fname}` extracted* — +{added} file(s), *{total}* queued in total."
                f"{note}",
                uid, msg.message_id, reply_markup=kb_upload_collect(total))
        except ArchivePasswordRequired:
            bot.edit_message_text(
                "🔐 This archive is password-protected.\n\n"
                "_Upload-to-Repo doesn't support encrypted archives — "
                "extract locally and send the files._",
                uid, msg.message_id, reply_markup=kb_upload_collect(len(files)))
        except ArchivePasswordWrong:
            bot.edit_message_text(
                "❌ Wrong archive password — skipped this file.",
                uid, msg.message_id, reply_markup=kb_upload_collect(len(files)))
        except Exception as ex:
            _safe_user_error(uid, "Archive extraction", ex, msg.message_id)
        return

    # ── Regular documents ─────────────────────────────────────
    try:
        file_info = bot.get_file(doc.file_id)
        raw       = bot.download_file(file_info.file_path)
    except Exception as ex:
        _safe_user_error(uid, "File download", ex)
        return
    path = prefix + fname
    files.append({"path":      path,
                  "content_b64": base64.b64encode(raw).decode(),
                  "name":      fname})
    u["draft"]["upload_files"] = files[:_UPLOAD_MAX_FILES]
    save_user(uid, u)
    _upload_show_status(uid, f"📄 last: `{fname}`")


def _block_if_sensitive_upload(uid: int, msg_id: int, files: list, repo_name: str) -> bool:
    """Security gate for the direct Upload-to-Repo flow.

    Same rules as ``_block_if_sensitive_files`` but the resume keyboard strips
    flagged files from the queue instead of asking for a corrected archive."""
    scan = scan_files_for_secrets(files)
    if not scan["flagged_files"] and not scan["truncated_files"]:
        return False
    draft    = get_user(uid).get("draft", {})
    approval = draft.get("_security_upload_approval", {})
    if (scan["flagged_files"] and not scan["truncated_files"]
            and approval.get("archive") is True
            and approval.get("fingerprint") == _security_file_fingerprint(files)):
        return False
    if scan["truncated_files"] and not scan["flagged_files"]:
        text = (
            "🛡 *Upload blocked — scan limit reached*\n\n"
            f"Only the first {_SCAN_MAX_FILES} files can be scanned in one upload; "
            f"{scan['truncated_files']} file(s) were not checked. Split the upload "
            "into smaller batches and retry."
        )
    else:
        text = _format_security_warning(scan, repo_name)
    set_state(uid, State.SEC_WARN_UPLOAD)
    try:
        bot.edit_message_text(text, uid, msg_id, reply_markup=kb_sec_warn_upload())
    except Exception:
        bot.send_message(uid, text, reply_markup=kb_sec_warn_upload())
    return True


def _execute_upload_files(uid: int, msg_id: int) -> None:
    """Push the queued files into the chosen repo at the chosen folder.

    ➕ Add mode (default): single-commit Git Data upload that MERGES with the
    existing branch tree (base_tree kept) — nothing already in the repo is
    removed; failures fall back to the per-file Contents API inside
    _push_archive_files.
    🔄 Replace mode: the repo (root destination) or just the destination
    folder (folder destination) is emptied and the new files pushed in ONE
    atomic commit; failures fall back to clear/delete-then-push.
    """
    u      = get_user(uid)
    target = u["draft"].get("upload_target", "")
    folder = (u["draft"].get("upload_folder") or "").strip("/")
    files  = list(u["draft"].get("upload_files", []))
    token  = u.get("github_token")
    replace_mode = bool(u["draft"].get("upload_replace"))
    _t     = _time.time()

    if not target or not files or not token:
        _bot_notify(uid, msg_id,
                    "⚠️ *Upload session expired.*\n\nStart again with 📤 Upload to Repo.",
                    reply_markup=kb_home_only(uid))
        set_state(uid, State.IDLE, draft={})
        return

    # Same path sent twice → the last version wins (a Git tree can't carry
    # duplicate paths).
    dedup: dict = {}
    for f in files:
        dedup[f["path"]] = f
    files = list(dedup.values())

    owner = u.get("github_username") or _lp_resolve_owner(uid, token)
    if not owner:
        bot.edit_message_text("❌ Could not determine GitHub username.", uid, msg_id)
        return

    if _block_if_sensitive_upload(uid, msg_id, files, target):
        return

    if replace_mode:
        scope_txt = f"`/{folder}/`" if folder else "the whole repository"
        notify = (f"🔄 Replacing contents of {scope_txt} in `{target}` — "
                  f"*{len(files)}* new file(s) ···")
    else:
        notify = f"📤 Uploading *{len(files)}* file(s) to `{target}` ···"
    try:
        _bot_notify(uid, msg_id, notify)
    except Exception:
        pass

    if replace_mode and not folder:
        # ── REPLACE WHOLE REPO (destination = root) ──────────────
        # Primary: ONE atomic commit built without base_tree — old files
        # deleted and new files added together, repo never half-updated.
        ok_count, fail_count, failed_names, ignored_git = 0, 0, [], 0
        replaced = None
        try:
            replaced = _push_files_git_data(token, owner, target, files, msg_id, uid,
                                            show_progress=True, replace=True)
        except Exception as e:
            log.warn(f"Git Data replace errored ({str(e)[:80]}) — trying clear-then-push fallback")
        if replaced is not None:
            ok_count, fail_count, failed_names = replaced
            if failed_names:
                by_path = {f["path"]: f for f in files}
                still_failed = []
                for path in failed_names:
                    fobj = by_path.get(path)
                    if fobj and _push_one_file(token, owner, target, path, fobj["content_b64"]):
                        ok_count += 1
                    else:
                        still_failed.append(path)
                failed_names = still_failed
                fail_count   = len(still_failed)
        else:
            # Fallback: explicit empty-tree clear, then the regular pipeline.
            try:
                _animate(uid, msg_id, f"Clearing `{target}`",
                         gh.clear_repo_contents, token, owner, target)
            except Exception as ex:
                _safe_user_error(uid, "Repository clearing", ex, msg_id)
                return
            ok_count, fail_count, failed_names, ignored_git = _push_archive_files(
                token, owner, target, files, msg_id, uid)
    elif replace_mode and folder:
        # ── REPLACE ONE FOLDER (destination = /folder/) ─────────
        # Primary: one atomic commit that drops only folder/ paths and
        # carries every other existing blob over untouched.
        ok_count, fail_count, failed_names, ignored_git = 0, 0, [], 0
        replaced = None
        try:
            replaced = _push_files_git_data(token, owner, target, files, msg_id, uid,
                                            show_progress=True, replace=True,
                                            drop_prefix=folder)
        except Exception as e:
            log.warn(f"Git Data scoped replace errored ({str(e)[:80]}) — trying delete-then-push fallback")
        if replaced is not None:
            ok_count, fail_count, failed_names = replaced
            if failed_names:
                by_path = {f["path"]: f for f in files}
                still_failed = []
                for path in failed_names:
                    fobj = by_path.get(path)
                    if fobj and _push_one_file(token, owner, target, path, fobj["content_b64"]):
                        ok_count += 1
                    else:
                        still_failed.append(path)
                failed_names = still_failed
                fail_count   = len(still_failed)
        else:
            # Fallback: delete the folder's files one-by-one, then additively
            # push the new files (Contents API path).
            try:
                tree_items = gh.get_repo_tree(token, owner, target)
                prefix     = folder.strip("/") + "/"
                deleted    = 0
                branch     = _gh_default_branch(token, owner, target)
                for item in tree_items:
                    path = str(item.get("path", ""))
                    if path.startswith(prefix):
                        if gh.delete_file(token, owner, target, path,
                                          item.get("sha", ""),
                                          message=f"Delete {path} (folder replace)",
                                          branch=branch):
                            deleted += 1
                log.ok(f"Folder replace fallback on {owner}/{target}",
                       f"deleted {deleted} old file(s) under /{folder}/")
            except Exception as ex:
                log.warn(f"Folder-delete fallback failed: {str(ex)[:120]}")
            ok_count, fail_count, failed_names, ignored_git = _push_archive_files(
                token, owner, target, files, msg_id, uid)
    else:
        # ── ADD (original behaviour): merge with the existing tree ──
        ok_count, fail_count, failed_names, ignored_git = _push_archive_files(
            token, owner, target, files, msg_id, uid)

    elapsed  = _time.time() - _t
    repo_url = f"https://github.com/{owner}/{target}"
    dest     = f"`/{folder}/`" if folder else "`/`"
    mode_ln  = ("🔄 Mode: Replace — old files deleted, new files pushed"
                if replace_mode else
                "➕ Mode: Add — existing repo files kept")

    lines = [
        f"{'🎉 *Upload Complete!*' if not fail_count else '⚠️ *Upload Incomplete*'}",
        "",
        f"📦 [`{owner}/{target}`]({repo_url})",
        f"📁 Destination: {dest}",
        mode_ln,
        f"⏱ Done in `{elapsed:.1f}s`",
        "",
        f"✅ Uploaded: *{ok_count}* of *{len(files)}* files",
    ]
    if fail_count and failed_names:
        fail_items = "".join(f"\n  • `{n}`" for n in failed_names[:10])
        if len(failed_names) > 10:
            fail_items += "\n  • … and more"
        lines.append(f"❌ Failed ({fail_count}):{fail_items}")
    lines += ["", f"🔗 [Open on GitHub]({repo_url})"]
    result_text = "\n".join(lines)
    try:
        bot.edit_message_text(result_text, uid, msg_id, parse_mode="Markdown",
                              disable_web_page_preview=True,
                              reply_markup=kb_upload_result())
    except Exception:
        bot.send_message(uid, result_text, parse_mode="Markdown",
                         disable_web_page_preview=True,
                         reply_markup=kb_upload_result())

    mode_word = "Replaced" if replace_mode else "Uploaded"
    add_history(uid, f"{mode_word} {ok_count} file(s) into {target} "
                     f"({'/' + folder if folder else '/'})")
    u["files_pushed"] = u.get("files_pushed", 0) + ok_count
    # Keep just enough draft for the 👁 Live Preview button on the result.
    u["draft"] = {"preview_target": target, "preview_owner": owner}
    save_user(uid, u)
    set_state(uid, State.IDLE)
    log.ok(f"{'Replace' if replace_mode else 'Upload'} into {owner}/{target}",
           f"{ok_count} files in {elapsed:.1f}s")


# ─────────────────────────────────────────────────────────────
#  Fork Repo — V19: Single / Multiple modes
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["import_repo"])
def cmd_import_repo(m: Message) -> None:
    _auto_delete_command(m)
    uid   = m.chat.id
    u     = get_user(uid)
    parts = m.text.strip().split(maxsplit=1)
    if not u.get("github_token"):
        _send_github_token_guide(uid)
        return
    if len(parts) > 1:
        _process_import(uid, parts[1].strip())
        return
    set_state(uid, State.FORK_MODE_PICK)
    bot.send_message(uid,
        "📥 *Fork Repository*\n\nHow many repositories would you like to fork?",
        reply_markup=kb_fork_mode())


def _process_import(uid: int, url: str) -> None:
    raw   = url.strip().rstrip("/")
    match = re.match(r"https?://github\.com/([^/\s]+)/([^/\s]+?)(?:\.git)?$", raw)
    if not match:
        bot.send_message(uid,
            "❌ *Invalid GitHub URL*\n\nExpected: `https://github.com/owner/repo`\n\n"
            "Examples:\n• `https://github.com/torvalds/linux`\n• `https://github.com/django/django.git`")
        return
    owner, repo = match.group(1), match.group(2)
    u = get_user(uid)
    u["draft"]["fork_owner"] = owner
    u["draft"]["fork_repo"]  = repo
    u["draft"]["fork_url"]   = raw
    save_user(uid, u)
    set_state(uid, State.IMPORT_CONFIRM)
    bot.send_message(uid,
        f"📥 *Confirm Fork*\n━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔗 *URL:* `{raw}`\n👤 *Owner:* `{owner}`\n📦 *Repo:*  `{repo}`\n\n"
        "Tap ✅ to fork or ✏️ to change the URL.",
        reply_markup=kb_fork_confirm(owner, repo))


def _execute_fork(uid: int, msg_id: int) -> None:
    u     = get_user(uid)
    owner = u["draft"].get("fork_owner", "")
    repo  = u["draft"].get("fork_repo", "")
    _t    = _time.time()
    try:
        bot.edit_message_text(f"⏳ Forking `{owner}/{repo}` ·", uid, msg_id)
    except Exception:
        pass
    try:
        data = _animate(uid, msg_id, f"Forking `{owner}/{repo}`", gh.fork_repo, u["github_token"], owner, repo)
        elapsed_s = _time.time() - _t
        fork_url  = data.get('html_url', '')
        fork_name = data.get('full_name', repo)
        bot.edit_message_text(
            f"📥 *Fork Complete* — ⏱ `{elapsed_s:.1f}s`\n\n"
            f"✅ `{fork_name}`\n"
            f"🔗 [View on GitHub]({fork_url})\n\n"
            f"```\ngit clone {fork_url}.git\ncd {fork_name.split('/')[-1]}\n```",
            uid, msg_id, disable_web_page_preview=True,
            reply_markup=kb_home_only(uid))
        add_history(uid, f"Forked {owner}/{repo}")
        _bump(uid, "repos_forked")
    except gh.GitHubError as e:
        bot.edit_message_text(f"❌ Fork failed: `{e.message}`", uid, msg_id,
                              reply_markup=kb_home_only(uid))
    for k in ("fork_owner", "fork_repo", "fork_url"):
        u["draft"].pop(k, None)
    save_user(uid, u)
    set_state(uid, State.IDLE)


def _execute_fork_multi(uid: int, msg_id: int) -> None:
    u       = get_user(uid)
    urls    = u["draft"].get("fork_multi_urls", [])
    token   = u["github_token"]
    _t      = _time.time()
    results = []
    for i, url in enumerate(urls):
        match = re.match(r"https?://github\.com/([^/\s]+)/([^/\s]+?)(?:\.git)?$", url.strip())
        if not match:
            results.append((url, False, "Invalid URL"))
            continue
        owner, repo = match.group(1), match.group(2)
        try:
            bot.edit_message_text(f"⏳ Forking `{owner}/{repo}` ({i+1}/{len(urls)}) ···", uid, msg_id)
        except Exception:
            pass
        try:
            data = gh.fork_repo(token, owner, repo)
            results.append((f"{owner}/{repo}", True, data.get("html_url", "")))
            add_history(uid, f"Forked {owner}/{repo}")
            _bump(uid, "repos_forked")
        except Exception as ex:
            results.append((f"{owner}/{repo}", False, str(ex)))
        _time.sleep(0.5)
    elapsed = _time.time() - _t
    lines   = [f"📥 *Fork Complete* — ⏱ `{elapsed:.1f}s`\n"]
    for name, ok, info in results:
        lines.append(f"{'✅' if ok else '❌'} `{name}`" + (f" — [View]({info})" if ok else f" — `{info}`"))
    try:
        bot.edit_message_text("\n".join(lines), uid, msg_id,
                              disable_web_page_preview=True,
                              reply_markup=kb_home_only(uid))
    except Exception:
        bot.send_message(uid, "\n".join(lines),
                         disable_web_page_preview=True,
                         reply_markup=kb_home_only(uid))
    u["draft"].pop("fork_multi_urls", None)
    save_user(uid, u)
    set_state(uid, State.IDLE)


# ─────────────────────────────────────────────────────────────
#  /star_repo
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["star_repo"])
def cmd_star_repo(m: Message) -> None:
    _auto_delete_command(m)
    uid   = m.chat.id
    parts = m.text.strip().split(maxsplit=1)
    u     = get_user(uid)
    if not u.get("github_token"):
        _send_github_token_guide(uid)
        return
    if len(parts) < 2 or "/" not in parts[1]:
        bot.send_message(uid, "Usage: `/star_repo OWNER/REPO`")
        return
    owner, repo = parts[1].strip().split("/", 1)
    _t  = _time.time()
    msg = bot.send_message(uid, f"⏳ Starring `{owner}/{repo}` ·")
    ok  = _animate(uid, msg.message_id, f"Starring `{owner}/{repo}`", gh.star_repo, u["github_token"], owner, repo)
    if ok:
        bot.edit_message_text(f"⭐ *Starred* `{owner}/{repo}`  ⏱ `{(_time.time()-_t):.1f}s`", uid, msg.message_id)
        add_history(uid, f"Starred {owner}/{repo}")
        _bump(uid, "repos_starred")
    else:
        bot.edit_message_text("❌ Failed. Check the owner/repo name.", uid, msg.message_id)


# ─────────────────────────────────────────────────────────────
#  Animated progress helper
# ─────────────────────────────────────────────────────────────

def _animate(uid: int, msg_id: int, label: str, fn, *args, **kwargs):
    result_box = [None]
    exc_box    = [None]
    done_evt   = threading.Event()

    def _worker():
        try:
            result_box[0] = fn(*args, **kwargs)
        except Exception as ex:
            exc_box[0] = ex
        finally:
            done_evt.set()

    threading.Thread(target=_worker, daemon=True).start()
    dots  = ["·", "··", "···"]
    idx   = 0
    start = _time.time()
    while not done_evt.is_set():
        elapsed = _time.time() - start
        timer   = f"  `{elapsed:.1f}s`" if elapsed >= 1.0 else ""
        try:
            bot.edit_message_text(f"⏳ {label} {dots[idx % 3]}{timer}", uid, msg_id)
        except Exception:
            pass
        done_evt.wait(timeout=0.7)
        idx += 1
    if exc_box[0] is not None:
        raise exc_box[0]
    return result_box[0]


def _escape_md(text: str) -> str:
    """Escape Telegram legacy-Markdown special characters in untrusted text.\n\n    Used specifically for free-form user input (e.g. support ticket bodies)\n    that gets embedded inside a larger ``parse_mode="Markdown"`` message.\n    Without this, a user's message can break the surrounding formatting or\n    inject fake bold/italic/code segments into what an admin reads.\n    Deliberately narrow in scope — the bot's own literal templates elsewhere\n    use real Markdown intentionally and should not be escaped.\n    """
    if not text:
        return text
    for ch in ("\\", "_", "*", "`", "["):
        text = text.replace(ch, "\\" + ch)
    return text


def _scrub_secret_message(uid: int, message_id: int) -> None:
    """Best-effort delete of a message that contained a raw secret\n    (GitHub PAT, AI API key) the moment it's been read.\n\n    Telegram has no way to redact a message's content after the fact —\n    deleting is the only option, and Telegram only allows bots to delete\n    their own messages plus other users' messages sent within the last\n    48 hours in a chat the bot administers. In a private 1:1 chat with the\n    bot (the normal case) this always succeeds. It can silently fail (too\n    old, already deleted, permissions) — that's fine, the goal is "delete\n    when possible," not a guarantee, and failure here must never block the\n    secret from being processed and saved.\n    """
    try:
        bot.delete_message(uid, message_id)
    except Exception:
        pass


def _bot_notify(uid: int, msg_id: int, text: str, reply_markup=None, parse_mode: str = "Markdown") -> None:
    """Edit an existing message; if that fails (too old, deleted, etc.) send a fresh one.\n    This ensures the user always sees the latest status even in long flows."""
    try:
        bot.edit_message_text(text, uid, msg_id, parse_mode=parse_mode,
                              disable_web_page_preview=True,
                              reply_markup=reply_markup)
    except Exception:
        try:
            bot.send_message(uid, text, parse_mode=parse_mode,
                             disable_web_page_preview=True,
                             reply_markup=reply_markup)
        except Exception:
            pass




class ArchivePasswordRequired(Exception):
    """Raised when an archive is encrypted and no password was supplied."""
    pass

class ArchivePasswordWrong(Exception):
    """Raised when the supplied password is incorrect."""
    pass


def _archive_is_encrypted(raw_bytes: bytes, filename: str) -> bool:
    """Quick check: is ANY file inside this archive encrypted?"""
    import zipfile, tarfile
    fname = filename.lower()
    try:
        if fname.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                return any(bool(m.flag_bits & 0x1) for m in zf.infolist())
        elif fname.endswith(".rar"):
            if not _RARFILE_OK:
                return False
            import tempfile, os as _os
            with tempfile.NamedTemporaryFile(suffix=".rar", delete=False) as _tmp:
                _tmp.write(raw_bytes)
                _tmp_path = _tmp.name
            try:
                if _ucffi_rf is not None:
                    rf = _ucffi_rf.RarFile(_tmp_path)
                    # ucffi RarInfo has is_encrypted attribute
                    return any(getattr(info, 'is_encrypted', False) for info in rf.infolist())
                elif _rarfile_mod is not None:
                    with _rarfile_mod.RarFile(_tmp_path) as rf:
                        return rf.needs_password()
                return False
            finally:
                _os.unlink(_tmp_path)
    except Exception:
        pass
    return False


def _rar_to_zip_bytes(raw_bytes: bytes, password: str = None) -> bytes:
    """Convert RAR bytes → ZIP bytes in-memory.\n    Uses unrar-cffi (pure Python, no external tool) if available,\n    then falls back to rarfile with auto-detected unrar/7z."""
    import tempfile, os as _os, zipfile as _zipfile

    with tempfile.NamedTemporaryFile(suffix=".rar", delete=False) as _tmp:
        _tmp.write(raw_bytes)
        _tmp_path = _tmp.name

    try:
        # ── Path A: unrar-cffi (no external binary needed) ──────────────
        if _ucffi_rf is not None:
            rf = _ucffi_rf.RarFile(_tmp_path)
            zip_buf = io.BytesIO()
            with _zipfile.ZipFile(zip_buf, "w", _zipfile.ZIP_DEFLATED) as zout:
                for info in rf.infolist():
                    if not info.is_dir():
                        try:
                            data = rf.read(info)
                            zout.writestr(info.filename, data)
                        except Exception as _e:
                            err = str(_e).lower()
                            if "password" in err or "wrong" in err or "crc" in err:
                                raise ArchivePasswordWrong()
                            raise
            return zip_buf.getvalue()

        # ── Path B: rarfile with auto-detected tool ──────────────────────
        if _rarfile_mod is not None:
            with _rarfile_mod.RarFile(_tmp_path) as rf:
                if rf.needs_password() and not password:
                    raise ArchivePasswordRequired()
                if password:
                    rf.setpassword(password)
                zip_buf = io.BytesIO()
                with _zipfile.ZipFile(zip_buf, "w", _zipfile.ZIP_DEFLATED) as zout:
                    for member in rf.infolist():
                        if member.is_dir():
                            dirname = member.filename.replace("\\", "/").rstrip("/")
                            if dirname:
                                zout.writestr(dirname + "/", b"")
                        else:
                            try:
                                data = rf.read(member)
                                zout.writestr(member.filename, data)
                            except (_rarfile_mod.RarWrongPassword, _rarfile_mod.RarCRCError):
                                raise ArchivePasswordWrong()
                return zip_buf.getvalue()

        raise ValueError("No RAR extraction backend available.")

    finally:
        _os.unlink(_tmp_path)


# ── Decompression-bomb guards ────────────────────────────────
# Keep decompression safely below GitHub's blob limit.  This is intentionally
# lower than GitHub's 100 MiB API maximum so one compressed member cannot make
# the bot allocate an unsafe amount of memory.
_ARCHIVE_MAX_FILE_BYTES = 25 * 1024 * 1024
_ARCHIVE_MAX_TOTAL_BYTES = 100 * 1024 * 1024


class ArchiveTooLargeError(ValueError):
    """Raised when a single archive file exceeds GitHub's Git blob size limit."""
    pass


def _extract_archive(raw_bytes: bytes, filename: str, password: str = None) -> list:
    """\n    Extract archive bytes → list of {path, content_b64}.\n    Supports: .zip, .tar.gz, .tgz, .tar.bz2, .tar.xz, .tar, .rar\n    RAR files are auto-converted to ZIP if rarfile is available, otherwise raises a clear error.\n    Pass password=str to unlock encrypted archives.\n    Raises ArchivePasswordRequired if encrypted and no password given.\n    Raises ArchivePasswordWrong if password is incorrect.\n    Raises ArchiveTooLargeError if the archive would exceed the extraction\n    safety caps (guards against decompression / zip-bomb attacks).\n    """
    import zipfile, tarfile
    files = []
    extracted_total = 0
    fname = filename.lower()
    pwd_bytes = password.encode() if password else None
    def _read_member(stream, path):
        # Bound decompression while reading. Checking len(data) in _add after
        # an unbounded read lets a ZIP bomb exhaust memory before it is rejected.
        data = stream.read(_ARCHIVE_MAX_FILE_BYTES + 1)
        if len(data) > _ARCHIVE_MAX_FILE_BYTES:
            raise ArchiveTooLargeError(
                f"File `{path}` exceeds the {_ARCHIVE_MAX_FILE_BYTES // (1024 * 1024)} MB per-file limit."
            )
        return data

    def _add(path, data):
        nonlocal extracted_total
        # Keep the complete nested layout while converting archive paths to
        # safe repo-relative POSIX paths. Resolve dot segments without ever
        # allowing a path to escape the repository root.
        raw_path = (path or "").replace("\\", "/")
        segs = []
        for segment in raw_path.split("/"):
            if segment in ("", "."):
                continue
            if segment == "..":
                if segs:
                    segs.pop()
                continue
            segs.append(segment)
        path = "/".join(segs)
        if not path:
            return
        if len(data) > _ARCHIVE_MAX_FILE_BYTES:
            raise ArchiveTooLargeError(
                f"File `{path}` is {len(data) / (1024 * 1024):.1f} MB uncompressed, "
                f"which exceeds the {_ARCHIVE_MAX_FILE_BYTES // (1024 * 1024)} MB per-file limit."
            )
        extracted_total += len(data)
        if extracted_total > _ARCHIVE_MAX_TOTAL_BYTES:
            raise ArchiveTooLargeError(
                f"Archive exceeds the {_ARCHIVE_MAX_TOTAL_BYTES // (1024 * 1024)} MB total extraction limit."
            )
        files.append({"path": path, "content_b64": base64.b64encode(data).decode()})

    # ── RAR: auto-convert to ZIP first ──────────────────────────────────────
    if fname.endswith(".rar"):
        if not _RARFILE_OK:
            raise ValueError(
                "RAR support requires the `rarfile` package plus a system "
                "unrar/7z tool.\n"
                "Install: `pip install rarfile` and `apt-get install p7zip-full` "
                "(already included in the provided Dockerfile)."
            )
        # Convert RAR → ZIP in-memory, then fall through to ZIP extraction
        raw_bytes = _rar_to_zip_bytes(raw_bytes, password=password)
        fname = fname[:-4] + ".zip"
        # password already consumed during conversion — don't pass it again
        pwd_bytes = None
        password = None

    if fname.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
            # detect encryption
            encrypted = any(bool(m.flag_bits & 0x1) for m in zf.infolist() if not m.is_dir())
            if encrypted and not pwd_bytes:
                raise ArchivePasswordRequired()
            for member in zf.infolist():
                if member.is_dir():
                    continue
                if member.file_size > _ARCHIVE_MAX_FILE_BYTES:
                    raise ArchiveTooLargeError(
                        f"File `{member.filename}` exceeds the {_ARCHIVE_MAX_FILE_BYTES // (1024 * 1024)} MB per-file limit."
                    )
                else:
                    try:
                        with zf.open(member, pwd=pwd_bytes) as f:
                            _add(member.filename, _read_member(f, member.filename))
                    except RuntimeError as e:
                        if "password" in str(e).lower() or "bad password" in str(e).lower():
                            raise ArchivePasswordWrong()
                        raise
                    except ArchiveTooLargeError:
                        raise
                    except Exception as exc:
                        raise ValueError(
                            f"Could not extract archive member `{member.filename}`: {str(exc)[:160]}"
                        ) from exc

    elif any(fname.endswith(ext) for ext in (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        # tar archives don't support native encryption — extract normally
        with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:*") as tf:
            for member in tf.getmembers():
                if member.isdir():
                    continue
                elif member.isfile():
                    if member.size > _ARCHIVE_MAX_FILE_BYTES:
                        raise ArchiveTooLargeError(
                            f"File `{member.name}` is {member.size / (1024 * 1024):.1f} MB, "
                            f"which exceeds the {_ARCHIVE_MAX_FILE_BYTES // (1024 * 1024)} MB per-file limit."
                        )
                    try:
                        f = tf.extractfile(member)
                        if f:
                            _add(member.name, _read_member(f, member.name))
                    except ArchiveTooLargeError:
                        raise
                    except Exception as exc:
                        raise ValueError(
                            f"Could not extract archive member `{member.name}`: {str(exc)[:160]}"
                        ) from exc

    else:
        raise ValueError(
            f"Unsupported archive format: `{filename}`\n"
            "Supported: `.zip` · `.tar.gz` · `.tgz` · `.tar.bz2` · `.tar.xz` · `.tar` · `.rar`"
        )

    return files


def _preserve_archive_paths(files: list) -> list:
    """Drop only local Git internals; preserve the archive's original paths."""
    if not files:
        return files
    is_git_metadata = lambda f: any(
        part.casefold() == ".git"
        for part in str(f.get("path", "")).replace("\\", "/").split("/")
    )
    git_metadata_count = sum(1 for f in files if is_git_metadata(f))
    if git_metadata_count:
        files = [f for f in files if not is_git_metadata(f)]
    return files


def _archive_git_metadata_count(files: list) -> int:
    """Count local .git entries that cannot be included in a GitHub repository."""
    return sum(
        1 for f in files
        if any(part.casefold() == ".git" for part in
               str(f.get("path", "")).replace("\\", "/").split("/"))
    )


def _archive_file_count_note(total: int, ignored_git: int) -> str:
    """Explain why fewer files are queued than the archive contains."""
    if not ignored_git:
        return f"{total} files found"
    return f"{total} files found; {ignored_git} local .git files omitted, {total - ignored_git} project files ready"


def _common_dir_prefix(paths: list) -> str:
    """Longest leading directory path shared by EVERY path (whole segments only).

    Returns '' when the files have no common parent folder. The returned prefix
    never includes a filename segment: if the shared segments would consume an
    entire path, the last shared segment is dropped (this only guards
    pathological archives where a file and a folder share the same name).
    """
    if not paths:
        return ""
    seg_lists = []
    for p in paths:
        clean = str(p).replace("\\", "/").strip("/")
        if not clean:
            return ""           # a pathless entry blocks any unwrap
        seg_lists.append(clean.split("/"))
    common = seg_lists[0]
    for segs in seg_lists[1:]:
        new = []
        for a, b in zip(common, segs):
            if a == b:
                new.append(a)
            else:
                break
        common = new
        if not common:
            return ""
    # Never swallow a filename: if some path ends exactly at the shared
    # prefix, the last shared segment is that file's name, not a folder.
    while common and any(len(s) <= len(common) for s in seg_lists):
        common = common[:-1]
    return "/".join(common)


def _strip_archive_wrapper(files: list, filename: str) -> list:
    """Remove wrapper folders so extracted files land at the repository root.

    Two passes, both structure-preserving:

    1. Name pass — strips the classic ``<archive-name>/`` wrapper that
       "compress folder" tools and GitHub zipballs create.
    2. Structure pass — strips ANY single top-level folder that contains
       every file in the archive. This covers renamed archives (e.g.
       ``my-theme.zip`` holding ``github-automation-improved/``), double
       nesting, and re-zipped downloads whose wrapper no longer matches the
       file name.

    Folder structure *below* the wrapper is always kept (``src/``, ``assets/``,
    ``.github/workflows/`` … stay exactly where they are). Archives whose
    files already sit at several top-level entries are left untouched.
    """
    if not files:
        return files

    # ── Pass 1: archive-name wrapper ─────────────────────────
    archive_name = os.path.basename(filename or "")
    lower_name = archive_name.lower()
    for ext in (".tar.bz2", ".tar.gz", ".tar.xz", ".tgz", ".zip", ".rar", ".tar"):
        if lower_name.endswith(ext):
            archive_name = archive_name[:-len(ext)]
            break
    wrapper = archive_name.strip().casefold()
    if wrapper:
        paths = [str(f.get("path", "")).replace("\\", "/") for f in files]
        if all(path.casefold().startswith(wrapper + "/") for path in paths):
            for file_entry, path in zip(files, paths):
                _first, _sep, rest = path.partition("/")
                file_entry["path"] = rest

    # ── Pass 2: any single common top-level folder ───────────
    prefix = _common_dir_prefix([f.get("path", "") for f in files])
    if prefix:
        cut = len(prefix) + 1
        for file_entry in files:
            # Normalize the entry path exactly like _common_dir_prefix does,
            # so backslash separators and stray slashes can't survive the cut.
            clean = str(file_entry.get("path", "")).replace("\\", "/").strip("/")
            file_entry["path"] = clean[cut:]
    return files


def _is_root_readme(file_entry: dict) -> bool:
    """Match only a repository-root README, leaving nested README files intact."""
    path = str((file_entry or {}).get("path", "")).replace("\\", "/").strip("/")
    return path.casefold() == "readme.md"


def _github_retry_delay(response, attempt: int) -> float:
    """Respect GitHub's retry hints, with a capped exponential fallback."""
    retry_after = (getattr(response, "headers", {}) or {}).get("Retry-After")
    try:
        if retry_after is not None:
            return min(max(float(retry_after), 1.0), 120.0)
    except (TypeError, ValueError):
        pass
    reset = (getattr(response, "headers", {}) or {}).get("X-RateLimit-Reset")
    try:
        if reset:
            return min(max(float(reset) - _time.time(), 1.0), 120.0)
    except (TypeError, ValueError):
        pass
    return min(2 ** attempt, 30)


def _github_response_message(response) -> str:
    try:
        return str(response.json().get("message") or response.text[:180])
    except Exception:
        return str(getattr(response, "text", "") or "")[:180]


def _push_one_file(token: str, owner: str, repo: str, path: str, content_b64: str, retries: int = 8) -> bool:
    """\n    Upload a single file to GitHub with automatic SHA refresh and retry.\n    Uses exponential back-off. Returns True on success.\n    """
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    # URL-encode each path segment (keep "/" as separators). Spaces, unicode,
    # parentheses, "#", "+" etc. otherwise produce a silent 404 on the PUT.
    safe_path = "/".join(_urllib_parse.quote(seg) for seg in path.split("/"))
    url       = f"https://api.github.com/repos/{owner}/{repo}/contents/{safe_path}"
    for attempt in range(retries):
        try:
            # Fetch the current SHA before every write. Only a real 404 means
            # the file is new; a rate limit/auth/network response must never be
            # mistaken for "not found" or the following PUT will fail too.
            sha_r = _github_upload_session.get(url, headers=headers, timeout=20)
            if sha_r.status_code == 200:
                sha = sha_r.json().get("sha")
            elif sha_r.status_code == 404:
                sha = None
            elif sha_r.status_code in (403, 429) or sha_r.status_code >= 500:
                if attempt < retries - 1:
                    _time.sleep(_github_retry_delay(sha_r, attempt))
                    continue
                log.warn(f"Contents lookup failed for {path} (HTTP {sha_r.status_code}): {_github_response_message(sha_r)}")
                return False
            else:
                log.warn(f"Contents lookup failed for {path} (HTTP {sha_r.status_code}): {_github_response_message(sha_r)}")
                return False
            payload = {"message": f"Add {path}", "content": content_b64}
            if sha:
                payload["sha"] = sha
            r = _github_upload_session.put(url, headers=headers, json=payload, timeout=60)
            if r.status_code in (200, 201):
                return True
            # 409 = conflict (e.g. parallel write), 422 = stale SHA → retry
            if r.status_code in (409, 422) and attempt < retries - 1:
                _time.sleep(min(1.0 * (attempt + 1), 8.0))
                continue
            # 403/429 = rate-limited → back off longer
            if r.status_code in (403, 429) and attempt < retries - 1:
                _time.sleep(_github_retry_delay(r, attempt))
                continue
            # 5xx server errors → retry with backoff
            if r.status_code >= 500 and attempt < retries - 1:
                _time.sleep(min(2 ** attempt, 30))
                continue
            log.warn(f"Contents upload failed for {path} (HTTP {r.status_code}): {_github_response_message(r)}")
            return False
        except requests.RequestException:
            if attempt < retries - 1:
                _time.sleep(min(2 ** attempt, 30))
            else:
                log.warn(f"Contents upload failed for {path}: network error after {retries} attempts")
    return False


def _gh_default_branch(token: str, owner: str, repo: str) -> str:
    """Best-effort fetch of the repo's default branch; falls back to 'main'."""
    try:
        r = _github_upload_session.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
            timeout=20,
        )
        if r.status_code == 200:
            return r.json().get("default_branch") or "main"
    except requests.RequestException:
        pass
    return "main"


def _prepare_git_upload_files(files: list, stats: dict = None) -> tuple[list, list]:
    """Canonicalize Git tree paths and filter entries GitHub will reject.

    Git tree paths are always POSIX paths. Reject traversal, reserved .git
    components, control characters, overlong components, and invalid base64
    before spending time uploading blobs. Duplicate normalized paths are
    resolved deterministically with the last archive entry winning.
    """
    import base64 as _base64

    by_path = {}
    failures = []
    normalized_sources = []
    for source in files:
        source_path = str((source or {}).get("path") or "").replace("\\", "/")
        parts = []
        for segment in source_path.split("/"):
            if segment in ("", "."):
                continue
            if segment == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(segment)
        normalized_sources.append((source, parts))
    ignored_git_metadata = 0
    for fobj, parts in normalized_sources:
        original = str((fobj or {}).get("path") or "")
        # GitHub reserves .git for the actual repository database. Keep every
        # project path unchanged and omit only this uncommittable local metadata.
        if any(part.casefold() == ".git" for part in parts):
            ignored_git_metadata += 1
            continue
        if (not parts
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in "/".join(parts))
                or any(len(part.encode("utf-8")) > 255 for part in parts)
                or len("/".join(parts).encode("utf-8")) > 4096):
            failures.append(original or "<empty path>")
            continue
        path = "/".join(parts)
        if not path:
            failures.append(original or "<empty path>")
            continue
        content = (fobj or {}).get("content_b64", "")
        if not isinstance(content, str):
            failures.append(original or path)
            continue
        try:
            _base64.b64decode(content, validate=True)
        except (ValueError, TypeError):
            failures.append(original or path)
            continue
        if path in by_path:
            failures.append(original or path)
        by_path[path] = {"path": path, "content_b64": content}

    paths = set(by_path)
    conflicting = set()
    for path in paths:
        parts = path.split("/")
        conflicting.update("/".join(parts[:i]) for i in range(1, len(parts)))
    conflicts = paths & conflicting
    for path in sorted(conflicts):
        failures.append(path)
        by_path.pop(path, None)
    # Remove descendants of file paths too, so neither side of a file/directory
    # collision reaches the Git Trees endpoint.
    for path in list(by_path):
        if any(path.startswith(parent + "/") for parent in conflicts):
            failures.append(path)
            by_path.pop(path, None)
    if stats is not None:
        stats["ignored_git_metadata"] = ignored_git_metadata
    return list(by_path.values()), failures


def _create_blob_with_retry(base_url: str, headers: dict, content_b64: str, retries: int = 8):
    """Create a git blob from base64 content. Handles files up to 100 MB —\n    the Contents API's 1 MB cap is exactly why single large files used to fail.\n    Returns the blob SHA, or None on persistent failure."""
    for attempt in range(retries):
        try:
            r = _github_upload_session.post(
                f"{base_url}/git/blobs", headers=headers,
                json={"content": content_b64 or "", "encoding": "base64"}, timeout=120,
            )
            if r.status_code == 201:
                return r.json().get("sha")
            if r.status_code in (403, 429) and attempt < retries - 1:
                _time.sleep(_github_retry_delay(r, attempt))
                continue
            if r.status_code >= 500 and attempt < retries - 1:
                _time.sleep(min(2 ** attempt, 30))
                continue
            try:
                detail = r.json().get("message", r.text[:160])
            except Exception:
                detail = r.text[:160]
            log.warn(f"Git Data blob rejected (HTTP {r.status_code}): {detail}")
            return None
        except requests.RequestException:
            if attempt < retries - 1:
                _time.sleep(1.5 * (attempt + 1))
    return None


def _push_files_git_data(token: str, owner: str, repo: str, files: list, msg_id: int, uid: int,
                         show_progress: bool = True, replace: bool = False,
                         drop_prefix: str = None):
    """Push ALL files in a SINGLE commit via the Git Data API.\n\n    Why: the Contents API (one PUT per file) caps files at ~1 MB and creates a\n    commit per file, so a single oversized/binary file fails while the rest\n    succeed ("17 ok / 1 failed"). The Git Data API uploads each file as a blob\n    (up to 100 MB), assembles one tree, and makes one atomic commit — no\n    per-file conflicts, no size cliff. Works on both empty repos\n    (auto_init=False → no ref yet) and repos that already have a main branch.\n\n    When ``replace`` is True the new tree is built WITHOUT ``base_tree``, so\n    files that already exist on the branch are dropped in the very same\n    atomic commit — the branch ends up containing exactly ``files``.\n    With ``drop_prefix`` set (e.g. ``docs``) the replace is SCOPED: every\n    existing blob under ``drop_prefix/`` is removed, while all other blobs\n    from the current tree are carried over into the new tree untouched.\n\n    Returns (ok, fail, failed_names) on success, or None to signal the caller\n    to fall back to the per-file Contents method.\n    """
    headers  = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    base_url = f"https://api.github.com/repos/{owner}/{repo}"
    branch   = _gh_default_branch(token, owner, repo)
    total    = len(files)
    if total == 0:
        return (0, 0, [])

    # 1) Find the current branch tip + tree (absent on a brand-new empty repo).
    parents, base_tree = [], None
    try:
        rr = _github_upload_session.get(f"{base_url}/git/ref/heads/{branch}", headers=headers, timeout=20)
        if rr.status_code == 200:
            base_sha = rr.json()["object"]["sha"]
            parents  = [base_sha]
            cr = _github_upload_session.get(f"{base_url}/git/commits/{base_sha}", headers=headers, timeout=20)
            if cr.status_code == 200:
                base_tree = cr.json()["tree"]["sha"]
            else:
                log.warn(f"Git Data could not read branch commit (HTTP {cr.status_code}): {cr.text[:160]}")
                return None
        elif rr.status_code != 404:
            log.warn(f"Git Data could not read branch ref (HTTP {rr.status_code}): {rr.text[:160]}")
            return None
    except (requests.RequestException, KeyError, ValueError):
        log.warn("Git Data branch lookup failed due to a network or response error")
        return None  # network/parse issue → let caller fall back

    # 1b) Scoped replace: carry over every existing blob OUTSIDE the dropped
    # folder. The new tree is built without base_tree (so files under
    # drop_prefix/ vanish) but explicitly re-includes the surviving blobs —
    # one atomic commit that empties the folder and adds the new files.
    surviving_items = []
    if replace and drop_prefix:
        norm_prefix = drop_prefix.strip("/").strip() + "/"
        if base_tree:
            try:
                tr0 = _github_upload_session.get(
                    f"{base_url}/git/trees/{base_tree}", headers=headers,
                    params={"recursive": "1"}, timeout=60)
                if tr0.status_code != 200:
                    log.warn(f"Git Data scoped-replace tree read failed (HTTP {tr0.status_code})")
                    return None
                for item in tr0.json().get("tree", []):
                    # Only plain blobs are carried over; submodules (type=commit)
                    # cannot be re-declared safely and are intentionally dropped.
                    if item.get("type") != "blob":
                        continue
                    if str(item.get("path", "")).startswith(norm_prefix):
                        continue
                    surviving_items.append({
                        "path":  item["path"],
                        "mode":  item.get("mode", "100644"),
                        "type":  "blob",
                        "sha":   item["sha"],
                    })
            except (requests.RequestException, KeyError, ValueError):
                log.warn("Git Data scoped-replace tree read errored")
                return None
        # Empty repo (no base_tree) → nothing to carry over, nothing to drop.

    # 2) Create blobs in parallel. Each blob is independent; only the tree,
    # commit, and ref update below must remain ordered/atomic.
    import concurrent.futures
    blob_inputs = [
        ((fobj.get("path") or "").replace("\\", "/").lstrip("/"), fobj.get("content_b64", ""))
        for fobj in files
    ]
    blob_inputs = [(path, content) for path, content in blob_inputs if path]
    tree_items = []
    worker_count = min(config.GIT_BLOB_WORKERS, max(1, len(blob_inputs)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(_create_blob_with_retry, base_url, headers, content): path
            for path, content in blob_inputs
        }
        done = 0
        blob_failures = []
        for future in concurrent.futures.as_completed(futures):
            path = futures[future]
            try:
                sha = future.result()
            except Exception:
                sha = None
            if sha is None:
                # Keep uploading the rest as one bulk tree commit. The caller
                # can retry only this file through Contents API after commit.
                blob_failures.append(path)
                done += 1
                continue
            tree_items.append({"path": path, "mode": "100644", "type": "blob", "sha": sha})
            done += 1
            if show_progress and (done == 1 or done % 5 == 0 or done == len(blob_inputs)):
                try:
                    pct = int(done / len(blob_inputs) * 100)
                    bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
                    bot.edit_message_text(
                        f"⚡ Uploading to GitHub…\n`[{bar}]` {pct}%  ({done}/{len(blob_inputs)} files)",
                        uid, msg_id,
                    )
                except Exception:
                    pass

    if not tree_items:
        return None

    # 3) Create tree, 4) commit, 5) point the branch at it.
    try:
        tp = {"tree": surviving_items + tree_items}
        if base_tree and not replace:
            # Inheriting base_tree merges the new files with everything that
            # already exists on the branch. Omitting it (replace=True) makes
            # the uploaded file list — plus any surviving_items for a scoped
            # replace — the complete new contents.
            tp["base_tree"] = base_tree
        tr = _github_upload_session.post(f"{base_url}/git/trees", headers=headers, json=tp, timeout=120)
        if tr.status_code != 201:
            log.warn(f"Git Data tree creation failed (HTTP {tr.status_code}): {tr.text[:160]}")
            return None
        tree_sha = tr.json()["sha"]

        if replace and drop_prefix:
            commit_msg = f"Update {drop_prefix.strip('/')} — replace folder contents"
        elif replace:
            commit_msg = "Replace repository contents via Upload to Repo"
        else:
            commit_msg = "Add project files"
        cp = {"message": commit_msg, "tree": tree_sha, "parents": parents}
        cm = _github_upload_session.post(f"{base_url}/git/commits", headers=headers, json=cp, timeout=60)
        if cm.status_code != 201:
            log.warn(f"Git Data commit creation failed (HTTP {cm.status_code}): {cm.text[:160]}")
            return None
        commit_sha = cm.json()["sha"]

        if parents:  # branch exists → fast-forward update
            ur = _github_upload_session.patch(
                f"{base_url}/git/refs/heads/{branch}", headers=headers,
                json={"sha": commit_sha, "force": False}, timeout=20,
            )
            ok = ur.status_code == 200
        else:        # empty repo → create the initial ref
            ur = _github_upload_session.post(
                f"{base_url}/git/refs", headers=headers,
                json={"ref": f"refs/heads/{branch}", "sha": commit_sha}, timeout=20,
            )
            ok = ur.status_code == 201
        if not ok:
            log.warn(f"Git Data branch update failed (HTTP {ur.status_code}): {ur.text[:160]}")
            return None
    except (requests.RequestException, KeyError, ValueError):
        log.warn("Git Data commit or ref update failed due to a network or response error")
        return None

    return (len(tree_items), len(blob_failures), blob_failures)


def _push_archive_files(token: str, owner: str, repo: str, files: list, msg_id: int, uid: int,
                        show_progress: bool = True) -> tuple:
    """Push all extracted files to GitHub. Primary path = ONE atomic commit via\n    the Git Data API (handles large files, never partially fails); if that path\n    errors for any reason, fall back to the per-file Contents API method below.\n    Returns (ok_count, fail_count, failed_names_list)."""
    import concurrent.futures, threading as _threading

    upload_stats = {}
    files, invalid_paths = _prepare_git_upload_files(files, upload_stats)
    ignored_git_metadata = upload_stats.get("ignored_git_metadata", 0)
    if not files:
        return 0, len(invalid_paths), invalid_paths, ignored_git_metadata

    # ── Primary: single-commit Git Data API upload (robust to large files) ──
    try:
        result = _push_files_git_data(token, owner, repo, files, msg_id, uid, show_progress)
        if result is not None:
            ok, failed, failed_names = result
            # A transient/per-file Git Data problem must not send the entire
            # batch through the slow Contents endpoint. Retry only missed blobs.
            if failed_names:
                by_path = {f["path"]: f for f in files}
                still_failed = []
                for path in failed_names:
                    fobj = by_path.get(path)
                    if fobj and _push_one_file(token, owner, repo, path, fobj["content_b64"]):
                        ok += 1
                        failed -= 1
                    else:
                        still_failed.append(path)
            else:
                still_failed = []
            return ok, failed + len(invalid_paths), still_failed + invalid_paths, ignored_git_metadata
        log.warn("Git Data upload failed; using the per-file Contents API fallback. See preceding Git Data diagnostic for cause.")
    except Exception as e:
        log.warn(f"Git Data upload errored ({str(e)[:80]}) — falling back to Contents API")

    # ── Fallback: per-file Contents API (sequential, retrying) ──
    total        = len(files)
    ok_count     = 0
    fail_count   = 0
    failed_names = []
    counter_lock = _threading.Lock()
    done_counter = [0]

    # Pushes are SERIALIZED (1 worker). Every PUT to the contents API creates a
    # commit that advances the branch ref; concurrent writes to the same repo
    # collide (409/422) and used to silently drop files. Sequential writes are
    # the only reliable way with the contents API, and also stay well under
    # GitHub's secondary rate limit.
    MAX_WORKERS = 1

    def _scrub_and_upload(fobj):
        nonlocal ok_count, fail_count
        path        = fobj["path"]
        content_b64 = fobj["content_b64"]
        # Upload file exactly as-is, no scrubbing
        success = _push_one_file(token, owner, repo, path, content_b64)

        with counter_lock:
            if success:
                ok_count += 1
            else:
                fail_count += 1
                failed_names.append(path)
            done_counter[0] += 1
            done = done_counter[0]

        # Progress bar — update on 1st, every 5th, and last file
        if show_progress and (done == 1 or done % 5 == 0 or done == total):
            try:
                pct = int(done / total * 100)
                bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
                bot.edit_message_text(
                    f"⚡ Uploading to GitHub…\n`[{bar}]` {pct}%  ({done}/{total} files)",
                    uid, msg_id,
                )
            except Exception:
                pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        list(pool.map(_scrub_and_upload, files))

    return ok_count, fail_count + len(invalid_paths), failed_names + invalid_paths, ignored_git_metadata


# ─────────────────────────────────────────────────────────────
#  README deduplication helper
# ─────────────────────────────────────────────────────────────

def _deduplicate_readme_description(content: str, repo_desc: str = "") -> str:
    lines = content.splitlines()
    desc_heading_re = re.compile(r'^#{1,3}\s*(description|about|overview|summary)\s*$', re.I)
    lead_lines = []
    for line in lines:
        if re.match(r'^#{2,}', line):
            break
        lead_lines.append(line)
    lead_text = " ".join(l.strip().lstrip(">").strip() for l in lead_lines if l.strip()).lower()
    output_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if desc_heading_re.match(line.strip()):
            body_lines = []
            j = i + 1
            while j < len(lines) and not re.match(r'^#{2,}', lines[j]):
                body_lines.append(lines[j])
                j += 1
            body_text = " ".join(l.strip() for l in body_lines if l.strip()).lower()
            def _overlap(a, b):
                if not a or not b: return False
                aw, bw = set(a.lower().split()), set(b.lower().split())
                if not aw or not bw: return False
                return len(aw & bw) / min(len(aw), len(bw)) >= 0.70
            if _overlap(body_text, lead_text) or (repo_desc and _overlap(body_text, repo_desc.lower())):
                i = j
                continue
        output_lines.append(line)
        i += 1
    return "\n".join(output_lines)


# ─────────────────────────────────────────────────────────────
#  Shared file-creation helpers
# ─────────────────────────────────────────────────────────────

def _add_created_file(uid: int, u: dict, filename: str, content: str) -> None:
    u["draft"].setdefault("uploads", []).append({"name": filename, "content": content, "source": "created"})


def _ask_multi_file_content(uid: int, u: dict, extra: str = "") -> None:
    names = u["draft"].get("multi_filenames", [])
    idx   = u["draft"].get("multi_file_index", 0)
    total = len(names)
    fname = names[idx]
    bot.send_message(uid,
        f"📝 *File {idx+1}/{total}:* `{fname}`\n\n"
        "Send the content now (paste as text or upload a `.txt` file).\n"
        f"_Or tap ⏭ Skip to leave empty._{extra}",
        reply_markup=kb_multi_next(idx+1, total))


def _finish_multi_files(uid: int, u: dict) -> None:
    count     = len(u["draft"].get("uploads", []))
    file_word = "file" if count == 1 else "files"
    for k in ("multi_filenames", "multi_file_index", "multi_files_done"):
        u["draft"].pop(k, None)
    save_user(uid, u)
    set_state(uid, State.CREATE_FILES)
    bot.send_message(uid,
        f"✅ *All files created!*\n📁 *{count} {file_word} queued*\n\nAdd more files or continue?",
        reply_markup=kb_files_more())


# ─────────────────────────────────────────────────────────────
#  AI README/description helper
# ─────────────────────────────────────────────────────────────

# ── Project analysis: ground README generation in the REAL files ──
# Signal file → (stack label, install cmd, run cmd). Order = priority.
_STACK_SIGNALS = [
    ("package.json",      "Node.js",       "npm install",              "npm start"),
    ("pnpm-lock.yaml",    "Node.js (pnpm)", "pnpm install",            "pnpm dev"),
    ("yarn.lock",         "Node.js (yarn)", "yarn",                    "yarn start"),
    ("requirements.txt",  "Python",        "pip install -r requirements.txt", "python main.py"),
    ("pyproject.toml",    "Python",        "pip install .",            "python -m <package>"),
    ("Pipfile",           "Python",        "pipenv install",           "pipenv run start"),
    ("setup.py",          "Python",        "pip install .",            "python main.py"),
    ("Cargo.toml",        "Rust",          "cargo build --release",    "cargo run"),
    ("go.mod",            "Go",            "go mod download",          "go run ."),
    ("pom.xml",           "Java (Maven)",  "mvn install",              "mvn spring-boot:run"),
    ("build.gradle",      "Java (Gradle)", "./gradlew build",          "./gradlew run"),
    ("Gemfile",           "Ruby",          "bundle install",           "bundle exec ruby app.rb"),
    ("composer.json",     "PHP",           "composer install",         "php index.php"),
    ("pubspec.yaml",      "Dart/Flutter",  "flutter pub get",          "flutter run"),
    ("Dockerfile",        "Docker",        "docker build -t app .",    "docker run --rm app"),
]
_LANG_BY_EXT = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript/React",
    ".jsx": "JavaScript/React", ".rs": "Rust", ".go": "Go", ".java": "Java", ".rb": "Ruby",
    ".php": "PHP", ".cs": "C#", ".cpp": "C++", ".c": "C", ".swift": "Swift", ".kt": "Kotlin",
    ".dart": "Dart", ".sh": "Shell", ".html": "HTML", ".css": "CSS", ".vue": "Vue", ".scala": "Scala",
}

def _norm_files(files: list) -> list:
    """Normalize varied file dicts to [{'path', 'text'(maybe)}]. Handles both\n    archive_files ({path, content_b64}) and uploads ({name, content})."""
    out = []
    for f in files or []:
        path = f.get("path") or f.get("name") or ""
        if not path:
            continue
        text = None
        if f.get("content_b64"):
            try:
                text = base64.b64decode(f["content_b64"]).decode("utf-8", errors="replace")
            except Exception:
                text = None
        elif isinstance(f.get("content"), str):
            text = f["content"]
        out.append({"path": path.replace("\\", "/").lstrip("/"), "text": text})
    return out

def _analyze_project_files(files: list) -> dict:
    """Inspect real project files → manifest, detected stack, install/run\n    commands and a project-structure tree. Grounds the AI so output is\n    specific to THIS project, not random boilerplate."""
    nf = _norm_files(files)
    paths = [f["path"] for f in nf]
    basenames = {os.path.basename(p) for p in paths}

    # Detected stacks + commands from signal files (preserve priority order)
    stacks, installs, runs = [], [], []
    for sig, label, inst, run in _STACK_SIGNALS:
        if sig in basenames:
            if label not in stacks:
                stacks.append(label)
            if inst not in installs:
                installs.append(inst)
            if run not in runs:
                runs.append(run)

    # Language histogram from extensions (top 3)
    from collections import Counter
    lang_counts = Counter()
    for p in paths:
        ext = os.path.splitext(p)[1].lower()
        if ext in _LANG_BY_EXT:
            lang_counts[_LANG_BY_EXT[ext]] += 1
    top_langs = [l for l, _ in lang_counts.most_common(3)]
    for l in top_langs:
        if l not in stacks:
            stacks.append(l)

    # Environment / config signals
    has_env = any(os.path.basename(p) in (".env", ".env.example") or p.endswith(".env.example")
                  for p in paths)
    has_docker = "Dockerfile" in basenames or "docker-compose.yml" in basenames

    # License guess from a LICENSE file
    license_name = ""
    lic = next((f for f in nf if os.path.basename(f["path"]).lower().startswith("license")), None)
    if lic and lic.get("text"):
        low = lic["text"][:600].lower()
        for key, name in (("mit license", "MIT"), ("apache license", "Apache-2.0"),
                          ("gnu general public", "GPL-3.0"), ("bsd ", "BSD"),
                          ("mozilla public", "MPL-2.0")):
            if key in low:
                license_name = name
                break

    # Compact manifest (root files first, then nested) — up to 50 paths
    root = sorted(p for p in paths if "/" not in p)
    deep = sorted(p for p in paths if "/" in p)
    manifest = (root + deep)[:50]
    more = len(paths) - len(manifest)

    # Lightweight project-structure tree (top-level dirs + key root files)
    top_dirs = sorted({p.split("/")[0] for p in paths if "/" in p})
    structure = "\n".join(f"├── {d}/" for d in top_dirs[:12])
    if root:
        structure += "\n" + "\n".join(f"├── {p}" for p in root[:10])

    return {
        "manifest": "\n".join(manifest) + (f"\n…(+{more} more files)" if more > 0 else ""),
        "stacks": ", ".join(stacks) if stacks else "general",
        "primary_lang": top_langs[0] if top_langs else (stacks[0] if stacks else ""),
        "install_cmds": installs,
        "run_cmds": runs,
        "structure": structure.strip(),
        "has_env": has_env,
        "has_docker": has_docker,
        "license": license_name,
        "n_files": len(paths),
    }

def _repo_url_for_user(u: dict, repo_name: str) -> str:
    """Build the canonical GitHub URL from the runtime-only GitHub identity."""
    owner = (u.get("github_username") or "").strip()
    name = (repo_name or "").strip()
    if not owner or not name:
        return ""
    return f"https://github.com/{_urllib_parse.quote(owner, safe='')}/{_urllib_parse.quote(name, safe='')}"


def _polish_readme(md: str, repo_name: str, info: dict | None = None,
                   repo_url: str = "") -> str:
    """Deterministic post-processing so EVERY README lands in the same clean,\n    professional shape regardless of the model: strip AI preamble/code-fence\n    wrappers, guarantee a single H1 title, inject shields.io badges if the model\n    omitted them, and normalize spacing. Makes output consistent, not random."""
    if not md:
        return md
    text = md.strip()

    # 1) Remove a wrapping ```markdown ... ``` fence if the model added one.
    fence = re.match(r"^```(?:markdown|md)?\s*\n(.*)\n```$", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()

    # 2) Drop a leading conversational preamble line ("Here is the README:" etc.)
    lines = text.split("\n")
    if lines and not lines[0].lstrip().startswith(("#", "<", "![", "[", "|")) \
       and len(lines) > 1 and re.match(r"^\s*(here\b|sure\b|certainly\b|below\b|this\b)", lines[0], re.I):
        lines = lines[1:]
    text = "\n".join(lines).strip()

    # 3) Guarantee exactly one H1 at the top.
    if not re.match(r"^#\s+\S", text):
        title = repo_name.replace("-", " ").replace("_", " ").title()
        text = f"# {title}\n\n{text}"

    # Put the canonical repository link at the top level, directly below the
    # H1. This is deterministic so rewrites and generated READMEs behave the
    # same even when the model omits or moves the link.
    if repo_url and repo_url not in text:
        head, sep, rest = text.partition("\n")
        text = head + f"\n\n🔗 [View this repository on GitHub]({repo_url})"
        text += ("\n" + rest if sep else "")

    # 4) Inject a badge row right after the H1 if none present.
    if info is not None and "![" not in text.split("\n\n", 2)[0] and "shields.io" not in text[:600]:
        badges = []
        lang = info.get("primary_lang") or ""
        if lang:
            color = {"Python": "3776AB", "JavaScript": "F7DF1E", "TypeScript": "3178C6",
                     "Rust": "000000", "Go": "00ADD8", "Java": "ED8B00"}.get(lang.split("/")[0], "555555")
            slug = lang.split("/")[0].replace("#", "sharp").replace("+", "plus")
            badges.append(f"![{lang}](https://img.shields.io/badge/{slug}-{color}?style=flat-square)")
        lic = info.get("license") or "MIT"
        badges.append(f"![License](https://img.shields.io/badge/License-{lic.replace('-', '--')}-green?style=flat-square)")
        badges.append("![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)")
        # place badges directly under the first H1 line
        parts = text.split("\n", 1)
        head = parts[0]
        rest = parts[1] if len(parts) > 1 else ""
        text = head + "\n\n" + " ".join(badges) + "\n\n" + rest.lstrip("\n")

    # 5) Normalize: collapse 3+ blank lines, ensure single trailing newline.
    text = re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"
    return text

def _readme_context_block(info: dict) -> str:
    """Render the analysis as grounding context for the AI prompt."""
    if not info:
        return ""
    lines = [f"DETECTED TECH STACK: {info['stacks']}"]
    if info.get("install_cmds"):
        lines.append("REAL INSTALL COMMANDS (use these, do not invent):\n  "
                     + "\n  ".join(info["install_cmds"][:4]))
    if info.get("run_cmds"):
        lines.append("REAL RUN COMMANDS:\n  " + "\n  ".join(info["run_cmds"][:4]))
    if info.get("structure"):
        lines.append("PROJECT STRUCTURE (real top-level layout):\n" + info["structure"])
    if info.get("manifest"):
        lines.append("FILE LISTING (real files in this project):\n" + info["manifest"])
    flags = []
    if info.get("has_env"):
        flags.append("has a .env / environment config (add a ## ⚙️ Configuration section)")
    if info.get("has_docker"):
        flags.append("ships a Dockerfile (mention Docker usage)")
    if flags:
        lines.append("NOTES: " + "; ".join(flags))
    return "\n\n".join(lines)

# Strict professional section template shared by generate + rewrite.
_README_TEMPLATE = (
    "Produce a TOP-TIER, professional GitHub README.md with EXACTLY this structure "
    "and section order (use these headings verbatim, keep the emoji):\n\n"
    "1. `# <Project Title>` — Title-cased, with ONE relevant emoji\n"
    "2. A one-line **bold tagline** directly under the title\n"
    "3. A shields.io badge row (language, license, PRs welcome)\n"
    "4. `## 📖 Overview` — 2–3 sentence paragraph: what it is and the problem it solves\n"
    "5. `## ✨ Features` — 5–7 SPECIFIC bullets grounded in the real files/stack above\n"
    "6. `## 🛠️ Tech Stack` — bullet list of the detected languages/frameworks\n"
    "7. `## 📦 Installation` — numbered steps using the REAL install commands in fenced "
    "code blocks (include `git clone` first)\n"
    "8. `## 🚀 Usage` — a concrete fenced code block using the REAL run commands\n"
    "9. `## 📂 Project Structure` — a fenced code block reflecting the real layout above "
    "(omit if no structure was provided)\n"
    "10. `## ⚙️ Configuration` — ONLY if env/config was detected; list the env vars\n"
    "11. `## 🤝 Contributing` — short, standard fork→branch→PR guide\n"
    "12. `## 📄 License` — state the detected license (default MIT)\n\n"
    "STRICT RULES:\n"
    "— Ground EVERY section in the real stack, files and commands provided. Do NOT invent "
    "features, dependencies, or commands that aren't supported by the file listing.\n"
    "— Proper GitHub Markdown only: headings, bold, fenced code blocks with language tags, "
    "bullet/numbered lists. Emoji ONLY on section headers.\n"
    "— Professional, precise, confident tone. No fluff, no marketing fillers, no placeholders "
    "like `<your-x>` unless a real value is genuinely unknown.\n"
    "— Output ONLY the raw Markdown. No preamble, no explanation, no surrounding code fence."
)

def _ai_rewrite_readme(u: dict, repo_name: str, desc: str, existing_readme: str,
                       files: list | None = None) -> str:
    """Rewrite an existing README to a consistent, top-tier professional shape,\n    grounded in the project's real files. Deterministically polished after."""
    info = _analyze_project_files(files) if files else {}
    ctx  = _readme_context_block(info)
    repo_url = _repo_url_for_user(u, repo_name)
    prompt = (
        "You are a principal engineer rewriting a GitHub README.md to a flagship, "
        "production-grade standard.\n\n"
        + f"Project name: {repo_name}\n"
        + f"Short description: {desc or 'Not provided'}\n\n"
        + (f"CANONICAL GITHUB REPOSITORY URL (put this near the top): {repo_url}\n\n" if repo_url else "")
        + (ctx + "\n\n" if ctx else "")
        + "EXISTING README (preserve every real fact, command, URL and credit from it):\n"
        + "-----\n" + (existing_readme or "")[:4000] + "\n-----\n\n"
        + _README_TEMPLATE
        + "\n\nAdditionally: keep ALL real information from the existing README; only improve "
        "its structure, wording and completeness."
    )
    result, _ = ai.generate_safe(u["ai_provider"], u["ai_key"], u["ai_model"], prompt, max_tokens=2600)
    out = (result or existing_readme or "").strip()
    return _polish_readme(out, repo_name, info or None, repo_url)

def _ai_generate_readme(u: dict, repo_name: str, desc: str, files: list | None = None) -> str:
    """Generate a top-tier professional README grounded in the project's real\n    files (stack, structure, real install/run commands). Polished for a\n    consistent final format every time."""
    info = _analyze_project_files(files) if files else {}
    ctx  = _readme_context_block(info)
    repo_url = _repo_url_for_user(u, repo_name)
    prompt = (
        "You are a principal engineer writing the flagship GitHub README.md for a project "
        "about to be published.\n\n"
        + f"Project name: {repo_name}\n"
        + f"Short description: {desc or 'Not provided'}\n\n"
        + (f"CANONICAL GITHUB REPOSITORY URL (put this near the top): {repo_url}\n\n" if repo_url else "")
        + (ctx + "\n\n" if ctx else "")
        + _README_TEMPLATE
    )
    result, _ = ai.generate_safe(u["ai_provider"], u["ai_key"], u["ai_model"], prompt, max_tokens=2600)
    out = (result or "").strip()
    if not out:
        return ""
    return _polish_readme(out, repo_name, info or None, repo_url)

def _ai_rewrite_desc(u: dict, repo_name: str, raw_desc: str) -> str:
    """Rewrite description using AI. Professional tone, max 300 chars."""
    prompt = (
        f"Improve this GitHub repository description. Be professional, specific, and direct.\n"
        f"Repository name: {repo_name}\n"
        f"Original description: {raw_desc}\n\n"
        "Rules:\n"
        "— One or two sentences maximum\n"
        "— State clearly what the project does and the tech it uses\n"
        "— Professional GitHub style — no fluff or marketing language\n"
        "— Maximum 300 characters\n\n"
        "Return ONLY the improved description. No quotes, no preamble."
    )
    result, _ = ai.generate_safe(u["ai_provider"], u["ai_key"], u["ai_model"], prompt, max_tokens=150)
    out = (result or raw_desc).strip().strip('"').strip("'")
    return out[:300] if out else raw_desc


# ─────────────────────────────────────────────────────────────
#  Archive Upload — Single mode helpers
# ─────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────
#  AI Name & Description suggestion helpers
# ─────────────────────────────────────────────────────────────

_DESC_MIN_LENGTH = 120  # keep in sync with the "120-300 characters" instruction in the prompt


def _ensure_desc_min_length(desc: str, files: list, file_count: int) -> str:
    """\n    Safety net for _ai_suggest_names_and_descs: the prompt instructs the model\n    to write 120-300 character descriptions, but models sometimes ignore a\n    minimum and return a bare one-liner (e.g. "Automates GitHub workflows\n    using Python and Docker." — 51 chars). Rather than shipping that as-is,\n    pad it with real, grounded detail (detected stack + file count) pulled\n    from the actual uploaded files, so the result stays factual instead of\n    inventing anything.\n    """
    desc = (desc or "").strip()
    if len(desc) >= _DESC_MIN_LENGTH:
        return desc

    info = _analyze_project_files(files) if files else {}
    stacks_str = info.get("stacks") or ""
    extra_parts = []
    if stacks_str and stacks_str != "general":
        extra_parts.append(f"Built with {stacks_str}")
    if file_count:
        extra_parts.append(f"{file_count} files in the project")
    if info.get("has_docker"):
        extra_parts.append("containerized with Docker")
    if info.get("license"):
        extra_parts.append(f"{info['license']} licensed")
    run_cmds = info.get("run_cmds") or []
    if run_cmds:
        extra_parts.append(f"run with `{run_cmds[0]}`")

    if not extra_parts:
        return desc  # nothing grounded to add — better a short truth than padding

    addition = ". ".join(extra_parts)
    if not addition.endswith("."):
        addition += "."
    padded = f"{desc.rstrip('.')}. {addition}" if desc else addition

    if len(padded) > 300:
        padded = padded[:297] + "..."
    return padded


def _ai_suggest_names_and_descs(u: dict, files: list, archive_fname: str) -> tuple:
    """\n    Analyze archive file paths and generate 5 repo name + 5 description suggestions.\n    Returns (names: list[str], descs: list[str]).\n    Descriptions up to 300 chars. Professional Base-style tone.\n    """
    if not (u.get("ai_provider") and u.get("ai_key")):
        return [], []

    # Build a compact file manifest (top 60 paths, root files first)
    all_paths   = [f["path"] for f in files]
    root_files  = [p for p in all_paths if "/" not in p.rstrip("/")]
    deep_files  = [p for p in all_paths if "/" in p]
    manifest_paths = (root_files + deep_files)[:60]
    manifest   = "\n".join(manifest_paths)
    extra_note = f"\n…and {len(files) - 60} more files" if len(files) > 60 else ""
    archive_base = os.path.splitext(os.path.basename(archive_fname))[0].replace("_", "-").replace(" ", "-")

    combined_prompt = (
        "You are a senior software engineer helping a developer publish their project on GitHub.\n\n"
        + f"Archive filename: {archive_base}\n"
        + f"Project file listing (up to 60 paths):\n{manifest}{extra_note}\n\n"
        + "Analyze the file structure, detect the tech stack and purpose of this project.\n\n"
        + "Return EXACTLY the following format — nothing else, no extra text:\n\n"
        + "NAMES:\n"
        + "1. repo-name-one\n"
        + "2. repo-name-two\n"
        + "3. repo-name-three\n"
        + "4. repo-name-four\n"
        + "5. repo-name-five\n\n"
        + "DESCRIPTIONS:\n"
        + "1. First professional description, 120-300 characters.\n"
        + "2. Second professional description, 120-300 characters.\n"
        + "3. Third professional description, 120-300 characters.\n"
        + "4. Fourth professional description, 120-300 characters.\n"
        + "5. Fifth professional description, 120-300 characters.\n\n"
        + "Rules for NAMES:\n"
        + "— Lowercase, hyphens only (no spaces, no underscores, no dots)\n"
        + "— 2 to 5 words\n"
        + "— Specific to what the project does\n"
        + "— No filler: project, app, tool, repo, code\n"
        + "— Each of the 5 names must be meaningfully different from the others "
        + "(different angle/wording), not near-duplicates\n\n"
        + "Rules for DESCRIPTIONS:\n"
        + "— Professional, direct, specific — like a GitHub repo description\n"
        + "— Two to three full sentences — never a single short sentence\n"
        + "— Minimum 120 characters, maximum 300 characters each — descriptions "
        + "shorter than 120 characters are NOT acceptable, expand with more specific "
        + "detail (key modules, what problem it solves, notable files/structure) "
        + "until the minimum is met\n"
        + "— State what the project does, the tech/language it uses, and at least one "
        + "concrete detail drawn from the file listing (a filename, folder, or module)\n"
        + "— Base every claim ONLY on the file listing above — do not invent features, "
        + "frameworks, or purposes that aren't evidenced by the file names/structure\n"
        + "— No generic phrases like: this is a project, this repo contains\n"
        + "— Each of the 5 descriptions must describe the SAME project from a different "
        + "angle (e.g. what it does, who it's for, the tech stack, the problem it solves, "
        + "a key feature) — do not just reword the same sentence 5 times"
    )

    names, descs = [], []
    # Low temperature: this is a grounded extraction task (file manifest → name/desc),
    # not free creative writing — keeping it low makes results specific and consistent
    # instead of drifting into generic/random output on repeat calls.
    raw, err = ai.generate_safe(
        u["ai_provider"], u["ai_key"], u["ai_model"], combined_prompt,
        max_tokens=700, temperature=0.3,
    )
    if not raw:
        return [], []

    # Parse structured output
    in_names = False
    in_descs = False
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if line.upper().startswith("NAMES"):
            in_names = True; in_descs = False; continue
        if line.upper().startswith("DESCRIPTIONS"):
            in_names = False; in_descs = True; continue
        m = re.match(r"^\d+[.)\-]?\s*(.+)$", line)
        if not m:
            continue
        value = m.group(1).strip()
        if in_names:
            n = value.lower().replace(" ", "-").replace("_", "-")
            n = re.sub(r"[^a-z0-9\-]", "", n)
            n = re.sub(r"-{2,}", "-", n).strip("-")
            if n and len(n) >= 3:
                names.append(n)
        elif in_descs:
            d = value.strip(chr(34)).strip(chr(39))
            if len(d) > 300:
                d = d[:297] + "..."
            if d:
                descs.append(d)

    # Safety net: the prompt asks for 120-300 chars, but if the model still
    # returns something too short, pad it with grounded context (tech stack /
    # file count) instead of shipping a bare one-liner like "Automates X."
    descs = [_ensure_desc_min_length(d, files, len(all_paths)) for d in descs]

    # Fallback: split by DESCRIPTIONS section
    if not names or not descs:
        halves = re.split(r"DESCRIPTIONS?\s*:?", raw, flags=re.IGNORECASE)
        if len(halves) >= 2:
            name_half = halves[0]
            desc_half = halves[1]
            if not names:
                for line in name_half.splitlines():
                    m = re.match(r"^\d+[.)\-]?\s*(.+)$", line.strip())
                    if m:
                        n = m.group(1).strip().lower().replace(" ", "-")
                        n = re.sub(r"[^a-z0-9\-]", "", n).strip("-")
                        if n and len(n) >= 3:
                            names.append(n)
            if not descs:
                for line in desc_half.splitlines():
                    m = re.match(r"^\d+[.)\-]?\s*(.+)$", line.strip())
                    if m:
                        d = m.group(1).strip()[:300]
                        if d:
                            descs.append(d)

    return names[:5], descs[:5]

def _store_ai_suggestions(u: dict, names: list, descs: list) -> None:
    """Save AI suggestions to user draft."""
    u["draft"]["ai_suggested_names"] = names
    u["draft"]["ai_suggested_descs"] = descs


def _handle_archive_upload(uid: int, m: Message) -> None:
    """\n    Single archive upload flow:\n    Download → extract → ask name → desc → visibility → README → confirm → push\n    """
    u     = get_user(uid)
    fname = m.document.file_name or "archive.zip"
    msg   = bot.send_message(uid, f"📦 Downloading `{fname}` ·")
    try:
        file_info = bot.get_file(m.document.file_id)
        raw       = _animate(uid, msg.message_id, f"Downloading `{fname}`",
                             bot.download_file, file_info.file_path)
        _bot_notify(uid, msg.message_id, f"⏳ Extracting `{fname}` ···")
        # Try extraction (password may be needed)
        saved_password = None
        try:
            files = _extract_archive(raw, fname, password=None)
        except ArchivePasswordRequired:
            # Save raw bytes + filename; ask for password
            u["draft"].update({
                "archive_raw_b64":  base64.b64encode(raw).decode(),
                "archive_filename": fname,
                "archive_pw_tries": 0,
            })
            save_user(uid, u)
            set_state(uid, State.ARCHIVE_PASSWORD)
            bot.edit_message_text(
                f"🔐 *Password Required*\n\n"
                f"`{fname}` is encrypted.\n\n"
                "Please send the archive password:\n"
                "_(3 attempts allowed)_",
                uid, msg.message_id,
            )
            return
        except ArchivePasswordWrong:
            tries = u["draft"].get("archive_pw_tries", 0) + 1
            u["draft"]["archive_pw_tries"] = tries
            save_user(uid, u)
            remaining = 3 - tries
            if remaining <= 0:
                set_state(uid, State.IDLE, draft={})
                bot.edit_message_text(
                    "❌ *Wrong password — 3 attempts used.*\n\nArchive upload cancelled.",
                    uid, msg.message_id, reply_markup=kb_main(),
                )
            else:
                set_state(uid, State.ARCHIVE_PASSWORD)
                bot.edit_message_text(
                    f"❌ *Wrong password!* ({remaining} attempt{'s' if remaining != 1 else ''} left)\n\n"
                    "Please send the correct password:",
                    uid, msg.message_id,
                )
            return

        found_count = len(files)
        ignored_git = _archive_git_metadata_count(files)
        files  = _preserve_archive_paths(files)
        files = _strip_archive_wrapper(files, fname)
        if not files:
            _bot_notify(uid, msg.message_id, "❌ Archive is empty or contains no extractable files.")
            return
        readme_file    = next((f for f in files if _is_root_readme(f)), None)
        readme_content = ""
        if readme_file:
            try:
                readme_content = base64.b64decode(readme_file["content_b64"]).decode("utf-8", errors="replace")
            except Exception:
                pass
        ai_mode = u["draft"].get("arch_ai_mode", False)
        u["draft"] = {
            "archive_files":    files,
            "archive_filename": fname,
            "archive_readme":   readme_content,
            "arch_ai_mode":     ai_mode,
            "archive_original_file_count": found_count,
            "archive_ignored_git_count": ignored_git,
        }
        save_user(uid, u)
        set_state(uid, State.ARCHIVE_NAME)

        if ai_mode and u.get("ai_provider") and u.get("ai_key"):
            try:
                bot.edit_message_text(
                    f"\u23f3 Analyzing `{fname}` \u2014 generating name suggestions \u00b7\u00b7\u00b7",
                    uid, msg.message_id
                )
            except Exception:
                pass
            names, descs = _ai_suggest_names_and_descs(u, files, fname)
            u = get_user(uid)
            _store_ai_suggestions(u, names, descs)
            save_user(uid, u)
            set_state(uid, State.ARCHIVE_AI_SUGGEST)
            availability = _annotate_name_availability(u, names) if names else {}
            if names:
                try:
                    bot.edit_message_text(
                        "\U0001f916 *AI Repository Name Suggestions*\n\n"
                        f"\U0001f4e6 `{fname}` \u2014 {len(files)} files"
                        + ("\n\U0001f4c4 README found" if readme_file else "")
                        + "\n\n\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n\n"
                        "✅ = available on your account · ⚠️taken = already exists\n\n"
                        "Choose a suggested name or type your own:",
                        uid, msg.message_id,
                        reply_markup=kb_archive_ai_suggest(names, descs, availability),
                    )
                except Exception:
                    bot.send_message(
                        uid,
                        "\U0001f916 AI name suggestions ready. Choose or type your own:",
                        reply_markup=kb_archive_ai_suggest(names, descs, availability),
                    )
            else:
                bot.edit_message_text(
                    "\u26a0\ufe0f AI suggestions unavailable. Please type the repo name manually.",
                    uid, msg.message_id,
                )
        else:
            bot.edit_message_text(
                "\u2705 *Archive extracted!*\n\n"
                f"\U0001f4e6 `{fname}` \u2192 *{_archive_file_count_note(found_count, ignored_git)}*\n"
                + ("\U0001f4c4 README.md detected!\n" if readme_file else "\U0001f4c4 No README.md found\n")
                + "\n\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n\n"
                "\U0001f524 *Step 1 \u2014 Repository Name*\n\n"
                "What should the repository be called?\n\n"
                "_Lowercase \u00b7 hyphens \u00b7 no spaces_\n\nExample: `my-awesome-project`",
                uid, msg.message_id,
            )
        log.event(
            f"{log.mask_user_id(uid)} started single archive upload: {fname}, "
            f"{_archive_file_count_note(found_count, ignored_git)}"
        )
    except Exception as ex:
        _safe_user_error(uid, "Archive processing", ex, msg.message_id)


def _archive_go_to_visibility(uid: int, msg_id: int = None) -> None:
    set_state(uid, State.ARCHIVE_VISIBILITY)
    text = "━━━━━━━━━━━━━━━━━━━━\n\n👁 *Step 3 — Visibility*\n\nMake this repository public or private?"
    if msg_id:
        try:
            bot.edit_message_text(text, uid, msg_id, reply_markup=kb_archive_visibility())
            return
        except Exception:
            pass
    bot.send_message(uid, text, reply_markup=kb_archive_visibility())


def _archive_go_to_readme(uid: int, msg_id: int = None) -> None:
    u             = get_user(uid)
    readme_content = u["draft"].get("archive_readme", "")
    set_state(uid, State.ARCHIVE_AI_README)
    if readme_content:
        text = ("━━━━━━━━━━━━━━━━━━━━\n\n📄 *Step 4 — README*\n\n"
                "A `README.md` was found in your archive.\n\nWhat would you like to do with it?")
        kb = kb_archive_readme_choice()
    else:
        text = ("━━━━━━━━━━━━━━━━━━━━\n\n📄 *Step 4 — README*\n\n"
                "No `README.md` was found in your archive.\n\nWould you like to generate one with AI?")
        kb = kb_archive_no_readme()
    if msg_id:
        try:
            bot.edit_message_text(text, uid, msg_id, reply_markup=kb)
            return
        except Exception:
            pass
    bot.send_message(uid, text, reply_markup=kb)


def _archive_show_confirm(uid: int, msg_id: int = None) -> None:
    u      = get_user(uid)
    name   = u["draft"].get("name", "unknown")
    desc   = u["draft"].get("description", "") or "_No description_"
    vis    = "🔒 Private" if u["draft"].get("private") else "🌍 Public"
    files  = u["draft"].get("archive_files", [])
    fcount = len(files)
    readme = u["draft"].get("archive_readme", "")
    archive_count = _archive_file_count_note(
        u["draft"].get("archive_original_file_count", fcount),
        u["draft"].get("archive_ignored_git_count", 0),
    )

    scan = scan_files_for_secrets(files)
    flagged_count = len(scan["flagged_files"])
    u["draft"].pop("_sec_scan_flagged", None)
    save_user(uid, u)
    security_note = (
        f"🛡 Sensitive data detected in {flagged_count} file(s). "
        "The upload will be blocked until those files are fixed.\n\n"
        if flagged_count else "✅ No sensitive data detected.\n\n"
    )
    text = (
        "━━━━━━━━━━━━━━━━━━━━\n\n🔍 *Confirm Archive Upload*\n\n"
        f"📦 *Name:* `{name}`\n📝 *Desc:* _{_escape_md(desc)}_\n"
        f"👁 *Visibility:* {vis}\n📁 *Files:* {archive_count}\n"
        f"📄 *README:* {'✅ Included' if readme else '—'}\n\n"
        + security_note
        + "_Ready to create repo and upload all files?_"
    )
    if msg_id:
        try:
            bot.edit_message_text(text, uid, msg_id, reply_markup=kb_archive_confirm())
            return
        except Exception:
            pass
    bot.send_message(uid, text, reply_markup=kb_archive_confirm())


def _is_name_taken_error(ex) -> bool:
    """True if a create_repo exception means the repo name is already taken."""
    if isinstance(ex, gh.RepoNameExistsError):
        return True
    # Fallback for any path that didn't get the typed error
    return "already exists" in str(ex).lower()


def _name_taken_text(name: str) -> str:
    return (
        f"⚠️ *Name already taken*\n\n"
        f"You already have a repository called `{name}` on your GitHub account.\n\n"
        f"👉 Send a *different name* to continue — your files and settings are kept."
    )


def _security_file_fingerprint(files: list) -> str:
    """Fingerprint the exact outgoing payload without logging its contents."""
    digest = hashlib.sha256()
    for file_data in files:
        for key in ("path", "name", "content_b64", "content", "source"):
            digest.update(str(file_data.get(key, "")).encode("utf-8", errors="replace"))
            digest.update(b"\0")
    return digest.hexdigest()


def _block_if_sensitive_files(uid: int, msg_id: int, files: list, repo_name: str, archive: bool) -> bool:
    """Return True and stop the flow when the exact outgoing files are unsafe.

    This is deliberately called both by the confirmation callback and immediately
    before execution.  The second check prevents stale or forged callback data
    from bypassing the user-facing confirmation screen.
    """
    scan = scan_files_for_secrets(files)
    if not scan["flagged_files"] and not scan["truncated_files"]:
        return False
    draft = get_user(uid).get("draft", {})
    approval = draft.get("_security_upload_approval", {})
    if (scan["flagged_files"] and not scan["truncated_files"]
            and approval.get("archive") == archive
            and approval.get("fingerprint") == _security_file_fingerprint(files)):
        return False
    if scan["truncated_files"] and not scan["flagged_files"]:
        text = (
            "🛡 *Upload blocked — scan limit reached*\n\n"
            f"Only the first {_SCAN_MAX_FILES} files can be scanned in one upload; "
            f"{scan['truncated_files']} file(s) were not checked. Split the upload "
            "into smaller batches and retry."
        )
    else:
        text = _format_security_warning(scan, repo_name)
    keyboard = kb_sec_warn_archive() if archive else kb_sec_warn_create()
    try:
        bot.edit_message_text(text, uid, msg_id, reply_markup=keyboard)
    except Exception:
        bot.send_message(uid, text, reply_markup=keyboard)
    return True


def _execute_archive_upload(uid: int, msg_id: int) -> None:
    """Create repo + push all archive files (single mode)."""
    u       = get_user(uid)
    name    = u["draft"].get("name", "new-repo")
    desc    = u["draft"].get("description", "")
    private = u["draft"].get("private", False)
    files   = u["draft"].get("archive_files", [])
    archive_total = u["draft"].get("archive_original_file_count", len(files))
    archive_ignored_git = u["draft"].get("archive_ignored_git_count", 0)
    readme  = u["draft"].get("archive_readme", "")
    token   = u["github_token"]
    _t      = _time.time()

    # Inject README into files list
    if readme:
        files = [f for f in files if not _is_root_readme(f)]
        files.insert(0, {"path": "README.md", "content_b64": base64.b64encode(readme.encode("utf-8")).decode()})
    source_file_count = len(files)

    if _block_if_sensitive_files(uid, msg_id, files, name, archive=True):
        return

    try:
        bot.edit_message_text("⏳ Creating repository ·", uid, msg_id)
        repo_data = _animate(uid, msg_id, "Creating repository",
                            gh.create_repo, token, name, desc, private, True)
    except Exception as ex:
        if _is_name_taken_error(ex):
            set_state(uid, State.ARCHIVE_NAME)   # keep draft (files) intact
            bot.edit_message_text(_name_taken_text(name), uid, msg_id, parse_mode="Markdown")
            return
        _safe_user_error(uid, "Repository creation", ex, msg_id)
        return

    info = gh.get_user(token)
    if not info:
        bot.edit_message_text("❌ Could not determine GitHub username.", uid, msg_id)
        return
    owner    = info["login"]
    ok_count, fail_count, failed_names, ignored_git_metadata = _push_archive_files(
        token, owner, name, files, msg_id, uid)
    elapsed  = _time.time() - _t
    repo_url = repo_data.get("html_url", f"https://github.com/{owner}/{name}")

    failed_lines = ""
    if fail_count and failed_names:
        names_str = "\n".join(f"  • `{n}`" for n in failed_names[:20])
        if len(failed_names) > 20:
            names_str += f"\n  • … and {len(failed_names) - 20} more"
        failed_lines = f"\n❌ Failed: *{fail_count}* files\n{names_str}\n"

    archive_lines = [
        f"{'🎉 *Archive Upload Complete!*' if not fail_count else '⚠️ *Archive Upload Incomplete*'}",
        f"",
        f"📦 [`{owner}/{name}`]({repo_url})",
        f"⏱ Done in `{elapsed:.1f}s`",
        f"",
        f"✅ Uploaded: *{ok_count}* of *{source_file_count}* files",
    ]
    if archive_ignored_git:
        archive_lines.append(
            f"Archive entries: *{archive_total}*; local `.git` metadata omitted: *{archive_ignored_git}*"
        )
    if fail_count and failed_names:
        fail_items = "".join(f"\n  • `{n}`" for n in failed_names[:10])
        if len(failed_names) > 10:
            fail_items += "\n  • … and more"
        archive_lines.append(f"❌ Failed ({fail_count}):{fail_items}")
    archive_lines += [
        f"",
        f"🔗 [Open on GitHub]({repo_url})",
        f"",
        f"```",
        f"git clone {repo_url}.git",
        f"cd {name}",
        f"```",
    ]
    result_text = "\n".join(archive_lines)
    try:
        bot.edit_message_text(result_text, uid, msg_id, parse_mode="Markdown",
                              disable_web_page_preview=True,
                              reply_markup=kb_preview_added_menu())
    except Exception:
        bot.send_message(uid, result_text, parse_mode="Markdown",
                         disable_web_page_preview=True,
                         reply_markup=kb_preview_added_menu())

    add_history(uid, f"Archive uploaded: {name} ({ok_count} files)")
    u["repos_created"]     = u.get("repos_created", 0) + 1
    u["archives_uploaded"] = u.get("archives_uploaded", 0) + 1
    u["files_pushed"]      = u.get("files_pushed", 0) + ok_count
    # Keep enough draft for the 👁 Live Preview button on this result screen.
    u["draft"] = {"preview_target": name, "preview_owner": owner}
    save_user(uid, u)
    set_state(uid, State.IDLE)
    log.ok(f"Archive upload complete: {owner}/{name}", f"{ok_count} files in {elapsed:.1f}s")


# ─────────────────────────────────────────────────────────────
#  Archive Upload — Multiple mode helpers
# ─────────────────────────────────────────────────────────────

def _archm_expired(uid: int, msg_id: int = None) -> None:
    """Recover from a lost multi-archive draft (restart / Home reset /
    account switch) instead of crashing on stale inline buttons."""
    set_state(uid, State.IDLE, draft={})
    text = "⚠️ Session expired — please start the multi-archive flow again."
    if msg_id:
        try:
            bot.edit_message_text(text, uid, msg_id, reply_markup=kb_home_only(uid))
            return
        except Exception:
            pass
    bot.send_message(uid, text, reply_markup=kb_home_only(uid))


def _archm_guard(u: dict, idx) -> bool:
    """True when draft multi_queue[idx] exists and is safe to index."""
    queue = (u.get("draft") or {}).get("multi_queue") or []
    return isinstance(idx, int) and 0 <= idx < len(queue)


def _archm_next_step(uid: int) -> None:
    """\n    Drive the per-archive wizard for multi-archive mode.\n    Looks at multi_queue[multi_index] and starts the wizard:\n      → ask name → ask desc → ask visibility → ask README\n    When index reaches end → execute all uploads.\n    """
    u     = get_user(uid)
    queue = u["draft"].get("multi_queue", [])
    idx   = u["draft"].get("multi_index", 0)

    if idx >= len(queue):
        # All archives configured — execute uploads
        _archm_execute_all(uid)
        return

    item = queue[idx]
    fname = item.get("filename", f"archive_{idx+1}")
    fcount = len(item.get("files", []))
    readme_found = bool(item.get("readme_content", ""))

    ai_mode = item.get("ai_mode", False)

    if ai_mode and u.get("ai_provider") and u.get("ai_key"):
        set_state(uid, State.ARCHM_AI_SUGGEST)
        loading_msg = bot.send_message(
            uid,
            (
                f"\U0001f4e6 *Archive {idx+1}/{len(queue)}: `{fname}`*\n"
                f"\U0001f4c1 {fcount} files extracted"
                + ("  \u00b7  \U0001f4c4 README found" if readme_found else "")
                + "\n\n\U0001f916 Generating name suggestions \u00b7\u00b7\u00b7"
            )
        )
        names, descs = _ai_suggest_names_and_descs(u, item.get("files", []), fname)
        u = get_user(uid)
        u["draft"]["multi_queue"][idx]["ai_suggested_names"] = names
        u["draft"]["multi_queue"][idx]["ai_suggested_descs"] = descs
        save_user(uid, u)
        availability = _annotate_name_availability(u, names) if names else {}
        if names:
            try:
                bot.edit_message_text(
                    (
                        f"\U0001f916 *AI Suggestions for Archive {idx+1}/{len(queue)}*\n\n"
                        f"\U0001f4e6 `{fname}` \u2014 {fcount} files\n\n"
                        "\u2501" * 20 + "\n\n"
                        "✅ = available on your account · ⚠️taken = already exists\n\n"
                        "Choose a repository name or type your own:"
                    ),
                    uid, loading_msg.message_id,
                    reply_markup=kb_archm_ai_suggest(names, descs, availability),
                )
            except Exception:
                bot.send_message(
                    uid,
                    "\U0001f916 Choose a name or type your own:",
                    reply_markup=kb_archm_ai_suggest(names, descs, availability),
                )
        else:
            bot.edit_message_text(
                "\u26a0\ufe0f AI suggestions unavailable \u2014 please type the repo name.",
                uid, loading_msg.message_id,
            )
            set_state(uid, State.ARCHIVE_MULTI_NAME)
    else:
        set_state(uid, State.ARCHIVE_MULTI_NAME)
        bot.send_message(
            uid,
            (
                f"\U0001f4e6 *Archive {idx+1}/{len(queue)}: `{fname}`*\n"
                f"\U0001f4c1 {fcount} files extracted"
                + ("  \u00b7  \U0001f4c4 README found" if readme_found else "")
                + "\n\n\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n\n"
                "\U0001f524 *Repository Name*\n\n"
                "What should this repository be called?\n\n"
                "_Lowercase \u00b7 hyphens \u00b7 no spaces_\n\nExample: `my-project`"
            ),
            reply_markup=kb_archive_multi_name_step(),
        )


def _archm_execute_all(uid: int) -> None:
    """Upload queued archives as separate repos with bounded concurrency."""
    import concurrent.futures
    u = get_user(uid)
    queue = list(u["draft"].get("multi_queue", []))
    token = u["github_token"]
    started_at = _time.time()
    info = gh.get_user(token)
    if not info:
        bot.send_message(uid, "❌ Could not verify GitHub username.")
        return
    owner = info["login"]
    msg = bot.send_message(uid, f"📦 *Uploading {len(queue)} repositories in parallel…*")

    def upload_one(index, item):
        name = item.get("name", f"archive-{index + 1}")
        desc, private = item.get("description", ""), item.get("private", False)
        files = list(item.get("files", []))
        readme = item.get("readme_content", "")
        if readme:
            files = [f for f in files if not _is_root_readme(f)]
            files.insert(0, {"path": "README.md", "content_b64": base64.b64encode(readme.encode("utf-8")).decode()})
        try:
            try:
                repo_data = gh.create_repo(token, name, desc, private, True)
            except Exception as exc:
                if not _is_name_taken_error(exc):
                    raise
                base = name
                for suffix in range(2, 12):
                    candidate = f"{base}-{suffix}"
                    try:
                        repo_data = gh.create_repo(token, candidate, desc, private, True)
                        name = candidate
                        break
                    except Exception as retry_exc:
                        if not _is_name_taken_error(retry_exc):
                            raise
                else:
                    return index, f"⚠️ `{base}` — skipped: name already taken (and `-2`…`-11` too)", name, 0, 0, False
            t0 = _time.time()
            ok, failed, failed_names, ignored_git_metadata = _push_archive_files(
                token, owner, name, files, msg.message_id, uid, show_progress=False)
            elapsed = _time.time() - t0
            url = repo_data.get("html_url", f"https://github.com/{owner}/{name}")
            line = f"✅ [`{name}`]({url}) — {ok} files  · `{elapsed:.1f}s`"
            if failed_names:
                line += "\n  ❌ Failed: " + ", ".join(f"`{x}`" for x in failed_names[:5])
            return index, line, name, ok, failed, True
        except Exception as exc:
            log.error(f"Multi-archive upload failed for {name}", str(exc)[:120])
            return index, f"❌ `{name}` — failed: `{str(exc)[:120]}`", name, 0, 0, False

    results = [None] * len(queue)
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(config.BULK_REPO_WORKERS, len(queue)) or 1) as pool:
        pending = {pool.submit(upload_one, i, item): i for i, item in enumerate(queue)}
        for done, future in enumerate(concurrent.futures.as_completed(pending), start=1):
            i = pending[future]
            try:
                results[i] = future.result()
            except Exception as exc:
                name = queue[i].get("name", f"archive-{i + 1}")
                results[i] = (i, f"❌ `{name}` — failed: `{str(exc)[:120]}`", name, 0, 0, False)
            try:
                bot.edit_message_text(f"📦 Uploaded {done}/{len(queue)} repositories…", uid, msg.message_id)
            except Exception:
                pass

    summary_lines = ["📦 *Multi-Archive Upload Complete!*\n"]
    for result in results:
        if result is None:
            continue
        _, line, name, ok, failed, created = result
        summary_lines.append(line)
        if created:
            add_history(uid, f"Archive uploaded: {name} ({ok} files)")
            u["repos_created"] = u.get("repos_created", 0) + 1
            u["archives_uploaded"] = u.get("archives_uploaded", 0) + 1
            u["files_pushed"] = u.get("files_pushed", 0) + ok
            save_user(uid, u)
    total_elapsed = _time.time() - started_at
    summary_lines.append(f"\n⏱ Total: `{total_elapsed:.1f}s`")
    summary = "\n".join(summary_lines)
    try:
        bot.edit_message_text(summary, uid, msg.message_id, parse_mode="Markdown",
                              disable_web_page_preview=True, reply_markup=kb_home_only(uid))
    except Exception:
        bot.send_message(uid, summary, parse_mode="Markdown", disable_web_page_preview=True,
                         reply_markup=kb_home_only(uid))
    u["draft"] = {}
    save_user(uid, u)
    set_state(uid, State.IDLE)
    log.ok(f"{log.mask_user_id(uid)} multi-archive upload complete",
           f"{len(queue)} repos in {total_elapsed:.1f}s; parallel repos {config.BULK_REPO_WORKERS}")


def _handle_inline_archive(uid: int, m: Message) -> None:
    """Handle archive uploaded during CREATE_FILES_UPLOAD state (adds files to draft).\n    Reuses the shared upload_status_msg_id so no new message is spammed."""
    u     = get_user(uid)
    fname = m.document.file_name or "archive.zip"

    # Reuse existing status message or create one
    status_msg_id = u["draft"].get("upload_status_msg_id")
    if status_msg_id:
        try:
            bot.edit_message_text(f"📦 Downloading `{fname}` ···", uid, status_msg_id)
        except Exception as _edit_err:
            if "not found" in str(_edit_err).lower() or "message_id_invalid" in str(_edit_err).lower():
                status_msg_id = None
                u["draft"].pop("upload_status_msg_id", None)
                save_user(uid, u)
    if not status_msg_id:
        status_msg    = bot.send_message(uid, f"📦 Downloading `{fname}` ···")
        status_msg_id = status_msg.message_id
        u["draft"]["upload_status_msg_id"] = status_msg_id
        save_user(uid, u)

    try:
        file_info = bot.get_file(m.document.file_id)
        raw       = _animate(uid, status_msg_id, f"Downloading `{fname}`",
                             bot.download_file, file_info.file_path)
        _bot_notify(uid, status_msg_id, f"⏳ Extracting `{fname}` ···")
        files = _extract_archive(raw, fname)
        found_count = len(files)
        ignored_git = _archive_git_metadata_count(files)
        files = _preserve_archive_paths(files)
        files = _strip_archive_wrapper(files, fname)
        if not files:
            _bot_notify(uid, status_msg_id, f"⚠️ `{fname}` is empty — nothing added.")
            return
        uploads = []
        for f in files:
            try:
                text_content = base64.b64decode(f["content_b64"]).decode("utf-8")
                uploads.append({"name": f["path"], "content": text_content, "source": "archive"})
            except Exception:
                uploads.append({"name": f["path"], "content": f["content_b64"], "source": "archive_binary"})
        u["draft"].setdefault("uploads", [])
        u["draft"]["uploads"].extend(uploads)
        save_user(uid, u)
        set_state(uid, State.CREATE_FILES_UPLOAD)
        count     = len(u["draft"]["uploads"])
        file_word = "file" if count == 1 else "files"
        try:
            bot.edit_message_text(
                f"📁 *{count} {file_word} queued* — `{fname}` ({_archive_file_count_note(found_count, ignored_git)})\n\n"
                "_Keep sending files or tap ✅ Done._",
                uid, status_msg_id,
                reply_markup=kb_files_continue(),
            )
        except Exception:
            pass
    except ArchivePasswordRequired:
        _bot_notify(
            uid, status_msg_id,
            "🔐 That archive is *password-protected*, so it can't be added here.\n"
            "_Extract it on your device and send the plain files, or use "
            "📦 Archive Upload which supports passwords._",
            parse_mode="Markdown",
        )
    except ArchiveTooLargeError as ex:
        _bot_notify(uid, status_msg_id, f"⚠️ {ex}")
    except Exception as ex:
        _safe_user_error(uid, "Archive processing", ex, status_msg_id)


# ─────────────────────────────────────────────────────────────
#  Text message handler
# ─────────────────────────────────────────────────────────────

@bot.message_handler(func=lambda m: True, content_types=["text"])
def handle_text(m: Message) -> None:
    uid   = m.chat.id
    if _check_banned(uid):
        return
    text  = m.text.strip()
    if text.startswith("/"):
        _auto_delete_command(m)
    state = get_state(uid)
    if text.startswith("/"):
        command = text.split(maxsplit=1)[0].split("@", 1)[0].lower()
        bot.send_message(
            uid,
            f"❓ I don't recognize `{command}`. Try /help, /menu, or /cancel.",
            parse_mode="Markdown", reply_markup=kb_main(uid),
        )
        return
    if state == State.SETUP_GITHUB:
        _delete_pending_prompt(uid, "_pending_github_prompt_id")
    elif state == State.SETAI_KEY:
        _delete_pending_prompt(uid, "_pending_ai_prompt_id")
    elif state in (State.ACCOUNTS_ADD_TOKEN, State.ACCOUNTS_RENAME):
        _delete_pending_prompt(uid, "_pending_accounts_prompt_id")

    # ── Upload to Repo: destination folder typed by user ──────
    if state == State.UPLOAD_PATH:
        folder = _normalize_upload_folder(text)
        if folder is None:
            bot.send_message(
                uid,
                "⚠️ That folder path looks unsafe.\n\n"
                "Rules: no leading `/`, no `..` segments, and only letters, "
                "digits, spaces, `-`, `_`, `.`, `/`.\n\n"
                "_Try again, or tap ◀ Change Repo._")
            return
        u = get_user(uid)
        u["draft"]["upload_folder"] = folder
        save_user(uid, u)
        _show_upload_mode_step(uid)
        return

    # ── GitHub Extras text-input create flows ────────────────
    # (new issue body, tag name, branch name, release tag) — the gx flow
    # owns the next message when a draft["gx_pending"] marker is set.
    if gh_actions.on_text(uid, m):
        return

    # ── Edit Repo text input states ───────────────────────────
    _ER_STATES = {
        State.EDIT_FILE_EDIT, State.EDIT_FILE_NEW_NAME, State.EDIT_FILE_NEW_CONTENT,
        State.EDIT_FOLDER_NEW_NAME, State.EDIT_FOLDER_FIRST_FILE,
        State.EDIT_REPO_RENAME, State.EDIT_REPO_DESC, State.EDIT_REPO_HOMEPAGE,
        State.EDIT_REPO_TOPICS, State.EDIT_BRANCH_NEW, State.EDIT_FILE_MOVE_DEST,
    }
    if state in _ER_STATES:
        if _er_handle_text(uid, text, m):
            return
    # ── File search in Edit Repo ─────────────────────────────
    if state in (State.EDIT_BROWSE, State.EDIT_REPO_MENU, State.EDIT_REPO_PICK):
        u = get_user(uid)
        if u["draft"].get("er_pending") == "search":
            u["draft"]["er_pending"] = None
            save_user(uid, u)
            repo_name = u["draft"].get("er_repo", "")
            token     = u.get("github_token")
            owner     = u["draft"].get("er_owner", "")
            loading_id = bot.send_message(uid, f"🔍 Searching `{repo_name}` for `{text}` ···").message_id
            results = gh.search_repo_files(token, owner, repo_name, text)
            if results:
                # Index-based callbacks: repo + full path would often exceed
                # Telegram's 64-byte callback_data limit (screen would fail).
                result_paths = [item["path"] for item in results[:15]]
                u["draft"]["er_search_results"] = result_paths
                save_user(uid, u)
                kb = InlineKeyboardMarkup(row_width=1)
                for i, rpath in enumerate(result_paths):
                    kb.add(InlineKeyboardButton(
                        f"📄 {rpath}",
                        callback_data=f"er_sfile_{i}",
                    ))
                kb.add(
                    InlineKeyboardButton("🔍 New Search",   callback_data=f"er_search_{repo_name}"),
                    InlineKeyboardButton("◀ Repo Menu",    callback_data=f"er_repomenu_{repo_name}"),
                )
                kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
                bot.edit_message_text(
                    f"🔍 *Search results for `{text}` in `{repo_name}`*\n\n"
                    f"Found *{len(results)}* file(s):",
                    uid, loading_id, reply_markup=kb,
                )
            else:
                bot.edit_message_text(
                    f"🔍 No files found matching `{text}` in `{repo_name}`.",
                    uid, loading_id,
                    reply_markup=kb_edit_cancel(repo_name, ""),
                )
            return

    if state == State.SETUP_GITHUB:
        _scrub_secret_message(uid, m.message_id)
        _apply_github_token(uid, text)

    elif state == State.ACCOUNTS_ADD_TOKEN:
        _scrub_secret_message(uid, m.message_id)
        _handle_account_token_input(uid, text, m.message_id)

    elif state == State.ACCOUNTS_RENAME:
        _handle_account_rename_input(uid, text, m.message_id)

    elif state == State.SETAI_KEY:
        # User picked a provider via button; this message is their API key.
        u        = get_user(uid)
        provider = u.get("_pending_provider")
        set_state(uid, State.IDLE)
        u.pop("_pending_provider", None)
        save_user(uid, u)
        # Abort on a command-like message (e.g. /cancel) instead of saving it
        # as a key. Real commands (/start, /status…) are caught earlier by
        # their own handlers and never reach here.
        if text.strip().startswith("/"):
            bot.send_message(uid, "❎ Cancelled. Run /setai when you're ready.",
                             reply_markup=kb_home_only(uid))
            return
        if not provider:
            bot.send_message(uid, "⚠️ Session expired — run /setai again.",
                             reply_markup=kb_provider_picker())
            return
        _scrub_secret_message(uid, m.message_id)
        _apply_setai(uid, provider, text)

    elif state == State.ADMIN_TICKET_REPLY:
        # Admin tapped "💬 Reply" on a ticket; this message is the reply body.
        u = get_user(uid)
        target = u.get("_pending_reply_target")
        set_state(uid, State.IDLE)
        u.pop("_pending_reply_target", None)
        save_user(uid, u)
        if not is_admin(uid):
            return
        if text.strip().startswith("/"):
            bot.send_message(uid, "❎ Cancelled — no reply sent.",
                             reply_markup=kb_admin_back())
            return
        if not target:
            bot.send_message(uid, "⚠️ Session expired — open the ticket again from 🎫 Support Tickets.",
                             reply_markup=kb_admin_back())
            return
        try:
            bot.send_message(target,
                f"🎫 *Support Reply*\n\n{_escape_md(text)}",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup().add(
                    InlineKeyboardButton("🎫 Reply again", callback_data="menu_support"),
                    InlineKeyboardButton("🏠 Home", callback_data="menu_home"),
                ))
            tu = get_user(target)
            tu["pending_tickets"] = []
            save_user(target, tu)
            bot.send_message(uid, f"✅ Reply sent to `{target}` and ticket closed.",
                             parse_mode="Markdown", reply_markup=kb_admin_back())
        except Exception as e:
            _safe_user_error(uid, "Support reply", e)

    elif state == State.AI_SUGGEST_IDEA:
        # ── AI Suggest: generate repo from idea ───────────────
        u = get_user(uid)
        provider = u.get("ai_provider")
        api_key  = u.get("ai_key")
        model    = u.get("ai_model") or ai.PROVIDERS.get(provider, {}).get("default", "")
        if not provider or not api_key:
            bot.send_message(uid,
                "🤖 *AI not configured.*\n\nRun /setai to pick a provider and add your key.",
                parse_mode="Markdown")
            set_state(uid, State.IDLE)
            return
        loading = bot.send_message(uid,
            "✨ *Analysing your idea…*\n\n"
            "⏳ Step 1/3 — Detecting tech stack & project specifics…",
            parse_mode="Markdown")
        try:
            suggestion = ai.generate_repo_suggestion(provider, api_key, model, text)
        except Exception as ex:
            try:
                bot.edit_message_text(
                    f"❌ *AI error:* `{ex}`\n\nCheck /status and try again.",
                    uid, loading.message_id, parse_mode="Markdown",
                    reply_markup=InlineKeyboardMarkup().add(
                        InlineKeyboardButton("🔄 Try Again", callback_data="menu_ai_suggest"),
                        InlineKeyboardButton("🏠 Home",      callback_data="menu_home"),
                    ))
            except Exception:
                pass
            set_state(uid, State.IDLE)
            return

        # Store in draft
        u["draft"] = {
            "name":        suggestion["name"],
            "description": suggestion["description"],
            "readme":      suggestion["readme"],
            "gitignore":   suggestion["gitignore"],
            "private":     False,
            "source":      "ai_suggest",
            "_idea":       text,
        }
        save_user(uid, u)
        set_state(uid, State.AI_SUGGEST_CONFIRM)

        # Build feature list for preview
        features = suggestion.get("features", [])
        feat_lines = "\n".join(f"  • {f}" for f in features[:4]) if features else ""
        stack_line = f"🛠 *Stack:* `{suggestion.get('tech_stack', 'auto-detected')}`\n" if suggestion.get("tech_stack") else ""

        # README snippet — first non-title, non-empty line
        readme_lines = [l for l in suggestion["readme"].splitlines() if l.strip() and not l.startswith("#")]
        readme_snippet = readme_lines[0][:200] if readme_lines else suggestion["description"]

        preview = (
            f"✅ *AI Repo Suggestion*\n"
            f"━━━━━━━━━━━━━━━━━━━━\n\n"
            f"📦 *Name:* `{suggestion['name']}`\n"
            f"📝 *Description:* {suggestion['description']}\n"
            f"{stack_line}"
            f"\n✨ *Features:*\n{feat_lines}\n\n"
            f"📄 *README intro:*\n_{readme_snippet}_\n\n"
            f"📁 *Files ready:* `README.md` + `.gitignore`\n\n"
            f"Choose visibility to create the repo:"
        )
        kb = InlineKeyboardMarkup(row_width=2)
        kb.add(
            InlineKeyboardButton("🌍 Create Public",  callback_data="aisug_confirm_public"),
            InlineKeyboardButton("🔒 Create Private", callback_data="aisug_confirm_private"),
            InlineKeyboardButton("✏️ Edit Name",       callback_data="aisug_edit_name"),
            InlineKeyboardButton("🔄 Regenerate",      callback_data="aisug_regenerate"),
            InlineKeyboardButton("❌ Cancel",          callback_data="menu_home"),
        )
        try:
            bot.edit_message_text(preview, uid, loading.message_id,
                                  parse_mode="Markdown", reply_markup=kb)
        except Exception:
            bot.send_message(uid, preview, parse_mode="Markdown", reply_markup=kb)

    elif state == State.CREATE_NAME:
        name = __import__("re").sub(r"[^a-z0-9\-]", "", text.lower().replace(" ", "-"))
        u    = get_user(uid)
        if not name:
            bot.send_message(
                uid,
                "⚠️ That name has no valid characters (use letters, numbers, hyphens).\n"
                "Send a different name:",
            )
            return
        if (u.get("draft") or {}).get("_return_suggest"):
            # Came from the AI-suggest confirm screen ("✏️ Edit Name") — go
            # back there with the updated name instead of the 5-step wizard.
            draft = u["draft"]
            draft["name"] = name
            draft.pop("_return_suggest", None)
            save_user(uid, u)
            set_state(uid, State.AI_SUGGEST_CONFIRM, draft=draft)
            desc = draft.get("description", "")
            preview = (
                f"✅ *Name updated:* `{name}`\n\n"
                f"📝 *Description:* {desc}\n\n"
                f"📄 Files ready: `README.md` + `.gitignore`\n\n"
                f"Choose visibility to create the repo:"
            )
            kb = InlineKeyboardMarkup(row_width=2)
            kb.add(
                InlineKeyboardButton("🌍 Create Public",  callback_data="aisug_confirm_public"),
                InlineKeyboardButton("🔒 Create Private", callback_data="aisug_confirm_private"),
                InlineKeyboardButton("✏️ Edit Name",       callback_data="aisug_edit_name"),
                InlineKeyboardButton("🔄 Regenerate",      callback_data="aisug_regenerate"),
                InlineKeyboardButton("❌ Cancel",          callback_data="menu_home"),
            )
            bot.send_message(uid, preview, parse_mode="Markdown", reply_markup=kb)
            return
        u["draft"]["name"] = name
        save_user(uid, u)
        set_state(uid, State.CREATE_DESC)
        bot.send_message(uid,
            f"✅ *Name:* `{name}`\n\n━━━━━━━━━━━━━━━━━━━━\n\n"
            "📝 *Step 2/5 — Description*\n\nGive your repository a short description.\n_Or skip._",
            reply_markup=kb_desc_step())

    elif state == State.CREATE_DESC:
        if len(text) > GITHUB_DESC_MAX:
            bot.send_message(
                uid,
                f"⚠️ Your description has {len(text)} characters, but GitHub allows only "
                f"{GITHUB_DESC_MAX}. Please enter a shorter description:",
            )
            return
        u = get_user(uid)
        u["draft"]["description"] = text
        u["draft"]["desc_raw"]    = text
        save_user(uid, u)
        set_state(uid, State.CREATE_DESC_AWAIT)
        bot.send_message(uid,
            f"📝 *Description received:*\n_{_escape_md(text)}_\n\nWould you like to improve it with AI?",
            reply_markup=kb_desc_choice())

    # ── Single archive AI custom name ──────────────────────────
    elif state == State.ARCHIVE_AI_CUSTOM:
        name = text.lower().replace(" ", "-")
        name = __import__("re").sub(r"[^a-z0-9\-]", "", name)
        u    = get_user(uid)
        u["draft"]["name"] = name
        save_user(uid, u)
        # Show AI desc suggestions
        descs = u["draft"].get("ai_suggested_descs", [])
        set_state(uid, State.ARCHIVE_AI_SUGGEST)
        u["draft"]["ai_stage"] = "desc"
        save_user(uid, u)
        if descs:
            bot.send_message(uid,
                f"✅ *Name set:* `{name}`\n\n"
                "━━━━━━━━━━━━━━━━━━━━\n\n"
                "🤖 *AI Description Suggestions*\n\nChoose a description or type your own:",
                reply_markup=kb_archive_ai_desc(descs, name))
        else:
            set_state(uid, State.ARCHIVE_DESC)
            bot.send_message(uid,
                f"✅ *Name set:* `{name}`\n\n📝 Type a description (or `-` to skip):")

    # ── Single archive flow ──────────────────────────────────
    elif state == State.ARCHIVE_NAME:
        name = text.lower().replace(" ", "-")
        u    = get_user(uid)
        u["draft"]["name"] = name
        save_user(uid, u)
        set_state(uid, State.ARCHIVE_DESC)
        bot.send_message(uid,
            f"✅ *Repo name:* `{name}`\n\n📝 *Step 2 — Description*\n\n"
            "Give your repository a short description.\n_Or tap Skip._",
            reply_markup=kb_archive_desc_step())

    elif state == State.ARCHIVE_DESC:
        u    = get_user(uid)
        desc = "" if text == "-" else text
        if len(desc) > GITHUB_DESC_MAX:
            bot.send_message(
                uid,
                f"⚠️ Your description has {len(desc)} characters, but GitHub allows only "
                f"{GITHUB_DESC_MAX}. Please enter a shorter description:",
                reply_markup=kb_archive_desc_step(),
            )
            return
        u["draft"]["description"] = desc
        u["draft"]["desc_raw"]    = desc
        save_user(uid, u)
        if desc:
            set_state(uid, State.ARCHIVE_DESC_AWAIT)
            bot.send_message(uid,
                f"📝 *Description:*\n_{_escape_md(desc)}_\n\nWould you like to improve it with AI?",
                reply_markup=kb_archive_desc_choice())
        else:
            _archive_go_to_visibility(uid)

    # ── Multi-archive AI custom name ─────────────────────────
    elif state == State.ARCHM_AI_CUSTOM:
        name = text.lower().replace(" ", "-")
        name = __import__("re").sub(r"[^a-z0-9\-]", "", name)
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid)
            return
        u["draft"]["multi_queue"][idx]["name"] = name
        save_user(uid, u)
        # Show AI desc suggestions for this archive
        descs = u["draft"]["multi_queue"][idx].get("ai_suggested_descs", [])
        set_state(uid, State.ARCHM_AI_SUGGEST)
        u["draft"]["multi_queue"][idx]["ai_stage"] = "desc"
        save_user(uid, u)
        if descs:
            bot.send_message(uid,
                f"✅ *Name set:* `{name}`\n\n"
                "🤖 *AI Description Suggestions*\n\nChoose a description or type your own:",
                reply_markup=kb_archm_ai_desc(descs))
        else:
            set_state(uid, State.ARCHIVE_MULTI_DESC)
            bot.send_message(uid, f"✅ *Name:* `{name}`\n\n📝 Type a description (or `-` to skip):")

    # ── Multi-archive flow ───────────────────────────────────
    elif state == State.ARCHIVE_MULTI_NAME:
        name = text.lower().replace(" ", "-")
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid)
            return
        u["draft"]["multi_queue"][idx]["name"] = name
        u["draft"]["multi_queue"][idx]["desc_raw"] = ""
        save_user(uid, u)
        set_state(uid, State.ARCHIVE_MULTI_DESC)
        bot.send_message(uid,
            f"✅ *Name:* `{name}`\n\n"
            f"📝 *Description*\n\n"
            "Short description for this repo.\n_Or tap Skip._",
            reply_markup=kb_archive_multi_desc_step())

    elif state == State.ARCHIVE_MULTI_DESC:
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid)
            return
        desc = "" if text == "-" else text
        if len(desc) > GITHUB_DESC_MAX:
            bot.send_message(
                uid,
                f"⚠️ Your description has {len(desc)} characters, but GitHub allows only "
                f"{GITHUB_DESC_MAX}. Please enter a shorter description (or `-` to skip):",
            )
            return
        u["draft"]["multi_queue"][idx]["description"] = desc
        u["draft"]["multi_queue"][idx]["desc_raw"]    = desc
        save_user(uid, u)
        if desc:
            set_state(uid, State.ARCHIVE_MULTI_DESC_AWAIT)
            bot.send_message(uid,
                f"📝 *Description:*\n_{_escape_md(desc)}_\n\nWould you like to improve it with AI?",
                reply_markup=kb_archive_multi_desc_choice())
        else:
            set_state(uid, State.ARCHIVE_MULTI_VIS)
            queue = u["draft"]["multi_queue"]
            bot.send_message(uid,
                f"👁 *Visibility* for `{queue[idx].get('name', 'repo')}`\n\nPublic or Private?",
                reply_markup=kb_archive_multi_visibility())

    # ── Fork multi URL collection ────────────────────────────
    elif state == State.FORK_MULTI_URLS:
        u        = get_user(uid)
        raw_urls = [l.strip() for l in text.splitlines() if l.strip()]
        existing = u["draft"].get("fork_multi_urls", [])
        valid, invalid = [], []
        for url in raw_urls:
            clean = re.sub(r"\.git$", "", url.rstrip("/"))
            if re.match(r"https?://github\.com/[^/\s]+/[^/\s]+", clean):
                valid.append(clean)
            else:
                invalid.append(url)
        existing.extend(valid)
        u["draft"]["fork_multi_urls"] = existing
        save_user(uid, u)
        warn  = ""
        if invalid:
            warn = f"\n\n⚠️ Skipped ({len(invalid)}):\n" + "\n".join(f"• `{x}`" for x in invalid[:5])
        total = len(existing)
        if total == 0:
            bot.send_message(uid, f"❌ No valid URLs found.{warn}\n\nSend GitHub URLs, one per line.")
            return
        bot.send_message(uid,
            f"✅ *{len(valid)} URL(s) added* — {total} total{warn}\n\n"
            "Send more, or tap *Fork All* to proceed.",
            reply_markup=kb_fork_multi_done())  # includes Home + Cancel

    elif state == State.IMPORT_URL:
        _process_import(uid, text)

    # ── Replace Repo: typed confirmation to clear everything ──
    elif state == State.REPLACE_CLEAR_CONFIRM:
        u        = get_user(uid)
        target   = u["draft"].get("replace_target", "")
        owner    = u["draft"].get("replace_owner") or u.get("github_username", "")
        typed    = text.strip().lower()
        matches  = target and typed in (
            target.lower(),
            f"{owner}/{target}".lower() if owner else "",
        )
        if matches:
            working = bot.send_message(uid, f"🧹 Clearing all files from `{target}` ·")
            _execute_replace_clear(uid, working.message_id)
        elif target:
            bot.send_message(
                uid,
                f"⚠️ That doesn't match the repo name.\n\n"
                f"Send *exactly* `{target}` to confirm clearing, "
                "or tap ❌ Cancel below.",
                parse_mode="Markdown",
                reply_markup=kb_replace_clear_confirm(),
            )
        else:
            set_state(uid, State.IDLE, draft={})
            bot.send_message(uid, "⚠️ Session expired — start again with ♻️ Replace Repo.",
                             reply_markup=kb_main(uid))

    # ── Replace Repo: text typed while waiting for an archive ─
    elif state == State.REPLACE_UPLOAD:
        bot.send_message(
            uid,
            "📦 Please send an *archive file* (ZIP · RAR · tar.gz), not text.\n\n"
            "_Send /cancel to abort the replace._",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup().add(
                InlineKeyboardButton("◀ Back", callback_data="rr_repomenu"),
                InlineKeyboardButton("🏠 Home",   callback_data="menu_home"),
            ),
        )

    # ── Replace Repo: text typed on the action menu ───────────
    elif state == State.REPLACE_MENU:
        u = get_user(uid)
        if not u["draft"].get("replace_target"):
            set_state(uid, State.IDLE, draft={})
            bot.send_message(uid, "⚠️ Session expired — start again with ♻️ Replace Repo.",
                             reply_markup=kb_main(uid))
        else:
            bot.send_message(
                uid,
                "♻️ Use the buttons below: *Clear + Upload* or *Clear Only*.",
                parse_mode="Markdown",
                reply_markup=kb_replace_menu(),
            )

    elif state == State.CREATE_FILES_NAME:
        filename = text.strip()
        u = get_user(uid)
        u["draft"]["pending_filename"] = filename
        save_user(uid, u)
        set_state(uid, State.CREATE_FILES_CONTENT)
        bot.send_message(uid,
            f"📝 *File:* `{filename}`\n\nNow send the file content (or upload a `.txt`):")

    elif state == State.CREATE_FILES_CONTENT:
        u        = get_user(uid)
        filename = u["draft"].get("pending_filename", "file.txt")
        _add_created_file(uid, u, filename, text)
        u["draft"].pop("pending_filename", None)
        save_user(uid, u)
        set_state(uid, State.CREATE_FILES)
        count     = len(u["draft"]["uploads"])
        file_word = "file" if count == 1 else "files"
        bot.send_message(uid,
            f"✅ *File added:* `{filename}` ({len(text)} chars)\n📁 *{count} {file_word} queued*\n\nAdd another or continue?",
            reply_markup=kb_files_more())

    elif state == State.CREATE_FILES_MULTI_NAMES:
        u         = get_user(uid)
        raw_names = [n.strip() for n in text.replace("\n", ",").split(",") if n.strip()]
        valid, invalid = [], []
        for n in raw_names:
            if "\\" in n or len(n) > 200 or not n:
                invalid.append(n)
            else:
                valid.append(n)
        if not valid:
            bot.send_message(uid, "❌ No valid filenames. Enter filenames separated by commas:")
            return
        u["draft"]["multi_filenames"]  = valid
        u["draft"]["multi_file_index"] = 0
        u["draft"]["multi_files_done"] = []
        save_user(uid, u)
        set_state(uid, State.CREATE_FILES_MULTI_CONTENT)
        warn = f"\n\n⚠️ Skipped: {', '.join(f'`{n}`' for n in invalid)}" if invalid else ""
        _ask_multi_file_content(uid, u, warn)

    elif state == State.CREATE_FILES_MULTI_CONTENT:
        u     = get_user(uid)
        names = u["draft"].get("multi_filenames", [])
        idx   = u["draft"].get("multi_file_index", 0)
        if idx >= len(names):
            _finish_multi_files(uid, u)
            return
        _add_created_file(uid, u, names[idx], text)
        u["draft"]["multi_file_index"] = idx + 1
        save_user(uid, u)
        if u["draft"]["multi_file_index"] >= len(names):
            _finish_multi_files(uid, u)
        else:
            _ask_multi_file_content(uid, u)

    # ── Single archive: typing while name-suggestion buttons are shown ──
    # (treat free text the same as tapping "Type custom name")
    elif state == State.ARCHIVE_AI_SUGGEST:
        u = get_user(uid)
        if u["draft"].get("ai_stage") == "desc":
            # Buttons showing descriptions — treat typed text as a custom description.
            desc = "" if text == "-" else text
            u["draft"]["description"] = desc
            u["draft"]["desc_raw"]    = desc
            u["draft"].pop("ai_stage", None)
            save_user(uid, u)
            if desc:
                bot.send_message(uid, f"📝 *Description set:*\n_{_escape_md(desc)}_")
            else:
                bot.send_message(uid, "⏭ *Description skipped*")
            _archive_go_to_visibility(uid)
        else:
            # Buttons showing names — treat typed text as a custom name.
            name = text.lower().replace(" ", "-")
            name = __import__("re").sub(r"[^a-z0-9\-]", "", name)
            u["draft"]["name"] = name
            descs = u["draft"].get("ai_suggested_descs", [])
            u["draft"]["ai_stage"] = "desc"
            save_user(uid, u)
            if descs:
                bot.send_message(uid,
                    f"✅ *Name set:* `{name}`\n\n"
                    "🤖 *AI Description Suggestions*\n\n"
                    "Tap a number to preview it in full, then confirm. Or type your own.",
                    reply_markup=kb_archive_ai_desc(descs, name))
            else:
                set_state(uid, State.ARCHIVE_DESC)
                bot.send_message(uid, f"✅ *Name set:* `{name}`\n\n📝 Type a description (or `-` to skip):")

    # ── Single archive: typing while a full-description preview is shown ──
    elif state == State.ARCHIVE_AI_DESC_PREVIEW:
        u   = get_user(uid)
        desc = "" if text == "-" else text
        u["draft"]["description"] = desc
        u["draft"]["desc_raw"]    = desc
        save_user(uid, u)
        if desc:
            bot.send_message(uid, f"📝 *Description set:*\n_{_escape_md(desc)}_")
        else:
            bot.send_message(uid, "⏭ *Description skipped*")
        _archive_go_to_visibility(uid)

    # ── Multi-archive: typing while name-suggestion buttons are shown ──
    elif state == State.ARCHM_AI_SUGGEST:
        u   = get_user(uid)
        idx = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid)
            return
        q   = u["draft"]["multi_queue"][idx]
        if q.get("ai_stage") == "desc":
            desc = "" if text == "-" else text
            u["draft"]["multi_queue"][idx]["description"] = desc
            u["draft"]["multi_queue"][idx]["desc_raw"]    = desc
            u["draft"]["multi_queue"][idx].pop("ai_stage", None)
            save_user(uid, u)
            set_state(uid, State.ARCHIVE_MULTI_VIS)
            bot.send_message(uid,
                f"👁 *Visibility* for `{q.get('name', 'repo')}`\n\nPublic or Private?",
                reply_markup=kb_archive_multi_visibility())
        else:
            name = text.lower().replace(" ", "-")
            name = __import__("re").sub(r"[^a-z0-9\-]", "", name)
            u["draft"]["multi_queue"][idx]["name"] = name
            descs = q.get("ai_suggested_descs", [])
            u["draft"]["multi_queue"][idx]["ai_stage"] = "desc"
            save_user(uid, u)
            if descs:
                bot.send_message(uid,
                    f"✅ *Name set:* `{name}`\n\n"
                    "🤖 *AI Description Suggestions*\n\n"
                    "Tap a number to preview it in full, then confirm. Or type your own.",
                    reply_markup=kb_archm_ai_desc(descs))
            else:
                set_state(uid, State.ARCHIVE_MULTI_DESC)
                bot.send_message(uid, f"✅ *Name set:* `{name}`\n\n📝 Type a description (or `-` to skip):")

    # ── Multi-archive: typing while a full-description preview is shown ──
    elif state == State.ARCHM_AI_DESC_PREVIEW:
        u   = get_user(uid)
        idx = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid)
            return
        desc = "" if text == "-" else text
        if len(desc) > GITHUB_DESC_MAX:
            bot.send_message(
                uid,
                f"⚠️ Your description has {len(desc)} characters, but GitHub allows only "
                f"{GITHUB_DESC_MAX}. Please enter a shorter description (or `-` to skip):",
            )
            return
        u["draft"]["multi_queue"][idx]["description"] = desc
        u["draft"]["multi_queue"][idx]["desc_raw"]    = desc
        save_user(uid, u)
        set_state(uid, State.ARCHIVE_MULTI_VIS)
        q = u["draft"]["multi_queue"][idx]
        bot.send_message(uid,
            f"👁 *Visibility* for `{q.get('name', 'repo')}`\n\nPublic or Private?",
            reply_markup=kb_archive_multi_visibility())

    # ── Single archive: submitting an edited AI description ──
    elif state == State.ARCHIVE_AI_DESC_EDIT:
        u    = get_user(uid)
        desc = text.strip()
        u["draft"]["description"] = desc
        u["draft"]["desc_raw"]    = desc
        save_user(uid, u)
        bot.send_message(uid, f"✅ *Description saved:*\n\n_{_escape_md(desc)}_\n\n{_length_badge(desc)}")
        _archive_go_to_visibility(uid)

    # ── Multi-archive: submitting an edited AI description ───
    elif state == State.ARCHM_AI_DESC_EDIT:
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid)
            return
        desc = text.strip()
        if len(desc) > GITHUB_DESC_MAX:
            bot.send_message(
                uid,
                f"⚠️ Your description has {len(desc)} characters, but GitHub allows only "
                f"{GITHUB_DESC_MAX}. Please enter a shorter description:",
            )
            return
        u["draft"]["multi_queue"][idx]["description"] = desc
        u["draft"]["multi_queue"][idx]["desc_raw"]    = desc
        save_user(uid, u)
        set_state(uid, State.ARCHIVE_MULTI_VIS)
        q = u["draft"]["multi_queue"][idx]
        bot.send_message(uid,
            f"✅ *Description saved:*\n\n_{_escape_md(desc)}_\n\n{_length_badge(desc)}\n\n"
            f"👁 *Visibility* for `{q.get('name', 'repo')}`\n\nPublic or Private?",
            reply_markup=kb_archive_multi_visibility())

    # ── Archive password attempts arrive as TEXT ──────────────
    # (these states used to be reachable only from the document handler,
    #  so a typed password was answered with "Use the menu…" and the flow
    #  hung forever — now the shared handlers run from both paths)
    elif state == State.ARCHIVE_PASSWORD:
        _handle_archive_password(uid, m)

    elif state == State.ARCHIVE_MULTI_PASSWORD:
        _handle_archive_multi_password(uid, m)

    elif state == State.REPLACE_PASSWORD:
        _handle_replace_password(uid, m)

    else:
        bot.send_message(uid, "Use the menu or type a command. Try /help", reply_markup=kb_main())


# ─────────────────────────────────────────────────────────────
#  File/document upload handler
# ─────────────────────────────────────────────────────────────

_ARCHIVE_EXTS = (".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar", ".rar")

# ── Shared password handlers ─────────────────────────────────
# Passwords arrive as TEXT messages, but these states used to be handled
# only inside the document/photo handler — so a typed password never
# reached the state machine ("Use the menu…" was the reply) and the flow
# hung forever.  They are now callable from BOTH handlers.


def _handle_archive_password(uid: int, m: Message) -> None:
    """Password attempt for a protected archive (single-archive flow)."""
    state = get_state(uid)
    if state != State.ARCHIVE_PASSWORD:
        return
    password = m.text.strip() if m.text else ""
    if not password:
        bot.send_message(uid, "🔐 Please type the password (text only):")
        return
    _scrub_secret_message(uid, m.message_id)
    u = get_user(uid)
    raw_b64  = u["draft"].get("archive_raw_b64", "")
    fname    = u["draft"].get("archive_filename", "archive.zip")
    tries    = u["draft"].get("archive_pw_tries", 0)
    raw      = base64.b64decode(raw_b64) if raw_b64 else b""
    msg      = bot.send_message(uid, f"🔓 Trying password for `{fname}` ···")
    try:
        files = _extract_archive(raw, fname, password=password)
    except ArchivePasswordWrong:
        tries += 1
        u["draft"]["archive_pw_tries"] = tries
        save_user(uid, u)
        remaining = 3 - tries
        if remaining <= 0:
            set_state(uid, State.IDLE, draft={})
            bot.edit_message_text(
                "❌ *Wrong password — 3 attempts used.*\n\nArchive upload cancelled.",
                uid, msg.message_id, reply_markup=kb_main(),
            )
        else:
            bot.edit_message_text(
                f"❌ *Wrong password!* ({remaining} attempt{'s' if remaining != 1 else ''} left)\n\n"
                "Please send the correct password:",
                uid, msg.message_id,
            )
        return
    except Exception as ex:
        _safe_user_error(uid, "Archive extraction", ex, msg.message_id)
        return

    found_count = len(files)
    ignored_git = _archive_git_metadata_count(files)
    files  = _preserve_archive_paths(files)

    files = _strip_archive_wrapper(files, fname)
    if not files:
        _bot_notify(uid, msg.message_id, "❌ Archive is empty or contains no extractable files.")
        return
    readme_file    = next((f for f in files if _is_root_readme(f)), None)
    readme_content = ""
    if readme_file:
        try:
            readme_content = base64.b64decode(readme_file["content_b64"]).decode("utf-8", errors="replace")
        except Exception:
            pass
    ai_mode = u["draft"].get("arch_ai_mode", False)
    u["draft"] = {
        "archive_files":    files,
        "archive_filename": fname,
        "archive_readme":   readme_content,
        "arch_ai_mode":     ai_mode,
        "archive_original_file_count": found_count,
        "archive_ignored_git_count": ignored_git,
    }
    save_user(uid, u)
    set_state(uid, State.ARCHIVE_NAME)
    unlocked_header = (
        f"✅ *Unlocked & extracted!*\n\n"
        f"📦 `{fname}` → *{_archive_file_count_note(found_count, ignored_git)}*\n"
        f"{'📄 README.md detected!' if readme_file else '📄 No README.md found'}\n\n"
    )
    if ai_mode and u.get("ai_provider") and u.get("ai_key"):
        try:
            bot.edit_message_text(
                f"⏳ Analyzing `{fname}` — generating name suggestions ···",
                uid, msg.message_id,
            )
        except Exception:
            pass
        names, descs = _ai_suggest_names_and_descs(u, files, fname)
        u = get_user(uid)
        _store_ai_suggestions(u, names, descs)
        save_user(uid, u)
        set_state(uid, State.ARCHIVE_AI_SUGGEST)
        availability = _annotate_name_availability(u, names) if names else {}
        if names:
            try:
                bot.edit_message_text(
                    unlocked_header
                    + "🤖 *AI Repository Name Suggestions*\n\n"
                    "✅ = available on your account · ⚠️taken = already exists\n\n"
                    "Choose a suggested name or type your own:",
                    uid, msg.message_id,
                    reply_markup=kb_archive_ai_suggest(names, descs, availability),
                )
            except Exception:
                bot.send_message(
                    uid,
                    unlocked_header + "🤖 Choose a name or type your own:",
                    reply_markup=kb_archive_ai_suggest(names, descs, availability),
                )
        else:
            bot.edit_message_text(
                unlocked_header
                + "⚠️ AI suggestions unavailable. Please type the repo name manually.",
                uid, msg.message_id,
            )
            set_state(uid, State.ARCHIVE_NAME)
    else:
        bot.edit_message_text(
            unlocked_header
            + "━━━━━━━━━━━━━━━━━━━━\n\n"
            "🔤 *Step 1 — Repository Name*\n\n"
            "What should the repository be called?\n\n"
            "_Lowercase · hyphens · no spaces_\n\nExample: `my-awesome-project`",
            uid, msg.message_id,
        )


def _handle_archive_multi_password(uid: int, m: Message) -> None:
    """Password attempt for a protected archive (multi-archive flow)."""
    state = get_state(uid)
    if state != State.ARCHIVE_MULTI_PASSWORD:
        return
    password = m.text.strip() if m.text else ""
    if not password:
        bot.send_message(uid, "🔐 Please type the password (text only):")
        return
    _scrub_secret_message(uid, m.message_id)
    u    = get_user(uid)
    pend = u["draft"].get("multi_pw_pending", {})
    fname    = pend.get("filename", "archive.rar")
    raw_b64  = pend.get("raw_b64", "")
    orig_msg = pend.get("msg_id")
    tries    = pend.get("tries", 0)
    raw      = base64.b64decode(raw_b64) if raw_b64 else b""
    queue    = u["draft"].get("multi_queue", [])
    msg      = bot.send_message(uid, f"🔓 Trying password for `{fname}` ···")
    try:
        files = _extract_archive(raw, fname, password=password)
    except ArchivePasswordWrong:
        tries += 1
        pend["tries"] = tries
        u["draft"]["multi_pw_pending"] = pend
        save_user(uid, u)
        remaining = 3 - tries
        if remaining <= 0:
            u["draft"].pop("multi_pw_pending", None)
            save_user(uid, u)
            set_state(uid, State.ARCHIVE_MULTI_COLLECT)
            bot.edit_message_text(
                f"❌ *Wrong password — 3 attempts used.* `{fname}` skipped.\n\n"
                "_Send more archives or tap ✅ Done._",
                uid, msg.message_id,
                reply_markup=kb_archive_multi_collecting(len(queue)),
            )
        else:
            bot.edit_message_text(
                f"❌ *Wrong password!* ({remaining} attempt{'s' if remaining != 1 else ''} left)\n\n"
                "Please send the correct password:",
                uid, msg.message_id,
            )
        return
    except Exception as ex:
        _safe_user_error(uid, "Archive extraction", ex, msg.message_id)
        return

    found_count = len(files)
    ignored_git = _archive_git_metadata_count(files)
    files = _preserve_archive_paths(files)
    files = _strip_archive_wrapper(files, fname)
    if not files:
        _bot_notify(uid, msg.message_id, f"⚠️ `{fname}` is empty — skipped.")
        set_state(uid, State.ARCHIVE_MULTI_COLLECT)
        return
    readme_file    = next((f for f in files if _is_root_readme(f)), None)
    readme_content = ""
    if readme_file:
        try:
            readme_content = base64.b64decode(readme_file["content_b64"]).decode("utf-8", errors="replace")
        except Exception:
            pass
    queue.append({
        "filename":       fname,
        "files":          files,
        "readme_content": readme_content,
        "name":           "",
        "description":    "",
        "private":        False,
        "ai_mode":        u["draft"].get("multi_ai_mode", False),
    })
    u["draft"]["multi_queue"] = queue
    u["draft"].pop("multi_pw_pending", None)
    save_user(uid, u)
    set_state(uid, State.ARCHIVE_MULTI_COLLECT)
    count = len(queue)
    bot.edit_message_text(
        f"✅ *`{fname}` unlocked & added!*  ({_archive_file_count_note(found_count, ignored_git)}"
        f"{'  ·  📄 README found' if readme_file else ''})\n\n"
        f"📦 *{count}/100 archive(s) queued*\n\n"
        "_Send more archives or tap ✅ Done when finished._",
        uid, msg.message_id,
        reply_markup=kb_archive_multi_collecting(count),
    )


def _handle_replace_password(uid: int, m: Message) -> None:
    """Password attempt for a protected archive (replace-repo flow)."""
    state = get_state(uid)
    if state != State.REPLACE_PASSWORD:
        return
    password = m.text.strip() if m.text else ""
    if not password:
        bot.send_message(uid, "🔐 Please type the password (text only):")
        return
    _scrub_secret_message(uid, m.message_id)
    u        = get_user(uid)
    raw_b64  = u["draft"].get("replace_raw_b64", "")
    fname    = u["draft"].get("replace_filename", "archive.zip")
    tries    = u["draft"].get("replace_pw_tries", 0)
    raw      = base64.b64decode(raw_b64) if raw_b64 else b""
    msg      = bot.send_message(uid, f"🔓 Trying password for `{fname}` ···")
    try:
        files = _extract_archive(raw, fname, password=password)
    except ArchivePasswordWrong:
        tries += 1
        u["draft"]["replace_pw_tries"] = tries
        save_user(uid, u)
        remaining = 3 - tries
        if remaining <= 0:
            set_state(uid, State.IDLE, draft={})
            bot.edit_message_text(
                "❌ *Wrong password — 3 attempts used.*\n\nReplace cancelled.",
                uid, msg.message_id, reply_markup=kb_main(),
            )
        else:
            bot.edit_message_text(
                f"❌ *Wrong password!* ({remaining} attempt{'s' if remaining != 1 else ''} left)\n\n"
                "Please send the correct password:",
                uid, msg.message_id,
            )
        return
    except Exception as ex:
        _safe_user_error(uid, "Archive extraction", ex, msg.message_id)
        return

    files = _preserve_archive_paths(files)
    files = _strip_archive_wrapper(files, fname)
    if not files:
        _bot_notify(uid, msg.message_id, "❌ Archive is empty or contains no extractable files.")
        return
    u["draft"].pop("replace_raw_b64", None)
    u["draft"].pop("replace_pw_tries", None)
    save_user(uid, u)
    bot.edit_message_text(
        f"✅ *Unlocked & extracted!*\n\n"
        f"📦 `{fname}` → *{len(files)} files*\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n\nReview and confirm below 👇",
        uid, msg.message_id,
    )
    _store_replace_files(uid, files, fname)

@bot.message_handler(func=lambda m: True, content_types=["document", "photo"])
def handle_file_upload(m: Message) -> None:
    uid   = m.chat.id
    if _check_banned(uid):
        return
    state = get_state(uid)
    u     = get_user(uid)

    # ── Upload to Repo: queue incoming files/folders ─────────
    if state == State.UPLOAD_COLLECT:
        _handle_upload_file(uid, m)
        return

    # ── Replace Repo: password for a protected archive ───────
    if state == State.REPLACE_PASSWORD:
        _handle_replace_password(uid, m)
        return

    # ── Replace Repo: waiting for the new archive ────────────
    if state == State.REPLACE_UPLOAD:
        if not m.document:
            bot.send_message(uid, "❌ Please send an archive file (ZIP, RAR, tar.gz, etc.)")
            return
        _handle_replace_archive(uid, m)
        return

    # ── Archive password — single mode ──────────────────────
    if state == State.ARCHIVE_PASSWORD:
        _handle_archive_password(uid, m)
        return

    # ── Archive password — multi mode ────────────────────────
    if state == State.ARCHIVE_MULTI_PASSWORD:
        _handle_archive_multi_password(uid, m)
        return

    # ── Archive upload: single mode ──────────────────────────
    if state == State.ARCHIVE_UPLOAD:
        if not m.document:
            bot.send_message(uid, "❌ Please send an archive file (ZIP, RAR, tar.gz, etc.)")
            return
        _handle_archive_upload(uid, m)
        return

    # ── Archive upload: multiple mode — collecting archives ──
    if state == State.ARCHIVE_MULTI_COLLECT:
        if not m.document:
            bot.send_message(uid, "❌ Please send an archive file.")
            return
        fname = m.document.file_name or "archive.zip"
        fname_lower = fname.lower()
        if not any(fname_lower.endswith(ext) for ext in _ARCHIVE_EXTS):
            bot.send_message(uid,
                f"⚠️ `{fname}` doesn't look like an archive.\n\n"
                "Supported: ZIP, tar.gz, tgz, tar.bz2, tar.xz, RAR\n\n"
                "_Keep sending archives or tap ✅ Done when finished._")
            return
        queue = u["draft"].get("multi_queue", [])
        if len(queue) >= 100:
            bot.send_message(uid,
                "⚠️ *Maximum 100 archives reached.*\n\nTap ✅ Done to proceed.",
                reply_markup=kb_archive_multi_collecting(len(queue)))
            return
        msg = bot.send_message(uid, f"⏳ Downloading `{fname}` ({len(queue)+1}/100) ·")
        try:
            file_info = bot.get_file(m.document.file_id)
            raw       = _animate(uid, msg.message_id, f"Downloading `{fname}`",
                                 bot.download_file, file_info.file_path)
            _bot_notify(uid, msg.message_id, f"⏳ Extracting `{fname}` ···")
            try:
                files = _extract_archive(raw, fname)
            except ArchivePasswordRequired:
                # Stash this archive and ask for password
                u["draft"]["multi_pw_pending"] = {
                    "raw_b64":  base64.b64encode(raw).decode(),
                    "filename": fname,
                    "msg_id":   msg.message_id,
                    "tries":    0,
                }
                save_user(uid, u)
                set_state(uid, State.ARCHIVE_MULTI_PASSWORD)
                bot.edit_message_text(
                    f"🔐 *Password Required*\n\n"
                    f"`{fname}` is encrypted.\n\n"
                    "Please send the password:\n"
                    "_(3 attempts allowed)_",
                    uid, msg.message_id,
                )
                return
            except ArchivePasswordWrong:
                bot.edit_message_text(
                    f"❌ Wrong password for `{fname}` — skipped.",
                    uid, msg.message_id,
                    reply_markup=kb_archive_multi_collecting(len(queue)),
                )
                return

            found_count = len(files)
            ignored_git = _archive_git_metadata_count(files)
            files = _preserve_archive_paths(files)
            files = _strip_archive_wrapper(files, fname)
            if not files:
                _bot_notify(uid, msg.message_id, f"⚠️ `{fname}` is empty — skipped.")
                return
            readme_file    = next((f for f in files if _is_root_readme(f)), None)
            readme_content = ""
            if readme_file:
                try:
                    readme_content = base64.b64decode(readme_file["content_b64"]).decode("utf-8", errors="replace")
                except Exception:
                    pass
            ai_mode = u["draft"].get("multi_ai_mode", False)
            queue.append({
                "filename":       fname,
                "files":          files,
                "readme_content": readme_content,
                "name":           "",
                "description":    "",
                "private":        False,
                "ai_mode":        ai_mode,
            })
            u["draft"]["multi_queue"] = queue
            save_user(uid, u)
            count = len(queue)
            bot.edit_message_text(
                f"✅ *`{fname}` added!*  ({_archive_file_count_note(found_count, ignored_git)}"
                f"{'  ·  📄 README found' if readme_file else ''})\n\n"
                f"📦 *{count}/100 archive(s) queued*\n\n"
                "_Send more archives or tap ✅ Done when finished._",
                uid, msg.message_id,
                reply_markup=kb_archive_multi_collecting(count),
            )
            log.event(f"{log.mask_user_id(uid)} added archive {count}: {fname}, {len(files)} files")
        except Exception as ex:
            _bot_notify(uid, msg.message_id, f"❌ Archive error for `{fname}`: `{ex}`")
        return

    # ── Inline archive during normal file upload ─────────────
    if state == State.CREATE_FILES_UPLOAD and m.document:
        fname = (m.document.file_name or "").lower()
        if any(fname.endswith(ext) for ext in _ARCHIVE_EXTS):
            _handle_inline_archive(uid, m)
            return

    # ── .txt content for single/multi create modes ───────────
    if state in (State.CREATE_FILES_CONTENT, State.CREATE_FILES_MULTI_CONTENT):
        if m.document and m.document.file_name and m.document.file_name.lower().endswith(".txt"):
            file_info = bot.get_file(m.document.file_id)
            raw       = bot.download_file(file_info.file_path)
            try:
                content = raw.decode("utf-8")
            except UnicodeDecodeError:
                content = raw.decode("latin-1", errors="replace")
            if state == State.CREATE_FILES_CONTENT:
                filename = u["draft"].get("pending_filename", "file.txt")
                _add_created_file(uid, u, filename, content)
                u["draft"].pop("pending_filename", None)
                save_user(uid, u)
                set_state(uid, State.CREATE_FILES)
                count         = len(u["draft"]["uploads"])
                file_word     = "file" if count == 1 else "files"
                status_msg_id = u["draft"].get("upload_status_msg_id")
                if status_msg_id:
                    try:
                        bot.edit_message_text(
                            f"📁 *{count} {file_word} queued* — last: `{filename}`\n\n"
                            "_Keep sending files or tap ✅ Done._",
                            uid, status_msg_id,
                            reply_markup=kb_files_continue(),
                        )
                        status_msg_id = status_msg_id  # keep existing
                    except Exception:
                        status_msg_id = None
                if not status_msg_id:
                    msg = bot.send_message(uid,
                        f"📁 *{count} {file_word} queued* — last: `{filename}`\n\n"
                        "_Keep sending files or tap ✅ Done._",
                        reply_markup=kb_files_continue())
                    u["draft"]["upload_status_msg_id"] = msg.message_id
                    save_user(uid, u)
            else:
                names = u["draft"].get("multi_filenames", [])
                idx   = u["draft"].get("multi_file_index", 0)
                if idx < len(names):
                    _add_created_file(uid, u, names[idx], content)
                    u["draft"]["multi_file_index"] = idx + 1
                    save_user(uid, u)
                    if u["draft"]["multi_file_index"] >= len(names):
                        _finish_multi_files(uid, u)
                    else:
                        _ask_multi_file_content(uid, u)
            return

    # ── Regular file upload ──────────────────────────────────
    if state not in (State.CREATE_FILES_UPLOAD, State.CREATE_FILES):
        bot.send_message(uid, "📁 Send files during the file upload step of repo creation.")
        return
    doc   = m.document
    photo = m.photo
    if not doc and not photo:
        return
    try:
        # ── Get or create the shared status message ──────────
        status_msg_id = u["draft"].get("upload_status_msg_id")

        if doc:
            filename = doc.file_name or "upload.bin"
        else:
            ph       = photo[-1]
            filename = f"image_{ph.file_id[:8]}.jpg"

        # Try to reuse the existing status bubble; if it fails create a new one
        if status_msg_id:
            try:
                bot.edit_message_text(f"📥 Downloading `{filename}` ···", uid, status_msg_id)
            except Exception as _edit_err:
                # Only reset if the message was deleted/not found — keep ID for all other errors
                if "not found" in str(_edit_err).lower() or "message_id_invalid" in str(_edit_err).lower():
                    status_msg_id = None
                    u["draft"].pop("upload_status_msg_id", None)
                    save_user(uid, u)

        if not status_msg_id:
            status_msg    = bot.send_message(uid, f"📥 Downloading `{filename}` ···")
            status_msg_id = status_msg.message_id
            u["draft"]["upload_status_msg_id"] = status_msg_id
            save_user(uid, u)   # persist BEFORE download so any crash won't lose it

        # ── Download ─────────────────────────────────────────
        if doc:
            file_info = bot.get_file(doc.file_id)
            raw       = bot.download_file(file_info.file_path)
            try:
                content = raw.decode("utf-8")
                source  = "text"
            except UnicodeDecodeError:
                content = base64.b64encode(raw).decode()
                source  = "binary"
        else:
            file_info = bot.get_file(ph.file_id)
            raw       = bot.download_file(file_info.file_path)
            content   = base64.b64encode(raw).decode()
            source    = "binary"

        # ── Store & update the ONE status bubble ─────────────
        u["draft"].setdefault("uploads", []).append({"name": filename, "content": content, "source": source})
        save_user(uid, u)
        set_state(uid, State.CREATE_FILES_UPLOAD)
        count     = len(u["draft"]["uploads"])
        file_word = "file" if count == 1 else "files"

        try:
            bot.edit_message_text(
                f"📁 *{count} {file_word} queued* — last: `{filename}`\n\n"
                "_Keep sending files or tap ✅ Done._",
                uid, status_msg_id,
                reply_markup=kb_files_continue(),
            )
        except Exception:
            pass   # Telegram sometimes rejects identical text edits — that's fine

    except Exception as ex:
        _safe_user_error(uid, "File upload", ex)


# ─────────────────────────────────────────────────────────────
#  Create repo: flow helpers
# ─────────────────────────────────────────────────────────────

def _go_to_visibility(uid: int, msg_id: int = None) -> None:
    u = get_user(uid)
    set_state(uid, State.CREATE_VISIBILITY, draft=u["draft"])
    text = "━━━━━━━━━━━━━━━━━━━━\n\n👁 *Step 3/5 — Visibility*\n\nMake this repository public or private?"
    if msg_id:
        try:
            bot.edit_message_text(text, uid, msg_id, reply_markup=kb_visibility())
            return
        except Exception:
            pass
    bot.send_message(uid, text, reply_markup=kb_visibility())


def _go_to_files(uid: int, msg_id: int = None) -> None:
    u = get_user(uid)
    if "uploads" not in u["draft"]:
        u["draft"]["uploads"] = []
        save_user(uid, u)
    set_state(uid, State.CREATE_FILES, draft=u["draft"])
    text = (
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        "📁 *Step 4/5 — Files*\n\n"
        "Upload files, create new ones, or upload an archive (ZIP, RAR, tar.gz)."
    )
    if msg_id:
        try:
            bot.edit_message_text(text, uid, msg_id, reply_markup=kb_files_step())
            return
        except Exception:
            pass
    bot.send_message(uid, text, reply_markup=kb_files_step())


def _go_to_ai_files(uid: int, msg_id: int = None) -> None:
    u            = get_user(uid)
    ai_available = bool(u.get("ai_provider") and u.get("ai_key"))
    set_state(uid, State.CREATE_AI_FILES, draft=u["draft"])
    repo_name    = u["draft"].get("name", "your repo")
    uploads      = u["draft"].get("uploads", [])
    uploaded_readme = next((f for f in uploads if f["name"].lower() == "readme.md"), None)
    u["draft"]["has_uploaded_readme"] = bool(uploaded_readme)
    save_user(uid, u)

    if not ai_available:
        text = (
            "━━━━━━━━━━━━━━━━━━━━\n\n🤖 *Step 5/5 — AI Files*\n\n"
            "⚠️ No AI provider configured. Set one with `/setai`.\n\n_Skipping AI step._"
        )
        if msg_id:
            try:
                bot.edit_message_text(text, uid, msg_id)
            except Exception:
                bot.send_message(uid, text)
        else:
            bot.send_message(uid, text)
        u["draft"]["ai_files"] = False
        save_user(uid, u)
        _show_create_confirm(uid, None)
        return

    has_readme = bool(uploaded_readme)
    readme_note = "📄 *README.md detected!* AI can rewrite or improve it.\n\n" if has_readme else ""
    text = (
        f"━━━━━━━━━━━━━━━━━━━━\n\n🤖 *Step 5/5 — AI Files*\n\n"
        f"{readme_note}Would you like AI to generate or improve files for `{repo_name}`?"
    )
    if msg_id:
        try:
            bot.edit_message_text(text, uid, msg_id, reply_markup=kb_ai_files(has_readme))
            return
        except Exception:
            pass
    bot.send_message(uid, text, reply_markup=kb_ai_files(has_readme))


def _show_create_confirm(uid: int, msg_id: Optional[int]) -> None:
    u       = get_user(uid)
    d       = u["draft"]
    name    = d.get("name", "")
    desc    = d.get("description", "") or "_No description_"
    vis     = "🔒 Private" if d.get("private") else "🌍 Public"
    uploads = d.get("uploads", [])
    ai_opt  = d.get("ai_files", False)
    ai_str  = "README + .gitignore" if ai_opt is True else ("README only" if ai_opt == "readme_only" else "None")

    scan = {"flagged_files": []}
    if uploads:
        scan = scan_files_for_secrets(uploads)
    flagged_count = len(scan["flagged_files"])
    u["draft"].pop("_sec_scan_flagged", None)
    save_user(uid, u)
    sec_badge = ""
    if uploads and flagged_count:
        sec_badge = f"\n🛡 Sensitive data detected in {flagged_count} file(s); creation will be blocked until fixed.\n"
    elif uploads:
        sec_badge = "\n✅ *No sensitive data detected.*\n"
    text = (
        "━━━━━━━━━━━━━━━━━━━━\n\n🔍 *Confirm Repository*\n\n"
        f"📦 *Name:* `{name}`\n📝 *Desc:* _{_escape_md(desc)}_\n"
        f"👁 *Visibility:* {vis}\n📁 *Files:* {len(uploads) or 'None'}\n"
        f"🤖 *AI Files:* {ai_str}\n"
        + sec_badge
        + "\n_Everything look good? Tap ✅ to create._"
    )
    set_state(uid, State.CREATE_CONFIRM)
    if msg_id:
        try:
            bot.edit_message_text(text, uid, msg_id, reply_markup=kb_confirm("create"))
            return
        except Exception:
            pass
    bot.send_message(uid, text, reply_markup=kb_confirm("create"))


# ─────────────────────────────────────────────────────────────
#  Create repo: execute
# ─────────────────────────────────────────────────────────────

def _execute_create_repo(uid: int, msg_id: int) -> None:
    u       = get_user(uid)
    d       = u["draft"]
    name    = d.get("name", "new-repo")
    desc    = d.get("description", "")
    private = d.get("private", False)
    uploads = d.get("uploads", [])
    ai_opt  = d.get("ai_files", False)
    token   = u["github_token"]
    _t      = _time.time()

    if _block_if_sensitive_files(uid, msg_id, uploads, name, archive=False):
        return

    try:
        bot.edit_message_text("⏳ Creating repository ·", uid, msg_id)
        repo = _animate(uid, msg_id, "Creating repository",
                       gh.create_repo, token, name, desc, private, True)
    except Exception as ex:
        if _is_name_taken_error(ex):
            set_state(uid, State.CREATE_NAME)   # keep draft intact
            bot.edit_message_text(_name_taken_text(name), uid, msg_id, parse_mode="Markdown")
            return
        _safe_user_error(uid, "Repository creation", ex, msg_id)
        return

    info = gh.get_user(token)
    if not info:
        bot.edit_message_text("❌ Could not verify GitHub user.", uid, msg_id)
        return
    owner    = info["login"]
    repo_url = repo.get("html_url", f"https://github.com/{owner}/{name}")

    pushed = []
    failed = []        # list of (filename, reason)

    # ── Smart AI commit message ────────────────────────────────
    commit_msg = d.get("commit_message", "")
    if not commit_msg and uploads and u.get("ai_provider") and u.get("ai_key"):
        try:
            filenames = [f["name"] for f in uploads]
            commit_msg = ai.generate_smart_commit_message(
                u["ai_provider"], u["ai_key"],
                u.get("ai_model") or ai.PROVIDERS.get(u["ai_provider"], {}).get("default", ""),
                filenames, desc
            )
        except Exception:
            commit_msg = "Initial commit via GitHub AI Bot"
    if not commit_msg:
        commit_msg = "Initial commit via GitHub AI Bot"

    for i, f in enumerate(uploads):
        fn      = f["name"]
        content = f["content"]
        source  = f.get("source", "text")
        try:
            bot.edit_message_text(f"⏳ Uploading `{fn}` ({i+1}/{len(uploads)}) ···", uid, msg_id)
        except Exception:
            pass
        try:
            # Binary Telegram/archive uploads are stored as base64 text in the
            # draft. push_file accepts bytes and performs the one required
            # base64 encoding for GitHub; passing the encoded text directly
            # would upload the base64 representation as a text file.
            if source in ("binary", "archive_binary"):
                content = base64.b64decode(content, validate=True)
            ok = gh.push_file(token, owner, name, fn, content, commit_msg)
            if ok:
                pushed.append(fn)
                log.github(f"Pushed: {owner}/{name}/{fn}")
            else:
                failed.append((fn, "push returned False"))
                log.warn(f"Failed (no exception): {fn}")
        except Exception as _fe:
            reason = str(_fe)[:80]
            failed.append((fn, reason))
            log.error(f"Failed: {fn}", reason)
        _time.sleep(0.1)

    if ai_opt:
        has_uploaded_readme = d.get("has_uploaded_readme", False)
        existing_readme_file = next((f for f in uploads if f["name"].lower() == "readme.md"), None)
        if has_uploaded_readme and existing_readme_file:
            try:
                bot.edit_message_text("🤖 Rewriting README with AI ···", uid, msg_id)
            except Exception:
                pass
            readme_text = _ai_rewrite_readme(u, name, desc, existing_readme_file["content"], files=uploads)
            if readme_text:
                readme_text = _deduplicate_readme_description(readme_text, desc)
                gh.push_file(token, owner, name, "README.md", readme_text, "✍️ AI rewrite README")
                pushed.append("README.md (AI rewrite)")
        else:
            try:
                bot.edit_message_text("🤖 Generating README with AI ···", uid, msg_id)
            except Exception:
                pass
            readme_text = _ai_generate_readme(u, name, desc, files=uploads)
            if readme_text:
                readme_text = _deduplicate_readme_description(readme_text, desc)
                gh.push_file(token, owner, name, "README.md", readme_text, "✨ AI generated README")
                pushed.append("README.md (AI generated)")
        if ai_opt is True:
            try:
                bot.edit_message_text("🤖 Generating .gitignore ···", uid, msg_id)
            except Exception:
                pass
            gi_prompt = (
                f"Generate a comprehensive .gitignore for a project named '{name}'.\n"
                f"Description: {desc or 'Not provided'}\nReturn only the .gitignore content."
            )
            gi_text, _ = ai.generate_safe(u["ai_provider"], u["ai_key"], u["ai_model"], gi_prompt, max_tokens=400)
            if gi_text:
                gh.push_file(token, owner, name, ".gitignore", gi_text, "✨ AI generated .gitignore")
                pushed.append(".gitignore (AI generated)")

    elapsed = _time.time() - _t
    lines   = [f"🎉 *Repository Created!*\n", f"📦 [`{owner}/{name}`]({repo_url})", f"⏱ Done in `{elapsed:.1f}s`\n"]
    if pushed:
        push_items = "".join(f"\n  • `{p}`" for p in pushed[:10])
        if len(pushed) > 10:
            push_items += "\n  • … and more"
        lines.append(f"✅ Pushed ({len(pushed)}):{push_items}")
    if failed:
        fail_items = "".join(
            f"\n  • `{fn}` — _{_escape_md(reason)}_" if reason and reason != "push returned False"
            else f"\n  • `{fn}`"
            for fn, reason in failed[:10]
        )
        if len(failed) > 10:
            fail_items += "\n  • … and more"
        lines.append(f"❌ Failed ({len(failed)}):{fail_items}")
    lines.append(f"\n🔗 [Open on GitHub]({repo_url})")
    lines.append(f"\n```\ngit clone {repo_url}.git\ncd {name}\n```")
    try:
        bot.edit_message_text("\n".join(lines), uid, msg_id,
                              disable_web_page_preview=True,
                              reply_markup=kb_home_only(uid))
    except Exception:
        bot.send_message(uid, "\n".join(lines),
                         disable_web_page_preview=True,
                         reply_markup=kb_home_only(uid))
    add_history(uid, f"Created repo: {name}")
    u["repos_created"] = u.get("repos_created", 0) + 1
    u["files_pushed"]  = u.get("files_pushed", 0) + len(pushed)
    u["draft"] = {}
    save_user(uid, u)
    set_state(uid, State.IDLE)


# ─────────────────────────────────────────────────────────────
#  Callback query handler
# ─────────────────────────────────────────────────────────────

# Wire the shared singletons into the GitHub Extras module (issues / PRs /
# releases / branches) now that every dependency above is defined.
gh_actions.configure(
    bot=bot,
    gh=gh,
    get_user=get_user,
    save_user=save_user,
    add_history=add_history,
    kb_repo_picker=kb_repo_picker,
    escape=_escape_md,
)

# ─────────────────────────────────────────────────────────────
#  Navigation renderer — re-renders a screen by its callback key
# ─────────────────────────────────────────────────────────────

def _show_home(uid: int, msg_id: int) -> None:
    """Render Home in place; never send a second Home message on edit failure."""
    text = _tr(uid, "home_title")
    try:
        bot.edit_message_text(text, uid, msg_id, reply_markup=kb_main(uid))
    except Exception as exc:
        # Telegram reports an error for unchanged content. Treat it as success.
        if "message is not modified" in str(exc).lower():
            return
        # Sending a fallback here creates another Home screen every time a
        # stale/unsupported message is tapped. Keep navigation idempotent.


def _nav_render(uid: int, data: str, msg_id: int) -> None:
    """\n    Re-render a screen identified by its callback_data key.\n    Used by the ◀ Back button to go back exactly one step.\n    Preserves all draft data — never resets it.\n    """
    u = get_user(uid)

    # ── Home ─────────────────────────────────────────────────
    if data == "menu_home":
        nav_clear(uid)
        set_state(uid, State.IDLE, draft={})
        _show_home(uid, msg_id)

    # ── Archive Upload mode picker ────────────────────────────
    elif data == "files_archive_upload":
        if not u.get("github_token"):
            _send_github_token_guide(uid)
            return
        set_state(uid, State.IDLE)
        try:
            bot.edit_message_text(
                "📦 *Archive Upload*\n\n"
                "How would you like to upload?\n\n"
                "📁 *Single Archive* — one archive → one repository\n"
                "📚 *Multiple Archives* — up to 100 archives → separate repositories",
                uid, msg_id, reply_markup=kb_archive_mode(),
            )
        except Exception:
            bot.send_message(uid, "📦 *Archive Upload*", reply_markup=kb_archive_mode())

    # ── Fork mode picker ─────────────────────────────────────
    elif data == "menu_import":
        set_state(uid, State.FORK_MODE_PICK)
        try:
            bot.edit_message_text(
                "📥 *Fork Repository*\n\nHow many repositories would you like to fork?",
                uid, msg_id, reply_markup=kb_fork_mode(),
            )
        except Exception:
            bot.send_message(uid, "📥 *Fork Repository*", reply_markup=kb_fork_mode())

    # ── Delete repo picker ────────────────────────────────────
    elif data == "menu_download":
        _show_download_picker(uid, edit_msg_id=msg_id)

    elif data == "menu_delete":
        _show_delete_picker(uid, edit_msg_id=msg_id)

    elif data == "menu_edit_repo":
        _show_edit_repo_picker(uid, edit_msg_id=msg_id)

    # ── Replace Repo Contents ─────────────────────────────────
    elif data == "menu_replace_repo":
        _show_replace_picker(uid, edit_msg_id=msg_id)

    elif data == "rr_repomenu":
        _show_replace_menu(uid, msg_id)

    elif data.startswith("er_repomenu_"):
        repo_name = data[len("er_repomenu_"):]
        _show_edit_repo_menu(uid, repo_name, msg_id)

    elif data.startswith("er_browse_"):
        rest = data[len("er_browse_"):]
        if "|" in rest:
            repo_name, path = rest.split("|", 1)
        elif "_" in rest:              # legacy keyboard
            sep  = rest.index("_")
            repo_name = rest[:sep]
            path      = rest[sep+1:]
        else:
            repo_name, path = rest, ""
        _browse_path(uid, repo_name, path, msg_id)

    # ── Create repo (step 1) ──────────────────────────────────
    elif data == "menu_create":
        set_state(uid, State.CREATE_NAME)
        try:
            bot.edit_message_text(
                "📦 *Create Repository*\n━━━━━━━━━━━━━━━━━━━━\n\n"
                "🔤 *Step 1/5 — Name*\n\nWhat should the repository be called?\n\n"
                "_Lowercase · hyphens · no spaces_",
                uid, msg_id,
            )
        except Exception:
            bot.send_message(uid, "📦 What should the repository be called?")

    # ── Visibility step (single archive) ─────────────────────
    elif data == "arch_visibility_step":
        _archive_go_to_visibility(uid, msg_id)

    # ── README step (single archive) ─────────────────────────
    elif data == "arch_readme_step":
        _archive_go_to_readme(uid, msg_id)

    # ── Fallback: show archive mode picker ───────────────────
    else:
        try:
            bot.edit_message_text(
                "📦 *Archive Upload*\n\nChoose mode:",
                uid, msg_id, reply_markup=kb_archive_mode(),
            )
        except Exception:
            bot.send_message(uid, "📦 *Archive Upload*", reply_markup=kb_archive_mode())


def _answer(call, text: str = None, alert: bool = False) -> None:
    """Safely answer a callback query.

    The dispatcher already answered the query once, so a second
    answer_callback_query for the same id raises
    ApiTelegramException("query is already answered") — which used to abort the
    whole callback branch (dead buttons). This wrapper swallows that error.
    """
    try:
        bot.answer_callback_query(call.id, text, show_alert=alert)
    except Exception:
        pass


@bot.callback_query_handler(func=lambda c: True)
def handle_callback(call) -> None:
    uid  = call.message.chat.id
    data = call.data
    _answer(call)

    # ── Ban gate ─────────────────────────────────────────────
    if _check_banned(uid):
        return

    if data == "github_token_setup":
        if getattr(call.message.chat, "type", "private") != "private":
            _answer(call, "Open a private chat with the bot to connect GitHub.", alert=True)
            return
        set_state(uid, State.SETUP_GITHUB)
        prompt = bot.send_message(uid, "🔑 Send your GitHub Personal Access Token now:")
        user = get_user(uid)
        user["_pending_github_prompt_id"] = prompt.message_id
        save_user(uid, user)
        return

    if data == "github_token_remove_confirm":
        user = get_user(uid)
        user["github_token"]    = None
        user["github_username"] = None
        user["github_accounts"] = []   # multi-account: disconnect clears every saved account
        user["github_active"]   = None
        user.pop("_pending_github_prompt_id", None)
        save_user(uid, user)
        add_history(uid, "Removed saved GitHub token(s)")
        try:
            bot.edit_message_text(
                "✅ *GitHub disconnected.*\n\nAll saved tokens and accounts have been removed from this bot. "
                "You can reconnect anytime with /setgithub or /accounts.",
                uid, call.message.message_id, parse_mode="Markdown", reply_markup=kb_home_only(uid),
            )
        except Exception:
            bot.send_message(uid, "✅ GitHub disconnected. Reconnect anytime with /setgithub or /accounts.",
                             reply_markup=kb_home_only(uid))
        return

    # ── Multi-Account Manager ─────────────────────────────────
    if data == "menu_accounts":
        _render_accounts(uid, call.message.message_id)
        return

    if data == "accadd":
        set_state(uid, State.ACCOUNTS_ADD_TOKEN)
        prompt = bot.send_message(
            uid,
            "➕ *Add a GitHub account*\n\n"
            "Send the Personal Access Token of the account you want to add.\n"
            "It will be verified, encrypted, and become the active account.\n\n"
            "_Send /cancel to abort._",
            parse_mode="Markdown",
        )
        u = get_user(uid)
        u["_pending_accounts_prompt_id"] = prompt.message_id
        save_user(uid, u)
        return

    if data == "accrename":
        u        = get_user(uid)
        accounts = _normalize_accounts(uid, u)
        if not accounts:
            _answer(call, "No saved accounts to rename.", alert=True)
            return
        kb = InlineKeyboardMarkup(row_width=1)
        for i, acct in enumerate(accounts):
            kb.add(InlineKeyboardButton(f"✏️ {acct['label']}", callback_data=f"accrename_{i}"))
        kb.add(InlineKeyboardButton("◀ Back", callback_data="menu_accounts"))
        try:
            bot.edit_message_text(
                "✏️ *Rename account*\n\nWhich account do you want to rename?",
                uid, call.message.message_id, parse_mode="Markdown", reply_markup=kb,
            )
        except Exception:
            pass
        return

    if data.startswith("accrename_"):
        try:
            idx = int(data[len("accrename_"):])
        except ValueError:
            return
        u        = get_user(uid)
        accounts = _normalize_accounts(uid, u)
        if not (0 <= idx < len(accounts)):
            _answer(call, "That account no longer exists.", alert=True)
            _render_accounts(uid, call.message.message_id)
            return
        draft = u.get("draft") or {}
        draft["acc_rename_idx"] = idx
        u["draft"] = draft
        set_state(uid, State.ACCOUNTS_RENAME, draft=draft)
        prompt = bot.send_message(
            uid,
            f"✏️ Send a new name for *{_escape_md(accounts[idx]['label'])}*:\n\n"
            "_1-32 characters. Send /cancel to abort._",
            parse_mode="Markdown",
        )
        u["_pending_accounts_prompt_id"] = prompt.message_id
        save_user(uid, u)
        return

    if data.startswith("accdel_ok_"):
        try:
            idx = int(data[len("accdel_ok_"):])
        except ValueError:
            return
        u        = get_user(uid)
        accounts = _normalize_accounts(uid, u)
        if not (0 <= idx < len(accounts)):
            _answer(call, "That account no longer exists.", alert=True)
            _render_accounts(uid, call.message.message_id)
            return
        removed = accounts.pop(idx)
        u["github_accounts"] = accounts
        note = f"🗑 Removed *{_escape_md(removed['label'])}* from this bot."
        if u.get("github_token") == removed["token"]:
            if accounts:
                nxt = accounts[0]
                _activate_account(uid, u, nxt)
                note += f"\n▶️ Switched the active account to *{_escape_md(nxt['label'])}*."
            else:
                u["github_token"]    = None
                u["github_username"] = None
                u["github_active"]   = None
                set_state(uid, State.IDLE, draft={})
                note += "\n⚠️ That was the last account — GitHub is now disconnected."
            add_history(uid, f"Removed GitHub account {removed['label']} (was active)")
        else:
            add_history(uid, f"Removed GitHub account {removed['label']}")
        save_user(uid, u)
        _render_accounts(uid, call.message.message_id, note=note)
        return

    if data.startswith("accdel_"):
        try:
            idx = int(data[len("accdel_"):])
        except ValueError:
            return
        u        = get_user(uid)
        accounts = _normalize_accounts(uid, u)
        if not (0 <= idx < len(accounts)):
            _answer(call, "That account no longer exists.", alert=True)
            return
        acct   = accounts[idx]
        active = u.get("github_token") == acct["token"]
        kb = InlineKeyboardMarkup(row_width=2)
        kb.add(
            InlineKeyboardButton("🗑 Yes, remove it", callback_data=f"accdel_ok_{idx}"),
            InlineKeyboardButton("◀ Keep it",        callback_data="accdel"),
        )
        warn = (
            "\n\n⚠️ This is the *active* account. Removing it switches to another "
            "saved account, or disconnects GitHub if none remain."
        ) if active else ""
        try:
            bot.edit_message_text(
                f"🗑 *Remove {_escape_md(acct['label'])}?*\n\n"
                "The bot deletes only its saved copy of this token — "
                "your repositories on GitHub are not touched." + warn,
                uid, call.message.message_id, parse_mode="Markdown", reply_markup=kb,
            )
        except Exception:
            pass
        return

    if data == "accdel":
        u        = get_user(uid)
        accounts = _normalize_accounts(uid, u)
        if not accounts:
            _answer(call, "No saved accounts to remove.", alert=True)
            return
        kb = InlineKeyboardMarkup(row_width=1)
        active = u.get("github_token")
        for i, acct in enumerate(accounts):
            mark = "✅" if acct["token"] == active else "▫️"
            kb.add(InlineKeyboardButton(f"🗑 {mark} {acct['label']}", callback_data=f"accdel_{i}"))
        kb.add(InlineKeyboardButton("◀ Back", callback_data="menu_accounts"))
        try:
            bot.edit_message_text(
                "🗑 *Remove account*\n\n"
                "Which account do you want to remove from this bot?\n"
                "_Only the bot's saved copy is removed — nothing happens on GitHub._",
                uid, call.message.message_id, parse_mode="Markdown", reply_markup=kb,
            )
        except Exception:
            pass
        return

    if data.startswith("accsw_"):
        try:
            idx = int(data[len("accsw_"):])
        except ValueError:
            return
        u        = get_user(uid)
        accounts = _normalize_accounts(uid, u)
        if not (0 <= idx < len(accounts)):
            _answer(call, "That account no longer exists.", alert=True)
            _render_accounts(uid, call.message.message_id)
            return
        acct = accounts[idx]
        if u.get("github_token") == acct["token"]:
            _answer(call, f"{acct['label']} is already active.")
            return
        msg = bot.send_message(uid, "⏳ Verifying account ·")
        try:
            info = _animate(uid, msg.message_id,
                            f"Switching to {acct['label']}", gh.get_user, acct["token"])
        except Exception:
            info = None
        if not info:
            try:
                bot.edit_message_text(
                    f"❌ The token for *{_escape_md(acct['label'])}* is invalid or expired.\n\n"
                    "Remove this account and add it again with a fresh token.",
                    uid, msg.message_id, parse_mode="Markdown",
                    reply_markup=InlineKeyboardMarkup().add(
                        InlineKeyboardButton("◀ Back to accounts", callback_data="menu_accounts")),
                )
            except Exception:
                pass
            return
        acct["username"]      = info.get("login", acct.get("username") or "")
        u["github_accounts"]  = accounts
        _activate_account(uid, u, acct)
        add_history(uid, f"Switched GitHub account to {acct['label']}")
        _render_accounts(
            uid, msg.message_id,
            note=(f"✅ Active account is now *{_escape_md(acct['label'])}* — "
                  "every feature now works on this account."),
        )
        return

    if data == "menu_language":
        _show_language_picker(uid, call.message.message_id)
        return

    if data.startswith("lang_"):
        language = data[len("lang_"):]
        if language not in LANGUAGES:
            return
        user = get_user(uid)
        user["language"] = language
        user["language_selected"] = True
        save_user(uid, user)
        try:
            bot.edit_message_text(
                _tr(uid, "language_saved", language=LANGUAGES[language]),
                uid, call.message.message_id,
                reply_markup=kb_home_only(uid),
            )
        except Exception:
            pass
        return

    if data == "menu_timezone":
        _show_timezone_picker(uid, call.message.message_id)
        return

    if data.startswith("tz_"):
        zone_name = _save_timezone(uid, data[len("tz_"):])
        if zone_name is None:
            return
        try:
            bot.edit_message_text(
                _tr(uid, "timezone_saved", zone=zone_name),
                uid, call.message.message_id,
                reply_markup=kb_home_only(uid),
            )
        except Exception:
            pass
        return

    if data.startswith("history_page_"):
        try:
            page = int(data[len("history_page_"):])
        except ValueError:
            return
        text, page, pages = _render_history(uid, page)
        try:
            bot.edit_message_text(
                text, uid, call.message.message_id,
                parse_mode="Markdown",
                reply_markup=kb_history(uid, page, pages),
                disable_web_page_preview=True,
            )
        except Exception:
            pass
        return

    # ── GitHub Extras (issues / PRs / releases / branches) ───
    if gh_actions.handles(data):
        gh_actions.handle(uid, data, call)
        return

    MENU_MAP = {
        "menu_create":     cmd_create_repo,
        "menu_repos":      cmd_list_repos,
        "menu_status":     cmd_status,
        "menu_history":    cmd_history,
        "menu_setup":      cmd_guide,
        "menu_help":       cmd_help,
        "menu_guide":      cmd_guide,
        "menu_models":     cmd_models,
        "menu_support":    cmd_support,
        "menu_ai_suggest": cmd_suggest,
    }

    # ── AI Suggest callbacks ──────────────────────────────────
    if data.startswith("aisug_"):
        u = get_user(uid)
        draft = u.get("draft", {})

        if data in ("aisug_confirm_public", "aisug_confirm_private"):
            if "name" not in draft or "description" not in draft:
                _answer(call, "Session expired — send your project idea again.", alert=True)
                set_state(uid, State.IDLE, draft={})
                return
            draft["private"] = (data == "aisug_confirm_private")
            u["draft"] = draft
            save_user(uid, u)
            # Push the repo
            token       = u.get("github_token")
            owner_info  = gh.get_user(token)
            owner       = owner_info["login"] if owner_info else ""
            repo_name   = draft["name"]
            description = draft["description"]
            is_private  = draft["private"]
            loading_id  = call.message.message_id
            try:
                bot.edit_message_text(
                    f"🚀 *Creating `{repo_name}`…*\n\n⏳ Setting up repo on GitHub…",
                    uid, loading_id, parse_mode="Markdown")
            except Exception:
                pass
            try:
                repo_data = gh.create_repo(token, repo_name, description, private=is_private, auto_init=True)
            except Exception as ex:
                if _is_name_taken_error(ex):
                    set_state(uid, State.CREATE_NAME)   # keep draft intact for retry
                    try:
                        bot.edit_message_text(_name_taken_text(repo_name), uid, loading_id,
                                              parse_mode="Markdown")
                    except Exception:
                        pass
                    return
                _safe_user_error(uid, "Repository creation", ex, loading_id)
                set_state(uid, State.IDLE, draft={})
                return
            # Push README and .gitignore
            readme_ok = gh.push_file(token, owner, repo_name, "README.md", draft.get("readme", ""))
            gi_ok     = gh.push_file(token, owner, repo_name, ".gitignore", draft.get("gitignore", ""))
            vis_icon  = "🔒" if is_private else "🌍"
            pushed    = []
            if readme_ok: pushed.append("README.md")
            if gi_ok:     pushed.append(".gitignore")
            _bump(uid, "repos_created")
            add_history(uid, f"AI-suggested repo created: {repo_name}")
            set_state(uid, State.IDLE, draft={})
            repo_url = repo_data.get("html_url", f"https://github.com/{owner}/{repo_name}")
            result_text = (
                f"✅ *AI Repo Created!*\n\n"
                f"{vis_icon} [{repo_name}]({repo_url})\n"
                f"📝 _{description}_\n\n"
                f"📄 Files pushed: `{'`, `'.join(pushed) or 'none'}`"
            )
            try:
                bot.edit_message_text(result_text, uid, loading_id,
                                      parse_mode="Markdown", reply_markup=kb_home_only(uid))
            except Exception:
                bot.send_message(uid, result_text, parse_mode="Markdown", reply_markup=kb_home_only(uid))
            return

        if data == "aisug_edit_name":
            if "name" not in draft:
                _answer(call, "Session expired — send your project idea again.", alert=True)
                set_state(uid, State.IDLE, draft={})
                return
            bot.edit_message_text(
                f"✏️ *Edit repo name*\n\nCurrent: `{draft.get('name', '')}`\n\nSend the new name:",
                uid, call.message.message_id, parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup().add(
                    InlineKeyboardButton("❌ Cancel", callback_data="menu_home")
                ),
            )
            # Re-use CREATE_NAME to catch the next text; the flag makes that
            # handler return to the AI confirm screen instead of the wizard.
            set_state(uid, State.CREATE_NAME, draft={**draft, "_return_suggest": True})
            return

        if data == "aisug_regenerate":
            # If we have the original idea stored, offer to refine or resend
            stored_idea = draft.get("_idea", "")
            set_state(uid, State.AI_SUGGEST_IDEA)
            try:
                hint = f'\n\n_Previous idea: "{stored_idea}"_\n\nSend the same idea to regenerate, or type a refined version:' if stored_idea else "\n\nSend your project idea:"
                bot.edit_message_text(
                    f"🔄 *Regenerate*{hint}",
                    uid, call.message.message_id, parse_mode="Markdown",
                    reply_markup=InlineKeyboardMarkup().add(
                        InlineKeyboardButton("❌ Cancel", callback_data="menu_home")
                    ),
                )
            except Exception:
                bot.send_message(uid, "Send your project idea:")
            return
        return  # unknown aisug_ sub-command

    # ── Admin Panel ──────────────────────────────────────────
    if data == "admin_panel":
        if not is_admin(uid):
            _answer(call, "🚫 Access denied.", alert=True)
            return
        cmd_admin(call.message, edit_message_id=call.message.message_id)
        return

    if data == "admin_stats":
        if not is_admin(uid):
            return
        with _db_lock:
            all_users = list(_db.items())
        recent = sorted(all_users, key=lambda kv: kv[1].get("created_at", ""), reverse=True)[:5]
        most_active = sorted(
            all_users,
            key=lambda kv: kv[1].get("repos_created", 0) + kv[1].get("archives_uploaded", 0),
            reverse=True,
        )[:5]

        def _fmt(rows):
            out = []
            for raw_uid, u in rows:
                repos = u.get("repos_created", 0)
                arch  = u.get("archives_uploaded", 0)
                out.append(f"  • `{log.mask_user_id(raw_uid)}` — {repos} repo(s), {arch} archive(s)")
            return "\n".join(out) if out else "  _none yet_"

        text = (
            "📊 *Bot Stats — Detail*\n"
            "━━━━━━━━━━━━━━━━━━━━\n\n"
            "🆕 *Most recently joined:*\n" + _fmt(recent) + "\n\n"
            "🔥 *Most active (repos + archives):*\n" + _fmt(most_active) + "\n\n"
            "_Only usage counts are shown — no tokens, keys, or file/repo content._"
        )
        try:
            bot.edit_message_text(text, uid, call.message.message_id,
                                  parse_mode="Markdown", reply_markup=kb_admin_back())
        except Exception:
            bot.send_message(uid, text, parse_mode="Markdown", reply_markup=kb_admin_back())
        return

    if data == "admin_analytics":
        if not is_admin(uid):
            return
        text = _admin_analytics_text()
        try:
            bot.edit_message_text(text, uid, call.message.message_id,
                                  parse_mode="Markdown", reply_markup=kb_admin_back())
        except Exception:
            bot.send_message(uid, text, parse_mode="Markdown", reply_markup=kb_admin_back())
        return

    if data == "admin_health":
        if not is_admin(uid):
            return
        uptime = int(_time.time() - _APP_STARTED_AT)
        db_state = "✅ Encrypted and available" if security.is_enabled() else "❌ Encryption unavailable"
        text = (
            "🩺 *System Health*\n"
            "━━━━━━━━━━━━━━━━━━━━\n\n"
            "🤖 Telegram bot: *Online*\n"
            f"🔐 User database: *{db_state}*\n"
            f"👥 Loaded users: *{len(_db)}*\n"
            f"⏱ Uptime: `{uptime // 3600}h {(uptime % 3600) // 60}m`\n"
            f"🧾 Log level: `{config.LOG_LEVEL}`\n\n"
            "_Health information never includes tokens, keys, file contents, or error details._"
        )
        try:
            bot.edit_message_text(text, uid, call.message.message_id,
                                  parse_mode="Markdown", reply_markup=kb_admin_back())
        except Exception:
            bot.send_message(uid, text, parse_mode="Markdown", reply_markup=kb_admin_back())
        return

    if data == "admin_noop":
        return

    if data.startswith("admin_users_"):
        if not is_admin(uid):
            return
        page = int(data.split("_")[-1])
        try:
            bot.edit_message_text(
                f"👥 *All Users* — Page {page + 1}\n\n"
                "_Tap a user to manage. Sensitive data is never shown._",
                uid, call.message.message_id,
                parse_mode="Markdown",
                reply_markup=kb_admin_users(page),
            )
        except Exception:
            bot.send_message(uid,
                f"👥 *All Users* — Page {page + 1}",
                parse_mode="Markdown",
                reply_markup=kb_admin_users(page))
        return

    if data.startswith("admin_view_"):
        if not is_admin(uid):
            return
        target_parts = data[len("admin_view_"):].split("_", 1)
        target_uid = int(target_parts[0])
        return_page = int(target_parts[1]) if len(target_parts) > 1 else 0
        s = _public_user_stats(target_uid)
        badge = "🚫 BANNED" if s["banned"] else ("👑 Admin" if s["is_admin"] else "👤 User")
        target = get_user(target_uid)
        user_actions = sum(s.get(key, 0) for key in ("repos_created", "repos_deleted", "repos_forked", "archives_up"))
        activity = _admin_bar(user_actions, max(10, user_actions))
        github_status = "✅ Connected" if target.get("github_token") else "⚪ Not connected"
        ai_status = "✅ Configured" if target.get("ai_provider") and target.get("ai_key") else "⚪ Not configured"
        text = (
            f"👤 *User Profile*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"🆔 ID: `{s['uid']}`\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"📦 Repos created:  *{s['repos_created']}*\n"
            f"🗑 Repos deleted:  *{s['repos_deleted']}*\n"
            f"🍴 Repos forked:   *{s['repos_forked']}*\n"
            f"📦 Archives up:    *{s['archives_up']}*\n"
            f"📈 Activity: `{activity}` *{user_actions} actions*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"🏷 Status: *{badge}*\n"
            f"📅 Joined: `{s['created_at']}`\n\n"
            f"🔑 GitHub: {github_status}\n"
            f"🤖 AI: {ai_status}\n\n"
            f"_Only connection state is shown. Tokens, keys, history, and content are never shown._"
        )
        try:
            bot.edit_message_text(text, uid, call.message.message_id,
                                  parse_mode="Markdown",
                                  reply_markup=kb_admin_user(target_uid, viewer_uid=uid,
                                                             return_page=return_page))
        except Exception:
            bot.send_message(uid, text, parse_mode="Markdown",
                             reply_markup=kb_admin_user(target_uid, viewer_uid=uid,
                                                        return_page=return_page))
        return

    if data.startswith("admin_ban_"):
        if not is_admin(uid):
            return
        target_parts = data[len("admin_ban_"):].split("_", 1)
        target_uid = int(target_parts[0])
        return_page = int(target_parts[1]) if len(target_parts) > 1 else 0
        if target_uid in ADMIN_IDS:
            _answer(call, "🚫 Cannot ban an admin.", alert=True)
            return
        bot.edit_message_text(
            f"Choose a ban duration for `{target_uid}`:",
            uid, call.message.message_id,
            parse_mode="Markdown",
            reply_markup=kb_admin_ban_durations(target_uid, return_page),
        )
        return

    if data.startswith("admin_banfor_"):
        if not is_admin(uid):
            return
        try:
            parts = data.split("_")
            if len(parts) not in (4, 5):
                raise ValueError("Malformed ban callback")
            duration_code = parts[2]
            target_uid = int(parts[3])
            return_page = int(parts[4]) if len(parts) == 5 else 0
            duration_seconds, duration_label = _BAN_DURATIONS[duration_code]
        except (ValueError, KeyError):
            _answer(call, "Invalid ban duration.", alert=True)
            return
        if target_uid in ADMIN_IDS:
            _answer(call, "🚫 Cannot ban an admin.", alert=True)
            return
        ban_user(target_uid, duration_seconds)
        try:
            bot.send_message(target_uid,
                f"🚫 *Your account has been suspended {duration_label}.*"
                + (" You may contact support if you believe this is a mistake." if duration_seconds else ""),
                parse_mode="Markdown")
        except Exception:
            pass
        _answer(call, f"✅ User {target_uid} banned {duration_label}.", alert=True)
        # Refresh user view
        call.data = f"admin_view_{target_uid}_{return_page}"
        handle_callback(call)
        return

    if data.startswith("admin_unban_"):
        if not is_admin(uid):
            return
        target_parts = data[len("admin_unban_"):].split("_", 1)
        target_uid = int(target_parts[0])
        return_page = int(target_parts[1]) if len(target_parts) > 1 else 0
        unban_user(target_uid)
        try:
            bot.send_message(target_uid,
                "✅ *Your account has been reinstated.*",
                parse_mode="Markdown")
        except Exception:
            pass
        _answer(call, f"✅ User {target_uid} unbanned.", alert=True)
        call.data = f"admin_view_{target_uid}_{return_page}"
        handle_callback(call)
        return

    if data.startswith("admin_promote_"):
        if not is_admin(uid):
            return
        if uid != ADMIN_CHAT_ID:
            _answer(call, "🚫 Only the primary admin can grant admin access.", alert=True)
            return
        target_parts = data[len("admin_promote_"):].split("_", 1)
        target_uid = int(target_parts[0])
        return_page = int(target_parts[1]) if len(target_parts) > 1 else 0
        promote_admin(target_uid)
        try:
            bot.send_message(target_uid,
                "👑 *You have been granted admin access.*",
                parse_mode="Markdown")
        except Exception:
            pass
        _answer(call, f"✅ User {target_uid} promoted.", alert=True)
        call.data = f"admin_view_{target_uid}_{return_page}"
        handle_callback(call)
        return

    if data.startswith("admin_demote_"):
        if not is_admin(uid):
            return
        if uid != ADMIN_CHAT_ID:
            _answer(call, "🚫 Only the primary admin can revoke admin access.", alert=True)
            return
        target_parts = data[len("admin_demote_"):].split("_", 1)
        target_uid = int(target_parts[0])
        return_page = int(target_parts[1]) if len(target_parts) > 1 else 0
        if target_uid == ADMIN_CHAT_ID:
            _answer(call, "🚫 Cannot demote the primary admin.", alert=True)
            return
        demote_admin(target_uid)
        try:
            bot.send_message(target_uid,
                "ℹ️ *Your admin access has been removed.*",
                parse_mode="Markdown")
        except Exception:
            pass
        _answer(call, f"✅ User {target_uid} demoted.", alert=True)
        call.data = f"admin_view_{target_uid}_{return_page}"
        handle_callback(call)
        return

    if data == "admin_broadcast":
        if not is_admin(uid):
            return
        bot.send_message(uid,
            "📢 *Broadcast*\n\nUsage: `/broadcast YOUR MESSAGE`",
            parse_mode="Markdown",
            reply_markup=kb_admin_back())
        return

    if data == "admin_tickets":
        if not is_admin(uid):
            return
        open_count = sum(1 for u in _db.values() if u.get("pending_tickets"))
        header = (
            "🎫 *Support Tickets*\n\n"
            f"Open tickets: *{open_count}*\n"
            "Tap a user below to read their message and reply.\n\n"
            "_Only that user's ticket text is shown — no other account data._"
        )
        try:
            bot.edit_message_text(header, uid, call.message.message_id,
                                  parse_mode="Markdown", reply_markup=kb_admin_tickets())
        except Exception:
            bot.send_message(uid, header, parse_mode="Markdown",
                             reply_markup=kb_admin_tickets())
        return

    if data.startswith("admin_ticket_view_"):
        if not is_admin(uid):
            return
        target_uid = int(data[len("admin_ticket_view_"):])
        tu = get_user(target_uid)
        tickets = tu.get("pending_tickets", [])
        if not tickets:
            _answer(call, "✅ This ticket was already resolved.", alert=True)
            call.data = "admin_tickets"
            handle_callback(call)
            return
        lines = [
            f"🎫 *Ticket from* `{target_uid}`",
            "━━━━━━━━━━━━━━━━━━",
        ]
        for t in tickets[-10:]:
            when = (t.get("created_at") or "")[:16].replace("T", " ")
            lines.append(f"🕐 `{when}`\n{_escape_md(t.get('text', ''))}")
        lines.append("━━━━━━━━━━━━━━━━━━")
        lines.append("_⚠️ Only this user's own ticket text is shown — no tokens, keys, or other account data._")
        text = "\n\n".join(lines)
        try:
            bot.edit_message_text(text, uid, call.message.message_id,
                                  parse_mode="Markdown",
                                  reply_markup=kb_admin_ticket_detail(target_uid))
        except Exception:
            bot.send_message(uid, text, parse_mode="Markdown",
                             reply_markup=kb_admin_ticket_detail(target_uid))
        return

    if data.startswith("admin_ticket_reply_"):
        if not is_admin(uid):
            return
        target_uid = int(data[len("admin_ticket_reply_"):])
        au = get_user(uid)
        au["_pending_reply_target"] = target_uid
        save_user(uid, au)
        set_state(uid, State.ADMIN_TICKET_REPLY)
        bot.send_message(uid,
            f"💬 Type your reply to `{target_uid}` now, or /cancel.",
            parse_mode="Markdown")
        return

    if data.startswith("admin_ticket_dismiss_"):
        if not is_admin(uid):
            return
        target_uid = int(data[len("admin_ticket_dismiss_"):])
        tu = get_user(target_uid)
        tu["pending_tickets"] = []
        save_user(target_uid, tu)
        _answer(call, "🗑 Ticket dismissed (no reply sent).", alert=True)
        call.data = "admin_tickets"
        handle_callback(call)
        return

    # ── Support menu shortcut ────────────────────────────────
    if data == "menu_support":
        kb_sp = InlineKeyboardMarkup(row_width=2)
        kb_sp.add(InlineKeyboardButton("\U0001f3e0 Home", callback_data="menu_home"))
        bot.send_message(uid,
            "🎫 *Support*\n\n"
            "Send a message to the admin team:\n\n"
            "`/support YOUR MESSAGE`\n\n"
            "Example: `/support I have a problem with my GitHub token`",
            parse_mode="Markdown",
            reply_markup=kb_sp)
        return

    # ── Edit Repo button ─────────────────────────────────────
    if data == "menu_edit_repo":
        u = get_user(uid)
        if not u.get("github_token"):
            _send_github_token_guide(uid)
            return
        nav_push(uid, "menu_edit_repo", "Edit Repository")
        _show_edit_repo_picker(uid, edit_msg_id=call.message.message_id)
        return

    # ── Replace Repo Contents (clear files, keep the repo) ───
    if data == "menu_replace_repo":
        u = get_user(uid)
        if not u.get("github_token"):
            _send_github_token_guide(uid)
            return
        nav_push(uid, "menu_replace_repo", "Replace Repo Contents")
        _show_replace_picker(uid, edit_msg_id=call.message.message_id)
        return

    # ── Upload to Repo (send files/folders into an existing repo) ─
    if data == "menu_upload_files":
        u = get_user(uid)
        if not u.get("github_token"):
            _send_github_token_guide(uid)
            return
        nav_push(uid, "menu_upload_files", "Upload to Repo")
        _show_upload_picker(uid, edit_msg_id=call.message.message_id)
        return

    if data == "up_noop":
        return

    if data.startswith("up_page_"):
        try:
            page = int(data[len("up_page_"):])
        except ValueError:
            return
        u     = get_user(uid)
        repos = u["draft"].get("upload_repos_cache", [])
        if not repos:
            _show_upload_picker(uid, edit_msg_id=call.message.message_id, page=page)
            return
        u["draft"]["upload_page"] = page
        save_user(uid, u)
        set_state(uid, State.UPLOAD_PICK, draft=u["draft"])
        try:
            bot.edit_message_text(
                "📤 *Upload to Repo*\n\n"
                "Select the repository to upload into.\n"
                "🌍 Public · 🔒 Private · Total: *" + str(len(repos)) + "*\n\n"
                "_Next: pick the destination, then ➕ Add or 🔄 Replace mode._",
                uid, call.message.message_id,
                reply_markup=kb_upload_picker(repos, page))
        except Exception:
            bot.send_message(
                uid,
                "📤 *Upload to Repo*\n\nSelect the repository to upload into.",
                reply_markup=kb_upload_picker(repos, page))
        return

    if data.startswith("up_pick_"):
        u     = get_user(uid)
        repos = u["draft"].get("upload_repos_cache", [])
        try:
            idx = int(data[len("up_pick_"):])
        except ValueError:
            return
        if idx < 0 or idx >= len(repos):
            _show_upload_picker(uid, edit_msg_id=call.message.message_id)
            return
        u["draft"]["upload_target"] = repos[idx]["name"]
        u["draft"]["upload_page"]   = idx // _UPLOAD_PAGE_SIZE
        u["draft"].pop("upload_folder", None)
        u["draft"].pop("upload_replace", None)
        u["draft"].pop("upload_files", None)
        u["draft"].pop("upload_status_msg_id", None)
        save_user(uid, u)
        _show_upload_path_step(uid, call.message.message_id)
        return

    if data == "up_root":
        u = get_user(uid)
        if not u["draft"].get("upload_target"):
            _show_upload_picker(uid, edit_msg_id=call.message.message_id)
            return
        u["draft"]["upload_folder"] = ""
        save_user(uid, u)
        _show_upload_mode_step(uid, call.message.message_id)
        return

    # ── Upload to Repo: Add vs Replace mode choice ────────────
    if data in ("up_mode_add", "up_mode_replace"):
        u = get_user(uid)
        if not u["draft"].get("upload_target"):
            _show_upload_picker(uid, edit_msg_id=call.message.message_id)
            return
        u["draft"]["upload_replace"] = (data == "up_mode_replace")
        save_user(uid, u)
        _start_upload_collect(uid, call.message.message_id)
        return

    if data == "up_back_dest":
        u = get_user(uid)
        if not u["draft"].get("upload_target"):
            _show_upload_picker(uid, edit_msg_id=call.message.message_id)
            return
        _show_upload_path_step(uid, call.message.message_id)
        return

    if data == "up_path_type":
        u = get_user(uid)
        if not u["draft"].get("upload_target"):
            _show_upload_picker(uid, edit_msg_id=call.message.message_id)
            return
        set_state(uid, State.UPLOAD_PATH, draft=u["draft"])
        try:
            bot.edit_message_text(
                "✍️ *Type the destination folder*\n\n"
                "Examples:\n"
                "• `docs`\n"
                "• `assets/images`\n"
                "• `src/components`\n\n"
                "_The folder is created automatically if it doesn't exist. "
                "Send `.` or `/` for the repo root._",
                uid, call.message.message_id, parse_mode="Markdown")
        except Exception:
            bot.send_message(
                uid,
                "✍️ *Type the destination folder*\n\n"
                "Examples: `docs`, `assets/images`, `src/components`\n\n"
                "_Send `.` or `/` for the repo root._",
                parse_mode="Markdown")
        return

    if data == "up_done":
        u = get_user(uid)
        if not u["draft"].get("upload_files"):
            _answer(call, "No files queued yet — send some first.", alert=True)
            return
        set_state(uid, State.UPLOAD_COLLECT, draft=u["draft"])
        _execute_upload_files(uid, call.message.message_id)
        return

    if data == "up_reset":
        u = get_user(uid)
        u["draft"]["upload_files"]         = []
        u["draft"]["upload_status_msg_id"] = None
        save_user(uid, u)
        set_state(uid, State.UPLOAD_COLLECT, draft=u["draft"])
        _start_upload_collect(uid, call.message.message_id)
        return

    # ── Security gate: direct upload (Upload to Repo) ─────────
    if data == "sec_warn_upload_proceed":
        u = get_user(uid)
        files = list(u["draft"].get("upload_files", []))
        u["draft"]["_security_upload_approval"] = {
            "archive":    True,
            "fingerprint": _security_file_fingerprint(files),
        }
        save_user(uid, u)
        try:
            _bot_notify(uid, call.message.message_id,
                        "⚠️ Security warning acknowledged — starting upload ···")
        except Exception:
            pass
        _execute_upload_files(uid, call.message.message_id)
        return

    if data == "sec_warn_upload_edit":
        u = get_user(uid)
        files   = u["draft"].get("upload_files", [])
        flagged = {item["path"] for item in scan_files_for_secrets(files).get("flagged_files", [])}
        u["draft"]["upload_files"] = [f for f in files if f.get("path") not in flagged]
        u["draft"].pop("_security_upload_approval", None)
        u["draft"].pop("upload_status_msg_id", None)
        save_user(uid, u)
        remaining = len(u["draft"]["upload_files"])
        try:
            bot.edit_message_text(
                f"✂️ Removed *{len(flagged)}* flagged file(s). *{remaining}* file(s) remain queued.\n\n"
                "_Keep sending corrected files, or tap ✅ Done to upload._",
                uid, call.message.message_id, reply_markup=kb_upload_collect(remaining))
        except Exception:
            bot.send_message(
                uid,
                f"✂️ Removed flagged files — *{remaining}* remain queued. Send more or tap ✅ Done.",
                parse_mode="Markdown", reply_markup=kb_upload_collect(remaining))
        set_state(uid, State.UPLOAD_COLLECT, draft=u["draft"])
        return

    # ── Live Preview (GitHub Pages / instant HTML preview) ────
    if data == "menu_live_preview":
        u = get_user(uid)
        if not u.get("github_token"):
            _send_github_token_guide(uid)
            return
        nav_push(uid, "menu_live_preview", "Live Preview")
        _show_preview_picker(uid, edit_msg_id=call.message.message_id)
        return

    if data == "lp_open":
        u = get_user(uid)
        if not u.get("github_token"):
            _send_github_token_guide(uid)
            return
        if u["draft"].get("preview_target"):
            _show_live_preview(uid, call.message.message_id)
        else:
            nav_push(uid, "menu_live_preview", "Live Preview")
            _show_preview_picker(uid, edit_msg_id=call.message.message_id)
        return

    if data == "lp_noop":
        return

    if data.startswith("lp_page_"):
        try:
            page = int(data[len("lp_page_"):])
        except ValueError:
            return
        u     = get_user(uid)
        repos = u["draft"].get("preview_repos_cache", [])
        if not repos:
            _show_preview_picker(uid, edit_msg_id=call.message.message_id, page=page)
            return
        u["draft"]["preview_page"] = page
        save_user(uid, u)
        set_state(uid, State.PREVIEW_PICK, draft=u["draft"])
        try:
            bot.edit_message_text(
                "👁 *Live Preview*\n\n"
                "Select the repository to preview as a live website.\n"
                "🌍 Public · 🔒 Private · Total: *" + str(len(repos)) + "*\n\n"
                "_Shows GitHub Pages status and an instant HTML preview for repos "
                "that contain `index.html` or any `.html` page._",
                uid, call.message.message_id,
                reply_markup=kb_preview_picker(repos, page))
        except Exception:
            bot.send_message(
                uid,
                "👁 *Live Preview*\n\nSelect the repository to preview.",
                parse_mode="Markdown", reply_markup=kb_preview_picker(repos, page))
        return

    if data.startswith("lp_pick_"):
        u     = get_user(uid)
        repos = u["draft"].get("preview_repos_cache", [])
        try:
            idx = int(data[len("lp_pick_"):])
        except ValueError:
            return
        if idx < 0 or idx >= len(repos):
            _show_preview_picker(uid, edit_msg_id=call.message.message_id)
            return
        u["draft"]["preview_target"] = repos[idx]["name"]
        u["draft"]["preview_page"]   = idx // _PREVIEW_PAGE_SIZE
        u["draft"].pop("preview_owner", None)
        u["draft"].pop("preview_branch", None)
        u["draft"].pop("preview_html", None)
        save_user(uid, u)
        _show_live_preview(uid, call.message.message_id)
        return

    if data == "lp_enable":
        _lp_enable_pages(uid, call.message.message_id)
        return

    if data == "er_preview":
        # 👁 Live Preview from the Edit Repo menu — preview the repo
        # currently open there.
        u    = get_user(uid)
        repo = u["draft"].get("er_repo", "")
        if not repo:
            nav_push(uid, "menu_live_preview", "Live Preview")
            _show_preview_picker(uid, edit_msg_id=call.message.message_id)
            return
        u["draft"]["preview_target"] = repo
        u["draft"]["preview_owner"]  = u["draft"].get("er_owner") or u.get("github_username")
        u["draft"].pop("preview_branch", None)
        u["draft"].pop("preview_html", None)
        save_user(uid, u)
        _show_live_preview(uid, call.message.message_id)
        return

    if data == "rr_noop":
        return

    if data.startswith("rr_page_"):
        try:
            page = int(data[len("rr_page_"):])
        except ValueError:
            return
        u     = get_user(uid)
        repos = u["draft"].get("replace_repos_cache", [])
        if not repos:
            _show_replace_picker(uid, edit_msg_id=call.message.message_id, page=page)
            return
        u["draft"]["replace_page"] = page
        save_user(uid, u)
        set_state(uid, State.REPLACE_PICK, draft=u["draft"])
        total = len(repos)
        try:
            bot.edit_message_text(
                "♻️ *Replace Repo Contents*\n\n"
                "Select the repository whose files you want to wipe.\n"
                "🌍 Public · 🔒 Private · Total: *" + str(total) + "*\n\n"
                "_The repo itself is NOT deleted — stars, settings, URL and history "
                "stay. Only the files and folders on the default branch are removed._",
                uid, call.message.message_id,
                reply_markup=kb_replace_picker(repos, page),
            )
        except Exception:
            pass
        return

    if data.startswith("rr_pick_"):
        u     = get_user(uid)
        repos = u["draft"].get("replace_repos_cache", [])
        try:
            idx = int(data[len("rr_pick_"):])
        except ValueError:
            return
        if idx < 0 or idx >= len(repos):
            _show_replace_picker(uid, edit_msg_id=call.message.message_id)
            return
        u["draft"]["replace_target"] = repos[idx]["name"]
        u["draft"]["replace_page"]   = idx // _REPLACE_PAGE_SIZE
        save_user(uid, u)
        _show_replace_menu(uid, call.message.message_id)
        return

    if data == "rr_repomenu":
        _show_replace_menu(uid, call.message.message_id)
        return

    if data == "rr_clear_confirm":
        u = get_user(uid)
        if not u["draft"].get("replace_target"):
            _show_replace_picker(uid, edit_msg_id=call.message.message_id)
            return
        _show_replace_clear_warning(uid, call.message.message_id)
        return

    if data == "rr_clear_cancel":
        _show_replace_menu(uid, call.message.message_id)
        return

    if data == "rr_replace_ask":
        _ask_replace_archive(uid, call.message.message_id)
        return

    if data == "rr_replace_confirm":
        _show_replace_confirm(uid, call.message.message_id)
        return

    if data == "rr_replace_go":
        u = get_user(uid)
        if not u["draft"].get("replace_target") or not u["draft"].get("replace_files"):
            _show_replace_picker(uid, edit_msg_id=call.message.message_id)
            return
        try:
            _bot_notify(uid, call.message.message_id, "⏳ Starting replace ···")
        except Exception:
            pass
        _execute_replace_upload(uid, call.message.message_id)
        return

    if data == "rr_replace_cancel":
        u = get_user(uid)
        u["draft"] = {}
        save_user(uid, u)
        set_state(uid, State.IDLE)
        try:
            bot.edit_message_text(
                "❎ *Replace cancelled.* Your repository was not touched.",
                uid, call.message.message_id, parse_mode="Markdown",
                reply_markup=kb_main(uid),
            )
        except Exception:
            bot.send_message(uid, "❎ Replace cancelled.", reply_markup=kb_main(uid))
        return

    # ── Delete Repo button ───────────────────────────────────
    if data == "menu_delete":
        u = get_user(uid)
        if not u.get("github_token"):
            _send_github_token_guide(uid)
            return
        nav_push(uid, "menu_delete", "Delete Repository")
        _show_delete_picker(uid, edit_msg_id=call.message.message_id)
        return

    # ── Download Repo button ─────────────────────────────────
    if data == "menu_download":
        u = get_user(uid)
        if not u.get("github_token"):
            _send_github_token_guide(uid)
            return
        nav_push(uid, "menu_download", "Download Repository")
        _show_download_picker(uid, edit_msg_id=call.message.message_id)
        return

    # ── Fork Repo button ─────────────────────────────────────
    if data == "menu_import":
        u = get_user(uid)
        if not u.get("github_token"):
            _send_github_token_guide(uid)
            return
        set_state(uid, State.FORK_MODE_PICK)
        nav_push(uid, "menu_import", "Fork Repository")
        try:
            bot.edit_message_text(
                "📥 *Fork Repository*\n\nHow many repositories would you like to fork?",
                uid, call.message.message_id, reply_markup=kb_fork_mode())
        except Exception:
            bot.send_message(uid, "📥 *Fork Repository*\n\nHow many?", reply_markup=kb_fork_mode())
        return

    # ── Fork mode selection ──────────────────────────────────
    if data == "fork_mode_single":
        set_state(uid, State.IMPORT_URL)
        nav_push(uid, "menu_import", "Fork Mode")
        try:
            bot.edit_message_text(
                "🔗 *Fork — Single Mode*\n\nSend the GitHub repository URL:\n\nExample:\n`https://github.com/owner/repo`",
                uid, call.message.message_id,
                reply_markup=kb_fork_single_prompt())
        except Exception:
            bot.send_message(uid, "🔗 *Fork — Single Mode*\n\nSend the GitHub repo URL:\n\nExample:\n`https://github.com/owner/repo`",
                             reply_markup=kb_fork_single_prompt())
        return

    if data == "fork_mode_multi":
        u = get_user(uid)
        u["draft"]["fork_multi_urls"] = []
        save_user(uid, u)
        set_state(uid, State.FORK_MULTI_URLS)
        nav_push(uid, "menu_import", "Fork Mode")
        try:
            bot.edit_message_text(
                "🔗🔗 *Fork — Multiple Mode*\n\nSend GitHub repo URLs — one per line:\n\n"
                "`https://github.com/owner/repo1`\n`https://github.com/owner/repo2`\n\n"
                "_Tap *Fork All* when done._",
                uid, call.message.message_id,
                reply_markup=kb_fork_multi_collecting())
        except Exception:
            bot.send_message(uid,
                "🔗🔗 *Fork — Multiple Mode*\n\nSend GitHub repo URLs — one per line:\n\n"
                "`https://github.com/owner/repo1`\n`https://github.com/owner/repo2`\n\n"
                "_Tap *Fork All* when done._",
                reply_markup=kb_fork_multi_collecting())
        return

    if data == "fork_multi_execute":
        u    = get_user(uid)
        urls = u["draft"].get("fork_multi_urls", [])
        if not urls:
            bot.send_message(uid, "❌ No URLs queued.")
            return
        try:
            bot.edit_message_text(f"⏳ Forking {len(urls)} repositories ···", uid, call.message.message_id)
        except Exception:
            pass
        _execute_fork_multi(uid, call.message.message_id)
        return

    # ── Archive Upload mode picker ───────────────────────────
    if data == "files_archive_upload":
        u = get_user(uid)
        if not u.get("github_token"):
            _send_github_token_guide(uid)
            return
        nav_push(uid, "files_archive_upload", "Archive Upload Mode")
        try:
            bot.edit_message_text(
                "📦 *Archive Upload*\n\n"
                "How would you like to upload?\n\n"
                "📁 *Single Archive* — one archive → one repository\n"
                "📚 *Multiple Archives* — up to 100 archives → separate repositories",
                uid, call.message.message_id,
                reply_markup=kb_archive_mode(),
            )
        except Exception:
            bot.send_message(uid,
                "📦 *Archive Upload*\n\nChoose mode:",
                reply_markup=kb_archive_mode())
        return

    # ── Archive Single mode → ask AI? ────────────────────────
    if data == "arch_mode_single":
        nav_push(uid, "files_archive_upload", "Archive Mode")
        try:
            bot.edit_message_text(
                "📁 *Single Archive Upload*\n\n"
                "🤖 *Do you want to use AI assistance?*\n\n"
                "AI can analyze your archive and suggest a repository name, "
                "description, and README — or you can skip it and enter "
                "everything yourself.",
                uid, call.message.message_id,
                reply_markup=kb_archive_use_ai("single"),
            )
        except Exception:
            bot.send_message(uid, "🤖 Do you want to use AI assistance for this upload?",
                             reply_markup=kb_archive_use_ai("single"))
        return

    # ── Archive Multiple mode → ask AI? ──────────────────────
    if data == "arch_mode_multi":
        nav_push(uid, "files_archive_upload", "Archive Mode")
        try:
            bot.edit_message_text(
                "📚 *Multiple Archive Upload* _(up to 100)_\n\n"
                "🤖 *Do you want to use AI assistance?*\n\n"
                "AI can analyze each archive and suggest a name, description, "
                "and README for it — or you can skip it and enter everything "
                "yourself for every archive.",
                uid, call.message.message_id,
                reply_markup=kb_archive_use_ai("multi"),
            )
        except Exception:
            bot.send_message(uid, "🤖 Do you want to use AI assistance for this upload?",
                             reply_markup=kb_archive_use_ai("multi"))
        return

    # ── AI Yes/No confirmation → start the actual upload ─────
    if data.startswith("arch_ai_confirm:"):
        _, target, choice = data.split(":", 2)
        use_ai = (choice == "yes")

        if use_ai:
            u = get_user(uid)
            if not u.get("ai_provider") or not u.get("ai_key"):
                _answer(call, "⚠️ Set an AI provider first (/setai), or choose 'No, skip AI'.", alert=True)
                return

        if target == "single":
            set_state(uid, State.ARCHIVE_UPLOAD)
            u = get_user(uid)
            u["draft"]["arch_ai_mode"] = use_ai
            save_user(uid, u)
            nav_push(uid, "files_archive_upload", "Archive Upload")
            header = (
                "🤖 *AI-Assisted Single Archive Upload*\n\n"
                "_AI will analyze the contents and suggest repository names & descriptions._"
                if use_ai else
                "📁 *Single Archive Upload* _(no AI)_\n\n"
                "You'll be asked to enter the name, description, and README yourself."
            )
            text = (
                f"{header}\n\n"
                "Send your archive file now.\n\n"
                "✅ Supported: ZIP · tar.gz · tgz · tar.bz2 · tar.xz · RAR"
            )
            try:
                bot.edit_message_text(text, uid, call.message.message_id,
                                       reply_markup=kb_archive_single_prompt())
            except Exception:
                bot.send_message(uid, text, reply_markup=kb_archive_single_prompt())
            return

        else:  # target == "multi"
            set_state(uid, State.ARCHIVE_MULTI_COLLECT)
            u = get_user(uid)
            u["draft"]["multi_queue"]   = []
            u["draft"]["multi_index"]   = 0
            u["draft"]["multi_ai_mode"] = use_ai
            save_user(uid, u)
            nav_push(uid, "files_archive_upload", "Archive Upload")
            header = (
                "🤖 *AI-Assisted Multiple Archive Upload* _(up to 100)_\n\n"
                "_AI will analyze each archive and suggest a name & description separately._"
                if use_ai else
                "📚 *Multiple Archive Upload* _(no AI, up to 100)_\n\n"
                "You'll be asked to enter the name, description, and README "
                "yourself for each archive."
            )
            text = (
                f"{header}\n\n"
                "Send your archive files one by one.\n\n"
                "✅ Supported: ZIP · tar.gz · tgz · tar.bz2 · tar.xz · RAR\n\n"
                "Tap ✅ *Done* when all archives are uploaded."
            )
            try:
                bot.edit_message_text(text, uid, call.message.message_id,
                                       reply_markup=kb_archive_multi_collecting(0))
            except Exception:
                bot.send_message(uid, text, reply_markup=kb_archive_multi_collecting(0))
            return


    # ── Single Archive AI name selection ────────────────────
    if data.startswith("arch_ai_name_"):
        idx = int(data.split("_")[-1])
        u   = get_user(uid)
        names = u["draft"].get("ai_suggested_names", [])
        if idx < len(names):
            name = names[idx]
            u["draft"]["name"] = name
            descs = u["draft"].get("ai_suggested_descs", [])
            u["draft"]["ai_stage"] = "desc"
            save_user(uid, u)
            set_state(uid, State.ARCHIVE_AI_SUGGEST)
            if descs:
                try:
                    bot.edit_message_text(
                        f"✅ *Name selected:* `{name}`\n\n"
                        "━━━━━━━━━━━━━━━━━━━━\n\n"
                        "🤖 *AI Description Suggestions*\n\n"
                        "Tap a number to preview it in full, then confirm. "
                        "Or type your own below.",
                        uid, call.message.message_id,
                        reply_markup=kb_archive_ai_desc(descs, name),
                    )
                except Exception:
                    bot.send_message(uid,
                        f"✅ *Name:* `{name}`\n\n🤖 Choose a description:",
                        reply_markup=kb_archive_ai_desc(descs, name))
            else:
                set_state(uid, State.ARCHIVE_DESC)
                bot.send_message(uid, f"✅ *Name:* `{name}`\n\n📝 Type a description (or `-` to skip):")
        return

    if data == "arch_ai_custom":
        set_state(uid, State.ARCHIVE_AI_CUSTOM)
        try:
            bot.edit_message_text(
                "✏️ *Custom Repository Name*\n\n"
                "Type your repository name:\n\n"
                "_Lowercase · hyphens · no spaces_",
                uid, call.message.message_id,
            )
        except Exception:
            bot.send_message(uid, "✏️ Type your repository name:")
        return

    if data == "arch_ai_regen":
        u = get_user(uid)
        files  = u["draft"].get("archive_files", [])
        fname  = u["draft"].get("archive_filename", "archive")
        msg    = bot.send_message(uid, "🔄 Regenerating suggestions ···")
        names, descs = _ai_suggest_names_and_descs(u, files, fname)
        _store_ai_suggestions(u, names, descs)
        save_user(uid, u)
        try:
            bot.edit_message_text(
                "🤖 *AI Repository Name Suggestions*\n\nChoose a name or type your own:",
                uid, msg.message_id,
                reply_markup=kb_archive_ai_suggest(names, descs),
            )
        except Exception:
            bot.send_message(uid, "🤖 Choose a name:", reply_markup=kb_archive_ai_suggest(names, descs))
        return

    if data == "arch_ai_reorder":
        # Reorganize = re-rank the SAME already-generated names (no new AI call,
        # instant, free) so the person can see them in a different order/priority.
        u     = get_user(uid)
        names = u["draft"].get("ai_suggested_names", [])
        descs = u["draft"].get("ai_suggested_descs", [])
        if len(names) > 1:
            names = names[1:] + names[:1]
            u["draft"]["ai_suggested_names"] = names
            save_user(uid, u)
        try:
            _answer(call, "🔀 Reorganized")
        except Exception:
            pass
        try:
            bot.edit_message_text(
                "🤖 *AI Repository Name Suggestions* (reorganized)\n\nChoose a name or type your own:",
                uid, call.message.message_id,
                reply_markup=kb_archive_ai_suggest(names, descs),
            )
        except Exception:
            bot.send_message(uid, "🤖 Choose a name:", reply_markup=kb_archive_ai_suggest(names, descs))
        return

    if data == "arch_ai_back_names":
        u     = get_user(uid)
        names = u["draft"].get("ai_suggested_names", [])
        descs = u["draft"].get("ai_suggested_descs", [])
        set_state(uid, State.ARCHIVE_AI_SUGGEST)
        u["draft"].pop("ai_stage", None)
        save_user(uid, u)
        try:
            bot.edit_message_text(
                "🤖 *AI Repository Name Suggestions*\n\nChoose a name or type your own:",
                uid, call.message.message_id,
                reply_markup=kb_archive_ai_suggest(names, descs),
            )
        except Exception:
            bot.send_message(uid, "🤖 Choose a name:", reply_markup=kb_archive_ai_suggest(names, descs))
        return

    # ── Single Archive AI description: tap → full preview ────
    if data.startswith("arch_ai_desc_") and not any(
        data.startswith(p) for p in
        ("arch_ai_desc_custom", "arch_ai_desc_skip", "arch_ai_desc_regen",
         "arch_ai_desc_reorder", "arch_ai_desc_confirm_", "arch_ai_desc_back_list",
         "arch_ai_desc_edit_")
    ):
        idx = int(data.split("_")[-1])
        u   = get_user(uid)
        descs = u["draft"].get("ai_suggested_descs", [])
        name  = u["draft"].get("name", "")
        if idx < len(descs):
            desc = descs[idx]
            u["draft"]["ai_preview_idx"] = idx
            save_user(uid, u)
            set_state(uid, State.ARCHIVE_AI_DESC_PREVIEW)
            preview_text = (
                f"📝 *Description {idx+1} of {len(descs)}* — full text:\n\n"
                f"_{_escape_md(desc)}_\n\n"
                f"{_length_badge(desc)}"
            )
            if name:
                preview_text += f"\n\n━━━━━━━━━━━━━━━━━━━━\n📦 *For repo:* `{name}`"
            try:
                bot.edit_message_text(preview_text, uid, call.message.message_id,
                                       reply_markup=kb_archive_ai_desc_preview(idx))
            except Exception:
                bot.send_message(uid, preview_text, reply_markup=kb_archive_ai_desc_preview(idx))
        return

    # ── Single Archive AI description: confirm from preview ──
    if data.startswith("arch_ai_desc_confirm_"):
        idx = int(data.split("_")[-1])
        u   = get_user(uid)
        descs = u["draft"].get("ai_suggested_descs", [])
        if idx < len(descs):
            desc = descs[idx]
            u["draft"]["description"] = desc
            u["draft"]["desc_raw"]    = desc
            save_user(uid, u)
            try:
                bot.edit_message_text(
                    f"✅ *Description confirmed:*\n\n_{_escape_md(desc)}_",
                    uid, call.message.message_id,
                )
            except Exception:
                pass
            _archive_go_to_visibility(uid)
        return

    if data.startswith("arch_ai_desc_edit_"):
        idx = int(data.split("_")[-1])
        u   = get_user(uid)
        descs = u["draft"].get("ai_suggested_descs", [])
        if idx < len(descs):
            u["draft"]["ai_edit_idx"] = idx
            save_user(uid, u)
            set_state(uid, State.ARCHIVE_AI_DESC_EDIT)
            try:
                bot.edit_message_text(
                    f"✏️ *Editing description {idx+1}*\n\n"
                    f"Current text:\n_{descs[idx]}_\n\n"
                    "Send the edited version below:",
                    uid, call.message.message_id,
                )
            except Exception:
                bot.send_message(uid, f"✏️ Send the edited description:\n\n_{descs[idx]}_")
        return

    if data == "arch_ai_desc_back_list":
        u     = get_user(uid)
        descs = u["draft"].get("ai_suggested_descs", [])
        name  = u["draft"].get("name", "")
        set_state(uid, State.ARCHIVE_AI_SUGGEST)
        try:
            bot.edit_message_text(
                "🤖 *AI Description Suggestions*\n\n"
                "Tap a number to preview it in full, then confirm. Or type your own below.",
                uid, call.message.message_id,
                reply_markup=kb_archive_ai_desc(descs, name),
            )
        except Exception:
            bot.send_message(uid, "🤖 Choose a description:", reply_markup=kb_archive_ai_desc(descs, name))
        return

    if data == "arch_ai_desc_custom":
        set_state(uid, State.ARCHIVE_DESC)
        try:
            bot.edit_message_text(
                "✏️ *Custom Description*\n\nType your repository description (or `-` to skip):",
                uid, call.message.message_id,
            )
        except Exception:
            bot.send_message(uid, "✏️ Type your description (or `-` to skip):")
        return

    if data == "arch_ai_desc_skip":
        u = get_user(uid)
        u["draft"]["description"] = ""
        save_user(uid, u)
        try:
            bot.edit_message_text("⏭ *Description skipped*", uid, call.message.message_id)
        except Exception:
            pass
        _archive_go_to_visibility(uid)
        return

    if data == "arch_ai_desc_reorder":
        # Reorganize = re-rank the SAME already-generated descriptions instantly.
        u     = get_user(uid)
        descs = u["draft"].get("ai_suggested_descs", [])
        name  = u["draft"].get("name", "")
        if len(descs) > 1:
            descs = descs[1:] + descs[:1]
            u["draft"]["ai_suggested_descs"] = descs
            save_user(uid, u)
        try:
            _answer(call, "🔀 Reorganized")
        except Exception:
            pass
        try:
            bot.edit_message_text(
                "🤖 *AI Description Suggestions* (reorganized)\n\n"
                "Tap a number to preview it in full, then confirm. Or type your own below.",
                uid, call.message.message_id,
                reply_markup=kb_archive_ai_desc(descs, name),
            )
        except Exception:
            bot.send_message(uid, "🤖 Choose a description:", reply_markup=kb_archive_ai_desc(descs, name))
        return

    if data == "arch_ai_desc_regen":
        u      = get_user(uid)
        files  = u["draft"].get("archive_files", [])
        fname  = u["draft"].get("archive_filename", "archive")
        name   = u["draft"].get("name", "")
        msg    = bot.send_message(uid, "🔄 Regenerating description suggestions ···")
        _, descs = _ai_suggest_names_and_descs(u, files, fname)
        u["draft"]["ai_suggested_descs"] = descs
        save_user(uid, u)
        try:
            bot.edit_message_text(
                "🤖 *AI Description Suggestions*\n\n"
                "Tap a number to preview it in full, then confirm. Or type your own below.",
                uid, msg.message_id,
                reply_markup=kb_archive_ai_desc(descs, name),
            )
        except Exception:
            bot.send_message(uid, "🤖 Choose a description:", reply_markup=kb_archive_ai_desc(descs, name))
        return

    # ── Multi-archive AI name selection ─────────────────────
    if data.startswith("archm_ai_name_"):
        pick = int(data.split("_")[-1])
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        names = u["draft"]["multi_queue"][idx].get("ai_suggested_names", [])
        if pick < len(names):
            name = names[pick]
            u["draft"]["multi_queue"][idx]["name"] = name
            descs = u["draft"]["multi_queue"][idx].get("ai_suggested_descs", [])
            u["draft"]["multi_queue"][idx]["ai_stage"] = "desc"
            save_user(uid, u)
            set_state(uid, State.ARCHM_AI_SUGGEST)
            if descs:
                try:
                    bot.edit_message_text(
                        f"✅ *Name selected:* `{name}`\n\n"
                        "🤖 *AI Description Suggestions*\n\n"
                        "Tap a number to preview it in full, then confirm. Or type your own.",
                        uid, call.message.message_id,
                        reply_markup=kb_archm_ai_desc(descs),
                    )
                except Exception:
                    bot.send_message(uid, f"✅ Name: `{name}`\n\n🤖 Choose a description:",
                                     reply_markup=kb_archm_ai_desc(descs))
            else:
                set_state(uid, State.ARCHIVE_MULTI_DESC)
                bot.send_message(uid, f"✅ *Name:* `{name}`\n\n📝 Type a description (or `-` to skip):")
        return

    if data == "archm_ai_custom":
        set_state(uid, State.ARCHM_AI_CUSTOM)
        try:
            bot.edit_message_text(
                "✏️ *Custom Repo Name*\n\nType your repository name:\n_Lowercase · hyphens_",
                uid, call.message.message_id,
            )
        except Exception:
            bot.send_message(uid, "✏️ Type the repository name:")
        return

    if data == "archm_ai_regen":
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        q    = u["draft"]["multi_queue"][idx]
        msg  = bot.send_message(uid, "🔄 Regenerating suggestions ···")
        names, descs = _ai_suggest_names_and_descs(u, q.get("files", []), q.get("filename", "archive"))
        u["draft"]["multi_queue"][idx]["ai_suggested_names"] = names
        u["draft"]["multi_queue"][idx]["ai_suggested_descs"] = descs
        save_user(uid, u)
        try:
            bot.edit_message_text(
                "🤖 Choose a repository name or type your own:",
                uid, msg.message_id,
                reply_markup=kb_archm_ai_suggest(names, descs),
            )
        except Exception:
            bot.send_message(uid, "🤖 Choose a name:", reply_markup=kb_archm_ai_suggest(names, descs))
        return

    if data == "archm_ai_reorder":
        # Reorganize = re-rank the SAME already-generated names instantly.
        u     = get_user(uid)
        idx   = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        names = u["draft"]["multi_queue"][idx].get("ai_suggested_names", [])
        descs = u["draft"]["multi_queue"][idx].get("ai_suggested_descs", [])
        if len(names) > 1:
            names = names[1:] + names[:1]
            u["draft"]["multi_queue"][idx]["ai_suggested_names"] = names
            save_user(uid, u)
        try:
            _answer(call, "🔀 Reorganized")
        except Exception:
            pass
        try:
            bot.edit_message_text(
                "🤖 Repository name suggestions (reorganized):",
                uid, call.message.message_id,
                reply_markup=kb_archm_ai_suggest(names, descs),
            )
        except Exception:
            bot.send_message(uid, "🤖 Choose a name:", reply_markup=kb_archm_ai_suggest(names, descs))
        return

    if data == "archm_ai_back_names":
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        names = u["draft"]["multi_queue"][idx].get("ai_suggested_names", [])
        descs = u["draft"]["multi_queue"][idx].get("ai_suggested_descs", [])
        set_state(uid, State.ARCHM_AI_SUGGEST)
        u["draft"]["multi_queue"][idx].pop("ai_stage", None)
        save_user(uid, u)
        try:
            bot.edit_message_text(
                "🤖 Choose a repository name or type your own:",
                uid, call.message.message_id,
                reply_markup=kb_archm_ai_suggest(names, descs),
            )
        except Exception:
            bot.send_message(uid, "🤖 Choose a name:", reply_markup=kb_archm_ai_suggest(names, descs))
        return

    # ── Multi-archive AI description: tap → full preview ─────
    if data.startswith("archm_ai_desc_") and not any(
        data.startswith(p) for p in
        ("archm_ai_desc_custom", "archm_ai_desc_skip", "archm_ai_desc_regen",
         "archm_ai_desc_reorder", "archm_ai_desc_confirm_", "archm_ai_desc_back_list",
         "archm_ai_desc_edit_")
    ):
        pick = int(data.split("_")[-1])
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        descs = u["draft"]["multi_queue"][idx].get("ai_suggested_descs", [])
        name  = u["draft"]["multi_queue"][idx].get("name", "")
        if pick < len(descs):
            desc = descs[pick]
            u["draft"]["multi_queue"][idx]["ai_preview_idx"] = pick
            save_user(uid, u)
            set_state(uid, State.ARCHM_AI_DESC_PREVIEW)
            preview_text = (
                f"📝 *Description {pick+1} of {len(descs)}* — full text:\n\n"
                f"_{_escape_md(desc)}_\n\n"
                f"{_length_badge(desc)}"
            )
            if name:
                preview_text += f"\n\n━━━━━━━━━━━━━━━━━━━━\n📦 *For repo:* `{name}`"
            try:
                bot.edit_message_text(preview_text, uid, call.message.message_id,
                                       reply_markup=kb_archm_ai_desc_preview(pick))
            except Exception:
                bot.send_message(uid, preview_text, reply_markup=kb_archm_ai_desc_preview(pick))
        return

    # ── Multi-archive AI description: confirm from preview ───
    if data.startswith("archm_ai_desc_confirm_"):
        pick = int(data.split("_")[-1])
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        descs = u["draft"]["multi_queue"][idx].get("ai_suggested_descs", [])
        if pick < len(descs):
            desc = descs[pick]
            u["draft"]["multi_queue"][idx]["description"] = desc
            u["draft"]["multi_queue"][idx]["desc_raw"]    = desc
            save_user(uid, u)
            try:
                bot.edit_message_text(f"✅ *Description confirmed:*\n\n_{_escape_md(desc)}_", uid, call.message.message_id)
            except Exception:
                pass
            set_state(uid, State.ARCHIVE_MULTI_VIS)
            queue = u["draft"]["multi_queue"]
            bot.send_message(uid,
                f"👁 *Visibility* for `{queue[idx].get('name', 'repo')}`\n\nPublic or Private?",
                reply_markup=kb_archive_multi_visibility())
        return

    if data.startswith("archm_ai_desc_edit_"):
        pick = int(data.split("_")[-1])
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        descs = u["draft"]["multi_queue"][idx].get("ai_suggested_descs", [])
        if pick < len(descs):
            u["draft"]["multi_queue"][idx]["ai_edit_idx"] = pick
            save_user(uid, u)
            set_state(uid, State.ARCHM_AI_DESC_EDIT)
            try:
                bot.edit_message_text(
                    f"✏️ *Editing description {pick+1}*\n\n"
                    f"Current text:\n_{descs[pick]}_\n\n"
                    "Send the edited version below:",
                    uid, call.message.message_id,
                )
            except Exception:
                bot.send_message(uid, f"✏️ Send the edited description:\n\n_{descs[pick]}_")
        return

    if data == "archm_ai_desc_back_list":
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        descs = u["draft"]["multi_queue"][idx].get("ai_suggested_descs", [])
        set_state(uid, State.ARCHM_AI_SUGGEST)
        try:
            bot.edit_message_text(
                "🤖 *AI Description Suggestions*\n\n"
                "Tap a number to preview it in full, then confirm. Or type your own.",
                uid, call.message.message_id,
                reply_markup=kb_archm_ai_desc(descs),
            )
        except Exception:
            bot.send_message(uid, "🤖 Choose a description:", reply_markup=kb_archm_ai_desc(descs))
        return

    if data == "archm_ai_desc_custom":
        set_state(uid, State.ARCHIVE_MULTI_DESC)
        try:
            bot.edit_message_text(
                "✏️ Type your description (or `-` to skip):",
                uid, call.message.message_id,
            )
        except Exception:
            bot.send_message(uid, "✏️ Type your description (or `-` to skip):")
        return

    if data == "archm_ai_desc_skip":
        u   = get_user(uid)
        idx = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        u["draft"]["multi_queue"][idx]["description"] = ""
        save_user(uid, u)
        set_state(uid, State.ARCHIVE_MULTI_VIS)
        queue = u["draft"]["multi_queue"]
        bot.send_message(uid,
            f"👁 *Visibility* for `{queue[idx].get('name', 'repo')}`\n\nPublic or Private?",
            reply_markup=kb_archive_multi_visibility())
        return

    if data == "archm_ai_desc_reorder":
        # Reorganize = re-rank the SAME already-generated descriptions instantly.
        u     = get_user(uid)
        idx   = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        descs = u["draft"]["multi_queue"][idx].get("ai_suggested_descs", [])
        if len(descs) > 1:
            descs = descs[1:] + descs[:1]
            u["draft"]["multi_queue"][idx]["ai_suggested_descs"] = descs
            save_user(uid, u)
        try:
            _answer(call, "🔀 Reorganized")
        except Exception:
            pass
        try:
            bot.edit_message_text(
                "🤖 *AI Description Suggestions* (reorganized)\n\n"
                "Tap a number to preview it in full, then confirm. Or type your own.",
                uid, call.message.message_id,
                reply_markup=kb_archm_ai_desc(descs),
            )
        except Exception:
            bot.send_message(uid, "🤖 Choose a description:", reply_markup=kb_archm_ai_desc(descs))
        return

    if data == "archm_ai_desc_regen":
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        q    = u["draft"]["multi_queue"][idx]
        msg  = bot.send_message(uid, "🔄 Regenerating description suggestions ···")
        _, descs = _ai_suggest_names_and_descs(u, q.get("files", []), q.get("filename", "archive"))
        u["draft"]["multi_queue"][idx]["ai_suggested_descs"] = descs
        save_user(uid, u)
        try:
            bot.edit_message_text(
                "🤖 *AI Description Suggestions*\n\n"
                "Tap a number to preview it in full, then confirm. Or type your own.",
                uid, msg.message_id,
                reply_markup=kb_archm_ai_desc(descs),
            )
        except Exception:
            bot.send_message(uid, "🤖 Choose a description:", reply_markup=kb_archm_ai_desc(descs))
        return

    # ── Multi-archive: name step buttons ────────────────────
    if data == "archm_name_type":
        # Show a visible prompt so the tap has an obvious effect.
        u     = get_user(uid)
        queue = u["draft"].get("multi_queue", [])
        idx   = u["draft"].get("multi_index", 0)
        fname = queue[idx].get("filename", f"archive {idx+1}") if idx < len(queue) else "archive"
        set_state(uid, State.ARCHIVE_MULTI_NAME)
        try:
            bot.edit_message_text(
                f"✏️ *Type the Repository Name*\n\n"
                f"📦 Archive *{idx+1}/{len(queue) or 1}* — `{fname}`\n\n"
                "Send the name as your next message.\n\n"
                "_Lowercase · hyphens · no spaces_\nExample: `my-project`",
                uid, call.message.message_id, parse_mode="Markdown",
                reply_markup=kb_archive_multi_name_step(),
            )
        except Exception:
            bot.send_message(
                uid,
                f"✏️ Send the repository name for archive *{idx+1}/{len(queue) or 1}* "
                "as your next message:\n\n_Lowercase · hyphens · no spaces_",
                parse_mode="Markdown",
                reply_markup=kb_archive_multi_name_step(),
            )
        return

    # ── Multi-archive: desc step buttons ────────────────────
    if data == "archm_desc_type":
        # Show a visible prompt so the tap has an obvious effect.
        set_state(uid, State.ARCHIVE_MULTI_DESC)
        try:
            bot.edit_message_text(
                "📝 *Type the Description*\n\n"
                "Send the description for this archive as your next message.\n\n"
                "_Or tap ⏭ Skip._",
                uid, call.message.message_id, parse_mode="Markdown",
                reply_markup=kb_archive_multi_desc_step(),
            )
        except Exception:
            bot.send_message(uid, "📝 Send the description for this archive:",
                             reply_markup=kb_archive_multi_desc_step())
        return

    if data == "archm_desc_skip_now":
        # User tapped "Skip" on description
        u   = get_user(uid)
        idx = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        u["draft"]["multi_queue"][idx]["description"] = ""
        u["draft"]["multi_queue"][idx]["desc_raw"]    = ""
        save_user(uid, u)
        set_state(uid, State.ARCHIVE_MULTI_VIS)
        queue = u["draft"]["multi_queue"]
        try:
            bot.edit_message_text(
                f"⏭ *Description skipped*\n\n"
                f"👁 *Visibility* for `{queue[idx].get('name', 'repo')}`\n\nPublic or Private?",
                uid, call.message.message_id,
                reply_markup=kb_archive_multi_visibility())
        except Exception:
            bot.send_message(uid,
                f"👁 *Visibility* for `{queue[idx].get('name', 'repo')}`\n\nPublic or Private?",
                reply_markup=kb_archive_multi_visibility())
        return

    # ── Multi-archive: done collecting ──────────────────────
    if data == "archm_done_collecting":
        u     = get_user(uid)
        queue = u["draft"].get("multi_queue", [])
        if not queue:
            _answer(call, "No archives yet! Send some files first.")
            return
        u["draft"]["multi_index"] = 0
        save_user(uid, u)
        try:
            bot.edit_message_text(
                f"✅ *{len(queue)} archive(s) collected!*\n\n"
                f"Now I'll ask you to configure each repository one by one.\n\n"
                f"_Starting with archive 1 of {len(queue)}…_",
                uid, call.message.message_id,
            )
        except Exception:
            pass
        _archm_next_step(uid)
        return

    # ── Multi-archive: description AI rewrite ───────────────
    if data == "archm_desc_ai":
        u   = get_user(uid)
        idx = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        raw_desc  = u["draft"]["multi_queue"][idx].get("desc_raw", "")
        repo_name = u["draft"]["multi_queue"][idx].get("name", "")
        msg = bot.send_message(uid, "🤖 Rewriting description ·")
        _t  = _time.time()
        rewritten = _ai_rewrite_desc(u, repo_name, raw_desc)
        u["draft"]["multi_queue"][idx]["description"] = rewritten
        save_user(uid, u)
        bot.edit_message_text(
            f"✅ *AI Rewrote:*  ⏱ `{(_time.time()-_t):.1f}s`\n\n_{rewritten}_",
            uid, msg.message_id,
        )
        set_state(uid, State.ARCHIVE_MULTI_VIS)
        queue = u["draft"]["multi_queue"]
        bot.send_message(uid,
            f"👁 *Visibility* for `{queue[idx].get('name', 'repo')}`\n\n"
            "Public or Private?",
            reply_markup=kb_archive_multi_visibility())
        return

    if data == "archm_desc_keep":
        u   = get_user(uid)
        idx = u["draft"].get("multi_index", 0)
        queue = u["draft"].get("multi_queue", [])
        if not queue or idx >= len(queue):
            # Draft lost (restart/legacy data) — recover instead of crashing.
            set_state(uid, State.IDLE, draft={})
            try:
                bot.edit_message_text("⚠️ Session expired — please start the upload again.",
                                      uid, call.message.message_id, reply_markup=kb_home_only(uid))
            except Exception:
                bot.send_message(uid, "⚠️ Session expired — please start the upload again.",
                                 reply_markup=kb_home_only(uid))
            return
        set_state(uid, State.ARCHIVE_MULTI_VIS)
        bot.send_message(uid,
            f"👁 *Visibility* for `{queue[idx].get('name', 'repo')}`\n\nPublic or Private?",
            reply_markup=kb_archive_multi_visibility())
        return

    # ── Multi-archive: visibility ────────────────────────────
    if data in ("archm_vis_public", "archm_vis_private"):
        u   = get_user(uid)
        idx = u["draft"].get("multi_index", 0)
        queue = u["draft"].get("multi_queue", [])
        if not queue or idx >= len(queue):
            # Draft lost (restart/legacy data) — recover instead of crashing.
            set_state(uid, State.IDLE, draft={})
            try:
                bot.edit_message_text("⚠️ Session expired — please start the upload again.",
                                      uid, call.message.message_id, reply_markup=kb_home_only(uid))
            except Exception:
                bot.send_message(uid, "⚠️ Session expired — please start the upload again.",
                                 reply_markup=kb_home_only(uid))
            return
        u["draft"]["multi_queue"][idx]["private"] = (data == "archm_vis_private")
        save_user(uid, u)
        vis = "🔒 Private" if data == "archm_vis_private" else "🌍 Public"
        try:
            bot.edit_message_text(f"✅ *Visibility:* {vis}", uid, call.message.message_id)
        except Exception:
            pass
        # Go to README step
        queue         = u["draft"].get("multi_queue", [])
        readme_content = queue[idx].get("readme_content", "")
        set_state(uid, State.ARCHIVE_MULTI_README)
        fname = queue[idx].get("filename", "archive")
        total = len(queue)
        bot.send_message(uid,
            f"📄 *README* for archive {idx+1}/{total}: `{fname}`\n\n"
            + ("A `README.md` was found. What would you like to do?" if readme_content
               else "No `README.md` found. Would you like to generate one with AI?"),
            reply_markup=kb_archive_multi_readme(bool(readme_content)))
        return

    # ── Multi-archive: README choices ───────────────────────
    if data == "archm_readme_rewrite":
        u   = get_user(uid)
        idx = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        q   = u["draft"]["multi_queue"][idx]
        msg = bot.send_message(uid, "✍️ Rewriting README with AI ···")
        _t  = _time.time()
        rewritten = _ai_rewrite_readme(u, q.get("name", ""), q.get("description", ""), q.get("readme_content", ""), files=q.get("files"))
        rewritten = _deduplicate_readme_description(rewritten, q.get("description", ""))
        u["draft"]["multi_queue"][idx]["readme_content"] = rewritten
        save_user(uid, u)
        elapsed = _time.time() - _t
        preview = rewritten[:350].strip()
        if len(rewritten) > 350:
            preview += "…"
        try:
            bot.edit_message_text(
                f"✅ *README rewritten!*  ⏱ `{elapsed:.1f}s`\n\n"
                f"_{preview}_",
                uid, msg.message_id,
            )
        except Exception:
            pass
        _archm_advance(uid)
        return

    if data == "archm_readme_keep":
        _archm_advance(uid)
        return

    if data == "archm_readme_generate":
        u   = get_user(uid)
        idx = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        q   = u["draft"]["multi_queue"][idx]
        msg = bot.send_message(uid, "✨ Generating README with AI ···")
        _t  = _time.time()
        generated = _ai_generate_readme(u, q.get("name", ""), q.get("description", ""), files=q.get("files"))
        generated = _deduplicate_readme_description(generated, q.get("description", ""))
        u["draft"]["multi_queue"][idx]["readme_content"] = generated
        save_user(uid, u)
        elapsed = _time.time() - _t
        preview = generated[:350].strip() if generated else "_No content generated._"
        if generated and len(generated) > 350:
            preview += "…"
        try:
            bot.edit_message_text(
                f"✅ *README generated!*  ⏱ `{elapsed:.1f}s`\n\n"
                f"_{preview}_",
                uid, msg.message_id,
            )
        except Exception:
            pass
        _archm_advance(uid)
        return

    if data == "archm_readme_skip":
        u   = get_user(uid)
        idx = u["draft"].get("multi_index", 0)
        if not _archm_guard(u, idx):
            _archm_expired(uid, call.message.message_id)
            return
        u["draft"]["multi_queue"][idx]["readme_content"] = ""
        save_user(uid, u)
        _archm_advance(uid)
        return

    # ── Delete: toggle repo selection ───────────────────────
    if data.startswith("del_repo_"):
        repo_name   = data[len("del_repo_"):]
        u           = get_user(uid)
        selected    = set(u["draft"].get("del_selected", []))
        repos_cache = u["draft"].get("del_repos_cache", [])
        # repos_cache may be list of dicts {name,private} or legacy list of strings
        if repos_cache and isinstance(repos_cache[0], str):
            repos_cache = [{"name": n, "private": False} for n in repos_cache]
        if repo_name in selected:
            selected.discard(repo_name)
        else:
            selected.add(repo_name)
        u["draft"]["del_selected"] = list(selected)
        save_user(uid, u)
        repos = repos_cache
        header = (
            f"🗑 *Delete Repository*\n\n"
            f"Choose a repository to delete:\n"
            f"_Tap multiple to select · ☑️ Select All · then 🗑 Delete Selected_\n\n"
            f"✅ *{len(selected)} selected*"
            if selected else
            "🗑 *Delete Repository*\n\n"
            "Choose a repository to delete:\n"
            "_Tap multiple to select · ☑️ Select All · then 🗑 Delete Selected_"
        )
        try:
            bot.edit_message_text(header, uid, call.message.message_id, reply_markup=kb_repo_picker(repos, "del", selected))
        except Exception:
            pass
        return

    if data == "del_select_all":
        u           = get_user(uid)
        repos_cache = u["draft"].get("del_repos_cache", [])
        if repos_cache and isinstance(repos_cache[0], str):
            repos_cache = [{"name": n, "private": False} for n in repos_cache]
        all_names = [r["name"] for r in repos_cache]
        u["draft"]["del_repos_cache"] = repos_cache
        u["draft"]["del_selected"] = all_names[:]
        save_user(uid, u)
        selected = set(all_names)
        repos    = repos_cache
        try:
            bot.edit_message_text(
                f"🗑 *Delete Repository*\n\n✅ *All {len(selected)} repos selected!*\n\n_Tap 🗑 Delete Selected to confirm._",
                uid, call.message.message_id,
                reply_markup=kb_repo_picker(repos, "del", selected))
        except Exception:
            pass
        return

    if data == "del_deselect_all":
        u = get_user(uid)
        u["draft"]["del_selected"] = []
        save_user(uid, u)
        repos_cache = u["draft"].get("del_repos_cache", [])
        if repos_cache and isinstance(repos_cache[0], str):
            repos_cache = [{"name": n, "private": False} for n in repos_cache]
        repos = repos_cache
        try:
            bot.edit_message_text(
                "🗑 *Delete Repository*\n\nChoose a repository to delete:",
                uid, call.message.message_id,
                reply_markup=kb_repo_picker(repos, "del", set()))
        except Exception:
            pass
        return

    if data == "del_confirm_selected":
        u        = get_user(uid)
        selected = list(set(u["draft"].get("del_selected", [])))
        if not selected:
            _answer(call, "No repos selected!")
            return
        if len(selected) == 1:
            _confirm_delete(uid, selected[0], edit_msg_id=call.message.message_id)
        else:
            _confirm_delete_multiple(uid, selected, edit_msg_id=call.message.message_id)
        return

    if data == "confirm_delete_multi":
        _execute_delete_multiple(uid, call.message.message_id)
        return

    # ── Step 2/5: description ────────────────────────────────
    if data == "desc_type":
        u = get_user(uid)
        set_state(uid, State.CREATE_DESC)
        try:
            bot.edit_message_text(
                f"✅ *Name:* `{u['draft'].get('name', '')}` — Step 2/5\n\n"
                "📝 *Type your description:*\n_1-2 sentences about what this repo does._",
                uid, call.message.message_id)
        except Exception:
            bot.send_message(uid, "📝 Type your description:")
        return

    if data == "desc_skip":
        u = get_user(uid)
        u["draft"]["description"] = ""
        save_user(uid, u)
        _go_to_visibility(uid, call.message.message_id)
        return

    if data == "desc_ai_rewrite":
        u         = get_user(uid)
        raw_desc  = u["draft"].get("desc_raw", u["draft"].get("description", ""))
        repo_name = u["draft"].get("name", "")
        msg       = bot.send_message(uid, "🤖 Rewriting description ·")
        _t        = _time.time()
        rewritten = _ai_rewrite_desc(u, repo_name, raw_desc)
        u["draft"]["description"] = rewritten
        save_user(uid, u)
        bot.edit_message_text(
            f"✅ *AI Rewrote:*  ⏱ `{(_time.time()-_t):.1f}s`\n\n_{rewritten}_",
            uid, msg.message_id)
        _go_to_visibility(uid)
        return

    if data == "desc_use_original":
        _go_to_visibility(uid, call.message.message_id)
        return

    # ── Archive: description AI rewrite ─────────────────────
    if data == "arch_desc_type":
        u = get_user(uid)
        set_state(uid, State.ARCHIVE_DESC)
        name = u["draft"].get("name", "")
        try:
            bot.edit_message_text(
                f"✅ *Repo name:* `{name}` — Step 2\n\n"
                "📝 *Type your description:*\n\n_Send it as a message. Or type `-` to skip._",
                uid, call.message.message_id,
            )
        except Exception:
            bot.send_message(uid, "📝 Type your description (or `-` to skip):")
        return

    if data == "arch_desc_skip":
        u = get_user(uid)
        u["draft"]["description"] = ""
        u["draft"]["desc_raw"]    = ""
        save_user(uid, u)
        _archive_go_to_visibility(uid, call.message.message_id)
        return

    if data == "arch_desc_ai_rewrite":
        u         = get_user(uid)
        raw_desc  = u["draft"].get("desc_raw", u["draft"].get("description", ""))
        repo_name = u["draft"].get("name", "")
        msg       = bot.send_message(uid, "🤖 Rewriting description ·")
        _t        = _time.time()
        rewritten = _ai_rewrite_desc(u, repo_name, raw_desc)
        u["draft"]["description"] = rewritten
        save_user(uid, u)
        bot.edit_message_text(
            f"✅ *AI Rewrote:*  ⏱ `{(_time.time()-_t):.1f}s`\n\n_{rewritten}_",
            uid, msg.message_id)
        _archive_go_to_visibility(uid)
        return

    if data == "arch_desc_use_original":
        _archive_go_to_visibility(uid, call.message.message_id)
        return

    # ── Archive: visibility ──────────────────────────────────
    if data in ("arch_vis_public", "arch_vis_private"):
        u = get_user(uid)
        u["draft"]["private"] = (data == "arch_vis_private")
        save_user(uid, u)
        vis = "🔒 Private" if u["draft"]["private"] else "🌍 Public"
        try:
            bot.edit_message_text(f"✅ *Visibility:* {vis}", uid, call.message.message_id)
        except Exception:
            pass
        _archive_go_to_readme(uid)
        return

    # ── Archive: README choices ──────────────────────────────
    if data == "arch_readme_rewrite":
        u              = get_user(uid)
        readme_content = u["draft"].get("archive_readme", "")
        repo_name      = u["draft"].get("name", "")
        desc           = u["draft"].get("description", "")
        msg            = bot.send_message(uid, "✍️ Rewriting README with AI ···")
        _t             = _time.time()
        rewritten      = _ai_rewrite_readme(u, repo_name, desc, readme_content, files=u["draft"].get("archive_files"))
        rewritten      = _deduplicate_readme_description(rewritten, desc)
        u["draft"]["archive_readme"] = rewritten
        save_user(uid, u)
        elapsed = _time.time() - _t
        preview = rewritten[:350].strip()
        if len(rewritten) > 350:
            preview += "…"
        try:
            bot.edit_message_text(
                f"✅ *README rewritten!*  ⏱ `{elapsed:.1f}s`\n\n_{preview}_",
                uid, msg.message_id,
            )
        except Exception:
            pass
        _archive_show_confirm(uid)
        return

    if data == "arch_readme_keep":
        _archive_show_confirm(uid, call.message.message_id)
        return

    if data == "arch_readme_generate":
        u         = get_user(uid)
        repo_name = u["draft"].get("name", "")
        desc      = u["draft"].get("description", "")
        msg       = bot.send_message(uid, "✨ Generating README with AI ···")
        _t        = _time.time()
        generated = _ai_generate_readme(u, repo_name, desc, files=u["draft"].get("archive_files"))
        generated = _deduplicate_readme_description(generated, desc)
        if generated:
            files = u["draft"].get("archive_files", [])
            files = [f for f in files if not _is_root_readme(f)]
            files.insert(0, {"path": "README.md", "content_b64": base64.b64encode(generated.encode()).decode()})
            u["draft"]["archive_files"]  = files
            u["draft"]["archive_readme"] = generated
            save_user(uid, u)
        elapsed = _time.time() - _t
        preview = generated[:350].strip() if generated else "_No content generated._"
        if generated and len(generated) > 350:
            preview += "…"
        try:
            bot.edit_message_text(
                f"✅ *README generated!*  ⏱ `{elapsed:.1f}s`\n\n_{preview}_",
                uid, msg.message_id,
            )
        except Exception:
            pass
        _archive_show_confirm(uid)
        return

    if data == "arch_readme_skip":
        u = get_user(uid)
        u["draft"]["archive_readme"] = ""
        save_user(uid, u)
        _archive_show_confirm(uid, call.message.message_id)
        return

    # ── Security warning: edit / re-upload ───────────────────
    if data == "sec_warn_create_edit":
        u = get_user(uid)
        # Remove the unsafe queued files so a corrected version can replace
        # them instead of leaving the original secret in the outgoing list.
        flagged_paths = {item["path"] for item in scan_files_for_secrets(u["draft"].get("uploads", [])).get("flagged_files", [])}
        u["draft"]["uploads"] = [
            file_data for file_data in u["draft"].get("uploads", [])
            if file_data.get("name") not in flagged_paths
        ]
        u["draft"].pop("_security_upload_approval", None)
        save_user(uid, u)
        _go_to_files(uid, call.message.message_id)
        return

    if data == "sec_warn_archive_edit":
        u = get_user(uid)
        u["draft"].pop("_security_upload_approval", None)
        save_user(uid, u)
        try:
            bot.edit_message_text(
                "✏️ *Edit your archive locally, then upload the corrected archive again.*\n\n"
                "The unsafe archive has not been sent to GitHub.",
                uid, call.message.message_id, reply_markup=kb_archive_mode(),
            )
        except Exception:
            bot.send_message(uid, "✏️ Edit the archive locally, then upload the corrected version again.", reply_markup=kb_archive_mode())
        return

    # ── Security warning: archive upload — explicit approval ────────────
    if data == "sec_warn_archive_proceed":
        u = get_user(uid)
        readme_content = u["draft"].get("archive_readme", "")
        files = list(u["draft"].get("archive_files", []))
        if readme_content:
            files = [f for f in files if not _is_root_readme(f)]
            files.insert(0, {"path": "README.md", "content_b64": base64.b64encode(readme_content.encode()).decode()})
        u["draft"]["_security_upload_approval"] = {
            "archive": True, "fingerprint": _security_file_fingerprint(files),
        }
        save_user(uid, u)
        try:
            _bot_notify(uid, call.message.message_id, "⚠️ Security warning acknowledged — starting upload ···")
        except Exception:
            pass
        _execute_archive_upload(uid, call.message.message_id)
        return

    # ── Security warning: repo create — proceed ───────────────
    if data == "sec_warn_create_proceed":
        u = get_user(uid)
        u["draft"]["_security_upload_approval"] = {
            "archive": False,
            "fingerprint": _security_file_fingerprint(u["draft"].get("uploads", [])),
        }
        save_user(uid, u)
        try:
            _bot_notify(uid, call.message.message_id, "⚠️ Security warning acknowledged — creating repository ···")
        except Exception:
            pass
        set_state(uid, State.CREATE_CONFIRM)
        _execute_create_repo(uid, call.message.message_id)
        return

    # ── Security warning: cancel ─────────────────────────────
    if data == "sec_warn_cancel":
        set_state(uid, State.IDLE, draft={})
        try:
            bot.edit_message_text(
                "🛡 *Upload cancelled.*\n\n"
                "Remove sensitive data from your files (or add them to `.gitignore`) "
                "before trying again.",
                uid, call.message.message_id,
                reply_markup=kb_main(uid),
            )
        except Exception:
            bot.send_message(uid, "🛡 Upload cancelled.", reply_markup=kb_main(uid))
        return

    if data == "confirm_archive":
        u             = get_user(uid)
        readme_content = u["draft"].get("archive_readme", "")
        if readme_content:
            files = u["draft"].get("archive_files", [])
            files = [f for f in files if not _is_root_readme(f)]
            files.insert(0, {"path": "README.md", "content_b64": base64.b64encode(readme_content.encode()).decode()})
            u["draft"]["archive_files"] = files
            save_user(uid, u)
        try:
            _bot_notify(uid, call.message.message_id, "⏳ Starting archive upload ···")
        except Exception:
            pass
        _execute_archive_upload(uid, call.message.message_id)
        return

    # ── Visibility (New Repo) ────────────────────────────────
    if data in ("vis_public", "vis_private"):
        u = get_user(uid)
        u["draft"]["private"] = (data == "vis_private")
        save_user(uid, u)
        vis = "🔒 Private" if u["draft"]["private"] else "🌍 Public"
        try:
            bot.edit_message_text(f"✅ *Visibility:* {vis}", uid, call.message.message_id)
        except Exception:
            pass
        _go_to_files(uid)
        return

    # ── AI files ─────────────────────────────────────────────
    if data in ("ai_yes", "ai_readme_only", "ai_no"):
        u = get_user(uid)
        u["draft"]["ai_files"] = True if data == "ai_yes" else ("readme_only" if data == "ai_readme_only" else False)
        save_user(uid, u)
        set_state(uid, State.CREATE_AI_FILES, draft=u["draft"])
        try:
            label = "README + .gitignore" if u["draft"]["ai_files"] is True else ("README only" if u["draft"]["ai_files"] == "readme_only" else "None")
            bot.edit_message_text(f"✅ AI files: {label}", uid, call.message.message_id)
        except Exception:
            pass
        _show_create_confirm(uid, None)
        return

    # ── File step ────────────────────────────────────────────
    if data == "files_upload":
        u     = get_user(uid)
        count = len(u["draft"].get("uploads", []))
        set_state(uid, State.CREATE_FILES_UPLOAD)
        existing = f"\n📁 Already queued: *{count}* file(s)" if count > 0 else ""
        try:
            bot.edit_message_text(
                f"📤 *Upload File(s)*\n\nSend your file(s) now. Up to 1000 files.{existing}\n\n"
                "_Tap ✅ Done when finished._",
                uid, call.message.message_id, reply_markup=kb_files_continue())
        except Exception:
            bot.send_message(uid, "📤 Send your file(s).", reply_markup=kb_files_continue())
        return

    if data == "files_create":
        try:
            bot.edit_message_text("📝 *Create New File*\n\nHow many files?",
                uid, call.message.message_id, reply_markup=kb_create_mode())
        except Exception:
            bot.send_message(uid, "📝 How many files?", reply_markup=kb_create_mode())
        return

    if data == "create_single":
        set_state(uid, State.CREATE_FILES_NAME)
        try:
            bot.edit_message_text(
                "📄 *Single File — Step 1/2*\n\nFilename?\n\nExamples: `README.md` · `main.py` · `docs/guide.md`",
                uid, call.message.message_id)
        except Exception:
            bot.send_message(uid, "📄 Enter the filename:")
        return

    if data == "create_multi":
        set_state(uid, State.CREATE_FILES_MULTI_NAMES)
        try:
            bot.edit_message_text(
                "📚 *Multiple Files — Step 1*\n\nEnter all filenames separated by commas:\n\n"
                "Example: `main.py, config.json, README.md`\n\n_Content collected one by one._",
                uid, call.message.message_id)
        except Exception:
            bot.send_message(uid, "📚 Enter filenames separated by commas:")
        return

    if data == "multi_skip_file":
        u     = get_user(uid)
        names = u["draft"].get("multi_filenames", [])
        idx   = u["draft"].get("multi_file_index", 0)
        if idx < len(names):
            u["draft"]["multi_file_index"] = idx + 1
            save_user(uid, u)
            bot.send_message(uid, f"⏭ Skipped `{names[idx]}`.")
            if u["draft"]["multi_file_index"] >= len(names):
                _finish_multi_files(uid, u)
            else:
                _ask_multi_file_content(uid, u)
        return

    if data == "files_skip":
        u = get_user(uid)
        u["draft"]["uploads"] = []
        save_user(uid, u)
        _go_to_ai_files(uid, call.message.message_id)
        return

    if data == "files_done":
        _go_to_ai_files(uid, call.message.message_id)
        return

    # ── Confirmations ────────────────────────────────────────
    if data == "confirm_create":
        _execute_create_repo(uid, call.message.message_id)
        return

    if data == "confirm_delete":
        _execute_delete(uid, call.message.message_id)
        return

    # ── Fork confirm / edit ──────────────────────────────────
    if data == "fork_confirm":
        _execute_fork(uid, call.message.message_id)
        return

    if data == "fork_edit":
        set_state(uid, State.IMPORT_URL)
        try:
            bot.edit_message_text("✏️ Send the corrected GitHub repository URL:", uid, call.message.message_id)
        except Exception:
            bot.send_message(uid, "✏️ Send the corrected GitHub URL:")
        return

    if data == "menu_home":
        nav_clear(uid)
        set_state(uid, State.IDLE, draft={})
        _show_home(uid, call.message.message_id)
        return

    if data == "cancel":
        # If there's a navigation history, go back one step
        entry = nav_pop(uid)
        if entry and entry["data"] not in ("menu_home", "cancel"):
            # Re-dispatch as if user tapped that button
            class _FakeCall:
                def __init__(self, msg, d):
                    self.message = msg
                    self.data    = d
                    self.id      = call.id
            fake = _FakeCall(call.message, entry["data"])
            # Avoid infinite recursion: just re-render the screen manually
            _nav_render(uid, entry["data"], call.message.message_id)
        else:
            nav_clear(uid)
            set_state(uid, State.IDLE, draft={})
            try:
                bot.edit_message_text("✅ Cancelled.", uid, call.message.message_id, reply_markup=kb_main())
            except Exception:
                bot.send_message(uid, "✅ Cancelled.", reply_markup=kb_main())
        return


    # ═══════════════════════════════════════════════════════════
    #  DOWNLOAD REPO — callback handlers
    # ═══════════════════════════════════════════════════════════

    if data.startswith("dl_toggle_"):
        u         = get_user(uid)
        repo_name = data[len("dl_toggle_"):]
        selected  = set(u["draft"].get("dl_selected", []))
        if repo_name in selected:
            selected.discard(repo_name)
        else:
            selected.add(repo_name)
        u["draft"]["dl_selected"] = list(selected)
        save_user(uid, u)
        repos = u["draft"].get("dl_repos", [])
        page  = u["draft"].get("dl_page", 0)
        try:
            bot.edit_message_reply_markup(
                uid, call.message.message_id,
                reply_markup=kb_download_picker(repos, page, selected),
            )
        except Exception:
            pass
        return

    if data.startswith("dl_page_"):
        u    = get_user(uid)
        page = int(data[len("dl_page_"):])
        u["draft"]["dl_page"] = page
        save_user(uid, u)
        repos    = u["draft"].get("dl_repos", [])
        selected = set(u["draft"].get("dl_selected", []))
        total    = len(repos)
        try:
            bot.edit_message_text(
                (
                    "\u2b07\ufe0f *Download Repository*\n\n"
                    "Select one or more repositories to download as ZIP.\n"
                    f"\U0001f30d Public \u00b7 \U0001f512 Private \u00b7 Total: *{total}*\n\n"
                    "_Tap to select \u00b7 \u2611\ufe0f Select All \u00b7 \u2b07\ufe0f Download_"
                ),
                uid, call.message.message_id,
                reply_markup=kb_download_picker(repos, page, selected),
            )
        except Exception:
            pass
        return

    if data == "dl_noop":
        return

    if data == "dl_select_all":
        u     = get_user(uid)
        repos = u["draft"].get("dl_repos", [])
        u["draft"]["dl_selected"] = [r["name"] for r in repos]
        save_user(uid, u)
        selected = set(u["draft"]["dl_selected"])
        page     = u["draft"].get("dl_page", 0)
        total    = len(repos)
        try:
            bot.edit_message_text(
                (
                    "\u2b07\ufe0f *Download Repository*\n\n"
                    f"\u2611\ufe0f *All {len(selected)} repos selected*\n\n"
                    "_Tap \u2b07\ufe0f Download to proceed._"
                ),
                uid, call.message.message_id,
                reply_markup=kb_download_picker(repos, page, selected),
            )
        except Exception:
            pass
        return

    if data == "dl_deselect_all":
        u = get_user(uid)
        u["draft"]["dl_selected"] = []
        save_user(uid, u)
        repos = u["draft"].get("dl_repos", [])
        page  = u["draft"].get("dl_page", 0)
        try:
            bot.edit_message_reply_markup(
                uid, call.message.message_id,
                reply_markup=kb_download_picker(repos, page, set()),
            )
        except Exception:
            pass
        return

    if data == "dl_execute":
        u        = get_user(uid)
        selected = u["draft"].get("dl_selected", [])
        if not selected:
            _answer(call, "\u26a0\ufe0f Select at least one repo first.", alert=True)
            return
        _execute_download(uid, call.message.message_id)
        return

    # ═══════════════════════════════════════════════════════════
    #  EDIT REPO — callback handlers
    # ═══════════════════════════════════════════════════════════

    # Repo picker: page navigation
    if data.startswith("er_page_"):
        page = int(data[len("er_page_"):])
        u    = get_user(uid)
        repos = u["draft"].get("er_repos", [])
        u["draft"]["er_page"] = page
        save_user(uid, u)
        total = len(repos)
        try:
            bot.edit_message_text(
                f"✏️ *Edit Repository*\n\n"
                f"Select a repository to edit.\n"
                f"🌍 Public · 🔒 Private · Total: *{total}*\n\n"
                "_Choose a repo to browse files, edit code, rename, and more._",
                uid, call.message.message_id,
                reply_markup=kb_edit_repo_picker(repos, page),
            )
        except Exception:
            pass
        return

    if data == "er_noop":
        return

    # Repo selected from picker (index into the draft-cached repo list)
    if data.startswith("er_pick_"):
        try:
            idx = int(data[len("er_pick_"):])
        except ValueError:
            return
        u = get_user(uid)
        if not u.get("github_token"):
            _send_github_token_guide(uid)
            return
        repos = u["draft"].get("er_repos") or []
        if not (0 <= idx < len(repos)):
            _answer(call, "That repo is no longer in the list — reopen Edit Repo.", alert=True)
            return
        repo_name = (repos[idx] or {}).get("name", "")
        if not repo_name:
            return
        nav_push(uid, f"er_repomenu_{repo_name}", repo_name)
        _show_edit_repo_menu(uid, repo_name, call.message.message_id)
        return

    # Back to repo menu from within edit flow
    if data.startswith("er_repomenu_"):
        repo_name = data[len("er_repomenu_"):]
        nav_push(uid, f"er_repomenu_{repo_name}", repo_name)
        _show_edit_repo_menu(uid, repo_name, call.message.message_id)
        return

    # Browse a directory path
    # Format: er_browse_{repo}|{path} — '|' cannot appear in repo names, so the
    # repo is always the text before the first '|'. Legacy keyboards used '_'.
    if data.startswith("er_browse_"):
        rest = data[len("er_browse_"):]
        if "|" in rest:
            repo_name, path = rest.split("|", 1)
        elif "_" in rest:                      # legacy keyboard
            sep_idx   = rest.index("_")
            repo_name = rest[:sep_idx]
            path      = rest[sep_idx + 1:]
        else:
            repo_name, path = rest, ""
        _browse_path(uid, repo_name, path, call.message.message_id)
        return

    # Browse page navigation — er_bpage_{repo}|{path}|{page}
    if data.startswith("er_bpage_"):
        rest = data[len("er_bpage_"):]
        try:
            if "|" in rest:
                repo_name, _, mid = rest.partition("|")
                path, _, page_str = mid.rpartition("|")
                page = int(page_str)
            else:                               # legacy keyboard
                parts     = rest.split("_")
                repo_name = parts[0]
                page      = int(parts[-1])
                path      = "_".join(parts[1:-1])
        except (ValueError, IndexError):
            return
        u         = get_user(uid)
        items     = u["draft"].get("er_browse_items", [])
        try:
            bot.edit_message_reply_markup(
                uid, call.message.message_id,
                reply_markup=kb_browse_dir(repo_name, path, items, page),
            )
        except Exception:
            pass
        return

    # Search result file picked (index into draft-cached result paths)
    if data.startswith("er_sfile_"):
        try:
            sidx = int(data[len("er_sfile_"):])
        except ValueError:
            return
        u         = get_user(uid)
        paths     = u["draft"].get("er_search_results") or []
        repo_name = u["draft"].get("er_repo", "")
        if not repo_name or not (0 <= sidx < len(paths)):
            _answer(call, "Search results expired — run the search again.", alert=True)
            return
        _show_file_actions(uid, repo_name, paths[sidx], call.message.message_id)
        return

    # View/action on a specific file — er_file_{repo}|{path}
    if data.startswith("er_file_"):
        rest = data[len("er_file_"):]
        if "|" in rest:
            repo_name, file_path = rest.split("|", 1)
        elif "_" in rest:                      # legacy keyboard
            sep_idx   = rest.index("_")
            repo_name = rest[:sep_idx]
            file_path = rest[sep_idx + 1:]
        else:
            repo_name, file_path = rest, ""
        _show_file_actions(uid, repo_name, file_path, call.message.message_id)
        return

    # Edit file content — er_edit_{repo}|{path}
    if data.startswith("er_edit_"):
        rest = data[len("er_edit_"):]
        if "|" in rest:
            repo_name, file_path = rest.split("|", 1)
        elif "_" in rest:                      # legacy keyboard
            sep_idx   = rest.index("_")
            repo_name = rest[:sep_idx]
            file_path = rest[sep_idx + 1:]
        else:
            repo_name, file_path = rest, ""
        u = get_user(uid)
        fname = file_path.split("/")[-1]
        set_state(uid, State.EDIT_FILE_EDIT)
        try:
            bot.edit_message_text(
                f"✏️ *Edit `{fname}`*\n\n"
                f"📍 `{file_path}`\n\n"
                "Send the *new file content* as a message.\n\n"
                "⚠️ This will *replace* the entire file content.",
                uid, call.message.message_id,
                reply_markup=kb_edit_cancel(repo_name, "/".join(file_path.split("/")[:-1])),
            )
        except Exception:
            bot.send_message(uid,
                f"✏️ Send the new content for `{fname}`:",
                reply_markup=kb_edit_cancel(repo_name, "/".join(file_path.split("/")[:-1])))
        return

    # View raw file content — er_view_{repo}|{path}
    if data.startswith("er_view_"):
        rest = data[len("er_view_"):]
        if "|" in rest:
            repo_name, file_path = rest.split("|", 1)
        elif "_" in rest:                      # legacy keyboard
            sep_idx   = rest.index("_")
            repo_name = rest[:sep_idx]
            file_path = rest[sep_idx + 1:]
        else:
            repo_name, file_path = rest, ""
        u     = get_user(uid)
        token = u.get("github_token")
        owner = u["draft"].get("er_owner", "")
        import base64 as _b64
        file_data = gh.get_file_content(token, owner, repo_name, file_path)
        if file_data:
            raw = _b64.b64decode(file_data.get("content","").replace("\n","")).decode("utf-8", errors="replace")
            chunks = [raw[i:i+3500] for i in range(0, min(len(raw), 7000), 3500)]
            for chunk in chunks:
                bot.send_message(uid, f"```\n{chunk}\n```")
            bot.send_message(uid, f"_End of `{file_path.split('/')[-1]}`_",
                             reply_markup=kb_file_actions(repo_name, file_path))
        else:
            _answer(call, "❌ Could not fetch file.", alert=True)
        return

    # Move/rename file — er_move_{repo}|{path}
    if data.startswith("er_move_"):
        rest = data[len("er_move_"):]
        if "|" in rest:
            repo_name, file_path = rest.split("|", 1)
        elif "_" in rest:                      # legacy keyboard
            sep_idx   = rest.index("_")
            repo_name = rest[:sep_idx]
            file_path = rest[sep_idx + 1:]
        else:
            repo_name, file_path = rest, ""
        u = get_user(uid)
        u["draft"]["er_file_path"] = file_path
        save_user(uid, u)
        set_state(uid, State.EDIT_FILE_MOVE_DEST)
        try:
            bot.edit_message_text(
                f"✂️ *Move/Rename `{file_path.split('/')[-1]}`*\n\n"
                f"Current: `{file_path}`\n\n"
                "Send the *new path* (e.g. `src/utils/helpers.py`):",
                uid, call.message.message_id,
                reply_markup=kb_edit_cancel(repo_name, "/".join(file_path.split("/")[:-1])),
            )
        except Exception:
            bot.send_message(uid, "Send the new path:", reply_markup=kb_edit_cancel(repo_name, ""))
        return

    # Delete file — confirmation prompt — er_del_file_{repo}|{path}
    if data.startswith("er_del_file_"):
        rest = data[len("er_del_file_"):]
        if "|" in rest:
            repo_name, file_path = rest.split("|", 1)
        elif "_" in rest:                      # legacy keyboard
            sep_idx   = rest.index("_")
            repo_name = rest[:sep_idx]
            file_path = rest[sep_idx + 1:]
        else:
            repo_name, file_path = rest, ""
        try:
            bot.edit_message_text(
                f"⚠️ *Delete `{file_path.split('/')[-1]}`?*\n\n"
                f"`{file_path}`\n\n"
                "_This cannot be undone._",
                uid, call.message.message_id,
                reply_markup=kb_confirm_del_file(repo_name, file_path),
            )
        except Exception:
            pass
        return

    # Delete file — confirmed — er_del_confirm_{repo}|{path}
    if data.startswith("er_del_confirm_"):
        rest = data[len("er_del_confirm_"):]
        if "|" in rest:
            repo_name, file_path = rest.split("|", 1)
        elif "_" in rest:                      # legacy keyboard
            sep_idx   = rest.index("_")
            repo_name = rest[:sep_idx]
            file_path = rest[sep_idx + 1:]
        else:
            repo_name, file_path = rest, ""
        u     = get_user(uid)
        token = u.get("github_token")
        owner = u["draft"].get("er_owner", "")
        try:
            bot.edit_message_text(f"⏳ Deleting `{file_path}` ···", uid, call.message.message_id)
        except Exception:
            pass
        file_data = gh.get_file_content(token, owner, repo_name, file_path)
        if file_data:
            sha = file_data.get("sha", "")
            ok  = gh.delete_file(token, owner, repo_name, file_path, sha)
            parent = "/".join(file_path.split("/")[:-1])
            if ok:
                add_history(uid, f"Deleted file {repo_name}/{file_path}")
                try:
                    bot.edit_message_text(
                        f"✅ *Deleted!*\n\n`{file_path}` removed from `{repo_name}`.",
                        uid, call.message.message_id,
                        reply_markup=kb_edit_cancel(repo_name, parent),
                    )
                except Exception:
                    bot.send_message(uid, f"✅ Deleted `{file_path}`.",
                                     reply_markup=kb_edit_cancel(repo_name, parent))
            else:
                try:
                    bot.edit_message_text(
                        "❌ Delete failed. Check token permissions.",
                        uid, call.message.message_id,
                        reply_markup=kb_file_actions(repo_name, file_path),
                    )
                except Exception:
                    pass
        else:
            _answer(call, "❌ Could not fetch file SHA.", alert=True)
        return

    # New file in a path — er_newfile_{repo}|{base_path}
    if data.startswith("er_newfile_"):
        rest = data[len("er_newfile_"):]
        if "|" in rest:
            repo_name, base_path = rest.split("|", 1)
        elif "_" in rest:                      # legacy keyboard
            sep_idx   = rest.index("_")
            repo_name = rest[:sep_idx]
            base_path = rest[sep_idx + 1:]
        else:
            repo_name, base_path = rest, ""
        u = get_user(uid)
        u["draft"]["er_repo"]          = repo_name
        u["draft"]["er_new_base_path"] = base_path
        save_user(uid, u)
        set_state(uid, State.EDIT_FILE_NEW_NAME)
        path_display = f"`{base_path}/`" if base_path else "_repo root_"
        try:
            bot.edit_message_text(
                f"📄 *New File*\n\n"
                f"📍 Location: {path_display}\n\n"
                "Send the *file name* (e.g. `main.py`, `utils/helpers.js`):",
                uid, call.message.message_id,
                reply_markup=kb_edit_cancel(repo_name, base_path),
            )
        except Exception:
            bot.send_message(uid, "Send the file name:", reply_markup=kb_edit_cancel(repo_name, base_path))
        return

    # New folder — er_newfolder_{repo}|{base_path} (root variant has no '|')
    if data.startswith("er_newfolder_"):
        rest = data[len("er_newfolder_"):]
        if "|" in rest:
            repo_name, base_path = rest.split("|", 1)
        elif "_" in rest:                      # legacy keyboard
            sep_idx   = rest.index("_")
            repo_name = rest[:sep_idx]
            base_path = rest[sep_idx + 1:]
        else:
            repo_name, base_path = rest, ""
        u = get_user(uid)
        u["draft"]["er_repo"]          = repo_name
        u["draft"]["er_new_base_path"] = base_path
        save_user(uid, u)
        set_state(uid, State.EDIT_FOLDER_NEW_NAME)
        path_display = f"`{base_path}/`" if base_path else "_repo root_"
        try:
            bot.edit_message_text(
                f"📁 *New Folder*\n\n"
                f"📍 Location: {path_display}\n\n"
                "Send the *folder name*:",
                uid, call.message.message_id,
                reply_markup=kb_edit_cancel(repo_name, base_path),
            )
        except Exception:
            bot.send_message(uid, "Send the folder name:", reply_markup=kb_edit_cancel(repo_name, base_path))
        return

    # Rename repo
    if data.startswith("er_rename_"):
        repo_name = data[len("er_rename_"):]
        u = get_user(uid)
        u["draft"]["er_repo"] = repo_name
        save_user(uid, u)
        set_state(uid, State.EDIT_REPO_RENAME)
        try:
            bot.edit_message_text(
                f"✏️ *Rename Repository*\n\n"
                f"Current: `{repo_name}`\n\n"
                "Send the *new repository name*:\n_(lowercase, hyphens, no spaces)_",
                uid, call.message.message_id,
                reply_markup=kb_edit_cancel(repo_name, ""),
            )
        except Exception:
            bot.send_message(uid, "Send the new repo name:", reply_markup=kb_edit_cancel(repo_name, ""))
        return

    # Edit description
    if data.startswith("er_desc_"):
        repo_name = data[len("er_desc_"):]
        u = get_user(uid)
        u["draft"]["er_repo"] = repo_name
        save_user(uid, u)
        set_state(uid, State.EDIT_REPO_DESC)
        try:
            bot.edit_message_text(
                f"📝 *Edit Description*\n\n"
                f"Repo: `{repo_name}`\n\n"
                "Send the *new description*:",
                uid, call.message.message_id,
                reply_markup=kb_edit_cancel(repo_name, ""),
            )
        except Exception:
            bot.send_message(uid, "Send the new description:", reply_markup=kb_edit_cancel(repo_name, ""))
        return

    # Toggle visibility
    if data.startswith("er_vis_toggle_"):
        repo_name = data[len("er_vis_toggle_"):]
        u     = get_user(uid)
        token = u.get("github_token")
        owner = u["draft"].get("er_owner", "")
        info  = gh.get_repo_info(token, owner, repo_name)
        if info:
            new_vis = not info.get("private", False)
            try:
                bot.edit_message_text(
                    f"⏳ Changing visibility of `{repo_name}` ···",
                    uid, call.message.message_id,
                )
            except Exception:
                pass
            result = gh.update_repo_settings(token, owner, repo_name, private=new_vis)
            if result:
                vis_txt = "🔒 Private" if new_vis else "🌍 Public"
                add_history(uid, f"Changed visibility of {repo_name} to {vis_txt}")
                try:
                    bot.edit_message_text(
                        f"✅ *Visibility changed!*\n\n`{repo_name}` is now {vis_txt}",
                        uid, call.message.message_id,
                        reply_markup=kb_edit_repo_menu(repo_name, new_vis),
                    )
                except Exception:
                    bot.send_message(uid, f"✅ `{repo_name}` is now {vis_txt}",
                                     reply_markup=kb_edit_repo_menu(repo_name, new_vis))
            else:
                _answer(call, "❌ Failed to change visibility.", alert=True)
        return

    # Set homepage
    if data.startswith("er_homepage_"):
        repo_name = data[len("er_homepage_"):]
        u = get_user(uid)
        u["draft"]["er_repo"] = repo_name
        save_user(uid, u)
        set_state(uid, State.EDIT_REPO_HOMEPAGE)
        try:
            bot.edit_message_text(
                f"🌐 *Set Homepage*\n\n"
                f"Repo: `{repo_name}`\n\n"
                "Send the *homepage URL* (or `-` to remove):",
                uid, call.message.message_id,
                reply_markup=kb_edit_cancel(repo_name, ""),
            )
        except Exception:
            bot.send_message(uid, "Send the homepage URL:", reply_markup=kb_edit_cancel(repo_name, ""))
        return

    # Edit topics
    if data.startswith("er_topics_"):
        repo_name = data[len("er_topics_"):]
        u     = get_user(uid)
        token = u.get("github_token")
        owner = u["draft"].get("er_owner", "")
        u["draft"]["er_repo"] = repo_name
        save_user(uid, u)
        set_state(uid, State.EDIT_REPO_TOPICS)
        # Show current topics
        topics = gh.get_repo_topics(token, owner, repo_name)
        current = ", ".join(topics) if topics else "_(none)_"
        try:
            bot.edit_message_text(
                f"🏷 *Edit Topics*\n\n"
                f"Repo: `{repo_name}`\n"
                f"Current: {current}\n\n"
                "Send *new topics* separated by commas or spaces:\n"
                "_(e.g. `python, bot, telegram, github`)_",
                uid, call.message.message_id,
                reply_markup=kb_edit_cancel(repo_name, ""),
            )
        except Exception:
            bot.send_message(uid, "Send new topics:", reply_markup=kb_edit_cancel(repo_name, ""))
        return

    # New branch
    if data.startswith("er_newbranch_"):
        repo_name = data[len("er_newbranch_"):]
        u = get_user(uid)
        u["draft"]["er_repo"] = repo_name
        save_user(uid, u)
        set_state(uid, State.EDIT_BRANCH_NEW)
        try:
            bot.edit_message_text(
                f"🔀 *Create New Branch*\n\n"
                f"Repo: `{repo_name}`\n\n"
                "Send the *new branch name*:",
                uid, call.message.message_id,
                reply_markup=kb_edit_cancel(repo_name, ""),
            )
        except Exception:
            bot.send_message(uid, "Send the new branch name:", reply_markup=kb_edit_cancel(repo_name, ""))
        return

    # Repo info
    if data.startswith("er_info_"):
        repo_name = data[len("er_info_"):]
        u     = get_user(uid)
        token = u.get("github_token")
        owner = u["draft"].get("er_owner", "")
        try:
            bot.edit_message_text(f"⏳ Loading info for `{repo_name}` ···", uid, call.message.message_id)
        except Exception:
            pass
        info     = gh.get_repo_info(token, owner, repo_name)
        branches = gh.list_branches(token, owner, repo_name)
        topics   = gh.get_repo_topics(token, owner, repo_name)
        if info:
            vis_txt  = "🔒 Private" if info.get("private") else "🌍 Public"
            lang     = info.get("language") or "—"
            stars    = info.get("stargazers_count", 0)
            forks    = info.get("forks_count", 0)
            watchers = info.get("watchers_count", 0)
            size     = info.get("size", 0)
            branch   = info.get("default_branch", "—")
            homepage = info.get("homepage") or "—"
            desc     = info.get("description") or "—"
            open_issues = info.get("open_issues_count", 0)
            created  = info.get("created_at", "—")[:10]
            updated  = info.get("updated_at", "—")[:10]
            pushed   = info.get("pushed_at", "—")[:10]
            topic_txt = " ".join(f"`{t}`" for t in topics) if topics else "—"
            branch_names = ", ".join(f"`{b['name']}`" for b in branches[:10]) if branches else "—"

            text = (
                f"📊 *Repository Info — `{repo_name}`*\n\n"
                f"🏷 {vis_txt}  ·  🛠 {lang}\n"
                f"⭐ {stars}  🍴 {forks}  👁 {watchers}  🐛 {open_issues}\n"
                f"💾 {size} KB  ·  🌿 `{branch}`\n\n"
                f"📝 _{_escape_md(desc)}_\n"
                f"🌐 {homepage}\n\n"
                f"🏷 Topics: {topic_txt}\n"
                f"🔀 Branches: {branch_names}\n\n"
                f"📅 Created: `{created}`\n"
                f"🔄 Updated: `{updated}`\n"
                f"🚀 Last push: `{pushed}`"
            )
        else:
            text = f"❌ Could not fetch info for `{repo_name}`."
        try:
            bot.edit_message_text(text, uid, call.message.message_id,
                                  reply_markup=kb_edit_repo_menu(repo_name, False))
        except Exception:
            bot.send_message(uid, text, reply_markup=kb_edit_repo_menu(repo_name, False))
        return

    # Search files in repo
    if data.startswith("er_search_"):
        repo_name = data[len("er_search_"):]
        u = get_user(uid)
        u["draft"]["er_repo"]           = repo_name
        u["draft"]["er_search_mode"]    = True
        save_user(uid, u)
        # We'll reuse a simple state for this — ask for query via text
        # Store pending action in draft and set state for routing
        u["draft"]["er_pending"] = "search"
        save_user(uid, u)
        set_state(uid, State.EDIT_BROWSE)
        try:
            bot.edit_message_text(
                f"🔍 *Search Files in `{repo_name}`*\n\n"
                "Send a *search query* (file name or path fragment):\n"
                "_(e.g. `main`, `utils`, `.py`, `README`)_",
                uid, call.message.message_id,
                reply_markup=kb_edit_cancel(repo_name, ""),
            )
        except Exception:
            bot.send_message(uid, "Send search query:", reply_markup=kb_edit_cancel(repo_name, ""))
        return

    # ── AI provider picker (button-driven /setai) ────────────
    if data.startswith("pick_provider_"):
        provider = data[len("pick_provider_"):]
        if provider not in PROVIDERS:
            bot.send_message(uid, "⚠️ Unknown provider — run /setai again.",
                             reply_markup=kb_provider_picker())
            return
        _prompt_for_ai_key(uid, provider)
        return

    if data in MENU_MAP:
        MENU_MAP[data](call.message)
        return

    # ── My Repos pagination ──────────────────────────────────
    if data.startswith("myrepos_page_"):
        page = int(data[len("myrepos_page_"):])
        u    = get_user(uid)
        u["draft"]["my_repos_page"] = page
        save_user(uid, u)
        _show_my_repos(uid, call.message.message_id, page=page)
        return

    if data == "myrepos_noop":
        return

    if data == "menu_star":
        if not get_user(uid).get("github_token"):
            _send_github_token_guide(uid)
            return
        kb_star = InlineKeyboardMarkup(row_width=2)
        kb_star.add(InlineKeyboardButton("\U0001f3e0 Home", callback_data="menu_home"))
        star_text = (
            "\u2b50 *Star a Repository*\n\n"
            "Usage: `/star_repo OWNER/REPO`\n\n"
            "Example: `/star_repo torvalds/linux`"
        )
        try:
            bot.edit_message_text(
                star_text,
                uid, call.message.message_id,
                parse_mode="Markdown",
                reply_markup=kb_star,
            )
        except Exception:
            bot.send_message(uid, star_text, parse_mode="Markdown", reply_markup=kb_star)
        return

    # ── Safety net: any unrecognized / expired callback ──────
    # Pure no-op buttons (page counters etc.) are intentionally silent.
    if data.endswith("_noop") or data == "admin_noop":
        return
    # Otherwise the button had no handler (e.g. a stale message after a
    # restart). Degrade gracefully instead of a dead tap.
    try:
        _answer(call, "⌛ This action expired — tap 🏠 Home or send /start.")
    except Exception:
        pass
    log.warn("Unhandled callback", str(data))


# ─────────────────────────────────────────────────────────────
#  Multi-archive advance helper
# ─────────────────────────────────────────────────────────────

def _archm_advance(uid: int) -> None:
    """Move to the next archive in the multi queue, or execute all when done."""
    u     = get_user(uid)
    idx   = u["draft"].get("multi_index", 0)
    queue = u["draft"].get("multi_queue", [])
    next_idx = idx + 1
    u["draft"]["multi_index"] = next_idx
    save_user(uid, u)
    if next_idx >= len(queue):
        # All configured — show summary and execute
        total = len(queue)
        lines = [f"✅ *All {total} archives configured!*\n"]
        for i, item in enumerate(queue):
            vis = "🔒" if item.get("private") else "🌍"
            lines.append(f"{i+1}. {vis} `{item.get('name', '?')}` — {len(item.get('files', []))} files")
        lines.append("\n🚀 *Starting upload to GitHub…*")
        msg = bot.send_message(uid, "\n".join(lines))
        _archm_execute_all(uid)
    else:
        _archm_next_step(uid)


# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import time as _poll_time
    import requests as _req
    import logging as _logging

    # Suppress telebot's own ERROR-level logs for known transient errors
    _telebot_logger = _logging.getLogger("TeleBot")
    _telebot_logger.setLevel(_logging.CRITICAL)

    # A leftover webhook (e.g. from a previous hosting service) makes Telegram
    # deliver updates there instead of getUpdates. Polling then retries the
    # resulting 409 Conflict forever with no log line, so the bot looks healthy
    # while every command is silently swallowed. Clear it before polling.
    try:
        _hook_url = bot.get_webhook_info().url
        if _hook_url:
            log.warn("Webhook is still set — removing", _hook_url)
            bot.delete_webhook(drop_pending_updates=False)
            log.ok("Webhook removed — updates will use getUpdates")
    except Exception as _e:
        log.warn("Could not check webhook status", str(_e))

    # 🌸 Confirm Telegram connectivity, then play the kawaii ONLINE flourish.
    # Retry with backoff first — DNS/network often isn't ready in the first
    # second or two of a fresh container (e.g. right after a cold deploy),
    # so a single immediate attempt can fail even though the bot is fine.
    _me = None
    for _attempt, _delay in enumerate((0, 2, 4, 8), start=1):
        if _delay:
            _poll_time.sleep(_delay)
        try:
            _me = bot.get_me()
            log.online(getattr(_me, "username", "") or "")
            break
        except Exception as _e:
            if _attempt < 4:
                log.warn(f"Could not verify bot identity yet (attempt {_attempt}/4) — retrying")
            else:
                # Don't block startup if get_me still fails — polling below has
                # its own retry loop and will recover once DNS/network is up.
                log.warn("Could not verify bot identity after retries — continuing to polling", str(_e))

    if _me is not None:
        _register_command_menu()
    log.ok("Bot is running — polling for updates")

    _TRANSIENT = (
        "Read timed out", "timed out", "NameResolutionError",
        "getaddrinfo", "Max retries exceeded", "Failed to resolve",
        "Connection refused", "ConnectionError", "Bad Gateway",
        "Service Unavailable", "HTTPSConnectionPool",
        "RemoteDisconnected", "EOF occurred",
    )

    while True:
        try:
            bot.infinity_polling(
                timeout              = 30,
                long_polling_timeout = 20,
                # Keep TeleBot's API/polling errors visible in the application
                # log. None disables its logging and made getUpdates conflicts
                # look like a silent hang.
                logger_level         = _logging.ERROR,
                # Telegram keeps the bot's last allowed_updates subscription, and
                # the stale webhook's list had no callback_query — so omitting this
                # left every inline button tap undelivered. Name it explicitly.
                allowed_updates      = ["message", "edited_message", "callback_query"],
            )
            if _polling_conflict:
                log.critical(
                    "Telegram polling stopped: another process is using this bot token. "
                    "Run exactly one bot instance (one container/replica/service) and stop duplicates."
                )
                break
        except KeyboardInterrupt:
            log.warn("Bot stopped by user (Ctrl+C)")
            break
        except (_req.exceptions.ConnectionError,
                _req.exceptions.ReadTimeout,
                _req.exceptions.Timeout,
                OSError) as e:
            log.warn("🔌 Connection lost — retrying in 5 s...")
            _poll_time.sleep(5)
            continue
        except Exception as e:
            err = str(e)
            if any(k in err for k in _TRANSIENT):
                log.warn("🔌 Connection lost — retrying in 5 s...")
                _poll_time.sleep(5)
                continue
            # Keep the service alive after an unexpected library failure. The
            # detailed, redacted error stays in operator logs; users never see
            # stack traces or provider/GitHub response bodies.
            log.critical("Unexpected polling failure — restarting in 10 s", err)
            _poll_time.sleep(10)
            continue
