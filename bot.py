"""
GitHub AI Repo Bot V29
Author  : Saqueeb
Version : 29.0.0

New in V29:
  • Admin Panel (/admin) — live user list, per-user stats, broadcast, ban/unban
  • Admin: promote any user to admin or demote
  • Privacy — sensitive data (tokens, keys) NEVER shown to admin; only visible to
    the owner of that account
  • Per-user history & logs are private — admin cannot view them
  • User data is NOT stored in plain text for admin inspection; admin sees only
    public stats (join date, repos created, banned status, username)
  • Repos-Created counter shown live in admin user list
  • Support command (/support) for users — sends message to admin
  • Admin can reply to support tickets via /reply USER_ID MESSAGE

New in V19:
  • Delete Repository: "Select All" with animation, Cancel button, updated header text
  • Fork Repository: mode picker — Single / Multiple / Cancel
      - Single mode: ask for one GitHub repo URL
      - Multiple mode: collect multiple GitHub repo URLs, fork all
  • Archive Upload — mode picker after clicking the button:
      📁 Single Archive:
          send 1 archive → name → description (+ AI rewrite) → visibility
          → README choice → confirm → upload to GitHub
      📚 Multiple Archives (up to 100):
          send archives one-by-one (tap "Done" when finished)
          → for each archive in turn:
              show extracted file list → ask repo name → ask description
              (+ AI rewrite) → ask README choice
          → upload ALL archives as separate GitHub repos
  • All new flows include smooth loading animations
"""

import base64
import io
import json
import os
import re
import sys
import time as _time
import threading
# ── RAR support: cffi-first (no external tool), then rarfile with auto-detected tool ──
_RARFILE_OK    = False
_rarfile_mod   = None   # 'rarfile' package (needs external tool: unrar / 7z)
_ucffi_rf      = None   # 'unrar-cffi' pure-Python backend (preferred, no external tool)

try:
    from unrar.cffi import rarfile as _ucffi_rf
    _RARFILE_OK = True
except Exception:
    _ucffi_rf = None

if not _RARFILE_OK:
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
from datetime import datetime
from enum import Enum
from typing import Optional

import requests
import telebot
from telebot.types import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

import cli_log as log
import ai_providers as ai
import github_api   as gh
from ai_providers import PROVIDERS, FREE_PROVIDERS
from config import BOT_TOKEN, ADMIN_CHAT_ID, ADMIN_IDS

# ─────────────────────────────────────────────────────────────
#  Sensitive-file helpers
# ─────────────────────────────────────────────────────────────

_SENSITIVE_PATTERNS = [
    (re.compile(r'(?i)(BOT_TOKEN\s*=\s*)["\']?[\w:.\-]{10,}["\']?'),       r'\1"REDACTED"'),
    (re.compile(r'(?i)(ADMIN_CHAT_ID\s*=\s*)\d{5,}'),                       r'\g<1>000000000'),
    (re.compile(r'(?i)(token\s*[=:]\s*)["\']?[\w:.\-]{10,}["\']?'),         r'\1"REDACTED"'),
    (re.compile(r'(?i)(api[_\-]?key\s*[=:]\s*)["\']?[\w:.\-]{10,}["\']?'), r'\1"REDACTED"'),
    (re.compile(r'(?i)(secret\s*[=:]\s*)["\']?[\w:.\-]{10,}["\']?'),        r'\1"REDACTED"'),
    (re.compile(r'(?i)(password\s*[=:]\s*)["\']?\S{4,}["\']?'),             r'\1"REDACTED"'),
    (re.compile(r'(?i)(private_key\s*[=:]\s*)["\']?\S{4,}["\']?'),          r'\1"REDACTED"'),
    (re.compile(r'ghp_[A-Za-z0-9]{10,}'),          'ghp_REDACTED'),
    (re.compile(r'github_pat_[A-Za-z0-9_]{10,}'),  'github_pat_REDACTED'),
    (re.compile(r'\b\d{8,12}:[A-Za-z0-9_\-]{30,}\b'), 'TELEGRAM_TOKEN_REDACTED'),
    (re.compile(r'gsk_[A-Za-z0-9]{20,}'), 'gsk_REDACTED'),
    (re.compile(r'AIza[A-Za-z0-9_\-]{30,}'), 'GOOGLE_KEY_REDACTED'),
]

_SENSITIVE_FILENAMES = {
    "config.py", "config.json", "config.yml", "config.yaml",
    ".env", ".env.local", ".env.production",
    "secrets.json", "secrets.yml", "credentials.json",
    "users.json",
}

def _is_sensitive_filename(fname: str) -> bool:
    base = fname.lower().split("/")[-1]
    return base in _SENSITIVE_FILENAMES

def _scrub_content(content: str) -> tuple:
    scrubbed = content
    count    = 0
    for pattern, replacement in _SENSITIVE_PATTERNS:
        new = pattern.sub(replacement, scrubbed)
        if new != scrubbed:
            count += 1
            scrubbed = new
    return scrubbed, count

def _has_sensitive_content(content: str) -> bool:
    for pattern, _ in _SENSITIVE_PATTERNS:
        if pattern.search(content):
            return True
    return False

# ─────────────────────────────────────────────────────────────
#  Startup
# ─────────────────────────────────────────────────────────────

log.print_banner()
flog = log.setup_file_logger("bot.log")

if not BOT_TOKEN or ":" not in BOT_TOKEN:
    "REDACTED"("Invalid BOT_TOKEN in config.py")
    sys.exit(1)

log.info("Initializing Telegram bot...")

try:
    bot = telebot.TeleBot(BOT_TOKEN, threaded=True, parse_mode="Markdown")
except Exception as e:
    log.critical("Telegram init failed", str(e))
    sys.exit(1)

log.ok("Telegram bot initialized")

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
    ARCHIVE_PASSWORD          = "REDACTED"        # waiting for password (single)
    ARCHIVE_MULTI_PASSWORD    = "REDACTED"  # waiting for password (multi)
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
    # ── Setup ─────────────────────────────────────────────────
    SETUP_GITHUB              = "setup_github"
    # ── Archive AI name/desc suggest ─────────────────────────
    ARCHIVE_AI_SUGGEST        = "archive_ai_suggest"   # single: choosing from AI suggestions
    ARCHIVE_AI_CUSTOM         = "archive_ai_custom"    # single: typing custom name after AI
    ARCHM_AI_SUGGEST          = "archm_ai_suggest"     # multi: choosing from AI suggestions
    ARCHM_AI_CUSTOM           = "archm_ai_custom"      # multi: typing custom name after AI

    DOWNLOAD_PICK             = "download_pick"         # browsing repo list to download

    DOWNLOAD_CONFIRM          = "download_confirm"      # single download confirm
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

# ─────────────────────────────────────────────────────────────
#  Database
# ─────────────────────────────────────────────────────────────

DB_FILE = "users.json"

def _load() -> dict:
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        log.warn("Corrupted users.json — resetting")
        return {}

def _save(data: dict) -> None:
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    flog.debug("DB saved")

_db: dict = _load()
log.ok(f"Database loaded", f"{len(_db)} users")

def get_user(uid: int) -> dict:
    key = str(uid)
    if key not in _db:
        _db[key] = {
            "welcomed":        False,
            "github_token":    None,
            "github_username": None,
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
            "created_at":        datetime.utcnow().isoformat(),
        }
        _save(_db)
    return _db[key]

def save_user(uid: int, data: dict) -> None:
    _db[str(uid)] = data
    _save(_db)

def add_history(uid: int, entry: str) -> None:
    u  = get_user(uid)
    ts = datetime.now().strftime("%d %b %H:%M")
    u["history"].append(f"[{ts}] {entry}")
    u["history"] = u["history"][-50:]
    save_user(uid, u)

def _bump(uid: int, key: str, by: int = 1) -> None:
    """Atomically increment a stats counter."""
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
    """
    Return ONLY non-sensitive stats safe to display in admin panel.
    Tokens, keys, history, draft data are NEVER included.
    """
    u = _db.get(str(uid), {})
    return {
        "uid":           uid,
        "github_user":   u.get("github_username") or "—",
        "ai_provider":   u.get("ai_provider") or "—",
        "repos_created": u.get("repos_created", 0),
        "repos_deleted": u.get("repos_deleted", 0),
        "repos_forked":  u.get("repos_forked", 0),
        "archives_up":   u.get("archives_uploaded", 0),
        "banned":        u.get("banned", False),
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


def ban_user(uid: int) -> None:
    u = get_user(uid)
    u["banned"] = True
    save_user(uid, u)


def unban_user(uid: int) -> None:
    u = get_user(uid)
    u["banned"] = False
    save_user(uid, u)


def is_banned(uid: int) -> bool:
    return get_user(uid).get("banned", False)


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
        InlineKeyboardButton("🏠 Home",             callback_data="menu_home"),
    )
    return kb

def kb_admin_user(uid: int) -> InlineKeyboardMarkup:
    kb  = InlineKeyboardMarkup(row_width=2)
    u   = get_user(uid)
    ban_label    = "✅ Unban"   if u.get("banned")   else "🚫 Ban"
    ban_cb       = f"admin_unban_{uid}" if u.get("banned") else f"admin_ban_{uid}"
    is_adm       = u.get("is_admin", False) or (uid in ADMIN_IDS)
    adm_label    = "⬇️ Demote Admin" if is_adm else "⬆️ Promote Admin"
    adm_cb       = f"admin_demote_{uid}" if is_adm else f"admin_promote_{uid}"
    kb.add(
        InlineKeyboardButton(ban_label, callback_data=ban_cb),
        InlineKeyboardButton(adm_label, callback_data=adm_cb),
        InlineKeyboardButton("◀ Back",  callback_data="admin_users_0"),
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

def kb_admin_users(page: int = 0) -> InlineKeyboardMarkup:
    kb         = InlineKeyboardMarkup(row_width=1)
    all_uids   = list(_db.keys())
    page_size  = 10
    start      = page * page_size
    end        = min(start + page_size, len(all_uids))
    for raw_uid in all_uids[start:end]:
        s     = _public_user_stats(int(raw_uid))
        badge = "🚫" if s["banned"] else ("👑" if s["is_admin"] else "👤")
        label = (f"{badge} {s['uid']} · @{s['github_user']}"
                 f" · 📦{s['repos_created']}")
        kb.add(InlineKeyboardButton(label, callback_data=f"admin_view_{raw_uid}"))
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


def kb_home_only() -> InlineKeyboardMarkup:
    """Single 🏠 Home button — used on result screens."""
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    return kb

def kb_main(uid: int = 0) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    kb.add(
        InlineKeyboardButton("📦 New Repo",       callback_data="menu_create"),
        InlineKeyboardButton("📥 Fork Repo",       callback_data="menu_import"),
        InlineKeyboardButton("📦 Archive Upload",  callback_data="files_archive_upload"),
        InlineKeyboardButton("📋 My Repos",        callback_data="menu_repos"),
        InlineKeyboardButton("✏️ Edit Repo",        callback_data="menu_edit_repo"),
        InlineKeyboardButton("🗑 Delete Repo",     callback_data="menu_delete"),
        InlineKeyboardButton("⬇️ Download Repo",   callback_data="menu_download"),
        InlineKeyboardButton("⭐ Star Repo",        callback_data="menu_star"),
        InlineKeyboardButton("📊 Status",           callback_data="menu_status"),
        InlineKeyboardButton("⚙️ Setup",            callback_data="menu_setup"),
        InlineKeyboardButton("📜 History",          callback_data="menu_history"),
        InlineKeyboardButton("📚 Help",             callback_data="menu_help"),
        InlineKeyboardButton("📖 Guide",            callback_data="menu_guide"),
        InlineKeyboardButton("🤖 AI Models",        callback_data="menu_models"),
        InlineKeyboardButton("🎫 Support",          callback_data="menu_support"),
    )
    if uid and is_admin(uid):
        kb.add(InlineKeyboardButton("🛡 Admin Panel", callback_data="admin_panel"))
    return kb

def kb_main_noback(uid: int = 0) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("📦 New Repo",       callback_data="menu_create"),
        InlineKeyboardButton("📥 Fork Repo",       callback_data="menu_import"),
        InlineKeyboardButton("📦 Archive Upload",  callback_data="files_archive_upload"),
        InlineKeyboardButton("📋 My Repos",        callback_data="menu_repos"),
        InlineKeyboardButton("✏️ Edit Repo",        callback_data="menu_edit_repo"),
        InlineKeyboardButton("🗑 Delete Repo",     callback_data="menu_delete"),
        InlineKeyboardButton("⬇️ Download Repo",   callback_data="menu_download"),
        InlineKeyboardButton("⭐ Star Repo",        callback_data="menu_star"),
        InlineKeyboardButton("📊 Status",           callback_data="menu_status"),
        InlineKeyboardButton("⚙️ Setup",            callback_data="menu_setup"),
        InlineKeyboardButton("📜 History",          callback_data="menu_history"),
        InlineKeyboardButton("📚 Help",             callback_data="menu_help"),
        InlineKeyboardButton("📖 Guide",            callback_data="menu_guide"),
        InlineKeyboardButton("🤖 AI Models",        callback_data="menu_models"),
        InlineKeyboardButton("🎫 Support",          callback_data="menu_support"),
    )
    if uid and is_admin(uid):
        kb.add(InlineKeyboardButton("🛡 Admin Panel", callback_data="admin_panel"))
    return kb

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
        InlineKeyboardButton("↩️ Return",  callback_data="files_archive_upload"),
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
        InlineKeyboardButton("↩️ Return",  callback_data="files_archive_upload"),
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
        InlineKeyboardButton("↩️ Return",  callback_data="cancel"),
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
            InlineKeyboardButton("↩️ Return",    callback_data="menu_delete"),
            InlineKeyboardButton("🏠 Home",      callback_data="menu_home"),
        )
    else:
        kb.add(InlineKeyboardButton("↩️ Return", callback_data="menu_home"))
    return kb


# ─────────────────────────────────────────────────────────────
#  Download Repo — keyboards
# ─────────────────────────────────────────────────────────────

_DL_PAGE_SIZE = 8   # repos shown per page

def kb_download_picker(repos: list, page: int, selected: set) -> InlineKeyboardMarkup:
    """
    Paginated repo picker for download.
    Each repo shown as a tappable button.  Selected ones have ✅.
    Nav: ◀ Prev / Next ▶, Select All / Deselect All, ⬇️ Download, Home.
    """
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
    kb.add(
        InlineKeyboardButton("↩️ Return", callback_data="menu_home"),
        InlineKeyboardButton("🏠 Home",   callback_data="menu_home"),
    )
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
        InlineKeyboardButton("↩️ Return",             callback_data="files_archive_upload"),
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
        InlineKeyboardButton("↩️ Return",            callback_data="menu_create"),
        InlineKeyboardButton("🏠 Home",              callback_data="menu_home"),
    )
    return kb

def kb_files_step() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("📤 Upload File(s)",  callback_data="files_upload"),
        InlineKeyboardButton("📝 Create new file", callback_data="files_create"),
        InlineKeyboardButton("⏭ Skip",            callback_data="files_skip"),
        InlineKeyboardButton("↩️ Return",          callback_data="menu_create"),
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
        InlineKeyboardButton("↩️ Return",          callback_data="menu_create"),
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
    """Shown when user clicks Archive Upload — pick Single or Multiple."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("📁 Single Archive",                    callback_data="arch_mode_single"),
        InlineKeyboardButton("📚 Multiple Archives (up to 100)",     callback_data="arch_mode_multi"),
        InlineKeyboardButton("🤖 AI Repository Name & Description",  callback_data="arch_mode_ai_single"),
        InlineKeyboardButton("🤖 AI Multi-Archive Names & Descs",    callback_data="arch_mode_ai_multi"),
        InlineKeyboardButton("↩️ Return",                            callback_data="menu_home"),
    )
    return kb

def kb_archive_single_prompt() -> InlineKeyboardMarkup:
    """Shown in Single Archive Upload — waiting for file."""
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("↩️ Return",  callback_data="files_archive_upload"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb

def kb_archive_multi_collecting(count: int) -> InlineKeyboardMarkup:
    """Shown while user is sending archives in multi mode."""
    kb = InlineKeyboardMarkup(row_width=1)
    if count > 0:
        kb.add(InlineKeyboardButton(f"✅ Done — Process {count} Archive(s)", callback_data="archm_done_collecting"))
    kb.add(
        InlineKeyboardButton("↩️ Return",  callback_data="files_archive_upload"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb

def kb_archive_multi_name_step() -> InlineKeyboardMarkup:
    """Shown right after archive info in multi-archive flow — ask for repo name."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("✏️ Type repo name",   callback_data="archm_name_type"),
        InlineKeyboardButton("↩️ Return",            callback_data="files_archive_upload"),
        InlineKeyboardButton("🏠 Home",              callback_data="menu_home"),
    )
    return kb

def kb_archive_multi_desc_step() -> InlineKeyboardMarkup:
    """Shown after repo name in multi-archive flow — match single archive style."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("✏️ Type description",  callback_data="archm_desc_type"),
        InlineKeyboardButton("⏭ Skip",               callback_data="archm_desc_skip_now"),
        InlineKeyboardButton("↩️ Return",             callback_data="files_archive_upload"),
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
        InlineKeyboardButton("↩️ Return",  callback_data="files_archive_upload"),
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
        InlineKeyboardButton("↩️ Return",           callback_data="files_archive_upload"),
        InlineKeyboardButton("🏠 Home",             callback_data="menu_home"),
    )
    return kb

def kb_archive_ai_suggest(names: list, descs: list) -> InlineKeyboardMarkup:
    """Show AI-suggested repo names for single archive."""
    kb = InlineKeyboardMarkup(row_width=1)
    for i, n in enumerate(names[:5]):
        kb.add(InlineKeyboardButton(f"📦 {n}", callback_data=f"arch_ai_name_{i}"))
    kb.add(InlineKeyboardButton("✏️ Type custom name", callback_data="arch_ai_custom"))
    kb.add(
        InlineKeyboardButton("🔄 Regenerate",  callback_data="arch_ai_regen"),
        InlineKeyboardButton("↩️ Return",       callback_data="arch_mode_single"),
    )
    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    return kb


def kb_archive_ai_desc(descs: list, chosen_name: str) -> InlineKeyboardMarkup:
    """Show AI-suggested repo descriptions for single archive."""
    kb = InlineKeyboardMarkup(row_width=1)
    for i, d in enumerate(descs[:5]):
        short = d[:80] + "…" if len(d) > 80 else d
        kb.add(InlineKeyboardButton(f"📝 {short}", callback_data=f"arch_ai_desc_{i}"))
    kb.add(InlineKeyboardButton("✏️ Type custom description", callback_data="arch_ai_desc_custom"))
    kb.add(InlineKeyboardButton("⏭ Skip description",        callback_data="arch_ai_desc_skip"))
    kb.add(
        InlineKeyboardButton("🔄 Regenerate",  callback_data="arch_ai_desc_regen"),
        InlineKeyboardButton("↩️ Return",       callback_data="arch_ai_back_names"),
    )
    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    return kb


def kb_archm_ai_suggest(names: list, descs: list) -> InlineKeyboardMarkup:
    """Show AI-suggested repo names for multi-archive (per archive)."""
    kb = InlineKeyboardMarkup(row_width=1)
    for i, n in enumerate(names[:5]):
        kb.add(InlineKeyboardButton(f"📦 {n}", callback_data=f"archm_ai_name_{i}"))
    kb.add(InlineKeyboardButton("✏️ Type custom name", callback_data="archm_ai_custom"))
    kb.add(
        InlineKeyboardButton("🔄 Regenerate",  callback_data="archm_ai_regen"),
        InlineKeyboardButton("↩️ Return",       callback_data="files_archive_upload"),
    )
    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    return kb


def kb_archm_ai_desc(descs: list) -> InlineKeyboardMarkup:
    """Show AI-suggested descriptions for multi-archive (per archive)."""
    kb = InlineKeyboardMarkup(row_width=1)
    for i, d in enumerate(descs[:5]):
        short = d[:80] + "…" if len(d) > 80 else d
        kb.add(InlineKeyboardButton(f"📝 {short}", callback_data=f"archm_ai_desc_{i}"))
    kb.add(InlineKeyboardButton("✏️ Type custom description", callback_data="archm_ai_desc_custom"))
    kb.add(InlineKeyboardButton("⏭ Skip description",        callback_data="archm_ai_desc_skip"))
    kb.add(
        InlineKeyboardButton("🔄 Regenerate",  callback_data="archm_ai_desc_regen"),
        InlineKeyboardButton("↩️ Return",       callback_data="archm_ai_back_names"),
    )
    kb.add(InlineKeyboardButton("🏠 Home", callback_data="menu_home"))
    return kb


def kb_fork_mode() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("🔗 Single",            callback_data="fork_mode_single"),
        InlineKeyboardButton("🔗🔗 Multiple",         callback_data="fork_mode_multi"),
        InlineKeyboardButton("↩️ Return",             callback_data="menu_home"),
    )
    return kb

def kb_fork_confirm(owner: str, repo: str) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton(f"✅ Fork  {owner}/{repo}", callback_data="fork_confirm"),
        InlineKeyboardButton("✏️ Edit URL",              callback_data="fork_edit"),
        InlineKeyboardButton("↩️ Return",                callback_data="menu_import"),
        InlineKeyboardButton("🏠 Home",                  callback_data="menu_home"),
    )
    return kb

def kb_fork_single_prompt() -> InlineKeyboardMarkup:
    """Shown in Fork Single Mode — return to fork picker."""
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("↩️ Return",  callback_data="menu_import"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb

def kb_fork_multi_collecting() -> InlineKeyboardMarkup:
    """Shown in Fork Multi Mode while collecting URLs — return to fork picker."""
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("↩️ Return",  callback_data="menu_import"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb

def kb_fork_multi_done() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("✅ Fork All Now",  callback_data="fork_multi_execute"),
        InlineKeyboardButton("↩️ Return",        callback_data="menu_import"),
        InlineKeyboardButton("🏠 Home",          callback_data="menu_home"),
    )
    return kb

def kb_provider_picker() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    for pid, pinfo in PROVIDERS.items():
        badge = " 🆓" if pinfo["free"] else " 💳"
        kb.add(InlineKeyboardButton(f"{pinfo['emoji']} {pinfo['name']}{badge}", callback_data=f"pick_provider_{pid}"))
    kb.add(
        InlineKeyboardButton("↩️ Return",  callback_data="menu_setup"),
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

    for r in page_repos:
        vis  = "🔒" if r.get("private") else "🌍"
        name = r["name"]
        kb.add(InlineKeyboardButton(f"{vis} {name}", callback_data=f"er_pick_{name}"))

    total_pages = max(1, (total + _EDIT_PAGE_SIZE - 1) // _EDIT_PAGE_SIZE)
    nav_btns = []
    if page > 0:
        nav_btns.append(InlineKeyboardButton("◀ Prev", callback_data=f"er_page_{page-1}"))
    nav_btns.append(InlineKeyboardButton(f"📄 {page+1}/{total_pages}", callback_data="er_noop"))
    if end < total:
        nav_btns.append(InlineKeyboardButton("Next ▶", callback_data=f"er_page_{page+1}"))
    if nav_btns:
        kb.row(*nav_btns)

    kb.add(
        InlineKeyboardButton("↩️ Return", callback_data="menu_home"),
        InlineKeyboardButton("🏠 Home",   callback_data="menu_home"),
    )
    return kb


def kb_edit_repo_menu(repo_name: str, is_private: bool, branch: str = "main") -> InlineKeyboardMarkup:
    """Main edit menu for a selected repo."""
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("📂 Browse Files & Folders", callback_data=f"er_browse_{repo_name}_"),
    )
    kb.add(
        InlineKeyboardButton("📄 New File",         callback_data=f"er_newfile_{repo_name}_"),
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
    kb.add(
        InlineKeyboardButton("↩️ Return", callback_data="menu_edit_repo"),
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
                callback_data=f"er_browse_{repo_name}_{sub_path}",
            ))
        else:
            file_path = item["path"]
            kb.add(InlineKeyboardButton(
                f"📄 {item['name']}",
                callback_data=f"er_file_{repo_name}_{file_path}",
            ))

    total_pages = max(1, (total + PAGE_SZ - 1) // PAGE_SZ)
    if total_pages > 1:
        nav_btns = []
        if page > 0:
            nav_btns.append(InlineKeyboardButton("◀ Prev", callback_data=f"er_bpage_{repo_name}_{path}_{page-1}"))
        nav_btns.append(InlineKeyboardButton(f"📄 {page+1}/{total_pages}", callback_data="er_noop"))
        if end < total:
            nav_btns.append(InlineKeyboardButton("Next ▶", callback_data=f"er_bpage_{repo_name}_{path}_{page+1}"))
        kb.row(*nav_btns)

    # Add new file/folder in current dir
    kb.add(
        InlineKeyboardButton("📄 + New File Here",   callback_data=f"er_newfile_{repo_name}_{path}"),
        InlineKeyboardButton("📁 + New Folder Here", callback_data=f"er_newfolder_{repo_name}_{path}"),
    )
    # Back button: go up one level
    parent = "/".join(path.rstrip("/").split("/")[:-1]) if path and "/" in path else ""
    if path:
        kb.add(InlineKeyboardButton(
            "⬆️ Up a Level",
            callback_data=f"er_browse_{repo_name}_{parent}",
        ))
    kb.add(
        InlineKeyboardButton("↩️ Repo Menu",  callback_data=f"er_repomenu_{repo_name}"),
        InlineKeyboardButton("🏠 Home",       callback_data="menu_home"),
    )
    return kb


def kb_file_actions(repo_name: str, file_path: str) -> InlineKeyboardMarkup:
    """Actions available on a specific file."""
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(InlineKeyboardButton("✏️ Edit Content",     callback_data=f"er_edit_{repo_name}_{file_path}"))
    kb.add(
        InlineKeyboardButton("📋 View Raw",           callback_data=f"er_view_{repo_name}_{file_path}"),
        InlineKeyboardButton("✂️ Move/Rename",        callback_data=f"er_move_{repo_name}_{file_path}"),
    )
    kb.add(InlineKeyboardButton("🗑 Delete File",       callback_data=f"er_del_file_{repo_name}_{file_path}"))
    # Back: go to parent folder
    parent = "/".join(file_path.split("/")[:-1])
    kb.add(
        InlineKeyboardButton("⬆️ Back to Folder",  callback_data=f"er_browse_{repo_name}_{parent}"),
        InlineKeyboardButton("🏠 Home",             callback_data="menu_home"),
    )
    return kb


def kb_edit_cancel(repo_name: str, back_path: str = "") -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("↩️ Return",  callback_data=f"er_browse_{repo_name}_{back_path}"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
    return kb


def kb_confirm_del_file(repo_name: str, file_path: str) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton(
        f"⚠️ Yes, delete {file_path.split('/')[-1]}",
        callback_data=f"er_del_confirm_{repo_name}_{file_path}",
    ))
    kb.add(
        InlineKeyboardButton("❌ Cancel",   callback_data=f"er_file_{repo_name}_{file_path}"),
        InlineKeyboardButton("🏠 Home",    callback_data="menu_home"),
    )
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
            uid, loading_id, reply_markup=kb_home_only(),
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
    owner = u.get("github_username") or gh.get_user(token).get("login", "")
    if not owner:
        bot.edit_message_text("❌ Could not fetch GitHub username.", uid, msg_id, reply_markup=kb_home_only())
        return
    # Cache owner for later use
    u["draft"]["er_owner"]    = owner
    u["draft"]["er_repo"]     = repo_name
    u["draft"]["er_path"]     = ""
    save_user(uid, u)

    info = gh.get_repo_info(token, owner, repo_name)
    if not info:
        bot.edit_message_text("❌ Could not fetch repo info.", uid, msg_id, reply_markup=kb_home_only())
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
        f"✏️ *Edit Repo — `{repo_name}`*\n\n🏷 {vis_txt}  ·  🌿 `{branch}`  ·  💾 {size} KB\n⭐ {stars}  🍴 {forks}  🛠 {lang}\n📝 _{desc}_\n\n_What would you like to do?_"
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
            uid, msg_id, reply_markup=kb_home_only(),
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
    """
    Handle Edit-Repo text input states.
    Returns True if consumed, False otherwise.
    """
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
                f"✅ *Description updated!*\n\n`{repo}`: _{desc}_",
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

@bot.message_handler(commands=["start"])
def cmd_start(m: Message) -> None:
    uid = m.chat.id
    if _check_banned(uid):
        return
    u   = get_user(uid)
    log.user(f"User {uid} /start")
    if not u["welcomed"]:
        text = (
            "🚀✨ *GitHub AI Repo Bot V29* ✨🚀\n\n"
            "Manage GitHub repos with AI — right from Telegram.\n\n"
            "━━━━━━━━━━━━━━━━━\n"
            "⚡ *Quick Setup*\n"
            "━━━━━━━━━━━━━━━━━\n"
            "1️⃣ `/setgithub YOUR_TOKEN`\n"
            "2️⃣ `/setai groq YOUR_KEY` _(free!)_\n"
            "3️⃣ Use the menu to create repos!\n\n"
            "📚 /help · 📖 /guide · 🤖 /models\n\n"
            "👨‍💻 *Creator: Saqueeb* · v29.0.0"
        )
        u["welcomed"] = True
        save_user(uid, u)
    else:
        text = "🏠 *Home* — What would you like to do?"
    bot.send_message(uid, text, reply_markup=kb_main_noback(uid))


# ─────────────────────────────────────────────────────────────
#  /help  /guide  /models
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["help"])
def cmd_help(m: Message) -> None:
    kb_h = InlineKeyboardMarkup(row_width=2)
    kb_h.add(
        InlineKeyboardButton("↩️ Return", callback_data="menu_home"),
        InlineKeyboardButton("🏠 Home",   callback_data="menu_home"),
    )
    bot.send_message(
        m.chat.id,
        "📚 *Commands*\n\n"
        "`/start` — Show main menu\n"
        "`/setgithub TOKEN` — Connect GitHub\n"
        "`/setai PROVIDER KEY` — Set AI provider\n"
        "`/create_new_repo` — Create a new repo\n"
        "`/import_repo [URL]` — Fork a repo\n"
        "`/list_repos` — List your repos\n"
        "`/delete_repo [NAME]` — Delete a repo\n"
        "`/star_repo OWNER/REPO` — Star a repo\n"
        "`/status` — Check your setup\n"
        "`/history` — Recent activity (last 30)\n"
        "`/models` — List AI models\n\n"
        "💡 *New in V22:*\n"
        "• Avatar in /status\n"
        "• Contribution bar in /status\n"
        "• Fork Single/Multi with Cancel & Home\n"
        "• Multi-Archive: name/desc step buttons\n"
        "• Delete picker shows 🔒/🌍 correctly\n",
        reply_markup=kb_h,
    )


@bot.message_handler(commands=["guide"])
def cmd_guide(m: Message) -> None:
    kb_g = InlineKeyboardMarkup(row_width=2)
    kb_g.add(
        InlineKeyboardButton("↩️ Return", callback_data="menu_home"),
        InlineKeyboardButton("🏠 Home",   callback_data="menu_home"),
    )
    bot.send_message(
        m.chat.id,
        "📖 *Setup Guide*\n\n"
        "*1. GitHub Token*\n"
        "Settings → Developer Settings → Personal Access Tokens\n"
        "Scopes needed:\n• ✅ `repo`\n• ✅ `delete_repo`\n\n"
        "Then run: `/setgithub YOUR_TOKEN`\n\n"
        "*2. AI Provider (free options)*\n"
        "• Groq: https://console.groq.com\n"
        "• Gemini: https://aistudio.google.com\n\n"
        "Then run: `/setai groq YOUR_KEY`\n\n"
        "📚 /help for all commands",
        reply_markup=kb_g,
    )


@bot.message_handler(commands=["models"])
def cmd_models(m: Message) -> None:
    lines = ["🤖 *Available AI Providers*\n"]
    for pid, p in PROVIDERS.items():
        badge = "🆓 FREE" if p.get("free") else "💳 Paid"
        lines.append(f"{p['emoji']} *{p['name']}* — {badge}")
        lines.append(f"  Default model: `{p['default']}`")
        lines.append(f"  Usage: `/setai {pid} YOUR_KEY`\n")
    kb_m = InlineKeyboardMarkup(row_width=2)
    kb_m.add(
        InlineKeyboardButton("↩️ Return", callback_data="menu_home"),
        InlineKeyboardButton("🏠 Home",   callback_data="menu_home"),
    )
    bot.send_message(m.chat.id, "\n".join(lines), reply_markup=kb_m)


# ─────────────────────────────────────────────────────────────
#  /status
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["status"])
def cmd_status(m: Message) -> None:
    uid = m.chat.id
    u   = get_user(uid)

    # ── Animated loading ────────────────────────────────────
    msg = bot.send_message(uid, "⏳ Loading status ·")
    _t  = _time.time()

    gh_line      = "❌ Not set"
    gh_extra     = ""
    avatar_url   = None
    gh_profile   = None
    if u.get("github_token"):
        info = _animate(uid, msg.message_id, "Fetching GitHub info", gh.get_user, u["github_token"])
        if info:
            login         = info["login"]
            live_repos    = info.get("public_repos", 0)
            private_count = info.get("total_private_repos", 0)
            followers     = info.get("followers", 0)
            following     = info.get("following", 0)
            disk_usage    = info.get("disk_usage", 0)
            bio           = info.get("bio") or ""
            name          = info.get("name") or login
            avatar_url    = info.get("avatar_url")
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
            gh_line = "⚠️ Token invalid or expired"
    else:
        try:
            bot.edit_message_text("⏳ Loading status ··", uid, msg.message_id)
        except Exception:
            pass

    ai_line = "❌ Not set"
    if u.get("ai_provider"):
        p      = PROVIDERS.get(u["ai_provider"], {})
        badge  = "🆓" if p.get("free") else "💳"
        ai_line = f"✅ {badge} *{u['ai_provider']}* · `{u['ai_model']}`"

    # ── Pull stats ──────────────────────────────────────────
    created      = u.get("repos_created",    0)
    deleted      = u.get("repos_deleted",    0)
    forked       = u.get("repos_forked",     0)
    starred      = u.get("repos_starred",    0)
    archives     = u.get("archives_uploaded",0)
    files_pushed = u.get("files_pushed",     0)
    since        = u.get("created_at", "")[:10]
    elapsed      = _time.time() - _t

    # Build contribution bar (visual progress)
    total_actions = created + deleted + forked + starred + archives
    bar_filled  = min(10, total_actions)
    bar_empty   = 10 - bar_filled
    contrib_bar = "🟩" * bar_filled + "⬜" * bar_empty

    status_text = (
        f"📊 *Account Status*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔑 *GitHub:* {gh_line}{gh_extra}\n\n"
        f"🤖 *AI Provider:* {ai_line}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📈 *Activity Stats*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📦 Repos created:     *{created}*\n"
        f"🗑 Repos deleted:     *{deleted}*\n"
        f"🍴 Repos forked:      *{forked}*\n"
        f"⭐ Repos starred:     *{starred}*\n"
        f"📦 Archives uploaded: *{archives}*\n"
        f"📄 Files pushed:      *{files_pushed}*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🌱 *Contributions*\n"
        f"{contrib_bar}  *{total_actions}* total actions\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🕐 *Member since:* `{since}`\n"
        f"⏱ _Loaded in `{elapsed:.1f}s`_"
    )
    kb_status = InlineKeyboardMarkup(row_width=2)
    if gh_profile:
        kb_status.add(InlineKeyboardButton("👤 View GitHub Profile", url=gh_profile))
    kb_status.add(
        InlineKeyboardButton("↩️ Return", callback_data="menu_home"),
        InlineKeyboardButton("🏠 Home",   callback_data="menu_home"),
    )

    # ── Try to send avatar as photo + caption ────────────────
    # Telegram caps photo captions at 1024 chars; trim safely
    caption_text = status_text if len(status_text) <= 1024 else status_text[:1020] + "…"
    sent = False
    if avatar_url:
        try:
            # Fetch a small 64px avatar instead of full-size
            small_avatar = (avatar_url + "?s=48") if "?" not in avatar_url else (avatar_url + "&s=48")
            bot.delete_message(uid, msg.message_id)
            bot.send_photo(uid, small_avatar, caption=caption_text,
                           parse_mode="Markdown", reply_markup=kb_status)
            sent = True
        except Exception:
            pass
    if not sent:
        try:
            bot.edit_message_text(status_text, uid, msg.message_id,
                                  parse_mode="Markdown", reply_markup=kb_status,
                                  disable_web_page_preview=True)
        except Exception:
            bot.send_message(uid, status_text, parse_mode="Markdown",
                             reply_markup=kb_status, disable_web_page_preview=True)

# ─────────────────────────────────────────────────────────────
#  /history
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["history"])
def cmd_history(m: Message) -> None:
    u    = get_user(m.chat.id)
    hist = u.get("history", [])
    kb_hist = InlineKeyboardMarkup(row_width=2)
    kb_hist.add(
        InlineKeyboardButton("↩️ Return", callback_data="menu_home"),
        InlineKeyboardButton("🏠 Home",   callback_data="menu_home"),
    )
    if not hist:
        bot.send_message(m.chat.id, "📜 No history yet. Create your first repo!",
                         reply_markup=kb_hist)
        return
    entries = hist[-30:]
    text = f"📜 *Recent Activity* (last {len(entries)})\n\n"
    for h in entries:
        text += f"• {h}\n"
    bot.send_message(m.chat.id, text, reply_markup=kb_hist)


# ─────────────────────────────────────────────────────────────
#  /admin  — Admin Panel (admin-only command)
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["admin"])
def cmd_admin(m: Message) -> None:
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
    tickets      = [u for u in _db.values() if u.get("pending_tickets")]
    text = (
        "🛡 *Admin Panel* — V29\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        f"👥 Total users:     *{total_users}*\n"
        f"🚫 Banned users:    *{banned_count}*\n"
        f"👑 Admins:          *{admin_count}*\n"
        f"📦 Total repos created: *{total_repos}*\n"
        f"🎫 Pending tickets: *{len(tickets)}*\n\n"
        "_Sensitive data (tokens/keys/history) is never shown here._"
    )
    bot.send_message(uid, text, parse_mode="Markdown", reply_markup=kb_admin_main())


# ─────────────────────────────────────────────────────────────
#  /addadmin USER_ID  — Promote a user to admin
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["addadmin"])
def cmd_addadmin(m: Message) -> None:
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
    uid = m.chat.id
    if not is_admin(uid):
        bot.send_message(uid, "🚫 *Access denied.*", parse_mode="Markdown")
        return
    parts = m.text.strip().split()
    if len(parts) < 2 or not parts[1].isdigit():
        bot.send_message(uid, "Usage: `/ban USER_ID`", parse_mode="Markdown")
        return
    target = int(parts[1])
    if target in ADMIN_IDS:
        bot.send_message(uid, "🚫 Cannot ban an admin.", parse_mode="Markdown")
        return
    ban_user(target)
    bot.send_message(uid, f"✅ User `{target}` has been banned.", parse_mode="Markdown")
    try:
        bot.send_message(target,
            "🚫 *Your account has been suspended.*\n\nContact support if you think this is a mistake.",
            parse_mode="Markdown")
    except Exception:
        pass


@bot.message_handler(commands=["unban"])
def cmd_unban(m: Message) -> None:
    uid = m.chat.id
    if not is_admin(uid):
        bot.send_message(uid, "🚫 *Access denied.*", parse_mode="Markdown")
        return
    parts = m.text.strip().split()
    if len(parts) < 2 or not parts[1].isdigit():
        bot.send_message(uid, "Usage: `/unban USER_ID`", parse_mode="Markdown")
        return
    target = int(parts[1])
    unban_user(target)
    bot.send_message(uid, f"✅ User `{target}` has been unbanned.", parse_mode="Markdown")
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
    all_uids = list(_db.keys())
    status_msg = bot.send_message(uid, f"📢 Broadcasting to {len(all_uids)} users…")
    for raw_uid in all_uids:
        target = int(raw_uid)
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
    uid = m.chat.id
    if _check_banned(uid):
        return
    parts = m.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        kb_sp = InlineKeyboardMarkup(row_width=2)
        kb_sp.add(
            InlineKeyboardButton("↩️ Return", callback_data="menu_home"),
            InlineKeyboardButton("🏠 Home",   callback_data="menu_home"),
        )
        bot.send_message(uid,
            "🎫 *Support*\n\nUsage: `/support YOUR MESSAGE`\n\n"
            "Example: `/support I cannot connect my GitHub token`",
            parse_mode="Markdown", reply_markup=kb_sp)
        return
    ticket_text = parts[1]
    u = get_user(uid)
    gh_user = u.get("github_username") or "unknown"
    # Notify all admins
    admin_msg = (
        f"🎫 *New Support Ticket*\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"👤 User ID: `{uid}`\n"
        f"🐙 GitHub: `{gh_user}`\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"{ticket_text}\n"
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
            reply_markup=kb_home_only())
    else:
        bot.send_message(uid,
            "⚠️ Could not reach support right now. Please try again later.",
            parse_mode="Markdown",
            reply_markup=kb_home_only())


# ─────────────────────────────────────────────────────────────
#  /reply USER_ID MESSAGE  — Admin replies to a support ticket
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["reply"])
def cmd_reply(m: Message) -> None:
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
            f"🎫 *Support Reply*\n\n{reply_text}",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup().add(
                InlineKeyboardButton("🎫 Reply again", callback_data="menu_support"),
                InlineKeyboardButton("🏠 Home", callback_data="menu_home"),
            ))
        bot.send_message(uid, f"✅ Reply sent to `{target}`.", parse_mode="Markdown")
    except Exception as e:
        bot.send_message(uid, f"❌ Could not send reply: `{e}`", parse_mode="Markdown")


# ─────────────────────────────────────────────────────────────
#  /setgithub
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["setgithub"])
def cmd_setgithub(m: Message) -> None:
    parts = m.text.strip().split(maxsplit=1)
    uid   = m.chat.id
    if _check_banned(uid):
        return
    if len(parts) < 2:
        set_state(uid, State.SETUP_GITHUB)
        bot.send_message(uid, "🔑 Send your GitHub Personal Access Token now:")
        return
    _apply_github_token(uid, parts[1].strip())


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
        bot.edit_message_text(
            f"✅ GitHub connected as *{login}*  ⏱ `{(_time.time()-_t):.1f}s`\n"
            f"📦 {info.get('public_repos', 0)} public repos",
            uid, msg.message_id,
        )
        add_history(uid, f"GitHub token saved for {login}")
    else:
        bot.edit_message_text(
            "❌ *Token verification failed.*\n\n"
            "Make sure your token:\n• Has the `repo` scope\n• Is not expired\n• Starts with `ghp_`",
            uid, msg.message_id,
        )


# ─────────────────────────────────────────────────────────────
#  /setai
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["setai"])
def cmd_setai(m: Message) -> None:
    parts = m.text.strip().split()
    uid   = m.chat.id
    if len(parts) < 3:
        bot.send_message(uid,
            "⚙️ *Usage:*\n`/setai PROVIDER YOUR_KEY [MODEL]`\n\n"
            "*Examples (Free):*\n`/setai groq gsk_xxx`\n`/setai gemini AIza_xxx`\n\nSee all: /models")
        return
    provider = parts[1].lower()
    api_key  = parts[2]
    pinfo    = PROVIDERS.get(provider)
    if not pinfo:
        known = ", ".join(f"`{p}`" for p in PROVIDERS)
        bot.send_message(uid, f"❌ Unknown provider `{provider}`.\n\nAvailable: {known}")
        return
    model = parts[3] if len(parts) >= 4 else pinfo["default"]
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
        save_user(uid, u)
        bot.edit_message_text(
            f"✅ AI configured!  ⏱ `{(_time.time()-_t):.1f}s`\n\n"
            f"{pinfo['emoji']} *{pinfo['name']}* {badge}\nModel: `{model}`",
            uid, msg.message_id,
        )
        add_history(uid, f"AI set: {provider}/{model}")
    else:
        bot.edit_message_text(err or "❌ Unknown error.", uid, msg.message_id)


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
    uid = m.chat.id
    u   = get_user(uid)
    if not u.get("github_token"):
        bot.send_message(uid, "⚠️ Set your GitHub token first.")
        return
    _t    = _time.time()
    msg   = bot.send_message(uid, "⏳ Fetching repositories ·")
    repos = _animate(uid, msg.message_id, "Fetching repositories",
                     gh.list_all_repos, u["github_token"])
    if not repos:
        bot.edit_message_text("📦 No repositories found.", uid, msg.message_id,
                              reply_markup=kb_home_only())
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
    uid = m.chat.id
    u   = get_user(uid)
    if not u.get("github_token"):
        bot.send_message(uid, "⚠️ Set your GitHub token first: `/setgithub YOUR_TOKEN`")
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
    uid   = m.chat.id
    u     = get_user(uid)
    parts = m.text.strip().split(maxsplit=1)
    if not u.get("github_token"):
        bot.send_message(uid, "⚠️ Set your GitHub token first.")
        return
    if len(parts) >= 2:
        _confirm_delete(uid, parts[1].strip())
        return
    _show_delete_picker(uid)



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
            uid, loading_id, reply_markup=kb_home_only(),
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
        bot.answer_callback_query
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

    success = []
    failed  = []

    for i, repo_name in enumerate(selected):
        repo_info = next((r for r in repos if r["name"] == repo_name), None)
        is_private = repo_info.get("private", False) if repo_info else False
        vis_icon   = "🔒" if is_private else "🌍"

        try:
            bot.edit_message_text(
                f"⬇️ Downloading `{repo_name}` ({i+1}/{len(selected)}) ···",
                uid, msg_id,
            )
        except Exception:
            pass

        try:
            # Get default branch info first
            repo_meta = gh.get_repo_info(token, owner, repo_name)
            branch    = (repo_meta or {}).get("default_branch", "HEAD")

            # Download zipball
            zip_bytes = gh.download_repo_zipball(token, owner, repo_name, branch)
            if not zip_bytes:
                failed.append(repo_name)
                continue

            # Repack zip — rename root folder → repo_name/
            import zipfile
            import io as _io
            raw_io   = _io.BytesIO(zip_bytes)
            out_io   = _io.BytesIO()
            with zipfile.ZipFile(raw_io, "r") as zin:
                namelist = zin.namelist()
                # GitHub zip root is like "owner-repo-sha/" — strip to repo_name/
                root_prefix = namelist[0].split("/")[0] + "/" if namelist else ""
                with zipfile.ZipFile(out_io, "w", zipfile.ZIP_DEFLATED) as zout:
                    for item in zin.infolist():
                        new_name = item.filename
                        if root_prefix and new_name.startswith(root_prefix):
                            new_name = repo_name + "/" + new_name[len(root_prefix):]
                        if not new_name or new_name.endswith("/"):
                            continue
                        zout.writestr(new_name, zin.read(item.filename))

            out_io.seek(0)
            final_bytes = out_io.read()
            size_kb     = len(final_bytes) / 1024

            # Send the file to user
            fname = f"{repo_name}.zip"
            bot.send_document(
                uid,
                (fname, final_bytes),
                caption=(
                    f"✅ *{vis_icon} {repo_name}*\n"
                    f"📦 `{fname}`  ·  `{size_kb:.0f} KB`\n"
                    f"🌿 Branch: `{branch}`\n"
                    f"👤 Owner: `{owner}`"
                ),
                parse_mode="Markdown",
            )
            success.append(repo_name)

        except Exception as ex:
            failed.append(repo_name)
            log.error(f"Download failed for {repo_name}", str(ex)[:100])

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
        InlineKeyboardButton("↩️ Return",  callback_data="menu_delete"),
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
#  Fork Repo — V19: Single / Multiple modes
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["import_repo"])
def cmd_import_repo(m: Message) -> None:
    uid   = m.chat.id
    u     = get_user(uid)
    parts = m.text.strip().split(maxsplit=1)
    if not u.get("github_token"):
        bot.send_message(uid, "⚠️ Set your GitHub token first.")
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
            reply_markup=kb_home_only())
        add_history(uid, f"Forked {owner}/{repo}")
        _bump(uid, "repos_forked")
    except gh.GitHubError as e:
        bot.edit_message_text(f"❌ Fork failed: `{e.message}`", uid, msg_id,
                              reply_markup=kb_home_only())
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
                              reply_markup=kb_home_only())
    except Exception:
        bot.send_message(uid, "\n".join(lines),
                         disable_web_page_preview=True,
                         reply_markup=kb_home_only())
    u["draft"].pop("fork_multi_urls", None)
    save_user(uid, u)
    set_state(uid, State.IDLE)


# ─────────────────────────────────────────────────────────────
#  /star_repo
# ─────────────────────────────────────────────────────────────

@bot.message_handler(commands=["star_repo"])
def cmd_star_repo(m: Message) -> None:
    uid   = m.chat.id
    parts = m.text.strip().split(maxsplit=1)
    u     = get_user(uid)
    if not u.get("github_token"):
        bot.send_message(uid, "⚠️ Set your GitHub token first.")
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


def _bot_notify(uid: int, msg_id: int, text: str, reply_markup=None, parse_mode: str = "Markdown") -> None:
    """Edit an existing message; if that fails (too old, deleted, etc.) send a fresh one.
    This ensures the user always sees the latest status even in long flows."""
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
    """Convert RAR bytes → ZIP bytes in-memory.
    Uses unrar-cffi (pure Python, no external tool) if available,
    then falls back to rarfile with auto-detected unrar/7z."""
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
                    "REDACTED" ArchivePasswordRequired()
                if password:
                    "REDACTED"
                zip_buf = io.BytesIO()
                with _zipfile.ZipFile(zip_buf, "w", _zipfile.ZIP_DEFLATED) as zout:
                    for member in rf.infolist():
                        if not member.is_dir():
                            try:
                                data = rf.read(member)
                                zout.writestr(member.filename, data)
                            except (_rarfile_mod.RarWrongPassword, _rarfile_mod.RarCRCError):
                                raise ArchivePasswordWrong()
                return zip_buf.getvalue()

        raise ValueError("No RAR extraction backend available.")

    finally:
        _os.unlink(_tmp_path)


def _extract_archive(raw_bytes: bytes, filename: str, password: str = None) -> list:
    """
    Extract archive bytes → list of {path, content_b64}.
    Supports: .zip, .tar.gz, .tgz, .tar.bz2, .tar.xz, .tar, .rar
    RAR files are auto-converted to ZIP if rarfile is available, otherwise raises a clear error.
    Pass password=str to unlock encrypted archives.
    Raises ArchivePasswordRequired if encrypted and no password given.
    Raises ArchivePasswordWrong if password is incorrect.
    """
    import zipfile, tarfile
    files = []
    fname = filename.lower()
    pwd_bytes = password.encode() if password else None

    def _add(path, data):
        if "__MACOSX" in path or path.endswith(".DS_Store"):
            return
        if not path or path.endswith("/"):
            return
        files.append({"path": path, "content_b64": base64.b64encode(data).decode()})

    # ── RAR: auto-convert to ZIP first ──────────────────────────────────────
    if fname.endswith(".rar"):
        if not _RARFILE_OK:
            raise ValueError(
                "RAR support requires the `rarfile` package.\n"
                "Install it on your server: `pip install rarfile unrar-cffi`"
            )
        # Convert RAR → ZIP in-memory, then fall through to ZIP extraction
        raw_bytes = _rar_to_zip_bytes(raw_bytes, password="REDACTED"
        fname = fname[:-4] + ".zip"
        # password already consumed during conversion — don't pass it again
        pwd_bytes = None
        password = "REDACTED"

    if fname.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
            # detect encryption
            encrypted = any(bool(m.flag_bits & 0x1) for m in zf.infolist() if not m.is_dir())
            if encrypted and not pwd_bytes:
                raise ArchivePasswordRequired()
            for member in zf.infolist():
                if not member.is_dir():
                    try:
                        with zf.open(member, pwd=pwd_bytes) as f:
                            _add(member.filename, f.read())
                    except RuntimeError as e:
                        if "password" in str(e).lower() or "bad password" in str(e).lower():
                            raise ArchivePasswordWrong()
                        raise
                    except Exception:
                        # Skip unreadable members instead of crashing entire archive
                        pass

    elif any(fname.endswith(ext) for ext in (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        # tar archives don't support native encryption — extract normally
        with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:*") as tf:
            for member in tf.getmembers():
                if member.isfile():
                    try:
                        f = tf.extractfile(member)
                        if f:
                            _add(member.name, f.read())
                    except Exception:
                        pass

    else:
        raise ValueError(
            f"Unsupported archive format: `{filename}`\n"
            "Supported: `.zip` · `.tar.gz` · `.tgz` · `.tar.bz2` · `.tar.xz` · `.tar` · `.rar`"
        )

    return files


def _strip_top_folder(files: list) -> list:
    """Strip common single top-level folder prefix if all files share it."""
    if not files:
        return files
    parts = [f["path"].split("/") for f in files]
    if all(len(p) > 1 for p in parts):
        tops = {p[0] for p in parts}
        if len(tops) == 1:
            prefix = tops.pop() + "/"
            return [{"path": f["path"][len(prefix):], "content_b64": f["content_b64"]} for f in files]
    return files


def _push_one_file(token: str, owner: str, repo: str, path: str, content_b64: str, retries: int = 5) -> bool:
    """
    Upload a single file to GitHub with automatic SHA refresh and retry.
    Uses exponential back-off. Returns True on success.
    """
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    url     = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    for attempt in range(retries):
        try:
            # Always fetch fresh SHA — avoids 422 conflicts from stale SHA
            sha_r = requests.get(url, headers=headers, timeout=20)
            sha   = sha_r.json().get("sha") if sha_r.status_code == 200 else None
            payload = {"message": f"Add {path}", "content": content_b64}
            if sha:
                payload["sha"] = sha
            r = requests.put(url, headers=headers, json=payload, timeout=60)
            if r.status_code in (200, 201):
                return True
            # 409 = conflict (e.g. parallel write), 422 = stale SHA → retry
            if r.status_code in (409, 422) and attempt < retries - 1:
                _time.sleep(1.0 * (attempt + 1))
                continue
            # 403/429 = rate-limited → back off longer
            if r.status_code in (403, 429) and attempt < retries - 1:
                retry_after = int(r.headers.get("Retry-After", 5))
                _time.sleep(max(retry_after, 3 * (attempt + 1)))
                continue
            # 5xx server errors → retry with backoff
            if r.status_code >= 500 and attempt < retries - 1:
                _time.sleep(2 * (attempt + 1))
                continue
        except requests.RequestException:
            if attempt < retries - 1:
                _time.sleep(1.0 * (attempt + 1))
    return False


def _push_archive_files(token: str, owner: str, repo: str, files: list, msg_id: int, uid: int) -> tuple:
    """Push all extracted files to GitHub with concurrency + per-file retry.
    Returns (ok_count, fail_count, failed_names_list)."""
    import concurrent.futures, threading as _threading

    total        = len(files)
    ok_count     = 0
    fail_count   = 0
    failed_names = []
    counter_lock = _threading.Lock()
    done_counter = [0]

    # Safe concurrency: 5 workers avoids GitHub secondary-rate-limit (10 req/s per repo)
    MAX_WORKERS = 5

    def _scrub_and_upload(fobj):
        nonlocal ok_count, fail_count
        path        = fobj["path"]
        content_b64 = fobj["content_b64"]
        # Scrub sensitive files
        if _is_sensitive_filename(path):
            try:
                raw_text = base64.b64decode(content_b64).decode("utf-8", errors="replace")
                scrubbed, _ = _scrub_content(raw_text)
                content_b64 = base64.b64encode(scrubbed.encode("utf-8")).decode()
            except Exception:
                pass

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
        if done == 1 or done % 5 == 0 or done == total:
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

    return ok_count, fail_count, failed_names


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
    is_private = u["draft"].get("private", False)
    if not is_private and (_is_sensitive_filename(filename) or _has_sensitive_content(content)):
        content, _ = _scrub_content(content)
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

def _ai_rewrite_readme(u: dict, repo_name: str, desc: str, existing_readme: str) -> str:
    """Rewrite an existing README using AI. Matches New Repo quality."""
    prompt = (
        "You are a senior developer improving a GitHub README.md.\n\n"
        + f"Project name: {repo_name}\n"
        + f"Description: {desc or 'Not provided'}\n\n"
        + "Original README (preserve all real information):\n---\n"
        + existing_readme[:3500]
        + "\n---\n\n"
        + "Rewrite and improve this README.md to professional GitHub standard.\n\n"
        + "Rules:\n"
        + "— Keep ALL real information from the original\n"
        + "— Improve structure, formatting, and clarity\n"
        + "— Add any missing standard sections (Installation, Usage, Contributing, License)\n"
        + "— Use proper Markdown: headings, code blocks, bullet lists\n"
        + "— Emoji on section headers only\n"
        + "— Professional, direct tone — no fluff\n\n"
        + "Output ONLY the improved Markdown. No preamble, no explanation."
    )
    result, _ = ai.generate_safe(u["ai_provider"], u["ai_key"], u["ai_model"], prompt, max_tokens=2000)
    return (result or existing_readme).strip()

def _ai_generate_readme(u: dict, repo_name: str, desc: str) -> str:
    """Generate a professional README. Matches New Repo quality."""
    prompt = (
        "You are a senior developer writing a GitHub README.md for a new project.\n\n"
        + f"Project name: {repo_name}\n"
        + f"Description: {desc or 'Not provided'}\n\n"
        + "Write a complete, professional README.md in clean Markdown.\n\n"
        + "Required sections (in order):\n"
        + "1. # Project Title with a relevant emoji\n"
        + "2. Short description paragraph\n"
        + "3. ## ✨ Features — 4 to 6 specific, technical bullet points\n"
        + "4. ## 📦 Installation — step-by-step with code blocks\n"
        + "5. ## 🚀 Usage — practical example with code block\n"
        + "6. ## 🤝 Contributing — brief guide\n"
        + "7. ## 📄 License — MIT\n\n"
        + "Style rules:\n"
        + "— Professional and precise — no fluff\n"
        + "— Proper Markdown: headings, bold, code blocks, bullet lists\n"
        + "— Emoji only in section headers\n"
        + "— Write as if this will be public on GitHub immediately\n\n"
        + "Output ONLY the Markdown content. No preamble, no explanation."
    )
    result, _ = ai.generate_safe(u["ai_provider"], u["ai_key"], u["ai_model"], prompt, max_tokens=1800)
    return (result or "").strip()

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

def _ai_suggest_names_and_descs(u: dict, files: list, archive_fname: str) -> tuple:
    """
    Analyze archive file paths and generate 5 repo name + 5 description suggestions.
    Returns (names: list[str], descs: list[str]).
    Descriptions up to 300 chars. Professional Base-style tone.
    """
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
        + "1. First professional description, max 300 characters.\n"
        + "2. Second professional description, max 300 characters.\n"
        + "3. Third professional description, max 300 characters.\n"
        + "4. Fourth professional description, max 300 characters.\n"
        + "5. Fifth professional description, max 300 characters.\n\n"
        + "Rules for NAMES:\n"
        + "— Lowercase, hyphens only (no spaces, no underscores, no dots)\n"
        + "— 2 to 5 words\n"
        + "— Specific to what the project does\n"
        + "— No filler: project, app, tool, repo, code\n\n"
        + "Rules for DESCRIPTIONS:\n"
        + "— Professional, direct, specific — like a GitHub repo description\n"
        + "— One or two sentences\n"
        + "— State what the project does and the tech/language it uses\n"
        + "— Maximum 300 characters each\n"
        + "— No generic phrases like: this is a project, this repo contains\n"
        + "— Each description must be unique"
    )

    names, descs = [], []
    raw, err = ai.generate_safe(u["ai_provider"], u["ai_key"], u["ai_model"], combined_prompt, max_tokens=700)
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
    """
    Single archive upload flow:
    Download → extract → ask name → desc → visibility → README → confirm → push
    """
    u     = get_user(uid)
    fname = m.document.file_name or "archive.zip"
    msg   = bot.send_message(uid, f"📦 Downloading `{fname}` ·")
    try:
        file_info = bot.get_file(m.document.file_id)
        raw       = _animate(uid, msg.message_id, f"Downloading `{fname}`",
                             bot.download_file, file_info.file_path)
        _bot_notify(uid, msg.message_id, f"⏳ Extracting `{fname}` ···")
        # Try extraction (password may be needed)
        saved_password = "REDACTED"
        try:
            files = _extract_archive(raw, fname, password="REDACTED"
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

        files  = _strip_top_folder(files)
        if not files:
            _bot_notify(uid, msg.message_id, "❌ Archive is empty or contains no extractable files.")
            return
        readme_file    = next((f for f in files if os.path.basename(f["path"]).lower() == "readme.md"), None)
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
            if names:
                try:
                    bot.edit_message_text(
                        "\U0001f916 *AI Repository Name Suggestions*\n\n"
                        f"\U0001f4e6 `{fname}` \u2014 {len(files)} files"
                        + ("\n\U0001f4c4 README found" if readme_file else "")
                        + "\n\n\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n\n"
                        "Choose a suggested name or type your own:",
                        uid, msg.message_id,
                        reply_markup=kb_archive_ai_suggest(names, descs),
                    )
                except Exception:
                    bot.send_message(
                        uid,
                        "\U0001f916 AI name suggestions ready. Choose or type your own:",
                        reply_markup=kb_archive_ai_suggest(names, descs),
                    )
            else:
                bot.edit_message_text(
                    "\u26a0\ufe0f AI suggestions unavailable. Please type the repo name manually.",
                    uid, msg.message_id,
                )
        else:
            bot.edit_message_text(
                "\u2705 *Archive extracted!*\n\n"
                f"\U0001f4e6 `{fname}` \u2192 *{len(files)} files* ready\n"
                + ("\U0001f4c4 README.md detected!\n" if readme_file else "\U0001f4c4 No README.md found\n")
                + "\n\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n\n"
                "\U0001f524 *Step 1 \u2014 Repository Name*\n\n"
                "What should the repository be called?\n\n"
                "_Lowercase \u00b7 hyphens \u00b7 no spaces_\n\nExample: `my-awesome-project`",
                uid, msg.message_id,
            )
        log.event(f"User {uid} started single archive upload: {fname}, {len(files)} files")
    except Exception as ex:
        _bot_notify(uid, msg.message_id, f"❌ Archive error: `{ex}`")


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
    fcount = len(u["draft"].get("archive_files", []))
    readme = u["draft"].get("archive_readme", "")
    text = (
        "━━━━━━━━━━━━━━━━━━━━\n\n🔍 *Confirm Archive Upload*\n\n"
        f"📦 *Name:* `{name}`\n📝 *Desc:* _{desc}_\n"
        f"👁 *Visibility:* {vis}\n📁 *Files:* {fcount} files\n"
        f"📄 *README:* {'✅ Included' if readme else '—'}\n\n"
        "_Ready to create repo and upload all files?_"
    )
    if msg_id:
        try:
            bot.edit_message_text(text, uid, msg_id, reply_markup=kb_archive_confirm())
            return
        except Exception:
            pass
    bot.send_message(uid, text, reply_markup=kb_archive_confirm())


def _execute_archive_upload(uid: int, msg_id: int) -> None:
    """Create repo + push all archive files (single mode)."""
    u       = get_user(uid)
    name    = u["draft"].get("name", "new-repo")
    desc    = u["draft"].get("description", "")
    private = u["draft"].get("private", False)
    files   = u["draft"].get("archive_files", [])
    readme  = u["draft"].get("archive_readme", "")
    token   = u["github_token"]
    _t      = _time.time()

    # Inject README into files list
    if readme:
        files = [f for f in files if os.path.basename(f["path"]).lower() != "readme.md"]
        files.insert(0, {"path": "README.md", "content_b64": base64.b64encode(readme.encode("utf-8")).decode()})

    try:
        bot.edit_message_text("⏳ Creating repository ·", uid, msg_id)
        repo_data = _animate(uid, msg_id, "Creating repository",
                            gh.create_repo, token, name, desc, private, False)
    except Exception as ex:
        bot.edit_message_text(f"❌ Failed to create repo: `{ex}`", uid, msg_id)
        return

    info = gh.get_user(token)
    if not info:
        bot.edit_message_text("❌ Could not determine GitHub username.", uid, msg_id)
        return
    owner    = info["login"]
    ok_count, fail_count, failed_names = _push_archive_files(token, owner, name, files, msg_id, uid)
    elapsed  = _time.time() - _t
    repo_url = repo_data.get("html_url", f"https://github.com/{owner}/{name}")

    failed_lines = ""
    if fail_count and failed_names:
        names_str = "\n".join(f"  • `{n}`" for n in failed_names[:20])
        if len(failed_names) > 20:
            names_str += f"\n  • … and {len(failed_names) - 20} more"
        failed_lines = f"\n❌ Failed: *{fail_count}* files\n{names_str}\n"

    archive_lines = [
        f"🎉 *Archive Upload Complete!*",
        f"",
        f"📦 [`{owner}/{name}`]({repo_url})",
        f"⏱ Done in `{elapsed:.1f}s`",
        f"",
        f"✅ Uploaded: *{ok_count}* files",
    ]
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
                              reply_markup=kb_home_only())
    except Exception:
        bot.send_message(uid, result_text, parse_mode="Markdown",
                         disable_web_page_preview=True,
                         reply_markup=kb_home_only())

    add_history(uid, f"Archive uploaded: {name} ({ok_count} files)")
    u["repos_created"]     = u.get("repos_created", 0) + 1
    u["archives_uploaded"] = u.get("archives_uploaded", 0) + 1
    u["files_pushed"]      = u.get("files_pushed", 0) + ok_count
    u["draft"] = {}
    save_user(uid, u)
    set_state(uid, State.IDLE)
    log.ok(f"Archive upload complete: {owner}/{name}", f"{ok_count} files in {elapsed:.1f}s")


# ─────────────────────────────────────────────────────────────
#  Archive Upload — Multiple mode helpers
# ─────────────────────────────────────────────────────────────

def _archm_next_step(uid: int) -> None:
    """
    Drive the per-archive wizard for multi-archive mode.
    Looks at multi_queue[multi_index] and starts the wizard:
      → ask name → ask desc → ask visibility → ask README
    When index reaches end → execute all uploads.
    """
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
        if names:
            try:
                bot.edit_message_text(
                    (
                        f"\U0001f916 *AI Suggestions for Archive {idx+1}/{len(queue)}*\n\n"
                        f"\U0001f4e6 `{fname}` \u2014 {fcount} files\n\n"
                        "\u2501" * 20 + "\n\n"
                        "Choose a repository name or type your own:"
                    ),
                    uid, loading_msg.message_id,
                    reply_markup=kb_archm_ai_suggest(names, descs),
                )
            except Exception:
                bot.send_message(
                    uid,
                    "\U0001f916 Choose a name or type your own:",
                    reply_markup=kb_archm_ai_suggest(names, descs),
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
    """Execute all queued archive uploads as separate GitHub repos."""
    u     = get_user(uid)
    queue = u["draft"].get("multi_queue", [])
    token = u["github_token"]
    _t    = _time.time()

    info = gh.get_user(token)
    if not info:
        bot.send_message(uid, "❌ Could not verify GitHub username.")
        return
    owner = info["login"]

    msg = bot.send_message(uid, f"🚀 *Uploading {len(queue)} repositories…*")

    summary_lines = [f"🎉 *Multi-Archive Upload Complete!*\n"]

    for i, item in enumerate(queue):
        name    = item.get("name", f"archive-{i+1}")
        desc    = item.get("description", "")
        private = item.get("private", False)
        readme  = item.get("readme_content", "")
        files   = list(item.get("files", []))

        # Inject README
        if readme:
            files = [f for f in files if os.path.basename(f["path"]).lower() != "readme.md"]
            files.insert(0, {
                "path":        "README.md",
                "content_b64": base64.b64encode(readme.encode("utf-8")).decode(),
            })

        try:
            bot.edit_message_text(
                f"⏳ *Creating repo {i+1}/{len(queue)}:* `{name}` ···",
                uid, msg.message_id,
            )
        except Exception:
            pass

        try:
            repo_data = gh.create_repo(token, name, desc, private, False)
            _it = _time.time()
            ok_count, fail_count, failed_names = _push_archive_files(token, owner, name, files, msg.message_id, uid)
            elapsed = _time.time() - _it
            repo_url = repo_data.get("html_url", f"https://github.com/{owner}/{name}")
            line = (
                f"✅ [`{name}`]({repo_url}) — {ok_count} files  ⏱ `{elapsed:.1f}s`"
            )
            if fail_count and failed_names:
                short = ", ".join(f"`{n}`" for n in failed_names[:5])
                if len(failed_names) > 5:
                    short += f" +{len(failed_names)-5} more"
                line += f"\n  ❌ {fail_count} failed: {short}"
            elif fail_count:
                line += f"  ❌ {fail_count} failed"
            summary_lines.append(line)
            add_history(uid, f"Archive uploaded: {name} ({ok_count} files)")
            u["repos_created"]     = u.get("repos_created", 0) + 1
            u["archives_uploaded"] = u.get("archives_uploaded", 0) + 1
            u["files_pushed"]      = u.get("files_pushed", 0) + ok_count
            save_user(uid, u)
        except Exception as ex:
            summary_lines.append(f"❌ `{name}` — failed: `{ex}`")

        _time.sleep(0.5)

    total_elapsed = _time.time() - _t
    summary_lines.append(f"\n⏱ Total: `{total_elapsed:.1f}s`")

    try:
        bot.edit_message_text("\n".join(summary_lines), uid, msg.message_id,
                              parse_mode="Markdown", disable_web_page_preview=True,
                              reply_markup=kb_home_only())
    except Exception:
        bot.send_message(uid, "\n".join(summary_lines), parse_mode="Markdown",
                         disable_web_page_preview=True, reply_markup=kb_home_only())

    u["draft"] = {}
    save_user(uid, u)
    set_state(uid, State.IDLE)
    log.ok(f"Multi-archive upload complete for user {uid}", f"{len(queue)} repos in {total_elapsed:.1f}s")


# ─────────────────────────────────────────────────────────────
#  Inline archive helper (during normal repo creation)
# ─────────────────────────────────────────────────────────────

def _handle_inline_archive(uid: int, m: Message) -> None:
    """Handle archive uploaded during CREATE_FILES_UPLOAD state (adds files to draft).
    Reuses the shared upload_status_msg_id so no new message is spammed."""
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
        files = _strip_top_folder(files)
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
                f"📁 *{count} {file_word} queued* — `{fname}` ({len(files)} files extracted)\n\n"
                "_Keep sending files or tap ✅ Done._",
                uid, status_msg_id,
                reply_markup=kb_files_continue(),
            )
        except Exception:
            pass
    except Exception as ex:
        _bot_notify(uid, status_msg_id, f"❌ Archive error: `{ex}`")


# ─────────────────────────────────────────────────────────────
#  Text message handler
# ─────────────────────────────────────────────────────────────

@bot.message_handler(func=lambda m: True, content_types=["text"])
def handle_text(m: Message) -> None:
    uid   = m.chat.id
    if _check_banned(uid):
        return
    text  = m.text.strip()
    state = get_state(uid)

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
                kb = InlineKeyboardMarkup(row_width=1)
                for item in results[:15]:
                    kb.add(InlineKeyboardButton(
                        f"📄 {item['path']}",
                        callback_data=f"er_file_{repo_name}_{item['path']}",
                    ))
                kb.add(
                    InlineKeyboardButton("🔍 New Search",   callback_data=f"er_search_{repo_name}"),
                    InlineKeyboardButton("↩️ Repo Menu",    callback_data=f"er_repomenu_{repo_name}"),
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
        _apply_github_token(uid, text)

    elif state == State.CREATE_NAME:
        name = text.lower().replace(" ", "-")
        u    = get_user(uid)
        u["draft"]["name"] = name
        save_user(uid, u)
        set_state(uid, State.CREATE_DESC)
        bot.send_message(uid,
            f"✅ *Name:* `{name}`\n\n━━━━━━━━━━━━━━━━━━━━\n\n"
            "📝 *Step 2/5 — Description*\n\nGive your repository a short description.\n_Or skip._",
            reply_markup=kb_desc_step())

    elif state == State.CREATE_DESC:
        u = get_user(uid)
        u["draft"]["description"] = text
        u["draft"]["desc_raw"]    = text
        save_user(uid, u)
        set_state(uid, State.CREATE_DESC_AWAIT)
        bot.send_message(uid,
            f"📝 *Description received:*\n_{text}_\n\nWould you like to improve it with AI?",
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
        u["draft"]["description"] = desc
        u["draft"]["desc_raw"]    = desc
        save_user(uid, u)
        if desc:
            set_state(uid, State.ARCHIVE_DESC_AWAIT)
            bot.send_message(uid,
                f"📝 *Description:*\n_{desc}_\n\nWould you like to improve it with AI?",
                reply_markup=kb_archive_desc_choice())
        else:
            _archive_go_to_visibility(uid)

    # ── Multi-archive AI custom name ─────────────────────────
    elif state == State.ARCHM_AI_CUSTOM:
        name = text.lower().replace(" ", "-")
        name = __import__("re").sub(r"[^a-z0-9\-]", "", name)
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
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
        desc = "" if text == "-" else text
        u["draft"]["multi_queue"][idx]["description"] = desc
        u["draft"]["multi_queue"][idx]["desc_raw"]    = desc
        save_user(uid, u)
        if desc:
            set_state(uid, State.ARCHIVE_MULTI_DESC_AWAIT)
            bot.send_message(uid,
                f"📝 *Description:*\n_{desc}_\n\nWould you like to improve it with AI?",
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
            if re.match(r"https?://github\.com/[^/\s]+/[^/\s]+", url):
                valid.append(url.rstrip("/").replace(".git", ""))
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

    else:
        bot.send_message(uid, "Use the menu or type a command. Try /help", reply_markup=kb_main())


# ─────────────────────────────────────────────────────────────
#  File/document upload handler
# ─────────────────────────────────────────────────────────────

_ARCHIVE_EXTS = (".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar", ".rar")

@bot.message_handler(func=lambda m: True, content_types=["document", "photo"])
def handle_file_upload(m: Message) -> None:
    uid   = m.chat.id
    if _check_banned(uid):
        return
    state = get_state(uid)
    u     = get_user(uid)

    # ── Archive password — single mode ──────────────────────
    if state == State.ARCHIVE_PASSWORD:
        "REDACTED" = m.text.strip() if m.text else ""
        if not password:
            "REDACTED" "🔐 Please type the password (text only):")
            return
        u = get_user(uid)
        raw_b64  = u["draft"].get("archive_raw_b64", "")
        fname    = u["draft"].get("archive_filename", "archive.zip")
        tries    = u["draft"].get("archive_pw_tries", 0)
        raw      = base64.b64decode(raw_b64) if raw_b64 else b""
        msg      = bot.send_message(uid, f"🔓 Trying password for `{fname}` ···")
        try:
            files = _extract_archive(raw, fname, password="REDACTED"
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
            bot.edit_message_text(f"❌ Extraction error: `{ex}`", uid, msg.message_id)
            return

        files  = _strip_top_folder(files)
        if not files:
            _bot_notify(uid, msg.message_id, "❌ Archive is empty or contains no extractable files.")
            return
        readme_file    = next((f for f in files if os.path.basename(f["path"]).lower() == "readme.md"), None)
        readme_content = ""
        if readme_file:
            try:
                readme_content = base64.b64decode(readme_file["content_b64"]).decode("utf-8", errors="replace")
            except Exception:
                pass
        u["draft"] = {
            "archive_files":    files,
            "archive_filename": fname,
            "archive_readme":   readme_content,
        }
        save_user(uid, u)
        set_state(uid, State.ARCHIVE_NAME)
        bot.edit_message_text(
            f"✅ *Unlocked & extracted!*\n\n"
            f"📦 `{fname}` → *{len(files)} files* ready\n"
            f"{'📄 README.md detected!' if readme_file else '📄 No README.md found'}\n\n"
            "━━━━━━━━━━━━━━━━━━━━\n\n"
            "🔤 *Step 1 — Repository Name*\n\n"
            "What should the repository be called?\n\n"
            "_Lowercase · hyphens · no spaces_\n\nExample: `my-awesome-project`",
            uid, msg.message_id,
        )
        return

    # ── Archive password — multi mode ────────────────────────
    if state == State.ARCHIVE_MULTI_PASSWORD:
        "REDACTED" = m.text.strip() if m.text else ""
        if not password:
            "REDACTED" "🔐 Please type the password (text only):")
            return
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
            files = _extract_archive(raw, fname, password="REDACTED"
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
            bot.edit_message_text(f"❌ Extraction error: `{ex}`", uid, msg.message_id)
            return

        files = _strip_top_folder(files)
        if not files:
            _bot_notify(uid, msg.message_id, f"⚠️ `{fname}` is empty — skipped.")
            set_state(uid, State.ARCHIVE_MULTI_COLLECT)
            return
        readme_file    = next((f for f in files if os.path.basename(f["path"]).lower() == "readme.md"), None)
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
        })
        u["draft"]["multi_queue"] = queue
        u["draft"].pop("multi_pw_pending", None)
        save_user(uid, u)
        set_state(uid, State.ARCHIVE_MULTI_COLLECT)
        count = len(queue)
        bot.edit_message_text(
            f"✅ *`{fname}` unlocked & added!*  ({len(files)} files"
            f"{'  ·  📄 README found' if readme_file else ''})\n\n"
            f"📦 *{count}/100 archive(s) queued*\n\n"
            "_Send more archives or tap ✅ Done when finished._",
            uid, msg.message_id,
            reply_markup=kb_archive_multi_collecting(count),
        )
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

            files = _strip_top_folder(files)
            if not files:
                _bot_notify(uid, msg.message_id, f"⚠️ `{fname}` is empty — skipped.")
                return
            readme_file    = next((f for f in files if os.path.basename(f["path"]).lower() == "readme.md"), None)
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
                f"✅ *`{fname}` added!*  ({len(files)} files extracted"
                f"{'  ·  📄 README found' if readme_file else ''})\n\n"
                f"📦 *{count}/100 archive(s) queued*\n\n"
                "_Send more archives or tap ✅ Done when finished._",
                uid, msg.message_id,
                reply_markup=kb_archive_multi_collecting(count),
            )
            log.event(f"User {uid} added archive {count}: {fname}, {len(files)} files")
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

        # ── Scrub sensitive content ──────────────────────────
        is_private = u["draft"].get("private", False)
        scrub_warn = ""
        if not is_private and source == "text" and (_is_sensitive_filename(filename) or _has_sensitive_content(content)):
            content, cnt = _scrub_content(content)
            if cnt:
                scrub_warn = f"  ⚠️ {cnt} sensitive value(s) scrubbed"

        # ── Store & update the ONE status bubble ─────────────
        u["draft"].setdefault("uploads", []).append({"name": filename, "content": content, "source": source})
        save_user(uid, u)
        set_state(uid, State.CREATE_FILES_UPLOAD)
        count     = len(u["draft"]["uploads"])
        file_word = "file" if count == 1 else "files"

        try:
            bot.edit_message_text(
                f"📁 *{count} {file_word} queued* — last: `{filename}`{scrub_warn}\n\n"
                "_Keep sending files or tap ✅ Done._",
                uid, status_msg_id,
                reply_markup=kb_files_continue(),
            )
        except Exception:
            pass   # Telegram sometimes rejects identical text edits — that's fine

    except Exception as ex:
        bot.send_message(uid, f"❌ Upload error: `{ex}`")


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
    text = (
        "━━━━━━━━━━━━━━━━━━━━\n\n🔍 *Confirm Repository*\n\n"
        f"📦 *Name:* `{name}`\n📝 *Desc:* _{desc}_\n"
        f"👁 *Visibility:* {vis}\n📁 *Files:* {len(uploads) or 'None'}\n"
        f"🤖 *AI Files:* {ai_str}\n\n_Everything look good? Tap ✅ to create._"
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

    try:
        bot.edit_message_text("⏳ Creating repository ·", uid, msg_id)
        repo = _animate(uid, msg_id, "Creating repository",
                       gh.create_repo, token, name, desc, private, True)
    except Exception as ex:
        bot.edit_message_text(f"❌ Failed to create repo:\n`{ex}`", uid, msg_id)
        return

    info = gh.get_user(token)
    if not info:
        bot.edit_message_text("❌ Could not verify GitHub user.", uid, msg_id)
        return
    owner    = info["login"]
    repo_url = repo.get("html_url", f"https://github.com/{owner}/{name}")

    pushed = []
    failed = []        # list of (filename, reason)
    for i, f in enumerate(uploads):
        fn      = f["name"]
        content = f["content"]
        source  = f.get("source", "text")
        try:
            bot.edit_message_text(f"⏳ Uploading `{fn}` ({i+1}/{len(uploads)}) ···", uid, msg_id)
        except Exception:
            pass
        try:
            ok = gh.push_file(token, owner, name, fn, content, f"Add {fn}")
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
            readme_text = _ai_rewrite_readme(u, name, desc, existing_readme_file["content"])
            if readme_text:
                readme_text = _deduplicate_readme_description(readme_text, desc)
                gh.push_file(token, owner, name, "README.md", readme_text, "✍️ AI rewrite README")
                pushed.append("README.md (AI rewrite)")
        else:
            try:
                bot.edit_message_text("🤖 Generating README with AI ···", uid, msg_id)
            except Exception:
                pass
            readme_text = _ai_generate_readme(u, name, desc)
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
            f"\n  • `{fn}` — _{reason}_" if reason and reason != "push returned False"
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
                              reply_markup=kb_home_only())
    except Exception:
        bot.send_message(uid, "\n".join(lines),
                         disable_web_page_preview=True,
                         reply_markup=kb_home_only())
    add_history(uid, f"Created repo: {name}")
    u["repos_created"] = u.get("repos_created", 0) + 1
    u["files_pushed"]  = u.get("files_pushed", 0) + len(pushed)
    u["draft"] = {}
    save_user(uid, u)
    set_state(uid, State.IDLE)


# ─────────────────────────────────────────────────────────────
#  Callback query handler
# ─────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────
#  Navigation renderer — re-renders a screen by its callback key
# ─────────────────────────────────────────────────────────────

def _nav_render(uid: int, data: str, msg_id: int) -> None:
    """
    Re-render a screen identified by its callback_data key.
    Used by the ↩️ Return button to go back exactly one step.
    Preserves all draft data — never resets it.
    """
    u = get_user(uid)

    # ── Home ─────────────────────────────────────────────────
    if data == "menu_home":
        nav_clear(uid)
        set_state(uid, State.IDLE, draft={})
        try:
            bot.edit_message_text("🏠 *Home* — What would you like to do?", uid, msg_id, reply_markup=kb_main(uid))
        except Exception:
            bot.send_message(uid, "🏠 *Home*", reply_markup=kb_main(uid))

    # ── Archive Upload mode picker ────────────────────────────
    elif data == "files_archive_upload":
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

    elif data.startswith("er_repomenu_"):
        repo_name = data[len("er_repomenu_"):]
        _show_edit_repo_menu(uid, repo_name, msg_id)

    elif data.startswith("er_browse_"):
        rest = data[len("er_browse_"):]
        sep  = rest.index("_")
        repo_name = rest[:sep]
        path      = rest[sep+1:]
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


@bot.callback_query_handler(func=lambda c: True)
def handle_callback(call) -> None:
    uid  = call.message.chat.id
    data = call.data
    bot.answer_callback_query(call.id)

    # ── Ban gate ─────────────────────────────────────────────
    if _check_banned(uid):
        return

    MENU_MAP = {
        "menu_create":  cmd_create_repo,
        "menu_repos":   cmd_list_repos,
        "menu_status":  cmd_status,
        "menu_history": cmd_history,
        "menu_setup":   cmd_guide,
        "menu_help":    cmd_help,
        "menu_guide":   cmd_guide,
        "menu_models":  cmd_models,
        "menu_support": cmd_support,
    }

    # ── Admin Panel ──────────────────────────────────────────
    if data == "admin_panel":
        if not is_admin(uid):
            bot.answer_callback_query(call.id, "🚫 Access denied.", show_alert=True)
            return
        cmd_admin(call.message)
        return

    if data == "admin_stats":
        if not is_admin(uid):
            return
        cmd_admin(call.message)
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
        target_uid = int(data[len("admin_view_"):])
        s = _public_user_stats(target_uid)
        badge = "🚫 BANNED" if s["banned"] else ("👑 Admin" if s["is_admin"] else "👤 User")
        text = (
            f"👤 *User Profile*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"🆔 ID: `{s['uid']}`\n"
            f"🐙 GitHub: `{s['github_user']}`\n"
            f"🤖 AI: `{s['ai_provider']}`\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"📦 Repos created:  *{s['repos_created']}*\n"
            f"🗑 Repos deleted:  *{s['repos_deleted']}*\n"
            f"🍴 Repos forked:   *{s['repos_forked']}*\n"
            f"📦 Archives up:    *{s['archives_up']}*\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"🏷 Status: *{badge}*\n"
            f"📅 Joined: `{s['created_at']}`\n\n"
            f"_⚠️ Tokens, keys, and personal history are never shown here._"
        )
        try:
            bot.edit_message_text(text, uid, call.message.message_id,
                                  parse_mode="Markdown",
                                  reply_markup=kb_admin_user(target_uid))
        except Exception:
            bot.send_message(uid, text, parse_mode="Markdown",
                             reply_markup=kb_admin_user(target_uid))
        return

    if data.startswith("admin_ban_"):
        if not is_admin(uid):
            return
        target_uid = int(data[len("admin_ban_"):])
        if target_uid in ADMIN_IDS:
            bot.answer_callback_query(call.id, "🚫 Cannot ban an admin.", show_alert=True)
            return
        ban_user(target_uid)
        try:
            bot.send_message(target_uid,
                "🚫 *Your account has been suspended.*",
                parse_mode="Markdown")
        except Exception:
            pass
        bot.answer_callback_query(call.id, f"✅ User {target_uid} banned.", show_alert=True)
        # Refresh user view
        call.data = f"admin_view_{target_uid}"
        handle_callback(call)
        return

    if data.startswith("admin_unban_"):
        if not is_admin(uid):
            return
        target_uid = int(data[len("admin_unban_"):])
        unban_user(target_uid)
        try:
            bot.send_message(target_uid,
                "✅ *Your account has been reinstated.*",
                parse_mode="Markdown")
        except Exception:
            pass
        bot.answer_callback_query(call.id, f"✅ User {target_uid} unbanned.", show_alert=True)
        call.data = f"admin_view_{target_uid}"
        handle_callback(call)
        return

    if data.startswith("admin_promote_"):
        if not is_admin(uid):
            return
        target_uid = int(data[len("admin_promote_"):])
        promote_admin(target_uid)
        try:
            bot.send_message(target_uid,
                "👑 *You have been granted admin access.*",
                parse_mode="Markdown")
        except Exception:
            pass
        bot.answer_callback_query(call.id, f"✅ User {target_uid} promoted.", show_alert=True)
        call.data = f"admin_view_{target_uid}"
        handle_callback(call)
        return

    if data.startswith("admin_demote_"):
        if not is_admin(uid):
            return
        target_uid = int(data[len("admin_demote_"):])
        if target_uid == ADMIN_CHAT_ID:
            bot.answer_callback_query(call.id, "🚫 Cannot demote the primary admin.", show_alert=True)
            return
        demote_admin(target_uid)
        try:
            bot.send_message(target_uid,
                "ℹ️ *Your admin access has been removed.*",
                parse_mode="Markdown")
        except Exception:
            pass
        bot.answer_callback_query(call.id, f"✅ User {target_uid} demoted.", show_alert=True)
        call.data = f"admin_view_{target_uid}"
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
        bot.send_message(uid,
            "🎫 *Support Tickets*\n\n"
            "When users send `/support MESSAGE` you'll receive them here.\n\n"
            "Reply with: `/reply USER_ID YOUR MESSAGE`",
            parse_mode="Markdown",
            reply_markup=kb_admin_back())
        return

    # ── Support menu shortcut ────────────────────────────────
    if data == "menu_support":
        kb_sp = InlineKeyboardMarkup(row_width=2)
        kb_sp.add(
            InlineKeyboardButton("↩️ Return", callback_data="menu_home"),
            InlineKeyboardButton("🏠 Home",   callback_data="menu_home"),
        )
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
            bot.send_message(uid, "⚠️ Set your GitHub token first: `/setgithub YOUR_TOKEN`")
            return
        nav_push(uid, "menu_edit_repo", "Edit Repository")
        _show_edit_repo_picker(uid, edit_msg_id=call.message.message_id)
        return

    # ── Delete Repo button ───────────────────────────────────
    if data == "menu_delete":
        u = get_user(uid)
        if not u.get("github_token"):
            bot.send_message(uid, "⚠️ Set your GitHub token first: `/setgithub YOUR_TOKEN`")
            return
        nav_push(uid, "menu_delete", "Delete Repository")
        _show_delete_picker(uid, edit_msg_id=call.message.message_id)
        return

    # ── Download Repo button ─────────────────────────────────
    if data == "menu_download":
        u = get_user(uid)
        if not u.get("github_token"):
            bot.send_message(uid, "⚠️ Set your GitHub token first: `/setgithub YOUR_TOKEN`")
            return
        nav_push(uid, "menu_download", "Download Repository")
        _show_download_picker(uid, edit_msg_id=call.message.message_id)
        return

    # ── Fork Repo button ─────────────────────────────────────
    if data == "menu_import":
        u = get_user(uid)
        if not u.get("github_token"):
            bot.send_message(uid, "⚠️ Set your GitHub token first: `/setgithub YOUR_TOKEN`")
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
            bot.send_message(uid, "⚠️ Set your GitHub token first: `/setgithub YOUR_TOKEN`")
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

    # ── Archive AI Single mode ───────────────────────────────
    if data == "arch_mode_ai_single":
        u = get_user(uid)
        if not u.get("ai_provider") or not u.get("ai_key"):
            bot.answer_callback_query(call.id, "⚠️ Set an AI provider first (/setai)", show_alert=True)
            return
        set_state(uid, State.ARCHIVE_UPLOAD)
        u = get_user(uid)
        u["draft"]["arch_ai_mode"] = True
        save_user(uid, u)
        nav_push(uid, "files_archive_upload", "Archive Upload")
        try:
            bot.edit_message_text(
                "🤖 *AI Single Archive Upload*\n\n"
                "Send your archive file now.\n\n"
                "✅ Supported: ZIP · tar.gz · tgz · tar.bz2 · tar.xz · RAR\n\n"
                "_AI will analyze the contents and suggest repository names & descriptions._",
                uid, call.message.message_id,
                reply_markup=kb_archive_single_prompt(),
            )
        except Exception:
            bot.send_message(uid, "🤖 Send your archive for AI analysis:",
                             reply_markup=kb_archive_single_prompt())
        return

    # ── Archive AI Multi mode ────────────────────────────────
    if data == "arch_mode_ai_multi":
        u = get_user(uid)
        if not u.get("ai_provider") or not u.get("ai_key"):
            bot.answer_callback_query(call.id, "⚠️ Set an AI provider first (/setai)", show_alert=True)
            return
        set_state(uid, State.ARCHIVE_MULTI_COLLECT)
        u = get_user(uid)
        u["draft"]["multi_queue"]   = []
        u["draft"]["multi_index"]   = 0
        u["draft"]["multi_ai_mode"] = True
        save_user(uid, u)
        nav_push(uid, "files_archive_upload", "Archive Upload")
        try:
            bot.edit_message_text(
                "🤖 *AI Multiple Archive Upload* _(up to 100)_\n\n"
                "Send your archive files one by one.\n\n"
                "✅ Supported: ZIP · tar.gz · tgz · tar.bz2 · tar.xz · RAR\n\n"
                "_AI will analyze each archive and suggest repository names & descriptions separately._\n\n"
                "Tap ✅ *Done* when all archives are uploaded.",
                uid, call.message.message_id,
                reply_markup=kb_archive_multi_collecting(0),
            )
        except Exception:
            bot.send_message(uid, "🤖 Send your archives for AI analysis.",
                             reply_markup=kb_archive_multi_collecting(0))
        return

    # ── Archive Single mode ──────────────────────────────────
    if data == "arch_mode_single":
        set_state(uid, State.ARCHIVE_UPLOAD)
        nav_push(uid, "files_archive_upload", "Archive Mode")
        try:
            bot.edit_message_text(
                "📁 *Single Archive Upload*\n\n"
                "Send your archive file now.\n\n"
                "✅ Supported:\n"
                "• `ZIP` (.zip)\n• `TAR` (.tar.gz · .tgz · .tar.bz2 · .tar.xz)\n• `RAR` (.rar)\n\n"
                "All files and folders will be extracted and uploaded to GitHub "
                "preserving the original structure.",
                uid, call.message.message_id,
                reply_markup=kb_archive_single_prompt(),
            )
        except Exception:
            bot.send_message(uid, "📁 Send your archive file (ZIP, RAR, tar.gz):",
                             reply_markup=kb_archive_single_prompt())
        return

    # ── Archive Multiple mode ────────────────────────────────
    if data == "arch_mode_multi":
        u = get_user(uid)
        u["draft"]["multi_queue"] = []
        u["draft"]["multi_index"] = 0
        save_user(uid, u)
        set_state(uid, State.ARCHIVE_MULTI_COLLECT)
        nav_push(uid, "files_archive_upload", "Archive Mode")
        try:
            bot.edit_message_text(
                "📚 *Multiple Archive Upload* _(up to 100)_\n\n"
                "Send your archive files one by one.\n\n"
                "✅ Supported: ZIP · tar.gz · tgz · tar.bz2 · tar.xz · RAR\n\n"
                "Each archive will become a *separate GitHub repository*.\n\n"
                "After sending all archives, tap ✅ *Done* to start configuring each one "
                "(name · description · visibility · README).",
                uid, call.message.message_id,
                reply_markup=kb_archive_multi_collecting(0),
            )
        except Exception:
            bot.send_message(uid,
                "📚 Send your archive files. Tap ✅ Done when finished.",
                reply_markup=kb_archive_multi_collecting(0))
        return

    # ── Single Archive AI name selection ────────────────────
    if data.startswith("arch_ai_name_"):
        idx = int(data.split("_")[-1])
        u   = get_user(uid)
        names = u["draft"].get("ai_suggested_names", [])
        if idx < len(names):
            name = names[idx]
            u["draft"]["name"] = name
            save_user(uid, u)
            descs = u["draft"].get("ai_suggested_descs", [])
            u["draft"]["ai_stage"] = "desc"
            save_user(uid, u)
            set_state(uid, State.ARCHIVE_AI_SUGGEST)
            if descs:
                try:
                    bot.edit_message_text(
                        f"✅ *Name chosen:* `{name}`\n\n"
                        "━━━━━━━━━━━━━━━━━━━━\n\n"
                        "🤖 *AI Description Suggestions*\n\nChoose a description or type your own:",
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

    # ── Single Archive AI description selection ──────────────
    if data.startswith("arch_ai_desc_") and not data.startswith("arch_ai_desc_custom") and not data.startswith("arch_ai_desc_skip") and not data.startswith("arch_ai_desc_regen"):
        idx = int(data.split("_")[-1])
        u   = get_user(uid)
        descs = u["draft"].get("ai_suggested_descs", [])
        if idx < len(descs):
            desc = descs[idx]
            u["draft"]["description"] = desc
            u["draft"]["desc_raw"]    = desc
            save_user(uid, u)
            try:
                bot.edit_message_text(f"✅ *Description chosen:*\n_{desc}_", uid, call.message.message_id)
            except Exception:
                pass
            _archive_go_to_visibility(uid)
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
                "🤖 *AI Description Suggestions*\n\nChoose or type your own:",
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
        names = u["draft"]["multi_queue"][idx].get("ai_suggested_names", [])
        if pick < len(names):
            name = names[pick]
            u["draft"]["multi_queue"][idx]["name"] = name
            save_user(uid, u)
            descs = u["draft"]["multi_queue"][idx].get("ai_suggested_descs", [])
            u["draft"]["multi_queue"][idx]["ai_stage"] = "desc"
            save_user(uid, u)
            set_state(uid, State.ARCHM_AI_SUGGEST)
            if descs:
                try:
                    bot.edit_message_text(
                        f"✅ *Name chosen:* `{name}`\n\n"
                        "🤖 *AI Description Suggestions*\n\nChoose or type your own:",
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

    if data == "archm_ai_back_names":
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
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

    if data.startswith("archm_ai_desc_") and not data.startswith("archm_ai_desc_custom") and not data.startswith("archm_ai_desc_skip") and not data.startswith("archm_ai_desc_regen"):
        pick = int(data.split("_")[-1])
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
        descs = u["draft"]["multi_queue"][idx].get("ai_suggested_descs", [])
        if pick < len(descs):
            desc = descs[pick]
            u["draft"]["multi_queue"][idx]["description"] = desc
            u["draft"]["multi_queue"][idx]["desc_raw"]    = desc
            save_user(uid, u)
            try:
                bot.edit_message_text(f"✅ *Description:*\n_{desc}_", uid, call.message.message_id)
            except Exception:
                pass
            set_state(uid, State.ARCHIVE_MULTI_VIS)
            queue = u["draft"]["multi_queue"]
            bot.send_message(uid,
                f"👁 *Visibility* for `{queue[idx].get('name', 'repo')}`\n\nPublic or Private?",
                reply_markup=kb_archive_multi_visibility())
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
        u["draft"]["multi_queue"][idx]["description"] = ""
        save_user(uid, u)
        set_state(uid, State.ARCHIVE_MULTI_VIS)
        queue = u["draft"]["multi_queue"]
        bot.send_message(uid,
            f"👁 *Visibility* for `{queue[idx].get('name', 'repo')}`\n\nPublic or Private?",
            reply_markup=kb_archive_multi_visibility())
        return

    if data == "archm_ai_desc_regen":
        u    = get_user(uid)
        idx  = u["draft"].get("multi_index", 0)
        q    = u["draft"]["multi_queue"][idx]
        msg  = bot.send_message(uid, "🔄 Regenerating description suggestions ···")
        _, descs = _ai_suggest_names_and_descs(u, q.get("files", []), q.get("filename", "archive"))
        u["draft"]["multi_queue"][idx]["ai_suggested_descs"] = descs
        save_user(uid, u)
        try:
            bot.edit_message_text(
                "🤖 Choose a description or type your own:",
                uid, msg.message_id,
                reply_markup=kb_archm_ai_desc(descs),
            )
        except Exception:
            bot.send_message(uid, "🤖 Choose a description:", reply_markup=kb_archm_ai_desc(descs))
        return

    # ── Multi-archive: name step buttons ────────────────────
    if data == "archm_name_type":
        # User tapped "Type repo name" — just dismiss the callback, they type next
        bot.answer_callback_query(call.id, "Type your repo name below 👇")
        return

    # ── Multi-archive: desc step buttons ────────────────────
    if data == "archm_desc_type":
        # User tapped "Type description" — just dismiss the callback, they type next
        bot.answer_callback_query(call.id, "Type your description below 👇")
        return

    if data == "archm_desc_skip_now":
        # User tapped "Skip" on description
        u   = get_user(uid)
        idx = u["draft"].get("multi_index", 0)
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
            bot.answer_callback_query(call.id, "No archives yet! Send some files first.")
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
        set_state(uid, State.ARCHIVE_MULTI_VIS)
        queue = u["draft"]["multi_queue"]
        bot.send_message(uid,
            f"👁 *Visibility* for `{queue[idx].get('name', 'repo')}`\n\nPublic or Private?",
            reply_markup=kb_archive_multi_visibility())
        return

    # ── Multi-archive: visibility ────────────────────────────
    if data in ("archm_vis_public", "archm_vis_private"):
        u   = get_user(uid)
        idx = u["draft"].get("multi_index", 0)
        u["draft"]["multi_queue"][idx]["private"] = (data == "archm_vis_private")
        save_user(uid, u)
        vis = "🔒 Private" if data == "archm_vis_private" else "🌍 Public"
        try:
            bot.edit_message_text(f"✅ *Visibility:* {vis}", uid, call.message.message_id)
        except Exception:
            pass
        # Go to README step
        queue         = u["draft"]["multi_queue"]
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
        q   = u["draft"]["multi_queue"][idx]
        msg = bot.send_message(uid, "✍️ Rewriting README with AI ···")
        _t  = _time.time()
        rewritten = _ai_rewrite_readme(u, q.get("name", ""), q.get("description", ""), q.get("readme_content", ""))
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
        q   = u["draft"]["multi_queue"][idx]
        msg = bot.send_message(uid, "✨ Generating README with AI ···")
        _t  = _time.time()
        generated = _ai_generate_readme(u, q.get("name", ""), q.get("description", ""))
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
            bot.answer_callback_query(call.id, "No repos selected!")
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
        rewritten      = _ai_rewrite_readme(u, repo_name, desc, readme_content)
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
        generated = _ai_generate_readme(u, repo_name, desc)
        generated = _deduplicate_readme_description(generated, desc)
        if generated:
            files = u["draft"].get("archive_files", [])
            files = [f for f in files if os.path.basename(f["path"]).lower() != "readme.md"]
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

    if data == "confirm_archive":
        u             = get_user(uid)
        readme_content = u["draft"].get("archive_readme", "")
        if readme_content:
            files = u["draft"].get("archive_files", [])
            files = [f for f in files if os.path.basename(f["path"]).lower() != "readme.md"]
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
        try:
            bot.edit_message_text("🏠 *Home* — What would you like to do?", uid, call.message.message_id, reply_markup=kb_main(uid))
        except Exception:
            bot.send_message(uid, "🏠 *Home* — What would you like to do?", reply_markup=kb_main(uid))
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
            bot.answer_callback_query(call.id, "\u26a0\ufe0f Select at least one repo first.", show_alert=True)
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

    # Repo selected from picker
    if data.startswith("er_pick_"):
        repo_name = data[len("er_pick_"):]
        u = get_user(uid)
        if not u.get("github_token"):
            bot.answer_callback_query(call.id, "⚠️ Set GitHub token first.", show_alert=True)
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
    if data.startswith("er_browse_"):
        rest      = data[len("er_browse_"):]
        sep_idx   = rest.index("_")
        repo_name = rest[:sep_idx]
        path      = rest[sep_idx+1:]
        _browse_path(uid, repo_name, path, call.message.message_id)
        return

    # Browse page navigation
    if data.startswith("er_bpage_"):
        rest  = data[len("er_bpage_"):]
        parts = rest.split("_")
        repo_name = parts[0]
        page_str  = parts[-1]
        path      = "_".join(parts[1:-1])
        page      = int(page_str)
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

    # View/action on a specific file
    if data.startswith("er_file_"):
        rest      = data[len("er_file_"):]
        sep_idx   = rest.index("_")
        repo_name = rest[:sep_idx]
        file_path = rest[sep_idx+1:]
        _show_file_actions(uid, repo_name, file_path, call.message.message_id)
        return

    # Edit file content
    if data.startswith("er_edit_"):
        rest      = data[len("er_edit_"):]
        sep_idx   = rest.index("_")
        repo_name = rest[:sep_idx]
        file_path = rest[sep_idx+1:]
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

    # View raw file content
    if data.startswith("er_view_"):
        rest      = data[len("er_view_"):]
        sep_idx   = rest.index("_")
        repo_name = rest[:sep_idx]
        file_path = rest[sep_idx+1:]
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
            bot.answer_callback_query(call.id, "❌ Could not fetch file.", show_alert=True)
        return

    # Move/rename file
    if data.startswith("er_move_"):
        rest      = data[len("er_move_"):]
        sep_idx   = rest.index("_")
        repo_name = rest[:sep_idx]
        file_path = rest[sep_idx+1:]
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

    # Delete file — confirmation prompt
    if data.startswith("er_del_file_"):
        rest      = data[len("er_del_file_"):]
        sep_idx   = rest.index("_")
        repo_name = rest[:sep_idx]
        file_path = rest[sep_idx+1:]
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

    # Delete file — confirmed
    if data.startswith("er_del_confirm_"):
        rest      = data[len("er_del_confirm_"):]
        sep_idx   = rest.index("_")
        repo_name = rest[:sep_idx]
        file_path = rest[sep_idx+1:]
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
            bot.answer_callback_query(call.id, "❌ Could not fetch file SHA.", show_alert=True)
        return

    # New file in a path
    if data.startswith("er_newfile_"):
        rest    = data[len("er_newfile_"):]
        sep_idx = rest.index("_")
        repo_name = rest[:sep_idx]
        base_path = rest[sep_idx+1:]
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

    # New folder
    if data.startswith("er_newfolder_"):
        rest      = data[len("er_newfolder_"):]
        sep_idx   = rest.index("_") if "_" in rest else len(rest)
        repo_name = rest[:sep_idx]
        base_path = rest[sep_idx+1:] if sep_idx < len(rest) else ""
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
                bot.answer_callback_query(call.id, "❌ Failed to change visibility.", show_alert=True)
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
                f"📝 _{desc}_\n"
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
        kb_star = InlineKeyboardMarkup(row_width=2)
        kb_star.add(
            InlineKeyboardButton("↩️ Return", callback_data="menu_home"),
            InlineKeyboardButton("🏠 Home",   callback_data="menu_home"),
        )
        bot.send_message(uid,
            "⭐ *Star a Repository*\n\n"
            "Usage: `/star_repo OWNER/REPO`\n\n"
            "Example: `/star_repo torvalds/linux`",
            reply_markup=kb_star)
        return


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
                logger_level         = None,
            )
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
            log.critical("Bot crashed", err)
            raise
