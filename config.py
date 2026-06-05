# ╔══════════════════════════════════════════════════════════════╗
# ║        GitHub AI Repo Bot V29 — Configuration                ║
# ╚══════════════════════════════════════════════════════════════╝
#
#  Edit the values below to configure your bot.
#  Never share this file publicly — it contains secrets.
# ──────────────────────────────────────────────────────────────

# ── Telegram Bot Token ──────────────────────────────────────────
#  Get yours from @BotFather on Telegram
#  Format: 123456789:ABCxyz...
BOT_TOKEN = "REDACTED"

# ── Primary Admin Chat ID ────────────────────────────────────────
#  Your personal Telegram user ID.
#  Find yours by messaging @userinfobot on Telegram.
ADMIN_CHAT_ID = 000000000

# ── Admin List ───────────────────────────────────────────────────
#  All admin user IDs (including primary admin).
#  Add more IDs to grant admin access to additional users.
#  Example: ADMIN_IDS = [6721548185, 987654321]
ADMIN_IDS: list[int] = [ADMIN_CHAT_ID]
