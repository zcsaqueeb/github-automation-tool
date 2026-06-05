# 🚀 GitHub AI Repo Bot 

### 🛡 Admin Panel (`/admin`)
- Full admin panel accessible via `/admin` command **or** 🛡 Admin Panel button on the Home menu
- Shows live stats: total users, banned count, admin count, total repos created, support ticket count
- **User List** — paginated (10 per page), shows per-user:
  - 📦 Repos Created (live count)
  - GitHub username
  - Banned / Admin status
- Click any user → detailed profile card
- Per-user actions: **Ban**, **Unban**, **Promote to Admin**, **Demote Admin**

### 👑 Admin Management
- `/addadmin USER_ID` — Promote any user to admin
- `/removeadmin USER_ID` — Demote admin (primary admin is permanent)
- Multiple admins supported in `config.py` via `ADMIN_IDS` list

### 🚫 Ban System
- `/ban USER_ID` — Instantly suspend a user (they receive a notification)
- `/unban USER_ID` — Reinstate a user (they receive a welcome-back message)
- Banned users are **silently blocked** from ALL bot actions
- Cannot ban another admin

### 📢 Broadcast
- `/broadcast YOUR MESSAGE` — Send a message to all non-banned users
- Shows sent/failed count after completion
- Also accessible from Admin Panel → 📢 Broadcast

### 🎫 Support System
- Users: `/support YOUR MESSAGE` — sends a support ticket to **all admins**
  - Ticket includes User ID, GitHub username, and message
- Admins: `/reply USER_ID YOUR MESSAGE` — reply directly to any user
- Support button added to main menu (🎫 Support)

### 🔒 Privacy & Data Security
- **Admin CANNOT see**: GitHub tokens, AI keys, personal history/logs, draft data
- Admin only sees safe public stats (join date, repos created, banned status, username)
- Users' history (`/history`) is completely private — admin has zero access
- No sensitive data is ever exposed through the admin panel or user profile view
- Users can **only see their own** tokens, keys, history, and logs

### 🏠 Home Menu Updates
- 🎫 Support button added for all users
- 🛡 Admin Panel button appears **only for admins**

---

## Privacy Architecture

| Data | User | Admin |
|------|------|-------|
| GitHub Token | ✅ Own only | ❌ Never |
| AI API Key | ✅ Own only | ❌ Never |
| Personal History | ✅ Own only | ❌ Never |
| Draft/State data | ✅ Own only | ❌ Never |
| Repos Created (count) | ✅ Own | ✅ Count only |
| GitHub Username | ✅ Own | ✅ Visible |
| Banned Status | ✅ Own | ✅ Visible |
| Join Date | ✅ Own | ✅ Visible |

---

## Configuration (`config.py`)

```python
BOT_TOKEN    = "REDACTED"
ADMIN_CHAT_ID = 000000000          # Primary admin (permanent, cannot be removed)
ADMIN_IDS    = [ADMIN_CHAT_ID]     # Add more admin IDs here
```

---

## New Commands

| Command | Who | Description |
|---------|-----|-------------|
| `/admin` | Admin | Open admin panel |
| `/addadmin USER_ID` | Admin | Promote user to admin |
| `/removeadmin USER_ID` | Admin | Demote admin |
| `/ban USER_ID` | Admin | Ban a user |
| `/unban USER_ID` | Admin | Unban a user |
| `/broadcast MSG` | Admin | Send to all users |
| `/support MSG` | Everyone | Send support ticket |
| `/reply USER_ID MSG` | Admin | Reply to user |
