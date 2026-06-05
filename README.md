# 🚀 Introduction

The GitHub Automation Tool is a GitHub automation platform controlled through Telegram forms, utilizing the Telegram Bot API for secure administration and repository management.

---

# 🛡 Admin Panel

The Admin Panel can be accessed using the `/admin` command or the 🛡 **Admin Panel** button available in the Home Menu for administrators.

The panel provides live statistics, including:

* 👥 Total Users
* 🚫 Banned Users
* 👑 Total Admins
* 📦 Total Repositories Created
* 🎫 Support Tickets

### User Management

The **User List** is paginated (10 users per page) and displays:

* 📦 Repositories Created (live count)
* GitHub Username
* Admin Status
* Ban Status

Selecting a user opens a detailed profile card with the following actions:

* 🚫 Ban User
* ✅ Unban User
* 👑 Promote to Admin
* 👤 Demote Admin

---

# 👑 Admin Management

Administrators can be managed using the following commands:

| Command                | Description             |
| ---------------------- | ----------------------- |
| `/addadmin USER_ID`    | Promote a user to admin |
| `/removeadmin USER_ID` | Remove admin privileges |

The primary administrator is permanent and cannot be removed.

Multiple administrators are supported through the `ADMIN_IDS` list in `config.py`.

---

# 🚫 Ban System

Administrators can manage user access using:

| Command          | Description              |
| ---------------- | ------------------------ |
| `/ban USER_ID`   | Instantly suspend a user |
| `/unban USER_ID` | Restore user access      |

### Features

* Banned users receive a notification when banned.
* Users receive a welcome-back notification when unbanned.
* Banned users are silently blocked from all bot functions.
* Administrators cannot ban other administrators.

---

# 📢 Broadcast System

Administrators can send announcements to all non-banned users.

| Command                   | Description              |
| ------------------------- | ------------------------ |
| `/broadcast YOUR_MESSAGE` | Send a broadcast message |

After completion, the bot reports:

* ✅ Successfully Delivered
* ❌ Failed Deliveries

The broadcast feature is also available from:

**Admin Panel → 📢 Broadcast**

---

# 🎫 Support System

Users can contact administrators directly through the support system.

### User Command

```text
/support YOUR_MESSAGE
```

Support tickets are delivered to all administrators and include:

* User ID
* GitHub Username
* Message Content

### Admin Reply Command

```text
/reply USER_ID YOUR_MESSAGE
```

Replies are sent directly to the selected user.

A 🎫 **Support** button is available in the Home Menu for all users.

---

# 🔒 Privacy & Data Security

Sensitive information remains completely private.

### Administrators CANNOT Access

* GitHub Tokens
* AI API Keys
* Personal History
* Logs
* Draft Data
* User State Data

### Administrators CAN Access

* GitHub Username
* Repository Count
* Join Date
* Admin Status
* Ban Status

User history (`/history`) is fully private and inaccessible to administrators.

---

# 🏠 Home Menu

The Home Menu includes:

* 🎫 Support
* 🛡 Admin Panel (Admins Only)

---

# 📋 Privacy Architecture

| Data                         | User       | Admin        |
| ---------------------------- | ---------- | ------------ |
| GitHub Token                 | ✅ Own Only | ❌ Never      |
| AI API Key                   | ✅ Own Only | ❌ Never      |
| Personal History             | ✅ Own Only | ❌ Never      |
| Draft/State Data             | ✅ Own Only | ❌ Never      |
| Repositories Created (Count) | ✅ Own      | ✅ Count Only |
| GitHub Username              | ✅ Own      | ✅ Visible    |
| Banned Status                | ✅ Own      | ✅ Visible    |
| Join Date                    | ✅ Own      | ✅ Visible    |

---

# 📥 Installation

Clone the repository:

```bash
git clone https://github.com/zcsaqueeb/github-automation-tool.git
cd github-automation-tool
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Configure your bot settings in `config.py`.

Start the bot:

```bash
python bot.py
```

---

# ⚙️ Configuration (`config.py`)

```python
BOT_TOKEN      = "REDACTED"

ADMIN_CHAT_ID  = 000000000  # Primary admin (permanent)

ADMIN_IDS      = [ADMIN_CHAT_ID]
```

You can add additional administrator IDs to the `ADMIN_IDS` list.

---

# 💻 Commands

| Command                  | Access   | Description           |
| ------------------------ | -------- | --------------------- |
| `/admin`                 | Admin    | Open Admin Panel      |
| `/addadmin USER_ID`      | Admin    | Promote User          |
| `/removeadmin USER_ID`   | Admin    | Demote Admin          |
| `/ban USER_ID`           | Admin    | Ban User              |
| `/unban USER_ID`         | Admin    | Unban User            |
| `/broadcast MESSAGE`     | Admin    | Broadcast Message     |
| `/support MESSAGE`       | Everyone | Submit Support Ticket |
| `/reply USER_ID MESSAGE` | Admin    | Reply To User         |

---

# 🤝 Contributing

Contributions are welcome.

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Commit your work
5. Submit a Pull Request

---

# 📄 License

This project is licensed under the license specified in the repository.
