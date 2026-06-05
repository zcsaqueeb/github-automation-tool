# 🚀 Introduction
The GitHub Automation Tool is a GitHub automation tool controlled via Telegram forms, utilizing the Telegram API for secure administration.

## 🛡 Admin Panel
The admin panel is accessible via the `/admin` command or the 🛡 Admin Panel button on the Home menu. It displays live stats, including:
* Total users
* Banned count
* Admin count
* Total repositories created
* Support ticket count

The admin panel also features a **User List**, which is paginated (10 per page) and shows the following information for each user:
* 📦 Repositories Created (live count)
* GitHub username
* Banned / Admin status

Clicking on a user displays a detailed profile card. Per-user actions include:
* **Ban**
* **Unban**
* **Promote to Admin**
* **Demote Admin**

## 👑 Admin Management
Admin management is performed using the following commands:
* `/addadmin USER_ID` - Promote any user to admin
* `/removeadmin USER_ID` - Demote admin (primary admin is permanent)

Multiple admins are supported in `config.py` via the `ADMIN_IDS` list.

## 🚫 Ban System
The ban system allows admins to:
* `/ban USER_ID` - Instantly suspend a user (they receive a notification)
* `/unban USER_ID` - Reinstate a user (they receive a welcome-back message)

Banned users are **silently blocked** from all bot actions. Admins cannot ban another admin.

## 📢 Broadcast
The `/broadcast YOUR MESSAGE` command sends a message to all non-banned users. The command also displays the sent/failed count after completion. This feature is also accessible from the Admin Panel → 📢 Broadcast.

## 🎫 Support System
The support system allows:
* Users: `/support YOUR MESSAGE` - sends a support ticket to **all admins**
	+ Ticket includes User ID, GitHub username, and message
* Admins: `/reply USER_ID YOUR MESSAGE` - reply directly to any user

A support button is added to the main menu (🎫 Support).

## 🔒 Privacy & Data Security
The following data is protected:
* **Admin CANNOT see**: GitHub tokens, AI keys, personal history/logs, draft data
* Admin only sees safe public stats (join date, repositories created, banned status, username)
* Users' history (`/history`) is completely private — admin has zero access
* No sensitive data is ever exposed through the admin panel or user profile view
* Users can **only see their own** tokens, keys, history, and logs

## 🏠 Home Menu Updates
The home menu features:
* 🎫 Support button added for all users
* 🛡 Admin Panel button appears **only for admins**

## Privacy Architecture
The following table outlines the data accessibility:
| Data | User | Admin |
|------|------|-------|
| GitHub Token | ✅ Own only | ❌ Never |
| AI API Key | ✅ Own only | ❌ Never |
| Personal History | ✅ Own only | ❌ Never |
| Draft/State data | ✅ Own only | ❌ Never |
| Repositories Created (count) | ✅ Own | ✅ Count only |
| GitHub Username | ✅ Own | ✅ Visible |
| Banned Status | ✅ Own | ✅ Visible |
| Join Date | ✅ Own | ✅ Visible |

## Installation
To install the GitHub Automation Tool, follow these steps:
1. Clone the repository
2. Install the required dependencies
3. Configure the `config.py` file

## Configuration (`config.py`)
```python
BOT_TOKEN    = "REDACTED"
ADMIN_CHAT_ID = 000000000          # Primary admin (permanent, cannot be removed)
ADMIN_IDS    = [ADMIN_CHAT_ID]     # Add more admin IDs here
```

## Usage
The following commands are available:
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

## Contributing
To contribute to the GitHub Automation Tool, please:
1. Fork the repository
2. Make your changes
3. Submit a pull request

## License
The GitHub Automation Tool is licensed under [insert license].