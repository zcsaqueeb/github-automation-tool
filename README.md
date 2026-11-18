# GitHub AI Repo Bot

Manage GitHub repositories from Telegram. Publish project archives, create repositories from an idea, generate documentation with AI, edit existing repositories, and run a privacy-safe admin panel.

## Features

- Create repositories from files, project ideas, or archives.
- Extract ZIP, TAR, TAR.GZ, TAR.BZ2, TAR.XZ, and RAR archives while retaining their project structure.
- **Flat root uploads:** if an archive wraps everything in one top-level folder (for example a zipped `github-automation-improved/` project folder), that wrapper is stripped automatically — files land directly at the repository root, exactly like a standard professional repository. Folders below the wrapper (`.github/workflows/`, `deploy/`, `src/`, …) keep their correct locations.
- Generate repository names, descriptions, commit messages, README files, and `.gitignore` files from the real project structure.
- Browse repositories; create, edit, move, rename, and delete individual files; manage repository details and branches.
- List, download, fork, star, and delete repositories.
- **Replace Repo Contents:** wipe every file and folder of an existing repository WITHOUT deleting the repo, then optionally upload a fresh archive in its place — all in one atomic commit (`/replace_repo` or the ♻️ Replace Repo button).
- **Upload to Repo:** send files, photos, and archives straight into an existing repository at any folder path (`/upload` or the 📤 Upload to Repo button). Two modes: **➕ Add** keeps everything already in the repo and updates same-named files to your new version; **🔄 Replace** deletes the old files first (whole repo at root, or just the destination folder) and pushes your upload as one atomic commit — perfect when you fixed code locally and want the repo to match exactly.
- **Live Preview:** see any repository as a live website — one-tap GitHub Pages enablement, live build status, and an instant HTML preview link (`/preview` or the 👁 Live Preview button).
- **Multi-Account Manager:** connect up to 10 GitHub accounts to ONE Telegram chat and switch between them with a single tap — no second Telegram account or bot instance needed (`/accounts` or the 👥 My Accounts button). Every feature works on whichever account is active.
- Use Groq, Gemini, Mistral, Together, OpenAI, OpenRouter, Anthropic, xAI, or DeepSeek with user-owned API keys.
- Offer support tickets, activity history, language/time-zone settings, a Telegram command menu, and admin analytics.

## Security and privacy

### Sensitive-data scanner

Before upload, the bot scans filenames and file content for API keys, tokens, passwords, database URLs, private keys, wallet secrets, service-account files, and `.env` files. A detection screen gives a redacted report with severity and file path; users can edit/re-upload, cancel, or explicitly acknowledge the exact reviewed upload. Changed files are scanned again.

Archive extraction has per-file and total-size limits to reduce decompression-bomb risk. Never treat a private repository as safe storage for credentials: remove and rotate exposed secrets.

### Encrypted storage

`users.json` is authenticated Fernet ciphertext and is decrypted only in memory.

- In production, set `DATA_ENCRYPTION_KEY` through your platform secret manager.
- Locally, the bot automatically creates a random installation key in `users.json.key` when no environment key is configured.
- Keys are never shown in Telegram, admin screens, command output, or logs.
- A wrong/missing key fails safely rather than overwriting encrypted data.

Admins see only aggregate usage, account state, and per-user counters. They cannot view user tokens, AI keys, history, uploaded content, or encryption keys.

### Safe errors and logs

Users receive recovery guidance, never stack traces or raw provider/GitHub errors. Redacted rotating logs protect PATs, AI keys, JWTs, Bearer headers, database URLs, and Fernet keys. The bot retries transient polling failures.

## Quick start

1. Create a bot with [@BotFather](https://t.me/BotFather) and get your numeric user ID from [@userinfobot](https://t.me/userinfobot).
2. Create `.env`:

```dotenv
BOT_TOKEN=123456789:your-bot-token
ADMIN_CHAT_ID=123456789
```

3. Install and run:

```bash
pip install -r requirements.txt
python bot.py
```

Or run with Docker:

```bash
docker compose up -d --build
```

Open a private conversation with the bot and send `/start`.

## Use cases and workflows

### Publish an archive

1. Choose **Archive Upload**.
2. Send one archive or queue a batch.
3. Review extracted files, AI suggestions, README choices, and visibility.
4. Review and fix any sensitive-data detection.
5. Confirm; the bot creates the repository and commits the project files.

### Create from an idea

Run `/suggest`, describe the project, review AI-generated repository details and starter files, choose visibility, and confirm.

### Connect GitHub and AI

Only in private chat:

```text
/setgithub
/setai
```

If GitHub is not connected, the bot automatically shows a guided setup screen with the official [GitHub token settings](https://github.com/settings/tokens) link. Create a token with access to the repositories you want the bot to manage, then return to private chat and tap **Connect token**. Credentials are verified, encrypted, and their incoming messages are removed where Telegram permissions allow it.

### Edit an existing repository

Select **Edit Repository** from the menu to browse files, edit/create/move/delete files, manage metadata, and work with branches. Use `/list_repos` to start from a repository list.

### Replace a repository's contents (archive-style reset)

Already have a repository but want to start over without losing it?

1. Choose **♻️ Replace Repo** (or run `/replace_repo`) and pick the repository.
2. **Clear + Upload:** send an archive; the bot deletes every existing file/folder and pushes your archive contents in their place — old and new swap in ONE commit, so the repository is never half-updated.
3. **Clear Only:** confirm by typing the repository name; the bot commits an empty tree, keeping the repository, its URL, stars, settings, and history intact.
4. Review the sensitive-data scan, then confirm. Folder structure inside the archive is preserved; a single wrapper folder around all files is stripped so the new contents sit at the repository root.

Use this to recycle a repository name, reset a template repo, or republish a new version of a project.

### Upload files into an existing repository

Already have a repo and just want to add files?

1. Choose **📤 Upload to Repo** (or run `/upload`) and pick the repository.
2. Choose the destination: repository root (`/`) or type a folder path such as `docs` or `assets/images` — the folder is created automatically.
3. Pick the upload mode:
   - **➕ Add files** — adds your files on top of the current contents, nothing is deleted; files with the same path are updated to your version.
   - **🔄 Replace files** — deletes what is already there first: at repository root the whole repo is synced to your upload; inside a folder only that folder is emptied. Old and new swap in ONE atomic commit, so the repo is never half-updated.
4. Send any documents, photos, or archives (archives are extracted, any single wrapper folder is removed, and the remaining folder structure is kept). Send as many as you like.
5. Tap **✅ Done**. The result screen shows which mode ran.
6. Open **👁 Live Preview** right from the result screen.

Typical update loop: fix code locally → 📤 Upload to Repo → same repo → 🔄 Replace → send your files → the repo now matches your local project exactly.

Files up to ~19 MB each (Telegram's download limit), 150 files per batch. Duplicate filenames are resolved to the latest version you sent. The sensitive-data scanner runs on every batch.

### See a repository as a live website

1. Choose **👁 Live Preview** (or run `/preview`) and pick a repository.
2. The bot detects the default branch, looks for an entry file (`index.html` first, then any `.html` page), and checks GitHub Pages status.
3. If Pages is off, tap **🚀 Enable GitHub Pages** — the bot turns it on via the API and hands you the `https://owner.github.io/repo/` URL. The first build usually takes 1–2 minutes; tap **🔄 Refresh** to check the build status.
4. Public repos also get **⚡ Instant HTML Preview** — a browser-rendered view of `index.html` that works immediately, no Pages build needed.

Live Preview is also available from **✏️ Edit Repo** (per-repo menu) and directly on the result screens of Archive Upload, Replace Repo, and Upload to Repo.

### Manage multiple GitHub accounts at once

Run personal, work, and client accounts side by side in a single chat:

1. Choose **👥 My Accounts** (or run `/accounts`).
2. **➕ Add account** — send that account's Personal Access Token; it is verified, encrypted, and becomes the active account.
3. Tap any account in the list to make it active — repos, uploads, previews, edits, and every other feature instantly operate on that account. Starting a switch cancels any half-finished draft so nothing crosses accounts.
4. **✏️ Rename** gives accounts friendly labels such as `Work` or `Client-A`; **🗑 Remove** deletes only the bot's saved copy (nothing happens on GitHub). Removing the active account automatically falls back to another saved account.

Existing users are migrated automatically: the already-connected token shows up as the first saved account. `/setgithub` and the account list stay in sync, and **Disconnect GitHub** clears all saved accounts at once. All tokens are encrypted at rest and never displayed in chat.

### Admin panel

Run `/admin` in private chat. The panel includes user management, timed/permanent bans, support tickets, broadcasts, system health, and analytics. Analytics graph aggregate user activity, account setup, encrypted database size, host disk use, and uptime. Per-user screens show counters and connection state only.

## Commands

| Command | Purpose |
|---|---|
| `/start`, `/menu`, `/home` | Open the main menu |
| `/cancel` | Cancel the current workflow |
| `/help`, `/guide` | Help and walkthrough |
| `/status` | Private connection, privacy, and activity status |
| `/setgithub`, `/setai` | Connect GitHub/AI in private chat |
| `/accounts` | Manage multiple GitHub accounts in one chat |
| `/disconnectgithub` | Remove ALL saved GitHub accounts/tokens from this bot |
| `/models` | List AI providers and models |
| `/create_new_repo` | Create a repository from scratch |
| `/suggest` | Build a repository from an idea |
| `/list_repos` | List repositories |
| `/import_repo URL` | Fork/import a repository |
| `/delete_repo` | Delete selected repositories |
| `/replace_repo` | Clear a repository's files (repo is kept) and upload fresh ones |
| `/upload` | Upload files/folders into an existing repository |
| `/preview` | Live preview of a repository's website |
| `/star_repo OWNER/REPO` | Star a repository |
| `/history` | View activity history |
| `/language`, `/timezone [Area/City]` | Localize the bot |
| `/support MESSAGE` | Send a support request |
| `/admin` | Private admin panel |

Telegram’s native command picker lists the common user commands. Administrative actions remain permission-checked and hidden from the public list.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `BOT_TOKEN` | — | Required Telegram token |
| `ADMIN_CHAT_ID` | — | Required primary admin ID |
| `ADMIN_IDS` | — | Extra admin IDs |
| `DATA_ENCRYPTION_KEY` | automatic local key | Production Fernet key from secret manager |
| `DB_FILE` | `users.json` | Encrypted user database |
| `LOG_FILE` / `LOG_LEVEL` | `bot.log` / `INFO` | Redacted rotating logs |
| `HTTP_TIMEOUT` / `HTTP_MAX_RETRIES` | `15` / `3` | HTTP reliability controls |
| `GIT_BLOB_WORKERS` | `12` | Archive upload concurrency (1–16) |
| `BULK_REPO_WORKERS` | `2` | Batch repository concurrency (1–3) |
| `BULK_DOWNLOAD_WORKERS` | `3` | Download concurrency (1–4) |
| `CLI_THEME` | `cyber` | `cyber` or `classic` startup theme |
| `CLI_USER_LOG_TTL` | `10` | Interactive user-log lifetime; `0` disables it |

## Deployment and troubleshooting

Persist `users.json` and `users.json.key` for local automatic encryption, or persist `users.json` and retain the same managed `DATA_ENCRYPTION_KEY` across deployments. The Docker image supplies `p7zip-full` for RAR extraction and the project includes a systemd unit for Linux services.

- **Polling conflict (409):** stop duplicate bot processes/containers; one Telegram token supports one long-polling consumer.
- **Encrypted database cannot open:** restore the original key; do not replace the key while retaining the old database.
- **Scanner blocks upload:** remove secrets, use environment variables, add local files to `.gitignore`, rotate exposed credentials, and re-upload.
- **RAR extraction fails:** use the supplied Docker setup or install `7z`/`unrar` on the host.

## Project layout

```text
bot.py                    Telegram workflows, archive processing, admin panel
github_api.py             GitHub REST/Git Data API client
ai_providers.py           Multi-provider AI integration
security.py               Encryption-key provisioning and Fernet helpers
cli_log.py                Cyber CLI, log redaction, rotation
config.py                 Environment configuration
gh_actions.py             Issues, PRs, releases, and branches
test_security_scanner.py  Security and regression suite
```

## Verification

```bash
python test_security_scanner.py
python test_github_api.py
python test_gh_actions.py
python test_new_features.py
```

## Changelog — full bug-fix pass (2026-11-16)

Buttons and callbacks
- Fixed the #1 cause of "tapped the button and nothing happened": the dispatcher answered every callback once at the top, and the ~20 handlers that answer again raised `query is already answered`, aborting the branch mid-way (alerts never shown, screens never refreshed). All answers now go through a safe `_answer()` wrapper.
- Edit-Repo callbacks no longer split repository names at the first underscore — repos like `my_bot` used to break every browse/file/edit/delete action. Repo and path are now separated by `|` (impossible in repo names), with legacy-keyboard fallback.
- Repo pickers and file-search results moved to index-based callbacks so long repo names / deep paths can no longer overflow Telegram's 64-byte `callback_data` limit (which made whole screens fail to render).
- Stale multi-archive buttons (after 🏠 Home, restart, or account switch) now show "Session expired — please start again" instead of crashing silently (22 branches guarded).
- 🌐 Language, 🕐 Timezone, ⭐ Star and the Replace / Upload / Preview pickers fall back to a fresh message when the original message can no longer be edited, instead of doing nothing.

Flows
- AI name/description suggestions are no longer silently dropped for password-protected archives (single and multi mode).
- Encrypted archives sent during the "add files to repo" flow now explain that a password is needed instead of a generic error.
- Multi-archive descriptions are length-checked like single-archive ones, so a long description no longer loses the whole archive at execution time.
- Fork-by-URL list no longer corrupts URLs containing `.git` anywhere but the end (`my.gitlab-backup` case).
- "✏️ Edit Name" on the AI suggestion screen now returns to the AI confirmation screen instead of dropping the user into the empty 5-step wizard; repo names are sanitized before creation.
- Permanently failed file uploads stop retrying immediately instead of burning 8 identical requests per file.
- The bot no longer advertises 7z archives (they were never supported).

Multi-account manager
- Re-submitting an already-saved token no longer corrupts the active-account label while another account's token stays active.
- Connecting an 11th account via `/setgithub` now warns that the list is full instead of silently keeping an unsavable active token.
- Tag creation uses the repository's default branch (matching the prompt) instead of hardcoded `main`→`master`.

Reliability / security
- Rate-limited (403 with `X-RateLimit-Remaining: 0`) requests report a rate-limit message with reset time instead of a misleading token-permission error.
- `push_file` no longer double-encodes base64 content (documented contract fixed); `get_file_sha` survives directory paths.
- User records are restored with every directly-indexed key, so old-schema databases can't crash `add_history`, nav, or `/start`.
- Stats counters and admin DB iteration are now actually thread-safe (the bot runs in threaded mode).
- AI responses that are valid JSON but not an object (or with missing `message`) are handled instead of raising raw `AttributeError`.
- The secret scanner no longer skips CJK/emoji text files as "binary" (the old >30%-non-ASCII heuristic was a trivial scan bypass); real binaries are still skipped.
- `HTTP_TIMEOUT=0` is clamped to 1s instead of instantly timing out every request.
- File-log redaction now covers third-party loggers (telebot/urllib3) that bypass logger-attached filters; console detail lines can no longer interleave across threads; whitespace-only display names no longer crash log tagging.

## License

MIT
