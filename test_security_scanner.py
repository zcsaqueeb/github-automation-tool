"""
test_security_scanner.py — Smoke tests for the sensitive-data scanner.

Run with:  python test_security_scanner.py
No external dependencies beyond the project's own requirements.

IMPORTANT: this file imports the real scanner straight out of ``bot.py``
(``_is_sensitive_filename``, ``_scan_content``, the pattern tables) instead
of keeping a hand-copied duplicate. A duplicated copy silently drifts out
of sync every time the real patterns change in bot.py, which means the
tests stop testing the code that actually runs. Importing guarantees the
tests always exercise the exact same code path GitHub uploads go through.
"""

from __future__ import annotations

import base64
import io
import os
import sys
import uuid
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Importing bot.py requires BOT_TOKEN / ADMIN_CHAT_ID to pass config.validate().
# Provide harmless throwaway values for the test process only, never touching
# the real .env, so this file can run in CI / a fresh checkout with no secrets
# configured at all.
os.environ.setdefault("BOT_TOKEN", "000000000:TEST-TOKEN-FOR-UNIT-TESTS-ONLY-000000")
os.environ.setdefault("ADMIN_CHAT_ID", "1")
os.environ.setdefault("DB_FILE", os.path.join(os.path.dirname(__file__), f".test_users.{uuid.uuid4().hex}.json"))
os.environ.setdefault("LOG_FILE", os.path.join(os.path.dirname(__file__), ".test_bot.log"))
os.environ.setdefault("CLI_ANIMATION", "false")

# config.validate() (run at bot.py import time) treats a missing encryption
# key as a fatal error, so generate a disposable, valid-format Fernet key
# for this test process only — it never touches the real .env and nothing
# encrypted with it is meant to persist beyond the test run.
if not os.environ.get("DATA_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["DATA_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import bot  # noqa: E402  (must import after env vars are set above)
import github_api  # noqa: E402

_is_sensitive_filename = bot._is_sensitive_filename
_scan_content = bot._scan_content


def test_repo_description_is_limited_to_github_maximum() -> None:
    class Response:
        status_code = 201
        text = ""

        @staticmethod
        def json():
            return {"name": "demo"}

    original_post = github_api._session.post
    captured = {}

    def fake_post(*args, **kwargs):
        captured.update(kwargs.get("json", {}))
        return Response()

    github_api._session.post = fake_post
    try:
        try:
            github_api.create_repo("token", "demo", "x" * 500)
            raise AssertionError("overlong description was accepted")
        except github_api.GitHubError as exc:
            assert exc.status == 422
            assert "350" in str(exc)
    finally:
        github_api._session.post = original_post
    assert not captured


def test_readme_repo_link_is_top_level() -> None:
    url = "https://github.com/example-owner/demo-repo"
    output = bot._polish_readme("# Demo Repo\n\n## Overview\nText", "demo-repo", repo_url=url)
    assert output.index(url) < output.index("## Overview")
    assert output.count(url) == 1


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


# ─────────────────────────────────────────────────────────────
#  Test cases
# ─────────────────────────────────────────────────────────────

PASS = "PASS"
FAIL = "FAIL"
results: list[tuple[bool, str, object]] = []


def check(desc: str, got, expected_true: bool = True) -> None:
    ok = bool(got) == expected_true
    results.append((ok, desc, got))
    status = PASS if ok else FAIL
    print(f"  [{status}]  {desc}")
    if not ok:
        print(f"          got: {got!r}")


def run() -> int:
    print("\n-- Filename detection -------------------------------------")
    check(".env", _is_sensitive_filename(".env"))
    check(".env.local", _is_sensitive_filename(".env.local"))
    check(".env.production", _is_sensitive_filename(".env.production"))
    check("config/.env", _is_sensitive_filename("config/.env"))
    check("id_rsa", _is_sensitive_filename("id_rsa"))
    check("id_ed25519", _is_sensitive_filename("id_ed25519"))
    check("secrets.json", _is_sensitive_filename("secrets.json"))
    check("credentials.yml", _is_sensitive_filename("credentials.yml"))
    check("server.pem", _is_sensitive_filename("server.pem"))
    check("private.key", _is_sensitive_filename("private.key"))
    check("wp-config.php", _is_sensitive_filename("wp-config.php"))
    check("service_account.json", _is_sensitive_filename("service_account.json"))
    check("firebase-adminsdk-xyz.json", _is_sensitive_filename("firebase-adminsdk-xyz.json"))
    check("kubeconfig", _is_sensitive_filename("kubeconfig"))
    check(".kube/config", _is_sensitive_filename(".kube/config"))
    check("terraform.tfvars", _is_sensitive_filename("terraform.tfvars"))
    check("database.yml", _is_sensitive_filename("database.yml"))
    check("keystore.jks", _is_sensitive_filename("keystore.jks"))
    check(".netrc", _is_sensitive_filename(".netrc"))
    check("README.md (safe)", _is_sensitive_filename("README.md"), expected_true=False)
    check("main.py (safe)", _is_sensitive_filename("main.py"), expected_true=False)
    check("requirements.txt (safe)", _is_sensitive_filename("requirements.txt"), expected_true=False)
    check("config.py (NOT flagged by name)", _is_sensitive_filename("config.py"), expected_true=False)

    print("\n-- Content detection ---------------------------------------")
    check("GitHub PAT", _scan_content("token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"))
    check("AWS key ID", _scan_content("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"))
    check("AWS secret key", _scan_content(
        "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1"))
    check("Google API key", _scan_content("key=AIzaSyD-9tSrke72xVTnkR43_some_key_here12345"))
    check("Stripe live", _scan_content("sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZabc"))
    check("Slack token", _scan_content("token: xoxb-123456789012-1234567890123-abc123def456ghi"))
    check("Slack webhook", _scan_content(
        "https://hooks.slack.com/services/T0000000/B0000000/abcdefghijklmnopqrstuvwx"))
    check("Telegram token", _scan_content("BOT_TOKEN=7038523846:AAHnjHXZtJi3-kk2bZGRHmRq3n-_jMfGu0g"))
    check("OpenAI key", _scan_content("OPENAI_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"))
    check("Anthropic key", _scan_content("key = sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"))
    check("Groq key", _scan_content("GROQ_KEY=gsk_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno"))
    check("Bearer token", _scan_content("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signaturevalue123"))
    check("JWT token", _scan_content("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signaturevalue123"))
    check("Hugging Face token", _scan_content("HF_TOKEN=hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"))
    check("GitLab token", _scan_content("glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"))
    check("npm token", _scan_content("npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"))
    check("PyPI token", _scan_content("pypi-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"))
    check("SendGrid key", _scan_content("SG.ABCDEFGHIJKLMNOPQRSTUVWXYZ.abcdefghijklmnopqrstuvwxyz123456"))
    check("Expo token", _scan_content("EXPO_TOKEN=expo_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"))
    check("Mobile API secret", _scan_content("ANDROID_API_SECRET=abcdefghijklmnopqrstuvwxyz123456"))
    check("Ethereum private key", _scan_content("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
    check("Bitcoin extended private key", _scan_content("xprv" + "a" * 90))
    check("Wallet seed phrase", _scan_content("wallet_seed_phrase = abandon ability able about above absent absorb abstract"))
    check("Crypto exchange secret", _scan_content("BINANCE_API_SECRET=abcdefghijklmnopqrstuvwxyz123456"))
    check("Blockchain RPC key", _scan_content("INFURA_API_KEY=abcdefghijklmnopqrstuvwxyz123456"))
    check("PEM private key", _scan_content("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK..."))
    check("Password field", _scan_content("password=supersecret123"))
    check("DB conn string", _scan_content("DATABASE_URL=postgresql://admin:p@ssw0rd@db.host/mydb"))
    check("Encryption key", _scan_content("DATA_ENCRYPTION_KEY=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef=="))
    check("Fernet key label", _scan_content("fernet_key = 'D8lb6V9yv-90kCyHXNbCmf8G-350U87FSLM0Xldeypc='"))

    # Should NOT flag these
    check("Plain text (safe)", _scan_content("Hello world, this is a README."), expected_true=False)
    check("Short password= (too short)", _scan_content("password=hi"), expected_true=False)
    check("Git config no secret", _scan_content("[core]\n  autocrlf = true"), expected_true=False)
    check("URL no creds", _scan_content("https://github.com/user/repo"), expected_true=False)

    print("\n-- End-to-end: scan_files_for_secrets -----------------------")
    flagged = bot.scan_files_for_secrets([
        {"path": ".env", "content_b64": _b64("BOT_TOKEN=123:abc\nSECRET=xyz")},
        {"path": "README.md", "content_b64": _b64("# Hello\nJust docs, nothing sensitive here.")},
    ])
    check("Flags known-sensitive filename in a batch", flagged.get("flagged_files"))
    flagged_paths = {f["path"] for f in flagged.get("flagged_files", [])}
    check(".env correctly identified in batch result", ".env" in flagged_paths)
    check("README.md NOT flagged in batch result", "README.md" in flagged_paths, expected_true=False)

    # Direct Telegram uploads use {name, content}, not archive-style
    # {path, content_b64}. Both representations must be protected.
    direct_flagged = bot.scan_files_for_secrets([
        {"name": ".env", "content": "API_KEY=super-secret-value-123456", "source": "text"},
    ])
    check("Flags sensitive filename in a direct upload", direct_flagged.get("flagged_files"))
    warning = bot._format_security_warning(direct_flagged, "demo")
    check("Security warning does not reveal a full secret", "super-secret-value-123456" not in warning)
    check("Security warning tells user upload is blocked", "Upload blocked" in warning)
    oversized_batch = bot.scan_files_for_secrets([
        {"name": f"safe-{i}.txt", "content": "ordinary text", "source": "text"}
        for i in range(bot._SCAN_MAX_FILES + 1)
    ])
    check("Reports files beyond scan limit", oversized_batch["truncated_files"] == 1)

    print("\n-- GitHub Contents API path encoding -------------------------")
    # Regression test: raw (unencoded) paths containing spaces, parens, '#',
    # or unicode characters previously produced a malformed request URL that
    # GitHub answered with a silent 404 — the file was dropped with no
    # visible error. _encode_path() must escape every segment while still
    # preserving '/' as a path separator.
    check(
        "Encodes spaces, parens, # and unicode",
        github_api._encode_path("src/a b (1)/файл#2.py")
        == "src/a%20b%20%281%29/%D1%84%D0%B0%D0%B9%D0%BB%232.py",
    )
    check(
        "Plain ASCII path is left readable",
        github_api._encode_path("README.md") == "README.md",
    )
    check(
        "Directory separators are preserved, not encoded",
        "/" in github_api._encode_path("src/lib/main.py")
        and "%2F" not in github_api._encode_path("src/lib/main.py"),
    )
    check("Empty path doesn't crash", github_api._encode_path("") == "")

    print("\n-- Archive decompression-bomb guard ---------------------------")
    # A small compressed file that expands far past the per-file cap must be
    # rejected before it fully inflates in memory.
    bomb_buf = io.BytesIO()
    with zipfile.ZipFile(bomb_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge.bin", b"0" * (30 * 1024 * 1024))  # 30 MB of zeros
    try:
        bot._extract_archive(bomb_buf.getvalue(), "huge.zip")
        check("Oversized archive member is rejected", False)
    except bot.ArchiveTooLargeError:
        check("Oversized archive member is rejected", True)

    # A normal, small archive must still extract correctly.
    ok_buf = io.BytesIO()
    with zipfile.ZipFile(ok_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.md", "# hello world")
        zf.writestr("src/main.py", "print('hi')")
    ok_files = bot._extract_archive(ok_buf.getvalue(), "normal.zip")
    ok_paths = sorted(f["path"] for f in ok_files)
    check("Normal archive still extracts all files", ok_paths == ["README.md", "src/main.py"])

    print("\n-- Markdown escaping (support tickets / admin replies) --------")
    check("Escapes underscores/asterisks/backticks/brackets",
          bot._escape_md("_hi_ *bold* `code` [link]")
          == "\\_hi\\_ \\*bold\\* \\`code\\` \\[link]")
    check("Empty string passes through", bot._escape_md("") == "")
    check("Plain text unchanged", bot._escape_md("hello world") == "hello world")

    print("\n-- Admin privilege restriction ---------------------------------")
    # Only the primary admin (config.ADMIN_CHAT_ID) may promote/demote.
    # A non-primary admin must not see promote/demote controls for another
    # user, and must never be offered controls on themself either.
    primary = bot.ADMIN_CHAT_ID
    other_admin = primary + 1
    plain_user = primary + 2
    kb_for_primary_viewing_other = bot.kb_admin_user(other_admin, viewer_uid=primary)
    kb_for_other_viewing_plain = bot.kb_admin_user(plain_user, viewer_uid=other_admin)

    def _has_admin_toggle(markup):
        for row in markup.keyboard:
            for btn in row:
                if btn.callback_data and (
                    btn.callback_data.startswith("admin_promote_")
                    or btn.callback_data.startswith("admin_demote_")
                ):
                    return True
        return False

    check("Primary admin sees promote/demote controls",
          _has_admin_toggle(kb_for_primary_viewing_other))
    check("Non-primary admin does NOT see promote/demote controls",
          not _has_admin_toggle(kb_for_other_viewing_plain))

    print("\n-- Home navigation -----------------------------------------------")
    home_buttons = [
        button for row in bot.kb_main(primary).keyboard for button in row
        if button.callback_data == "menu_home"
    ]
    check("Main menu does not duplicate its own Home button", len(home_buttons) == 0)
    home_only_buttons = [
        button for row in bot.kb_home_only(primary).keyboard for button in row
        if button.callback_data == "menu_home"
    ]
    check("Result screens retain exactly one Home button", len(home_only_buttons) == 1)

    print("\n-- Support ticket persistence -----------------------------------")
    test_uid = 999999001
    tu = bot.get_user(test_uid)
    tu["pending_tickets"] = []
    bot.save_user(test_uid, tu)
    tu = bot.get_user(test_uid)
    tu.setdefault("pending_tickets", [])
    tu["pending_tickets"].append({
        "text": "test ticket body",
        "created_at": "2026-01-01T00:00:00+00:00",
    })
    bot.save_user(test_uid, tu)
    reloaded = bot.get_user(test_uid)
    check("Ticket persists on the user record", len(reloaded.get("pending_tickets", [])) == 1)
    check("Ticket text round-trips correctly",
          reloaded["pending_tickets"][0]["text"] == "test ticket body")
    with open(os.environ["DB_FILE"], "r", encoding="utf-8") as db_file:
        on_disk = db_file.read()
    check("Entire users database is encrypted at rest", on_disk.startswith("enc:"))
    # Clearing (what a reply/dismiss does) must fully empty the list.
    reloaded["pending_tickets"] = []
    bot.save_user(test_uid, reloaded)
    check("Clearing tickets leaves an empty list", bot.get_user(test_uid)["pending_tickets"] == [])
    # Clean up the test fixture user so it doesn't pollute a real run.
    bot._db.pop(str(test_uid), None)
    bot._save(bot._db)

    print("\n-- Log redaction (defense in depth) ----------------------------")
    import cli_log
    _redact = cli_log._redact
    check("Redacts GitHub PAT (ghp_)",
          "[REDACTED]" in _redact("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"))
    check("Redacts GitHub fine-grained PAT",
          "[REDACTED]" in _redact("github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz1234567890"))
    check("Redacts Anthropic key",
          "[REDACTED]" in _redact("sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"))
    check("Redacts OpenAI-style key",
          "[REDACTED]" in _redact("sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"))
    check("Redacts Groq key",
          "[REDACTED]" in _redact("gsk_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno"))
    check("Redacts Google API key",
          "[REDACTED]" in _redact("AIzaSyD-9tSrke72xVTnkR43_some_key_here12345"))
    check("Redacts Telegram bot token",
          "[REDACTED]" in _redact("7038523846:AAHnjHXZtJi3-kk2bZGRHmRq3n-_jMfGu0g"))
    check("Redacts Fernet key",
          "[REDACTED]" in _redact("D8lb6V9yv-90kCyHXNbCmf8G-350U87FSLM0Xldeypc="))
    check("Redacts password=value",
          "[REDACTED]" in _redact("password=supersecret123"))
    check("Redacts api_key: value",
          "[REDACTED]" in _redact("api_key: abc123xyz789"))
    check("Redacts JWT in error output",
          "[REDACTED]" in _redact("request failed: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signaturevalue123"))
    check("Redacts database URL credentials",
          "[REDACTED]" in _redact("postgresql://admin:secret-password@db.example/app"))
    check("Plain log line is untouched",
          _redact("Hello world, this is a plain log line.") == "Hello world, this is a plain log line.")
    check("Numeric user IDs are not falsely redacted",
          _redact("User 12345 created repo test-repo") == "User 12345 created repo test-repo")

    print("\n-- Secret-message scrubbing helper ------------------------------")
    # _scrub_secret_message must never raise even when deletion fails
    # (e.g. message already gone, or bot lacks delete permission) — it's
    # best-effort and must never block the calling flow.
    try:
        bot._scrub_secret_message(999999002, 1)  # bogus uid/message_id, will fail
        check("_scrub_secret_message never raises on failure", True)
    except Exception:
        check("_scrub_secret_message never raises on failure", False)

    print("\n-------------------------------------------------------------")
    total = len(results)
    passed = sum(1 for ok, *_ in results if ok)
    failed = total - passed
    print(f"\n  {passed}/{total} passed" + (f"   {failed} FAILED" if failed else "") + "\n")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
