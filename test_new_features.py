"""
test_new_features.py — Offline tests for the Upload-to-Repo and Live Preview
features added on top of the Replace-Repo flow.

No network: github_api._session is monkeypatched with a fake session so the
new Pages endpoints are verified deterministically. bot.py is imported with a
dummy BOT_TOKEN (no polling starts at import time).

Run: python test_new_features.py
"""
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
os.environ.setdefault("BOT_TOKEN", "123456789:TEST-TOKEN-FOR-UNIT-TESTS")
os.environ.setdefault("ADMIN_CHAT_ID", "123456789")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests  # noqa: E402
import github_api as gh  # noqa: E402
import localization  # noqa: E402


# ── tiny test harness ────────────────────────────────────────
PASSED = 0
FAILED = 0


def check(name, cond):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  [PASS]  {name}")
    else:
        FAILED += 1
        print(f"  [FAIL]  {name}")


def divider(title):
    print(f"\n-- {title} " + "-" * max(0, 58 - len(title)))


class FakeResp:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = text or (str(self._payload) if self._payload else "")

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    """Records calls per verb and returns a canned or queued response."""
    def __init__(self):
        self.calls = []
        self._resp = FakeResp()
        self._queue = []

    def queue(self, resp):
        self._resp = resp

    def queue_seq(self, *resps):
        self._queue = list(resps)

    def _next(self):
        if self._queue:
            return self._queue.pop(0)
        return self._resp

    def get(self, url, **kw):
        self.calls.append(("GET", url, kw))
        return self._next()

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        return self._next()

    def patch(self, url, **kw):
        self.calls.append(("PATCH", url, kw))
        return self._next()

    def put(self, url, **kw):
        self.calls.append(("PUT", url, kw))
        return self._next()

    def delete(self, url, **kw):
        self.calls.append(("DELETE", url, kw))
        return self._next()


class NetErrSession:
    def get(self, url, **kw):
        raise requests.RequestException("boom")

    def post(self, url, **kw):
        raise requests.RequestException("boom")


# ── Live Preview: find_html_entry ────────────────────────────
def test_find_html_entry():
    divider("find_html_entry")
    tree = [
        {"path": "README.md", "type": "blob"},
        {"path": "assets/style.css", "type": "blob"},
        {"path": "docs/guide.html", "type": "blob"},
        {"path": "index.html", "type": "blob"},
        {"path": "app.js", "type": "blob"},
    ]
    check("root index.html wins", gh.find_html_entry(tree) == "index.html")

    tree2 = [{"path": "index.htm", "type": "blob"}, {"path": "x.html", "type": "blob"}]
    check("index.htm accepted", gh.find_html_entry(tree2) == "index.htm")

    tree3 = [{"path": "a/b/deep.html", "type": "blob"}, {"path": "top.html", "type": "blob"}]
    check("shallowest nested html picked", gh.find_html_entry(tree3) == "top.html")

    tree4 = [{"path": "readme.md", "type": "blob"}, {"path": "main.py", "type": "blob"}]
    check("no html -> None", gh.find_html_entry(tree4) is None)

    check("empty tree -> None", gh.find_html_entry([]) is None)


# ── Pages API: get_pages_info / enable_pages ─────────────────
def test_get_pages_info():
    divider("get_pages_info")
    fake = FakeSession()
    old = gh._session
    try:
        fake.queue(FakeResp(200, {"html_url": "https://o.github.io/r/", "status": "built"}))
        gh._session = fake
        info = gh.get_pages_info("tok", "o", "r")
        check("200 returns dict", info and info.get("status") == "built")
        verb, url, _ = fake.calls[0]
        check("hits /pages endpoint", verb == "GET" and url.endswith("/repos/o/r/pages"))

        fake2 = FakeSession()
        fake2.queue(FakeResp(404, {"message": "Not Found"}))
        gh._session = fake2
        check("404 -> None", gh.get_pages_info("tok", "o", "r") is None)

        gh._session = NetErrSession()
        check("network error -> None", gh.get_pages_info("tok", "o", "r") is None)
    finally:
        gh._session = old


def test_enable_pages():
    divider("enable_pages")
    fake = FakeSession()
    old = gh._session
    try:
        fake.queue(FakeResp(201, {"html_url": "https://o.github.io/r/"}))
        gh._session = fake
        ok, why = gh.enable_pages("tok", "o", "r", branch="main")
        check("201 -> created", ok and why == "created")
        verb, url, kw = fake.calls[0]
        check("POSTs /pages", verb == "POST" and url.endswith("/repos/o/r/pages"))
        check("payload carries branch source",
              kw.get("json") == {"source": {"branch": "main", "path": "/"}})

        fake2 = FakeSession()
        fake2.queue(FakeResp(409, {"message": "already exists"}))
        gh._session = fake2
        check("409 -> exists", gh.enable_pages("tok", "o", "r") == (True, "exists"))

        fake3 = FakeSession()
        fake3.queue(FakeResp(403, {"message": "private repos need pro"}))
        gh._session = fake3
        check("403 -> private", gh.enable_pages("tok", "o", "r") == (False, "private"))

        fake4 = FakeSession()
        fake4.queue(FakeResp(500, {"message": "boom"}))
        gh._session = fake4
        check("500 -> error", gh.enable_pages("tok", "o", "r") == (False, "error"))

        gh._session = NetErrSession()
        check("network error -> error", gh.enable_pages("tok", "o", "r") == (False, "error"))
    finally:
        gh._session = old


# ── Upload to Repo: folder path validation ───────────────────
def test_normalize_upload_folder():
    divider("_normalize_upload_folder")
    from bot import _normalize_upload_folder as norm

    check("empty -> root", norm("") == "")
    check("dot -> root", norm(".") == "")
    check("slash -> root", norm("/") == "")
    check("spaces -> root", norm("   ") == "")
    check("simple path kept", norm("docs") == "docs")
    check("nested path kept", norm("assets/images") == "assets/images")
    check("leading slash stripped", norm("/docs/") == "docs")
    check("backslash converted", norm("a\\b") == "a/b")
    check("trailing slash stripped", norm("docs/") == "docs")
    check("dot segments removed", norm("docs/./img") == "docs/img")
    check("double slash collapsed", norm("docs//img") == "docs/img")
    check("traversal rejected", norm("../etc") is None)
    check("inner traversal rejected", norm("docs/../../../etc") is None)
    check("control chars rejected", norm("docs\x00img") is None)
    check("overlong path rejected", norm("a" * 301) is None)
    check("null byte deep rejected", norm("a/b/c\x0b") is None)


# ── Localization ─────────────────────────────────────────────
def test_localization_keys():
    divider("localization")
    for lang in ("en", "hi", "bn", "es"):
        entry = localization._TEXT[lang]
        check(f"{lang}: upload_files present", bool(entry.get("upload_files")))
        check(f"{lang}: live_preview present", bool(entry.get("live_preview")))
    check("translate falls back for hi", localization.translate("hi", "upload_files") ==
          localization._TEXT["hi"]["upload_files"])
    check("unknown lang -> english", localization.translate("xx", "upload_files") ==
          localization._TEXT["en"]["upload_files"])


# ── Keyboards & menu wiring (structural checks) ──────────────
def test_keyboard_and_menu():
    divider("keyboards & menu wiring")
    import bot

    kb = bot.kb_upload_picker([{"name": "alpha", "private": False},
                               {"name": "beta", "private": True}], 0)
    datas = [b.callback_data for row in kb.keyboard for b in row]
    check("upload picker uses index callbacks", "up_pick_0" in datas and "up_pick_1" in datas)
    check("upload picker has home", "menu_home" in datas)

    kb2 = bot.kb_upload_collect(2)
    datas2 = [b.callback_data for row in kb2.keyboard for b in row]
    check("collect keyboard: Done/Reset/Home",
          "up_done" in datas2 and "up_reset" in datas2 and "menu_home" in datas2)

    kb3 = bot.kb_live_preview(pages_url="https://o.github.io/r/",
                              quick_url="https://htmlpreview.github.io/?x",
                              enable_btn=False)
    urls = [b.url for row in kb3.keyboard for b in row if getattr(b, "url", None)]
    cbs = [b.callback_data for row in kb3.keyboard for b in row if b.callback_data]
    check("pages url button", "https://o.github.io/r/" in urls)
    check("quick preview url button", "https://htmlpreview.github.io/?x" in urls)
    check("refresh + another repo + home",
          "lp_open" in cbs and "menu_live_preview" in cbs and "menu_home" in cbs)
    check("no enable button when ready",
          "lp_enable" not in cbs)

    kb4 = bot.kb_sec_warn_upload()
    datas4 = [b.callback_data for row in kb4.keyboard for b in row]
    check("sec warn upload buttons",
          "sec_warn_upload_edit" in datas4 and "sec_warn_upload_proceed" in datas4
          and "sec_warn_cancel" in datas4)

    # Main menu carries the two new entries
    kb5 = bot.kb_main(0)
    datas5 = [b.callback_data for row in kb5.keyboard for b in row]
    check("main menu has Upload to Repo", "menu_upload_files" in datas5)
    check("main menu has Live Preview", "menu_live_preview" in datas5)

    # Command menu includes the new commands
    cmds = [c for c, _ in bot._COMMAND_MENU]
    check("command menu has /upload", "upload" in cmds)
    check("command menu has /preview", "preview" in cmds)


# ── Callback dispatcher coverage (static) ────────────────────
def test_callback_coverage():
    divider("callback dispatcher coverage")
    import re
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "bot.py"),
              encoding="utf-8") as f:
        text = f.read()
    handler = text[text.index("@bot.callback_query_handler"):]
    for pattern in ("menu_upload_files", "up_pick_", "up_page_", "up_root",
                    "up_path_type", "up_done", "up_reset", "up_noop",
                    "sec_warn_upload_proceed", "sec_warn_upload_edit",
                    "menu_live_preview", "lp_open", "lp_pick_", "lp_page_",
                    "lp_noop", "lp_enable", "er_preview"):
        check(f"dispatcher handles {pattern}",
              f'data == "{pattern}"' in handler or f'data.startswith("{pattern}")' in handler)


def main():
    print("\n=== New Features Test Suite ===")
    test_find_html_entry()
    test_get_pages_info()
    test_enable_pages()
    test_normalize_upload_folder()
    test_localization_keys()
    test_keyboard_and_menu()
    test_callback_coverage()
    print(f"\n{'='*60}")
    print(f"TOTAL: {PASSED + FAILED}  |  PASSED: {PASSED}  |  FAILED: {FAILED}")
    print(f"{'='*60}")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
