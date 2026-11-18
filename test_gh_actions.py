"""
test_gh_actions.py — Offline tests for the GitHub Extras feature module.

We inject fake dependencies (fake bot, fake github_api, in-memory user store)
via gh_actions.configure(...) and drive handle()/on_text(). No network, no
running Telegram — we assert on the API calls made and the keyboards/text the
module produces. Keyboard builders return real telebot InlineKeyboardMarkup.

Run: python test_gh_actions.py
"""
import io
import os
import sys
from types import SimpleNamespace

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gh_actions as gx  # noqa: E402

PASSED = 0
FAILED = 0
def check(name, cond):
    global PASSED, FAILED
    if cond: PASSED += 1; print(f"  [PASS]  {name}")
    else:    FAILED += 1; print(f"  [FAIL]  {name}")
def divider(t): print(f"\n-- {t} " + "-" * max(0, 56 - len(t)))


# ── fakes ────────────────────────────────────────────────────
class FakeBot:
    def __init__(self): self.edits = []; self.sends = []
    def edit_message_text(self, text, chat_id, msg_id, parse_mode=None, reply_markup=None):
        self.edits.append(SimpleNamespace(text=text, kb=reply_markup))
    def send_message(self, chat_id, text, parse_mode=None, reply_markup=None):
        self.sends.append(SimpleNamespace(text=text, kb=reply_markup))
        return SimpleNamespace(message_id=999)
    def answer_callback_query(self, *a, **k): pass

class FakeGH:
    def __init__(self): self.calls = []; self.issue_seq = []
    def list_repos(self, token, per_page=15):
        self.calls.append(("list_repos", token)); return [{"name": "app", "private": False}]
    def get_user(self, token): return {"login": "octocat"}
    def list_issues(self, token, owner, repo, state="open", per_page=10):
        self.calls.append(("list_issues", owner, repo, state))
        return [{"number": 5, "title": "Bug", "state": "open", "labels": [{"name": "bug"}],
                 "comments": 1, "body": "det", "user": {"login": "a"}}]
    def get_issue(self, token, owner, repo, number):
        return {"number": number, "title": "Bug", "state": "open", "labels": [],
                "comments": 0, "body": "x", "user": {"login": "a"}}
    def create_issue(self, token, owner, repo, title, body="", labels=None):
        self.calls.append(("create_issue", owner, repo, title, body)); return {"number": 9, "html_url": "u", "title": title}
    def set_issue_state(self, token, owner, repo, number, state):
        self.calls.append(("set_issue_state", number, state)); return True
    def list_pull_requests(self, *a, **k): return []
    def list_releases(self, *a, **k): return []
    def list_tags(self, *a, **k): return []
    def list_branches(self, *a, **k): return []
    def get_repo_info(self, token, owner, repo):
        return {"default_branch": "main"}
    def create_tag(self, token, owner, repo, tag, from_ref="main"):
        self.calls.append(("create_tag", tag, from_ref)); return True

class FakeStore:
    def __init__(self): self.users = {}
    def get_user(self, uid): return self.users.setdefault(uid, {"github_token": "ghp_x", "draft": {}})
    def save_user(self, uid, data): self.users[uid] = data

def make_call(uid=111, msg_id=42):
    return SimpleNamespace(id="cq", message=SimpleNamespace(
        chat=SimpleNamespace(id=uid), message_id=msg_id))
def make_msg(uid=111, text=""):
    return SimpleNamespace(chat=SimpleNamespace(id=uid), message_id=77, text=text)

BOT, GH, STORE = FakeBot(), FakeGH(), FakeStore()
REPO_PICKER_CALLS = []
def fake_kb_repo_picker(repos, action, selected=None):
    REPO_PICKER_CALLS.append((len(repos), action))
    return SimpleNamespace(rows=[], is_repo_picker=True, action=action)

gx.configure(bot=BOT, gh=GH, get_user=STORE.get_user, save_user=STORE.save_user,
             add_history=lambda uid, e: STORE.get_user(uid).setdefault("hist", []).append(e),
             kb_repo_picker=fake_kb_repo_picker, escape=lambda s: s)


# ── handles() ────────────────────────────────────────────────
divider("handles() routing predicate")
check("menu_extras handled", gx.handles("menu_extras"))
check("gx_ handled", gx.handles("gx_iss_new"))
check("non-gx ignored", not gx.handles("menu_home"))
check("unrelated prefix ignored", not gx.handles("admin_panel"))


# ── keyboard builders ────────────────────────────────────────
divider("kb_extras_menu structure")
kb = gx.kb_extras_menu()
flat = [b for row in kb.keyboard for b in row]
cbs = [b.callback_data for b in flat]
check("4 feature entries + Home", cbs == ["gx_pick_issues", "gx_pick_pulls", "gx_pick_releases", "gx_pick_branches", "menu_home"])

divider("kb_list encodes ids and adds footer")
kb = gx.kb_list([("Issue #5", 5), ("v1/beta tag", "v1/beta")], "gx_tag_view", "empty")
flat = [b for row in kb.keyboard for b in row]
labels = [b.callback_data for b in flat]
check("plain int id kept", "gx_tag_view_5" in labels)
check("slash id is URL-encoded", "gx_tag_view_v1%2Fbeta" in labels)
check("footer has repick/menu/home", {"gx_repick", "gx_menu", "menu_home"} <= set(labels))

divider("kb_list empty state")
kb = gx.kb_list([], "pfx", "No items here", )
flat = [b for row in kb.keyboard for b in row]
check("empty shows noop button", any(b.callback_data == "gx_noop" for b in flat))


# ── dispatch: entry + repo pick ──────────────────────────────
divider("handle menu_extras shows extras menu")
BOT.edits.clear()
ok = gx.handle(111, "menu_extras", make_call())
check("consumed", ok is True)
check("rendered extras menu", BOT.edits and any("GitHub Extras" in e.text for e in BOT.edits))

divider("handle gx_pick_issues -> repo picker via shared helper")
BOT.edits.clear(); REPO_PICKER_CALLS.clear()
gx.handle(111, "gx_pick_issues", make_call())
check("called kb_repo_picker with action 'gx'", REPO_PICKER_CALLS and REPO_PICKER_CALLS[-1][1] == "gx")
check("draft gx_feat set to issues", STORE.get_user(111)["draft"].get("gx_feat") == "issues")

divider("handle gx_pick_issues without token warns")
u = STORE.get_user(222); u["github_token"] = ""; STORE.save_user(222, u)
BOT.edits.clear()
gx.handle(222, "gx_pick_issues", make_call(uid=222))
check("asks for token", BOT.edits and "GitHub token" in BOT.edits[-1].text)

divider("repo selection stores owner+repo and renders feature home")
BOT.edits.clear()
gx.handle(111, "gx_repo_app", make_call())
dr = STORE.get_user(111)["draft"]
check("draft gx_owner set", dr.get("gx_owner") == "octocat")
check("draft gx_repo set", dr.get("gx_repo") == "app")
check("issues fetched for selected repo", ("list_issues", "octocat", "app", "open") in GH.calls)


# ── issues list + view + close ───────────────────────────────
divider("issue view + close round-trip")
BOT.edits.clear()
gx.handle(111, "gx_iss_view_5", make_call())
check("issue detail rendered", BOT.edits and "#5" in BOT.edits[-1].text)
GH.calls.clear()
gx.handle(111, "gx_iss_close_5", make_call())
check("set_issue_state(closed) called", ("set_issue_state", 5, "closed") in GH.calls)


# ── text-input create: new issue (two-step) ──────────────────
divider("new issue create flow via on_text")
gx.handle(111, "gx_iss_new", make_call())
check("pending iss_title", STORE.get_user(111)["draft"].get("gx_pending") == "iss_title")
BOT.sends.clear(); GH.calls.clear()
handled = gx.on_text(111, make_msg(text="Login broken"))
check("first text consumed", handled is True)
check("advanced to iss_body", STORE.get_user(111)["draft"].get("gx_pending") == "iss_body")
check("title buffered", STORE.get_user(111)["draft"]["gx_buffer"].get("title") == "Login broken")
gx.on_text(111, make_msg(text="Steps to reproduce..."))
check("create_issue called with title+body", ("create_issue", "octocat", "app", "Login broken", "Steps to reproduce...") in GH.calls)
check("pending cleared after create", STORE.get_user(111)["draft"].get("gx_pending") is None)

divider("on_text cancel via slash command")
STORE.get_user(333)["draft"] = {"gx_repo": "app", "gx_owner": "octocat", "gx_pending": "iss_title"}
handled = gx.on_text(333, make_msg(uid=333, text="/cancel"))
check("cancel consumed", handled is True)
check("pending cleared on cancel", STORE.get_user(333)["draft"].get("gx_pending") is None)

divider("on_text passthrough when no gx flow active")
STORE.get_user(444)["draft"] = {}
check("returns False when idle", gx.on_text(444, make_msg(uid=444, text="hi")) is False)


# ── tag create via text ──────────────────────────────────────
divider("new tag create flow")
STORE.get_user(555)["draft"] = {"gx_repo": "app", "gx_owner": "octocat", "gx_pending": "tag_name"}
GH.calls.clear()
gx.on_text(555, make_msg(uid=555, text="v2.0.0"))
check("create_tag called on default branch", ("create_tag", "v2.0.0", "main") in GH.calls)


# ── summary ──────────────────────────────────────────────────
divider("SUMMARY")
total = PASSED + FAILED
print(f"  {PASSED}/{total} passed")
sys.stdout.flush()
sys.exit(1 if FAILED else 0)
