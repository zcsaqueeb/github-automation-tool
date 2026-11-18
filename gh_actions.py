"""
gh_actions.py — GitHub "extras" feature set for the bot:
Issues, Pull Requests, Releases & Tags, Branches & Commits.

Kept out of the monolithic bot.py on purpose (organize). bot.py wires this in
with a few additive hooks and calls configure(...) with the shared singletons
it needs (telebot instance, github_api module, user store, and the existing
keyboard helpers). All per-flow state lives in the per-user draft dict so no
repo name is ever embedded in callback_data.

Callback namespace: everything starts with "gx_" (plus the "menu_extras"
entry). Text-input create flows are driven by draft["gx_pending"].
"""
from __future__ import annotations

from urllib.parse import quote, unquote

D: dict = {}


def configure(**deps) -> None:
    """Expected deps: bot, gh, get_user, save_user, add_history,
    kb_repo_picker, escape (optional _bump for counters)."""
    D.update(deps)


def handles(data: str) -> bool:
    return data == "menu_extras" or data.startswith("gx_")


# ── local helpers ─────────────────────────────────────────────
def _IK():
    from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
    return InlineKeyboardMarkup, InlineKeyboardButton

def _bot(): return D["bot"]
def _gh():  return D["gh"]
def _esc(s):
    fn = D.get("escape")
    return fn(s) if fn else (s or "")

def _short(s, n=60):
    s = (s or "").replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"

def _edit(uid, msg_id, text, kb=None):
    try:
        _bot().edit_message_text(text, uid, msg_id, parse_mode="Markdown", reply_markup=kb)
    except Exception:
        try:
            _bot().send_message(uid, text, parse_mode="Markdown", reply_markup=kb)
        except Exception:
            pass

def _token(uid):
    return D["get_user"](uid).get("github_token") or ""

def _ctx(uid):
    u = D["get_user"](uid)
    dr = (u.get("draft") or {})
    return u, dr, dr.get("gx_repo", ""), dr.get("gx_owner", "")

def _set_draft(uid, **kv):
    u = D["get_user"](uid)
    dr = u.get("draft") or {}
    dr.update(kv)
    u["draft"] = dr
    D["save_user"](uid, u)
    return dr


# ══════════════════════════════════════════════════════════════
#  Keyboard builders (pure — unit-testable without Telegram)
# ══════════════════════════════════════════════════════════════
def kb_extras_menu():
    M, B = _IK()
    kb = M(row_width=1)
    kb.add(
        B("🎫 Issues",             callback_data="gx_pick_issues"),
        B("🔀 Pull Requests",      callback_data="gx_pick_pulls"),
        B("🏷 Releases & Tags",   callback_data="gx_pick_releases"),
        B("🌿 Branches & Commits", callback_data="gx_pick_branches"),
        B("🏠 Home",               callback_data="menu_home"),
    )
    return kb


def kb_back_only():
    M, B = _IK()
    kb = M(row_width=2)
    kb.add(B("◀ Extras", callback_data="gx_menu"), B("🏠 Home", callback_data="menu_home"))
    return kb


def kb_list(items, cb_prefix, empty_label, nav_rows=None):
    """items: list of (label, ident). ident is URL-encoded into the callback."""
    M, B = _IK()
    kb = M(row_width=1)
    if not items:
        kb.add(B(empty_label, callback_data="gx_noop"))
    else:
        for label, ident in items:
            kb.add(B(label, callback_data=f"{cb_prefix}_{quote(str(ident), safe='')}"))
    for row in (nav_rows or []):
        kb.row(*row)
    kb.add(
        B("🔁 Pick Another Repo", callback_data="gx_repick"),
        B("🗂 Extras Menu",       callback_data="gx_menu"),
        B("🏠 Home",             callback_data="menu_home"),
    )
    return kb


def kb_issue_detail(number, state):
    M, B = _IK()
    kb = M(row_width=2)
    if state == "open":
        kb.add(B("🔴 Close Issue", callback_data=f"gx_iss_close_{number}"))
    else:
        kb.add(B("🟢 Reopen Issue", callback_data=f"gx_iss_reopen_{number}"))
    kb.add(B("◀ Issue list", callback_data="gx_feat_issues"),
           B("🏠 Home", callback_data="menu_home"))
    return kb


def kb_confirm(label, cb):
    M, B = _IK()
    kb = M(row_width=2)
    kb.add(B(label, callback_data=cb), B("◀ Cancel", callback_data="gx_menu"))
    kb.add(B("🏠 Home", callback_data="menu_home"))
    return kb


# ══════════════════════════════════════════════════════════════
#  Entry + repo selection
# ══════════════════════════════════════════════════════════════
def handle(uid: int, data: str, call) -> bool:
    """Dispatch a gx_* / menu_extras callback. Returns True if consumed."""
    try:
        return _dispatch(uid, data, call)
    except Exception as ex:
        _edit(uid, call.message.message_id,
              f"❌ Something went wrong: `{_esc(str(ex))}`", kb_back_only())
        return True


def _dispatch(uid, data, call) -> bool:
    msg_id = call.message.message_id

    if data in ("menu_extras", "gx_menu"):
        _edit(uid, msg_id,
              "🧩 *GitHub Extras*\n\nPick a capability to manage on one of your repos:",
              kb_extras_menu())
        return True

    if data == "gx_noop":
        return True

    if data == "gx_repick":
        feat = _ctx(uid)[1].get("gx_feat", "issues")
        _begin_repo_pick(uid, msg_id, feat)
        return True

    if data in ("gx_pick_issues", "gx_pick_pulls", "gx_pick_releases", "gx_pick_branches"):
        _begin_repo_pick(uid, msg_id, data[len("gx_pick_"):])
        return True

    if data.startswith("gx_repo_"):
        _select_repo(uid, msg_id, data[len("gx_repo_"):])
        return True

    # re-open a feature on the currently-selected repo
    if data.startswith("gx_feat_"):
        _render_feature_home(uid, msg_id, data[len("gx_feat_"):])
        return True

    if data.startswith("gx_iss_"): return _issues_cb(uid, data, msg_id)
    if data.startswith("gx_pr_"):  return _pulls_cb(uid, data, msg_id)
    if data.startswith("gx_rel_"): return _releases_cb(uid, data, msg_id)
    if data.startswith("gx_tag_"): return _tags_cb(uid, data, msg_id)
    if data.startswith("gx_br_"):  return _branches_cb(uid, data, msg_id)
    return False


def _begin_repo_pick(uid, msg_id, feat):
    token = _token(uid)
    if not token:
        _edit(uid, msg_id, "⚠️ Set your GitHub token first via /setgithub.", kb_back_only())
        return
    _set_draft(uid, gx_feat=feat)
    _edit(uid, msg_id, "⏳ Loading your repos…", None)
    repos = _gh().list_repos(token, per_page=15)
    _edit(uid, msg_id,
          "📦 *Pick a repository*\n\nChoose the repo to act on:",
          D["kb_repo_picker"](repos, "gx"))


def _select_repo(uid, msg_id, name):
    token = _token(uid)
    info = _gh().get_user(token)
    owner = info["login"] if info else ""
    dr = _set_draft(uid, gx_repo=name, gx_owner=owner)
    _render_feature_home(uid, msg_id, dr.get("gx_feat", "issues"))


def _render_feature_home(uid, msg_id, feat):
    if not _ctx(uid)[2]:
        _edit(uid, msg_id, "⚠️ No repo selected — pick one first.", kb_extras_menu())
        return
    {"issues": lambda: _show_issues(uid, msg_id, "open"),
     "pulls":  lambda: _show_pulls(uid, msg_id, "open"),
     "releases": lambda: _show_releases(uid, msg_id),
     "branches": lambda: _show_branches(uid, msg_id)}.get(feat,
        lambda: _edit(uid, msg_id, "Unknown section.", kb_extras_menu()))()


# ══════════════════════════════════════════════════════════════
#  Issues
# ══════════════════════════════════════════════════════════════
def _show_issues(uid, msg_id, state="open"):
    _, dr, repo, owner = _ctx(uid)
    token = _token(uid)
    _set_draft(uid, gx_istate=state)
    issues = _gh().list_issues(token, owner, repo, state=state, per_page=12)
    items = []
    for it in issues:
        labels = ",".join(l["name"] for l in it.get("labels", []))
        badge = "🟢" if it.get("state") == "open" else "⚪"
        suffix = f" · {_short(labels, 18)}" if labels else ""
        items.append((f"{badge} #{it['number']} {_short(it.get('title',''))}{suffix}", it["number"]))
    _, B = _IK()
    toggle = "🔴 Show closed" if state == "open" else "🟢 Show open"
    nav = [[B("🆕 New Issue", callback_data="gx_iss_new"),
            B(toggle, callback_data=f"gx_iss_toggle_{state}")]]
    _edit(uid, msg_id,
          f"🎫 *Issues · {_esc(repo)}*  _(showing {state}, {len(items)})_",
          kb_list(items, "gx_iss_view", "✅ No issues here yet", nav))


def _issues_cb(uid, data, msg_id):
    _, dr, repo, owner = _ctx(uid)
    token = _token(uid)
    if data == "gx_iss_new":
        _set_draft(uid, gx_pending="iss_title", gx_buffer={})
        _edit(uid, msg_id, "✍️ *New issue*\n\nSend the *title* (or /cancel):", None)
        return True
    if data.startswith("gx_iss_toggle_"):
        cur = data.rsplit("_", 1)[1]
        _show_issues(uid, msg_id, "closed" if cur == "open" else "open")
        return True
    if data.startswith("gx_iss_view_"):
        _view_issue(uid, msg_id, int(data[len("gx_iss_view_"):])); return True
    if data.startswith("gx_iss_close_"):
        n = int(data[len("gx_iss_close_"):])
        _gh().set_issue_state(token, owner, repo, n, "closed")
        _view_issue(uid, msg_id, n); return True
    if data.startswith("gx_iss_reopen_"):
        n = int(data[len("gx_iss_reopen_"):])
        _gh().set_issue_state(token, owner, repo, n, "open")
        _view_issue(uid, msg_id, n); return True
    return False


def _view_issue(uid, msg_id, number):
    _, dr, repo, owner = _ctx(uid)
    token = _token(uid)
    it = _gh().get_issue(token, owner, repo, number)
    if not it:
        _edit(uid, msg_id, f"❓ Issue #{number} not found.", kb_back_only()); return
    state = it.get("state", "open")
    labels = ", ".join(l["name"] for l in it.get("labels", [])) or "—"
    text = (
        f"🎫 #{number} *{_esc(_short(it.get('title',''), 120))}*\n\n"
        f"State: `{'🟢 open' if state=='open' else '⚪ closed'}`  ·  💬 `{it.get('comments',0)}`\n"
        f"🏷 `{_esc(labels)}`  ·  👤 {_esc((it.get('user') or {}).get('login','?'))}\n\n"
        f"{_esc(_short(it.get('body') or '_No description_', 700))}"
    )
    _edit(uid, msg_id, text, kb_issue_detail(number, state))


# ══════════════════════════════════════════════════════════════
#  Pull Requests
# ══════════════════════════════════════════════════════════════
def _show_pulls(uid, msg_id, state="open"):
    _, dr, repo, owner = _ctx(uid)
    token = _token(uid)
    pulls = _gh().list_pull_requests(token, owner, repo, state=state, per_page=12)
    items = [(f"🔀 #{pr['number']} {_short(pr.get('title',''))}", pr["number"]) for pr in pulls]
    _, B = _IK()
    toggle = "🔴 Show closed" if state == "open" else "🟢 Show open"
    nav = [[B(toggle, callback_data=f"gx_pr_toggle_{state}")]]
    _edit(uid, msg_id, f"🔀 *Pull Requests · {_esc(repo)}*  _(showing {state})_",
          kb_list(items, "gx_pr_view", "No pull requests here", nav))


def _pulls_cb(uid, data, msg_id):
    _, dr, repo, owner = _ctx(uid)
    token = _token(uid)
    if data.startswith("gx_pr_toggle_"):
        cur = data.rsplit("_", 1)[1]
        _show_pulls(uid, msg_id, "closed" if cur == "open" else "open")
        return True
    if data.startswith("gx_pr_view_"):
        n = int(data[len("gx_pr_view_"):])
        pr = _gh().get_pull_request(token, owner, repo, n)
        if not pr:
            _edit(uid, msg_id, f"❓ PR #{n} not found.", kb_back_only()); return True
        files = _gh().list_pull_request_files(token, owner, repo, n, per_page=15)
        file_line = "\n".join(
            f"· `{_esc(f.get('filename',''))}` +{f.get('additions',0)}/-{f.get('deletions',0)}"
            for f in files[:10]) or "_no changed files_"
        head = (pr.get("head") or {}).get("ref", "?")
        base = (pr.get("base") or {}).get("ref", "?")
        text = (
            f"🔀 #{n} *{_esc(_short(pr.get('title',''), 120))}*\n\n"
            f"State: `{_esc(pr.get('state',''))}{' · merged' if pr.get('merged') else ''}`\n"
            f"🌿 `{_esc(head)}` → `{_esc(base)}`\n"
            f"📄 {pr.get('changed_files',0)} file(s), +{pr.get('additions',0)}/-{pr.get('deletions',0)}\n\n"
            f"_{file_line}_"
        )
        _edit(uid, msg_id, text, kb_back_only())
        return True
    return False


# ══════════════════════════════════════════════════════════════
#  Releases & Tags
# ══════════════════════════════════════════════════════════════
def _show_releases(uid, msg_id):
    _, dr, repo, owner = _ctx(uid)
    token = _token(uid)
    releases = _gh().list_releases(token, owner, repo, per_page=12)
    items = []
    for rel in releases:
        badge = "📝" if rel.get("draft") else ("🧪" if rel.get("prerelease") else "🚀")
        items.append((f"{badge} {rel.get('tag_name','')} · {_short(rel.get('name','') or '')}", rel.get("id")))
    _, B = _IK()
    nav = [[B("🏷 Tags", callback_data="gx_tag_list"),
            B("➕ New Release", callback_data="gx_rel_new")]]
    _edit(uid, msg_id, f"🚀 *Releases · {_esc(repo)}*",
          kb_list(items, "gx_rel_view", "No releases yet", nav))


def _releases_cb(uid, data, msg_id):
    _, dr, repo, owner = _ctx(uid)
    token = _token(uid)
    if data == "gx_rel_new":
        _set_draft(uid, gx_pending="rel_tag")
        _edit(uid, msg_id,
              "🚀 *New release*\n\nSend the *tag name* (an existing tag is used; a new one is "
              "created on the default branch):", None)
        return True
    if data.startswith("gx_rel_view_"):
        rel_id = int(data[len("gx_rel_view_"):])
        rels = _gh().list_releases(token, owner, repo, per_page=50)
        rel = next((x for x in rels if x.get("id") == rel_id), None)
        if not rel:
            _edit(uid, msg_id, "❓ Release not found.", kb_back_only()); return True
        text = (
            f"🚀 *{_esc(rel.get('name') or rel.get('tag_name',''))}*\n\n"
            f"Tag `{_esc(rel.get('tag_name',''))}` · "
            f"{'📝 draft' if rel.get('draft') else ('🧪 prerelease' if rel.get('prerelease') else '🟢 published')}\n\n"
            f"{_esc(_short(rel.get('body') or '_No release notes_', 700))}"
        )
        _edit(uid, msg_id, text, kb_back_only())
        return True
    return False


def _show_tags(uid, msg_id):
    _, dr, repo, owner = _ctx(uid)
    token = _token(uid)
    tags = _gh().list_tags(token, owner, repo, per_page=30)
    items = [(f"🏷 {t.get('name','')}", t.get("name", "")) for t in tags]
    _, B = _IK()
    nav = [[B("➕ New Tag", callback_data="gx_tag_new"),
            B("🚀 Releases", callback_data="gx_feat_releases")]]
    _edit(uid, msg_id, f"🏷 *Tags · {_esc(repo)}*",
          kb_list(items, "gx_tag_view", "No tags yet", nav))


def _tags_cb(uid, data, msg_id):
    _, dr, repo, owner = _ctx(uid)
    token = _token(uid)
    if data == "gx_tag_list":
        _show_tags(uid, msg_id); return True
    if data == "gx_tag_new":
        _set_draft(uid, gx_pending="tag_name")
        _edit(uid, msg_id, "🏷 *New tag*\n\nSend the tag name (created on the default branch):", None)
        return True
    if data.startswith("gx_tag_del_"):
        tag = unquote(data[len("gx_tag_del_"):])
        _gh().delete_tag(token, owner, repo, tag)
        _show_tags(uid, msg_id); return True
    if data.startswith("gx_tag_view_"):
        tag = unquote(data[len("gx_tag_view_"):])
        _edit(uid, msg_id,
              f"🏷 `{_esc(tag)}`\n\nDelete this tag? (removes the ref; any release attached stays as a draft note)",
              kb_confirm("🗑 Delete Tag", f"gx_tag_del_{quote(tag, safe='')}"))
        return True
    return False


# ══════════════════════════════════════════════════════════════
#  Branches & Commits
# ══════════════════════════════════════════════════════════════
def _show_branches(uid, msg_id):
    _, dr, repo, owner = _ctx(uid)
    token = _token(uid)
    branches = _gh().list_branches(token, owner, repo)
    items = [(f"🌿 {b.get('name','')}", b.get("name", "")) for b in branches]
    _, B = _IK()
    nav = [[B("➕ New Branch", callback_data="gx_br_new")]]
    _edit(uid, msg_id, f"🌿 *Branches · {_esc(repo)}*",
          kb_list(items, "gx_br_view", "No branches found", nav))


def _branches_cb(uid, data, msg_id):
    _, dr, repo, owner = _ctx(uid)
    token = _token(uid)
    if data == "gx_br_new":
        _set_draft(uid, gx_pending="br_name")
        _edit(uid, msg_id, "🌿 *New branch*\n\nSend the branch name (branched from the default branch):", None)
        return True
    if data.startswith("gx_br_del_"):
        name = unquote(data[len("gx_br_del_"):])
        _gh().delete_branch(token, owner, repo, name)
        _show_branches(uid, msg_id); return True
    if data.startswith("gx_br_view_"):
        name = unquote(data[len("gx_br_view_"):])
        _show_commits(uid, msg_id, name); return True
    return False


def _show_commits(uid, msg_id, branch):
    _, dr, repo, owner = _ctx(uid)
    token = _token(uid)
    commits = _gh().list_commits(token, owner, repo, branch=branch, per_page=12)
    lines = []
    for c in commits:
        sha = (c.get("sha") or "")[:7]
        msg = _short((c.get("commit") or {}).get("message", ""))
        author = (c.get("author") or {}).get("login") or (c.get("commit") or {}).get("author", {}).get("name", "?")
        lines.append(f"`{sha}` {_esc(_short(msg, 50))} · _{_esc(author)}_")
    body = "\n".join(lines) or "_no commits_"
    M, B = _IK()
    kb = M(row_width=2)
    kb.add(B("🗑 Delete Branch", callback_data=f"gx_br_del_{quote(branch, safe='')}"))
    kb.add(B("◀ Branches", callback_data="gx_feat_branches"),
           B("🏠 Home", callback_data="menu_home"))
    _edit(uid, msg_id, f"🌿 Commits on `{_esc(branch)}` (newest first):\n\n{body}", kb)


# ══════════════════════════════════════════════════════════════
#  Text-input create flows (driven by draft["gx_pending"])
# ══════════════════════════════════════════════════════════════
def on_text(uid, m) -> bool:
    """Handle a free-text message while a gx create flow is active."""
    pending = (_ctx(uid)[1] or {}).get("gx_pending")
    if not pending:
        return False
    text = (m.text or "").strip()
    if text.startswith("/"):
        _set_draft(uid, gx_pending=None, gx_buffer=None)
        _edit(uid, m.message_id, "❎ Cancelled.", kb_extras_menu())
        return True

    _, dr, repo, owner = _ctx(uid)
    token = _token(uid)
    buf = dr.get("gx_buffer") or {}
    try:
        if pending == "iss_title":
            _set_draft(uid, gx_pending="iss_body", gx_buffer={**buf, "title": text})
            _bot().send_message(uid, "Now send the *body*. Send `/done` for an empty body:",
                                parse_mode="Markdown")
            return True
        if pending == "iss_body":
            body = "" if text == "/done" else text
            made = _gh().create_issue(token, owner, repo, buf.get("title", text), body)
            _set_draft(uid, gx_pending=None, gx_buffer=None)
            D.get("add_history") and D["add_history"](uid, f"Opened issue #{made.get('number')} in {repo}")
            _bot().send_message(uid,
                f"✅ Issue #{made.get('number')} created: [{_esc(_short(made.get('title','')))}]({made.get('html_url','#')})",
                parse_mode="Markdown")
            _view_issue(uid, m.message_id, made.get("number"))
            return True
        if pending == "tag_name":
            # Tags must land on the repo's DEFAULT branch (what the prompt
            # promises) — not hardcoded main/master.
            info = _gh().get_repo_info(token, owner, repo) or {}
            base = info.get("default_branch", "main")
            ok = _gh().create_tag(token, owner, repo, text, from_ref=base)
            _set_draft(uid, gx_pending=None, gx_buffer=None)
            _bot().send_message(uid, f"{'✅' if ok else '❌'} Tag `{_esc(text)}` {'created' if ok else 'failed'}",
                                parse_mode="Markdown")
            _show_tags(uid, m.message_id)
            return True
        if pending == "br_name":
            info = _gh().get_repo_info(token, owner, repo) or {}
            base = info.get("default_branch", "main")
            ok = _gh().create_branch(token, owner, repo, text, base)
            _set_draft(uid, gx_pending=None, gx_buffer=None)
            _bot().send_message(uid,
                f"{'✅' if ok else '❌'} Branch `{_esc(text)}` {'from '+_esc(base) if ok else 'failed'}",
                parse_mode="Markdown")
            _show_branches(uid, m.message_id)
            return True
        if pending == "rel_tag":
            info = _gh().get_repo_info(token, owner, repo) or {}
            base = info.get("default_branch", "main")
            made = _gh().create_release(token, owner, repo, tag=text, name=text,
                                        body=f"Release {text}", target=base)
            _set_draft(uid, gx_pending=None, gx_buffer=None)
            D.get("add_history") and D["add_history"](uid, f"Released {repo} {text}")
            _bot().send_message(uid, f"🚀 Release created: [{_esc(text)}]({made.get('html_url','#')})",
                                parse_mode="Markdown")
            _show_releases(uid, m.message_id)
            return True
    except Exception as ex:
        _set_draft(uid, gx_pending=None, gx_buffer=None)
        _bot().send_message(uid, f"❌ Failed: `{_esc(str(ex))}`", parse_mode="Markdown")
        return True
    return False
