"""
test_github_api.py — Offline tests for the GitHub REST wrapper.

No network: we monkeypatch github_api._session with a fake that records the
calls we make and returns canned responses, so URL construction, params,
payloads, response handling and error paths are all verified deterministically.

Run: python test_github_api.py
"""
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests  # noqa: E402
import github_api as gh  # noqa: E402


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
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    """Records calls per verb and returns a canned or queued response.
    queue() -> one response reused for every call.
    queue_seq(*resp) -> responses consumed in call order (last repeats)."""
    def __init__(self):
        self.calls = []  # (verb, url, kwargs)
        self._resp = FakeResp()
        self._exc = None
        self._queue = None
        self._i = 0

    def queue(self, resp=None, exc=None):
        self._resp, self._exc = resp, exc
        self._queue, self._i = None, 0

    def queue_seq(self, *resps):
        self._queue, self._i, self._exc = list(resps), 0, None

    def _next(self):
        if self._queue is not None:
            if not self._queue:
                raise AssertionError("queue_seq called with no responses")
            r = self._queue[min(self._i, len(self._queue) - 1)]
            self._i += 1
            return r
        return self._resp

    def _do(self, verb, url, **kw):
        self.calls.append((verb, url, kw))
        if self._exc is not None:
            raise self._exc
        return self._next()

    def get(self, url, **kw):   return self._do("GET", url, **kw)
    def post(self, url, **kw):  return self._do("POST", url, **kw)
    def put(self, url, **kw):   return self._do("PUT", url, **kw)
    def patch(self, url, **kw): return self._do("PATCH", url, **kw)
    def delete(self, url, **kw):return self._do("DELETE", url, **kw)


FAKE = FakeSession()
gh._session = FAKE  # inject fake for the whole module

TOK = "ghp_test_token_0123456789_abcdefghij"
OWNER, REPO = "octocat", "hello-world"


def last():
    return FAKE.calls[-1]


def _raises(fn):
    try:
        fn()
        return False
    except gh.GitHubError:
        return True
    except Exception:
        return False


# ── Issues ───────────────────────────────────────────────────
divider("list_issues: filters PRs, builds params")
FAKE.calls.clear()
FAKE.queue(FakeResp(200, [
    {"number": 1, "title": "a"},
    {"number": 2, "title": "pr", "pull_request": {"url": "x"}},
]))
res = gh.list_issues(TOK, OWNER, REPO, state="open", per_page=5, page=2)
verb, url, kw = last()
check("PR rows are filtered out", len(res) == 1 and res[0]["number"] == 1)
check("hits /repos/{owner}/{repo}/issues", url.endswith(f"/repos/{OWNER}/{REPO}/issues"))
check("carries state + paging params",
      kw["params"]["state"] == "open" and kw["params"]["per_page"] == 5 and kw["params"]["page"] == 2)

divider("list_issues: auth header")
_, _, kw = last()
check("uses Bearer auth", kw["headers"]["Authorization"] == f"Bearer {TOK}")

divider("list_issues: error paths return []")
FAKE.queue(FakeResp(404, {"message": "Not Found"}))
check("non-200 -> []", gh.list_issues(TOK, OWNER, REPO) == [])
FAKE.queue(exc=requests.RequestException("boom"))
check("network error -> []", gh.list_issues(TOK, OWNER, REPO) == [])

divider("create_issue: validation + payload")
FAKE.queue(FakeResp(201, {"number": 7, "html_url": "https://x/7"}))
made = gh.create_issue(TOK, OWNER, REPO, "Bug found", "details", labels=["bug"])
verb, url, kw = last()
check("POSTs to /issues", verb == "POST" and url.endswith(f"/repos/{OWNER}/{REPO}/issues"))
check("payload has title/body/labels",
      kw["json"]["title"] == "Bug found" and kw["json"]["body"] == "details" and kw["json"]["labels"] == ["bug"])
check("returns parsed 201 body", made.get("number") == 7)

check("empty title raises", _raises(lambda: gh.create_issue(TOK, OWNER, REPO, "  ")))
check("overlong title raises", _raises(lambda: gh.create_issue(TOK, OWNER, REPO, "x" * 300)))


divider("set_issue_state / comment_issue")
FAKE.calls.clear()
FAKE.queue(FakeResp(200, {}))
check("close issue ok", gh.set_issue_state(TOK, OWNER, REPO, 7, "closed") is True)
check("PATCH with state=closed", last()[2]["json"] == {"state": "closed"})
check("invalid state rejected without call", gh.set_issue_state(TOK, OWNER, REPO, 7, "archived") is False)
FAKE.queue(FakeResp(201, {}))
check("comment ok", gh.comment_issue(TOK, OWNER, REPO, 7, "hi") is True)
check("empty comment rejected", gh.comment_issue(TOK, OWNER, REPO, 7, "   ") is False)


# ── Pull Requests ────────────────────────────────────────────
divider("create_pull_request validation + payload")
FAKE.queue(FakeResp(201, {"number": 3}))
made = gh.create_pull_request(TOK, OWNER, REPO, "Add feature", "feature", "main")
verb, url, kw = last()
check("POST /pulls", verb == "POST" and url.endswith(f"/repos/{OWNER}/{REPO}/pulls"))
check("payload head/base present", kw["json"]["head"] == "feature" and kw["json"]["base"] == "main")
check("empty title raises", _raises(lambda: gh.create_pull_request(TOK, OWNER, REPO, "", "a", "b")))
check("missing head/base raises", _raises(lambda: gh.create_pull_request(TOK, OWNER, REPO, "t", "", "main")))

divider("list_pull_request_files")
FAKE.queue(FakeResp(200, [{"filename": "x.py"}]))
check("returns file list", gh.list_pull_request_files(TOK, OWNER, REPO, 3) == [{"filename": "x.py"}])


# ── Commits ──────────────────────────────────────────────────
divider("list_commits")
FAKE.calls.clear()
FAKE.queue(FakeResp(200, [{"sha": "abc"}]))
gh.list_commits(TOK, OWNER, REPO, branch="dev", per_page=3)
_, _, kw = last()
check("passes sha param for branch", kw["params"].get("sha") == "dev")
FAKE.calls.clear()
gh.list_commits(TOK, OWNER, REPO)
_, _, kw = last()
check("omits sha when no branch", "sha" not in kw["params"])


# ── Tags ─────────────────────────────────────────────────────
divider("get_ref_sha")
FAKE.queue(FakeResp(200, {"object": {"sha": "deadbeef"}}))
check("extracts object.sha", gh.get_ref_sha(TOK, OWNER, REPO, "heads/main") == "deadbeef")
FAKE.queue(FakeResp(404, {}))
check("missing ref -> None", gh.get_ref_sha(TOK, OWNER, REPO, "heads/nope") is None)

divider("create_tag resolves sha from branch then POSTs ref")
FAKE.calls.clear()
# 1st call (get_ref_sha heads/main) -> 200 w/ sha, 2nd call (POST /git/refs) -> 201
FAKE.queue_seq(FakeResp(200, {"object": {"sha": "cafe1234"}}), FakeResp(201, {}))
resp_created = gh.create_tag(TOK, OWNER, REPO, "v1.0.0", from_ref="main")
post_calls = [c for c in FAKE.calls if c[0] == "POST"]
check("create_tag returns True", resp_created is True)
check("POSTs refs/tags with resolved sha",
      post_calls and post_calls[-1][1].endswith("/git/refs")
      and post_calls[-1][2]["json"] == {"ref": "refs/tags/v1.0.0", "sha": "cafe1234"})

FAKE.calls.clear()
FAKE.queue(FakeResp(404, {}))  # no branch ref found, from_ref not a 40-hex sha
check("create_tag fails when sha unresolvable", gh.create_tag(TOK, OWNER, REPO, "v2", from_ref="ghost") is False)

divider("delete_tag keeps slash as ref path separator")
FAKE.calls.clear()
FAKE.queue(FakeResp(204, {}))
check("delete_tag ok", gh.delete_tag(TOK, OWNER, REPO, "v1/beta") is True)
_, url, _ = last()
check("slashes kept as path segments", url.endswith("/git/refs/tags/v1/beta"))


# ── Releases ─────────────────────────────────────────────────
divider("create_release validation + payload")
FAKE.queue(FakeResp(201, {"id": 9, "tag_name": "v1.0.0"}))
rel = gh.create_release(TOK, OWNER, REPO, "v1.0.0", name="", body="notes", target="main")
verb, url, kw = last()
check("POST /releases", verb == "POST" and url.endswith(f"/repos/{OWNER}/{REPO}/releases"))
check("name defaults to tag", kw["json"]["name"] == "v1.0.0")
check("returns body", rel.get("id") == 9)
check("empty tag raises", _raises(lambda: gh.create_release(TOK, OWNER, REPO, "")))

divider("list_releases error -> []")
FAKE.queue(FakeResp(500, {}))
check("non-200 -> []", gh.list_releases(TOK, OWNER, REPO) == [])


# ── delete_branch ────────────────────────────────────────────
divider("delete_branch keeps nested branch path")
FAKE.calls.clear()
FAKE.queue(FakeResp(204, {}))
check("delete_branch ok", gh.delete_branch(TOK, OWNER, REPO, "feature/x") is True)
_, url, _ = last()
check("nested branch kept as path segments", url.endswith("/git/refs/heads/feature/x"))


# ── clear_repo_contents ──────────────────────────────────────
divider("clear_repo_contents: one empty-tree commit, ref moved")
FAKE.calls.clear()
# 1) GET repo info, 2) GET branch ref, 3) POST empty tree,
# 4) POST commit, 5) PATCH branch ref
FAKE.queue_seq(
    FakeResp(200, {"default_branch": "main", "private": False}),
    FakeResp(200, {"object": {"sha": "head123"}}),
    FakeResp(201, {"sha": "emptytree1"}),
    FakeResp(201, {"sha": "newcommit1"}),
    FakeResp(200, {"object": {"sha": "newcommit1"}}),
)
check("clear ok on populated repo", gh.clear_repo_contents(TOK, OWNER, REPO) is True)
posts = [c for c in FAKE.calls if c[0] == "POST"]
trees = [c for c in posts if c[1].endswith("/git/trees")]
commits = [c for c in posts if c[1].endswith("/git/commits")]
patches = [c for c in FAKE.calls if c[0] == "PATCH"]
check("posts exactly one empty tree",
      len(trees) == 1 and trees[0][2]["json"] == {"tree": []})
check("commit has empty tree sha + previous head as parent",
      len(commits) == 1
      and commits[0][2]["json"]["tree"] == "emptytree1"
      and commits[0][2]["json"]["parents"] == ["head123"])
check("moves branch ref to the empty commit",
      len(patches) == 1
      and patches[0][1].endswith("/git/refs/heads/main")
      and patches[0][2]["json"] == {"sha": "newcommit1", "force": False})

divider("clear_repo_contents: already-empty repo is a no-op")
FAKE.calls.clear()
FAKE.queue_seq(
    FakeResp(200, {"default_branch": "main"}),
    FakeResp(404, {"message": "Not Found"}),  # no branch ref yet
)
check("returns False for empty repo", gh.clear_repo_contents(TOK, OWNER, REPO) is False)
check("no tree/commit written for empty repo",
      not [c for c in FAKE.calls if c[0] == "POST"])

divider("clear_repo_contents: unknown repo raises GitHubError")
FAKE.queue_seq(FakeResp(404, {"message": "Not Found"}))
check("raises when repo missing", _raises(lambda: gh.clear_repo_contents(TOK, OWNER, REPO)))


# ── summary ──────────────────────────────────────────────────
divider("SUMMARY")
total = PASSED + FAILED
print(f"  {PASSED}/{total} passed")
sys.stdout.flush()
sys.exit(1 if FAILED else 0)
