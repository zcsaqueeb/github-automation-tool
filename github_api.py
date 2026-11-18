"""
github_api.py — GitHub REST API wrapper for GitHub AI Repo Bot

Uses a pooled, auto-retrying requests.Session so transient network errors
and GitHub rate-limit/5xx responses are retried with exponential backoff
instead of failing the whole bot action outright.
"""

from __future__ import annotations
from typing import Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import config
    TIMEOUT      = config.HTTP_TIMEOUT
    MAX_RETRIES  = config.HTTP_MAX_RETRIES
except Exception:  # pragma: no cover - config should always be importable
    TIMEOUT     = 15
    MAX_RETRIES = 3

GITHUB_API = "https://api.github.com"
_MAX_REPO_DESCRIPTION = 350

_retry = Retry(
    total=MAX_RETRIES,
    backoff_factor=0.5,
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=("GET", "POST", "PUT", "PATCH", "DELETE"),
    raise_on_status=False,
)
_session = requests.Session()
_adapter = HTTPAdapter(max_retries=_retry, pool_connections=10, pool_maxsize=10)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)


def _headers(token: str) -> dict:
    return {
        "Authorization":        f"Bearer {token}",
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


class GitHubError(Exception):
    def __init__(self, message: str, status: int = 0):
        self.status  = status
        self.message = message
        super().__init__(message)


class RepoNameExistsError(GitHubError):
    """Raised when a repository name already exists on the account (HTTP 422)."""
    pass


def _encode_path(path: str) -> str:
    """URL-encode each segment of a repo file path for use in the Contents API.

    GitHub's Contents API endpoints (``/repos/{owner}/{repo}/contents/{path}``)
    require the path to be percent-encoded. A raw path containing a space,
    parenthesis, ``#``, ``+``, or non-ASCII/unicode character produces a
    malformed URL that GitHub answers with a silent 404 — the request looks
    like it should have worked, but the file is dropped with no clear error.
    Encoding each ``/``-separated segment individually (instead of the whole
    path at once) preserves the directory separators while safely escaping
    everything else.
    """
    from urllib.parse import quote
    return "/".join(quote(segment, safe="") for segment in (path or "").split("/"))


def _is_name_taken(r: requests.Response) -> bool:
    """Detect GitHub's 'name already exists on this account' 422 response."""
    if r.status_code != 422:
        return False
    try:
        data = r.json()
    except Exception:
        return False
    if "already exists" in (data.get("message") or "").lower():
        return True
    for err in (data.get("errors") or []):
        emsg = (err.get("message") or "").lower()
        if err.get("field") == "name" and ("already exists" in emsg or err.get("code") == "custom"):
            return True
    return False


def _check(r: requests.Response, expect: int | tuple) -> dict:
    """Raise GitHubError if status code is unexpected."""
    expected = expect if isinstance(expect, tuple) else (expect,)
    if r.status_code not in expected:
        try:
            payload = r.json()
            msg = payload.get("message", r.text[:200])
            details = []
            for item in payload.get("errors", []) or []:
                if isinstance(item, dict):
                    field = item.get("field") or item.get("resource") or ""
                    detail = item.get("message") or item.get("code") or ""
                    if detail:
                        details.append(f"{field}: {detail}" if field else str(detail))
            if details:
                msg = f"{msg} ({'; '.join(details[:3])})"
        except Exception:
            msg = r.text[:200]
        if r.status_code == 401:
            msg = f"GitHub authentication failed: {msg}. Check that your token is valid and not expired."
        elif r.status_code == 403 and r.headers.get("X-RateLimit-Remaining", "1") == "0":
            reset = r.headers.get("X-RateLimit-Reset", "")
            when = ""
            if reset.isdigit():
                import datetime as _dt
                when = f" (resets at {_dt.datetime.fromtimestamp(int(reset), _dt.timezone.utc).strftime('%H:%M:%S UTC')})"
            msg = f"GitHub rate limit reached{when}. Wait a few minutes and try again."
        elif r.status_code == 403 and r.headers.get("X-RateLimit-Remaining", "1") == "0":
            reset = r.headers.get("X-RateLimit-Reset", "")
            when = ""
            if reset.isdigit():
                import datetime as _dt
                when = f" (resets at {_dt.datetime.fromtimestamp(int(reset), _dt.timezone.utc).strftime('%H:%M:%S UTC')})"
            msg = f"GitHub rate limit reached{when}. Wait a few minutes and try again."
        elif r.status_code == 403:
            msg = f"GitHub denied this request: {msg}. Your token may need account repository-creation permission."
        elif r.status_code == 422:
            msg = f"GitHub rejected the repository details: {msg}"
        raise GitHubError(msg, r.status_code)
    try:
        return r.json()
    except Exception:
        return {}


# ── Auth ───────────────────────────────────────────────────────

def get_user(token: str) -> Optional[dict]:
    try:
        r = _session.get(f"{GITHUB_API}/user", headers=_headers(token), timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json()
        return None
    except requests.RequestException:
        return None


def repo_name_available(token: str, owner: str, name: str, timeout: int = 5) -> Optional[bool]:
    """
    Check whether `owner/name` is free to use for a new repo.
    Returns True (available), False (taken), or None (couldn't determine —
    e.g. network error or rate limit; caller should treat as "unknown").
    Uses a short timeout by default since this is a best-effort UI hint, not
    a blocking step — callers should never let this delay the main flow.
    """
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{name}",
            headers=_headers(token),
            timeout=timeout,
        )
        if r.status_code == 404:
            return True
        if r.status_code == 200:
            return False
        return None  # rate-limited, bad token, etc. — unknown, not a hard no
    except requests.RequestException:
        return None


# ── Repositories ───────────────────────────────────────────────

def create_repo(
    token:       str,
    name:        str,
    description: str  = "",
    private:     bool = False,
    auto_init:   bool = True,
) -> dict:
    """Create a repo. Returns response dict. Raises GitHubError on failure."""
    description = (description or "").strip()
    if len(description) > _MAX_REPO_DESCRIPTION:
        raise GitHubError(
            f"Repository description is {len(description)} characters; "
            f"GitHub allows a maximum of {_MAX_REPO_DESCRIPTION}.", 422
        )
    r = _session.post(
        f"{GITHUB_API}/user/repos",
        headers=_headers(token),
        json={
            "name":        name,
            "description": description,
            "private":     private,
            "auto_init":   auto_init,
        },
        timeout=TIMEOUT,
    )
    if _is_name_taken(r):
        raise RepoNameExistsError(
            f"A repository named '{name}' already exists on your account.", 422
        )
    return _check(r, 201)


def delete_repo(token: str, owner: str, repo: str) -> bool:
    """Delete a repo. Returns True on success."""
    try:
        r = _session.delete(
            f"{GITHUB_API}/repos/{owner}/{repo}",
            headers=_headers(token),
            timeout=TIMEOUT,
        )
        return r.status_code == 204
    except requests.RequestException:
        return False


def list_repos(token: str, per_page: int = 15) -> list:
    """List user's repos sorted by last updated."""
    try:
        r = _session.get(
            f"{GITHUB_API}/user/repos",
            headers=_headers(token),
            params={"sort": "updated", "per_page": per_page},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        return []
    except requests.RequestException:
        return []


def fork_repo(token: str, owner: str, repo: str) -> dict:
    """Fork a repo. Raises GitHubError on failure."""
    r = _session.post(
        f"{GITHUB_API}/repos/{owner}/{repo}/forks",
        headers=_headers(token),
        timeout=TIMEOUT,
    )
    return _check(r, 202)


def star_repo(token: str, owner: str, repo: str) -> bool:
    try:
        r = _session.put(
            f"{GITHUB_API}/user/starred/{owner}/{repo}",
            headers=_headers(token),
            timeout=TIMEOUT,
        )
        return r.status_code == 204
    except requests.RequestException:
        return False


def get_file_sha(token: str, owner: str, repo: str, path: str) -> str | None:
    """Return the blob SHA of an existing file, or None if it does not exist."""
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{_encode_path(path)}",
            headers=_headers(token),
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            # Directories return a JSON *list* from the Contents API — guard
            # the shape so a folder path cannot raise AttributeError.
            data = r.json()
            return data.get("sha") if isinstance(data, dict) else None
        return None
    except requests.RequestException:
        return None


def push_file(
    token:   str,
    owner:   str,
    repo:    str,
    path:    str,
    content: str,
    message: str = "Initial commit",
) -> bool:
    """Create or update a file. Fetches existing SHA automatically so updates never fail."""
    import base64
    if isinstance(content, bytes):
        encoded = base64.b64encode(content).decode()
    else:
        # Plain text (or anything str-like) is encoded from its UTF-8 bytes.
        # NOTE: callers with pre-encoded base64 must pass bytes instead —
        # a base64 *string* is valid UTF-8 and would otherwise be
        # double-encoded, silently corrupting the stored file.
        encoded = base64.b64encode(str(content).encode("utf-8")).decode()

    payload: dict = {"message": message, "content": encoded}

    # Fetch existing SHA — needed if file already exists (e.g. README.md from auto_init)
    sha = get_file_sha(token, owner, repo, path)
    if sha:
        payload["sha"] = sha

    try:
        r = _session.put(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{_encode_path(path)}",
            headers=_headers(token),
            json=payload,
            timeout=TIMEOUT,
        )
        return r.status_code in (200, 201)
    except requests.RequestException:
        return False


def get_repo_info(token: str, owner: str, repo: str) -> dict | None:
    """Get repo metadata (name, private, default_branch, size, etc.)."""
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}",
            headers=_headers(token),
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        return None
    except requests.RequestException:
        return None


def get_repo_tree(token: str, owner: str, repo: str, branch: str = "HEAD") -> list:
    """Return a flat list of all blob paths in the repo tree (recursive)."""
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{_encode_path(branch)}",
            headers=_headers(token),
            params={"recursive": "1"},
            timeout=30,
        )
        if r.status_code == 200:
            return [item for item in r.json().get("tree", []) if item.get("type") == "blob"]
        return []
    except requests.RequestException:
        return []


def replace_repo_contents(token: str, owner: str, repo: str, files: list, message: str = "Replace repository contents") -> bool:
    """Atomically replace tracked files while preserving the repository and history.

    ``files`` contains ``path`` and base64-encoded ``content_b64`` values. A
    single Git commit is created with a new root tree, so old files disappear
    together only if every blob and the ref update succeeds.
    """
    info = get_repo_info(token, owner, repo)
    if not info:
        raise GitHubError("Could not load repository details.")
    branch = info.get("default_branch") or "main"
    headers = _headers(token)
    try:
        ref = _session.get(f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{_encode_path(branch)}", headers=headers, timeout=TIMEOUT)
        head = _check(ref, 200).get("object", {}).get("sha")
        if not head:
            raise GitHubError("Could not determine the current branch commit.")
        tree = []
        for file_data in files:
            path, content = file_data.get("path", ""), file_data.get("content_b64", "")
            if not path or not content:
                continue
            blob = _session.post(f"{GITHUB_API}/repos/{owner}/{repo}/git/blobs", headers=headers,
                                 json={"content": content, "encoding": "base64"}, timeout=TIMEOUT)
            sha = _check(blob, 201).get("sha")
            tree.append({"path": path, "mode": "100644", "type": "blob", "sha": sha})
        if not tree:
            raise GitHubError("The replacement archive has no uploadable files.")
        created_tree = _check(_session.post(f"{GITHUB_API}/repos/{owner}/{repo}/git/trees", headers=headers,
                                            json={"tree": tree}, timeout=TIMEOUT), 201)
        commit = _check(_session.post(f"{GITHUB_API}/repos/{owner}/{repo}/git/commits", headers=headers,
                                      json={"message": message, "tree": created_tree["sha"], "parents": [head]}, timeout=TIMEOUT), 201)
        updated = _session.patch(f"{GITHUB_API}/repos/{owner}/{repo}/git/refs/heads/{_encode_path(branch)}", headers=headers,
                                 json={"sha": commit["sha"], "force": False}, timeout=TIMEOUT)
        _check(updated, 200)
        return True
    except requests.RequestException as exc:
        raise GitHubError(f"Network error while replacing repository contents: {exc}") from exc


def clear_repo_contents(token: str, owner: str, repo: str, message: str = "Delete all repository contents") -> bool:
    """Delete every file and folder in a repository WITHOUT deleting the repo.

    One commit is created whose root tree is empty and the default branch is
    moved to it, so all tracked files and folders disappear while the
    repository itself (settings, stars, description, URL) is preserved.
    Old versions remain reachable through commit history.  Returns ``False``
    when the repository is already empty (nothing to clear).
    """
    info = get_repo_info(token, owner, repo)
    if not info:
        raise GitHubError("Could not load repository details.")
    branch  = info.get("default_branch") or "main"
    headers = _headers(token)
    try:
        ref = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{_encode_path(branch)}",
            headers=headers, timeout=TIMEOUT)
        if ref.status_code == 404:
            return False  # brand-new repo with no commits — nothing to clear
        head = _check(ref, 200).get("object", {}).get("sha")
        if not head:
            raise GitHubError("Could not determine the current branch commit.")
        # No ``base_tree`` → the new root tree is built from scratch: empty.
        empty_tree = _check(_session.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees",
            headers=headers, json={"tree": []}, timeout=TIMEOUT), 201)
        commit = _check(_session.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/commits",
            headers=headers,
            json={"message": message, "tree": empty_tree["sha"], "parents": [head]},
            timeout=TIMEOUT), 201)
        _check(_session.patch(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/refs/heads/{_encode_path(branch)}",
            headers=headers, json={"sha": commit["sha"], "force": False},
            timeout=TIMEOUT), 200)
        return True
    except requests.RequestException as exc:
        raise GitHubError(f"Network error while clearing repository: {exc}") from exc


def download_repo_zipball(token: str, owner: str, repo: str, branch: str = "HEAD") -> bytes | None:
    """
    Download the entire repo as a ZIP via GitHub zipball API.
    Works for both public and private repos (uses token auth).
    Returns raw bytes of the zip file, or None on failure.
    """
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/zipball/{branch}",
            headers=_headers(token),
            timeout=120,
            allow_redirects=True,
            stream=True,
        )
        if r.status_code == 200:
            return r.content
        return None
    except requests.RequestException:
        return None


def list_all_repos(token: str) -> list:
    """List ALL repos (public + private), paginated."""
    repos = []
    page  = 1
    while True:
        try:
            r = _session.get(
                f"{GITHUB_API}/user/repos",
                headers=_headers(token),
                params={"sort": "updated", "per_page": 100, "page": page, "affiliation": "owner"},
                timeout=TIMEOUT,
            )
            if r.status_code != 200:
                break
            batch = r.json()
            if not batch:
                break
            repos.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        except requests.RequestException:
            break
    return repos


# ── Edit Repo / File & Folder operations ──────────────────────

def get_repo_contents(token: str, owner: str, repo: str, path: str = "", branch: str = "") -> list | dict | None:
    """Get contents of a path (file or directory) in a repo."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{_encode_path(path)}"
    params = {}
    if branch:
        params["ref"] = branch
    try:
        r = _session.get(url, headers=_headers(token), params=params, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json()
        return None
    except requests.RequestException:
        return None


def get_file_content(token: str, owner: str, repo: str, path: str, branch: str = "") -> dict | None:
    """Get a file's content and metadata (sha, content base64)."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{_encode_path(path)}"
    params = {}
    if branch:
        params["ref"] = branch
    try:
        r = _session.get(url, headers=_headers(token), params=params, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json()
        return None
    except requests.RequestException:
        return None


def update_file(
    token:   str,
    owner:   str,
    repo:    str,
    path:    str,
    content: str,
    sha:     str,
    message: str = "Update via GitHub Bot",
    branch:  str = "",
) -> bool:
    """Update an existing file (requires SHA)."""
    import base64
    try:
        encoded = base64.b64encode(content.encode("utf-8")).decode()
    except (UnicodeEncodeError, AttributeError):
        encoded = content if isinstance(content, str) else base64.b64encode(content).decode()

    payload: dict = {"message": message, "content": encoded, "sha": sha}
    if branch:
        payload["branch"] = branch

    try:
        r = _session.put(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{_encode_path(path)}",
            headers=_headers(token),
            json=payload,
            timeout=TIMEOUT,
        )
        return r.status_code in (200, 201)
    except requests.RequestException:
        return False


def create_file(
    token:   str,
    owner:   str,
    repo:    str,
    path:    str,
    content: str,
    message: str = "Create file via GitHub Bot",
    branch:  str = "",
) -> bool:
    """Create a new file in a repo."""
    import base64
    try:
        encoded = base64.b64encode(content.encode("utf-8")).decode()
    except (UnicodeEncodeError, AttributeError):
        encoded = content if isinstance(content, str) else base64.b64encode(content).decode()

    payload: dict = {"message": message, "content": encoded}
    if branch:
        payload["branch"] = branch

    try:
        r = _session.put(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{_encode_path(path)}",
            headers=_headers(token),
            json=payload,
            timeout=TIMEOUT,
        )
        return r.status_code in (200, 201)
    except requests.RequestException:
        return False


def delete_file(
    token:   str,
    owner:   str,
    repo:    str,
    path:    str,
    sha:     str,
    message: str = "Delete file via GitHub Bot",
    branch:  str = "",
) -> bool:
    """Delete a file from a repo."""
    payload: dict = {"message": message, "sha": sha}
    if branch:
        payload["branch"] = branch
    try:
        r = _session.delete(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{_encode_path(path)}",
            headers=_headers(token),
            json=payload,
            timeout=TIMEOUT,
        )
        return r.status_code == 200
    except requests.RequestException:
        return False


def rename_repo(token: str, owner: str, repo: str, new_name: str) -> dict | None:
    """Rename a repository."""
    try:
        r = _session.patch(
            f"{GITHUB_API}/repos/{owner}/{repo}",
            headers=_headers(token),
            json={"name": new_name},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        return None
    except requests.RequestException:
        return None


def update_repo_settings(
    token:       str,
    owner:       str,
    repo:        str,
    description: str  = None,
    private:     bool = None,
    homepage:    str  = None,
    has_issues:  bool = None,
    has_wiki:    bool = None,
    archived:    bool = None,
    default_branch: str = None,
) -> dict | None:
    """Update repository settings."""
    payload = {}
    if description is not None:  payload["description"]    = description
    if private      is not None:  payload["private"]        = private
    if homepage     is not None:  payload["homepage"]       = homepage
    if has_issues   is not None:  payload["has_issues"]     = has_issues
    if has_wiki     is not None:  payload["has_wiki"]       = has_wiki
    if archived     is not None:  payload["archived"]       = archived
    if default_branch is not None: payload["default_branch"] = default_branch
    if not payload:
        return None
    try:
        r = _session.patch(
            f"{GITHUB_API}/repos/{owner}/{repo}",
            headers=_headers(token),
            json=payload,
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        return None
    except requests.RequestException:
        return None


def create_branch(token: str, owner: str, repo: str, branch: str, from_branch: str = "main") -> bool:
    """Create a new branch from an existing one."""
    try:
        # Get sha of from_branch
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{_encode_path(from_branch)}",
            headers=_headers(token), timeout=TIMEOUT,
        )
        if r.status_code != 200:
            # Try master
            r = _session.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/master",
                headers=_headers(token), timeout=TIMEOUT,
            )
        if r.status_code != 200:
            return False
        sha = r.json()["object"]["sha"]
        r2 = _session.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/refs",
            headers=_headers(token),
            json={"ref": f"refs/heads/{branch}", "sha": sha},
            timeout=TIMEOUT,
        )
        return r2.status_code == 201
    except requests.RequestException:
        return False


def list_branches(token: str, owner: str, repo: str) -> list:
    """List all branches of a repo."""
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/branches",
            headers=_headers(token),
            params={"per_page": 100},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        return []
    except requests.RequestException:
        return []


def get_repo_topics(token: str, owner: str, repo: str) -> list:
    """Get repository topics/tags."""
    try:
        headers = _headers(token)
        headers["Accept"] = "application/vnd.github.mercy-preview+json"
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/topics",
            headers=headers,
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json().get("names", [])
        return []
    except requests.RequestException:
        return []


def set_repo_topics(token: str, owner: str, repo: str, topics: list) -> bool:
    """Set repository topics/tags."""
    try:
        headers = _headers(token)
        headers["Accept"] = "application/vnd.github.mercy-preview+json"
        r = _session.put(
            f"{GITHUB_API}/repos/{owner}/{repo}/topics",
            headers=headers,
            json={"names": topics},
            timeout=TIMEOUT,
        )
        return r.status_code == 200
    except requests.RequestException:
        return False


def search_repo_files(token: str, owner: str, repo: str, query: str) -> list:
    """Search for files in a repo by name using the tree API."""
    tree = get_repo_tree(token, owner, repo)
    query_lower = query.lower()
    results = []
    for item in tree:
        if query_lower in item["path"].lower():
            results.append(item)
    return results[:30]


def move_file(
    token:      str,
    owner:      str,
    repo:       str,
    old_path:   str,
    new_path:   str,
    message:    str = "Move/rename file via GitHub Bot",
    branch:     str = "",
) -> bool:
    """Move/rename a file by copying then deleting the original."""
    import base64 as _b64
    # Get old file
    file_data = get_file_content(token, owner, repo, old_path, branch)
    if not file_data:
        return False
    content_b64 = file_data.get("content", "").replace("\n", "")
    sha         = file_data.get("sha", "")

    # Decode and re-encode (already base64, just pass through)
    payload_create: dict = {"message": message, "content": content_b64}
    if branch:
        payload_create["branch"] = branch

    try:
        r = _session.put(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{_encode_path(new_path)}",
            headers=_headers(token),
            json=payload_create,
            timeout=TIMEOUT,
        )
        if r.status_code not in (200, 201):
            return False
    except requests.RequestException:
        return False

    # Delete old
    return delete_file(token, owner, repo, old_path, sha, f"Remove {old_path} (moved to {new_path})", branch)


# ══════════════════════════════════════════════════════════════
#  Issues
# ══════════════════════════════════════════════════════════════

def list_issues(
    token:    str,
    owner:    str,
    repo:     str,
    state:    str  = "open",   # open | closed | all
    labels:   str  = "",       # comma-separated label filter
    per_page: int  = 10,
    page:     int  = 1,
) -> list:
    """List a repo's issues (excludes pull requests, which GitHub also
    returns as issues). Returns [] on any error."""
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/issues",
            headers=_headers(token),
            params={
                "state":     state,
                "per_page":  per_page,
                "page":      page,
                "sort":      "created",
                "direction": "desc",
                **({"labels": labels} if labels else {}),
            },
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return []
        return [it for it in r.json() if "pull_request" not in it]
    except requests.RequestException:
        return []


def get_issue(token: str, owner: str, repo: str, number: int) -> dict | None:
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/issues/{number}",
            headers=_headers(token),
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        return None
    except requests.RequestException:
        return None


def create_issue(
    token:  str,
    owner:  str,
    repo:   str,
    title:  str,
    body:   str  = "",
    labels: list | None = None,
) -> dict:
    """Create an issue. Raises GitHubError on failure."""
    title = (title or "").strip()
    if not title:
        raise GitHubError("Issue title cannot be empty.", 422)
    if len(title) > 256:
        raise GitHubError(f"Issue title is {len(title)} characters; GitHub allows at most 256.", 422)
    payload: dict = {"title": title, "body": body or ""}
    if labels:
        payload["labels"] = labels
    r = _session.post(
        f"{GITHUB_API}/repos/{owner}/{repo}/issues",
        headers=_headers(token),
        json=payload,
        timeout=TIMEOUT,
    )
    return _check(r, 201)


def set_issue_state(token: str, owner: str, repo: str, number: int, state: str) -> bool:
    """Open or close an issue. state must be 'open' or 'closed'."""
    if state not in ("open", "closed"):
        return False
    try:
        r = _session.patch(
            f"{GITHUB_API}/repos/{owner}/{repo}/issues/{number}",
            headers=_headers(token),
            json={"state": state},
            timeout=TIMEOUT,
        )
        return r.status_code == 200
    except requests.RequestException:
        return False


def comment_issue(token: str, owner: str, repo: str, number: int, body: str) -> bool:
    body = (body or "").strip()
    if not body:
        return False
    try:
        r = _session.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/issues/{number}/comments",
            headers=_headers(token),
            json={"body": body},
            timeout=TIMEOUT,
        )
        return r.status_code in (200, 201)
    except requests.RequestException:
        return False


# ══════════════════════════════════════════════════════════════
#  Pull Requests
# ══════════════════════════════════════════════════════════════

def list_pull_requests(
    token:    str,
    owner:    str,
    repo:     str,
    state:    str  = "open",   # open | closed | all
    per_page: int  = 10,
    page:     int  = 1,
) -> list:
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/pulls",
            headers=_headers(token),
            params={"state": state, "per_page": per_page, "page": page, "sort": "created", "direction": "desc"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        return []
    except requests.RequestException:
        return []


def get_pull_request(token: str, owner: str, repo: str, number: int) -> dict | None:
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{number}",
            headers=_headers(token),
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        return None
    except requests.RequestException:
        return None


def list_pull_request_files(token: str, owner: str, repo: str, number: int, per_page: int = 30) -> list:
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{number}/files",
            headers=_headers(token),
            params={"per_page": per_page},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        return []
    except requests.RequestException:
        return []


def create_pull_request(
    token: str,
    owner: str,
    repo:  str,
    title: str,
    head:  str,
    base:  str,
    body:  str = "",
    draft: bool = False,
) -> dict:
    """Open a pull request. Raises GitHubError on failure."""
    title = (title or "").strip()
    if not title:
        raise GitHubError("Pull request title cannot be empty.", 422)
    if not head or not base:
        raise GitHubError("Both head and base branches are required.", 422)
    r = _session.post(
        f"{GITHUB_API}/repos/{owner}/{repo}/pulls",
        headers=_headers(token),
        json={"title": title, "head": head, "base": base, "body": body or "", "draft": draft},
        timeout=TIMEOUT,
    )
    return _check(r, 201)


# ══════════════════════════════════════════════════════════════
#  Commits
# ══════════════════════════════════════════════════════════════

def list_commits(
    token:    str,
    owner:    str,
    repo:     str,
    branch:   str  = "",
    per_page: int  = 15,
    page:     int  = 1,
) -> list:
    params: dict = {"per_page": per_page, "page": page}
    if branch:
        params["sha"] = branch
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/commits",
            headers=_headers(token),
            params=params,
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        return []
    except requests.RequestException:
        return []


# ══════════════════════════════════════════════════════════════
#  Tags (git refs of type tag)
# ══════════════════════════════════════════════════════════════

def get_ref_sha(token: str, owner: str, repo: str, ref: str) -> str | None:
    """ref is a short ref such as 'heads/main' or 'tags/v1.0.0'."""
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/{ref}",
            headers=_headers(token),
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json().get("object", {}).get("sha")
        return None
    except requests.RequestException:
        return None


def list_tags(token: str, owner: str, repo: str, per_page: int = 30) -> list:
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/tags",
            headers=_headers(token),
            params={"per_page": per_page},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        return []
    except requests.RequestException:
        return []


def create_tag(token: str, owner: str, repo: str, tag: str, from_ref: str = "main") -> bool:
    """Create a lightweight tag pointing at the tip of from_ref (a branch or sha)."""
    tag = (tag or "").strip()
    if not tag:
        return False
    sha = get_ref_sha(token, owner, repo, f"heads/{from_ref}")
    if not sha and from_ref == "main":
        # Only the well-known main→master rename may be auto-fallback;
        # any other ref must fail loudly so callers pass the real branch.
        sha = get_ref_sha(token, owner, repo, "heads/master")
    if not sha:
        # from_ref may itself be a sha
        sha = from_ref if len(from_ref) == 40 else None
    if not sha:
        return False
    try:
        r = _session.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/refs",
            headers=_headers(token),
            json={"ref": f"refs/tags/{tag}", "sha": sha},
            timeout=TIMEOUT,
        )
        return r.status_code == 201
    except requests.RequestException:
        return False


def delete_tag(token: str, owner: str, repo: str, tag: str) -> bool:
    try:
        r = _session.delete(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/refs/tags/{_encode_path(tag)}",
            headers=_headers(token),
            timeout=TIMEOUT,
        )
        return r.status_code == 204
    except requests.RequestException:
        return False


# ══════════════════════════════════════════════════════════════
#  Releases
# ══════════════════════════════════════════════════════════════

def list_releases(token: str, owner: str, repo: str, per_page: int = 20) -> list:
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/releases",
            headers=_headers(token),
            params={"per_page": per_page},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        return []
    except requests.RequestException:
        return []


def create_release(
    token:       str,
    owner:       str,
    repo:        str,
    tag:         str,
    name:        str = "",
    body:        str = "",
    draft:       bool = False,
    prerelease:  bool = False,
    target:      str = "main",
) -> dict:
    """Publish a GitHub release for an existing tag.
    GitHub auto-creates the tag from ``target`` if it doesn't exist yet.
    Raises GitHubError on failure."""
    tag = (tag or "").strip()
    if not tag:
        raise GitHubError("A tag is required to create a release.", 422)
    r = _session.post(
        f"{GITHUB_API}/repos/{owner}/{repo}/releases",
        headers=_headers(token),
        json={
            "tag_name":          tag,
            "name":              (name or tag),
            "body":              body or "",
            "draft":             draft,
            "prerelease":        prerelease,
            "target_commitish":  target,
        },
        timeout=TIMEOUT,
    )
    return _check(r, 201)


def delete_release(token: str, owner: str, repo: str, release_id: int) -> bool:
    try:
        r = _session.delete(
            f"{GITHUB_API}/repos/{owner}/{repo}/releases/{release_id}",
            headers=_headers(token),
            timeout=TIMEOUT,
        )
        return r.status_code == 204
    except requests.RequestException:
        return False


def delete_branch(token: str, owner: str, repo: str, branch: str) -> bool:
    try:
        r = _session.delete(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/refs/heads/{_encode_path(branch)}",
            headers=_headers(token),
            timeout=TIMEOUT,
        )
        return r.status_code == 204
    except requests.RequestException:
        return False


# ── GitHub Pages / Live Preview ──────────────────────────────

def get_pages_info(token: str, owner: str, repo: str) -> dict | None:
    """Return the GitHub Pages site info for a repo, or None when Pages is
    not enabled (HTTP 404) or the request fails for any other reason.

    The returned dict contains ``html_url`` (the live preview site), ``status``
    (building/built/errored), ``source`` and ``cname`` when applicable.
    """
    try:
        r = _session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/pages",
            headers=_headers(token),
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            try:
                return r.json()
            except ValueError:
                return None
        return None
    except requests.RequestException:
        return None


def enable_pages(token: str, owner: str, repo: str, branch: str = "main",
                 path: str = "/") -> tuple[bool, str]:
    """Enable GitHub Pages for a repository (POST /repos/{owner}/{repo}/pages).

    Returns (ok, message). ``message`` carries a short, user-safe explanation:
      - created      → Pages site created
      - exists       → site already enabled (409)
      - private      → plan/repo visibility restriction (403)
      - error        → other API failure (details logged server-side only)
    """
    try:
        r = _session.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/pages",
            headers=_headers(token),
            json={"source": {"branch": branch, "path": path}},
            timeout=TIMEOUT,
        )
        if r.status_code in (201, 202):
            return True, "created"
        if r.status_code == 409:
            return True, "exists"
        if r.status_code == 403:
            return False, "private"
        return False, "error"
    except requests.RequestException:
        return False, "error"


def find_html_entry(files: list) -> str | None:
    """Pick the best HTML entry file from a repo tree listing.

    Preference order: index.html at root, index.htm, then any *.html/*.htm
    file (shallowest path first). ``files`` is the list returned by
    :func:`get_repo_tree` (dicts with ``path``).
    """
    html_paths = [f["path"] for f in files
                  if f.get("type") == "blob" or "path" in f]
    html_paths = [p for p in html_paths
                  if p.lower().endswith((".html", ".htm"))]
    if not html_paths:
        return None
    lowered = {p.lower(): p for p in html_paths}
    for candidate in ("index.html", "index.htm"):
        if candidate in lowered:
            return lowered[candidate]
    return sorted(html_paths, key=lambda p: (p.count("/"), len(p)))[0]
