"""
github_api.py — GitHub REST API wrapper for GitHub AI Repo Bot V9
"""

from __future__ import annotations
from typing import Optional
import requests

GITHUB_API = "https://api.github.com"
TIMEOUT    = 15


def _headers(token: str) -> dict:
    return {
        "Authorization":        f"token {token}",
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


class GitHubError(Exception):
    def __init__(self, message: str, status: int = 0):
        self.status  = status
        self.message = message
        super().__init__(message)


def _check(r: requests.Response, expect: int | tuple) -> dict:
    """Raise GitHubError if status code is unexpected."""
    expected = expect if isinstance(expect, tuple) else (expect,)
    if r.status_code not in expected:
        try:
            msg = r.json().get("message", r.text[:200])
        except Exception:
            msg = r.text[:200]
        raise GitHubError(msg, r.status_code)
    try:
        return r.json()
    except Exception:
        return {}


# ── Auth ───────────────────────────────────────────────────────

def get_user(token: str) -> Optional[dict]:
    try:
        r = requests.get(f"{GITHUB_API}/user", headers=_headers(token), timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json()
        return None
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
    r = requests.post(
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
    return _check(r, 201)


def delete_repo(token: str, owner: str, repo: str) -> bool:
    """Delete a repo. Returns True on success."""
    try:
        r = requests.delete(
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
        r = requests.get(
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
    r = requests.post(
        f"{GITHUB_API}/repos/{owner}/{repo}/forks",
        headers=_headers(token),
        timeout=TIMEOUT,
    )
    return _check(r, 202)


def star_repo(token: str, owner: str, repo: str) -> bool:
    try:
        r = requests.put(
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
        r = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
            headers=_headers(token),
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json().get("sha")
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
    # content may already be base64 (photos) — detect by trying to encode as utf-8
    try:
        encoded = base64.b64encode(content.encode("utf-8")).decode()
    except (UnicodeEncodeError, AttributeError):
        # already binary-safe base64 string
        encoded = content if isinstance(content, str) else base64.b64encode(content).decode()

    payload: dict = {"message": message, "content": encoded}

    # Fetch existing SHA — needed if file already exists (e.g. README.md from auto_init)
    sha = get_file_sha(token, owner, repo, path)
    if sha:
        payload["sha"] = sha

    try:
        r = requests.put(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
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
        r = requests.get(
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
        r = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}",
            headers=_headers(token),
            params={"recursive": "1"},
            timeout=30,
        )
        if r.status_code == 200:
            return [item for item in r.json().get("tree", []) if item.get("type") == "blob"]
        return []
    except requests.RequestException:
        return []


def download_repo_zipball(token: str, owner: str, repo: str, branch: str = "HEAD") -> bytes | None:
    """
    Download the entire repo as a ZIP via GitHub zipball API.
    Works for both public and private repos (uses token auth).
    Returns raw bytes of the zip file, or None on failure.
    """
    try:
        r = requests.get(
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
            r = requests.get(
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
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
    params = {}
    if branch:
        params["ref"] = branch
    try:
        r = requests.get(url, headers=_headers(token), params=params, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json()
        return None
    except requests.RequestException:
        return None


def get_file_content(token: str, owner: str, repo: str, path: str, branch: str = "") -> dict | None:
    """Get a file's content and metadata (sha, content base64)."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
    params = {}
    if branch:
        params["ref"] = branch
    try:
        r = requests.get(url, headers=_headers(token), params=params, timeout=TIMEOUT)
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
        r = requests.put(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
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
        r = requests.put(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
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
        r = requests.delete(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
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
        r = requests.patch(
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
        r = requests.patch(
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
        r = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{from_branch}",
            headers=_headers(token), timeout=TIMEOUT,
        )
        if r.status_code != 200:
            # Try master
            r = requests.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/master",
                headers=_headers(token), timeout=TIMEOUT,
            )
        if r.status_code != 200:
            return False
        sha = r.json()["object"]["sha"]
        r2 = requests.post(
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
        r = requests.get(
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
        r = requests.get(
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
        r = requests.put(
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
        r = requests.put(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{new_path}",
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
