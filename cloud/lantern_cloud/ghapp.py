"""Connect GitHub: check a private repository the person chose to share with Lantern's GitHub App.

The person installs the app on GitHub (https://github.com/apps/<slug>/installations/new) and picks repositories there;
nothing about the installation is stored here. When a run's link is a github.com repository that git cannot open
anonymously, the worker asks this module for a token:

1. the app (a short-lived JWT signed with its private key) looks up the installation that covers the repository;
   none -> `NoAccess("connect")`: the website offers "Connect GitHub";
2. it asks for an installation token for that one repository, contents read-only, valid for an hour at most;
3. with that token it asks GitHub whether the signed-in person (their GitHub account id, from the gateway sign-in)
   may read the repository. Anyone else -> `NoAccess("denied")`: someone who installed the app on their private
   repository never lets a stranger who pastes its link read it.

The token goes to git in an environment variable (`lantern.remote.fetch(auth=)`), never in a link, a file or a log,
and is dropped when the clone ends.
"""

from __future__ import annotations

import re
import time

import httpx

API = "https://api.github.com"
READ = ("admin", "maintain", "write", "triage", "read")


class NoAccess(Exception):
    """`kind`: "connect" (the app is not installed on this repository), "denied" (the person cannot read it),
    "github" (they signed in with Google, so GitHub cannot say whether they may read it)."""

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


class GitHubApp:
    def __init__(self, app_id: str, private_key: str, slug: str, transport: httpx.BaseTransport | None = None,
                 api: str = API):
        self.app_id, self.key, self.slug = str(app_id), private_key, slug
        self.transport, self.api = transport, api

    @property
    def install_url(self) -> str:
        return f"https://github.com/apps/{self.slug}/installations/new"

    def _jwt(self) -> str:
        import jwt  # PyJWT with cryptography (RS256); only needed when the app is configured

        now = int(time.time())
        return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": self.app_id}, self.key, algorithm="RS256")

    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=self.api, transport=self.transport, timeout=20, follow_redirects=False,
                            headers={"accept": "application/vnd.github+json", "x-github-api-version": "2022-11-28",
                                     "user-agent": "lantern-cloud"})

    def token_for(self, owner: str, repo: str, account: str, label: str | None) -> str:
        """A read-only token for owner/repo, if the person signed in as `account` (`github:<id>`) may read it."""
        if not account.startswith("github:") or not (label or "").startswith("github:"):
            raise NoAccess("github")
        uid, login = account.split(":", 1)[1], label.split(":", 1)[1]
        with self._client() as c:
            app_auth = {"authorization": f"Bearer {self._jwt()}"}
            r = c.get(f"/repos/{owner}/{repo}/installation", headers=app_auth)
            if r.status_code == 404:
                raise NoAccess("connect")
            r.raise_for_status()
            inst = r.json()["id"]
            r = c.post(f"/app/installations/{int(inst)}/access_tokens", headers=app_auth,
                       json={"repositories": [repo], "permissions": {"contents": "read", "metadata": "read"}})
            if r.status_code in (404, 422):     # the installation does not include this repository
                raise NoAccess("connect")
            r.raise_for_status()
            token = r.json()["token"]
            r = c.get(f"/repos/{owner}/{repo}/collaborators/{login}/permission",
                      headers={"authorization": f"token {token}"})
            if r.status_code == 404:
                raise NoAccess("denied")
            r.raise_for_status()
            d = r.json()
            if str((d.get("user") or {}).get("id")) != uid or d.get("permission") not in READ:
                raise NoAccess("denied")    # a renamed login now names someone else, or no read access
            return token


# ---- the person's own repositories, for the website's list (Wakil, 2026-11-17: "when a user clicks on github it
# should open a list of all of the user's github repos"). Public ones from GitHub's public listing; private ones only
# where the person installed the app on their own account, which is GitHub's own word that they chose to share them.
# Only repositories GitHub says the signed-in account owns (by its id, not its login) are listed; nothing is stored.

LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
FULL_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}")
PAGES = 3                 # 100 a page: the 300 repositories pushed to most recently
MOST_TEXT = 160           # a description is cut here


class GitHubDown(Exception):
    """GitHub did not answer, or answered with an error or a limit."""


def _client(api: str, transport) -> httpx.Client:
    return httpx.Client(base_url=api, transport=transport, timeout=15, follow_redirects=False,
                        headers={"accept": "application/vnd.github+json", "x-github-api-version": "2022-11-28",
                                 "user-agent": "lantern-cloud"})


def _repo(d, uid: str) -> dict | None:
    """One repository as the page shows it, or None when it is not the person's own or has an odd shape."""
    if not isinstance(d, dict) or str((d.get("owner") or {}).get("id")) != uid:
        return None
    name = d.get("full_name")
    if not isinstance(name, str) or not FULL_NAME.fullmatch(name):
        return None
    text = lambda k, n: d.get(k)[:n] if isinstance(d.get(k), str) else ""  # noqa: E731
    return {"name": name, "private": d.get("private") is True, "description": text("description", MOST_TEXT),
            "language": text("language", 40), "pushed": text("pushed_at", 20)}


def _pages(c: httpx.Client, path: str, headers: dict, key: str | None = None, **more) -> list:
    out = []
    for page in range(1, PAGES + 1):
        r = c.get(path, params={**more, "per_page": 100, "page": page}, headers=headers)
        if r.status_code != 200:
            raise GitHubDown(r.status_code)
        d = r.json()
        rows = d.get(key) if key and isinstance(d, dict) else d
        if not isinstance(rows, list):
            raise GitHubDown("shape")
        out += rows
        if len(rows) < 100:
            break
    return out


def your_repos(app: GitHubApp | None, account: str, label: str | None, transport=None, api: str = API) -> dict:
    """{"repos": [...], "connected": bool}: the signed-in GitHub account's repositories, newest push first.
    `connected`: the app is installed on the account, so its private repositories it chose are in the list."""
    if not account.startswith("github:") or not (label or "").startswith("github:"):
        raise NoAccess("github")
    uid, login = account.split(":", 1)[1], label.split(":", 1)[1]
    if not LOGIN.fullmatch(login):
        raise NoAccess("github")
    found, connected, auth = {}, False, {}
    try:
        with _client(api, transport if app is None else app.transport) as c:
            if app is not None:
                jwt_auth = {"authorization": f"Bearer {app._jwt()}"}
                r = c.get(f"/users/{login}/installation", headers=jwt_auth)
                inst = r.json() if r.status_code == 200 else None
                if r.status_code not in (200, 404):
                    raise GitHubDown(r.status_code)
                if inst and str((inst.get("account") or {}).get("id")) == uid:
                    r = c.post(f"/app/installations/{int(inst['id'])}/access_tokens", headers=jwt_auth,
                               json={"permissions": {"metadata": "read"}})
                    if r.status_code != 201:
                        raise GitHubDown(r.status_code)
                    auth = {"authorization": f"token {r.json()['token']}"}
                    connected = True
                    for d in _pages(c, "/installation/repositories", auth, "repositories"):
                        if (x := _repo(d, uid)):
                            found[x["name"]] = x
            for d in _pages(c, f"/users/{login}/repos", auth, type="owner", sort="pushed"):
                if (x := _repo(d, uid)):
                    found.setdefault(x["name"], x)
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as e:
        raise GitHubDown(type(e).__name__) from None
    repos = sorted(found.values(), key=lambda x: x["pushed"], reverse=True)
    return {"repos": repos, "connected": connected}
