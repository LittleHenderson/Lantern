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
