"""Browser checks (a firm pass or fail, stage 5, 2026-11-21): the project's own site opened in a real browser, and
what happened there said. The contract is `docs/browser.md`, written before the checks were built; this module holds
its list, and `tests/test_browse.py` holds the two to each other.

Step 1 of the stage: the list (`CHECKS`, each with its codes; `OUTCOMES`; `WHY_NOT`), where a browser is found
(`find_browser`) and the record a run gives (`run`). Until the checks are built, every check of a run is `not-run`
with the reason `not-built`, and nothing else in Lantern reads the record.

What the checks will hold to (docs/browser.md, "Where it runs, and where it never does"): the site is the project's
own, never an address; an app is started in the sealed box, plain pages are served from the project's folder by
Lantern's own code; the browser's one way out is a door of Lantern's own that answers the site's address and refuses
every other; the browser keeps its own sandbox, gets an empty profile of the run's own and is driven through a pipe,
never a port; pictures stay on this computer; a browser check never creates, closes or re-ranks a finding."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from . import programs


@dataclass(frozen=True)
class Check:
    """One check: its id, what it holds in plain words, and the codes a broken outcome gives."""
    id: str
    title: str
    codes: tuple[str, ...]


CHECKS: tuple[Check, ...] = (
    Check("opens", "every page opens", ("server-error", "not-found", "no-answer", "empty")),
    Check("script", "the page's own script runs without an error", ("raised", "console-error", "not-loaded")),
    Check("leads", "links and buttons lead somewhere", ("dead-link", "empty-link", "dead-button", "button-raises")),
    Check("forms", "forms can be sent", ("form-error", "form-nowhere", "form-raises")),
    Check("visitor", "a visitor who is not signed in is kept out where the code asks for a sign-in", ("let-in",)),
    Check("protections", "the protections the code sets are sent", ("said-not-sent", "cookie-open")),
    Check("outside", "nothing is asked of another computer", ("outside-script", "outside-file")),
    Check("keyboard", "it can be used without a mouse",
          ("no-name", "no-label", "not-reached", "no-focus-ring", "trapped")),
)
BY_ID = {c.id: c for c in CHECKS}

# Only `held` counts as held. `inconclusive` comes only from `script` (an error on a page where a script from another
# computer was refused may come from that script being missing).
OUTCOMES = ("held", "broken", "inconclusive", "nothing-to-check", "not-run")

# Why a check, or a whole run, was not run: Lantern's own words, never text of a page, a browser or an app.
WHY_NOT = {
    "not-built": "The browser checks are not built yet: this version of Lantern holds their list only.",
    "no-browser": "No browser Lantern can drive was found (Chrome, Chromium, Edge or Brave); LANTERN_BROWSER can name "
                  "one by its full path.",
    "no-browser-sandbox": "The browser cannot keep its own sandbox on this computer, and Lantern does not open a "
                          "project's pages without it.",
    "no-site": "There is nothing to open: no folder of plain pages and no app Lantern can start.",
    "not-started": "The app could not be started in the sealed box.",
    "no-sandbox": "The sealed box cannot be set up on this computer, so the app is not started.",
    "hosting-unknown": "Plain pages: what a hosting service would send with them is not in the project's folder.",
}

MOST_PAGES = 50          # pages opened in one run
MOST_CLICKS = 40         # links and buttons clicked on one page
PAGE_SECONDS = 20        # how long a page has to answer and settle
NOT_COMPARED = ("Strict-Transport-Security",)   # sent over HTTPS only; the site is served over plain HTTP in a run

# Where each system installs the browsers Lantern drives (all of the Chromium family, driven alike).
ON_PATH = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge",
           "microsoft-edge-stable", "brave-browser")
MAC_APPS = ("Google Chrome.app/Contents/MacOS/Google Chrome", "Chromium.app/Contents/MacOS/Chromium",
            "Microsoft Edge.app/Contents/MacOS/Microsoft Edge", "Brave Browser.app/Contents/MacOS/Brave Browser")
WINDOWS_PLACES = (("ProgramFiles", r"Google\Chrome\Application\chrome.exe"),
                  ("ProgramFiles(x86)", r"Google\Chrome\Application\chrome.exe"),
                  ("LOCALAPPDATA", r"Google\Chrome\Application\chrome.exe"),
                  ("ProgramFiles", r"Microsoft\Edge\Application\msedge.exe"),
                  ("ProgramFiles(x86)", r"Microsoft\Edge\Application\msedge.exe"),
                  ("ProgramFiles", r"BraveSoftware\Brave-Browser\Application\brave.exe"),
                  ("LOCALAPPDATA", r"BraveSoftware\Brave-Browser\Application\brave.exe"),
                  ("LOCALAPPDATA", r"Chromium\Application\chrome.exe"))


def _program(path: str) -> bool:
    return os.path.isabs(path) and os.path.isfile(path) and (sys.platform == "win32" or os.access(path, os.X_OK))


def find_browser(env=None, system: str | None = None) -> str | None:
    """The full path of the browser a run uses, or None: the one `LANTERN_BROWSER` names (a full path; one that names
    no program gives None, and no other is looked for), else the first of the places each system installs them."""
    env = os.environ if env is None else env
    system = system or sys.platform
    named = (env.get("LANTERN_BROWSER") or "").strip()
    if named:
        return os.path.normpath(named) if _program(named) else None
    if system == "win32":
        for var, rest in WINDOWS_PLACES:
            top = (env.get(var) or "").strip()
            if top and os.path.isabs(top) and _program(os.path.join(top, rest)):
                return os.path.join(top, rest)
        return None
    if system == "darwin":
        home = (env.get("HOME") or "").strip()
        for top in ["/Applications"] + ([os.path.join(home, "Applications")] if os.path.isabs(home) else []):
            for app in MAC_APPS:
                if _program(os.path.join(top, app)):
                    return os.path.join(top, app)
        return None
    for name in ON_PATH:
        found = programs.find(name, env.get("PATH", os.defpath))
        if found:
            return found
    return None


def _not_run(why: str) -> dict:
    return {"ran": False, "why_not": why, "why": WHY_NOT[why],
            "checks": [{"id": c.id, "outcome": "not-run", "codes": [], "saw": [], "why": why} for c in CHECKS]}


def run(repo, *, browser: str | None = None, page_seconds: float = PAGE_SECONDS, log=None) -> dict:
    """Open the site of the project at `repo` in a browser and give the record (docs/browser.md, "What comes out").
    `browser`: the browser's full path; None looks for one (`find_browser`). `page_seconds`: how long a page has to
    answer and settle. Until the checks are built, every check of the record is `not-run`: `no-browser` where no
    browser is there, `not-built` where one is."""
    found = (os.path.normpath(browser) if _program(browser) else None) if browser else find_browser()
    if log:
        log(f"browser {found or 'none found'}")
    return _not_run("no-browser" if found is None else "not-built")
