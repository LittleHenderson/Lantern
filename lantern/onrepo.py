"""What Lantern leaves on the repository it checked (2026-11-15): three ways, one set of words.

1. **The report saved in the repository**: `save(repo, out, dest)` writes a folder (`.lantern/report/` by default)
   holding `README.md` (the summary below, which GitHub shows when the folder is opened), `badge.svg`,
   `evidence.html` and `evidence.json` (the commit-pinned Evidence Report and its digest, which `lantern verify`
   checks). The GitHub Action (`action.yml` at the top of Lantern's repository) puts that folder on a branch of its
   own and opens, or brings up to date, one pull request with it; the owner merges it when they want it kept.
2. **A comment on each pull request**: `summary(ev, short=True)`, posted by the Action as one comment that it
   edits on every new push (`MARKER` finds it again).
3. **A badge on the front page**: `badge.svg` in the saved folder, which the README links to with a relative path
   (`BADGE_LINE`), so it needs no website of Lantern's to show.

`setup(repo)` (`lantern github setup`) writes the workflow that runs the Action, a first badge that says "no
analysis yet", the badge line at the top of the README and, where the project ignores `.lantern/` as a whole, the
lines that let `.lantern/report/` be committed. Nothing here talks to GitHub: the Action does that with GitHub's own
`gh` program and the token GitHub gives the workflow, so Lantern writes to a repository only where its owner has
put the workflow in it.

Every value in the words comes from result files, which may lie in a folder that came with the project, so each one
is taken by its shape and written so that GitHub shows it as text (`md`, `code`): no link, image, HTML, mention of a
person or reference to an issue can be made through a finding's title or a file's name."""

from __future__ import annotations

import re
from pathlib import Path

from . import __version__, evidence, release, results
from .python_frontend import inside_repo, project_text

MARKER = "<!-- lantern-report -->"
FOLDER = ".lantern/report"
WORKFLOW = ".github/workflows/lantern.yml"
BADGE_LINE = f"[![Lantern]({FOLDER}/badge.svg)]({FOLDER}/README.md)"
ACTION = "LittleHenderson/Lantern"
FIRST_WITH_ACTION = (0, 12, 0)        # the first release whose tag holds action.yml
MOST_COMMENT = 60_000                 # GitHub takes 65,536 characters in a comment or a pull request's text
TOP_COMMENT, TOP_SAVED = 10, 50       # how many open findings each form lists by name
RANK_ORDER = ("critical", "high", "medium", "low")

LOOK = {   # the mark beside each decision's word: a reading aid, never the only sign
    "Passed": ("🟢", "Passed", "Every check this kind of project needs was done and nothing serious is open."),
    "Blocked": ("🔴", "Blocked", "Something this project needs before release failed. Fix it before you ship."),
    "Incomplete": ("🟡", "Incomplete", "Nothing failed, but something this project needs was not checked, so this "
                                       "is not a pass yet."),
}
NO_DECISION = ("⚪", "No decision", "This report has no release decision (an older Lantern made it).")
STATE_MARK = {"passed": "✅ passed", "failed": "❌ failed", "missing": "⏳ not checked",
              "not-applicable": "➖ not needed here"}

_ZW = "\u200b"
_CONTROL = re.compile(r"[\x00-\x1f\x7f\u2028\u2029]+")


def md(value, most: int = 300) -> str:
    """Any value as plain text in GitHub's Markdown: one line, at most `most` characters, every character that could
    start a link, an image, emphasis, a table cell, HTML or a heading shown as itself, and `@name`, `#123` and `x://`
    broken with a zero-width space so GitHub makes no mention, issue reference or link of them."""
    s = _CONTROL.sub(" ", "" if value is None else str(value)).strip()
    if len(s) > most:
        s = s[:most - 1] + "…"
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = re.sub(r"([\\`*_{}\[\]()#!|~$])", r"\\\1", s)
    s = s.replace("@", "@" + _ZW).replace("\\#", "\\#" + _ZW).replace("://", ":" + _ZW + "//")
    s = re.sub(r"(?i)\bwww\.", lambda m: m.group(0)[:3] + _ZW + ".", s)
    return s


def code(value, most: int = 200) -> str:
    """A file name, an id or a command as a code span: nothing inside one is a link or a mention. Backticks are taken
    out, since a value cannot be trusted to hold none."""
    s = _CONTROL.sub(" ", "" if value is None else str(value)).replace("`", "'").strip()
    if len(s) > most:
        s = s[:most - 1] + "…"
    return f"`{s}`" if s else "`-`"


def _int(v) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0


def _text(v, most: int = 400) -> str:
    return v[:most] if isinstance(v, str) else ""


def _table(v) -> dict:
    return v if isinstance(v, dict) else {}


def _sentence(s: str) -> str:
    return s if not s or s[-1] in ".!?…)" else s + "."


def decision_of(ev: dict | None) -> str:
    """The decision's word, or "none" when the report has none."""
    view = release.shown({"release": _table(ev).get("release")})
    return view["decision"] if view else "none"


def _place(f: dict) -> str:
    where = _text(f.get("file"), 300)
    line = f.get("line")
    return where + (f":{line}" if isinstance(line, int) and not isinstance(line, bool) and line > 0 else "")


def _https(url) -> str | None:
    """A link for the words only when it is plain https to GitHub, the one place the Action points at."""
    return url if isinstance(url, str) and re.fullmatch(r"https://github\.com/[A-Za-z0-9._~/%#?=&+-]{1,500}", url) \
        else None


def summary(ev: dict | None, *, short: bool = False, run_url: str | None = None, report_url: str | None = None,
            saved: bool = False) -> str:
    """The report in a few lines of Markdown: the decision and what it means, the open problems by severity, why the
    decision is what it is, the most serious problems by name, what could not be checked, and, folded away for
    engineers, how to check the report again. `short`: the form for a pull request's comment. `saved`: the form
    kept in the repository beside `evidence.html` (it says how to open that file)."""
    ev = _table(ev)
    h, sc, se = _table(ev.get("header")), _table(ev.get("scorecard")), _table(ev.get("security"))
    now = _table(sc.get("now"))
    view = release.shown({"release": ev.get("release")})
    mark, word, means = LOOK.get(view["decision"]) if view else NO_DECISION
    commit = re.sub(r"[^0-9a-f]", "", _text(h.get("commit"), 64))
    lines = [MARKER, f"## {mark} Lantern: {word}", "", f"**What this means:** {means}"]
    if view and view["words"] and not view["criteria"]:
        lines.append(f"Lantern's own words: {md(view['words'], 600)}")
    when = md(_text(h.get("generated_at"), 40))
    lines += ["", "Checked " + (f"commit {code(commit[:12])}" if commit else "uncommitted files")
              + (" (with changes that were not committed)" if h.get("dirty") is True else "")
              + (f" on {when}" if when else "") + f" by Lantern {code(_text(h.get('engine'), 60) or __version__)}.", ""]

    counts = {k: _int(now.get(k)) for k in RANK_ORDER}
    lines += ["| Critical | High | Medium | Low |", "|---:|---:|---:|---:|",
              "| " + " | ".join(str(counts[k]) for k in RANK_ORDER) + " |", "",
              "Open problems by how serious they are. Critical and high ones block a release until they are fixed or "
              "accepted with a written reason.", ""]

    crit = view["criteria"] if view else []
    if crit:
        lines += ["### Why the decision is what it is", ""]
        for c in crit:
            need = "" if c["required"] else " (not needed for this kind of project)"
            lines.append(f"- {STATE_MARK.get(c['state'], md(c['state']))}: **{md(c['title'] or c['id'], 120)}**{need}"
                         + (f". {_sentence(md(c['why'], 400))}" if c["why"] else "")
                         + (f" To do: {md(c['fix'], 300)}" if c["fix"] and c["state"] in ("failed", "missing") else ""))
        lines.append("")

    opened = [f for f in (se.get("open") if isinstance(se.get("open"), list) else []) if isinstance(f, dict)]
    opened.sort(key=lambda f: RANK_ORDER.index(f["rank"]) if f.get("rank") in RANK_ORDER else 9)
    top = TOP_COMMENT if short else TOP_SAVED
    if opened:
        lines += [f"### The most serious open problems ({min(top, len(opened))} of {len(opened)})", ""]
        for f in opened[:top]:
            rank = f.get("rank") if f.get("rank") in RANK_ORDER else "unranked"
            heur = " (heuristic: a pattern Lantern matched, worth a second look)" if f.get("tool_confidence") == "LOW" \
                else ""
            lines.append(f"- **{rank}** · {md(f.get('title'), 200)} · {code(_place(f))}{heur}")
        lines.append("")
    accepted = se.get("accepted") if isinstance(se.get("accepted"), list) else []
    if accepted:
        lines += [f"{len(accepted)} more {'were' if len(accepted) != 1 else 'was'} accepted as a known risk with a "
                  "written reason; the full report lists them.", ""]

    gaps = [t for t in (se.get("incomplete") if isinstance(se.get("incomplete"), list) else []) if isinstance(t, dict)]
    if gaps:
        lines += ["### What Lantern could not check", ""]
        for t in gaps[:10]:
            lines.append(f"- {code(_text(t.get('tool'), 60))}: {md(t.get('why') or t.get('status'), 300)}")
        lines.append("")

    links = []
    if _https(report_url):
        links.append(f"[Download the full report]({report_url}) (open `report.html` from it in any browser)")
    if _https(run_url):
        links.append(f"[See this check's run]({run_url})")
    if saved:
        links.append("The full Evidence Report is `evidence.html` in this folder: download it and open it in a "
                     "browser")
    if links:
        lines += [" · ".join(links), ""]

    digest = _text(ev.get("digest"), 80)
    if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or commit:
        engine = _text(h.get("engine"), 60)
        ref = engine if re.fullmatch(r"[0-9a-f]{40}|v\d+\.\d+\.\d+", engine) else f"v{__version__}"
        lines += ["<details><summary>For engineers: check this report yourself</summary>", "",
                  f"- Results digest: {code(digest) if digest else 'none'}",
                  f"- Commit: {code(commit) if commit else 'none'}",
                  f"- Lantern: {code(ref)}", "",
                  "```",
                  (f"cp {FOLDER}/evidence.json ../lantern-evidence.json   # where the report is saved"
                   if saved else
                   "cp <the full report>/evidence.json ../lantern-evidence.json   # downloaded from the run"),
                  f"git checkout {commit or '<commit>'}",
                  f'pip install "lantern[scan] @ git+https://github.com/{ACTION}@{ref}"',
                  "lantern verify . --report ../lantern-evidence.json",
                  "```", "",
                  "`MATCH` means this Lantern finds the same results on this commit. A warning about a library that was "
                  "published after this check can change the dependency results, and `lantern verify` names what "
                  "differs. Lantern never says \"secure\" or \"verified\": the Limits section of the full report says "
                  "what was not checked.", "", "</details>", ""]
    lines.append("<sub>Lantern reads the code and runs its scanners; it changes nothing in this repository except "
                 f"the report folder {code(FOLDER)}, and only through a pull request you merge.</sub>")
    text = "\n".join(lines) + "\n"
    if len(text) > MOST_COMMENT:
        text = text[:MOST_COMMENT - 80].rsplit("\n", 1)[0] + "\n\n…cut short: the full report has the rest.\n"
    return text


def read(out: Path) -> dict:
    """`evidence.json` of a finished check, by its shape. `results.Refused` (in words for the person) when it is not
    a plain file holding a JSON table."""
    ev = results.table(Path(out) / "evidence.json")
    if not isinstance(ev, dict):
        raise results.Refused(f"{Path(out) / 'evidence.json'} does not hold an Evidence Report.")
    return ev


def _folder(repo: Path, rel: str) -> Path:
    """A folder of the project for Lantern's own files, made when it is not there; `results.Refused` when it, or a
    folder on the way, is a link that came with the project (`results.folder`)."""
    return results.folder(repo, Path(repo).resolve() / rel)


def save(repo: Path, out: Path, dest: str | None = None, *, run_url: str | None = None,
         report_url: str | None = None) -> list[Path]:
    """Write the report folder that is kept in the repository and return the files written. The Evidence Report is
    copied as Lantern wrote it; README.md is the summary; the badge is drawn anew from the report."""
    repo = Path(repo).resolve()
    out = Path(out)
    ev = read(out)
    where = _folder(repo, dest or FOLDER)
    written = [results.write(where / "README.md",
                             summary(ev, saved=True, run_url=run_url, report_url=report_url), newline="\n",
                             where="the project folder")]
    for name in ("evidence.html", "evidence.json"):
        text = results.text(out / name)
        if text is not None:
            written.append(results.write(where / name, text, newline="\n", where="the project folder"))
    rd = _table(_table(ev.get("scorecard")).get("readiness"))
    score = rd.get("score") if isinstance(rd.get("score"), int) else None
    written.append(results.write(where / "badge.svg",
                                 evidence.badge_svg(score, _text(rd.get("grade"), 3) or None, ev) + "\n",
                                 newline="\n", where="the project folder"))
    return written


def action_ref(engine: str | None = None) -> str:
    """The version of the Action a new workflow names: the exact commit of this Lantern when it knows it (an engineer
    can read what runs), its release tag once releases hold the Action, else the main branch."""
    engine = engine if engine is not None else evidence.engine_ref()
    if re.fullmatch(r"[0-9a-f]{40}", engine or ""):
        return engine
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", engine or "")
    if m and tuple(int(x) for x in m.groups()) >= FIRST_WITH_ACTION:
        return f"v{'.'.join(m.groups())}"
    return "main"


def workflow(ref: str) -> str:
    """The workflow `setup` writes. It runs on every push and pull request. The report folder itself is left out of
    the pushes that start it (`paths-ignore`), so merging the report does not start a new report."""
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", ref):
        raise ValueError("an Action version is a tag, a branch or a commit")
    return f"""# Lantern checks this repository and leaves its report here (written by `lantern github setup`).
# - On each pull request: one comment with the result (Passed, Blocked or Incomplete), updated on every push.
# - On the main branch: a pull request that saves the report in {FOLDER}/. Merge it to keep the report and
#   to update the badge on your front page.
# - The check fails when the result is Blocked. Change `require` below to `passed` or `none` to change that.
name: Lantern
on:
  push:
    paths-ignore: ["{FOLDER}/**"]
  pull_request:
  workflow_dispatch:
permissions:
  contents: write        # to put the report on the branch lantern/report
  pull-requests: write   # to comment on pull requests and open the report's pull request
jobs:
  lantern:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false   # the token is handed to git only for the push of the report's branch
      - uses: {ACTION}@{ref}
        with:
          require: not-blocked
"""


def placeholder() -> str:
    return (f"{MARKER}\n## ⚪ Lantern: no analysis yet\n\nThe first check runs when this repository is pushed to "
            "GitHub. It then opens a pull request that puts the report here; merge it and this page and the badge "
            "show the result.\n")


def _gitignore(repo: Path) -> str | None:
    """Let `.lantern/report/` be committed where the top `.gitignore` leaves the whole of `.lantern` out (git cannot
    take a file back out of a folder it ignores, so `.lantern/` becomes `.lantern/*` with the report folder taken
    back). The new text, or None when nothing has to change."""
    gi = repo / ".gitignore"
    if not inside_repo(gi, repo):
        return None
    text = project_text(gi, repo, 1_000_000)
    lines = text.splitlines()
    hit = [i for i, ln in enumerate(lines) if ln.strip() in (".lantern", ".lantern/", "/.lantern", "/.lantern/")]
    if not hit or any(ln.strip() in ("!.lantern/report/", "!/.lantern/report/") for ln in lines):
        return None
    for i in hit:
        lines[i] = lines[i].strip().rstrip("/") + "/*"
    lines.insert(hit[-1] + 1, "!" + ("/" if lines[hit[-1]].startswith("/") else "") + ".lantern/report/")
    return "\n".join(lines) + "\n"


README_NAMES = ("README.md", "Readme.md", "readme.md")


def _readme(repo: Path) -> tuple[Path | None, str | None]:
    """The README with the badge line put in (below the first heading, else at the top), or (path, None) when it
    already has it, or (None, None) when the project has no Markdown README."""
    for name in README_NAMES:
        p = repo / name
        if inside_repo(p, repo):
            text = project_text(p, repo, 5_000_000)
            if f"{FOLDER}/badge.svg" in text:
                return p, None
            lines = text.splitlines()
            at = next((i + 1 for i, ln in enumerate(lines[:20]) if ln.startswith("# ")), 0)
            lines[at:at] = ([""] if at else []) + [BADGE_LINE] + ([""] if not at else [])
            return p, "\n".join(lines) + "\n"
    return None, None


def setup(repo: Path, *, ref: str | None = None, readme: bool = True, force: bool = False) -> list[str]:
    """Put Lantern on a repository: the workflow, the first badge and README, the badge line in the project's README,
    and the `.gitignore` lines. Returns what was done, one sentence each. `results.Refused` for a workflow that is
    already there and is not Lantern's (unless `force`), and for a folder that is a link."""
    repo = Path(repo).resolve()
    done = []
    wf = repo / WORKFLOW
    old = project_text(wf, repo, 200_000) if inside_repo(wf, repo) else None
    if old is not None and f"{ACTION}@" not in old and not force:
        raise results.Refused(f"{WORKFLOW} is already there and does not run Lantern. Move it, or run again with "
                              "--force to replace it.")
    text = workflow(ref or action_ref())
    if old != text:
        _folder(repo, ".github/workflows")
        results.write(wf, text, newline="\n", where="the project folder")
        done.append(f"Wrote {WORKFLOW}: Lantern now checks every push and pull request on GitHub.")
    else:
        done.append(f"{WORKFLOW} was already there.")
    where = _folder(repo, FOLDER)
    if not inside_repo(where / "README.md", repo):
        results.write(where / "README.md", placeholder(), newline="\n", where="the project folder")
        results.write(where / "badge.svg", evidence.badge_svg() + "\n", newline="\n", where="the project folder")
        done.append(f"Wrote {FOLDER}/README.md and badge.svg, which say \"no analysis yet\" until the first report "
                    "is merged.")
    ignore = _gitignore(repo)
    if ignore is not None:
        results.write(repo / ".gitignore", ignore, newline="\n", where="the project folder")
        done.append(f".gitignore left all of .lantern out; it now keeps {FOLDER}/ so the report can be committed.")
    if readme:
        p, new = _readme(repo)
        if p is None:
            done.append(f"No README.md: put this line at the top of your front page to show the badge: {BADGE_LINE}")
        elif new is None:
            done.append(f"{p.name} already shows the badge.")
        else:
            results.write(p, new, newline="\n", where="the project folder")
            done.append(f"Put the Lantern badge at the top of {p.name}.")
    return done


def setup_steps() -> list[str]:
    """What the person still does on GitHub, in order."""
    return ["Commit these files and push them to GitHub (for example: git add -A && git commit -m \"Add Lantern\" "
            "&& git push).",
            "On GitHub open Settings, then Actions, then General. Under \"Workflow permissions\" tick \"Allow GitHub "
            "Actions to create and approve pull requests\" and press Save. Without it Lantern can still comment, but "
            "cannot open the pull request that saves the report.",
            "Wait for the first check (the Actions tab shows it), then merge the pull request \"Lantern report\" to "
            "keep the report and light up the badge."]

