import json
import os
import subprocess
import sys
from pathlib import Path

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
