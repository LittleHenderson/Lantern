"""Cloud service, milestone 3: a finished run's report, evidence, badge and data in the browser, for its owner only,
through a short-lived signed link; every page rebuilt from Lantern's templates with a nonce CSP, never the stored
bytes; privacy as chosen before the run."""

import json
import re
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from test_cloud_runs import LINK, SOURCE_LINE, bearer, clone_from, make, origin, wait  # noqa: E402,F401

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def done_run(tmp_path, clone_from):  # noqa: F811
    cloud, gw, s = make(tmp_path, public_url="http://testserver")
    tok = gw.sign_in("github:1", "github:octo")
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"]
    assert wait(cloud, tok, rid)["status"] == "done"
    return cloud, gw, s, tok, rid


def links(cloud, tok, rid):
    r = cloud.post(f"/v1/runs/{rid}/view", headers=bearer(tok))
    assert r.status_code == 200, r.text
    return r.json()


def path(url):
    return url.replace("http://testserver", "")


def test_owner_opens_report_evidence_badge_and_data(done_run):
    cloud, gw, s, tok, rid = done_run
    v = links(cloud, tok, rid)
    assert set(v) == {"expires_in", "report", "evidence", "badge", "findings", "graph", "readiness"}
    assert v["report"].startswith(f"http://testserver/r/{rid}/report.html?k=")
    cloud.cookies.clear()
    r = cloud.get(path(v["report"]))
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    csp = r.headers["content-security-policy"]
    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
    assert "frame-ancestors" in csp and r.headers["referrer-policy"] == "no-referrer"
    assert "no-store" in r.headers["cache-control"] and r.headers["x-content-type-options"] == "nosniff"
    scripts = [t for t in re.findall(r"<script[^>]*>", r.text) if 'type="application/json"' not in t]
    assert scripts and all(f'nonce="{nonce}"' in t for t in scripts)
    assert 'http-equiv="Content-Security-Policy"' in r.text
    assert "window.LANTERN_LIVE = " not in r.text       # read-only: no live actions in the cloud
    assert SOURCE_LINE not in r.text                     # structure privacy, as chosen
    ev = cloud.get(path(v["evidence"]))
    assert ev.status_code == 200 and "Made by Lantern" in ev.text and "cloud service" in ev.text
    b = cloud.get(path(v["badge"]))
    assert b.status_code == 200 and b.headers["content-type"].startswith("image/svg+xml") and "Lantern" in b.text
    f = cloud.get(path(v["findings"])).json()
    assert f["counts"]["critical"] >= 1 and isinstance(f["findings"], list)
    assert "nodes" in cloud.get(path(v["graph"])).json()


def test_links_need_a_valid_unexpired_key_for_that_run(done_run, tmp_path, clone_from):  # noqa: F811
    cloud, gw, s, tok, rid = done_run
    v = links(cloud, tok, rid)
    k = v["report"].split("k=", 1)[1]
    cloud.cookies.clear()
    assert cloud.get(f"/r/{rid}/report.html").status_code == 401
    wrong = k[:-1] + ("1" if k[-1] == "0" else "0")       # a different last digit, whatever the key ends in
    assert cloud.get(f"/r/{rid}/report.html?k={wrong}").status_code == 401
    assert cloud.get(f"/r/{rid}/report.html?k=garbage").status_code == 401
    exp, mac = k.split(".")
    assert cloud.get(f"/r/{rid}/report.html?k={int(exp) + 999}.{mac}").status_code == 401   # can't stretch the time
    # A key for one run does not open another.
    rid2 = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(gw.sign_in("github:2", "github:b"))).json()["id"]
    assert cloud.get(f"/r/{rid2}/report.html?k={k}").status_code == 401
    assert cloud.get(f"/r/{rid}/secrets.txt?k={k}").status_code == 404
    assert cloud.get(f"/r/{rid}/..%2Fcloud.db?k={k}").status_code == 404


def test_expired_link(tmp_path, clone_from):  # noqa: F811
    cloud, gw, s = make(tmp_path, public_url="http://testserver", view_minutes=0)
    tok = gw.sign_in("github:1", "github:octo")
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"]
    wait(cloud, tok, rid)
    v = links(cloud, tok, rid)
    time.sleep(1.1)
    r = cloud.get(path(v["report"]))
    assert r.status_code == 401 and "expired" in r.text


def test_only_the_owner_gets_links_and_only_for_finished_runs(done_run, monkeypatch):
    cloud, gw, s, tok, rid = done_run
    other = gw.sign_in("github:2", "github:b")
    r = cloud.post(f"/v1/runs/{rid}/view", headers=bearer(other))
    assert r.status_code == 404
    assert cloud.post(f"/v1/runs/{rid}/view").status_code == 401
    from lantern_cloud import worker as worker_mod

    def boom(link, dest, log):
        raise RuntimeError("could not clone it: not found")
    monkeypatch.setattr(worker_mod, "clone_repo", boom)
    bad = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(other)).json()["id"]
    wait(cloud, other, bad)
    assert cloud.post(f"/v1/runs/{bad}/view", headers=bearer(other)).status_code == 409


def test_cookie_opens_the_other_pages_of_the_same_run_only(done_run):
    cloud, gw, s, tok, rid = done_run
    v = links(cloud, tok, rid)
    cloud.cookies.clear()
    assert cloud.get(path(v["report"])).status_code == 200      # sets the cookie for /r/<id>/
    assert cloud.get(f"/r/{rid}/evidence.html").status_code == 200
    assert cloud.get(f"/r/{rid}/badge.svg").status_code == 200


def test_planted_result_files_never_reach_the_browser_as_written(done_run):
    """The run's folder is written by the analysis of a stranger's repository. Whatever is in it, the page is our
    template plus the data, and hostile strings in the data stay inside the escaped data block."""
    cloud, gw, s, tok, rid = done_run
    sys.path.insert(0, str(ROOT / "tools"))
    from poison_report import PAYLOAD, poison
    from lantern.report import read_bundle, render
    res = Path(s.results_dir) / rid
    data = poison(read_bundle(res / "report.html"))
    planted = render(data).replace("</body>", "<script>window.planted=1</script></body>")
    (res / "report.html").write_text(planted, encoding="utf-8", newline="\n")
    ev = json.loads((res / "evidence.json").read_text(encoding="utf-8"))
    ev["header"]["commit"] = PAYLOAD
    (res / "evidence.json").write_text(json.dumps(ev), encoding="utf-8")
    v = links(cloud, tok, rid)
    page = cloud.get(path(v["report"])).text
    assert "window.planted" not in page
    assert PAYLOAD not in page                              # only its escaped form, inside the data
    nonce = re.search(r'nonce="([^"]+)"', page).group(1)
    assert page == render(data, None, nonce)                # exactly our template + the data
    e = cloud.get(path(v["evidence"])).text
    assert PAYLOAD not in e
