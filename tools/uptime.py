"""Ask the live services for their health page and fail when one is down, slow, or running an old engine.

    python tools/uptime.py [--cloud URL] [--gateway URL] [--expect-engine 0.10.0] [--slow-s 5] [--summary PATH]

Used by .github/workflows/uptime.yml every 30 minutes (a failed run is the alert: GitHub emails the owner) and by hand
after a deploy. Each service must answer /v1/health with 200 and {"ok": true} within --slow-s seconds. With
--expect-engine, lantern-cloud's "engine" (the Lantern version inside its image) must not be older than that version
(the latest release): when it is, the live service is behind and needs a redeploy (docs/deploy.md).
lantern-cloud's health also says one word about its own clean-up: "behind" means that files of deleted runs have been
waiting to be removed for more than a day, or that runs past the retention time are still there. That fails this check
too, so the owner gets the email; the counts and reasons are in the service's /v1/admin/stats under "cleanup"
(docs/deploy.md). A service that says nothing about clean-up (a version from before 2026-11-10) passes.
It also says whether each check's steps run as a user of their own who could read none of the service's own files
when last asked ("steps", 2026-11-18; cloud/lantern_cloud/apart.py): "open" (that user could, and the service starts
no check), "shared" (the service is not root, and cannot give a check a user of its own) and any word but "apart" and
"unchecked" (said in the seconds after a start, before the first proof) fail this check. A service that says nothing
about it (a version from before that day) passes.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def health(url: str, timeout: float) -> tuple[dict | None, float, str]:
    t = time.monotonic()
    try:
        with urllib.request.urlopen(f"{url.rstrip('/')}/v1/health", timeout=timeout) as r:  # nosec B310: fixed https URLs
            body = json.loads(r.read())
            return body, time.monotonic() - t, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return None, time.monotonic() - t, f"HTTP {e.code}"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        return None, time.monotonic() - t, f"{type(e).__name__}: {str(e)[:120]}"


def vtuple(v: str) -> tuple[int, ...]:
    out = []
    for part in v.strip().lstrip("v").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cloud")
    ap.add_argument("--gateway")
    ap.add_argument("--expect-engine", default="", help="the latest released Lantern version; cloud's engine must not be older")
    ap.add_argument("--slow-s", type=float, default=5.0)
    ap.add_argument("--summary")
    a = ap.parse_args(argv)
    rows, bad = [], []
    for name, url in (("lantern-cloud", a.cloud), ("gateway", a.gateway)):
        if not url:
            continue
        body, dt, how = health(url, a.slow_s * 3)
        ok = bool(body and body.get("ok") is True)
        slow = dt > a.slow_s
        what = f"{how}, {dt:.1f} s"
        if body:
            what += f", version {body.get('version')}" + (f", engine {body.get('engine')}" if body.get("engine") else "") \
                    + (f", model {body.get('model')}" if body.get("model") else "")
        status = "ok" if ok and not slow else ("SLOW" if ok else "DOWN")
        rows.append((name, url, status, what))
        if status != "ok":
            bad.append(f"{name} is {status}: {what}")
        if name == "lantern-cloud" and ok and a.expect_engine:
            live = str(body.get("engine") or "")
            if vtuple(live) < vtuple(a.expect_engine):
                rows.append(("lantern-cloud engine", url, "BEHIND", f"live {live}, latest release {a.expect_engine}: redeploy (docs/deploy.md)"))
                bad.append(f"lantern-cloud runs engine {live}, the latest release is {a.expect_engine}: redeploy")
        if name == "lantern-cloud" and ok and body.get("cleanup") not in (None, "ok"):
            word = str(body.get("cleanup"))[:40]
            if word == "behind":
                why = ("files that should be gone have been waiting to be removed for more than a day; "
                       "the counts and reasons are in /v1/admin/stats under \"cleanup\" (docs/deploy.md)")
            else:
                why = f"the service could not say whether its clean-up is up to date (it said {word!r}); look at its logs"
            rows.append(("lantern-cloud clean-up", url, "OWED" if word == "behind" else "UNKNOWN", why))
            bad.append(f"lantern-cloud clean-up: {why}")
        if name == "lantern-cloud" and ok and body.get("steps") not in (None, "apart", "unchecked"):
            word = str(body.get("steps"))[:40]
            why = {"open": "a check's user could read what is the service's own when it was last asked, so the service "
                           "starts no check until that is put right (docs/deploy.md)",
                   "shared": "the service is not root, so it cannot run a check's steps as a user of their own, and "
                             "the website starts no check (docs/deploy.md)"}.get(
                word, f"the service could not say whether its checks are kept apart (it said {word!r}); look at its logs")
            rows.append(("lantern-cloud checks kept apart", url, word.upper() if word in ("open", "shared") else "UNKNOWN",
                         why))
            bad.append(f"lantern-cloud checks kept apart: {why}")
        if name == "lantern-cloud" and ok and body.get("service_user") not in (None, "own"):
            # None: a service from before the field was written (it began with the switcher, 2026-11-20)
            word = str(body.get("service_user"))[:40]
            why = ("the website's service runs as root: only the small part that starts each check's steps (its "
                   "switcher) should, and the service as an ordinary user of its own (docs/deploy.md)" if word == "root"
                   else f"the service could not say which user it runs as (it said {word!r}); look at its logs")
            rows.append(("lantern-cloud service user", url, "ROOT" if word == "root" else "UNKNOWN", why))
            bad.append(f"lantern-cloud service user: {why}")
    md = "| service | url | status | detail |\n|---|---|---|---|\n" + "\n".join(f"| {n} | {u} | {s} | {w} |" for n, u, s, w in rows)
    print(md)
    if a.summary:
        with open(a.summary, "a", encoding="utf-8") as f:
            f.write("## Uptime\n\n" + md + "\n\n")
    for b in bad:
        print("FAIL " + b, file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
