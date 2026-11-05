"""Ask the live services for their health page and fail when one is down, slow, or running an old engine.

    python tools/uptime.py [--cloud URL] [--gateway URL] [--expect-engine 0.10.0] [--slow-s 5] [--summary PATH]

Used by .github/workflows/uptime.yml every 30 minutes (a failed run is the alert: GitHub emails the owner) and by hand
after a deploy. Each service must answer /v1/health with 200 and {"ok": true} within --slow-s seconds. With
--expect-engine, lantern-cloud's "engine" (the Lantern version inside its image) must not be older than that version
(the latest release): when it is, the live service is behind and needs a redeploy (docs/deploy.md).
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
