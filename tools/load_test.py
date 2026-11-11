"""A small load test of the cloud website (test checklist 4.4): many readers at once, no errors, answers stay quick.

    python tools/cloud_site_demo.py --port 8872 --token-file /tmp/tok &      # the website with sample runs, no worker
    python tools/load_test.py http://127.0.0.1:8872 /tmp/tok [--readers 50] [--seconds 20] [--p95-ms 1500]

`readers` threads each loop over what a visitor does: open the front page, ask /v1/health, list their runs, read each
run, open the finished run's report through a view link, and read the shared assets, for `seconds`. Every answer's
status and time are recorded. The test fails (exit 1) when any answer is a 5xx or a connection error, or when the 95th
percentile is slower than --p95-ms. One line of JSON with the numbers goes to stdout for the step summary.

It only runs against a website on this computer (the demo above): any other address is refused before anything is
sent, so it can never be pointed at the live service by mistake.

This is readers only: starting runs needs the worker and a clone, and the daily caps (429 with a sentence) are covered by
tests/test_cloud_runs.py. It runs on one machine against one process, so it says "the single-machine website copes with
N people reading at once", not what the Fly machine does under the public internet.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "netguard"))
import lantern_netguard as netguard  # noqa: E402  (tools/netguard: every benchmark starts isolated)


def get(url: str, headers: dict | None = None, timeout: float = 30) -> tuple[int, float, int]:
    t = time.monotonic()
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310: local test server
            body = r.read()
            return r.status, time.monotonic() - t, len(body)
    except urllib.error.HTTPError as e:
        return e.code, time.monotonic() - t, 0
    except (urllib.error.URLError, OSError, TimeoutError):
        return 0, time.monotonic() - t, 0


def post(url: str, headers: dict, body: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=json.dumps(body or {}).encode(), method="POST",
                                 headers={"content-type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:  # nosec B310: local test server
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("token_file")
    ap.add_argument("--readers", type=int, default=50)
    ap.add_argument("--seconds", type=int, default=20)
    ap.add_argument("--p95-ms", type=int, default=1500)
    a = ap.parse_args(argv)
    base = a.base.rstrip("/")
    host = urllib.parse.urlsplit(base).hostname or ""
    if not netguard.is_local(host):
        print(f"the load test only runs against a website on this computer (tools/cloud_site_demo.py). {host or base} is "
              "somewhere else, and this is never pointed at the live service. Nothing was sent.", file=sys.stderr)
        return 2
    guard = netguard.begin()                      # isolated (tools/netguard): nothing but this computer can be reached
    tok = open(a.token_file, encoding="utf-8").read().strip()
    auth = {"authorization": f"Bearer {tok}", "X-Lantern-Site": "1"}
    st, runs = 200, []
    code, _, _ = get(f"{base}/v1/health")
    if code != 200:
        print(f"the website is not answering at {base} (health {code})", file=sys.stderr)
        netguard.end(guard)
        return 2
    req = urllib.request.Request(f"{base}/v1/runs", headers=auth)
    with urllib.request.urlopen(req, timeout=30) as r:  # nosec B310
        runs = json.loads(r.read())["runs"]
    done = [r for r in runs if r["status"] == "done"]
    pages: list[tuple[str, dict]] = [(f"{base}/", {}), (f"{base}/v1/health", {}), (f"{base}/v1/runs", auth), (f"{base}/v1/me", auth)]
    pages += [(f"{base}/v1/runs/{r['id']}", auth) for r in runs]
    if done:
        st, view = post(f"{base}/v1/runs/{done[0]['id']}/view", auth)
        for key in ("report", "evidence", "badge", "findings"):
            link = view.get(key) if isinstance(view, dict) else None
            if link:
                pages.append((link if link.startswith("http") else base + link, auth))
    results: list[tuple[str, int, float]] = []
    lock = threading.Lock()
    stop = time.monotonic() + a.seconds

    def reader(i: int) -> None:
        n = i
        local = []
        while time.monotonic() < stop:
            url, headers = pages[n % len(pages)]
            n += 1
            code, dt, _ = get(url, headers)
            local.append((url.replace(base, ""), code, dt))
        with lock:
            results.extend(local)

    threads = [threading.Thread(target=reader, args=(i,), daemon=True) for i in range(a.readers)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(a.seconds + 90)
    elapsed = time.monotonic() - t0
    times = sorted(dt for _, _, dt in results)
    bad = [(u, c) for u, c, _ in results if c == 0 or c >= 500]
    by_code: dict[str, int] = {}
    for _, c, _ in results:
        by_code[str(c)] = by_code.get(str(c), 0) + 1
    p50 = statistics.median(times) * 1000 if times else None
    p95 = times[int(len(times) * 0.95) - 1] * 1000 if len(times) >= 20 else (times[-1] * 1000 if times else None)
    slowest: dict[str, float] = {}
    for u, _, dt in results:
        slowest[u] = max(slowest.get(u, 0), dt)
    out = {"readers": a.readers, "seconds": round(elapsed, 1), "requests": len(results),
           "per_second": round(len(results) / elapsed, 1) if elapsed else None, "p50_ms": round(p50) if p50 else None,
           "p95_ms": round(p95) if p95 else None, "max_ms": round(times[-1] * 1000) if times else None,
           "status_counts": by_code, "errors": len(bad), "pages": len(pages), "runs_seen": len(runs),
           "slowest_pages_ms": {u: round(v * 1000) for u, v in sorted(slowest.items(), key=lambda x: -x[1])[:5]}}
    print(json.dumps(out))
    ok = not bad and p95 is not None and p95 <= a.p95_ms and len(results) > 0
    if not ok:
        print(f"LOAD TEST FAILED: {len(bad)} errors, p95 {p95 and round(p95)} ms (limit {a.p95_ms}); "
              f"first errors: {bad[:5]}", file=sys.stderr)
    refused = netguard.end(guard)
    return 0 if ok and not refused else 1


if __name__ == "__main__":
    sys.exit(main())
