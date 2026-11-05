"""Fuzz the language readers: mutate real files at random and check nothing crashes or hangs (test checklist 3.6).

    python bench/fuzz.py [--seconds 120] [--seed 1] [--out /tmp/fuzz]

Takes every source and manifest file from the sample apps in tests/fixtures, applies random mutations (delete a span,
duplicate a span, swap bytes, insert brackets/quotes/NULs/non-UTF-8 bytes, truncate, splice two files of different
languages), writes the result into a copy of its sample app, and runs the whole analysis (map, findings, readiness,
report) with a 60-second wall clock per case. A crash (exception) or a hang is a find: the mutated file and the
traceback are saved under --out/finds/ with a Python one-liner that reproduces it, and the run exits 1.

Not part of CI (random, slow); run it after changing a reader. tests/test_robustness.py holds the fixed garbled-file
cases that CI does run.
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import random
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
EXTS = {".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java", ".kt", ".swift", ".dart", ".cs", ".php", ".rb", ".c",
        ".cc", ".cpp", ".h", ".hpp", ".html", ".json", ".toml", ".yaml", ".xml", ".gradle", ".kts", ".plist", ".lock",
        ".csproj", ".txt", ".erb", ".mod", ".sum"}
NAMES = {"Gemfile", "Gemfile.lock", "CMakeLists.txt", "go.mod", "go.sum", "Cargo.lock", "composer.lock", "package-lock.json"}
JUNK = [b"(", b")", b"{", b"}", b"[", b"]", b"<", b">", b'"', b"'", b"`", b"\x00", b"\xff\xfe", b"\xc3\x28", b"\n", b";",
        b"${", b"#{", b"\\(", b"<?php", b"<script>", b"\\", b"/*", b"*/", b"//", b"#", b"@", b"$", b"=>", b"::"]


def files() -> list[tuple[Path, Path]]:
    out = []
    for app in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        for p in app.rglob("*"):
            if p.is_file() and (p.suffix in EXTS or p.name in NAMES) and "node_modules" not in p.parts and p.stat().st_size < 200_000:
                out.append((app, p))
    return out


def mutate(data: bytes, rnd: random.Random, other: bytes | None) -> bytes:
    n = len(data)
    kind = rnd.choice(["delete", "dup", "swap", "insert", "truncate", "splice", "many", "shuffle_lines", "nul_fill"])
    if n == 0:
        return rnd.choice(JUNK) * rnd.randrange(1, 50)
    a, b = sorted((rnd.randrange(n), rnd.randrange(n)))
    if kind == "delete":
        return data[:a] + data[b:]
    if kind == "dup":
        return data[:b] + data[a:b] * rnd.randrange(1, 4) + data[b:]
    if kind == "swap":
        s = bytearray(data)
        for _ in range(rnd.randrange(1, 20)):
            i, j = rnd.randrange(n), rnd.randrange(n)
            s[i], s[j] = s[j], s[i]
        return bytes(s)
    if kind == "insert":
        return data[:a] + b"".join(rnd.choice(JUNK) for _ in range(rnd.randrange(1, 30))) + data[a:]
    if kind == "truncate":
        return data[:a]
    if kind == "splice" and other:
        c = rnd.randrange(len(other) or 1)
        return data[:a] + other[c:c + rnd.randrange(1, 2000)] + data[a:]
    if kind == "shuffle_lines":
        lines = data.split(b"\n")
        rnd.shuffle(lines)
        return b"\n".join(lines)
    if kind == "nul_fill":
        return data[:a] + bytes(rnd.randrange(256) for _ in range(b - a)) + data[b:]
    out = data
    for _ in range(rnd.randrange(2, 6)):
        out = mutate(out, rnd, other)
    return out


def analyze(repo: str, out: str) -> None:
    from lantern.engine import build_graph
    from lantern.readiness import assess
    from lantern.report import write_report
    from lantern.security import scan
    Path(out).mkdir(parents=True, exist_ok=True)
    g = build_graph(repo)
    sec = scan(g, offline=True)
    rd = assess(g, sec)
    write_report(Path(out), g, sec, {}, "full", readiness=rd)


def _child(repo: str, out: str, q) -> None:
    try:
        analyze(repo, out)
        q.put(None)
    except Exception:  # noqa: BLE001 - this is what we are hunting
        q.put(traceback.format_exc())


def run_case(repo: Path, out: Path, timeout: int) -> str | None:
    q: mp.Queue = mp.Queue()
    p = mp.Process(target=_child, args=(str(repo), str(out), q))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.kill()
        p.join()
        return f"HANG: no result after {timeout} s"
    if p.exitcode not in (0, None):
        return f"CRASH: the process died with exit code {p.exitcode} (signal {-p.exitcode if p.exitcode < 0 else '-'})"
    return q.get() if not q.empty() else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=120)
    ap.add_argument("--seed", type=int, default=int(time.time()))
    ap.add_argument("--timeout", type=int, default=60, help="wall clock per case")
    ap.add_argument("--out", default=str(Path(tempfile.gettempdir()) / "lantern-fuzz"))
    a = ap.parse_args(argv)
    rnd = random.Random(a.seed)
    out = Path(a.out)
    finds = out / "finds"
    finds.mkdir(parents=True, exist_ok=True)
    pool = files()
    print(f"seed {a.seed}: {len(pool)} files from {len({app for app, _ in pool})} sample apps, {a.seconds} s", flush=True)
    end = time.monotonic() + a.seconds
    cases = found = 0
    while time.monotonic() < end:
        app, target = rnd.choice(pool)
        other = rnd.choice(pool)[1].read_bytes() if rnd.random() < 0.3 else None
        mutated = mutate(target.read_bytes(), rnd, other)
        work = Path(tempfile.mkdtemp(prefix="case-", dir=out))
        repo = work / app.name
        shutil.copytree(app, repo, ignore=shutil.ignore_patterns("node_modules", ".lantern"))
        rel = target.relative_to(app)
        (repo / rel).write_bytes(mutated)
        err = run_case(repo, work / "out", a.timeout)
        cases += 1
        if err:
            found += 1
            keep = finds / f"{cases:04d}-{app.name}-{rel.name}"
            keep.mkdir()
            (keep / rel.name).write_bytes(mutated)
            (keep / "traceback.txt").write_text(err, encoding="utf-8")
            (keep / "reproduce.json").write_text(json.dumps({"app": app.name, "file": rel.as_posix(), "seed": a.seed, "case": cases,
                                                            "how": f"copy tests/fixtures/{app.name}, replace {rel.as_posix()} with "
                                                                   f"{rel.name} from this folder, run `lantern analyze` on it"},
                                                           indent=1), encoding="utf-8")
            print(f"FIND #{found} case {cases}: {app.name}/{rel.as_posix()}: {err.strip().splitlines()[-1]}", flush=True)
        shutil.rmtree(work, ignore_errors=True)
        if cases % 25 == 0:
            print(f"  {cases} cases, {found} finds", flush=True)
    print(f"done: {cases} cases, {found} finds" + (f" (see {finds})" if found else ""))
    return 1 if found else 0


if __name__ == "__main__":
    mp.set_start_method("spawn" if sys.platform != "linux" else "fork")
    sys.exit(main())
