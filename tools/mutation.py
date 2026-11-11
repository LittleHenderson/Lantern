"""Mutation testing: make small deliberate mistakes in one module and check that some test fails each time
(test checklist, "Do the tests catch bugs?").

    python tools/mutation.py lantern/lanes.py tests/test_lanes.py [tests/other_test.py …] [--max 40] [--seed 1]
                             [--timeout 300] [--summary PATH] [--min-score 0.0]

A copy of the repository is made in a temporary folder (so the working tree and anything else running from it are
untouched), one mutation at a time is written into the module there, and the named test files run against the copy
(the copy is first on PYTHONPATH, ahead of the editable install). A mutant is **killed** when a test fails or errors
within the time limit and **survived** when every test still passes; a survivor is a mistake the tests would let
through. Mutations are the classic set: a comparison flipped (`==` → `!=`, `<` → `<=`, `>` → `>=` and back), a boolean
constant inverted, `and` ↔ `or`, a `not` removed, and a number nudged by one. `--max` caps how many run (a random
sample with `--seed`, so a run can be repeated). The score is killed / run. Exit 1 when the score is under
--min-score. bench/mutation_results.md keeps the last run; tests/test_mutation.py proves the tool on a tiny module.
"""
from __future__ import annotations

import argparse
import ast
import copy
import random
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "netguard"))
import lantern_netguard as netguard  # noqa: E402  (tools/netguard: every benchmark starts isolated)
IGNORE = shutil.ignore_patterns(".git", "node_modules", "__pycache__", ".lantern", ".pytest_cache", "*.pyc", ".ruff_cache",
                                "dist", "build", "htmlcov", ".coverage*")

FLIP_CMP = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt,
            ast.Is: ast.IsNot, ast.IsNot: ast.Is, ast.In: ast.NotIn, ast.NotIn: ast.In}


def mutants(source: str) -> list[tuple[str, int, str]]:
    """Every single-change variant of `source`: (description, line, mutated source)."""
    tree = ast.parse(source)
    out: list[tuple[str, int, str]] = []
    nodes = list(ast.walk(tree))
    for i, node in enumerate(nodes):
        changes: list[tuple[str, callable]] = []
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in FLIP_CMP:
            new_op = FLIP_CMP[type(node.ops[0])]
            changes.append((f"{type(node.ops[0]).__name__} -> {new_op.__name__}", lambda n, op=new_op: setattr(n, "ops", [op()])))
        elif isinstance(node, ast.Constant) and isinstance(node.value, bool):
            changes.append((f"{node.value} -> {not node.value}", lambda n: setattr(n, "value", not n.value)))
        elif isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool) and 0 <= node.value < 1000:
            changes.append((f"{node.value} -> {node.value + 1}", lambda n: setattr(n, "value", n.value + 1)))
        elif isinstance(node, ast.BoolOp):
            new = ast.Or if isinstance(node.op, ast.And) else ast.And
            changes.append((f"{type(node.op).__name__} -> {new.__name__}", lambda n, op=new: setattr(n, "op", op())))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            changes.append(("not x -> x", None))
        for desc, apply in changes:
            t2 = copy.deepcopy(tree)
            target = list(ast.walk(t2))[i]
            if apply is None:        # `not x` -> `x`: replace the node in its parent
                for parent in ast.walk(t2):
                    for name, val in ast.iter_fields(parent):
                        if val is target:
                            setattr(parent, name, target.operand)
                        elif isinstance(val, list):
                            for k, item in enumerate(val):
                                if item is target:
                                    val[k] = target.operand
            else:
                apply(target)
            try:
                out.append((desc, getattr(node, "lineno", 0), ast.unparse(t2)))
            except Exception:       # pragma: no cover - a shape unparse refuses
                continue
    return out


def run_tests(copy_root: Path, tests: list[str], timeout: int) -> str:
    env = {"PYTHONPATH": str(copy_root), "PATH": "/usr/bin:/bin:/usr/local/bin", "LANTERN_OFFLINE": "1",
           "HOME": str(copy_root), "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *tests],
                              cwd=str(copy_root), env=env, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return "killed (timeout)"
    return "survived" if proc.returncode == 0 else "killed"


def run(module: str, tests: list[str], max_mutants: int | None, seed: int, timeout: int, log=print) -> dict:
    src_path = ROOT / module
    source = src_path.read_text(encoding="utf-8")
    all_mutants = mutants(source)
    picked = all_mutants
    if max_mutants and len(all_mutants) > max_mutants:
        picked = sorted(random.Random(seed).sample(all_mutants, max_mutants), key=lambda m: m[1])
    tmp = Path(tempfile.mkdtemp(prefix="lantern-mut-"))
    copy_root = tmp / "repo"
    rows = []
    try:
        shutil.copytree(ROOT, copy_root, ignore=IGNORE, symlinks=True)
        clean = run_tests(copy_root, tests, timeout)
        if clean != "survived":
            raise SystemExit(f"the tests do not pass on the unchanged module ({clean}); fix that first")
        target = copy_root / module
        for k, (desc, line, text) in enumerate(picked, 1):
            target.write_text(text, encoding="utf-8")
            t = time.monotonic()
            verdict = run_tests(copy_root, tests, timeout)
            rows.append({"line": line, "change": desc, "verdict": verdict, "seconds": round(time.monotonic() - t, 1)})
            log(f"[{k}/{len(picked)}] line {line}: {desc} -> {verdict}")
        target.write_text(source, encoding="utf-8")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    killed = sum(1 for r in rows if r["verdict"].startswith("killed"))
    return {"module": module, "tests": tests, "possible": len(all_mutants), "run": len(rows), "killed": killed,
            "survived": len(rows) - killed, "score": round(killed / len(rows), 3) if rows else None, "rows": rows}


def table(res: dict) -> str:
    lines = [f"**`{res['module']}`** against `{'`, `'.join(res['tests'])}`: {res['killed']} of {res['run']} mutants killed "
             f"({res['score']:.0%}; {res['possible']} possible)", "", "| Line | Change | Result |", "|---:|---|---|"]
    for r in res["rows"]:
        if not r["verdict"].startswith("killed"):
            lines.append(f"| {r['line']} | `{r['change']}` | **survived** |")
    if res["survived"] == 0:
        lines.append("| – | every mutant | killed |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("module", help="repo-relative path, e.g. lantern/lanes.py")
    ap.add_argument("tests", nargs="+", help="test files to run against each mutant")
    ap.add_argument("--max", type=int, default=40)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--summary")
    ap.add_argument("--min-score", type=float, default=0.0)
    a = ap.parse_args(argv)
    guard = netguard.begin()                      # isolated (tools/netguard); the tests it runs isolate themselves too
    res = run(a.module, a.tests, a.max, a.seed, a.timeout)
    md = table(res)
    print("\n" + md)
    if a.summary:
        with open(a.summary, "a", encoding="utf-8") as fh:
            fh.write(md + "\n\n")
    refused = netguard.end(guard)
    return 0 if res["score"] is not None and res["score"] >= a.min_score and not refused else 1


if __name__ == "__main__":
    sys.exit(main())
