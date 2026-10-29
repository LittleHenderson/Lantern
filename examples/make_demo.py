"""Build the demo report for the `shop` fixture without any API key.

The explanations in shop_demo_explanations.json were written by hand in the format a model must
produce. They go through the same validator as real model output, so the demo also shows what
validation accepts.

    python examples/make_demo.py OUT_DIR
"""

import json
import re
import shutil
import sys
from pathlib import Path

from lantern.explain import run, select_nodes
from lantern.providers import FixtureProvider
from lantern.python_frontend import build_graph
from lantern.report import write_report
from lantern.security import scan
from lantern.trace import merge_trace, run_trace

HERE = Path(__file__).parent
FIX = HERE.parent / "tests" / "fixtures" / "shop"


def main(out: Path):
    repo = out / "shop"
    shutil.rmtree(repo, ignore_errors=True)
    shutil.copytree(FIX, repo)
    demo = json.loads((HERE / "shop_demo_explanations.json").read_text())
    g = build_graph(repo)
    merge_trace(g, run_trace(repo, ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]))
    sec = scan(g)

    def respond(system, user):
        unit = re.search(r"^UNIT: (\S+)", user, re.M).group(1)
        return json.dumps(demo["units"][unit])

    provider = FixtureProvider(respond, model="hand-written-demo")
    nids = [f"py:{q}" for q in demo["units"]]
    nids = [n for n in select_nodes(g) if n in nids]
    res = run(g, provider, sec["findings"], out / "cache", nids, metaphor=demo["metaphor"]["world"])
    bad = {k: v["validation_errors"] for k, v in res["explanations"].items() if not v["validated"]}
    if bad:
        raise SystemExit(f"demo explanations failed validation: {json.dumps(bad, indent=1)}")
    res["metaphor"] = demo["metaphor"]
    path = write_report(out, g, sec, res)
    print(path)


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "demo-out").resolve())
