"""Exporters: Lantern's findings in formats other tools read. The third plugin seam.

An exporter only reads `security.json` and `evidence.json`; it never changes a finding. SARIF 2.1.0 is the
one built in: GitHub code scanning, VS Code's SARIF viewer, and most security dashboards import it.
`lantern export PATH --sarif findings.sarif`.
"""

from __future__ import annotations

from pathlib import Path

from . import __version__

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"


def sarif(sec: dict, repo: Path | None = None) -> dict:
    findings = [f for f in sec.get("findings", []) if isinstance(f, dict)]
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rid = f"{f.get('tool')}/{f.get('rule')}"
        rules.setdefault(rid, {
            "id": rid, "name": str(f.get("rule")),
            "shortDescription": {"text": str(f.get("title") or f.get("rule"))},
            "properties": {"tool": f.get("tool"), "cwe": f.get("cwe"),
                           "heuristic": f.get("tool_confidence") == "LOW", "tags": ["security"]}})
        msg = str(f.get("title") or "")
        path = f.get("ui_path") or (f.get("reachable") or {}).get("path")
        if path:
            msg += " Reachable from an entry point: " + " -> ".join(_short(p) for p in path) + "."
        else:
            msg += " Not reachable from any detected entry point."
        if f.get("more_info") and not str(f["more_info"]).startswith("http"):
            msg += " " + str(f["more_info"])
        r = {"ruleId": rid, "level": SARIF_LEVEL.get(f.get("rank"), "warning"), "message": {"text": msg},
             "partialFingerprints": {"lanternFindingId/v1": str(f.get("id"))},
             "properties": {"rank": f.get("rank"), "status": f.get("status"), "in_tests": bool(f.get("in_tests")),
                            "uses_outside_input": (f.get("input") or {}).get("via") if isinstance(f.get("input"), dict) else None}}
        if f.get("file"):
            region = {"startLine": int(f["line"])} if f.get("line") else {}
            if f.get("snippet"):
                region["snippet"] = {"text": str(f["snippet"])[:300]}
            r["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": str(f["file"]), "uriBaseId": "%SRCROOT%"},
                                                    **({"region": region} if region else {})}}]
        if f.get("status") == "accepted":
            r["suppressions"] = [{"kind": "external", "status": "accepted",
                                  "justification": str((f.get("accepted") or {}).get("reason") or "")}]
        results.append(r)
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Lantern", "version": __version__, "informationUri": "https://github.com/LittleHenderson/Lantern",
                            "rules": list(rules.values())}},
        "originalUriBaseIds": {"%SRCROOT%": {"uri": (repo.resolve().as_uri() + "/") if repo else "file:///"}},
        "results": results,
        "properties": {"counts": sec.get("counts"), "scanners": [t.get("tool") for t in sec.get("tools", [])]}}]}


def _short(nid: str) -> str:
    return str(nid).split(":", 1)[-1]
