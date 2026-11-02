"""Ask Lantern: a question about a project, answered by the configured model from Lantern's own facts.

Facts from tools, words from models: the model is handed the project's results (readiness, findings with their
click paths, routes, the explanations already written) and may only refer to those. It cannot create, dismiss
or re-rank a finding; it can point at one by its id. With no project selected, it answers about Lantern itself.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

SYSTEM = """You are Lantern's assistant inside the Lantern app. Lantern maps an app's code (every path from a
click to the database), finds security problems, grades readiness to ship, and writes evidence for reviewers.
Answer the person's question in plain, short language (a few sentences, bullets when listing). Rules:
- Use ONLY the FACTS given below. If the facts do not contain the answer, say so and suggest what to run in Lantern
  (Re-analyze, Explain, the Readiness tab) rather than guessing.
- Refer to a finding by its short id in square brackets, e.g. [3c86aa4fd579], exactly as given. Never invent a finding,
  a file, a function or a number.
- You cannot change anything: you cannot accept, close or re-rank findings. Say that if asked.
- Never ask the person to paste secrets or keys."""

ABOUT = """FACTS: no project is selected. Lantern's features: Projects (add a folder or GitHub link, Analyze), the
Atlas map (routes and clicks → functions → database, confidence per link: seen running / confirmed / likely /
possible), Findings (ranked critical/high/medium/low by whether a route reaches them and whether outside input is
used; "Send to…" hands one to an AI assistant), Readiness score (0–100, grade A–F, ten categories, starter files
Lantern can write), Protections to add, Evidence Report (commit-pinned, with a digest and a badge), Explain (three
lenses: technical, everyday, mapped; every phrase anchored to real code), Learn (starter apps with planted problems),
Settings (model provider; free allowance via Sign in with GitHub/Google; privacy: full or structure-only reports;
Connections: which AI assistants called Lantern through the connector `lantern mcp`). Languages: Python,
TypeScript/JavaScript, Go, Rust, Java. AI apps: paid calls marked on the map, wallet-drain check, model output
into tools, notebook secrets."""


def facts(project_dir: Path, focus: dict | None = None, limit: int = 40) -> str:
    out = project_dir / ".lantern"
    load = lambda n: _load(out / n)  # noqa: E731
    rd, sec, g, ex = load("readiness.json") or {}, load("security.json") or {}, load("graph.json") or {}, load("explanations.json") or {}
    lines = [f"FACTS for project folder {project_dir.name!r} (analysis results on disk):"]
    if rd:
        lines.append(f"Readiness: {rd.get('score')}/100, grade {rd.get('grade')}, shape {rd.get('shape')}.")
        fails = [c for c in (rd.get("checks") or []) if isinstance(c, dict) and c.get("status") in ("fail", "partial")][:12]
        if fails:
            lines.append("Readiness checks not passing: " + "; ".join(f"{c.get('title')} ({c.get('status')}: {str(c.get('why') or '')[:80]})" for c in fails))
    counts = sec.get("counts") or {}
    if counts:
        lines.append(f"Findings open: {counts.get('critical', 0)} critical, {counts.get('high', 0)} high, {counts.get('medium', 0)} medium, {counts.get('low', 0)} low; accepted {counts.get('accepted', 0)}.")
    fs = [f for f in (sec.get("findings") or []) if isinstance(f, dict) and f.get("status") != "accepted" and not f.get("in_tests")][:limit]
    for f in fs:
        path = " → ".join(_short(x) for x in (f.get("ui_path") or [])[:5])
        inp = (f.get("input") or {}).get("via") if isinstance(f.get("input"), dict) else None
        lines.append(f"- [{f.get('id')}] {f.get('rank')}: {f.get('title')} at {f.get('file')}:{f.get('line')}"
                     + (f"; reachable via {path}" if path else "; not reached from any entry point")
                     + (f"; uses {inp}" if inp else "") + (f"; fix: {str(f.get('fix') or '')[:120]}" if f.get("fix") else ""))
    ai = sec.get("ai") or {}
    if ai.get("calls"):
        lines.append("Paid/AI calls: " + "; ".join(f"{c.get('provider')} ({c.get('kind')}) in {_short(c.get('node') or '')} {c.get('file')}:{c.get('line')}" for c in ai["calls"][:12]))
    nodes = g.get("nodes") or []
    routes = [n for n in nodes if isinstance(n, dict) and (n.get("entry") or {}).get("kind") == "route"][:limit]
    if routes:
        lines.append("Routes: " + "; ".join(f"{(n['entry'] or {}).get('detail')} → {_short(n.get('qualname') or n.get('id') or '')} ({n.get('file')}:{n.get('start_line')})" for n in routes))
    st = g.get("stats") or {}
    if st:
        lines.append(f"Map: {st.get('nodes', {}).get('callable', '?')} functions, {st.get('internal_call_edges', '?')} calls between them, {st.get('entry_points', '?')} entry points, languages {', '.join((g.get('meta') or {}).get('languages') or {})}.")
    exps = ex.get("explanations") or {}
    if focus and focus.get("node") and focus["node"] in exps:
        r = exps[focus["node"]]
        l2 = (r.get("lens2") or {}).get("text") or r.get("undetermined") or ""
        lines.append(f"Selected function {_short(focus['node'])}: {l2[:600]}")
    elif exps:
        lines.append(f"{len(exps)} functions have explanations; ask about one by name to get its plain-words lens.")
    if focus and focus.get("finding"):
        lines.append(f"The person is looking at finding [{focus['finding']}].")
    text = "\n".join(lines)
    return text[:14000]


def ask(provider, question: str, project_dir: Path | None, focus: dict | None = None) -> dict:
    q = question.strip()[:2000]
    if not q:
        raise ValueError("ask a question")
    body = facts(project_dir, focus) if project_dir else ABOUT
    answer = _plain(provider.complete(SYSTEM, body + "\n\nQUESTION: " + q, max_tokens=700))
    ids = set(re.findall(r"\[([0-9a-f]{12})\]", body))
    cited = re.findall(r"\[([0-9a-f]{12})\]", answer)
    invented = sorted({c for c in cited if c not in ids})
    for c in invented:                                  # a finding id not in the facts is removed, never shown
        answer = answer.replace(f"[{c}]", "[unknown finding]")
    return {"answer": answer.strip(), "cited": sorted({c for c in cited if c in ids}), "invented": invented,
            "model": getattr(provider, "label", "model")}


def _plain(text: str) -> str:
    """Some providers are held to JSON mode (the gateway is): unwrap {"answer": "..."} or any one-string object."""
    t = text.strip()
    if t.startswith("{"):
        try:
            d = json.loads(t)
            if isinstance(d, dict):
                vals = [v for v in d.values() if isinstance(v, str)]
                if len(vals) == 1:
                    return vals[0]
                if "answer" in d and isinstance(d["answer"], str):
                    return d["answer"]
        except ValueError:
            pass
    return text


def _load(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except (OSError, ValueError):
        return None


def _short(nid: str) -> str:
    s = str(nid)
    s = s.split("::", 1)[1] if "::" in s else s.split(":", 1)[-1]
    return s[-60:]


def read_screenshot(raw: bytes, ctype: str) -> dict:
    """A screenshot dropped into Ask Lantern: read on this computer. Needs Tesseract (pytesseract) for the text;
    without it the image size is reported and the person is told what to install. The image is never sent anywhere."""
    import email
    import email.policy
    import io
    msg = email.message_from_bytes(b"Content-Type: " + ctype.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + raw,
                                   policy=email.policy.HTTP)
    data = None
    for part in msg.iter_parts():
        if part.get_filename():
            data = part.get_payload(decode=True)
            break
    if not data:
        return {"error": "no image received"}
    try:
        from PIL import Image
    except ImportError:
        return {"error": "install Pillow to read screenshots (pip install pillow)"}
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception:  # noqa: BLE001
        return {"error": "not an image Lantern can open"}
    out = {"width": img.width, "height": img.height}
    try:
        import pytesseract
        text = pytesseract.image_to_string(img)
    except ImportError:
        out["error"] = "text reading needs Tesseract (pip install pytesseract, plus the Tesseract program)"
        return out
    except Exception as e:  # noqa: BLE001
        out["error"] = f"could not read text: {str(e)[:80]}"
        return out
    lines = [ln for ln in text.splitlines() if ln.strip()]
    out.update({"lines": len(lines), "text": "\n".join(lines)[:4000]})
    return out
