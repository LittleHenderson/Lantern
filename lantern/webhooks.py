"""A webhook that changes stored data without checking who sent the message (roadmap of 2026-11-14, stage 5).

A payment or message provider calls a route of the app when something happened: a payment went through, an account
was removed. The provider cannot sign in; what stands in a login's place is its signature on the message, checked with
a secret only the two share. A route that writes stored data on such a message and checks nothing does it for anybody
who sends the same words: `LW-UNSIGNED-WEBHOOK` (a heuristic, `tool_confidence: LOW`, medium).

What is read, and from where:

* **What the route writes** comes from the flow step (`flow.Result.changes`): every place the route, or a function it
  calls, writes stored data, each with whether only a message its provider signed gets there. Where every such place
  stands behind the provider's own check (`flow.Engine.sender_checked`: Stripe, svix, Standard Webhooks), this rule
  says nothing.
* **Whether the route is a provider's to call** is read from its address (a word `webhook` or `hook`) or from its own
  lines (a header or an event name a provider sends, `PROVIDER_SENDS`); it has to take a POST, and it must not show
  a login (a route somebody signs in for is the app's own people's).
* **What stands in the way** otherwise, in three answers (`webhook.check` on the finding):
  `late`: the check is there and data was written before it; `lets-on`: the provider's own check is called and a
  message that fails it, or never gets to it, still goes on (its failure is caught and passed over, it is made for
  some requests only, its secret is missing or empty: `flow.Result.tries`); `none`: nothing was found.
  Before it says `none` the rule looks, in the route's lines, in what runs before it and in the project's functions
  it calls (`DEPTH` calls deep), for a check Lantern cannot follow as code but can see is written: a comparison that
  takes the same time whatever the text (`COMPARES`), a call named for checking a signature, a webhook or a sender
  (`CHECK_CALL`), a value compared with a secret setting (`SECRET_SETTING`) or with something named like a signature
  or a secret (`NAMED`). Any of these keeps the rule quiet: it then cannot tell, and says nothing.

So it misses a check that is written and whose answer is thrown away (a yes-or-no check called and never asked),
and it does not know a provider whose check is made by a gateway in front of the app. It reads; it runs nothing.
"""
from __future__ import annotations

import re

RULE = "LW-UNSIGNED-WEBHOOK"
DEPTH = 2               # how many calls below the route a written check is looked for
MOST_NODES = 40         # ... in at most this many functions
MOST_SAID = 6           # places of a write named on one finding
MOST_LINE = 2000        # characters of one line that are read

# The verbs a provider sends its messages with.
RECEIVES = {"POST", "ANY"}
# A word of the address that says the route is one a provider calls.
PATH_WORD = re.compile(r"(?:^|[/_.\-])((?:web)?hooks?)(?:[/_.\-]|$)", re.I)
# What a provider sends and nobody else: the header its signature comes in, the header that names the event, the
# names of its events. Read in the route's own lines, texts included (`_` and `-` are one: Django writes
# `HTTP_STRIPE_SIGNATURE`).
PROVIDER_SENDS = re.compile(
    r"stripe[-_]signature|x[-_]hub[-_]signature|x[-_]github[-_](?:event|delivery)|svix[-_](?:id|signature|timestamp)|"
    r"webhook[-_](?:id|signature|timestamp)|x[-_]twilio[-_]signature|x[-_]shopify[-_](?:hmac[-_]sha256|topic)|"
    r"x[-_]slack[-_]signature|x[-_]signature[-_]ed25519|paddle[-_]signature|x[-_]razorpay[-_]signature|"
    r"x[-_]paystack[-_]signature|x[-_]square[-_]hmacsha256[-_]signature|linear[-_]signature|"
    r"checkout\.session\.completed|invoice\.(?:paid|payment[-_]succeeded|payment[-_]failed)|"
    r"customer\.subscription\.(?:created|updated|deleted)|payment[-_]intent\.succeeded", re.I)

# --- a check that is written, where the flow step shows none (read with texts and remarks blanked)
# a comparison that takes the same time whatever the two texts are: nobody writes one for anything but a secret
COMPARES = re.compile(r"\b(?:timingSafeEqual|compare_digest|secure_compare|safe_compare|safeCompare|safe_str_cmp|"
                      r"constant_time_compare|constantTimeEqual|constantTimeCompare|ConstantTimeCompare|tsscmp|"
                      r"hash_equals)\s*\(")
# a call named for checking a signature, a webhook, a sender; a provider's own yes-or-no check; a library's `verify`
CHECK_CALL = re.compile(
    r"(?i)\b\w*(?:verif|validat|authenticat|is_?valid|check)\w*(?:sign|hmac|webhook|hook|sender|secret|header)\w*\s*\(|"
    r"\b(?:validateRequest|validateRequestWithBody|validateExpressRequest|validateIncomingRequest|verifyKey|"
    r"validate_request|verify_key)\s*\(|"
    r"\.(?:verify|verifyAsync|verifyAndReceive|verify_header|verifyHeader|unmarshal|unwrap)\s*\(")
COMPARISON = re.compile(r"[!=]==?")
# ... a value compared on a line that reads a secret setting (the setting's name may stand in a text)
SECRET_SETTING = re.compile(r"(?i)(?:process\.env|import\.meta\.env|Deno\.env|os\.environ|getenv|settings|config|env|"
                            r"secrets)\W{1,8}\w*(?:secret|token|key|signature|password)\w*")
# ... or with something named like a signature or a secret, on either side, and not with nothing
# (`sig`, `sigHeader`, `expectedSig`, and not the same three letters inside `assignee`, `design` or `signup`)
_NAME = r"[\w$.]*(?:secret|signature|sig(?-i:(?![a-z]))|hmac|digest|expected|token|api_?key)[\w$]*"
_NOTHING = r"(?!(?:null|undefined|None|true|false|True|False)\b)"
NAMED = re.compile(rf"(?i)\b{_NAME}\s*[!=]==?\s*{_NOTHING}[A-Za-z_$]|"
                   rf"\b{_NOTHING}[A-Za-z_$][\w$.\[\]()]*\s*[!=]==?\s*{_NAME}\b")

WHY_NOT = {
    "secret": "it is made with a secret that is missing or is empty text, which anybody can sign with",
    "later": "its answer comes later and is not waited for, so the code goes on before the check has failed",
    "some": "a message that fails it, or never gets to it, still goes on: its failure is caught and passed over, "
            "or it is made for some requests only",
}
TITLE = {
    "none": "{route} changes stored data when a message arrives, and nothing checks who sent the message",
    "lets-on": "{route} changes stored data when a message arrives, and its check of who sent the message "
               "does not stop one that fails",
    "late": "{route} changes stored data before it checks who sent the message",
}


def receiver(path: str, own: list[str]) -> str | None:
    """Why a route is taken for one a provider calls, in words for the finding; None when nothing says so."""
    m = PATH_WORD.search(path or "")
    if m:
        return f"its address has the word `{m.group(1).lower()}`"
    for line in own:
        m = PROVIDER_SENDS.search(line[:MOST_LINE])
        if m:
            return f"its code reads `{m.group(0)}`, which a provider sends"
    return None


def _code(lines: list[str], js: bool) -> list[str]:
    from .websec import code_only
    return code_only("\n".join(x[:MOST_LINE] for x in lines), js=js).split("\n")


def written_check(lines: list[str], js: bool) -> int | None:
    """The first of `lines` (counted from 0) on which a check of the sender is written, in any of the forms this
    rule cannot follow as code; None when there is none."""
    code = _code(lines, js)
    for i, (raw, c) in enumerate(zip(lines, code)):
        if COMPARES.search(c) or CHECK_CALL.search(c):
            return i
        if COMPARISON.search(c) and (SECRET_SETTING.search(raw[:MOST_LINE]) or NAMED.search(c)):
            return i
    return None


def _below(g, n, adj: dict, entry: dict) -> list:
    """The project's functions that run before the route (its middleware) or that it calls, `DEPTH` calls deep."""
    seen, out = {n.id}, []
    first = [x for x in (*(entry.get("middleware") or ()), *((u or {}).get("id") for u in entry.get("use") or ()))
             if isinstance(x, str)]
    level = [*first, *adj.get(n.id, ())]
    for _depth in range(DEPTH):
        nxt = []
        for nid in level:
            m = g.nodes.get(nid)
            if nid in seen or m is None or not m.file or not m.start_line or len(out) >= MOST_NODES:
                continue
            seen.add(nid)
            out.append(m)
            nxt.extend(adj.get(nid, ()))
        level = nxt
    return out


def unsigned(g, res, lines_for) -> tuple[list[dict], int]:
    """The findings, and how many routes were taken for a provider's webhook that writes stored data (the rule's own
    denominator, for the scanner's record)."""
    from .websec import _finding, call_adjacency, login_check
    out: list[dict] = []
    looked = 0
    if lines_for is None or not getattr(res, "changes", None):
        return out, looked
    adj = None
    for node, c in sorted(res.changes.items()):
        n = g.nodes.get(node)
        if n is None or node in res.logins:
            continue
        verb, _, path = str(c["detail"]).partition(" ")
        if not {v.upper() for v in verb.split("/")} & RECEIVES:
            continue
        src = lines_for(n.file) or []
        start = n.start_line or c["line"]
        end = max(n.end_line or start, start)
        own = src[start - 1:end]
        why = receiver(path, own)
        if why is None:
            continue
        if adj is None:
            adj = call_adjacency(g)
        sign = login_check(g, n, adj, "\n".join(src) if src else None)
        if sign and sign[0] == "strong":
            continue            # somebody signs in for it: a route of the app's own people, not a provider's
        looked += 1
        open_ = [(f, ln) for f, ln, ok in c["wrote"] if not ok]
        if not open_:
            continue            # every write stands behind the provider's own check
        entry = n.entry if isinstance(n.entry, dict) else {}
        js = not n.file.endswith((".py", ".rb"))
        at = at_file = None
        if node in res.senders:
            check, at = "late", res.senders[node]       # the check holds, and these writes came before it
            said = f"The check of who sent the message stands on line {at}, after data was already written."
        else:
            below = _below(g, n, adj, entry)
            spans = [(n.file, start, end)] + [(m.file, m.start_line, max(m.end_line or m.start_line, m.start_line))
                                              for m in below]
            tries = sorted((f, ln, w) for (f, ln), w in res.tries.items()
                           if any(f == sf and a <= ln <= b for sf, a, b in spans))
            sure = [t for t in tries if t[2] != "unknown"]
            if sure:
                check = "lets-on"
                f0, at, w0 = next((t for t in sure if t[2]), sure[0])
                where = f"line {at}" if f0 == n.file else f"{f0}:{at}"
                at_file = f0 if f0 != n.file else None
                said = (f"The provider's own check is called ({where}), but {WHY_NOT.get(w0) or WHY_NOT['some']}. "
                        "So a message nobody signed gets to the change.")
            elif tries:
                continue        # a check by the provider's name on something Lantern cannot place: nothing is known
            else:
                first = written_check(own, js)
                if first is not None:
                    at = start + first
                    early = [(f, ln) for f, ln in open_ if f == n.file and start <= ln < at]
                    if not early:
                        continue        # a check is written before the writes: this rule cannot tell more
                    check, open_ = "late", early
                    said = f"A check of who sent the message is written on line {at}, after data was already written."
                elif any(written_check((lines_for(m.file) or [])[m.start_line - 1:max(m.end_line or m.start_line,
                                                                                      m.start_line)],
                                       not m.file.endswith((".py", ".rb"))) is not None for m in below):
                    continue            # written in what runs before the route or in a function it calls
                else:
                    check = "none"
                    said = ("Lantern found no check of a signature or of a shared secret in the route's code, in what "
                            f"runs before it, or in the functions it calls ({DEPTH} calls deep), so anybody who knows "
                            "the address can send the same words.")
        places = [{"file": f, "line": ln} for f, ln in sorted(open_)[:MOST_SAID]]
        named = ", ".join(f"{p['file']}:{p['line']}" for p in places)
        if len(open_) > MOST_SAID:
            named += f" and {len(open_) - MOST_SAID} more"
        route = str(c["detail"])
        more = ("Heuristic. Lantern takes this route for one a payment or message provider calls (a webhook) because "
                f"{why}. A provider cannot sign in: what proves a message is the provider's is its signature, checked "
                f"with a secret only the two share. {said} Stored data is written at {named}. If the message is "
                "checked somewhere Lantern does not read (a gateway in front of the app, a helper it could not "
                "follow), ignore this.")
        f = _finding(RULE, TITLE[check].format(route=route), "MEDIUM", n.file, start, conf="LOW", cwe=345,
                     fixed_rank="medium", more=more, snippet=src[start - 1].strip() if 0 < start <= len(src) else "")
        f["tool"] = "lantern-flow"
        f["webhook"] = {"route": route, "why": why, "check": check, "changes": places}
        if at is not None:
            f["webhook"]["at"] = at
        if at_file:
            f["webhook"]["at_file"] = at_file       # the check stands in another file than the route
        if len(open_) > MOST_SAID:
            f["webhook"]["more"] = len(open_) - MOST_SAID
        out.append(f)
    return out, looked
