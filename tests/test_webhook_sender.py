"""A webhook whose sender is checked is not a route anyone can call (directive point 6, a target carried from point 4).

A payment or message provider signs what it sends, and its own library checks that signature and fails when it does
not hold. A route that goes on only after that check is called by the provider and nobody else: it cannot have a
login, and "anyone can call it as often as they like" is false there. Until this stage `LA-WALLET-DRAIN` said just
that, at high, of every such webhook that goes on to use the payment API (found on a clean app of the held-out
benchmark; none of these files comes from it).

What counts is what the code does: the provider's library, the check before the money is spent, and a failure that
ends the request. Each webhook that counts stands beside one that must not.
"""
import pytest

from lantern.engine import build_graph
from lantern.security import scan

PKG = '{"dependencies": {"next": "14.0.0", "stripe": "^14.0.0", "svix": "^1.15.0", "express": "^4.19.0", "openai": "^4.0.0"}}'
TSCONFIG = '{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./*"]}}}'
LIB = 'import Stripe from "stripe"\n\nexport const stripe = new Stripe(process.env.STRIPE_API_KEY)\n'

NEXT = '''import { headers } from "next/headers"
import { stripe } from "@/lib/stripe"

export async function POST(req: Request) {
  const body = await req.text()
  const signature = headers().get("Stripe-Signature") as string
%s
  const subscription = await stripe.subscriptions.retrieve(event.data.object.subscription as string)
  return new Response(subscription.id, { status: 200 })
}
'''
CHECKED = '''  let event
  try {
    event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET)
  } catch (error) {
    return new Response("Webhook Error", { status: 400 })
  }'''
# ... and the near-misses, each one line or two away from it
NOT_CHECKED = "  const event = JSON.parse(body)"
CAUGHT_AND_ON = '''  let event = JSON.parse(body)
  try {
    event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET)
  } catch (error) {
    console.log("bad signature", error)
  }'''
NO_SECRET = '''  let event
  try {
    event = stripe.webhooks.constructEvent(body, signature, "")
  } catch (error) {
    return new Response("Webhook Error", { status: 400 })
  }'''
ONLY_SOME = '''  let event = JSON.parse(body)
  if (signature) {
    try {
      event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET)
    } catch (error) {
      return new Response("Webhook Error", { status: 400 })
    }
  }'''


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _drain(root, files):
    sec = scan(build_graph(_write(root, files)), offline=True)
    return [f for f in sec["findings"] if f["rule"] == "LA-WALLET-DRAIN"], sec


def _next(check, lib=LIB):
    return {"package.json": PKG, "tsconfig.json": TSCONFIG, "lib/stripe.ts": lib,
            "app/api/webhooks/stripe/route.ts": NEXT % check}


def test_a_webhook_that_checks_the_senders_signature_first_is_not_open_to_anyone(tmp_path):
    found, sec = _drain(tmp_path, _next(CHECKED))
    assert found == [], [(f["title"], f["rank"]) for f in found]
    rec = next(t for t in sec["tools"] if t["tool"] == "lantern-flow")
    assert rec["scope"]["sender_checked"] == 1, rec["scope"]         # not dropped without a word: counted in the record


NEAR = {
    "nothing checks who sent it": NOT_CHECKED,
    "the check fails and the request goes on": CAUGHT_AND_ON,
    "the check is handed no secret": NO_SECRET,
    "only requests that bring a signature are checked": ONLY_SOME,
}


@pytest.mark.parametrize("case", sorted(NEAR))
def test_a_webhook_that_does_not_turn_a_stranger_away_still_spends_money_for_anyone(tmp_path, case):
    found, sec = _drain(tmp_path, _next(NEAR[case]))
    assert len(found) == 1 and found[0]["rank"] == "high", [(f["title"], f["rank"]) for f in found]
    assert "anyone can call it" in found[0]["title"]
    rec = next(t for t in sec["tools"] if t["tool"] == "lantern-flow")
    assert not rec["scope"].get("sender_checked"), rec["scope"]


def test_the_money_spent_before_the_check_is_spent_for_anyone(tmp_path):
    late = '''import { headers } from "next/headers"
import { stripe } from "@/lib/stripe"

export async function POST(req: Request) {
  const body = await req.text()
  const signature = headers().get("Stripe-Signature") as string
  const customer = await stripe.customers.create({ email: JSON.parse(body).email })
  let event
  try {
    event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET)
  } catch (error) {
    return new Response("Webhook Error", { status: 400 })
  }
  return new Response(customer.id + event.id, { status: 200 })
}
'''
    found, _ = _drain(tmp_path, {**_next(CHECKED), "app/api/webhooks/stripe/route.ts": late})
    assert len(found) == 1 and found[0]["rank"] == "high", found


def test_a_function_of_the_projects_own_with_the_librarys_name_checks_nothing(tmp_path):
    """The call reads exactly like the library's. What makes it a check is where `stripe` comes from."""
    own = ('export const stripe = {\n  webhooks: { constructEvent: (body, sig, secret) => JSON.parse(body) },\n'
           '  subscriptions: { retrieve: async (id) => ({ id }) },\n}\n')
    found, sec = _drain(tmp_path, _next(CHECKED, lib=own))
    assert len(found) == 1 and found[0]["rank"] == "high", found
    assert not next(t for t in sec["tools"] if t["tool"] == "lantern-flow")["scope"].get("sender_checked")
    # ... and beside the real client: the money goes through the library, the check through the project's own object
    files = _next(CHECKED, lib=own)
    files["lib/pay.ts"] = LIB
    files["app/api/webhooks/stripe/route.ts"] = files["app/api/webhooks/stripe/route.ts"].replace(
        'import { stripe } from "@/lib/stripe"', 'import { stripe as fake } from "@/lib/stripe"\nimport { stripe } from "@/lib/pay"'
    ).replace("stripe.webhooks.constructEvent(", "fake.webhooks.constructEvent(")
    found, _ = _drain(tmp_path / "two", files)
    assert len(found) == 1 and found[0]["rank"] == "high", found
    # a file that loads the library and hands out an object of its own under the client's name
    both = ('import Stripe from "stripe"\n\nconst real = new Stripe(process.env.STRIPE_API_KEY)\n'
            'export const stripe = { ...real, webhooks: { constructEvent: (body) => JSON.parse(body) } }\n')
    found, _ = _drain(tmp_path / "both", _next(CHECKED, lib=both))
    assert len(found) == 1 and found[0]["rank"] == "high", found


WHERE_THE_CLIENT_IS_MADE = {
    "in the route's own file": (None, 'import Stripe from "stripe"\n\nconst stripe = new Stripe(process.env.STRIPE_API_KEY)'),
    "handed out by default": ('import Stripe from "stripe"\n\nconst stripe = new Stripe(process.env.STRIPE_API_KEY)\n'
                              'export default stripe\n', 'import stripe from "../../../../lib/stripe"'),
    "handed out by default, made in place": ('import Stripe from "stripe"\n\nexport default new Stripe(process.env.STRIPE_API_KEY)\n',
                                             'import stripe from "@/lib/stripe"'),
    "under another name": (LIB, 'import { stripe as pay } from "@/lib/stripe"\nconst stripe = pay'),
    "made the older way": ('export const stripe = require("stripe")(process.env.STRIPE_API_KEY)\n',
                           'import { stripe } from "@/lib/stripe"'),
}


@pytest.mark.parametrize("case", sorted(WHERE_THE_CLIENT_IS_MADE))
def test_the_check_counts_wherever_the_librarys_client_is_made(tmp_path, case):
    lib, loaded = WHERE_THE_CLIENT_IS_MADE[case]
    files = _next(CHECKED, lib=lib or LIB)
    files["app/api/webhooks/stripe/route.ts"] = files["app/api/webhooks/stripe/route.ts"].replace(
        'import { stripe } from "@/lib/stripe"', loaded)
    if lib is None:
        del files["lib/stripe.ts"]
    found, sec = _drain(tmp_path, files)
    if case == "under another name":
        # Lantern does not follow a client through a second name of the route's own file: listed as before
        assert len(found) == 1, found
        return
    assert found == [], [(f["title"], f["rank"]) for f in found]
    assert next(t for t in sec["tools"] if t["tool"] == "lantern-flow")["scope"]["sender_checked"] == 1


ROUTE = '''import { headers } from "next/headers"
import { stripe } from "@/lib/stripe"
import { tell } from "@/lib/mail"

export async function POST(req: Request) {
  const body = await req.text()
  const signature = headers().get("Stripe-Signature") as string
%s
  return new Response(event.id, { status: 200 })
}
'''
MAIL = '''import { Resend } from "resend"

const resend = new Resend(process.env.RESEND_KEY)

export async function tell(what: string) {
  await resend.emails.send({ from: "a@example.com", to: "b@example.com", subject: what, text: what })
}
'''
ORDER = {
    # the usual shape: check, then helpers that do the paid work
    "a helper pays after the check": (CHECKED + "\n  await tell(event.type)", 0),
    "a helper pays before the check": ("  await tell(body.slice(0, 20))\n" + CHECKED, 1),
    "a helper pays in the check's own line": (CHECKED.replace("body, signature", "body, await tell(signature)"), 1),
    "the check is written in a function nobody calls": (
        "  const check = () => stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET)\n"
        "  const event = JSON.parse(body)\n  await tell(event.type)", 1),
    "the check's answer is not waited for": (
        "  const event = JSON.parse(body)\n"
        "  stripe.webhooks.constructEventAsync(body, signature, process.env.STRIPE_WEBHOOK_SECRET).catch(() => {})\n"
        "  await tell(event.type)", 1),
    "the check's answer is waited for": (
        "  const event = await stripe.webhooks.constructEventAsync(body, signature, process.env.STRIPE_WEBHOOK_SECRET)\n"
        "  await tell(event.type)", 0),
    "the secret may be empty text": (CHECKED.replace("process.env.STRIPE_WEBHOOK_SECRET", 'process.env.STRIPE_WEBHOOK_SECRET || ""')
                                     + "\n  await tell(event.type)", 1),
    "the secret may be empty text, written with ??": (
        CHECKED.replace("process.env.STRIPE_WEBHOOK_SECRET", 'process.env.STRIPE_WEBHOOK_SECRET ?? ""')
        + "\n  await tell(event.type)", 1),
    "the check is made for one kind of message only": (
        "  let event = JSON.parse(body)\n  if (event.livemode) {\n  " + CHECKED.replace("\n", "\n  ").replace("let event\n", "")
        + "\n  }\n  await tell(event.type)", 1),
    "some requests are answered before the check": (
        "  if (req.headers.get('x-test')) {\n    await tell('test')\n    return new Response('ok')\n  }\n" + CHECKED
        + "\n  await tell(event.type)", 1),
}


@pytest.mark.parametrize("case", sorted(ORDER))
def test_what_is_paid_before_the_check_or_round_it_is_paid_for_anyone(tmp_path, case):
    body, want = ORDER[case]
    files = {"package.json": PKG.replace('"openai"', '"resend": "^3.0.0", "openai"'), "tsconfig.json": TSCONFIG,
             "lib/stripe.ts": LIB, "lib/mail.ts": MAIL, "app/api/webhooks/stripe/route.ts": ROUTE % body}
    found, sec = _drain(tmp_path, files)
    assert len(found) == want, (case, [(f["title"], f["rank"]) for f in found])
    assert all(f["rank"] == "high" for f in found)
    rec = next(t for t in sec["tools"] if t["tool"] == "lantern-flow")
    assert rec["scope"]["sender_checked"] == 1 - want, rec["scope"]


HELPER = '''import { headers } from "next/headers"
import { stripe } from "@/lib/stripe"
import { tell } from "@/lib/mail"

%s

export async function POST(req: Request) {
  const event = await sent(req)
  await tell(event.type)
  return new Response(event.id, { status: 200 })
}
'''
THROWS = '''async function sent(req: Request) {
  const body = await req.text()
  return stripe.webhooks.constructEvent(body, headers().get("Stripe-Signature") as string, process.env.STRIPE_WEBHOOK_SECRET)
}'''
SWALLOWS = '''async function sent(req: Request) {
  const body = await req.text()
  try {
    return stripe.webhooks.constructEvent(body, headers().get("Stripe-Signature") as string, process.env.STRIPE_WEBHOOK_SECRET)
  } catch (error) {
    return JSON.parse(body)
  }
}'''
PAYS_FIRST = '''async function sent(req: Request) {
  const body = await req.text()
  await tell("a message came in")
  return stripe.webhooks.constructEvent(body, headers().get("Stripe-Signature") as string, process.env.STRIPE_WEBHOOK_SECRET)
}'''


def test_a_check_made_in_a_helper_of_the_project(tmp_path):
    base = {"package.json": PKG.replace('"openai"', '"resend": "^3.0.0", "openai"'), "tsconfig.json": TSCONFIG,
            "lib/stripe.ts": LIB, "lib/mail.ts": MAIL}
    found, _ = _drain(tmp_path / "a", {**base, "app/api/webhooks/stripe/route.ts": HELPER % THROWS})
    assert found == [], [(f["title"], f["rank"]) for f in found]
    for name, helper in (("b", SWALLOWS), ("c", PAYS_FIRST)):
        found, _ = _drain(tmp_path / name, {**base, "app/api/webhooks/stripe/route.ts": HELPER % helper})
        assert len(found) == 1 and found[0]["rank"] == "high", (name, found)


EXPRESS = '''const express = require('express')
const OpenAI = require('openai')
const { Webhook } = require('svix')

const app = express()
const openai = new OpenAI()

app.post('/hooks/signup', express.raw({ type: 'application/json' }), async (req, res) => {
%s
  const answer = await openai.chat.completions.create({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: 'welcome ' + evt.data.name }] })
  res.json({ text: answer.choices[0].message.content })
})

app.listen(3000)
'''
SVIX_CHECKED = '''  let evt
  try {
    evt = new Webhook(process.env.SVIX_SECRET).verify(req.body, req.headers)
  } catch (err) {
    return res.status(400).end()
  }'''
SVIX_NOT = "  const evt = JSON.parse(req.body)"


def test_an_express_webhook_checked_with_svix_and_its_twin(tmp_path):
    found, _ = _drain(tmp_path / "a", {"package.json": PKG, "server.js": EXPRESS % SVIX_CHECKED})
    assert found == [], found
    found, _ = _drain(tmp_path / "b", {"package.json": PKG, "server.js": EXPRESS % SVIX_NOT})
    assert len(found) == 1 and found[0]["rank"] == "high", found


PY = '''import os

import stripe
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()


@app.post("/hooks/stripe")
async def hook(request: Request):
    payload = await request.body()
    sig = request.headers.get("stripe-signature")
%s
    session = stripe.checkout.Session.retrieve(event["data"]["object"]["id"])
    return {"id": session.id}
'''
PY_CHECKED = '''    try:
        event = stripe.Webhook.construct_event(payload, sig, os.environ["STRIPE_WEBHOOK_SECRET"])
    except Exception:
        raise HTTPException(status_code=400)'''
PY_NOT = "    import json\n    event = json.loads(payload)"
PY_CAUGHT = '''    import json
    event = json.loads(payload)
    try:
        event = stripe.Webhook.construct_event(payload, sig, os.environ["STRIPE_WEBHOOK_SECRET"])
    except Exception:
        pass'''


PY_HEADER = """    try:
        stripe.WebhookSignature.verify_header(payload.decode(), sig, os.environ["STRIPE_WEBHOOK_SECRET"], tolerance=300)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400)
    import json
    event = json.loads(payload)"""
PY_EMPTY = PY_CHECKED.replace('os.environ["STRIPE_WEBHOOK_SECRET"]', 'os.getenv("STRIPE_WEBHOOK_SECRET", "")')
PY_SOME = """    import json
    event = json.loads(payload)
    if sig:
        try:
            event = stripe.Webhook.construct_event(payload, sig, os.environ["STRIPE_WEBHOOK_SECRET"])
        except Exception:
            raise HTTPException(status_code=400)"""
PY_NAMED = PY_CHECKED.replace('payload, sig, os.environ["STRIPE_WEBHOOK_SECRET"]',
                              'payload=payload, sig_header=sig, secret=os.environ["STRIPE_WEBHOOK_SECRET"]')


def test_a_python_webhook_and_its_twins(tmp_path):
    deps = {"requirements.txt": "fastapi==0.115.0\nstripe==10.0.0\n"}
    for name, check in (("a", PY_CHECKED), ("header", PY_HEADER), ("named", PY_NAMED)):
        found, _ = _drain(tmp_path / name, {**deps, "hooks.py": PY % check})
        assert found == [], (name, found)
    for name, check in (("b", PY_NOT), ("c", PY_CAUGHT), ("empty", PY_EMPTY), ("some", PY_SOME)):
        found, _ = _drain(tmp_path / name, {**deps, "hooks.py": PY % check})
        assert len(found) == 1 and found[0]["rank"] == "high", (name, found)


def test_a_module_of_the_projects_own_called_stripe_is_not_the_library(tmp_path):
    """`stripe.Webhook.construct_event` from the project's own `stripe.py` reads the same and checks nothing."""
    own = "import json\n\n\nclass Webhook:\n    @staticmethod\n    def construct_event(payload, sig, secret):\n        return json.loads(payload)\n"
    hook = (PY % PY_CHECKED).replace("import stripe\n", "import pay as stripe\nimport openai\n").replace(
        'session = stripe.checkout.Session.retrieve(event["data"]["object"]["id"])',
        'session = openai.OpenAI().chat.completions.create(model="gpt-4o-mini", messages=[])')
    found, _ = _drain(tmp_path, {"requirements.txt": "fastapi==0.115.0\nopenai==1.50.0\n", "pay.py": own, "hooks.py": hook})
    assert len(found) == 1 and found[0]["rank"] == "high", found
