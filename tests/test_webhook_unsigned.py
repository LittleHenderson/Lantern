"""A webhook that changes money or data without checking who sent the message (roadmap of 2026-11-14, stage 5).

A payment or message provider calls a route of the app when something happened: a payment went through, an account
was removed. The route has no login, because the provider has none; what stands in its place is the provider's
signature on the message, checked with a secret only the two share. A route that changes a record on such a message
and checks no signature does it for anybody who sends the same words: `LW-UNSIGNED-WEBHOOK` (a heuristic, medium).

What counts is what the code does. Each dangerous route stands beside routes that check, and beside routes that only
look as if they checked (a check whose failure is caught and passed over, one made with an empty secret, a signature
worked out and never compared, a record changed before the check). Small made-up projects; none of these files comes
from an app of a benchmark.
"""
import pytest

from lantern.engine import build_graph
from lantern.security import scan

RULE = "LW-UNSIGNED-WEBHOOK"
PKG = ('{"name": "books", "dependencies": {"next": "15.0.0", "react": "19.0.0", "@prisma/client": "6.0.0", '
       '"stripe": "17.0.0", "svix": "1.40.0", "twilio": "5.3.0", "express": "4.19.0"}}\n')
SCHEMA = '''datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id               String @id
  email            String
  plan             String
  stripeCustomerId String
}
'''
NEXT = {
    "package.json": PKG,
    "tsconfig.json": '{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./*"]}}}\n',
    "prisma/schema.prisma": SCHEMA,
    "lib/db.ts": 'import { PrismaClient } from "@prisma/client";\nexport const prisma = new PrismaClient();\n',
    "lib/stripe.ts": 'import Stripe from "stripe";\n\nexport const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);\n',
    "lib/verify.ts": '''import { stripe } from "@/lib/stripe";

export async function stripeEvent(req: Request) {
  const body = await req.text();
  return stripe.webhooks.constructEvent(body, req.headers.get("stripe-signature")!, process.env.STRIPE_WEBHOOK_SECRET!);
}
''',
}
HEAD = ('import { NextResponse } from "next/server";\nimport { createHmac, timingSafeEqual } from "crypto";\n'
        'import { Webhook } from "svix";\nimport twilio from "twilio";\n'
        'import { prisma } from "@/lib/db";\nimport { stripe } from "@/lib/stripe";\n'
        'import { stripeEvent } from "@/lib/verify";\n\n')
BAD = 'return NextResponse.json({ error: "bad signature" }, { status: 400 });'
UPGRADE = ('  if (event.type === "checkout.session.completed") {\n'
           '    await prisma.user.update({ where: { stripeCustomerId: event.data.object.customer }, '
           'data: { plan: "pro" } });\n'
           "  }\n"
           "  return NextResponse.json({ received: true });\n")
TEAM = ("  await prisma.user.update({ where: { id: String(event.sender.id) }, data: { plan: \"team\" } });\n"
        "  return NextResponse.json({ ok: true });\n")
REMOVE = ('  if (event.type === "user.deleted") {\n'
          "    await prisma.user.delete({ where: { id: event.data.id } });\n  }\n"
          "  return NextResponse.json({ ok: true });\n")
SIGNED = ('  const body = await req.text();\n  const sig = req.headers.get("stripe-signature")!;\n  let event;\n  try {\n'
          "    event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);\n"
          f"  }} catch (err) {{\n    {BAD}\n  }}\n")
HMAC = ('  const body = await req.text();\n  const sig = req.headers.get("x-hub-signature-256") ?? "";\n'
        '  const want = "sha256=" + createHmac("sha256", process.env.GITHUB_WEBHOOK_SECRET!).update(body)'
        '.digest("hex");\n')


def _post(body):
    return HEAD + "export async function POST(req: Request) {\n" + body + "}\n"


# each: the route's place in the project, its file, and what the finding must say of the check (None: no finding)
ROUTES = {
    # --- no check at all
    "Stripe's event taken from the body as it came": (
        "app/api/webhooks/stripe/route.ts", _post("  const event = await req.json();\n" + UPGRADE), "none"),
    "GitHub's event taken from the body as it came": (
        "app/api/webhooks/github/route.ts", _post("  const event = await req.json();\n" + TEAM), "none"),
    "Clerk's event taken from the body as it came": (
        "app/api/webhooks/clerk/route.ts", _post("  const event = await req.json();\n" + REMOVE), "none"),
    "a route named for no webhook that reads a provider's event": (
        "app/api/billing/events/route.ts",
        _post('  const sig = req.headers.get("stripe-signature");\n  console.log("event from stripe", sig);\n'
              "  const event = await req.json();\n" + UPGRADE), "none"),
    "a signature worked out and never compared": (
        "app/api/webhooks/unused/route.ts",
        _post(HMAC + "  console.log(sig, want);\n  const event = JSON.parse(body);\n" + TEAM), "none"),
    # --- a check that turns nobody away
    "the check's failure is caught and the request goes on": (
        "app/api/webhooks/caught/route.ts",
        _post('  const body = await req.text();\n  const sig = req.headers.get("stripe-signature")!;\n'
              "  let event = JSON.parse(body);\n  try {\n"
              "    event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);\n"
              "  } catch (err) {\n    console.warn(err);\n  }\n" + UPGRADE), "lets-on"),
    "the check is made with an empty secret": (
        "app/api/webhooks/empty/route.ts",
        _post('  const body = await req.text();\n  const sig = req.headers.get("stripe-signature")!;\n'
              '  let event;\n  try {\n    event = stripe.webhooks.constructEvent(body, sig, "");\n'
              f"  }} catch (err) {{\n    {BAD}\n  }}\n" + UPGRADE), "lets-on"),
    "the check is made only when the header is there": (
        "app/api/webhooks/some/route.ts",
        _post('  const body = await req.text();\n  const sig = req.headers.get("stripe-signature");\n'
              "  let event = JSON.parse(body);\n  if (sig) {\n    try {\n"
              "      event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);\n"
              f"    }} catch (err) {{\n      {BAD}\n    }}\n  }}\n" + UPGRADE), "lets-on"),
    # --- a check that comes too late
    "the record is changed before the check": (
        "app/api/webhooks/late/route.ts",
        _post('  const body = await req.text();\n  const sig = req.headers.get("stripe-signature")!;\n'
              "  const first = JSON.parse(body);\n"
              '  await prisma.user.update({ where: { stripeCustomerId: first.data.object.customer }, '
              'data: { plan: "pro" } });\n'
              "  try {\n    stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);\n"
              f"  }} catch (err) {{\n    {BAD}\n  }}\n  return NextResponse.json({{ received: true }});\n"), "late"),
    # --- the safe twins
    "Stripe's own check, and a message that fails it is turned away": (
        "app/api/webhooks/signed/route.ts", _post(SIGNED + UPGRADE), None),
    "the same check, made in a helper of the project": (
        "app/api/webhooks/helper/route.ts",
        _post(f"  let event;\n  try {{\n    event = await stripeEvent(req);\n  }} catch (err) {{\n    {BAD}\n  }}\n"
              + UPGRADE), None),
    "Clerk's message checked with svix": (
        "app/api/webhooks/svix/route.ts",
        _post("  const body = await req.text();\n  const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET!);\n"
              "  let event: any;\n  try {\n"
              '    event = wh.verify(body, { "svix-id": req.headers.get("svix-id")!, '
              '"svix-timestamp": req.headers.get("svix-timestamp")!, '
              '"svix-signature": req.headers.get("svix-signature")! });\n'
              f"  }} catch {{\n    {BAD}\n  }}\n" + REMOVE), None),
    "GitHub's signature worked out and compared, and a wrong one turned away": (
        "app/api/webhooks/hmac/route.ts",
        _post(HMAC + "  if (sig.length !== want.length || !timingSafeEqual(Buffer.from(sig), Buffer.from(want))) {\n"
              f"    {BAD}\n  }}\n  const event = JSON.parse(body);\n" + TEAM), None),
    "a secret both sides know, sent in a header and compared": (
        "app/api/webhooks/shared/route.ts",
        _post('  if (req.headers.get("x-webhook-secret") !== process.env.WEBHOOK_SECRET) {\n'
              f"    {BAD}\n  }}\n  const event = await req.json();\n" + TEAM), None),
    "Twilio's own check of the request": (
        "app/api/webhooks/sms/route.ts",
        _post("  const form = Object.fromEntries(await req.formData());\n"
              '  const ok = twilio.validateRequest(process.env.TWILIO_AUTH_TOKEN!, '
              'req.headers.get("x-twilio-signature")!, req.url, form);\n'
              f"  if (!ok) {{\n    {BAD}\n  }}\n"
              "  await prisma.user.update({ where: { id: String(form.From) }, data: { plan: \"sms\" } });\n"
              "  return NextResponse.json({ ok: true });\n"), None),
    "a webhook that changes nothing": (
        "app/api/webhooks/log/route.ts",
        _post('  const event = await req.json();\n  console.log("got", event.type);\n'
              "  return NextResponse.json({ received: true });\n"), None),
}


def _scan(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
    sec = scan(build_graph(root), offline=True)
    flow = next(t for t in sec["tools"] if t["tool"] == "lantern-flow")
    assert flow["state"] == "ok", flow
    return [f for f in sec["findings"] if not f["in_tests"]]


def _hooks(fs):
    return sorted((f["file"], f["webhook"]["check"]) for f in fs if f["rule"] == RULE)


@pytest.mark.parametrize("case", sorted(ROUTES))
def test_a_webhook_route_and_what_it_checks(tmp_path, case):
    rel, text, check = ROUTES[case]
    fs = _scan(tmp_path, {**NEXT, rel: text})
    assert _hooks(fs) == ([] if check is None else [(rel, check)]), [(f["rule"], f["file"]) for f in fs]


def test_what_the_finding_says(tmp_path):
    rel, text, _check = ROUTES["Stripe's event taken from the body as it came"]
    fs = [f for f in _scan(tmp_path, {**NEXT, rel: text}) if f["rule"] == RULE]
    assert len(fs) == 1
    f = fs[0]
    assert f["tool_confidence"] == "LOW" and f["rank"] == "medium" and f["cwe"] == 345
    assert f["webhook"]["route"] == "POST /api/webhooks/stripe"
    assert f["snippet"] == "export async function POST(req: Request) {"
    # the line the record is changed on is named, so a person can go there
    changed = text.split("\n").index(next(x for x in text.split("\n") if "prisma.user.update" in x)) + 1
    assert f["webhook"]["changes"] == [{"file": rel, "line": changed}]
    assert f"{rel}:{changed}" in f["more_info"] and f["more_info"].startswith("Heuristic.")
    assert f["scenario"]["kind"] == "unsigned-webhook"
    assert "signature" in f["case"]["claim"]
    # ... and it is one finding: the route is not also listed as one that has no login
    assert [x["rule"] for x in _scan(tmp_path / "again", {**NEXT, rel: text})
            if x["file"] == rel and x["rule"].startswith(("LW-AUTH", "LT-AUTHZ"))] == []


def test_a_route_that_is_no_webhook_is_not_this_rules(tmp_path):
    """The same lines on a route nothing marks as a provider's: whoever sends the request chooses the record, which
    is the older finding about a route with no login, and not this one."""
    fs = _scan(tmp_path, {**NEXT, "app/api/accounts/route.ts": _post("  const event = await req.json();\n" + TEAM)})
    assert _hooks(fs) == []
    # ... and the page a provider asks first, to see that the address is the app's (a GET that changes nothing)
    get = HEAD + ('export async function GET(req: Request) {\n'
                  '  return new Response(new URL(req.url).searchParams.get("hub.challenge") ?? "");\n}\n')
    assert _hooks(_scan(tmp_path / "get", {**NEXT, "app/api/webhooks/meta/route.ts": get})) == []


EXPRESS = '''const express = require("express");
const Stripe = require("stripe");
const { PrismaClient } = require("@prisma/client");

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const prisma = new PrismaClient();
const app = express();

app.post("/webhooks/open", express.raw({ type: "application/json" }), async (req, res) => {
  const event = JSON.parse(req.body);
  await prisma.user.update({ where: { stripeCustomerId: event.data.object.customer }, data: { plan: "pro" } });
  res.json({ received: true });
});

app.post("/webhooks/checked", express.raw({ type: "application/json" }), async (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send("bad signature");
  }
  await prisma.user.update({ where: { stripeCustomerId: event.data.object.customer }, data: { plan: "pro" } });
  res.json({ received: true });
});

module.exports = app;
'''


def test_the_same_in_an_express_app(tmp_path):
    fs = _scan(tmp_path, {"package.json": PKG, "prisma/schema.prisma": SCHEMA, "server/app.js": EXPRESS})
    assert [f["webhook"]["route"] for f in fs if f["rule"] == RULE] == ["POST /webhooks/open"]


FLASK = {
    "requirements.txt": "Flask==3.0.3\nstripe==11.0.0\nFlask-SQLAlchemy==3.1.1\n",
    "app.py": '''import hashlib
import hmac
import os

import stripe
from flask import Flask, abort, jsonify, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    plan = db.Column(db.String(20))
    stripe_customer_id = db.Column(db.String(40))


@app.post("/webhooks/stripe-open")
def stripe_open():
    event = request.get_json()
    if event["type"] == "checkout.session.completed":
        user = User.query.filter_by(stripe_customer_id=event["data"]["object"]["customer"]).first()
        user.plan = "pro"
        db.session.commit()
    return jsonify(received=True)


@app.post("/webhooks/stripe-checked")
def stripe_checked():
    try:
        event = stripe.Webhook.construct_event(request.data, request.headers["Stripe-Signature"],
                                               os.environ["STRIPE_WEBHOOK_SECRET"])
    except Exception:
        abort(400)
    if event["type"] == "checkout.session.completed":
        user = User.query.filter_by(stripe_customer_id=event["data"]["object"]["customer"]).first()
        user.plan = "pro"
        db.session.commit()
    return jsonify(received=True)


@app.post("/webhooks/github-checked")
def github_checked():
    want = "sha256=" + hmac.new(os.environ["GITHUB_WEBHOOK_SECRET"].encode(), request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, request.headers.get("X-Hub-Signature-256", "")):
        abort(401)
    event = request.get_json()
    user = User.query.get(event["sender"]["id"])
    user.plan = "team"
    db.session.commit()
    return jsonify(ok=True)


@app.post("/webhooks/github-open")
def github_open():
    event = request.get_json()
    user = User.query.get(event["sender"]["id"])
    user.plan = "team"
    db.session.commit()
    return jsonify(ok=True)


@app.post("/webhooks/github-worked-out")
def github_worked_out():
    want = "sha256=" + hmac.new(os.environ["GITHUB_WEBHOOK_SECRET"].encode(), request.data, hashlib.sha256).hexdigest()
    app.logger.info("signature would be %s", want)
    event = request.get_json()
    user = User.query.get(event["sender"]["id"])
    user.plan = "team"
    db.session.commit()
    return jsonify(ok=True)
''',
}


def test_the_same_in_a_flask_app(tmp_path):
    fs = _scan(tmp_path, FLASK)
    assert sorted(f["webhook"]["route"] for f in fs if f["rule"] == RULE) == [
        "POST /webhooks/github-open", "POST /webhooks/github-worked-out", "POST /webhooks/stripe-open"]
