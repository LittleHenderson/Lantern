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
       '"stripe": "17.0.0", "svix": "1.40.0", "twilio": "5.3.0", "express": "4.19.0", "next-auth": "4.24.0", '
       '"@supabase/supabase-js": "2.45.0", "@clerk/nextjs": "6.0.0"}}\n')
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
    "lib/billing.ts": ('import { prisma } from "@/lib/db";\n\nexport async function upgrade(customer: string) {\n'
                       '  await prisma.user.update({ where: { stripeCustomerId: customer }, data: { plan: "pro" } });\n}\n'),
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


SERVICE = ('import { NextResponse } from "next/server";\nimport { createClient } from "@supabase/supabase-js";\n'
           'import { clerkClient } from "@clerk/nextjs/server";\nimport { Webhook } from "svix";\n'
           'import { prisma } from "@/lib/db";\n\n'
           "const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n\n"
           "export async function POST(req: Request) {\n")
PLAN = ('  await prisma.user.update({ where: { stripeCustomerId: event.data.object.customer }, '
        'data: { plan: "pro" } });\n')


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
    # --- written after the first twenty passed, by reading the rule as somebody who wants it to fail
    "a signature compared after the record was changed": (
        "app/api/webhooks/compared-late/route.ts",
        _post(HMAC + "  const event = JSON.parse(body);\n"
              '  await prisma.user.update({ where: { id: String(event.sender.id) }, data: { plan: "team" } });\n'
              "  if (sig.length !== want.length || !timingSafeEqual(Buffer.from(sig), Buffer.from(want))) {\n"
              f"    {BAD}\n  }}\n  return NextResponse.json({{ ok: true }});\n"), "late"),
    "the helper's check, and the route goes on when it fails": (
        "app/api/webhooks/helper-caught/route.ts",
        _post("  const copy = req.clone();\n  let event;\n  try {\n    event = await stripeEvent(req);\n"
              "  } catch (err) {\n    event = await copy.json();\n  }\n" + UPGRADE), "lets-on"),
    "the helper's check, after the record was changed": (
        "app/api/webhooks/helper-late/route.ts",
        _post("  const event = await req.clone().json();\n" + PLAN
              + f"  try {{\n    await stripeEvent(req);\n  }} catch (err) {{\n    {BAD}\n  }}\n"
              "  return NextResponse.json({ received: true });\n"), "late"),
    "the record is changed by a helper in another file": (
        "app/api/webhooks/far/route.ts",
        'import { NextResponse } from "next/server";\nimport { upgrade } from "@/lib/billing";\n\n'
        "export async function POST(req: Request) {\n  const event = await req.json();\n"
        "  await upgrade(event.data.object.customer);\n  return NextResponse.json({ received: true });\n}\n", "none"),
    "a route of the older pages folder": (
        "pages/api/webhooks/stripe.ts",
        'import type { NextApiRequest, NextApiResponse } from "next";\nimport { prisma } from "@/lib/db";\n\n'
        "export default async function handler(req: NextApiRequest, res: NextApiResponse) {\n"
        "  const event = req.body;\n" + PLAN + "  res.json({ received: true });\n}\n", "none"),
    "two names of the event compared, which is no check of the sender": (
        "app/api/webhooks/assignee/route.ts",
        _post("  const event = await req.json();\n  if (event.issue.assignee === event.sender.login) {\n"
              '    await prisma.user.update({ where: { id: String(event.sender.id) }, data: { plan: "team" } });\n'
              "  }\n  return NextResponse.json({ ok: true });\n"), "none"),
    "a row of a Supabase table changed with the server's own key": (
        "app/api/webhooks/table/route.ts",
        SERVICE + "  const event = await req.json();\n"
        '  await supabase.from("users").update({ plan: "pro" }).eq("stripe_customer_id", event.data.object.customer);\n'
        "  return NextResponse.json({ received: true });\n}\n", "none"),
    "an account changed through the sign-in service's admin side, beside the record": (
        "app/api/webhooks/account/route.ts",
        SERVICE + "  const event = await req.json();\n"
        "  await supabase.auth.admin.updateUserById(event.data.object.client_reference_id, "
        '{ user_metadata: { plan: "pro" } });\n' + PLAN + "  return NextResponse.json({ received: true });\n}\n",
        "none"),
    "only the account at the sign-in service is changed": (
        "app/api/webhooks/account-only/route.ts",
        SERVICE + "  const event = await req.json();\n"
        '  await clerkClient.users.updateUserMetadata(event.data.id, { publicMetadata: { plan: "free" } });\n'
        "  return NextResponse.json({ received: true });\n}\n", "none"),
    "the same change of an account, with the message checked first": (
        "app/api/webhooks/account-signed/route.ts",
        SERVICE + "  const body = await req.text();\n  const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET!);\n"
        "  let event: any;\n  try {\n"
        '    event = wh.verify(body, { "svix-id": req.headers.get("svix-id")!, '
        '"svix-timestamp": req.headers.get("svix-timestamp")!, '
        '"svix-signature": req.headers.get("svix-signature")! });\n'
        f"  }} catch {{\n    {BAD}\n  }}\n"
        '  await clerkClient.users.updateUserMetadata(event.data.id, { publicMetadata: { plan: "free" } });\n'
        "  return NextResponse.json({ received: true });\n}\n", None),
    "a route of the app's own people under the same word, who sign in": (
        "app/api/webhooks/route.ts",
        'import { NextResponse } from "next/server";\nimport { getServerSession } from "next-auth";\n'
        'import { prisma } from "@/lib/db";\n\n'
        "export async function POST(req: Request) {\n  const session = await getServerSession();\n"
        '  if (!session) {\n    return NextResponse.json({ error: "sign in" }, { status: 401 });\n  }\n'
        "  const { plan } = await req.json();\n"
        "  await prisma.user.update({ where: { id: session.user.id }, data: { plan } });\n"
        "  return NextResponse.json({ ok: true });\n}\n", None),
    "a check by the provider's name on a client Lantern cannot place": (
        "app/api/webhooks/unplaced/route.ts",
        'import { NextResponse } from "next/server";\nimport { prisma } from "@/lib/db";\n'
        'import { billing } from "@/lib/generated";\n\n'
        "export async function POST(req: Request) {\n  const body = await req.text();\n  let event;\n  try {\n"
        '    event = billing.webhooks.constructEvent(body, req.headers.get("stripe-signature")!, '
        "process.env.STRIPE_WEBHOOK_SECRET!);\n"
        f"  }} catch (err) {{\n    {BAD}\n  }}\n" + UPGRADE + "}\n", None),
    "a secret in the address, compared with a setting": (
        "app/api/webhooks/[key]/route.ts",
        HEAD + "export async function POST(req: Request, { params }: { params: { key: string } }) {\n"
        f"  if (params.key !== process.env.HOOK_KEY) {{\n    {BAD}\n  }}\n"
        "  const event = await req.json();\n" + TEAM + "}\n", None),
    "GitHub's signature compared with a plain comparison": (
        "app/api/webhooks/plain/route.ts",
        _post(HMAC + f"  if (sig !== want) {{\n    {BAD}\n  }}\n  const event = JSON.parse(body);\n" + TEAM), None),
    "a library's function named for checking the signature, and its answer asked": (
        "app/api/webhooks/library/route.ts",
        'import { NextResponse } from "next/server";\nimport { verifySignature } from "@acme/hooks";\n'
        'import { prisma } from "@/lib/db";\n\n'
        "export async function POST(req: Request) {\n  const body = await req.text();\n"
        '  if (!verifySignature(body, req.headers.get("x-acme-signature"), process.env.ACME_HOOK_SECRET)) {\n'
        f"    {BAD}\n  }}\n  const event = JSON.parse(body);\n" + TEAM + "}\n", None),
    "GitHub's own library asked whether the signature holds": (
        "app/api/webhooks/octokit/route.ts",
        'import { NextResponse } from "next/server";\nimport { Webhooks } from "@octokit/webhooks";\n'
        'import { prisma } from "@/lib/db";\n\n'
        "const webhooks = new Webhooks({ secret: process.env.GITHUB_WEBHOOK_SECRET! });\n\n"
        "export async function POST(req: Request) {\n  const body = await req.text();\n"
        '  const held = await webhooks.verify(body, req.headers.get("x-hub-signature-256") ?? "");\n'
        f"  if (!held) {{\n    {BAD}\n  }}\n  const event = JSON.parse(body);\n" + TEAM + "}\n", None),
    "a bearer text compared with a setting": (
        "app/api/webhooks/bearer/route.ts",
        _post('  if (req.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) {\n'
              f"    {BAD}\n  }}\n  const event = await req.json();\n" + TEAM), None),
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
    rel = "app/api/accounts/route.ts"
    fs = _scan(tmp_path, {**NEXT, rel: _post(
        "  const event = await req.json();\n"
        '  await prisma.user.update({ where: { id: event.id }, data: { plan: "team" } });\n'
        "  return NextResponse.json({ ok: true });\n")})
    assert _hooks(fs) == []
    assert [f["rule"] for f in fs if f["file"] == rel] == ["LW-AUTH-MISSING"]
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

function signed(req, res, next) {
  try {
    req.event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send("bad signature");
  }
  next();
}

function signedOrNot(req, res, next) {
  try {
    req.event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    req.event = JSON.parse(req.body);
  }
  next();
}

app.post("/webhooks/before", express.raw({ type: "application/json" }), signed, async (req, res) => {
  await prisma.user.update({ where: { stripeCustomerId: req.event.data.object.customer }, data: { plan: "pro" } });
  res.json({ received: true });
});

app.post("/webhooks/before-or-not", express.raw({ type: "application/json" }), signedOrNot, async (req, res) => {
  await prisma.user.update({ where: { stripeCustomerId: req.event.data.object.customer }, data: { plan: "pro" } });
  res.json({ received: true });
});

module.exports = app;
'''


def test_the_same_in_an_express_app(tmp_path):
    """Also with the check in a function put before the route: one that turns a failed message away, and one that
    takes the message as it came when the check fails."""
    fs = _scan(tmp_path, {"package.json": PKG, "prisma/schema.prisma": SCHEMA, "server/app.js": EXPRESS})
    assert sorted((f["webhook"]["route"], f["webhook"]["check"]) for f in fs if f["rule"] == RULE) == [
        ("POST /webhooks/before-or-not", "lets-on"), ("POST /webhooks/open", "none")]


FLASK = {
    "requirements.txt": "Flask==3.0.3\nstripe==11.0.0\nFlask-SQLAlchemy==3.1.1\n",
    "app.py": '''import hashlib
import hmac
import os
import sqlite3

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


@app.post("/webhooks/stripe-sql")
def stripe_sql():
    event = request.get_json()
    with sqlite3.connect("app.db") as conn:
        conn.execute("UPDATE user SET plan = 'pro' WHERE stripe_customer_id = ?", (event["data"]["object"]["customer"],))
    return jsonify(received=True)


@app.post("/webhooks/stripe-sql-new-row")
def stripe_sql_new_row():
    event = request.get_json()
    with sqlite3.connect("app.db") as conn:
        conn.execute("INSERT INTO payment (customer, amount) VALUES (?, ?)",
                     (event["data"]["object"]["customer"], event["data"]["object"]["amount"]))
    return jsonify(received=True)


@app.post("/webhooks/stripe-sql-read")
def stripe_sql_read():
    event = request.get_json()
    with sqlite3.connect("app.db") as conn:
        row = conn.execute("SELECT plan FROM user WHERE stripe_customer_id = ?",
                           (event["data"]["object"]["customer"],)).fetchone()
    return jsonify(plan=row[0] if row else None)


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
        "POST /webhooks/github-open", "POST /webhooks/github-worked-out", "POST /webhooks/stripe-open",
        "POST /webhooks/stripe-sql", "POST /webhooks/stripe-sql-new-row"]


DJANGO = {
    "requirements.txt": "Django==5.1\nstripe==11.0.0\n",
    "manage.py": "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'shop.settings')\n",
    "shop/__init__.py": "",
    "shop/settings.py": "INSTALLED_APPS = ['billing']\nROOT_URLCONF = 'shop.urls'\n",
    "shop/urls.py": ("from django.urls import path\n\nfrom billing import views\n\n"
                     "urlpatterns = [\n    path('billing/notify/', views.notify),\n"
                     "    path('billing/notify-checked/', views.notify_checked),\n]\n"),
    "billing/__init__.py": "",
    "billing/models.py": ("from django.db import models\n\n\nclass Account(models.Model):\n"
                          "    plan = models.CharField(max_length=20)\n"
                          "    stripe_customer_id = models.CharField(max_length=40)\n"),
    "billing/views.py": '''import json

import stripe
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import Account


@csrf_exempt
@require_POST
def notify(request):
    signature = request.META.get("HTTP_STRIPE_SIGNATURE")
    event = json.loads(request.body)
    Account.objects.filter(stripe_customer_id=event["data"]["object"]["customer"]).update(plan="pro")
    return JsonResponse({"received": True, "signed": bool(signature)})


@csrf_exempt
@require_POST
def notify_checked(request):
    try:
        event = stripe.Webhook.construct_event(request.body, request.META["HTTP_STRIPE_SIGNATURE"],
                                               settings.STRIPE_WEBHOOK_SECRET)
    except Exception:
        return HttpResponse(status=400)
    Account.objects.filter(stripe_customer_id=event["data"]["object"]["customer"]).update(plan="pro")
    return JsonResponse({"received": True})
''',
}


def test_the_same_in_a_django_app_where_only_the_header_says_whose_route_it_is(tmp_path):
    fs = [f for f in _scan(tmp_path, DJANGO) if f["rule"] == RULE]
    assert [(f["webhook"]["route"], f["webhook"]["check"]) for f in fs] == [("ANY /billing/notify/", "none")]
    assert "STRIPE_SIGNATURE" in f"{fs[0]['webhook']['why']}"


def test_where_a_check_in_another_file_stands_is_said_with_its_file(tmp_path):
    rel, text, _check = ROUTES["the helper's check, and the route goes on when it fails"]
    f = next(f for f in _scan(tmp_path, {**NEXT, rel: text}) if f["rule"] == RULE)
    line = NEXT["lib/verify.ts"].split("\n").index(next(x for x in NEXT["lib/verify.ts"].split("\n")
                                                        if "constructEvent" in x)) + 1
    assert (f["webhook"]["at_file"], f["webhook"]["at"]) == ("lib/verify.ts", line)
    assert f"lib/verify.ts:{line}" in f["more_info"]
