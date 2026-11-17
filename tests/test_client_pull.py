"""`LW-SERVER-IMPORT-IN-CLIENT`: a file that reads a secret setting, pulled into the browser's side (roadmap of
2026-11-14, stage 5).

A file that begins with `"use client"` is handed to every visitor, and so is every file it imports, and every file
those import. A file written for the server that reads a secret setting (`process.env.STRIPE_SECRET_KEY`) then has
its code in what visitors download. The setting itself arrives there empty unless the build hands it over
(`env` in `next.config.js` does). The rule reads import lines and settings' names; it builds nothing and runs
nothing. A heuristic until it is measured, so each dangerous example stands beside twins that must stay quiet.

No file here holds a secret's value: the rule reads names.
"""
import pytest

from lantern import clientpull
from lantern.engine import build_graph
from lantern.security import scan

RULE = "LW-SERVER-IMPORT-IN-CLIENT"

PACKAGE = '{"name": "shop", "dependencies": {"next": "15.0.0", "react": "19.0.0", "stripe": "17.0.0"}}\n'
TSCONFIG = '{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./*"]}}}\n'

APP = {
    "package.json": PACKAGE,
    "tsconfig.json": TSCONFIG,
    # ---- dangerous: a client file imports the server's file
    "app/billing/Button.tsx": '"use client";\nimport { charge } from "@/lib/pay";\n\n'
                              "export function Button() {\n  return <button onClick={() => charge(5)}>Pay</button>;\n}\n",
    "lib/pay.ts": 'import Stripe from "stripe";\n\n'
                  "const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);\n\n"
                  "export async function charge(amount: number) {\n"
                  '  return stripe.paymentIntents.create({ amount, currency: "usd" });\n}\n',
    # ---- dangerous: through a file in between
    "app/team/Members.tsx": '"use client";\nimport { listMembers } from "../../lib/members";\n\n'
                            "export function Members() {\n  listMembers();\n  return <ul />;\n}\n",
    "lib/members.ts": 'import { admin } from "./admin";\n\nexport function listMembers() {\n  return admin();\n}\n',
    "lib/admin.ts": "// the service role skips every row rule\n"
                    'const key = process.env["SUPABASE_SERVICE_ROLE_KEY"];\n\n'
                    "export function admin() {\n  return fetch(process.env.API_BASE + \"/rows\", "
                    "{ headers: { apikey: key! } });\n}\n",
    # ---- dangerous: the client file reads the secret setting itself
    "app/chat/Box.tsx": "'use client'\n\nexport function Box() {\n"
                        "  const send = () => fetch(\"https://api.model.test/v1\", "
                        "{ headers: { authorization: process.env.OPENAI_API_KEY! } });\n"
                        "  return <button onClick={send}>Ask</button>;\n}\n",
    # ---- dangerous: through a file that only hands names on
    "app/dash/Dash.tsx": '"use client";\nimport { Chart } from "@/components";\n\n'
                         "export function Dash() {\n  return <Chart />;\n}\n",
    "components/index.ts": 'export * from "./Chart";\nexport { rows } from "../lib/rows";\n',
    "components/Chart.tsx": "export function Chart() {\n  return <svg />;\n}\n",
    "lib/rows.ts": "const { DATABASE_URL, LOG_LEVEL } = process.env;\n\n"
                   "export function rows() {\n  return [DATABASE_URL, LOG_LEVEL];\n}\n",
    # ---- dangerous: imported for what it does when loaded
    "app/boot/Boot.tsx": '"use client";\nimport "../../lib/init";\n\nexport function Boot() {\n  return null;\n}\n',
    "lib/init.ts": "export const signer = { secret: process.env.SESSION_SECRET };\n",
    # ---- safe: only a type is imported, said on the statement or on the name
    "app/safe/Types.tsx": '"use client";\nimport type { Order } from "@/lib/orders";\n'
                          'import { type Line, money } from "@/lib/money";\n\n'
                          "export function Types(p: { order: Order; line: Line }) {\n  return <p>{money(1)}</p>;\n}\n",
    "lib/orders.ts": "export type Order = { id: string };\n"
                     "export const load = () => fetch(process.env.ORDERS_API_KEY!);\n",
    "lib/money.ts": 'import type { Order } from "./orders";\n\nexport type Line = { order: Order };\n'
                    "export const money = (n: number) => `$${n}`;\n",
    # ---- safe: the name that is imported is only a type in the file it comes from
    "app/safe/Plan.tsx": '"use client";\nimport { Plan } from "@/lib/plans";\n\n'
                         "export function PlanName(p: { plan: Plan }) {\n  return <p>{p.plan.name}</p>;\n}\n",
    "lib/plans.ts": "export interface Plan { name: string }\n"
                    "export const all = () => fetch(process.env.PLANS_API_KEY!);\n",
    # ---- safe: a Server Action is called over the network, its file is not handed over
    "app/safe/Form.tsx": '"use client";\nimport { save } from "../actions";\n\n'
                         "export function Form() {\n  return <form action={save} />;\n}\n",
    "app/actions.ts": '"use server";\n\nexport async function save() {\n'
                      "  return fetch(process.env.BILLING_API_KEY!);\n}\n",
    # ---- safe: the file says it is for the server only, so a page that pulls it in does not build
    "app/safe/Guarded.tsx": '"use client";\nimport { audit } from "@/lib/audit";\n\n'
                            "export function Guarded() {\n  audit();\n  return null;\n}\n",
    "lib/audit.ts": 'import "server-only";\n\nexport const audit = () => fetch(process.env.AUDIT_API_KEY!);\n',
    # ---- safe: settings that are no secrets, a secret's name in a remark or a text
    "app/safe/Plain.tsx": '"use client";\nimport { base } from "@/lib/site";\n\n'
                          "// process.env.STRIPE_SECRET_KEY is read on the server only\n"
                          "export function Plain() {\n"
                          '  const hint = "set process.env.OPENAI_API_KEY on the server";\n'
                          "  return <p title={hint}>{base}{process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY}"
                          "{process.env.NODE_ENV}</p>;\n}\n",
    "lib/site.ts": 'export const base = process.env.NEXT_PUBLIC_SITE ?? process.env.PORT ?? "";\n',
    # ---- safe: the server's own files import what they like
    "app/page.tsx": 'import { charge } from "@/lib/pay";\nimport { admin } from "@/lib/admin";\n\n'
                    "export default async function Page() {\n  await admin();\n  return <p>{String(charge)}</p>;\n}\n",
    "app/api/pay/route.ts": 'import { charge } from "@/lib/pay";\n\n'
                            "export async function POST() {\n  return Response.json(await charge(5));\n}\n",
}


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
    return root


def ours(root):
    return sorted((f for f in scan(build_graph(root))["findings"] if f["rule"] == RULE), key=lambda f: f["file"])


def test_a_file_that_reads_a_secret_setting_and_is_pulled_into_the_browsers_side_is_named(tmp_path):
    """Dangerous: a client file imports the server's file, reaches it through a file in between, reads the setting
    itself, reaches it through a file that only hands names on, or imports it for what it does when loaded. Safe
    twins: only a type is imported (said on the statement, on the name, or by what the other file exports), a
    Server Action's file, a file that says `server-only`, settings that are no secrets, a secret's name in a
    remark or a text, and the server's own pages and routes importing the same files."""
    found = ours(_write(tmp_path, APP))
    assert [(f["file"], f["line"], f["pulled"]["settings"], f["pulled"]["path"]) for f in found] == [
        ("app/chat/Box.tsx", 4, ["OPENAI_API_KEY"], ["app/chat/Box.tsx"]),
        ("lib/admin.ts", 2, ["SUPABASE_SERVICE_ROLE_KEY"], ["app/team/Members.tsx", "lib/members.ts", "lib/admin.ts"]),
        ("lib/init.ts", 1, ["SESSION_SECRET"], ["app/boot/Boot.tsx", "lib/init.ts"]),
        ("lib/pay.ts", 3, ["STRIPE_SECRET_KEY"], ["app/billing/Button.tsx", "lib/pay.ts"]),
        ("lib/rows.ts", 1, ["DATABASE_URL"], ["app/dash/Dash.tsx", "components/index.ts", "lib/rows.ts"]),
    ]
    for f in found:
        assert f["tool_confidence"] == "LOW" and f["rank"] == "medium" and f["category"] == "exposure", f
        assert f["cwe"] == 200 and f["more_info"].startswith("Heuristic") and f["pulled"]["clients"] == 1
        assert f["pulled"]["handed"] is None and "arrives there empty unless the build hands it over" in f["more_info"]
        assert f["snippet"] == f["pulled"]["settings"][0]
        assert f["scenario"]["steps"] and "downloaded" in " ".join(f["scenario"]["steps"])
    by = {f["file"]: f for f in found}
    assert by["lib/pay.ts"]["title"] == ("lib/pay.ts reads the secret setting STRIPE_SECRET_KEY and is pulled into "
                                         "the browser's side by app/billing/Button.tsx")
    assert by["app/chat/Box.tsx"]["title"] == ('app/chat/Box.tsx begins with "use client" and reads the secret '
                                               "setting OPENAI_API_KEY")
    assert "app/team/Members.tsx → lib/members.ts → lib/admin.ts" in by["lib/admin.ts"]["more_info"]
    assert 'import "server-only"' in by["lib/pay.ts"]["more_info"]


def test_where_the_build_hands_the_setting_to_the_page_the_finding_weighs_more(tmp_path):
    """`env` in `next.config.js` writes the settings it names into the page's code wherever the code reads them.
    Named there, the secret's value is in what visitors download: high. A setting named in a remark of that
    file, or another setting named there, changes nothing."""
    config = ("// env: { SESSION_SECRET: process.env.SESSION_SECRET }\n"
              "module.exports = {\n  reactStrictMode: true,\n"
              "  env: {\n    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,\n    SITE: process.env.SITE,\n  },\n};\n")
    found = {f["file"]: f for f in ours(_write(tmp_path, {**APP, "next.config.js": config}))}
    pay, init = found["lib/pay.ts"], found["lib/init.ts"]
    assert pay["rank"] == "high" and pay["pulled"]["handed"] == {"file": "next.config.js", "line": 5}
    assert pay["title"].endswith("by app/billing/Button.tsx, and next.config.js hands that setting to the page's code")
    assert "arrives there empty" not in pay["more_info"] and "next.config.js line 5" in pay["more_info"]
    assert init["rank"] == "medium" and init["pulled"]["handed"] is None
    assert {f["rank"] for f in found.values()} == {"high", "medium"} and len(found) == 5


def test_every_client_file_that_reaches_the_file_is_counted_and_the_nearest_is_named(tmp_path):
    more = {**APP,
            "app/billing/Refund.tsx": '"use client";\nimport { listMembers } from "@/lib/members";\n'
                                      'import { charge } from "@/lib/pay";\n\n'
                                      "export function Refund() {\n  listMembers();\n  return <p>{String(charge)}</p>;\n}\n"}
    found = {f["file"]: f for f in ours(_write(tmp_path, more))}
    assert found["lib/pay.ts"]["pulled"]["clients"] == 2 and found["lib/admin.ts"]["pulled"]["clients"] == 2
    assert found["lib/pay.ts"]["pulled"]["path"] == ["app/billing/Button.tsx", "lib/pay.ts"]     # the first by name
    assert "1 other file that begins with \"use client\" reaches it too" in found["lib/pay.ts"]["more_info"]


CHANGED = [
    # (the file that changes, the safe text, the dangerous text, the file the finding then stands in)
    ("app/safe/Types.tsx", 'import type { Order } from "@/lib/orders";', 'import { load } from "@/lib/orders";',
     "lib/orders.ts"),
    ("app/safe/Plan.tsx", 'import { Plan } from "@/lib/plans";', 'import { Plan, all } from "@/lib/plans";',
     "lib/plans.ts"),
    ("app/actions.ts", '"use server";\n', "", "app/actions.ts"),
    ("lib/audit.ts", 'import "server-only";\n', "", "lib/audit.ts"),
    ("lib/site.ts", "process.env.PORT", "process.env.SITE_PASSWORD", "lib/site.ts"),
    ("app/safe/Plain.tsx", "{process.env.NODE_ENV}", "{process.env.ADMIN_PASSWORD}", "app/safe/Plain.tsx"),
]


@pytest.mark.parametrize("rel,safe,dangerous,where", CHANGED, ids=[c[0] for c in CHANGED])
def test_one_changed_part_makes_a_safe_twin_dangerous(tmp_path, rel, safe, dangerous, where):
    assert APP[rel].count(safe) == 1
    found = ours(_write(tmp_path, {**APP, rel: APP[rel].replace(safe, dangerous)}))
    assert len(found) == 6 and where in [f["file"] for f in found], [f["file"] for f in found]


def test_what_a_file_reads(tmp_path):
    reads = clientpull.secret_reads
    assert reads("const a = process.env.STRIPE_SECRET_KEY;\n", "a.ts") == [(1, "STRIPE_SECRET_KEY")]
    assert reads("\n\nconst a = import.meta.env['DB_PASSWORD'];\n", "a.ts") == [(3, "DB_PASSWORD")]
    assert reads('const a = Deno.env.get("JWT_SECRET");\n', "a.ts") == [(1, "JWT_SECRET")]
    assert reads("const { A, DATABASE_URL: url, SMTP_PASSWORD } = process.env;\n", "a.ts") == [
        (1, "DATABASE_URL"), (1, "SMTP_PASSWORD")]
    assert reads("const a = process.env.NEXT_PUBLIC_API_KEY;\n", "a.ts") == []           # a public name: other rules
    assert reads("const a = process.env.STRIPE_PUBLISHABLE_KEY;\n", "a.ts") == []        # a key made for pages
    assert reads("const a = env.STRIPE_SECRET_KEY;\n", "a.ts") == []                     # an object of the project's
    assert reads("// process.env.STRIPE_SECRET_KEY\n/* process.env.JWT_SECRET */\n", "a.ts") == []
    assert reads('const hint = "process.env.STRIPE_SECRET_KEY";\n', "a.ts") == []
    assert reads("const a = process.env.stripe_secret_key;\n", "a.ts") == []             # not a setting's name


def test_files_built_to_hold_the_check_up_are_read_in_bounded_time(tmp_path):
    import time
    ring = {f"lib/r{i}.ts": f'import {{ f{(i + 1) % 400} }} from "./r{(i + 1) % 400}";\n'
                            f"export const f{i} = () => f{(i + 1) % 400};\n" for i in range(400)}
    ring["lib/r399.ts"] += "export const k = process.env.RING_SECRET;\n"
    files = {"package.json": PACKAGE, "tsconfig.json": TSCONFIG,
             "app/Start.tsx": '"use client";\nimport { f0 } from "@/lib/r0";\nexport const Start = () => f0;\n',
             "lib/wide.ts": "export const w = [" + "process.env.A_SECRET, " * 2000 + "];\n",
             "app/Wide.tsx": '"use client";\nimport { w } from "@/lib/wide";\nexport const Wide = () => w;\n',
             **ring}
    g = build_graph(_write(tmp_path, files))
    t = time.perf_counter()
    found = clientpull.pulled(g)
    assert time.perf_counter() - t < 20
    by = {f["file"]: f for f in found}
    assert by["lib/r399.ts"]["pulled"]["path"][0] == "app/Start.tsx" and len(by["lib/r399.ts"]["pulled"]["path"]) <= 12
    assert by["lib/wide.ts"]["pulled"]["settings"] == ["A_SECRET"]
    # one line of 20,000 reads, and one of 20,000 texts that only name a setting (the JS/TS reader takes a file like
    # these for a built bundle and does not read it, so the reading is asked directly)
    t = time.perf_counter()
    assert clientpull.secret_reads("export const w = [" + "process.env.A_SECRET, " * 20000 + "];\n", "w.ts") == [
        (1, "A_SECRET")]
    assert clientpull.secret_reads("export const w = [" + '"process.env.A_SECRET", ' * 20000 + "];\n", "w.ts") == []
    assert time.perf_counter() - t < 20
