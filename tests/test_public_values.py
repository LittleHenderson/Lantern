"""`LW-CLIENT-ENV-SECRET`: a setting every visitor's browser gets, whose value is a secret (roadmap of 2026-11-14,
stage 5).

A setting whose name begins with `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `PUBLIC_` and the like is copied into the
JavaScript every visitor downloads. `LW-PUBLIC-SECRET` reads the name (`NEXT_PUBLIC_STRIPE_SECRET_KEY`). This rule
reads what the setting is given, where the name says nothing: an address that carries a password, a key of a shape
only servers hold, or the value of another setting whose name is a secret's. It reads lines, runs nothing, and
never repeats the value. A heuristic until it is measured, so each dangerous example stands beside twins that must
stay quiet.

No value in this file is a real secret, and none is written out whole: each is put together when the test runs.
"""
import json
import time

from lantern import publicvalues
from lantern.engine import build_graph
from lantern.security import scan

RULE = "LW-CLIENT-ENV-SECRET"
PW = "t9" + "Rk-" + "wq7Lm2"                               # a password that is no placeholder word
PAY = "sk_" + "live_" + "51Hq" + "Zx9" * 8                 # the shape of a payment service's server key
PAGE = "pk_" + "live_" + "51Hq" + "Zx9" * 8                # the shape of the key that is made for the page
CODE = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0" + "k1L2m3N4o5P6q7R8"       # the shape of a code host's token

ENV_PRODUCTION = f"""# what the build of the website gets
NEXT_PUBLIC_API_BASE=https://deploy:{PW}@api.shop.test/v1
NEXT_PUBLIC_SITE=https://shop.test
NEXT_PUBLIC_DOCS=https://docs.shop.test/@team/start
NEXT_PUBLIC_PAY_KEY={PAGE}
PAY_KEY={PAY}
# NEXT_PUBLIC_OLD=https://deploy:{PW}@old.shop.test/v1
NEXT_PUBLIC_DEMO=https://demo:demo@demo.shop.test
NEXT_PUBLIC_SUPABASE_ANON_KEY=${{SUPABASE_SERVICE_ROLE_KEY}}
"""

ENV = f"""VITE_DB="postgresql://app:{PW}@db.internal:5432/shop"
VITE_LIVE=wss://app:${{WS_PASSWORD}}@live.shop.test/socket
VITE_LOCAL=postgresql://postgres:{PW}@localhost:5432/dev
VITE_PAGE_KEY=$STRIPE_PUBLISHABLE_KEY
VITE_API=${{API_URL}}
DB=postgresql://app:{PW}@db.internal:5432/shop
"""

FILLER_KEY = "sk_live_" + "x" * 24   # a key's place kept by filler, written while the test runs
ENV_EXAMPLE = """NEXT_PUBLIC_API_BASE=https://user:password@api.example.com/v1
NEXT_PUBLIC_DB=postgres://<user>:<password>@db.example.com/shop
EXPO_PUBLIC_PAY=""" + FILLER_KEY + """
VITE_PAY=your-key-here
"""

MOBILE_ENV = f"""export EXPO_PUBLIC_API=https://api.shop.test
export EXPO_PUBLIC_PAY={PAY}
"""

COMPOSE = """services:
  web:
    build:
      context: .
      args:
        NEXT_PUBLIC_BACKEND: ${DATABASE_URL}
        NEXT_PUBLIC_MAPS: ${MAPS_API_KEY}
    environment:
      - VITE_PAY=${STRIPE_SECRET_KEY:-}
      - VITE_API=${API_URL}
      - PAY=${STRIPE_SECRET_KEY}
"""

WORKFLOW = """name: deploy
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm run build
        env:
          NEXT_PUBLIC_SUPABASE_KEY: ${{ secrets.SUPABASE_SERVICE_ROLE_KEY }}
          NEXT_PUBLIC_FIREBASE: ${{ secrets.FIREBASE_API_KEY }}
          NEXT_PUBLIC_API: ${{ secrets.API_URL }}
          NEXT_PUBLIC_ANON: ${{ secrets.SUPABASE_ANON_KEY }}
          SUPABASE_KEY: ${{ secrets.SUPABASE_SERVICE_ROLE_KEY }}
"""

NEXT_CONFIG = """module.exports = {
  env: {
    NEXT_PUBLIC_PAY: process.env.STRIPE_SECRET_KEY,
    NEXT_PUBLIC_SITE: process.env.SITE_URL,
    NEXT_PUBLIC_PAGE_KEY: process.env.STRIPE_PUBLISHABLE_KEY,
    PAY: process.env.STRIPE_SECRET_KEY,
  },
};
"""

VITE_CONFIG = """import { defineConfig } from "vite";

export default defineConfig({
  define: {
    "import.meta.env.VITE_ADMIN": JSON.stringify(process.env.ADMIN_PASSWORD),
    "import.meta.env.VITE_MODE": JSON.stringify(process.env.NODE_ENV),
  },
});
"""

SETTINGS_TS = """interface Env {
  NEXT_PUBLIC_API_BASE: string;
  NEXT_PUBLIC_PAY: typeof process.env.STRIPE_SECRET_KEY;
}

export const live = process.env.NEXT_PUBLIC_MODE === process.env.ADMIN_PASSWORD;
export const base = process.env.NEXT_PUBLIC_API_BASE ?? "https://shop.test";
"""

DOCKERFILE = f"""FROM node:22
ARG VITE_TOKEN={CODE}
ENV NEXT_PUBLIC_SITE=https://shop.test
ENV VITE_DB postgresql://app:{PW}@db.internal/shop
ARG NEXT_PUBLIC_BUILD
RUN npm run build
"""

FLY_TOML = f"""app = "shop"

[env]
  PUBLIC_API = "https://svc:{PW}@internal.shop.test"
  PUBLIC_SITE = "https://shop.test"
"""

APP = {".env.production": ENV_PRODUCTION, ".env": ENV, ".env.example": ENV_EXAMPLE, "mobile/.env": MOBILE_ENV,
       "docker-compose.yml": COMPOSE, ".github/workflows/deploy.yml": WORKFLOW, "next.config.js": NEXT_CONFIG,
       "vite.config.ts": VITE_CONFIG, "web/src/settings.ts": SETTINGS_TS, "Dockerfile": DOCKERFILE,
       "fly.toml": FLY_TOML, "web/package.json": '{"name": "web", "dependencies": {"next": "15.0.0"}}\n',
       "web/src/page.tsx": "export default function Page() {\n  return <p>{process.env.NEXT_PUBLIC_SITE}</p>;\n}\n"}


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")


def at(rel: str, start: str) -> int:
    """The line of `APP[rel]` that begins (after its indent, a dash, `export`, `ARG` or `ENV`) with `start`."""
    [n] = [i for i, line in enumerate(APP[rel].split("\n"), 1) if start in line and not line.lstrip().startswith("#")]
    return n


def test_a_secret_value_under_a_public_name_is_named_and_its_safe_twins_are_not(tmp_path):
    """Dangerous: an address with a password (in a settings file, in quotes, in a Dockerfile's older `ENV NAME value`
    form, in a host's settings file), an address whose password is another setting, a server key by its shape
    (as a build argument), and a public setting filled from a secret one (in a compose file's two forms, a
    workflow's secret store, a framework's settings file, a bundler's `define`, and under a name that looks
    harmless). A server key on a line the secret scan lists (behind `export`, in a phone app's settings) is one
    finding, the secret scan's, which then says the name is a public one. Safe twins: an address with no password, an `@` in a path, a password that is the user name,
    this computer's own address, the key made for the page, a publishable or anon or map key, an address kept in
    the secret store, a server-only name with the same value, a comment, a type, a comparison, a build argument
    with no value, and the placeholders of an example file."""
    _write(tmp_path, APP)
    all_of = scan(build_graph(tmp_path))["findings"]
    found = sorted((f["file"], f["line"], f["snippet"], f["public"]["why"], f["public"].get("from"),
                    f["public"].get("kind")) for f in all_of if f["rule"] == RULE)
    assert found == sorted([
        (".env", at(".env", "VITE_DB="), "VITE_DB", "address-with-password", None, None),
        (".env", at(".env", "VITE_LIVE="), "VITE_LIVE", "address-with-password", "WS_PASSWORD", None),
        (".env.production", at(".env.production", "NEXT_PUBLIC_API_BASE="), "NEXT_PUBLIC_API_BASE",
         "address-with-password", None, None),
        (".env.production", at(".env.production", "NEXT_PUBLIC_SUPABASE_ANON_KEY="), "NEXT_PUBLIC_SUPABASE_ANON_KEY",
         "from-secret", "SUPABASE_SERVICE_ROLE_KEY", None),
        (".github/workflows/deploy.yml", at(".github/workflows/deploy.yml", "NEXT_PUBLIC_SUPABASE_KEY:"),
         "NEXT_PUBLIC_SUPABASE_KEY", "from-secret", "SUPABASE_SERVICE_ROLE_KEY", None),
        ("Dockerfile", at("Dockerfile", "ARG VITE_TOKEN="), "VITE_TOKEN", "key", None, "github-token"),
        ("Dockerfile", at("Dockerfile", "ENV VITE_DB "), "VITE_DB", "address-with-password", None, None),
        ("docker-compose.yml", at("docker-compose.yml", "NEXT_PUBLIC_BACKEND:"), "NEXT_PUBLIC_BACKEND", "from-secret",
         "DATABASE_URL", None),
        ("docker-compose.yml", at("docker-compose.yml", "- VITE_PAY="), "VITE_PAY", "from-secret",
         "STRIPE_SECRET_KEY", None),
        ("fly.toml", at("fly.toml", "PUBLIC_API ="), "PUBLIC_API", "address-with-password", None, None),
        ("next.config.js", at("next.config.js", "NEXT_PUBLIC_PAY:"), "NEXT_PUBLIC_PAY", "from-secret",
         "STRIPE_SECRET_KEY", None),
        ("vite.config.ts", at("vite.config.ts", "VITE_ADMIN"), "VITE_ADMIN", "from-secret", "ADMIN_PASSWORD", None),
    ]), found
    by = {(f["file"], f["snippet"]): f for f in all_of if f["rule"] == RULE}
    one = by[(".env.production", "NEXT_PUBLIC_API_BASE")]
    assert one["tool_confidence"] == "LOW" and one["rank"] == "high" and one["cwe"] == 200
    assert one["category"] == "exposure" and "Heuristic" in one["more_info"]
    assert "NEXT_PUBLIC_API_BASE" in one["title"] and "password" in one["title"] and "browser" in one["title"]
    passed_on = by[("next.config.js", "NEXT_PUBLIC_PAY")]
    assert "STRIPE_SECRET_KEY" in passed_on["title"] and passed_on["rank"] == "medium"     # read from two names
    assert by[("Dockerfile", "VITE_TOKEN")]["rank"] == "high" and "token" in by[("Dockerfile", "VITE_TOKEN")]["title"]
    # one problem, one finding: the key in `mobile/.env` is the secret scan's finding, which says where the key goes
    [key] = [f for f in all_of if f["file"] == "mobile/.env"]
    assert key["category"] == "secret" and key["rule"] != RULE
    assert key["public"] == {"name": "EXPO_PUBLIC_PAY", "why": "key", "kind": "stripe-live-key"}
    assert "EXPO_PUBLIC_PAY, which is built into the app every user installs" in key["more_info"]
    assert "WS_PASSWORD" in by[(".env", "VITE_LIVE")]["more_info"]
    story = one["scenario"]
    assert "the files their browser downloaded" in " ".join(story["steps"])


def test_the_value_is_never_repeated(tmp_path):
    """What Lantern writes down names the setting and says why. The password and the keys themselves are in no
    finding, whole or in part."""
    _write(tmp_path, APP)
    ours = [f for f in scan(build_graph(tmp_path))["findings"] if f["rule"] == RULE]
    said = json.dumps(ours)
    assert ours and PW not in said and PAY not in said and CODE not in said
    assert PAY[8:20] not in said and CODE[6:20] not in said and "deploy:" not in said


def test_what_one_value_reads_as():
    """The reading of one value by itself."""
    why = publicvalues.why
    assert why(f"https://deploy:{PW}@api.shop.test/v1") == {"why": "address-with-password"}
    assert why(f"redis://:{PW}@cache.internal:6379/0") == {"why": "address-with-password"}       # no user name
    assert why(f"mongodb+srv://app:{PW}@cluster0.shop.test/shop?retryWrites=true") == {"why": "address-with-password"}
    assert why("amqp://app:${QUEUE_PASSWORD}@queue.internal") == {"why": "address-with-password",
                                                                  "from": "QUEUE_PASSWORD"}
    assert why("https://app:${{ secrets.DEPLOY_PASSWORD }}@api.shop.test") == {"why": "address-with-password",
                                                                           "from": "DEPLOY_PASSWORD"}
    assert why(PAY) == {"why": "key", "kind": "stripe-live-key"}
    assert why("Bearer " + CODE) == {"why": "key", "kind": "github-token"}
    assert why("${STRIPE_SECRET_KEY}") == {"why": "from-secret", "from": "STRIPE_SECRET_KEY"}
    assert why("$DATABASE_URL") == {"why": "from-secret", "from": "DATABASE_URL"}
    assert why("${DB_PASSWORD:-}") == {"why": "from-secret", "from": "DB_PASSWORD"}
    assert why("${{ secrets.SUPABASE_SERVICE_ROLE_KEY }}") == {"why": "from-secret",
                                                               "from": "SUPABASE_SERVICE_ROLE_KEY"}
    assert why("process.env.ADMIN_PASSWORD") == {"why": "from-secret", "from": "ADMIN_PASSWORD"}
    assert why("JSON.stringify(process.env.ADMIN_PASSWORD)") == {"why": "from-secret", "from": "ADMIN_PASSWORD"}
    assert why("import.meta.env.PRIVATE_KEY") == {"why": "from-secret", "from": "PRIVATE_KEY"}
    for quiet in ("https://shop.test", "https://docs.shop.test/@team/start", "https://demo:demo@demo.shop.test",
                  "mailto:team@shop.test", "https://user:password@api.example.com", "postgres://<user>:<password>@db/x",
                  f"postgresql://postgres:{PW}@localhost:5432/dev", f"http://app:{PW}@127.0.0.1:8000",
                  f"http://app:{PW}@host.docker.internal:8000", "https://shop.test:8443/path", PAGE,
                  FILLER_KEY, "${STRIPE_PUBLISHABLE_KEY}", "${{ secrets.FIREBASE_API_KEY }}",
                  "${{ secrets.API_URL }}", "${NEXT_PUBLIC_API_KEY}", "process.env.SITE_URL", "true", "", "3",
                  "the password is sent by mail", "git@code.shop.test:team/shop.git"):
        assert why(quiet) is None, quiet


def test_one_changed_part_makes_a_safe_twin_dangerous():
    """Each twin is quiet for the one reason it shows: take that away and it is named."""
    read = publicvalues.read

    def names(name, text):
        return [(x["line"], x["name"], x["why"]) for x in read(name, text)]

    assert names(".env", "NEXT_PUBLIC_SITE=https://shop.test\n") == []
    assert names(".env", f"NEXT_PUBLIC_SITE=https://shop:{PW}@shop.test\n") == [
        (1, "NEXT_PUBLIC_SITE", "address-with-password")]
    assert names(".env", f"SITE=https://shop:{PW}@shop.test\n") == []                    # not a public name
    assert names(".env", f"# NEXT_PUBLIC_SITE=https://shop:{PW}@shop.test\n") == []      # a comment
    assert names(".env", f"NEXT_PUBLIC_DEMO=https://demo:{PW}@demo.shop.test\n") == [
        (1, "NEXT_PUBLIC_DEMO", "address-with-password")]
    assert names("docker-compose.yml", "      - VITE_API=${API_URL}\n") == []
    assert names("docker-compose.yml", "      - VITE_API=${API_SECRET}\n") == [(1, "VITE_API", "from-secret")]
    assert names("settings.ts", "const x = { NEXT_PUBLIC_PAY: process.env.STRIPE_SECRET_KEY };\n") == [
        (1, "NEXT_PUBLIC_PAY", "from-secret")]
    assert names("settings.ts", "interface Env {\n  NEXT_PUBLIC_PAY: typeof process.env.STRIPE_SECRET_KEY;\n}\n") == []
    assert names("settings.ts", "if (process.env.NEXT_PUBLIC_MODE === process.env.ADMIN_PASSWORD) {}\n") == []
    assert names("settings.ts", "process.env.NEXT_PUBLIC_MODE = process.env.ADMIN_PASSWORD;\n") == [
        (1, "NEXT_PUBLIC_MODE", "from-secret")]
    assert names("Dockerfile", "ARG NEXT_PUBLIC_BUILD\n") == []
    assert names("Dockerfile", f"ARG NEXT_PUBLIC_BUILD={PAY}\n") == [(1, "NEXT_PUBLIC_BUILD", "key")]
    assert names("notes.md", f"NEXT_PUBLIC_SITE=https://shop:{PW}@shop.test\n") == []     # not a file of settings


def test_a_name_the_older_rule_names_is_said_once(tmp_path):
    """`NEXT_PUBLIC_DATABASE_URL` is a secret by its name: `LW-PUBLIC-SECRET` names it, and this rule adds no second
    finding for the same setting of the same file. In another file, where the older rule does not read the name,
    this one speaks."""
    _write(tmp_path, {".env.production": f"NEXT_PUBLIC_DATABASE_URL=postgresql://app:{PW}@db.internal/shop\n",
                      "Dockerfile": f"FROM node:22\nARG NEXT_PUBLIC_DATABASE_URL=postgresql://app:{PW}@db.internal/shop\n",
                      "web/package.json": '{"name": "web"}\n'})
    found = sorted((f["rule"], f["file"], f["snippet"]) for f in scan(build_graph(tmp_path))["findings"]
                   if f["rule"] in (RULE, "LW-PUBLIC-SECRET"))
    assert found == [("LW-CLIENT-ENV-SECRET", "Dockerfile", "NEXT_PUBLIC_DATABASE_URL"),
                     ("LW-PUBLIC-SECRET", ".env.production", "NEXT_PUBLIC_DATABASE_URL")], found


def test_files_built_to_hold_the_check_up_are_read_in_bounded_time_or_passed_by(tmp_path):
    """A settings file of two hundred thousand lines, a line of five million characters with ten thousand `@`
    signs, and a file over the size that is read: the first two are read in bounded time (the long line is passed
    by), the third is passed by, and the file beside them is still read."""
    many = "".join(f"NEXT_PUBLIC_A{i}=https://shop.test/{i}\n" for i in range(200_000))
    long_line = "NEXT_PUBLIC_LONG=https://" + "a:b@" * 10_000 + "x" * 5_000_000 + "\n"
    large = f"NEXT_PUBLIC_API=https://deploy:{PW}@api.shop.test\n" + "# " + "x" * publicvalues.MOST_FILE + "\n"
    _write(tmp_path, {".env.many": many, ".env.long": long_line, ".env.large": large,
                      ".env.production": f"NEXT_PUBLIC_API=https://deploy:{PW}@api.shop.test\n"})
    t0 = time.monotonic()
    found = publicvalues.public_values(tmp_path)
    took = time.monotonic() - t0
    assert [(f["file"], f["line"]) for f in found] == [(".env.production", 1)], found
    assert took < 20, took
