#!/usr/bin/env bash
# One-command audit check for Lantern. See docs/audit/TEST_PLAN.md.
#   bash tools/audit.sh            # tests, self-audit, samples, determinism, CLI, offline model
#   bash tools/audit.sh --browser  # also drive the viewer in Chromium (needs Node + Playwright)
set -u
cd "$(dirname "$0")/.."
W="$(mktemp -d)"
FAILS=0
PY="${PYTHON:-python}"
step() { printf '\n== %s\n' "$1"; }
ok()   { printf 'PASS  %s\n' "$1"; }
bad()  { printf 'FAIL  %s\n' "$1"; FAILS=$((FAILS + 1)); }
check() { local name="$1"; shift; if "$@" >"$W/log" 2>&1; then ok "$name"; else bad "$name"; tail -20 "$W/log"; fi; }
# Like check, with a time budget in seconds (test checklist 3.3): a sample app that took 0.6 s and now takes a minute is a
# regression even when its results are right. Budgets are ~30x the measured time so slow CI runners pass and a hang or a
# quadratic loop fails. LANTERN_BUDGET_SCALE=2 doubles every budget on a slow machine.
budget() { local name="$1" limit="$2"; shift 2; local t0 t1 el
  limit=$(( limit * ${LANTERN_BUDGET_SCALE:-1} ))
  t0=$(date +%s); if timeout "$limit" "$@" >"$W/log" 2>&1; then t1=$(date +%s); el=$((t1 - t0)); ok "$name (${el}s, budget ${limit}s)"
  else t1=$(date +%s); el=$((t1 - t0)); if [ "$el" -ge "$limit" ]; then bad "$name: TOO SLOW, stopped after ${limit}s"; else bad "$name"; fi; tail -20 "$W/log"; fi; }

step "environment"
"$PY" --version; lantern --version || { echo "lantern not installed: pip install -e \".[scan,dev]\""; exit 2; }

step "unit and integration tests"
check "pytest" "$PY" -m pytest -q

step "Lantern audits itself"
budget "self-audit: no open critical/high/medium" 300 lantern analyze . --out "$W/self" --fail-on medium

step "sample apps"
budget "shop (React + FastAPI) analyzes" 60 lantern analyze tests/fixtures/shop --out "$W/shop"
check "shop: 2 critical findings, shell path from /admin" "$PY" - "$W/shop" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1] + "/security.json"))
assert s["counts"]["critical"] == 2, s["counts"]
b602 = next(f for f in s["findings"] if f["rule"] == "B602")
assert b602["ui_path"] and b602["ui_path"][0].endswith("Admin::Admin"), b602["ui_path"]
EOF
budget "androidapp (Android) analyzes" 60 lantern analyze tests/fixtures/androidapp --out "$W/aa"
check "androidapp: a deep link reaching rawQuery is critical, screens are on the phone" "$PY" - "$W/aa" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1] + "/security.json"))
sql = [f for f in s["findings"] if f["file"].endswith("NoteActivity.java") and f["rule"].endswith("SQL-CONCAT")]
assert len(sql) == 1 and sql[0]["rank"] == "critical", sql
assert s["mobile"]["platform"] == "android"
assert json.load(open(sys.argv[1] + "/readiness.json"))["shape"] == "Android app"
EOF
budget "kotlinapp (Android, Kotlin) analyzes" 60 lantern analyze tests/fixtures/kotlinapp --out "$W/ka"
check "kotlinapp: Kotlin is mapped and a deep link reaching rawQuery is critical" "$PY" - "$W/ka" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1] + "/security.json"))
sql = [f for f in s["findings"] if f["rule"].endswith("SQL-CONCAT")]
assert len(sql) == 1 and sql[0]["rank"] == "critical" and sql[0]["node"].startswith("kt:"), sql
EOF
budget "iosapp (iOS, Swift) analyzes" 60 lantern analyze tests/fixtures/iosapp --out "$W/ia"
check "iosapp: a link reaching a Swift query is critical, graded as an iOS app" "$PY" - "$W/ia" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1] + "/security.json"))
sql = [f for f in s["findings"] if f["rule"] == "LI-SQL-CONCAT"]
assert len(sql) == 1 and sql[0]["rank"] == "critical" and sql[0]["node"].startswith("sw:"), sql
assert s["mobile"]["platform"] == "ios"
assert json.load(open(sys.argv[1] + "/readiness.json"))["shape"] == "iOS app"
EOF
budget "flutterapp (Flutter, Dart) analyzes" 60 lantern analyze tests/fixtures/flutterapp --out "$W/fa"
check "flutterapp: Dart is mapped and a link reaching a Dart query is critical" "$PY" - "$W/fa" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1] + "/security.json"))
sql = [f for f in s["findings"] if f["rule"] == "LF-SQL-CONCAT"]
assert len(sql) == 1 and sql[0]["rank"] == "critical" and sql[0]["node"].startswith("dt:"), sql
EOF
budget "rnapp (React Native, Expo) analyzes" 60 lantern analyze tests/fixtures/rnapp --out "$W/ra"
check "rnapp: a link reaching an expo-sqlite query is critical, graded as a React Native app" "$PY" - "$W/ra" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1] + "/security.json"))
sql = [f for f in s["findings"] if f["rule"] == "LN-SQL-CONCAT"]
assert len(sql) == 1 and sql[0]["rank"] == "critical", sql
assert s["mobile"]["platform"] == "react-native"
assert json.load(open(sys.argv[1] + "/readiness.json"))["shape"] == "React Native app"
EOF
budget "csharpapp (ASP.NET + .NET MAUI) analyzes" 60 lantern analyze tests/fixtures/csharpapp --out "$W/ca"
check "csharpapp: the phone's search reaching server SQL is critical, graded as a .NET MAUI app" "$PY" - "$W/ca" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1] + "/security.json"))
sql = [f for f in s["findings"] if f["rule"] == "LC-SQL-CONCAT" and f["rank"] == "critical"]
assert len(sql) == 2 and all(f["node"].startswith("cs:") for f in sql), sql
assert json.load(open(sys.argv[1] + "/readiness.json"))["shape"] == ".NET MAUI app"
EOF
budget "phpapp (Laravel + React + a plain PHP page) analyzes" 60 lantern analyze tests/fixtures/phpapp --out "$W/pa"
check "phpapp: the React search reaching Laravel raw SQL is critical, the legacy page is checked" "$PY" - "$W/pa" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1] + "/security.json"))
sql = [f for f in s["findings"] if f["rule"] == "LH-SQL-CONCAT" and f["rank"] == "critical"]
assert {f["file"] for f in sql} == {"app/Http/Controllers/NoteController.php", "public/legacy/login.php"}, sql
assert any(f["ui_path"] for f in sql), sql
EOF
budget "rubyapp (Rails + React + Sinatra) analyzes" 60 lantern analyze tests/fixtures/rubyapp --out "$W/ru"
check "rubyapp: the React search reaching interpolated SQL is critical, the skipped login is reported" "$PY" - "$W/ru" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1] + "/security.json"))
sql = [f for f in s["findings"] if f["rule"] == "LB-SQL-INTERP" and f["rank"] == "critical"]
assert [f["node"] for f in sql] == ["rb:Api.NotesController.search"] and sql[0]["ui_path"], sql
assert any(f["rule"] == "LW-AUTH-MISSING" and f["node"] == "rb:Api.NotesController.destroy" for f in s["findings"])
EOF
budget "cppapp (C++ web server + C tool + React) analyzes" 60 lantern analyze tests/fixtures/cppapp --out "$W/cx"
check "cppapp: the React search reaching sprintf-built SQL is critical, the C tool's shell and format strings too" "$PY" - "$W/cx" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1] + "/security.json"))
crit = {(f["rule"], f["file"]) for f in s["findings"] if f["rank"] == "critical"}
assert {("LX-SQL-BUILT", "server/note_store.cpp"), ("LX-EXEC", "server/main.cpp"), ("LX-EXEC", "tools/backup.c"),
        ("LX-FORMAT", "tools/backup.c")} <= crit, crit
assert any(f["rule"] == "LX-SQL-BUILT" and f["ui_path"] for f in s["findings"])
EOF
budget "nextapp (Next.js + Supabase) analyzes" 60 lantern analyze tests/fixtures/nextapp --out "$W/nx"
check "nextapp: auth, RLS, and service-role findings" "$PY" - "$W/nx" <<'EOF'
import json, sys
rules = {f["rule"] for f in json.load(open(sys.argv[1] + "/security.json"))["findings"]}
assert {"LW-AUTH-MISSING", "LW-NO-RLS"} <= rules, rules
assert rules & {"LW-PUBLIC-SECRET", "LW-SERVICE-ROLE"}, rules
EOF

step "evidence digest is reproducible and detects change"
R="$W/repo"; mkdir -p "$R"
printf 'import hashlib\n\ndef h(x):\n    return hashlib.md5(x).hexdigest()\n' > "$R/app.py"
printf '.lantern/\n' > "$R/.gitignore"
git -C "$R" init -q && git -C "$R" add -A && git -C "$R" -c user.name=a -c user.email=a@b commit -qm init
lantern analyze "$R" >/dev/null 2>&1
check "verify: MATCH on the same commit" lantern verify "$R" --report "$R/.lantern/evidence.html"
sed -i.bak 's/md5/sha256/' "$R/app.py" && rm -f "$R/app.py.bak"
git -C "$R" -c user.name=a -c user.email=a@b commit -qam change
if lantern verify "$R" --report "$R/.lantern/evidence.html" >/dev/null 2>&1; then bad "verify: DIFFERENT after a change"; else ok "verify: DIFFERENT after a change"; fi

step "command-line surface"
check "starter preview" lantern starter tests/fixtures/shop --out "$W/shop"
check "evidence rebuild" lantern evidence tests/fixtures/shop --out "$W/shop"
if lantern accept tests/fixtures/shop nope --out "$W/shop" --reason "unknown finding id test" >/dev/null 2>&1; then
  bad "accept rejects unknown ids"; else ok "accept rejects unknown ids"; fi

step "offline model end to end"
PORT=$("$PY" -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1])")
"$PY" tools/fake_model.py "$PORT" & FAKE=$!
sleep 1
cp -r tests/fixtures/shop "$W/shop-src"
lantern analyze "$W/shop-src" >/dev/null 2>&1
check "explain with the fake model" lantern explain "$W/shop-src" --model openai-compatible/demo \
  --base-url "http://127.0.0.1:$PORT/v1" --node web/src/pages/Admin::BackupButton
kill "$FAKE" 2>/dev/null
check "explanation validated" "$PY" - "$W/shop-src" <<'EOF'
import json, sys
e = json.load(open(sys.argv[1] + "/.lantern/explanations.json"))["explanations"]
assert any(r.get("validated") for r in e.values()), {k: r.get("validation_errors") for k, r in e.items()}
EOF

if [ "${1:-}" = "--browser" ]; then
  step "browser"
  check "viewer: no JS errors, accessible (axe + keyboard), desktop light + phone dark" node tools/viewer_smoke.js "$W/shop/report.html" "$W/shot"
  # the same report in the other browser engines Playwright ships (CI: LANTERN_BROWSERS="firefox webkit"; needs
  # `npx playwright install firefox webkit`). Safari is WebKit; a CSS feature Chromium has and Safari lacks shows here.
  for eng in ${LANTERN_BROWSERS:-}; do
    PW_BROWSER=$eng check "viewer in $eng: no JS errors, accessible" node tools/viewer_smoke.js "$W/shop/report.html" "$W/shot-$eng"
  done
  H="$W/hostile"; mkdir -p "$H"
  cat > "$H/main.py" <<'EOF'
from fastapi import FastAPI

app = FastAPI()


@app.get("/<!--<script>")
def broken():
    """Ordinary docstring <!--<script> </script><img src=x onerror=alert(1)>"""
    return 1
EOF
  lantern analyze "$H" >/dev/null 2>&1
  check "viewer: hostile docstrings and routes can't blank or hijack the report" \
    node tools/viewer_smoke.js "$H/.lantern/report.html" "$W/hshot"
  for eng in ${LANTERN_BROWSERS:-}; do
    PW_BROWSER=$eng check "viewer in $eng: hostile data stays text" node tools/viewer_smoke.js "$H/.lantern/report.html" "$W/hshot-$eng"
  done
  # every string and number in the data carries an HTML payload: none of it may reach the page as markup
  check "viewer: poisoned report data stays text (every field escaped, content policy holds)" \
    bash -c "'$PY' tools/poison_report.py '$W/shop-src/.lantern/report.html' '$W/poison/report.html' && node tools/viewer_smoke.js '$W/poison/report.html' '$W/pshot'"
  # the same for scenarios alone, with the rest intact so the finding cards and Fix page that show them are drawn
  check "viewer: poisoned scenarios and headings stay text (finding cards, Fix page, Scenario lens)" \
    bash -c "'$PY' tools/poison_report.py '$W/shop-src/.lantern/report.html' '$W/poison-sc/report.html' --only scenario,dropped_scenarios,headline && node tools/viewer_smoke.js '$W/poison-sc/report.html' '$W/sshot'"
  # an Android app: the "On the phone" card, phone stories and entry details, poisoned, with the platform kept
  check "viewer: poisoned Android data stays text (On the phone card, screens, stories)" \
    bash -c "'$PY' tools/poison_report.py '$W/aa/report.html' '$W/poison-aa/report.html' --only mobile,detail,headline,scenario && node tools/viewer_smoke.js '$W/poison-aa/report.html' '$W/ashot'"
  # an iOS app: the same card and stories with iPhone words, poisoned
  check "viewer: poisoned iOS data stays text (On the phone card, screens, links)" \
    bash -c "'$PY' tools/poison_report.py '$W/ia/report.html' '$W/poison-ia/report.html' --only mobile,detail,headline,scenario && node tools/viewer_smoke.js '$W/poison-ia/report.html' '$W/ishot'"
  # a React Native app: the same card with app.json words, poisoned
  check "viewer: poisoned React Native data stays text (On the phone card, screens, links)" \
    bash -c "'$PY' tools/poison_report.py '$W/ra/report.html' '$W/poison-ra/report.html' --only mobile,detail,headline,scenario && node tools/viewer_smoke.js '$W/poison-ra/report.html' '$W/rshot'"
  # a PHP app: Laravel routes, a legacy page and Blade, poisoned
  check "viewer: poisoned PHP data stays text (routes, pages, findings)" \
    bash -c "'$PY' tools/poison_report.py '$W/pa/report.html' '$W/poison-pa/report.html' --only detail,headline,scenario && node tools/viewer_smoke.js '$W/poison-pa/report.html' '$W/pshot2'"
  # a Ruby app: Rails routes, a Sinatra block and ERB, poisoned
  check "viewer: poisoned Ruby data stays text (routes, findings)" \
    bash -c "'$PY' tools/poison_report.py '$W/ru/report.html' '$W/poison-ru/report.html' --only detail,headline,scenario && node tools/viewer_smoke.js '$W/poison-ru/report.html' '$W/rbshot'"
  # a C++ server and a C tool, poisoned
  check "viewer: poisoned C/C++ data stays text (routes, programs, findings)" \
    bash -c "'$PY' tools/poison_report.py '$W/cx/report.html' '$W/poison-cx/report.html' --only detail,headline,scenario && node tools/viewer_smoke.js '$W/poison-cx/report.html' '$W/cxshot'"
  # a .NET MAUI app with its ASP.NET server: screens, links and the phone-to-server path, poisoned
  check "viewer: poisoned .NET MAUI data stays text (screens, links, phone-to-server path)" \
    bash -c "'$PY' tools/poison_report.py '$W/ca/report.html' '$W/poison-ca/report.html' --only mobile,detail,headline,scenario && node tools/viewer_smoke.js '$W/poison-ca/report.html' '$W/cshot'"
  # the live app: the test sheet (sandboxed run), the terminal drawer, a screenshot in Ask Lantern, a pack toggle
  A="$W/app"; mkdir -p "$A"; cp -r tests/fixtures/shop "$A/shop"
  "$PY" - "$A/shot.png" <<'PYEOF'
import sys
from PIL import Image, ImageDraw, ImageFont
img = Image.new("RGB", (640, 120), "white")
try:
    font = ImageFont.truetype("DejaVuSans-Bold.ttf", 44)
except OSError:
    font = ImageFont.load_default(size=44)
ImageDraw.Draw(img).text((20, 30), "LANTERN SMOKE 7351", fill="black", font=font)
img.save(sys.argv[1])
PYEOF
  EXPECT=(); command -v tesseract >/dev/null && EXPECT=(--expect-text 7351)
  LANTERN_HOME="$A/home" LANTERN_OFFLINE=1 LANTERN_SANDBOX="${LANTERN_SANDBOX:-subprocess}" \
    lantern serve "$A/shop" --no-open --port 8871 > "$A/serve.log" 2>&1 &
  SPID=$!
  for _ in $(seq 100); do grep -q 'token=' "$A/serve.log" && break; sleep 0.2; done
  URL="$(grep -o 'http://[^ ]*token=[^ ]*' "$A/serve.log" | head -1)"
  check "app: test sheet, terminal drawer, screenshot upload and pack toggle work with no JS errors" \
    node tools/viewer_smoke.js --app "$URL" "$W/app" --image "$A/shot.png" "${EXPECT[@]}"
  cat "$W/log"
  kill $SPID 2>/dev/null; wait $SPID 2>/dev/null
  # the cloud website: signed out, sign-in sheet, My runs, progress, report; every run field carries an HTML payload
  if "$PY" -c "import fastapi, httpx, uvicorn" 2>/dev/null; then
    C="$W/cloud"; mkdir -p "$C"
    "$PY" tools/cloud_site_demo.py --port 8872 --token-file "$C/token" --poison > "$C/demo.log" 2>&1 &
    CPID=$!
    for _ in $(seq 150); do grep -q '"ready"' "$C/demo.log" && break; sleep 0.2; done
    check "cloud website: no JS errors, accessible, poisoned run data stays text (desktop + phone, light + dark)" \
      node tools/cloud_site_smoke.js http://127.0.0.1:8872/ "$C/token" "$C/shot"
    for eng in ${LANTERN_BROWSERS:-}; do
      PW_BROWSER=$eng check "cloud website in $eng" node tools/cloud_site_smoke.js http://127.0.0.1:8872/ "$C/token" "$C/shot-$eng"
    done
    kill $CPID 2>/dev/null; wait $CPID 2>/dev/null
  fi
fi

printf '\n%s\n' "$([ $FAILS -eq 0 ] && echo 'ALL PASS' || echo "$FAILS FAILED")  (work dir: $W)"
exit $FAILS
