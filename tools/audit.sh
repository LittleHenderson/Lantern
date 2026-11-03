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

step "environment"
"$PY" --version; lantern --version || { echo "lantern not installed: pip install -e \".[scan,dev]\""; exit 2; }

step "unit and integration tests"
check "pytest" "$PY" -m pytest -q

step "Lantern audits itself"
check "self-audit: no open critical/high/medium" lantern analyze . --out "$W/self" --fail-on medium

step "sample apps"
check "shop (React + FastAPI) analyzes" lantern analyze tests/fixtures/shop --out "$W/shop"
check "shop: 2 critical findings, shell path from /admin" "$PY" - "$W/shop" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1] + "/security.json"))
assert s["counts"]["critical"] == 2, s["counts"]
b602 = next(f for f in s["findings"] if f["rule"] == "B602")
assert b602["ui_path"] and b602["ui_path"][0].endswith("Admin::Admin"), b602["ui_path"]
EOF
check "nextapp (Next.js + Supabase) analyzes" lantern analyze tests/fixtures/nextapp --out "$W/nx"
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
  check "viewer: no JS errors (desktop + phone)" node tools/viewer_smoke.js "$W/shop/report.html" "$W/shot"
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
  # every string and number in the data carries an HTML payload: none of it may reach the page as markup
  check "viewer: poisoned report data stays text (every field escaped, content policy holds)" \
    bash -c "'$PY' tools/poison_report.py '$W/shop-src/.lantern/report.html' '$W/poison/report.html' && node tools/viewer_smoke.js '$W/poison/report.html' '$W/pshot'"
  # the same for scenarios alone, with the rest intact so the finding cards and Fix page that show them are drawn
  check "viewer: poisoned scenarios and headings stay text (finding cards, Fix page, Scenario lens)" \
    bash -c "'$PY' tools/poison_report.py '$W/shop-src/.lantern/report.html' '$W/poison-sc/report.html' --only scenario,dropped_scenarios,headline && node tools/viewer_smoke.js '$W/poison-sc/report.html' '$W/sshot'"
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
    check "cloud website: no JS errors, poisoned run data stays text (desktop + phone, light + dark)" \
      node tools/cloud_site_smoke.js http://127.0.0.1:8872/ "$C/token" "$C/shot"
    kill $CPID 2>/dev/null; wait $CPID 2>/dev/null
  fi
fi

printf '\n%s\n' "$([ $FAILS -eq 0 ] && echo 'ALL PASS' || echo "$FAILS FAILED")  (work dir: $W)"
exit $FAILS
