"""Stack lanes: which part of the stack a node lives in.

Four fixed stops, always in this order: ``browser`` → ``frontend`` → ``server`` → ``data``. The viewer
draws them as the "stack strip" ("You are here: Server"), as swimlanes in the Path view, and as a 4-dot
glyph on findings. Assignment is deterministic — it uses only the node id, file path and entry kind — so
it needs no model and no extra parsing.

* ``browser``  — what the visitor's browser shows: page entry points and the app start of a client bundle.
* ``frontend`` — the rest of the client-side code (components, hooks, helpers).
* ``server``   — code that runs on a machine the owner pays for: Python/Go/Rust/Java, Next.js route
                 handlers and ``pages/api``, Express-style handlers, server starts, and any module that
                 lives beside them.
* ``data``     — where the code reaches outside itself: databases, files, the shell, outside services.
                 Only external nodes get this lane; other externals (``json.dumps``) have no lane.
"""

from __future__ import annotations

import re

from .graph import Graph, Node

LANES = ["browser", "frontend", "server", "data"]
LANE_WORDS = {"browser": "Browser", "frontend": "Frontend", "server": "Server", "data": "Data"}

# External names that mean the code is reaching a database, a file, the shell, or a service outside the app.
DATA_RE = re.compile(
    r"^(sqlite3|psycopg2?|pymysql|mysql|asyncpg|sqlalchemy|sqlmodel|peewee|django\.db|pymongo|motor|redis|"
    r"aioredis|boto3|botocore|google\.cloud|azure|stripe|requests|httpx|urllib|aiohttp|smtplib|subprocess|"
    r"os\.(system|popen|remove|unlink|rename|makedirs|mkdir|rmdir)|open|shutil|pathlib|io\.open|pickle|"
    r"openai|anthropic|resend|sendgrid|twilio|mailgun|supabase|firebase|firestore|prisma|@prisma|mongoose|"
    r"pg|mysql2|knex|drizzle|typeorm|sequelize|kysely|ioredis|fs|fs/promises|node:fs|child_process|"
    r"node:child_process|axios|\$?fetch|ky|got|@aws-sdk|aws-sdk|@google-cloud|@supabase|@upstash|"
    r"@vercel/(kv|postgres|blob)|@planetscale|@neondatabase|@libsql|better-sqlite3|level|nodemailer|"
    # Android (Java/Kotlin externals are named Type.method)
    r"FirebaseDatabase|DatabaseReference|FirebaseFirestore|CollectionReference|DocumentReference|FirebaseStorage|"
    r"StorageReference|FirebaseAuth|FirebaseMessaging|SharedPreferences|SQLiteDatabase|RoomDatabase|SmsManager|"
    r"OkHttpClient|Retrofit|RequestQueue|Volley|HttpURLConnection|URL\.openConnection|FileOutputStream|"
    r"MediaRecorder|LocationManager|FusedLocationProviderClient|ContentResolver|TelephonyManager|WorkManager|"
    # C# (.NET externals are named Type.Method)
    r"SqlConnection|SqlCommand|NpgsqlConnection|NpgsqlCommand|MySqlConnection|MySqlCommand|SqliteConnection|"
    r"SqliteCommand|SQLiteConnection|SQLiteAsyncConnection|DbContext|DbSet|HttpClient|Process|File|Directory|"
    r"Preferences|SecureStorage|BlobClient|SmtpClient|"
    # PHP (library functions are `ext:<function>`, facades and classes `ext:<Class>.<method>`)
    r"mysqli_\w+|mysqli|mysql_\w+|pg_\w+|sqlite_\w+|PDO|PDOStatement|DB|Schema|curl_\w+|file_get_contents|"
    r"file_put_contents|fopen|fwrite|unlink|move_uploaded_file|shell_exec|exec|system|passthru|proc_open|popen|mail|"
    r"Http|Storage|Mail|Redis|Cache|Client|wpdb|wp_remote_\w+|wp_mail|"
    # Ruby (`ext:ActiveRecord.where`, `ext:Net.HTTP.get`, Kernel's shell and eval)
    r"ActiveRecord|Net\.HTTP|HTTParty|Faraday|RestClient|Open3|Kernel\.(system|exec|spawn|open|`|eval)|IO|Marshal|"
    r"FileUtils|Aws|Stripe|Sidekiq|ActionMailer)"
    r"(\.|\(|$|/)"
)

# A JS/TS module in one of these places runs on the server.
SERVER_PATH_RE = re.compile(
    r"(^|/)(src/)?(app/.*(/|^)route\.[cm]?[jt]sx?$|pages/api/|api/|server/|backend/|functions/|netlify/|"
    r"supabase/functions/|worker[s]?/|middleware\.[cm]?[jt]s$)"
)


def _module_id(n: Node) -> str:
    return n.id.split("::", 1)[0]


def _server_modules(g: Graph) -> set[str]:
    out: set[str] = set()
    for n in g.nodes.values():
        if not n.id.startswith("js:"):
            continue
        if n.file and SERVER_PATH_RE.search(n.file):
            out.add(_module_id(n))
        e = n.entry or {}
        if e.get("kind") == "route" or (e.get("kind") == "main" and str(e.get("detail", "")).startswith("server start")):
            out.add(_module_id(n))
    return out


def lane_of(n: Node, server_modules: set[str], android: dict | None = None) -> str | None:
    """The lane for one node, given the set of server-side JS modules. ``None`` = not part of the stack picture.
    In an Android app (``android`` = ``graph.meta["android"]``) the app's own code runs on the phone: screens are
    ``browser`` (the viewer calls it "Screen") and the rest ``frontend`` ("App")."""
    if n.id.startswith("ext:HTTP "):
        target = n.id[len("ext:HTTP "):].split(" ", 1)[-1]
        return "server" if target.startswith("/") else "data"
    if n.id.startswith("ext:"):
        return "data" if DATA_RE.match(n.id[4:]) else None
    if android and _in_roots(n.file, android):
        e = n.entry or {}
        screen = e.get("kind") == "page" or (e.get("kind") == "route" and " screen " in str(e.get("detail", "")))
        return "browser" if screen else "frontend"
    if not n.id.startswith("js:"):
        return "server"
    if _module_id(n) in server_modules:
        return "server"
    e = n.entry or {}
    if e.get("kind") == "page" or (e.get("kind") == "main" and str(e.get("detail", "")).startswith("app start")):
        return "browser"
    return "frontend"


def phone_roots(meta: dict) -> dict | None:
    """The folders of the phone apps in the repo (Android modules, iOS apps), shaped like `meta["android"]`."""
    roots = [r for k in ("android", "ios", "flutter", "rn", "maui") for r in ((meta.get(k) or {}).get("roots") or [])]
    return {"roots": roots} if roots else None


def _in_roots(file: str | None, android: dict) -> bool:
    return bool(file) and any(file.startswith(r) for r in android.get("roots") or [])


def assign(g: Graph) -> dict:
    """Set ``node.lane`` on every node. Returns counts per lane for ``graph.meta``."""
    servers = _server_modules(g)
    android = phone_roots(g.meta)
    counts = {k: 0 for k in LANES}
    for n in g.nodes.values():
        n.lane = lane_of(n, servers, android)
        if n.lane:
            counts[n.lane] += 1
    g.meta["lanes"] = counts
    return counts


def lanes_for_path(g: Graph, ids: list[str] | None, hot: str | None = None, extra: list[str] | None = None) -> list[str]:
    """Ordered, de-duplicated lanes crossed by a path (plus the hot lane and any extra lanes)."""
    seen: set[str] = set()
    for nid in ids or []:
        n = g.nodes.get(nid)
        if n and n.lane:
            seen.add(n.lane)
    if hot:
        seen.add(hot)
    for x in extra or []:
        seen.add(x)
    return [l for l in LANES if l in seen]


def lane_for_file(file: str | None, android: dict | None = None) -> str | None:
    """Fallback for a finding with no node (e.g. a secret in a config file)."""
    if not file:
        return None
    if android and _in_roots(file, android):
        return "frontend"                     # the manifest, the build file and the app's code ship on the phone
    if file.endswith((".py", ".go", ".rs", ".java", ".kt", ".cs", ".swift", ".dart", ".php", ".rb")):
        return "server"
    if re.search(r"\.[cm]?[jt]sx?$", file):
        return "server" if SERVER_PATH_RE.search(file) else "frontend"
    if re.search(r"(^|/)\.env|\.ya?ml$|\.toml$|\.json$|Dockerfile|\.ini$|\.cfg$", file):
        return "server"
    return None
