"""A secret written in the code (directive point 4: secret exposure; rule LW-SECRET-INLINE).

The text that signs sessions or login tokens, the password of a database or mail account, a database address that
carries its password. Each dangerous example sits beside the twin that reads the value from a setting, and beside
look-alikes that are no secret (a field's label, the name of a setting, a path to a key file, an empty form value).
None of these is copied from an app of the held-out benchmark; every value here is a plain made-up word."""

import pytest

from lantern import websec


def _found(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return sorted((f["file"], f["line"], f["secret_kind"]) for f in websec.inline_secrets(tmp_path))


def _one(tmp_path, text, name="server.js"):
    return [(line, kind) for _file, line, kind in _found(tmp_path, {name: text})]


JS = {
    # ---- caught: the text that signs sessions and tokens
    "caught: the session secret, written where the session is set up":
        ("app.use(session({\n  secret: 'keyboard cat',\n  resave: false\n}))\n", [(2, "signing")]),
    "caught: the cookie parser's signing text":
        ("app.use(cookieParser('cookie signing text'))\n", [(1, "signing")]),
    "caught: a token signed with text written in the call":
        ("const token = jwt.sign({ id: user.id, role: 'user' }, 'token-signing-text', { expiresIn: '1h' })\n",
         [(1, "signing")]),
    "caught: a token checked with text written in the call":
        ("jwt.verify(token, \"token-signing-text\", (err, data) => next(err))\n", [(1, "signing")]),
    "caught: the call spread over lines: the line of the text itself":
        ("const token = jwt.sign(\n  { id: user.id },\n  'token-signing-text',\n  { expiresIn: '1h' }\n)\n",
         [(3, "signing")]),
    "caught: a settings file with two of them":
        ("module.exports = {\n  port: 3000,\n  cookieSecret: \"session_cookie_text_here\",\n"
         "  jwtSecret: 'another made-up text'\n}\n", [(3, "signing"), (4, "signing")]),
    "caught: a name of the file's own":
        ("const JWT_SECRET = 'token-signing-text'\nlet sessionSecret = \"abc\"\n", [(1, "signing"), (2, "signing")]),
    "caught: put on a settings object":
        ("config.secret = 'token-signing-text'\nconfig['jwt_secret'] = 'x1'\n", [(1, "signing"), (2, "signing")]),
    "caught: a quoted name, as in a settings table":
        ("module.exports = { 'secret': 'abc', \"session_secret\": \"def\" }\n", [(1, "signing")]),
    "caught: a typed field of a class":
        ("class Auth {\n  private readonly secret: string = 'token-signing-text'\n}\n", [(2, "signing")]),
    "caught: a default for a parameter":
        ("function sign(payload, secret = 'token-signing-text') { return jwt.sign(payload, secret) }\n",
         [(1, "signing")]),
    "caught: the key of an HMAC":
        ("const mac = crypto.createHmac('sha256', 'hmac-key-text').update(body).digest('hex')\n", [(1, "signing")]),
    "caught: a token strategy and an OAuth client":
        ("passport.use(new JwtStrategy({ jwtFromRequest: fromHeader, secretOrKey: 'token-signing-text' }, verify))\n"
         "passport.use(new GitHubStrategy({ clientID: id, clientSecret: 'oauth-client-text' }, done))\n",
         [(1, "signing"), (2, "signing")]),
    "caught: one word that is the same as its name, in small letters":
        ("app.use(session({ secret: 'secret' }))\n", [(1, "signing")]),
    "caught: a phrase of several words where the session is set up":
        ("app.use(session({\n  secret: 'this is my made up phrase',\n}))\n", [(2, "signing")]),
    # ---- caught: the setting is read, with text in the code for when it is missing
    "caught: text in the code for when the setting is missing":
        ("const secret = process.env.JWT_SECRET || 'dev-signing-text'\n"
         "app.use(session({ secret: process.env.SESSION_SECRET ?? \"dev\" }))\n", [(1, "default"), (2, "default")]),
    "caught: the same inside the call that signs":
        ("jwt.sign(payload, process.env.JWT_SECRET || 'dev-signing-text')\n", [(1, "default")]),
    # ---- caught: passwords of accounts the app connects with
    "caught: a database account's password":
        ("const db = mysql.createConnection({\n  host: 'db.example.com',\n  user: 'app',\n"
         "  password: 'db-pass-text',\n  database: 'shop'\n})\n", [(4, "password")]),
    "caught: a mail account's password":
        ("const mail = nodemailer.createTransport({\n  service: 'gmail',\n"
         "  auth: { user: 'shop@example.com', pass: 'mail-pass-text' }\n})\n", [(3, "password")]),
    "caught: a database address that carries its password":
        ("mongoose.connect('mongodb+srv://app:db-pass-text@cluster0.example.net/shop')\n", [(1, "address")]),
    # ---- clean: read from a setting
    "clean: read from the environment":
        ("app.use(session({ secret: process.env.SESSION_SECRET, resave: false }))\n"
         "app.use(cookieParser(process.env.COOKIE_SECRET))\nconst JWT_SECRET = process.env.JWT_SECRET\n", []),
    "clean: read from a settings object":
        ("app.use(session({ secret: config.sessionSecret }))\njwt.sign(payload, config.jwt.secret)\n", []),
    "clean: a token signed with a name, and other text in the call":
        ("jwt.sign({ id: 1, kind: 'access' }, process.env.JWT_SECRET, { algorithm: 'HS256' })\n"
         "jwt.sign(payload, privateKey, { algorithm: 'RS256', issuer: 'shop' })\n"
         "jwt.verify(token, getKey, { audience: 'shop' }, done)\n", []),
    "clean: nothing for when the setting is missing":
        ("const secret = process.env.JWT_SECRET || ''\nconst other = process.env.SESSION_SECRET ?? null\n", []),
    "clean: the app stops when the setting is missing":
        ("const secret = process.env.JWT_SECRET\nif (!secret) throw new Error('JWT_SECRET is not set')\n", []),
    "clean: an HMAC with a key from a setting, and a plain hash":
        ("crypto.createHmac('sha256', process.env.HOOK_KEY).update(body)\ncrypto.createHash('sha256')\n", []),
    "clean: a cookie parser with no signing":
        ("app.use(cookieParser())\n", []),
    # ---- clean: look-alikes that are no secret
    "clean: the names of form fields":
        ("passport.use(new LocalStrategy({ usernameField: 'email', passwordField: 'password' }, check))\n", []),
    "clean: empty values of a form":
        ("const [form, setForm] = useState({ email: '', password: '', secret: '' })\n", []),
    "clean: the name or the place of a secret, not the secret":
        ("const opts = { secretName: 'prod/jwt', secretId: 'jwt', secretArn: 'arn:aws:secretsmanager:eu:1:secret:x' }\n"
         "const secretsPath = './secrets'\nconst SECRET_HEADER = 'x-hook-secret'\n", []),
    "clean: the name of the setting that holds it":
        ("const ENV_SECRET = 'JWT_SECRET'\nconst clientSecret = 'YOUR_CLIENT_SECRET'\n", []),
    "clean: a label, a hint and a message for a person":
        ("const labels = { secret: 'Secret', clientSecret: 'Client secret', password: 'Password' }\n"
         "const errors = { secret: 'Enter the secret you were sent' }\n", []),
    "clean: a path to a key file, and a placeholder":
        ("const opts = { privateKey: './keys/private.pem', signingKey: '/run/secrets/signing.key' }\n"
         "const secret = '<your secret here>'\n", []),
    "clean: a comparison and a type":
        ("if (kind === 'secret') hide()\nif (req.query.secret == 'x') next()\ninterface Opts { secret: string }\n", []),
    "clean: in a comment":
        ("// app.use(session({ secret: 'keyboard cat' }))\n/*\n * secret: 'keyboard cat'\n */\n", []),
    "clean: a demo sign-in with no connection settings beside it":
        ("const demo = { username: 'demo', password: 'demo-pass-text' }\n", []),
    "clean: a database on this computer, and one whose password is a setting":
        ("const url = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/shop'\n"
         "const other = 'postgres://app:' + process.env.DB_PASS + '@db.example.com/shop'\n"
         "const third = `postgres://app:${pass}@db.example.com/shop`\n", []),
    "clean: a password read from a setting beside the host":
        ("const db = mysql.createConnection({ host: 'db.example.com', user: 'app', password: process.env.DB_PASS })\n",
         []),
}


@pytest.mark.parametrize("case", sorted(JS))
def test_a_secret_written_in_javascript(tmp_path, case):
    text, want = JS[case]
    assert _one(tmp_path, text) == want


PY = {
    "caught: a token signed with text written in the call":
        ("token = jwt.encode({'sub': user.id, 'kind': 'access'}, 'token-signing-text', algorithm='HS256')\n",
         [(1, "signing")]),
    "caught: a token checked with text written in the call":
        ("data = jwt.decode(token, \"token-signing-text\", algorithms=['HS256'])\n", [(1, "signing")]),
    "caught: the key of an HMAC":
        ("mac = hmac.new(b'hmac-key-text', body, hashlib.sha256).hexdigest()\n", [(1, "signing")]),
    "caught: a signer made with text":
        ("signer = URLSafeTimedSerializer('link-signing-text')\n", [(1, "signing")]),
    "caught: text in the code for when the setting is missing":
        ("SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-signing-text')\n"
         "app.secret_key = os.getenv(\"FLASK_SECRET\", \"dev\")\n"
         "token = jwt.encode(payload, os.environ.get('JWT_SECRET', 'dev-signing-text'), algorithm='HS256')\n",
         [(1, "default"), (2, "default"), (3, "default")]),
    "caught: a database address that carries its password":
        ("engine = create_engine('postgresql://app:db-pass-text@db.example.com/shop')\n", [(1, "address")]),
    "clean: read from a setting":
        ("token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')\n"
         "data = jwt.decode(token, os.environ['JWT_SECRET'], algorithms=['HS256'])\n"
         "mac = hmac.new(key, body, 'sha256')\nsigner = URLSafeTimedSerializer(app.config['SECRET_KEY'])\n", []),
    "clean: no text for when the setting is missing":
        ("SECRET_KEY = os.environ['SECRET_KEY']\napp.secret_key = os.environ.get('FLASK_SECRET')\n"
         "DEBUG = os.environ.get('DEBUG', 'false')\nJWT_SECRET = os.getenv('JWT_SECRET', '')\n", []),
    "clean: other text in the call":
        ("token = jwt.encode({'kind': 'access'}, key, algorithm='HS256')\n", []),
    "clean: a database on this computer":
        ("engine = create_engine(os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost/shop'))\n", []),
    "clean: in a comment":
        ("# token = jwt.encode(payload, 'token-signing-text')\n", []),
}


@pytest.mark.parametrize("case", sorted(PY))
def test_a_secret_written_in_python(tmp_path, case):
    text, want = PY[case]
    assert _one(tmp_path, text, "app/auth.py") == want


def test_a_settings_file_in_json_and_files_that_are_not_the_apps_code(tmp_path):
    files = {"config/default.json": '{\n  "port": 3000,\n  "jwtSecret": "token-signing-text"\n}\n',
             "package.json": '{"name": "shop", "config": {"secret": "abc"}}\n',
             "locales/en.js": "module.exports = { secret: 'made-up word' }\n",
             "node_modules/x/index.js": "module.exports = { secret: 'made-up word' }\n",
             "src/types.d.ts": "declare const secret = 'made-up word'\n"}
    assert _found(tmp_path, files) == [("config/default.json", 3, "signing")]


def test_the_finding_says_what_it_is_and_never_repeats_the_text(tmp_path):
    (tmp_path / "server.js").write_text("app.use(session({ secret: 'keyboard cat' }))\n"
                                        "const s = process.env.S_SECRET || 'dev-signing-text'\n", encoding="utf-8")
    written, default = websec.inline_secrets(tmp_path)
    assert (written["rule"], written["cwe"], written["category"], written["fixed_rank"]) == \
        ("LW-SECRET-INLINE", 798, "code", "medium"), written
    assert "keyboard cat" not in written["snippet"] and "[redacted]" in written["snippet"], written["snippet"]
    assert "written in the code" in written["title"] and "when the setting is missing" in default["title"]
    assert "dev-signing-text" not in default["snippet"], default["snippet"]
    assert (written["tool_confidence"], default["tool_confidence"]) == ("MEDIUM", "LOW")


def test_a_real_looking_key_is_left_to_the_key_patterns(tmp_path):
    # one problem, one finding: the patterns for real keys already list this line (category `secret`, critical)
    from lantern.security import SECRET_PATTERNS
    key = "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"          # built here, never written out whole
    assert any(rx.search(key) for _name, rx in SECRET_PATTERNS)
    (tmp_path / "server.js").write_text(f"const stripeSecret = '{key}'\n", encoding="utf-8")
    assert websec.inline_secrets(tmp_path) == []


def test_in_the_findings_it_is_ranked_medium_with_the_story_of_a_key_in_the_code(tmp_path):
    from lantern.engine import build_graph
    from lantern.security import scan
    files = {"package.json": '{"dependencies": {"express": "4.19.2", "express-session": "1.18.0"}}',
             "server.js": "const express = require('express')\nconst session = require('express-session')\n"
                          "const app = express()\napp.use(session({ secret: 'keyboard cat' }))\n"
                          "app.get('/', (req, res) => res.send('ok'))\n"}
    for rel, text in files.items():
        (tmp_path / rel).write_text(text, encoding="utf-8")
    fs = [f for f in scan(build_graph(tmp_path), offline=True)["findings"] if f["rule"] == "LW-SECRET-INLINE"]
    assert [(f["file"], f["line"], f["rank"]) for f in fs] == [("server.js", 4, "medium")], fs
    assert "key" in fs[0]["scenario"]["harm"].lower(), fs[0]["scenario"]


# A secret kept under a plain name (round 3, 2026-11-11). The rule above reads names: `phrase: '…'` in a settings file
# says nothing by itself. What says it is the call that signs with it, so the name is followed from that call to the
# line that gives it its text: in the same file, or in the file of the project it was loaded from. Of 17 shapes of my
# own 6 were missed, and a Flask app's `app.secret_key = '…'` was listed only by Bandit, ranked low, with the text in
# its title. No held-out app was read; every value here is a plain made-up word.
TEXT = "'made-up-signing-text'"
SETTINGS = "module.exports = {\n  port: 3000,\n  phrase: " + TEXT + "\n}\n"
LOADS = "const session = require('express-session')\nconst jwt = require('jsonwebtoken')\n"
SIGNS = "app.use(session({ secret: config.phrase, resave: false }))\n"
FOLLOWED = {
    "caught: a plain name in a settings file, handed to the session":
        ({"config.js": SETTINGS, "server.js": LOADS + "const config = require('./config')\n" + SIGNS},
         [("config.js", 3, "signing")]),
    "clean: the same settings file, and nothing signs with that name":
        ({"config.js": SETTINGS, "server.js": LOADS + "const config = require('./config')\napp.listen(config.port)\n"},
         []),
    "caught: a plain name of the same file":
        ({"server.js": LOADS + "const PHRASE = " + TEXT + "\napp.use(session({ secret: PHRASE }))\n"},
         [("server.js", 3, "signing")]),
    "caught: a settings object of the same file":
        ({"server.js": LOADS + "const settings = {\n  port: 3000,\n  phrase: " + TEXT + "\n}\n"
                               "app.use(session({ secret: settings.phrase }))\n"}, [("server.js", 5, "signing")]),
    "clean: an object of the same file with that name in it, and the session takes a parameter's":
        ({"server.js": LOADS + "const hints = { phrase: 'four words you remember' }\n"
                               "function sessions(settings) {\n  return session({ secret: settings.phrase })\n}\n"}, []),
    "caught: exported by itself, handed to the token signer":
        ({"config.js": "exports.port = 3000\nexports.phrase = " + TEXT + "\n",
          "server.js": LOADS + "const config = require('./config')\n"
                               "const token = jwt.sign({ sub: 1 }, config.phrase, { expiresIn: '1h' })\n"},
         [("config.js", 2, "signing")]),
    "caught: an ES module's named export, imported by name, a token checked with it":
        ({"src/config.ts": "export const port = 3000\nexport const phrase: string = " + TEXT + "\n",
          "src/server.ts": "import jwt from 'jsonwebtoken'\nimport { phrase } from './config'\n"
                           "export const check = (token: string) => jwt.verify(token, phrase)\n"},
         [("src/config.ts", 2, "signing")]),
    "caught: a default export imported under a name, handed to the cookie parser":
        ({"config.js": "export default {\n  phrase: " + TEXT + "\n}\n",
          "server.js": "import cookieParser from 'cookie-parser'\nimport config from './config.js'\n"
                       "app.use(cookieParser(config.phrase))\n"}, [("config.js", 2, "signing")]),
    "caught: taken out of the settings file by name":
        ({"config.js": SETTINGS, "server.js": LOADS + "const { port, phrase } = require('./config')\n"
                                              "app.use(session({ secret: phrase }))\n"},
         [("config.js", 3, "signing")]),
    "caught: a settings file in a folder, one level up from the code that signs":
        ({"settings/all.js": SETTINGS, "src/server.js": LOADS + "const config = require('../settings/all')\n" + SIGNS},
         [("settings/all.js", 3, "signing")]),
    "caught: a settings file in JSON":
        ({"settings.json": '{\n  "port": 3000,\n  "phrase": "made-up-signing-text"\n}\n',
          "server.js": LOADS + "const config = require('./settings.json')\n" + SIGNS},
         [("settings.json", 3, "signing")]),
    "caught: the settings file falls back to text when the setting is missing":
        ({"config.js": "module.exports = {\n  phrase: process.env.PHRASE || " + TEXT + "\n}\n",
          "server.js": LOADS + "const config = require('./config')\n" + SIGNS}, [("config.js", 2, "default")]),
    "caught: one text for each place the app runs":
        ({"config.js": "module.exports = {\n  dev: { phrase: 'made-up-text-one' },\n"
                       "  live: { phrase: 'made-up-text-two' }\n}\n",
          "server.js": LOADS + "const config = require('./config')[process.env.NODE_ENV]\n" + SIGNS},
         [("config.js", 2, "signing"), ("config.js", 3, "signing")]),
    "clean: the settings file reads it from the environment":
        ({"config.js": "module.exports = {\n  phrase: process.env.PHRASE\n}\n",
          "server.js": LOADS + "const config = require('./config')\n" + SIGNS}, []),
    "clean: the name holds the path of a key file":
        ({"config.js": "module.exports = {\n  phrase: './keys/private.pem'\n}\n",
          "server.js": LOADS + "const config = require('./config')\nconst t = jwt.sign({ sub: 1 }, config.phrase)\n"},
         []),
    "clean: a library's settings, not a file of the project":
        ({"server.js": LOADS + "const config = require('config')\n" + SIGNS}, []),
    "clean: the file it names is not in the project":
        ({"server.js": LOADS + "const config = require('./config')\n" + SIGNS}, []),
}


@pytest.mark.parametrize("case", sorted(FOLLOWED))
def test_a_secret_under_a_plain_name_is_found_from_the_call_that_signs_with_it(tmp_path, case):
    files, want = FOLLOWED[case]
    assert _found(tmp_path, files) == want


PY_TEXT = "'made-up-signing-text'"
PY_FOLLOWED = {
    "caught: Flask's own name for the text that signs its sessions":
        ({"app.py": "from flask import Flask\n\napp = Flask(__name__)\napp.secret_key = " + PY_TEXT + "\n"},
         [("app.py", 4, "signing")]),
    "caught: the same through the app's settings":
        ({"app.py": "from flask import Flask\n\napp = Flask(__name__)\napp.config['SECRET_KEY'] = " + PY_TEXT + "\n"
                    "app.config.update(JWT_SECRET_KEY=" + PY_TEXT + ")\n"},
         [("app.py", 4, "signing"), ("app.py", 5, "signing")]),
    "caught: in a settings file, at the top and in a class":
        ({"settings.py": "DEBUG = False\nSECRET_KEY = " + PY_TEXT + "\n\n\nclass Live:\n    JWT_SECRET = " + PY_TEXT
                         + "\n"}, [("settings.py", 2, "signing"), ("settings.py", 6, "signing")]),
    "clean: read from the environment, empty, or the name of the setting":
        ({"settings.py": "import os\n\nSECRET_KEY = os.environ['SECRET_KEY']\nJWT_SECRET = ''\n"
                         "SECRET_KEY_SETTING = 'SECRET_KEY'\nHOOK_SECRET = 'HOOK_SECRET'\n"}, []),
    "clean: names that are about a secret and are none":
        ({"forms.py": "secret_label = 'Secret'\nsecret_help = 'Enter the secret you were sent.'\n"
                      "SECRET_HEADER = 'x-hook-secret'\nsecret_file = '/run/secrets/signing.key'\n"}, []),
    "caught: a plain name in a settings file, used as Flask's secret key":
        ({"config.py": "PORT = 8000\nPHRASE = " + PY_TEXT + "\n",
          "app.py": "from flask import Flask\n\nimport config\n\napp = Flask(__name__)\napp.secret_key = config.PHRASE\n"},
         [("config.py", 2, "signing")]),
    "clean: the same settings file, and nothing signs with that name":
        ({"config.py": "PORT = 8000\nPHRASE = " + PY_TEXT + "\n",
          "app.py": "from flask import Flask\n\nimport config\n\napp = Flask(__name__)\nprint(config.PORT)\n"}, []),
    "caught: imported by name, a token signed with it":
        ({"shop/config.py": "PHRASE = " + PY_TEXT + "\n",
          "shop/auth.py": "import jwt\n\nfrom .config import PHRASE\n\n\ndef token(user):\n"
                          "    return jwt.encode({'sub': user.id}, PHRASE, algorithm='HS256')\n"},
         [("shop/config.py", 1, "signing")]),
    "caught: the settings module of the same package":
        ({"shop/config.py": "PHRASE = " + PY_TEXT + "\n",
          "shop/auth.py": "import jwt\n\nfrom . import config\n\n\ndef check(token):\n"
                          "    return jwt.decode(token, config.PHRASE, algorithms=['HS256'])\n"},
         [("shop/config.py", 1, "signing")]),
    "caught: a settings class of another file":
        ({"shop/settings.py": "class Live:\n    DEBUG = False\n    PHRASE = " + PY_TEXT + "\n",
          "shop/app.py": "from flask import Flask\n\nfrom shop.settings import Live\n\napp = Flask(__name__)\n"
                         "app.config['SECRET_KEY'] = Live.PHRASE\n"}, [("shop/settings.py", 3, "signing")]),
    "caught: a plain name of the same file, handed to a signer":
        ({"links.py": "from itsdangerous import URLSafeTimedSerializer\n\nPHRASE = " + PY_TEXT + "\n"
                      "signer = URLSafeTimedSerializer(PHRASE)\n"}, [("links.py", 3, "signing")]),
    "clean: the plain name is read from the environment":
        ({"config.py": "import os\n\nPHRASE = os.environ['PHRASE']\n",
          "app.py": "from flask import Flask\n\nimport config\n\napp = Flask(__name__)\napp.secret_key = config.PHRASE\n"},
         []),
    "clean: a library's module":
        ({"app.py": "import jwt\nimport settings_lib\n\n\ndef token(user):\n"
                    "    return jwt.encode({'sub': user.id}, settings_lib.PHRASE, algorithm='HS256')\n"}, []),
}


@pytest.mark.parametrize("case", sorted(PY_FOLLOWED))
def test_a_python_secret_by_its_own_name_or_followed_from_the_call_that_signs(tmp_path, case):
    files, want = PY_FOLLOWED[case]
    assert _found(tmp_path, files) == want


def test_a_line_this_rule_lists_is_not_listed_again_as_a_possible_password(tmp_path):
    # one problem, one finding: Bandit lists `app.secret_key = '…'` as B105, ranked low, with the text in its title
    pytest.importorskip("bandit")
    from lantern.engine import build_graph
    from lantern.security import scan
    files = {"pyproject.toml": '[project]\nname="a"\nversion="0"\ndependencies=["flask"]\n',
             "app.py": "from flask import Flask\n\napp = Flask(__name__)\napp.secret_key = " + PY_TEXT + "\n"
                       "db_password = 'made-up-pass-text'\n"}
    for rel, text in files.items():
        (tmp_path / rel).write_text(text, encoding="utf-8")
    fs = scan(build_graph(tmp_path), offline=True)["findings"]
    assert sorted((f["rule"], f["line"], f["rank"]) for f in fs if f["file"] == "app.py") == \
        [("B105", 5, "low"), ("LW-SECRET-INLINE", 4, "medium")], fs
    mine = next(f for f in fs if f["rule"] == "LW-SECRET-INLINE")
    assert "made-up-signing-text" not in str(mine["title"]) + str(mine["snippet"]), mine
