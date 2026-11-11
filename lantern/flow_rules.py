"""The tables of the data-flow engine (flow.py): where request data comes in, what makes it safe and for what, which
calls are sensitive actions, and what a pattern proves. Data, not code: a new library is a new line here.

Names are the canonical ones the call inventory uses without their `ext:` / `builtin:` prefix (`requests.get`,
`express.Response.send`, `sqlite3.connect().cursor().execute`), or, where the object's type is unknown, the last
part of the callee (`execute`), which then needs evidence in the value itself (text that reads like SQL)."""

from __future__ import annotations

import re

CLASSES = ("sql", "shell", "eval", "deserialize", "xxe", "path", "ssrf", "xss", "redirect", "nosql", "pollution")
ALL = frozenset(CLASSES)
# A pattern or a character check says nothing about which computer an address names: `localhost` is letters only.
CHARS = ALL - {"ssrf"}
URLS = frozenset({"ssrf", "redirect"})

SEVERITY = {"sql": "HIGH", "shell": "HIGH", "eval": "HIGH", "deserialize": "HIGH", "xxe": "MEDIUM", "path": "MEDIUM",
            "ssrf": "MEDIUM", "xss": "MEDIUM", "redirect": "MEDIUM", "nosql": "MEDIUM", "pollution": "MEDIUM"}
FIXED_RANK = {"redirect": "medium"}
RULE = {c: "LT-" + c.upper() for c in CLASSES}
CWE = {"sql": 89, "shell": 78, "eval": 94, "deserialize": 502, "xxe": 611, "path": 22, "ssrf": 918, "xss": 79,
       "redirect": 601, "nosql": 943, "pollution": 1321}
TITLE = {
    "sql": "Request data is put into the text of a database query",
    "shell": "Request data is put into a command the server runs",
    "eval": "Request data is run as code or as a template",
    "deserialize": "An object is rebuilt from data the request sent",
    "xxe": "XML from the request is read by a parser that follows outside references",
    "path": "Request data chooses which file the server opens or writes",
    "ssrf": "Request data chooses the address the server connects to",
    "xss": "Request data is put into a page without escaping",
    "redirect": "Request data chooses where the visitor is sent next",
    "nosql": "Request data is used as a database filter without fixing its type",
    "pollution": "An object from the request is merged into the app's own objects",
}
ACTION = {   # the last step: what the value does at the sink
    "sql": "is run as part of the database query",
    "shell": "is run as part of a command on the server",
    "eval": "is run as code or as a template",
    "deserialize": "is turned back into an object",
    "xxe": "is read as XML",
    "path": "names the file that is opened, written or removed",
    "ssrf": "is the address the server connects to",
    "xss": "is sent to the browser as part of a page",
    "redirect": "is where the visitor is sent",
    "nosql": "is used as the database filter",
    "pollution": "is merged into an object of the app",
}
PROTECTS = {   # words for the steps: what a sanitizer is for
    "sql": "a database query", "shell": "a shell command", "path": "a file path", "xss": "a page",
    "redirect": "a redirect", "ssrf": "an outbound address", "nosql": "a database filter", "eval": "code",
    "deserialize": "stored objects", "xxe": "XML", "pollution": "merged objects",
}

SQL_WORDS = re.compile(r"\b(select\s[^;]{0,200}?\sfrom\b|insert\s+into\b|update\s+[\w.`\"\[\]]+\s+set\b|delete\s+from\b|"
                       r"\bwhere\s|order\s+by\b|group\s+by\b|union\s+(all\s+)?select\b|values\s*\(|drop\s+table\b|"
                       r"create\s+table\b|alter\s+table\b|\bfrom\s+[\w.`\"]+\s+(where|join|order|limit)\b|"
                       r"\blimit\s+\d|\bjoin\s+[\w.`\"]+\s+on\b)", re.I)
HTML_WORDS = re.compile(r"<\s*/?\s*[a-zA-Z][\w-]*[\s>/]|<!doctype", re.I)
HOST_FIXED = re.compile(r"^(?:https?:)?//[^/?#@\\]+[/?#]", re.I)   # scheme://host/ : the host part is complete


def host_fixed(prefix) -> bool:
    return isinstance(prefix, str) and bool(HOST_FIXED.match(prefix))


def local_path(prefix) -> bool:
    """Leading text that keeps a redirect on this site: one slash and something that is not a second one."""
    return isinstance(prefix, str) and len(prefix) > 1 and prefix[0] == "/" and prefix[1] not in "/\\"


# ---------------------------------------------------------------------------------------------- request data
# Attributes of a request object that hold what the caller sent. `user`, `session`, `app`, `method` are not here.
PY_INPUT = {"args", "form", "values", "json", "data", "files", "cookies", "headers", "GET", "POST", "FILES", "COOKIES",
            "META", "body", "query_params", "path_params", "view_args", "url", "path", "full_path", "query", "match_info",
            "rel_url", "query_string", "stream", "raw_post_data", "base_url", "url_root", "host", "referrer",
            "user_agent", "content_type", "get_json", "get_data", "getlist", "query_arguments", "body_arguments",
            "arguments", "params", "post", "content", "text", "forms", "base64_data"}
JS_INPUT = {"query", "params", "body", "headers", "cookies", "signedCookies", "files", "file", "url", "originalUrl",
            "path", "hostname", "host", "ip", "get", "header", "param", "nextUrl", "json", "formData", "text",
            "rawBody", "protocol", "subdomains", "baseUrl", "search", "searchParams", "payload"}
# What a request object knows about who is signed in (never request data; used by the ownership check).
IDENT_ATTRS = {"user", "session", "auth", "userId", "user_id", "currentUser", "current_user", "identity", "account",
               "principal", "token_payload", "jwt", "state", "locals", "decoded", "userid", "uid"}
STRING_ONLY = {"args", "form", "values", "GET", "POST", "query_params", "path_params", "view_args", "headers",
               "cookies", "COOKIES", "META", "params", "url", "path", "originalUrl", "match_info", "query_string"}
REQUEST_NAMES = {"request", "req"}
REQUEST_TYPES = re.compile(r"\b(Request|HttpRequest|WSGIRequest|NextRequest|NextApiRequest|FastifyRequest|"
                           r"WebSocket|HTTPConnection|IncomingMessage)\b")
REQUEST_GLOBALS = {"flask.request", "quart.request", "bottle.request", "flask.globals.request", "sanic.request"}
UPLOAD_TYPES = re.compile(r"\bUploadFile\b|\bFileStorage\b|\bInMemoryUploadedFile\b")
UPLOAD_NAME_ATTRS = {"filename", "originalname", "name", "originalFilename", "mimetype", "content_type", "headers",
                     "raw_filename"}
UPLOAD_STORED_ATTRS = {"path", "tempFilePath", "filepath", "destination", "buffer", "data", "file", "stream", "size",
                       "read", "stream_read", "chunks", "temporary_file_path"}
ARCHIVE_NAMES = {"namelist", "infolist", "getmembers", "getnames", "filelist"}      # methods/attributes of an archive
ARCHIVE_ENTRY_ATTRS = {"path", "fileName", "entryName", "filename", "name", "linkname"}
SAFE_TYPES = re.compile(r"^(?:Optional\[)?\s*(int|float|bool|UUID|uuid\.UUID|date|datetime|datetime\.date|"
                        r"datetime\.datetime|Decimal|PositiveInt|NonNegativeInt|conint\b.*|confloat\b.*|ObjectId|"
                        r"number|boolean|bigint)\s*\]?(\s*\|\s*None)?$")
NOT_INPUT_TYPES = re.compile(r"\b(Response|BackgroundTasks|Session|AsyncSession|SecurityScopes|Settings|Connection|"
                             r"Engine|Redis|Database|Depends|WebSocketDisconnect|Logger|sessionmaker)\b")
INJECTED = re.compile(r"^(?:fastapi\.)?(Depends|Security)\(")
DOM_SOURCES = re.compile(r"^(?:window\.|document\.|self\.|globalThis\.)?(location(\.(search|hash|href|pathname))?|"
                         r"URL|documentURI|referrer|name)$")
DOM_SOURCE_HEADS = {"location", "window.location", "document.location", "document.URL", "document.documentURI",
                    "document.referrer", "window.name"}
# NestJS: `find(@Query('name') name: string)`; a pipe that parses makes the value a number or refuses the request
PARAM_DECORATOR = re.compile(r"^@(Query|Param|Body|Headers|Req|Request|UploadedFile|UploadedFiles)\((.*)\)\s*$", re.S)
PARSE_PIPE = re.compile(r"\bParse(Int|Float|Bool|UUID|Enum)Pipe\b")
URL_HOOKS = {"useSearchParams", "useParams", "useLocalSearchParams", "useGlobalSearchParams"}

# ---------------------------------------------------------------------------------------------- sanitizers
# (pattern on the canonical name or the bare function name, classes made safe; None = every class)
SANITIZERS = [
    (r"^(int|float|bool|len|hash|ord|abs|round|complex|id)$", None),
    (r"^(uuid\.UUID|decimal\.Decimal|fractions\.Fraction)$", None),
    # text that is an IP address holds no quote, slash or space; whose address it is, nothing says
    (r"^ipaddress\.(ip_(address|network|interface)|IPv[46]Address)$", CHARS),
    (r"^hashlib\.|\.(hexdigest|digest)$|^(hmac|secrets|bcrypt|argon2|passlib|scrypt)\.", None),
    (r"^(datetime\.)?(datetime|date|time)\.(strptime|fromisoformat|fromtimestamp)$|^time\.(strptime|mktime)$", None),
    (r"^(parseInt|parseFloat|Number|BigInt|Boolean|Number\.parseInt|Number\.parseFloat|Math\.\w+|Date\.parse|"
     r"validator\.toInt|validator\.toFloat|validator\.toBoolean|validator\.toDate)$", None),
    (r"^(mongoose\.Types\.ObjectId|mongodb\.ObjectId|bson\.ObjectId|ObjectId|bson\.objectid\.ObjectId)$", None),
    (r"^crypto\.(createHash|createHmac|randomBytes|randomUUID)\b|^(bcrypt|bcryptjs|argon2)\.", None),
    (r"^(html\.escape|markupsafe\.escape|flask\.escape|jinja2\.escape|cgi\.escape|bleach\.(clean|linkify)|"
     r"django\.utils\.html\.(escape|conditional_escape|strip_tags|escapejs)|xml\.sax\.saxutils\.(escape|quoteattr)|"
     r"nh3\.clean|lxml\.html\.clean\.clean_html)$", {"xss"}),
    (r"^(escape-html|he\.(encode|escape)|lodash\.escape|underscore\.escape|validator\.escape|dompurify\.sanitize|"
     r"isomorphic-dompurify\.sanitize|DOMPurify\.sanitize|sanitize-html|xss|xss\.filterXSS|ejs\.escapeXML|"
     r"handlebars\.escapeExpression|handlebars\.Utils\.escapeExpression|entities\.(encode|escape|encodeHTML)|"
     r"html-entities\.encode|encodeURIComponent|encodeURI|escape|striptags|string-strip-html\.stripHtml)$", {"xss"}),
    (r"^urllib\.parse\.(quote|quote_plus)$|^werkzeug\.urls\.url_quote(_plus)?$|^requests\.utils\.quote$", {"xss"}),
    (r"^(shlex|pipes)\.quote$|^(shell-quote\.quote|shell-escape|shescape\.(quote|escape))$", {"shell"}),
    (r"^(os\.path|ntpath|posixpath)\.basename$|^werkzeug\.utils\.secure_filename$|^path\.(basename|extname)$|"
     r"^path\.(posix|win32)\.basename$|^(sanitize-filename|filenamify)$|^pathvalidate\.sanitize_filename$", {"path"}),
    (r"^(MySQLdb|pymysql|pymysql\.converters|mysql\.connector\.conversion)\b.*\.(escape_string|escape|literal)$|"
     r"^psycopg2\.(extensions\.(quote_ident|adapt|AsIs)|sql\.(Identifier|Literal))$|"
     r"^(mysql|mysql2|sqlstring|pg-format|pg)\b.*\.(escape|escapeId|escapeLiteral|escapeIdentifier|format)$|"
     r"^(sqlstring\.escape|pg-format)$", {"sql"}),
    (r"^(str|String|repr)$|^(mongo-sanitize|express-mongo-sanitize\.sanitize)$", {"nosql"}),
    (r"^JSON\.stringify$|^json\.dumps$", {"nosql", "path"}),
]
# by the last part of the callee, when nothing better is known
SANITIZER_MEMBERS = {
    "escape_string": {"sql"}, "real_escape_string": {"sql"}, "escapeId": {"sql"}, "escapeLiteral": {"sql"},
    "escapeIdentifier": {"sql"}, "quote_ident": {"sql"}, "secure_filename": {"path"}, "basename": {"path"},
    "escapeHtml": {"xss"}, "escapeHTML": {"xss"}, "escape_html": {"xss"}, "htmlEscape": {"xss"},
    "sanitizeHtml": {"xss"}, "strip_tags": {"xss"}, "toString": {"nosql"}, "hexdigest": None, "isoformat": None,
    "toFixed": None, "getTime": None, "valueOf": {"nosql"}, "to_bytes": None, "bit_length": None,
}
SQL_RECEIVERS = re.compile(r"conn|pool|db|mysql|sql|client|cursor|knex|database|pg", re.I)
# what these calls return is the argument in another form: the taint goes on
PROPAGATORS = re.compile(
    r"^(str|repr|bytes|bytearray|list|tuple|set|frozenset|dict|sorted|reversed|format|next|iter|min|max|sum|"
    r"enumerate|zip|map|filter|getattr|vars|copy\.(copy|deepcopy)|json\.(loads|load|dumps)|ujson\.\w+|orjson\.\w+|"
    r"simplejson\.\w+|base64\.\w+|binascii\.\w+|codecs\.(decode|encode)|urllib\.parse\.\w+|urlparse\.\w+|"
    r"os\.path\.(join|abspath|realpath|normpath|expanduser|expandvars|dirname|splitext|split)|os\.fspath|os\.fsdecode|"
    r"pathlib\.(Path|PurePath|PosixPath|PurePosixPath|WindowsPath)|io\.(BytesIO|StringIO|TextIOWrapper|BufferedReader)|"
    r"zipfile\.ZipFile|tarfile\.(open|TarFile)|gzip\.(decompress|open|GzipFile)|zlib\.decompress|bz2\.\w+|lzma\.\w+|"
    r"re\.(sub|subn|findall|search|match|fullmatch|split|finditer)|shlex\.split|ast\.literal_eval|html\.unescape|"
    r"yaml\.(safe_load|safe_load_all)|string\.Template|textwrap\.\w+|sqlalchemy\.(text|sql\.text|literal_column)|"
    r"sqlalchemy\.sql\.expression\.text|markupsafe\.Markup|typing\.cast|werkzeug\.datastructures\.\w+|"
    r"email\.\w+|xmltodict\.parse|flask\.json\.(loads|dumps)|pydantic\.\w+|"
    r"String|decodeURIComponent|decodeURI|unescape|JSON\.parse|Object\.(assign|values|keys|entries|fromEntries|"
    r"freeze)|Array\.from|Array\.of|Buffer\.(from|concat)|path\.(join|resolve|normalize|dirname|format|relative)|"
    r"path\.posix\.\w+|util\.(format|inspect)|querystring\.\w+|qs\.\w+|url\.(parse|resolve|format)|URL|"
    r"URLSearchParams|atob|btoa|structuredClone|Promise\.(resolve|all|allSettled|race)|"
    r"lodash\.(get|trim|toString|pick|omit|cloneDeep|clone|defaults|toLower|toUpper|values|map|filter)|"
    r"TextDecoder\(\)\.decode|new URL)$")
# normalising calls: afterwards a "starts with the folder" check means what it says
RESOLVERS = re.compile(r"^(os\.path\.(realpath|abspath|normpath)|path\.(resolve|normalize|join)|path\.posix\.(resolve|"
                       r"normalize|join))$")
RESOLVER_MEMBERS = {"resolve", "absolute", "realpath"}
HOST_OF = re.compile(r"^(urllib\.parse\.(urlparse|urlsplit)|urlparse\.(urlparse|urlsplit)|URL|new URL|url\.parse|"
                     r"yarl\.URL|furl\.furl|httpx\.URL|werkzeug\.urls\.url_parse|tldextract\.extract)$")
HOST_ATTRS = {"hostname", "netloc", "host", "origin", "registered_domain", "domain"}
URL_REST_ATTRS = {"path", "query", "fragment", "pathname", "search", "hash", "params"}   # of a parsed address: no host
# methods whose result is made of their arguments, not of the object they are called on
ARG_METHODS = {"join", "replace", "format", "format_map", "concat", "substitute", "safe_substitute", "render",
               "ljust", "rjust", "center", "zfill", "padStart", "padEnd", "with_name", "joinpath", "with_suffix"}
LOOKUP_METHODS = {"get", "pop", "setdefault"}
ARG_ONLY_METHODS = {"join", "format", "format_map", "substitute", "safe_substitute"}
MUTATORS = {"append", "extend", "add", "insert", "push", "unshift", "update", "write", "writelines", "appendleft",
            "set", "setdefault", "put"}
NUMERIC_ATTRS = {"length", "size", "status", "status_code", "ok", "byteLength", "returncode"}
CALLBACK_METHODS = {"then", "map", "forEach", "filter", "each", "flatMap", "some", "every", "find", "reduce", "on",
                    "once", "catch", "finally", "tap", "subscribe", "pipe", "addEventListener"}

# ---------------------------------------------------------------------------------------------- sensitive actions
SQL_LIBS = (r"(sqlite3|psycopg2?|psycopg|pymysql|MySQLdb|mysql\.connector|mysql|mysql2|aiosqlite|aiomysql|asyncpg|"
            r"cx_Oracle|oracledb|pyodbc|duckdb|databases|flask_mysqldb|django\.db|sqlalchemy|flask_sqlalchemy|"
            r"sqlmodel|peewee|records|pg|pg-promise|postgres|better-sqlite3|sqlite|mssql|tedious|knex|sequelize|"
            r"typeorm|@prisma/client|prisma|mariadb|oracledb|snowflake|clickhouse_driver|vertica_python)")
SQL_CALL = re.compile(r"^" + SQL_LIBS + r"\b.*\.(execute|executemany|executescript|exec_driver_sql|raw|fetch|fetchrow|"
                      r"fetchval|fetch_all|fetch_one|fetch_val|iterate|query|all|get|run|each|exec|prepare|unsafe|"
                      r"\$queryRawUnsafe|\$executeRawUnsafe|extra|scalar|scalars|first|one|execute_sql)$")
# libraries whose `get`, `run`, `all` or `query` are something else, whatever the text handed to them reads like
NOT_SQL = re.compile(r"^(requests|httpx|aiohttp|urllib|urllib3|http|https|axios|fetch|got|needle|superagent|"
                     r"node-fetch|os|subprocess|child_process|fs|path|json|JSON|re|console|logging|logger|log|"
                     r"redis|ioredis|express|fastapi|flask|django|react|Object|Array|Map|Set|Promise|document|"
                     r"window|localStorage|sessionStorage)\b")
SQL_MEMBERS = {"execute", "executemany", "executescript", "exec_driver_sql", "raw", "query", "fetch_all", "fetch_one",
               "fetch_val", "fetchrow", "fetchval", "all", "get", "run", "each", "exec", "prepare",
               "$queryRawUnsafe", "$executeRawUnsafe", "execute_sql", "read_sql", "read_sql_query", "extra", "scalar",
               "first", "one", "unsafe", "queryRaw", "rawQuery", "execSQL"}
SHELL_ALWAYS = re.compile(r"^(os\.(system|popen|popen2|popen3|popen4)|subprocess\.(getoutput|getstatusoutput)|"
                          r"commands\.(getoutput|getstatusoutput)|asyncio\.create_subprocess_shell|"
                          r"child_process\.(exec|execSync)|shelljs\.exec|execa\.(command|commandSync)|"
                          r"execa\.execaCommand(Sync)?|pexpect\.(run|spawn)|"
                          r"paramiko\b.*\.exec_command|fabric\b.*\.(run|sudo|local)|invoke\.run)$")
SHELL_PROGRAM = re.compile(r"^(subprocess\.(run|call|check_call|check_output|Popen)|asyncio\.create_subprocess_exec|"
                           r"os\.(execl|execle|execlp|execv|execve|execvp|execvpe|spawnl|spawnle|spawnlp|spawnv|"
                           r"spawnve|spawnvp|startfile)|child_process\.(spawn|spawnSync|execFile|execFileSync|fork)|"
                           r"execa|execa\.(execa|execaSync|sync)|cross-spawn|cross-spawn\.(sync|spawn))$")
EVAL_CALL = re.compile(r"^(eval|exec|compile|__import__|importlib\.import_module|flask\.render_template_string|"
                       r"flask\.templating\.render_template_string|jinja2\.Template|jinja2\.Environment\(\)\.from_string|"
                       r"jinja2\b.*\.from_string|django\.template\.Template|django\.template\.engines\b.*\.from_string|"
                       r"mako\.template\.Template|tornado\.template\.Template|"
                       r"Function|new Function|vm\.(runInContext|runInNewContext|runInThisContext|compileFunction|"
                       r"Script)|vm2\b.*\.run|ejs\.(render|compile)|pug\.(render|compile)|"
                       r"handlebars\.(compile|precompile)|nunjucks\.renderString|lodash\.template|"
                       r"underscore\.template|dot\.template|mustache\.render|hogan\.js\.compile|"
                       r"mathjs\.(evaluate|eval)|safe-eval|notevil|static-eval|require)$")
DESERIALIZE_CALL = re.compile(r"^((pickle|cPickle|_pickle|dill|cloudpickle|marshal)\.(loads|load|Unpickler)|"
                              r"jsonpickle\.(decode|loads)|jsonpickle\.unpickler\.decode|shelve\.open|"
                              r"yaml\.(load|load_all|unsafe_load|unsafe_load_all|full_load|full_load_all)|"
                              r"ruamel\.yaml\.(load|load_all)|joblib\.load|pandas\.read_pickle|torch\.load|"
                              r"numpy\.load|node-serialize\.unserialize|serialize-to-js\.deserialize|"
                              r"funcster\.(deepDeserialize|deserialize)|cryo\.parse|serialijse\.deserialize)$")
YAML_SAFE = re.compile(r"Safe|Base|CSafe")
XXE_CALL = re.compile(r"^(lxml\.etree\.(fromstring|parse|XML|iterparse|fromstringlist)|lxml\.objectify\.(fromstring|"
                      r"parse)|xml\.dom\.minidom\.(parseString|parse)|xml\.dom\.pulldom\.(parseString|parse)|"
                      r"xml\.sax\.(parseString|parse)|xml\.etree\.(ElementTree|cElementTree)\.(fromstring|parse|XML|"
                      r"iterparse)|libxmljs2?\.(parseXml|parseXmlString|parseXmlAsync))$")
XXE_NEEDS_OPTION = re.compile(r"^libxmljs2?\.")    # safe unless the options switch entity expansion on
PATH_CALL = re.compile(
    r"^(open|io\.open|codecs\.open|aiofiles\.open|os\.(remove|unlink|rmdir|listdir|scandir|mkdir|makedirs|rename|"
    r"replace|chmod|chown|walk|open|readlink|truncate|removedirs)|shutil\.(copy|copy2|copyfile|copytree|move|rmtree|"
    r"unpack_archive)|flask\.send_file|flask\.helpers\.send_file|werkzeug\.utils\.send_file|"
    r"(fastapi|starlette)\.responses\.FileResponse|fastapi\.FileResponse|sanic\.response\.file|"
    r"aiohttp\.web\.FileResponse|tornado\b.*\.StaticFileHandler|pandas\.read_(csv|excel|json|parquet)|"
    r"(fs|fs/promises|fs-extra|node:fs|node:fs/promises|graceful-fs|fs\.promises)\.(readFile|readFileSync|writeFile|"
    r"writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rm|rmSync|rmdir|"
    r"rmdirSync|readdir|readdirSync|mkdir|mkdirSync|open|openSync|copyFile|copyFileSync|rename|renameSync|"
    r"outputFile|outputFileSync|readJson|readJsonSync|remove|removeSync|copy|copySync|move|moveSync|ensureFile|"
    r"ensureDir|emptyDir|truncate)|express\.Response\b.*\.(sendFile|download|sendfile)|"
    r"koa-send|send|serve-static)$")
PATH_BOTH_ARGS = re.compile(r"\.(rename|replace|copy|copy2|copyfile|copytree|move|copyFile|copyFileSync|renameSync|"
                            r"copySync|moveSync)$")
PATH_MEMBERS = {"read_text", "read_bytes", "write_text", "write_bytes", "unlink", "rmdir", "iterdir", "sendFile",
                "download", "sendfile", "createReadStream", "createWriteStream", "readFileSync", "writeFileSync",
                "readFile", "writeFile", "unlinkSync"}
PATHLIB_MEMBERS = {"open", "touch", "mkdir", "rename", "replace", "glob", "rglob", "exists", "is_file", "stat"}
UPLOAD_SAVE = {"save", "mv", "saveAs", "save_to", "transferTo"}
TAR_EXTRACT = re.compile(r"^tarfile\b.*\.(extractall|extract)$|^shutil\.unpack_archive$")
SSRF_CALL = re.compile(
    r"^((requests|httpx|aiohttp|urllib3|grequests|treq|pycurl|httplib2|urlfetch)\b.*\.(get|post|put|patch|delete|head|"
    r"options|request|stream|fetch|send|urlopen)|urllib\.request\.(urlopen|Request|urlretrieve)|urllib2\.(urlopen|"
    r"Request)|urllib\.urlopen|"
    r"(axios|node-fetch|got|needle|request|request-promise|request-promise-native|superagent|undici|cross-fetch|"
    r"isomorphic-fetch|isomorphic-unfetch|ky|phin|bent|http|https|node:http|node:https|follow-redirects)"
    r"(\b.*\.(get|post|put|patch|delete|head|request|fetch|stream|del))?|fetch|\$fetch|ofetch|puppeteer\b.*\.goto|"
    r"playwright\b.*\.goto)$")
SSRF_URL_SECOND = re.compile(r"\.(request|open)$|^needle$|^(requests|httpx)\b.*\.request$")
HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options"}
XSS_CALL = re.compile(r"^(django\.http\.(HttpResponse|response\.HttpResponse)|django\.utils\.safestring\.mark_safe|"
                      r"django\.utils\.html\.mark_safe|flask\.(make_response|Markup|Response)|markupsafe\.Markup|"
                      r"(fastapi|starlette)\.responses\.HTMLResponse|fastapi\.HTMLResponse|aiohttp\.web\.Response|"
                      r"sanic\.response\.html|bottle\.HTTPResponse|werkzeug\.wrappers\.Response|"
                      r"express\.Response\b.*\.(send|write|end)|http\.ServerResponse\b.*\.(end|write)|"
                      r"document\.(write|writeln)|dangerouslySetInnerHTML|insertAdjacentHTML|jquery\b.*\.(html|append|"
                      r"prepend|after|before)|\$\(\)\.(html|append|prepend|after|before))$")
XSS_NOT_HTML = re.compile(r"json|text/plain|octet|csv|xml|javascript", re.I)
XSS_ASSIGN = {"innerHTML", "outerHTML", "srcdoc"}
RESPONSE_NAMES = {"res", "response", "reply", "resp"}
RESPONSE_SEND = {"send", "write", "end"}
REDIRECT_CALL = re.compile(r"^(flask\.redirect|werkzeug\.utils\.redirect|django\.shortcuts\.redirect|"
                           r"django\.http\.(HttpResponseRedirect|HttpResponsePermanentRedirect)|"
                           r"django\.http\.response\.HttpResponse(Permanent)?Redirect|"
                           r"(fastapi|starlette)\.responses\.RedirectResponse|fastapi\.RedirectResponse|"
                           r"aiohttp\.web\.(HTTPFound|HTTPSeeOther|HTTPMovedPermanently|HTTPTemporaryRedirect)|"
                           r"sanic\.response\.redirect|bottle\.redirect|quart\.redirect|"
                           r"express\.Response\b.*\.(redirect|location)|next/navigation\.redirect|"
                           r"next/server\.NextResponse\.redirect|location\.(assign|replace)|"
                           r"window\.location\.(assign|replace)|window\.open)$")
REDIRECT_ASSIGN = {"location", "location.href", "window.location", "window.location.href", "document.location",
                   "document.location.href", "self.location", "top.location", "top.location.href"}
NOSQL_LIBS = re.compile(r"^(mongodb|mongoose|pymongo|motor|mongoengine|monk|mongojs|flask_pymongo)\b")
NOSQL_MEMBERS = {"find", "findOne", "findOneAndUpdate", "findOneAndDelete", "findOneAndRemove", "findOneAndReplace",
                 "update", "updateOne", "updateMany", "deleteOne", "deleteMany", "remove", "count", "countDocuments",
                 "find_one", "find_one_and_update", "find_one_and_delete", "update_one", "update_many", "delete_one",
                 "delete_many", "count_documents", "replaceOne", "replace_one", "distinct", "where", "exists"}
NOSQL_CODE_KEYS = {"$where", "$function", "$accumulator"}
POLLUTION_CALL = re.compile(r"^(lodash|underscore|lodash\.merge|lodash\.mergewith|lodash\.defaultsdeep|lodash\.set|"
                            r"merge|deepmerge|deep-extend|merge-deep|mixin-deep|defaults-deep|extend|node\.extend|"
                            r"jquery|hoek|object-path|dot-prop|set-value)(\.(merge|mergeWith|defaultsDeep|set|setWith|"
                            r"zipObjectDeep|extend|applyToDefaults|ensureExists))?$")
POLLUTION_PLAIN = re.compile(r"^(lodash|underscore|jquery|hoek|object-path|dot-prop)$")

# a finding another tool made on the same line is the same problem: the flow is attached to it, not listed twice
SAME_PROBLEM = {
    "sql": re.compile(r"^(B608|B610|B611|LJ-SQL-CONCAT|LV-SQL|LN-SQL|LP-.*SQL)"),
    "shell": re.compile(r"^(B602|B604|B605|B609|LJ-EXEC|LA-MODEL-OUTPUT)"),
    "eval": re.compile(r"^(B102|B307|LJ-EVAL|B701|B702|B703)"),
    "deserialize": re.compile(r"^(B301|B302|B403|B506|B614|LJ-DESERIAL)"),
    "xxe": re.compile(r"^(B31[3-9]|B320|B40[5-9]|B410)"),
    "xss": re.compile(r"^(LJ-XSS|B308|B703)"),
    "path": re.compile(r"^(B202)"),
    "ssrf": re.compile(r"^(B310|LW-SSRF)"),
}

# ---------------------------------------------------------------------------------------------- what a check proves
DIGIT_METHODS = {"isdigit", "isdecimal", "isnumeric"}
CHAR_METHODS = {"isalnum", "isalpha", "isidentifier", "isascii_alnum", "islower", "isupper"}
VALIDATOR_ALL = re.compile(r"(^|\.)(isInt|isNumeric|isDecimal|isFloat|isBoolean|isMongoId|isUUID|isHexadecimal|"
                           r"isInteger|isSafeInteger|isFinite|is_integer|isdigit)$")
VALIDATOR_CHARS = re.compile(r"(^|\.)(isAlphanumeric|isAlpha|isSlug|isHexColor|isBase64|isJWT|isISO8601|isDate)$")
NAN_CHECK = re.compile(r"^(isNaN|Number\.isNaN)$")
URL_CHECK = re.compile(r"(^|\.)(url_has_allowed_host_and_scheme|is_safe_url|is_safe_redirect_url|isSafeRedirect|"
                       r"is_same_origin|isSameOrigin)$")
# An address inside the network. The host of an address is a name; what it leads to is known only once the name is
# looked up, and then the answer has to be asked whether it lies inside. Python's `is_private` covers this computer,
# the local network and the link-local range (cloud metadata); `is_loopback` and the others alone leave the rest open.
LOOKUP = re.compile(r"(^|\.)(gethostbyname|gethostbyname_ex|getaddrinfo)$|^(node:)?dns(/promises)?(\.promises)?\."
                    r"(lookup|resolve|resolve4|resolve6)$|^dns\.(resolver|asyncresolver)\.(resolve|query)$")
IP_PARSE = re.compile(r"^(ipaddress\.(ip_address|IPv4Address|IPv6Address)|netaddr\.IPAddress|"
                      r"ipaddr(\.js)?\.(parse|process)|ip-address\.(Address4|Address6))$")
IP_BLOCK_ATTRS = {"is_private"}             # true: inside. Not true: the address is out on the internet
IP_ALLOW_ATTRS = {"is_global"}              # true: out on the internet
IP_INSIDE_CALL = re.compile(r"^(ip\.isPrivate|private-ip(\.default)?|is-private-ip|ipaddr(\.js)?\.isPrivate)$")
IP_OUTSIDE_CALL = re.compile(r"^(ip\.isPublic|is-public-ip)$")
BLOCK_LIST = re.compile(r"(^|\.)BlockList\(\)$")          # Node's net.BlockList: `.check(address)` true = on the list
KEEP_SUBJECT = {"strip", "lower", "upper", "trim", "toLowerCase", "toUpperCase", "lstrip", "rstrip", "casefold",
                "toString", "decode", "encode", "trimStart", "trimEnd", "normalize", "title"}
EXITS = re.compile(r"(^|\.)(abort|exit|_exit|quit|fail|bail|die|reject|notFound|redirect_to_login|throwError)$|"
                   r"^(sys\.exit|os\._exit|process\.exit|flask\.abort|pytest\.fail|next/navigation\.(notFound|redirect))$")

DANGER = {   # characters that matter per kind of action; a pattern that allows none of them makes the value safe for it
    "sql": set("'\";\\ =()/*%"), "shell": set(" ;&|`$()<>\n'\"\\*?~!{}[]#"), "path": set("/\\"),
    "xss": set("<>\"'&"), "redirect": set("/:\\"),
}
SIMPLE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


def pattern_allows(pat: str, full: bool) -> set | None:
    """The characters a pattern lets a whole value consist of, or None when it does not bound the whole value (no
    anchors, a dot, a negated class, a look-around, or anything this small reader does not know)."""
    if not isinstance(pat, str) or len(pat) > 300:
        return None
    start = pat.startswith(("^", r"\A"))
    end = pat.endswith(("$", r"\Z", r"\z")) and not pat.endswith(r"\$")
    if not ((full or start) and (full or end)):
        return None
    body = re.sub(r"^(\^|\\A)", "", pat)
    body = re.sub(r"(\$|\\Z|\\z)$", "", body)
    allowed: set = set()
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c == "[":
            j = body.find("]", i + 2)
            if j < 0 or body[i + 1] == "^":
                return None
            inner = body[i + 1:j]
            k = 0
            while k < len(inner):
                ch = inner[k]
                if ch == "\\" and k + 1 < len(inner):
                    e = inner[k + 1]
                    got = _escape(e)
                    if got is None:
                        return None
                    allowed |= got
                    k += 2
                elif k + 2 < len(inner) and inner[k + 1] == "-":
                    lo, hi = ord(ch), ord(inner[k + 2])
                    if hi < lo or hi - lo > 100:
                        return None
                    allowed |= {chr(x) for x in range(lo, hi + 1)}
                    k += 3
                else:
                    allowed.add(ch)
                    k += 1
            i = j + 1
        elif c == "\\" and i + 1 < n:
            got = _escape(body[i + 1])
            if got is None:
                return None
            allowed |= got
            i += 2
        elif c in "+*?|":
            i += 1
        elif c == "{":
            j = body.find("}", i)
            if j < 0 or not re.fullmatch(r"\d*,?\d*", body[i + 1:j]):
                return None
            i = j + 1
        elif c == "(":
            if body.startswith("(?:", i):
                i += 3
            elif body.startswith("(?", i):
                return None
            else:
                i += 1
        elif c == ")":
            i += 1
        elif c in ".^$":
            return None
        else:
            allowed.add(c)
            i += 1
    return allowed


def _escape(e: str) -> set | None:
    if e == "d":
        return set("0123456789")
    if e == "w":
        return set(SIMPLE) - {"-"}
    if e in "sSWDbBnrtfvpPuxc" or e.isdigit():
        return None
    return {e}


def pattern_classes(pat, full: bool) -> frozenset:
    allowed = pattern_allows(pat, full)
    if allowed is None:
        return frozenset()
    if allowed <= SIMPLE:
        return CHARS
    out = {c for c, bad in DANGER.items() if not (allowed & bad)}
    if "." in allowed:
        out.discard("redirect")
    return frozenset(out)


# ---------------------------------------------------------------------------------------------- who may reach what
# Heuristics, each finding `tool_confidence: LOW`. "record" and "assign" are kinds of action like the ones above, but
# no check on the value makes them safe (a number is still someone else's order number), so they are not in ALL.
AUTHZ = ("record", "assign")
RULE.update({"record": "LT-AUTHZ-OWNER", "assign": "LT-AUTHZ-MASS-ASSIGN", "role": "LT-AUTHZ-ROLE"})
SEVERITY.update({"record": "MEDIUM", "assign": "MEDIUM", "role": "MEDIUM"})
FIXED_RANK.update({"record": "medium", "assign": "medium", "role": "medium"})
CWE.update({"record": 639, "assign": 915, "role": 285})
TITLE.update({
    "record": "reaches a record by an id from the request, and nothing compares the record's owner with who is "
              "signed in",
    "assign": "Everything the request sent is written onto a stored record, whatever fields it names",
    "role": "is an admin route, and nothing asks whether the signed-in person is an admin",
})
ACTION.update({
    "record": "chooses which record is read or changed",
    "assign": "is written onto a stored record, field by field as it was sent",
})
# A request value with one of these names picks one record (or one person's records).
ID_NAME = re.compile(r"(^|_)(id|ids|pk|uuid|guid|key|slug|no|num|number)$|[a-z0-9](Id|ID|Ids|Pk|Uuid|Guid|Key|Slug)$|"
                     r"^(user|username|email|account|owner|customer|member|tenant|org|profile)$")
# A name a person signs in with, where the others are a record's id
LOGIN_NAME = re.compile(r"^(username|user_?name|email|e_?mail|mail|login)$", re.I)
# The last word of a route's path (parameters aside) when the route signs a person in or up, or helps them back in.
# Nobody is signed in yet when such a route runs, and looking a person up by the name they typed is its job.
SIGN_IN_WORD = re.compile(r"(^|[-_.])(log[-_]?in|sign[-_]?in|sign[-_]?up|log[-_]?out|sign[-_]?out|register|"
                          r"registration|token|oauth2?|callback|recover|recovery|reset|forgot|forgotten|activate|"
                          r"activation|confirm|confirmation|verify|verification|otp|2fa|mfa)($|[-_.])", re.I)
PATH_PARAM = re.compile(r"^(\{.*\}|:.+|<.+>|\[.+\]|\*.*)$")
# What a called function is named (as whole lower-case words) when it makes or hands out a credential, takes one
# back or checks a password: a sign-in route calls these, so the name alone does not say somebody is signed in.
SIGNS_IN = re.compile(r"^(make|create|generate|gen|issue|sign|new|build|encode|mint|hash|set|save|store|send|write|"
                      r"add|grant|give|refresh|rotate|revoke|delete|remove|clear|destroy)\b|"
                      r"\b(password|passwd|pwd|credentials?|otp|2 ?fa|mfa)\b|"
                      r"^(log ?in|log ?out|sign ?in|sign ?up|sign ?out|register)( user)?$")
# What says who is signed in, besides `request.user` and its like (IDENT_ATTRS) and a dependency named for it.
IDENT_GLOBALS = {"flask_login.current_user", "flask.session", "flask.g.user", "flask.g.current_user",
                 "flask_jwt_extended.current_user", "flask_security.current_user", "flask_security.core.current_user",
                 "quart.session", "quart_auth.current_user", "flask_principal.identity", "flask_login.utils.current_user"}
IDENT_CALLS = re.compile(r"^(flask_jwt_extended\.(get_jwt_identity|get_current_user|get_jwt)|"
                         r"next-auth(/next)?\.(getServerSession|unstable_getServerSession|getToken)|"
                         r"next-auth/jwt\.getToken|@clerk/nextjs(/server)?\.(auth|currentUser|getAuth)|"
                         r"@auth0/nextjs-auth0\.getSession|iron-session\.getIronSession|"
                         r"@supabase/[\w-]+\b.*\.(getUser|getSession)|"
                         r"django\.contrib\.auth\.get_user|flask_login\.utils\._get_user)$")
# The part of a signed-in person that says what they may do. Read in a condition, it is a role check.
ROLE_WORD = re.compile(r"^(is_?)?(admin|administrator|superuser|super_?admin|staff|moderator|root|owner|manager)$|"
                       r"^(role|roles|permission|permissions|perms|scope|scopes|groups|privilege|privileges|"
                       r"abilities|capabilities|acl|access_level|accessLevel|user_type|userType|is_superuser|"
                       r"is_staff|isAdmin|isSuperuser|isStaff|isModerator|isOwner|isManager|has_role|hasRole|"
                       r"has_perm|has_perms|has_permission|hasPermission|has_scope|hasScope|can|cannot|is_authorized|"
                       r"isAuthorized|is_granted|isGranted|in_group|inGroup)$", re.I)
# A comparison with one of these is about the session's freshness or a form's token, not about whose record it is.
NOT_OWNER = re.compile(r"csrf|xsrf|nonce|captcha|otp|secret|expires|expiry|expire|ttl|password|passwd|"
                       r"(^|[._])(exp|iat|nbf|state|code|hash)([._\[]|$)", re.I)
# A call the code of which Lantern cannot read, named for a permission check, with the signed-in person in it.
AUTHZ_CALL = re.compile(r"(?i:owner|owns|permission|admin|authoriz|authoris|abilit|polic(y|ies)|allowed|privilege|"
                        r"belongs|entitle|access_?check|check_?access|is_?member|has_?access|can_?access|superuser)|"
                        r"(^|_)perms?(_|$)|(^|_)roles?(_|$)|[a-z]Roles?([A-Z]|$)|^[Rr]oles?([A-Z]|$)|(^|_)acl(_|$)|"
                        r"(^|_)can(_|[A-Z]|$)")
# A method that asks whether two values are the same (`order.user.equals(req.user._id)`).
EQUAL_MEMBERS = {"equals", "eq", "is", "isEqual", "__eq__", "localeCompare", "compare", "strictEqual", "same"}
# Fixed text that names a role. A comparison of the signed-in person with other fixed text ("active") asks no role.
ROLE_VALUE = re.compile(r"admin|super|staff|root|owner|manager|moderator|editor|operator|support|maintainer|"
                        r"privileged|internal", re.I)
# A secret only an admin has, by its name: a route that compares it with what the request sent is asking for an admin.
ADMIN_SECRET = re.compile(r"(admin|root|super|master)\w*[_.\-\[\]'\" ]*(key|secret|token|pass|pwd|password|credential)|"
                          r"(key|secret|token|pass|password)\w*[_.\- ]*(admin|root|master)", re.I)
SAME_SECRET = {"compare_digest", "timingSafeEqual", "constant_time_compare", "safe_str_cmp", "safeCompare",
               "secure_compare"}
PERSON_ATTR = re.compile(r"(email|e_mail|username|user_name|login|name|sub|uid|id)\W*$", re.I)
# A function named for giving back who is signed in. Taken by its name: this is where identity starts, not a check.
IDENT_FN = re.compile(r"^(get_?|require_?|fetch_?|load_?)?(current|auth|authenticated|logged_?in|session|active|"
                      r"request)_?(user|account|member|principal|identity)(_?id)?$|^(get_?jwt_?identity|"
                      r"get_?auth|current_?user(_?id)?|whoami|get_?me|get_?server_?session|get_?session_?user)$",
                      re.I)
# A dependency named like a session that is the database's, not the signed-in person's.
DB_NAME = re.compile(r"(^|_)(db|database|conn|connection|engine|sql|repo|repository|store|cache|redis|mongo|pool|"
                     r"uow|transaction)(_|$)|db_?session|session_?(maker|factory|local)|async_?session|"
                     r"^get_session$", re.I)
ANN_IDENT = re.compile(r"^(?:Optional\[)?\s*\w*(CurrentUser|CurrentActiveUser|CurrentSuperuser|AuthUser|"
                       r"AuthenticatedUser|ActiveUser|LoggedInUser|CurrentAccount|TokenData|TokenPayload|UserDep|"
                       r"CurrentUserDep)\w*\]?$")
CHANGE_MEMBERS = re.compile(r"^(delete|remove|destroy|update|replace|upsert|patch)|And(Update|Delete|Remove|Replace)$")
AUTHZ_RAISES = re.compile(r"^(authorize|authorise|ensure|require|assert|check|verify|deny|forbid|guard|enforce|must)",
                          re.I)
# Middleware, a decorator or a dependency from a library (code Lantern does not read), taken by its name.
ROLE_NAME = re.compile(r"admin|superuser|staff|role|permission|authoriz|authoris|scope|acl|rbac|abilit|privilege|"
                       r"owner|owns|polic|(^|[._])can([A-Z_.(]|$)|user_passes_test", re.I)
ADMIN_PATH = re.compile(r"(^|[/ ])(admin|administrator|superuser|backoffice|back-office)(/|$|[?#.])", re.I)
# Database text that reads, changes or removes rows that exist (an INSERT makes a new one: nobody else's record)
RECORD_SQL = re.compile(r"^\W*(select|update|delete|with|replace)\b", re.I)
SQL_WHERE = re.compile(r"\bwhere\b", re.I)
# Calls of a database library that reach one record by a key or a filter. The first set is said only of data.
RECORD_SURE = {"findById", "findByPk", "findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "findOne",
               "findOneBy", "findOneOrFail", "findOneByOrFail", "findByIdAndUpdate", "findByIdAndDelete",
               "findByIdAndRemove", "findOneAndUpdate", "findOneAndDelete", "findOneAndRemove", "findOneAndReplace",
               "get_or_404", "first_or_404", "get_object_or_404", "get_or_none", "deleteOne", "deleteMany",
               "updateOne", "updateMany", "replaceOne", "find_one", "find_one_and_update", "find_one_and_delete",
               "find_one_and_replace", "delete_one", "delete_many", "update_one", "update_many", "replace_one",
               "filter_by", "destroy", "findMany", "deleteById", "updateById", "removeById", "findAndCountAll",
               "get_by_id", "getById", "delete_by_id"}
RECORD_MAYBE = {"get", "find", "filter", "where", "update", "delete", "remove", "exclude", "findAll", "count",
                "upsert", "select", "eq", "match", "byId"}
DATA_RECEIVER = re.compile(r"(^|[._(\[])(db|database|session|sess|conn|connection|cursor|cur|pool|prisma|knex|repo|"
                           r"repository|collection|coll|objects|query|orm|em|entityManager|manager|store|supabase|"
                           r"firestore|table|model|models|dao)([._()\[]|$)|Repository([.(]|$)|Repo([.(]|$)|"
                           r"(^|\.)[A-Z][A-Za-z0-9]*(\.(objects|query|select\(\)))?$")
NOT_DATA = re.compile(r"^(Array|Object|Map|Set|WeakMap|WeakSet|Promise|JSON|Math|Date|String|Number|Boolean|Symbol|"
                      r"Reflect|Buffer|URL|URLSearchParams|FormData|Headers|Request|Response|Error|RegExp|Intl|"
                      r"console|process|window|document|localStorage|sessionStorage|React|Router|NextResponse|os|"
                      r"sys|re|json|math|time|datetime|logging|Path|Counter|OrderedDict|Decimal|Fraction)\b")
DATA_LIBS = re.compile(r"^(sqlalchemy|flask_sqlalchemy|django\.db|peewee|tortoise|pony|sqlmodel|mongoengine|pymongo|"
                       r"motor|beanie|odmantic|mongoose|mongodb|sequelize|typeorm|@prisma/client|prisma|knex|"
                       r"objection|bookshelf|mikro-orm|@mikro-orm/[\w-]+|drizzle-orm|waterline|@supabase/[\w-]+|"
                       r"firebase-admin|firebase/firestore|@google-cloud/firestore|dynamoose|redis-om|"
                       r"flask_pymongo|" + SQL_LIBS[1:] + r"(?![\w-])")
# Calls that write what they are given onto a stored record, or make one of it.
WRITE_MEMBERS = {"update", "create", "insert", "insertOne", "insert_one", "insertMany", "insert_many", "save",
                 "updateOne", "update_one", "updateMany", "update_many", "findByIdAndUpdate", "findOneAndUpdate",
                 "find_one_and_update", "upsert", "set", "setAttributes", "assign", "merge", "bulkCreate",
                 "replaceOne", "replace_one", "findOneAndReplace", "update_or_create", "get_or_create", "patch",
                 "updateAttributes", "update_attributes", "fill", "populate_obj", "from_dict", "updateById"}
WHOLE_KEYS = {"...", "$set", "$setOnInsert", "data", "values", "update", "defaults", "create", "attributes", "set"}
BODY_BAGS = {"json", "body", "form", "data", "get_json", "POST", "payload", "values", "post", "forms"}
OVERLAY_CALL = re.compile(r"^(Object\.assign|lodash\.(assign|assignIn|extend|merge|defaults)|underscore\.(extend|"
                          r"assign|defaults)|jquery\.extend|\$\.extend)$")
# A class a stored record is made from (its bases as written). pydantic's BaseModel checks what it is given: not one.
MODEL_BASE = re.compile(r"(^|\.)(Model|Base|DeclarativeBase|SQLModel|Document|DynamicDocument|EmbeddedDocument|"
                        r"BaseDocument|Entity|ActiveRecord)$")
MODEL_PATH = re.compile(r"(^|[./])(models?|entit(y|ies)|schemas?|db|database)([./]|$)", re.I)
NOT_RECORD_CLASS = re.compile(r"^(Error|TypeError|RangeError|Date|URL|URLSearchParams|Map|Set|Promise|Buffer|FormData|"
                              r"Headers|Request|Response|Array|Object|RegExp|Blob|File|Event|CustomEvent|Proxy|"
                              r"Uint8Array|TextEncoder|TextDecoder|AbortController|Intl\.\w+)$")
EMPTY = ("", None, 0, False)
