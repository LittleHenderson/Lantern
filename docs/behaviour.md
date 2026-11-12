# Behaviour checks: what the running app really does

`lantern analyze` reads code. `lantern behave` starts the app and asks it things, as the people who must be refused
and as the people who may, and then looks at the database and the files: **a refused request that changed
something all the same is a failure**, whatever the answer said.

```bash
lantern behave PATH            # runs PATH/lantern-behaviour.json, writes PATH/.lantern/behaviour.json
```

Result `0` only when every case held; `1` when a case is broken, undecided or was not run; `2` when there is no
plan or the plan cannot be used; `3` when the app was not started (the sandbox could not be set up on this system,
the plan's set-up failed, or the run left no record). A case that was not run never counts as held. On Windows no
app is started yet, so the result there is `3` (see Limits).

## Where it runs, and where it never does

The app is started inside Lantern's test sandbox (the one "Watch my tests run" uses): on a read-only copy of the
project, with the environment rebuilt from an allow-list, no network, and a temp folder for its data that is deleted
afterwards. It is not served at any address: requests are handed to the app inside one process, over a pipe.

A plan holds **paths only**. A request that names an address (`https://…`, `//host/…`) or a `Host` header is
refused before anything starts, so a plan cannot be pointed at a live site, and the app's database files and folders
must lie in the folder the sandbox gives it (`{data}`). The app has to take the place of its data from the
environment (`"env": {"APP_DB": "{data}/app.db"}`); an app with its database address written in the code is not
started against it, because nothing outside this computer can be reached.

Only ASGI apps in Python are started this way (FastAPI, Starlette, Quart, Django's ASGI app, or a plain
`async def app(scope, receive, send)`), with SQLite as the database whose rows are compared. Other servers and
databases are not started yet (see Limits).

## The plan

`lantern-behaviour.json`, in the project's top folder:

```json
{
  "app": {"asgi": "notes.main:app", "env": {"NOTES_DB": "{data}/notes.db", "NOTES_SECRET": "{secret}"}},
  "state": {"sqlite": ["{data}/notes.db"], "folders": ["{data}/uploads"]},
  "people": {"alice": {"token": "{alice_token}"}, "amir": {"token": "{amir_token}"}},
  "tokens": {"hs256_secret": "{secret}"},
  "quiet_tables": ["audit"],
  "seed": [
    {"request": {"method": "POST", "path": "/signup", "json": {"email": "alice@example.test", "password": "a-made-up-phrase"}}},
    {"request": {"method": "POST", "path": "/login", "json": {"email": "alice@example.test", "password": "a-made-up-phrase"}},
     "save": {"alice_token": "json:token"}},
    {"request": {"method": "POST", "path": "/notes", "json": {"text": "milk"}}, "as": "alice", "save": {"note": "json:id"}}
  ],
  "checks": [
    {"id": "delete-note", "kind": "refuse", "about": "Only its owner deletes a note",
     "request": {"method": "DELETE", "path": "/notes/{note}"}, "who": ["amir", "nobody"], "allowed": ["alice"]}
  ]
}
```

* `app.asgi` is how the app is loaded (`package.module:name`); with `"factory": true` the name is a function that
  makes the app (`create_app`, what a server's `--factory` is for); `app.cwd` a folder of the project to start it
  in; `app.env` what it is told. `{data}` is the app's own folder in the sandbox, `{secret}` a random text made for the run.
* `state` names what is compared before and after every step: SQLite files (row by row) and folders (file by file).
  Everything else in the sandbox's temp folder counts as "outside".
* `people`: how each signs in. `token` is sent as `Authorization: Bearer …` (`header` and `scheme` change that).
  `nobody` is always there: no sign-in at all.
* `seed` is the set-up, run once: requests (`as` a person; `save` keeps a value of the answer, `json:path.to.value`
  or `header:name`, for later `{name}`) and `sql` steps (`{"db": "{data}/notes.db", "run": "UPDATE …", "args": []}`)
  for what no request can set. After it the state is kept as an image; a case that changes something starts the next
  one from that image again, with the app started afresh.
* A request has `method`, `path`, `query`, `headers` and one body: `json`, `text`, `bytes` (that many), `base64`, or
  `zip` (entries `{"name", "text"}` or `{"name", "zeros": n}`). `{"$fill": n}` in a value becomes n characters.
* `quiet_tables` may change when a request is refused (a table of who tried what).
* `names` says where a name leads (`{"files.inside.test": "10.0.0.5"}`); `may_reach` lists the names or addresses the
  app may try, for the whole plan or for one check.

### Kinds of check

| `kind` | What must hold | Cases | Broken when |
|---|---|---|---|
| `refuse` | `who` are refused, `allowed` are not | one per person | let in; refused but something changed; the answer holds a `must_not_say` text; server error |
| `hide` | `who` do not get to see `must_not_say`, `shown_to` do | one per person | the text is in the answer |
| `tokens` | a sign-in token that is missing, empty, garbage, cut short, altered, unsigned, signed with another key or expired is refused (`variants` picks some of `none`, `empty`, `garbage`, `truncated`, `altered`, `unsigned`, `other-key`, `expired`; the last four need a signed token of three parts; `claims` is what an altered one says) | one per variant | let in; refused but changed |
| `input` | `request` (the bad one) is refused, `good` (the ordinary one) is not | one | accepted; refused but changed |
| `keeps` | after `request`, the `after` request still answers as `expect` says (and not as `expect_not`) | one | took effect |
| `contain` | `request` writes nothing outside the app's folders | one | outside file |
| `redirect` | the answer does not send the visitor to another site (`own_hosts`) | one | sent elsewhere |
| `address` | the app sets out for no address but `may_reach` | one | outside address |
| `limit` | after `times` tries the next is refused (`limited`, default 429 or 423), straight after, after a restart, and on another copy of the app | three | unlimited; forgotten |
| `once` | two of the same request at the same moment end as one after the other does | one | raced |
| `retry` | the same request sent again, or sent again after the answer was lost, is not done twice | two | repeated |
| `faults` | the request is made to fail at each of its database writes and commits, and is cut off before each and before the answer leaves; afterwards all of its work is there or none, and `then` (somebody else's ordinary request) works and saves only its own | one per place | partial; carried over; stuck |

Every check can have `arrange` (steps run before each of its cases) and `about` (a sentence shown with the outcome).

## What comes out

`behaviour.json` (shape in `docs/api.md`): one outcome per case.

* **held**: the app did what the plan says must hold, and the control beside it worked.
* **broken**, with codes: `let-in`, `refused-but-changed`, `leaked`, `accepted`, `took-effect`, `sent-elsewhere`,
  `outside-address`, `outside-file`, `unlimited`, `forgotten`, `raced`, `repeated`, `partial`, `carried-over`,
  `stuck`, `crashed`; `saw` holds the status, what changed (`{"notes": [added, removed, changed]}`), what the app
  asked about names, what it set out for, what the sandbox refused, and the files outside its folders that it
  made, removed or changed.
* **inconclusive**: the control failed. A refusal counts only when the same request from the person who may make it
  worked (and, for a request that changes things, changed something): an app that refuses everybody proves nothing.
* **not-run**, with the reason (the app could not be started, a step of the case's own set-up failed).

Asking where a name leads is not reaching it. The runner answers such questions itself, so no question leaves the
sandbox: an address written as numbers is itself (in any spelling the system reads as numbers: `127.1`,
`2130706433`, `::1`), a name in `names` leads where the plan says, any other name gets an address of its own from the
ranges kept for examples (198.51.100.0/24, 203.0.113.0/24). An app that looks a name up, sees that it leads inside
and refuses, holds; an app that goes on is refused by the sandbox at the connection and the case is broken.

## Limits

* The outcomes are a record of their own. They do not create, close or re-rank a finding, and the report, the
  Evidence Report and the readiness score do not read them yet.
* `behaviour.json` lies in the results folder, which is a folder anybody who can write there can change: the record
  proves what a run on this computer saw, to the person who ran it. Run `lantern behave` yourself.
* Only what the plan asks is tried. A plan with one check tells one thing.
* Not on Windows yet: no app is started there, and the command says why and ends with `3`. Python's event loop on
  Windows makes its connections in a way the sandbox's guard is not told about, so a case could come out held
  while a request left the computer. Until the guard sees those connections, run the checks on Linux or macOS.
* The runner sees an app set out for an address when the app's Python code makes the connection: `socket` and what
  is built on it (`urllib`, `requests`, `httpx` and asyncio's own connections were tried). A connection made below
  Python (gRPC, pycurl, an event loop written in C, a database driver in C) is not seen: on Linux the kernel still
  refuses it, but the case comes out held for an app that did set out.
* On macOS and a Linux kernel without Landlock the sandbox has fewer walls (`docs/audit/THREAT_MODEL.md`): what the
  app's Python code tries is refused and reported as everywhere, a program the app starts that is not Python is held
  only by the read-only copy and the rebuilt environment, and a connection made below Python is not refused. Start
  an app you do not trust on Linux.
* Python ASGI apps and SQLite only. An app that needs another database, a queue or a second service to start is not
  started (the case comes out `not-run` with the app's own error). Rows of other databases are not compared.
* The app is asked through its ASGI interface, in one process per copy: what a reverse proxy, a web server or a
  load balancer in front of it adds or strips is not there, and "another worker" is another process of the same
  code sharing the database file, not another machine.
* Failures are made at SQLite's writes and commits and at the answer; a failure inside a call to another service is
  not made (there is no other service in the sandbox).
* "At the same moment" holds the first request at its first database write until the second has finished: a race
  that needs another interleaving is not found.
* On a computer with no IPv6 an app's try for an IPv6 address is read from the socket it asks for after asking
  where the address is, one step before the connection (`saw.tried` says so).
