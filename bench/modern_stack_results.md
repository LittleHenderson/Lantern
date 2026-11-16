# The modern-stack readers and the type-aware pass, measured (2026-11-15)

What stage 1 of the roadmap of 2026-11-14 added was measured on twelve public projects: the Supabase table calls,
Next.js Server Actions, tRPC procedures, the files of SvelteKit and Remix as routes, and the opt-in type-aware pass
(`lantern analyze --typecheck`). Five of the twelve are starter projects downloaded for this stage, one for each kind
of app it reads; seven are the projects of the map benchmark. Every project was read and never run: no install, no
test run, no tracing, nothing of a project started, and its libraries were not installed. Linux, Python 3.13.18, four
processor cores, the dependency audits off (`LANTERN_OFFLINE=1`).

**This is not a recorded benchmark run.** `bench/run_bench.py` measures the Python map against a trace, and none of
these rules has a trace to be held against. The routes and links below were read by hand by the author, each against
the project's own code; the counts of what Lantern wrote come from its result files. No script in this folder repeats
the hand reading. The first numbers, the faults they showed and the numbers after the fixes are kept apart, and so are
the measurements that failed. Each new kind of link keeps the confidence these numbers support and no more.

## The projects

| Letter | What it is | Read at |
|---|---|---|
| A | a Next.js starter with Supabase and a payment provider | 9839fd4 |
| B | a Next.js starter with a database library and Server Actions | 6e33e58 |
| C | a tRPC monorepo (a Next.js app, a phone app, shared packages) | 8f945b7 |
| D | a SvelteKit starter with Supabase | 2e61406 |
| E | a Remix starter | 56abb93 |
| M1 to M7 | the seven projects of the map benchmark, in the order of the table in `scanner_start_results.md` | the refs written there |

## 1. Routes and links (roadmap steps 1 to 4)

A "server door" is a function a request from outside reaches: a Server Action, a tRPC procedure, a verb, `load` or
action of a SvelteKit route file, a Remix `loader` or `action`. A door counts as found when the map has an entry point
on the right function with the right address; a link counts as right when the code it names is the code that runs.

### First numbers, before any fix (code 3162715; A to D)

| Project | Doors of the new kinds | Found | Wrong |
|---|---|---|---|
| A | 4 Server Actions | 4 | 0 |
| B | 10 Server Actions | 3 | 0 |
| C | 6 tRPC procedures | 6 | 0 |
| D | 19 doors of SvelteKit route files | 19 | 0 |
| A to D | 39 | 32 | 0 |

D's pages: 25 of 25. The seven Server Actions of B that were missed are made by a helper (`export const save =
checked(schema, async (data) => …)`), which the reader did not look through.

| Kind of link | Read | Right |
|---|---|---|
| a tRPC client call to its procedure (`http-trpc`) | 12 | 12 |
| SvelteKit: a page to a server `load` (18) and a form to its action (2) (`http-sveltekit`) | 20 | 20 |
| SvelteKit: a page to the `load` of a `+page.ts` or `+layout.ts` file (`sveltekit-load`) | 18 | 18 |
| SvelteKit: a page to a layout it is drawn in (`sveltekit-layout`) | 67 | 67 |
| a Supabase table call, the client known by where it came from (`supabase-from`) | 12 | 12 |
| a Supabase table call, the client known by its name only (`supabase-name`) | 3 | 3 |
| a library's name on a call, reached through a value (`library-value`, `library-result`); those checked | 67 | 65 |

What the links missed on D: 6 of its 10 Supabase table calls were linked (the other four go through a client called
`supabaseServiceRole`), of the 8 pages that post a form, 2 were linked to their action (the other six post through one
form that stands in a shared part, where the page writes the address), and the data-flow step showed a login on 0 of
the 8 routes that have one (the function that asks who is signed in is taken out of `locals` first, `({ locals: {
safeGetSession } })`).

### The ten faults that showed, each fixed after a failing test

1. A paid-call finding's story said "anyone with an account" where no login had been found: the finding now keeps what
   it found (`paid: {login, limit}`) and the story is written from that.
2. SvelteKit: a function taken out of `locals` before it is called is the same function.
3. A Supabase client under a longer name that begins with the library's is a client by its name (`supabase-name`,
   possible).
4. A Server Action made by a helper is a route; the helper is what runs first (`action-helper`, likely); a login it
   asks for counts, one it asks late or does not enforce does not.
5. A query builder's condition functions (`eq`, `and`, `inArray`) hold the values they compare, so an owner asked for
   in a `where` is seen.
6. A package of the project itself is followed to its file and never called a library; a library's name that a project
   file hands on is that library's.
7. A SvelteKit form in a shared part posts where the page that uses the part says (`http-sveltekit-prop`, likely;
   possible where several actions fit).
8. A visitor who is sent on to another page was not turned away: a sign-in action showed a login it does not have.
9. One of two functions handed to a call (`useActionState(first ? signIn : signUp, null)`) is linked like one.
10. A webhook's sender check on a client made the older way, in another file, counts again. Two tests had been failing
    on the stage's branch unnoticed since an earlier change of this stage; no side run had held their file. A run of
    the whole suite now comes before any measurement.

### After the fixes (code fa53253; A to D)

| What | Before the fixes | After |
|---|---|---|
| server doors of the new kinds found, of 39 | 32, none wrong | 39, none wrong |
| Server Actions of B, of 10 | 3 | 10 |
| B: a helper-made action to its helper (`action-helper`) | not read | 9 of 9 right |
| B: a page to the actions it hands to a hook (`callback`), new | none | 7 of 7 right |
| D: pages that post a form, linked to their action | 2 of 8 | 8 of 8; the 6 new links (`http-sveltekit-prop`) right |
| D: Supabase table calls linked | 6 of 10 | 10 of 10 |
| `supabase-name` links right | 3 of 3 | 6 of 6 |
| a library's name on a call, right of those checked | 65 of 67 | 72 of 72 |
| C: calls followed into the project's own packages | not followed | 74, all right, each checked against its import |
| D: routes with a login on which the data-flow step shows it, of 8 | 0 | 8 |
| B: Server Actions on which the data-flow step shows a login | not measured at first (7 of the 10 were no doors yet) | 7; sign-in and sign-up rightly none (both showed one they do not have until fault 8 was fixed) |

The two wrong library labels were withdrawn, not corrected: those calls are unresolved again. On the seven projects of
the map benchmark no link an earlier version made changed: five have the same map link for link, and two gained 73
library labels on calls that were unresolved before.

### Remix (E; its reader was committed before the project was opened)

First numbers (code 9aa6d37): doors 12 of 12, none wrong; pages 6 of 6; posting forms linked to their action 5 of 5;
26 links the framework's wiring gives (17 `http-remix`, 9 `remix-layout`), all right; a login shown on 4 of the 4
routes that ask for one, none wrongly. One false alarm: "owner not checked" on the sign-up page, because the function
that starts the new session reads the session cookie and that was taken for a login check. Fixed after a failing test
beside two cases that must stay caught (code 23ed3d6): the false alarm is gone, and the other eleven projects have the
same map and the same findings before and after that fix.

E is small (12 doors), and the test app the reader was written against resembles it, since both follow the framework's
own example. This measurement shows less than the other four.

### Findings on the five, before this stage (code 6e119fe) and after

Written critical / high / medium / low, then the readiness grade, score and the shape Lantern gave the project.

| Project | Before | After | What changed |
|---|---|---|---|
| A | 0/0/2/0, D 60, full-stack web app | 0/0/2/0, D 60 | nothing |
| B | 0/0/1/0, F 56, full-stack web app | 0/0/4/0, F 56 | 3 new paid-call findings on Server Actions |
| C | 0/1/4/1, F 48, React Native app | 0/1/4/1, F 48 | nothing |
| D | 0/0/5/0, C 76, library | 0/1/9/0, F 46, full-stack web app | 5 new paid-call findings; read as an app with routes, no longer as a library |
| E | 0/0/1/1, F 57, frontend web app | 0/1/0/1, F 58, full-stack web app | one finding medium → high: it now names its route |

Eight findings are new. All eight are `LA-WALLET-DRAIN`, the paid-call rule as it was before this stage, on doors the
map did not have before. Read by hand: **2 are right** (D: a contact form anyone can send and a profile change, each
sending e-mail with no limit on how often) and **6 overstate** (B: 3, D: 3; a payment provider's calls that cost
nothing, such as opening a billing page, are counted as spending money). The finding that rose on E is `LT-SSRF` on a
health check that fetches an address built from a request header: true, and now ranked with its route. No new
`LW-AUTH-MISSING` on any of the five. D's grade fell from C 76 to F 46: Lantern now reads it as an app with routes,
where it read a library before, holds it to an app's checks and counts the new findings. Nothing in D changed.

### The stage's final code, with the type-aware pass switched off

The pass is off unless asked for. With it in the code and off, all twelve projects read as they did after the last fix
above: no call site, link, entry point, finding, protection or shown login differs.

### Still wrong after this stage, and said

- The paid-call rule decides that a login is there by names. On B a function that makes a token is read as a login
  check: the verdict is wrong on one route, whose story says "anyone with an account" where no login is asked for, and
  right on two actions for a reason the rule did not read. The data-flow step's evidence is not used by that rule yet.
- A payment provider's calls that cost nothing count as paid (the 6 above).
- A value the project's own function hands back (`export const auth = initAuth()`) is not followed: 5 calls on C stay
  unresolved.
- The data-flow step does not read a tRPC middleware as a gate.

## 2. The type-aware pass (roadmap step 5; all twelve projects)

With `--typecheck`, the written calls Lantern's own reading left unresolved are asked of pyright 1.1.414 (Python) and
of the TypeScript compiler 6.0.2 (JavaScript and TypeScript), both found outside the project and started in a folder
of Lantern's own. The total of calls never moves: a call is one call before and after, and only its outcome changes.
The pass was measured four times; each is kept.

1. **Failed.** pyright "could not be started" on five of the six Python projects. Three seconds after its start it
   looks for the process that started it; the walls it runs behind refused the look and it left. The small test
   projects had finished before the three seconds. Fixed after failing tests; the numbers of this measurement are not
   used.
2. **Failed the 90% bar.** 345 new links, all "likely" (328 Python, 17 TypeScript). Of a fixed-seed sample of 60
   Python links read by hand, 46 were right, 13 wrong and 1 depends on the system the code runs on: 77% at best.
   Twelve of the wrong ones led to a method that only declares (`@abstractmethod`, a body of `...` or `raise
   NotImplementedError`) where a class beneath does the work, one to a method the project's default subclass replaces.
   The checker was right about the value's type each time; the type is not the code that runs. Fixed by a rule, tests
   first: a method that only declares is never linked, and the methods that replace it in the classes beneath are each
   "possible".
3. After that rule (code af6daa2): 275 likely and 36 possible Python links, 17 likely TypeScript links. The fresh
   sample below was drawn from this measurement.
4. The final code (b1684ca), after two more corrections that came from reading the links: the name a replacing
   method's link bears, and what a TypeScript class that is made leads to. Every call it placed and every target is
   the same as in measurement 3. The numbers below are this one.

### Calls that could not be placed, before and after (final code)

| Project | App code: unresolved, of written calls | Test code: unresolved, of written calls | pyright: asked: confirmed / likely / possible / built-in / library / declared only / no answer | TypeScript: the same | Seconds to build the map, without → with | Checkers' peak memory, MB |
|---|---|---|---|---|---|---|
| M1 | 336 → 113 of 2,211 | 219 → 169 of 2,270 | 555: 0 / 6 / 8 / 155 / 104 / 44 / 238 | not asked | 0.53 → 18.09 | 520.3 |
| M2 | 350 → 176 of 1,526 | 906 → 792 of 2,708 | 1,240: 0 / 40 / 7 / 140 / 101 / 82 / 870 | not asked | 0.54 → 29.56 | 648.9 |
| M3 | 862 → 442 of 5,165 | 332 → 220 of 4,647 | 1,194: 0 / 173 / 15 / 237 / 107 / 392 / 270 | not asked | 1.11 → 28.69 | 727.2 |
| M4 | 223 → 139 of 992 | 295 → 265 of 1,630 | 517: 0 / 7 / 0 / 73 / 34 / 182 / 221 | not asked | 0.35 → 4.15 | 304.5 |
| M5 | 472 → 168 of 2,180 | 394 → 227 of 1,826 | 866: 0 / 49 / 6 / 223 / 193 / 91 / 304 | not asked | 0.58 → 41.00 | 817.1 |
| M6 | 264 → 133 of 2,054 | 566 → 557 of 1,323 | 98: 0 / 0 / 0 / 12 / 15 / 1 / 70 | 732: 0 / 13 / 0 / 100 / 0 / 44 / 575 | 0.59 → 4.62 | 320.9 |
| M7 | 141 → 116 of 1,184 | 0 → 0 of 0 | not asked | 141: 0 / 0 / 0 / 25 / 0 / 1 / 115 | 0.73 → 1.59 | 195.4 |
| A | 40 → 20 of 459 | 0 → 0 of 0 | not asked | 40: 0 / 0 / 0 / 20 / 0 / 6 / 14 | 0.22 → 0.94 | 186.8 |
| B | 61 → 48 of 838 | 0 → 0 of 0 | not asked | 61: 0 / 0 / 0 / 13 / 0 / 3 / 45 | 0.33 → 1.01 | 193.0 |
| C | 139 → 134 of 616 | 0 → 0 of 0 | not asked | 139: 0 / 0 / 0 / 5 / 0 / 0 / 134 | 0.25 → 1.05 | 191.8 |
| D | 138 → 125 of 462 | 17 → 11 of 150 | not asked | 122: 0 / 4 / 0 / 15 / 0 / 0 / 103 | 0.30 → 1.05 | 186.0 |
| E | 62 → 50 of 321 | 81 → 75 of 111 | not asked | 143: 0 / 0 / 0 / 18 / 0 / 1 / 124 | 0.25 → 1.01 | 192.2 |
| all twelve | 3,088 → 1,664 of 18,008 | 2,810 → 2,316 of 14,665 | 4,470: 0 / 275 / 36 / 840 / 554 / 792 / 1,973 | 1,378: 0 / 17 / 0 / 196 / 0 / 55 / 1,110 | 0.22 to 1.11 → 0.94 to 41.00 | 186.0 to 817.1 |

"Not asked" means no call of that language was unresolved. On D, 33 unresolved calls stand in `.svelte` files, which
the pass does not ask about.

Where the placed calls went. App code: 1,424 placed, likely +146, possible +33, library +360, built-in +885; resolved
(5,381) and name-only (540) as they were. Test code: 494 placed, likely +146, possible +3, library +194, built-in
+151.

### Were the new links right

- **No link was confirmed by a checker** (0 of the 292 calls it linked into a project as likely). The roadmap's word
  for this step is "resolved"; that is not claimed. The links are "likely" or "possible".
- A fresh fixed-seed sample of 60 of the 275 likely Python links, read by hand: 60 right.
- All 17 likely TypeScript links, read by hand: right.
- All 36 calls linked as "possible" name methods of real subclasses.
- Where a checker and Lantern both read a call, they agree. The checkers were also asked about 13,347 calls Lantern
  had linked into the projects by itself; they answered with a function for 10,020 of them, the same one for 10,018.
  Of the two that differ, one is Lantern's older reading being wrong (an import inside a function shadows the file's
  own function of the same name; written down as a known gap), and one depends on the system the code runs on.

Read with the numbers: 1,973 of the 4,470 Python calls and 1,110 of the 1,378 JavaScript and TypeScript calls got no
answer. The projects' libraries were not installed and the project's own Python is never used, so a checker sees the
project's files and its language's own library only; with the libraries there, more calls would get an answer, and
that was not measured. No TypeScript call was labelled a library's for the same reason.

## Not measured here

- Precision against a trace. The hand reading says where a link goes in the code; it does not say the call happened.
- The five starter projects running: they were never started, and their own tests were never run.
- The type-aware pass with the projects' libraries installed.
- The type-aware pass on Windows and macOS: the measurement was on Linux. The tests that start the real checkers run
  on all three in CI.
- Calls in `.svelte` files and in a page's own script, which the pass does not ask about.
- More than one project of each kind. One starter project per framework shows that the reader holds on a project it
  was not written against; it is not a precision number across projects, and the confidence words say so: the links by
  name are "possible", the helper and shared-part links "likely" with their numbers above, and the rules that read
  meaning from names stay marked heuristic.
