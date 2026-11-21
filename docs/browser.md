# Browser checks: what the site does in a real browser

**Status (2026-11-21, a firm pass or fail, stage 5):** this page was written before the checks were built, as the
contract they are built to. Each check below has a broken example and a safe twin in `tests/browse_sites.py`, and
`tests/test_browse.py` holds the checks to this page. The checks are built for Linux, macOS and Windows (macOS and
Windows since the rest of step 2, the same day); on any other system every check comes out `not-run` with the reason
`not-built`, and nothing else in Lantern reads the record yet.

`lantern analyze` reads the code. The browser checks open the project's own site in a real browser and say what
happened there: pages that do not open, errors in the page's own script, links and buttons that lead nowhere, forms
that cannot be sent, what a visitor who is not signed in can open, the protections the site really sends against what
its code says, anything a page asks another computer for, and the basics of use without a mouse.

```bash
lantern browse PATH      # opens the site of the project at PATH in a browser, writes PATH/.lantern/browser.json
lantern browse PATH --browser /full/path/of/chrome   # that browser (default: LANTERN_BROWSER, else where it is installed)
```

The command prints each check that did not hold, with its codes and the first three things the browser saw for it
(text of the site's own, printed with anything that is not printable replaced), then one line of counts. The record
is written whatever came out, also when nothing could be opened (`ran` false and the reason). Result `0` only when a
check held and every other check held or had nothing to check; `1` when a check is broken, undecided or was not run,
or none held; `2` when there is nothing to open (no pages and no app Lantern can start); `3` when the site was not
started or no browser could be used.

## Where it runs, and where it never does

* The site is the project's own. No address can be given: a check is never pointed at a live site.
* An app is started in the sealed box, the way `lantern behave` starts one: on a copy of the project, with no
  network, and its data is thrown away with the run. Plain pages are served from the project's folder by Lantern's own
  code, which hands out the project's own files only (a link that leads out of the project is not followed).
* Every request a page makes is stopped inside the browser before it leaves. One for the site's address is answered
  by Lantern from the site, through the pipe below; any other is refused there and written down with the page that
  made it. No program listens at the site's address: it is `http://localhost:<port>`, which a browser treats as a
  secure place, so the pages work as they do when the developer opens them.
* The browser's one way out is a door of Lantern's own on this computer that forwards nothing: what reaches it (what
  the browser asks for itself, not its pages) is refused and written down too.
* The browser gets a profile of the run's own, empty, removed afterwards: none of the person's own sign-ins, cookies
  or history is in it.
* The browser keeps its own sandbox. Lantern never starts it with that sandbox switched off; where the browser cannot
  have it here, the pages are not opened and the record says why (`no-browser-sandbox`).
* Lantern drives the browser through a pipe and never through a port, so a page's own script cannot reach the
  browser's controls.
* The browser is a program of its own: on Linux and macOS in a session of its own (as `nobody` where Lantern runs as
  root), on Windows made paused, put in a job of its own and only then let run. It is handed the two ends of its pipe
  and nothing else of Lantern's, and when the run ends it is closed and whatever it started is ended with it (its
  session's programs, or its job).
* Clicks and forms go to the site's own address only, and an app's data is thrown away with the run.
* Pictures of the pages stay on this computer.
* A browser check only says what the browser saw. It never creates, closes or re-ranks a finding.

Browsers: Chrome, Chromium, Edge and Brave, which Lantern drives the same way. `LANTERN_BROWSER` names one by its full
path; otherwise Lantern looks where each system installs them.

## The checks

Each check gives one outcome (below). A broken one lists what it saw, each with its code.

A page is looked at once it has settled: no request of it is under way, nothing on it has changed for a moment, and
nothing on it is still moving (a transition or an animation that comes to an end, by the browser's own list of them;
one that goes on for ever, a spinner, does not hold the page up), or once `PAGE_SECONDS` have passed. What a click or
a sent form does is looked at the same way, after a shorter wait (a form answered with a new page has a page's time
for that answer). Until 2026-11-21 a page that was still moving counted as settled: a cover that fades away as the
page opens was looked at and clicked while it was still there or after it had gone, and two runs on the same code gave
two answers.

### `opens`: every page opens

Looks at the start page and every page the site itself says it has: a route of the app's code that answers GET and
takes no value in its address, every `.html` file of a folder of plain pages; at most `MOST_PAGES`.
Broken when a page answers with a server error (`server-error`: 500 or more), a page the site says it has answers
"not found" (`not-found`: 404), no answer comes within `PAGE_SECONDS` (`no-answer`), or the page shows nothing at all
(`empty`: no text, picture or drawing that can be seen). A page that asks for a sign-in (401, 403, or a move to
another page of the site) is not broken.
Broken example: a route that divides by zero; a route that always answers 404; a route that never answers; a page
with an empty body. Safe twin: the same routes and page, answering with their content.
Codes: `server-error`, `not-found`, `no-answer`, `empty`.

### `script`: the page's own script runs without an error

Looks at the site's own scripts while each page loads and settles.
Broken when the site's script raises an error that nothing catches (`raised`), writes an error with `console.error`
(`console-error`), or a script the page names is not on the site (`not-loaded`). An error raised while Lantern clicks
or sends a form belongs to that check (`leads`, `forms`). The browser's own lines about a load it was refused are not
counted. An error on a page where a script from another computer was refused is undecided (below): it may come from
that script being missing. Nothing to check when the pages have no script.
Broken example: `document.title.notThere()` at the end of the page's script; a `console.error(...)` line;
`<script src="widgets.js">` with no such file. Safe twin: the same page without that line.
Codes: `raised`, `console-error`, `not-loaded`.

### `leads`: links and buttons lead somewhere

Looks at every link and button of every page opened, at most `MOST_CLICKS` a page: where a link points, and what a
click does.
Broken when a link points at an address the site does not have (`dead-link`: no route of the code, no file of the
folder; a page the site does have and that does not open is the `opens` check's), a link leads nowhere (`empty-link`:
`href="#"` and the like, and the click changes nothing but the part of the address after `#`), a button changes
nothing when it is clicked (`dead-button`: no change to the page, no new address, no request and no dialog), or a
click raises an error in the site's script (`button-raises`). Links to another computer are not followed and are not
counted; a form's own buttons are the `forms` check's.
Broken example: a link to `old-prices.html`, which is not there; `<a href="#">More news</a>`; a button whose handler
is never put on; a handler that looks for an element under a misspelt id. Safe twin: links to pages that are there,
and buttons whose handlers work.
Codes: `dead-link`, `empty-link`, `dead-button`, `button-raises`.

### `forms`: forms can be sent

Looks at every form of every page opened that is sent to the site itself: filled with made-up values by the kind of
each field (a name, an e-mail address at `example.com`, a number, a date) and sent once.
Broken when the site answers with a server error (`form-error`), the form is sent to an address the site does not
have (`form-nowhere`: 404 or 405), or the site's script raises an error when it is sent (`form-raises`). A site that
refuses the made-up values with an answer of its own (a 4xx other than 404 and 405) is checking what it is sent, which
is not broken. A form sent to another computer is not sent.
Broken example: a handler that reads a field under a misspelt name; a form sent to `/send`, which no route answers; a
submit handler that raises. Safe twin: the same form with the right name, address and handler.
Codes: `form-error`, `form-nowhere`, `form-raises`.

### `visitor`: a visitor who is not signed in is kept out where the code asks for a sign-in

Looks at every page that Lantern's reading of the code says asks who is calling (`route_logins` in `security.json`:
`shown` or `lookup`), opened by a visitor with no sign-in. GET only: what a request that changes something may do is
`lantern behave`'s.
Broken when the visitor is let in (`let-in`): the answer is 200 at the same address, holds no password field, and asks
for no sign-in. Kept out: 401 or 403, a move to another page, or a page with a password field. Nothing to check when
no page asks for a sign-in.
Broken example: a login check that falls back to a default person (`SESSIONS.get(key, "guest")`), so it never
refuses; Lantern's reading of the code cannot tell it from its twin. Safe twin: the same check without the default,
which refuses.
Codes: `let-in`.

### `protections`: the protections the code sets are sent

Looks at the headers and cookies of every answer the site gave the browser.
Broken when the code reading says a security header is set for every response (the "Security headers" protection
reads `in place`) and a page came without it (`said-not-sent`), or a cookie named like a sign-in (`session`, `sid`,
`auth`, `jwt` and the like) is set without `HttpOnly`, so that the page's script can read it (`cookie-open`).
`Strict-Transport-Security` is not compared: a site sends it over HTTPS only, and the site is served over plain HTTP
inside the run. Not run for plain pages (`hosting-unknown`): what a hosting service would send is not in the folder.
Broken example: a middleware that sets the policy only under `/api`, which the code reading takes for every response;
a session cookie set without `httponly`. Safe twin: the same middleware for every request; the cookie set with
`httponly` and `samesite`.
Codes: `said-not-sent`, `cookie-open`.

### `outside`: nothing is asked of another computer

Looks at every request a page makes that is not for the site: scripts, styles, fonts, pictures, frames, and what the
page's script sends (`fetch`, `XMLHttpRequest`, beacons, WebSockets). Each one is refused at Lantern's door and
written down with its address and the page.
Broken when a page asks another computer for a script (`outside-script`) or for anything else (`outside-file`).
Another address on this computer counts as another computer.
Broken example: an analytics script from a content network; a tracking picture; a `fetch` to another service. Safe
twin: the same page without them.
Codes: `outside-script`, `outside-file`.

### `keyboard`: it can be used without a mouse

Looks at every page opened, walked with the Tab key (once for each control of the page and a few more, up to a
limit), and at the names the browser itself gives its controls.
Broken when a link or button has no name the browser can tell (`no-name`: an icon button with no label, a picture
link with no `alt`), a form field has no label (`no-label`), something that answers a click and can be seen cannot be
reached with Tab (`not-reached`: a `div` with a click handler; a hidden one, with no size or `visibility: hidden`, is
not asked for, since nobody can click it either), the place the keyboard is at does not show (`no-focus-ring`:
nothing changes when a control is reached), or Tab cannot leave a place (`trapped`). These are the basics, not a
whole accessibility review: colours, headings and reading order are not judged.
A trap is a place where Tab and Shift+Tab both leave the keyboard where it is and the page's own script listens for
keys or focus there or above it. What a browser does by itself at the end of a page differs: the keyboard leaves the
page, goes back to the first control, or stays on the last. Lantern looks at it once a run, on a page of its own with
two buttons and no script (`keyboard_end` in the record), so a page with one link, in a browser that brings the
keyboard back to it or keeps it there, is no trap, and neither is a place the page's script does not hold. Tab moving
on inside a frame, a video or audio player with its controls, or a date or time field (Tab goes through its parts)
takes one press more and is no trap. Whether the place of the keyboard shows is not judged inside those, nor inside a
part of the page with a tree of its own, whose outline is drawn on its own elements.
Broken example: an icon button holding only a drawing; a phone field with no label; a menu made of a `div`;
`outline: none` on every control; a field whose script swallows Tab. Safe twin: the same controls with a label, a real
button, an outline that shows, and Tab moving on.
Codes: `no-name`, `no-label`, `not-reached`, `no-focus-ring`, `trapped`.

## Outcomes

* `held`: looked at, and nothing of this kind was found.
* `broken`, with codes; `saw` lists each thing seen: the code, the page, what it was (the control, the address asked
  for, the answer's status) and how the page was reached.
* `inconclusive`: everything the check saw is undecided (below): it may come from something the run itself refused.
* `nothing-to-check`: the site has nothing of this kind (no form, no page that asks for a sign-in), with why.
* `not-run`, with the reason: `not-built` (not built for this system yet), `no-browser` (no browser Lantern can drive
  was found), `no-browser-sandbox`, `browser-failed` (the browser stopped, or did not answer, before the pages were
  looked at), `no-site` (nothing to open), `not-started` (the app could not be started in the sealed box), `no-sandbox`
  (the sealed box cannot be set up here), `hosting-unknown` (only `protections`).

Only `held` counts as held.

**Undecided.** Every request for another computer is refused in a run (the `outside` check), so a page that loads a
script from another computer, a library from a content network, runs without it. What that script could have done on
the page is undecided on a page where one was refused while the page loaded: a page that shows nothing (`empty`), an
error of the page's own script (`raised`, `console-error`), a link that leads nowhere, a button that changes nothing
or raises (`empty-link`, `dead-button`, `button-raises`), a form whose script raises (`form-raises`), and a control
with no name or label, one Tab does not reach, or one whose place does not show (`no-name`, `no-label`,
`not-reached`, `no-focus-ring`). Such a thing is kept in `saw`, marked `undecided`, and gives no code. A check with at
least one decided thing is `broken` with the codes of the decided ones; a check whose every thing is undecided is
`inconclusive`. What the site answers, a file of the site's own that is not there, a link as the page was sent, a trap
(a listener of a script that did run) and a page a visitor was let into are decided whatever the refused script would
have done.

## What comes out

`browser.json` in the results folder (the shape to come): `of` (the code it is of, as in `behaviour.json`), `ran`,
`why_not`, `browser` (`name`, `version`, `own_sandbox`, `keyboard_end`: `leaves`, `wraps`, `stays` or `unknown`),
`site` (`how`: `pages` or `app`; `address`), `opened` (each page: its path, status and seconds), `checks` (one a
check: `id`, `outcome`, `codes` of the decided things only, `saw` with `undecided` on each undecided thing, `why`),
`asked_outside` (every request for another computer: address, kind, page; each refused) and `browser_own` (what the
browser itself asked for, not the pages, which is not counted for the site).

## How it is held to this

`tests/browse_sites.py` writes two small sites at test time: a folder of plain pages and a FastAPI app. Each is
written safe, or with one of 25 planted problems that changes only its own pieces (`PLANTED`: the check and the code
each must give), or as one of seven look-alikes (`LOOKALIKES`, each written before the fix it guards): a version that
looks like a problem to a careless check and is none, or where the run itself can only say undecided (a page of the
site in a frame, a date field, a part with a tree of its own, a page with one link that listens for keys, a hidden
element that answers a click, a library from another computer that the run refuses, a cover that fades away as the
page opens), each with what it must give. `tests/test_browse.py` checks that the list on this page is the list in
`lantern/browse.py`; that every planted version and look-alike is the safe site but for its own pieces; that Lantern's
reading of the code says the same of the app and of each twin where only a browser can tell them apart (the sign-in,
the headers); and, where `LANTERN_TESTS_BROWSER` names a browser by its full path, that each site written safe breaks
no check, that each planted problem breaks its own check, with its own code, and changes no other, and that each
look-alike gives what it must; the messages of those tests say what each check saw and what the browser does at the
end of a page. CI runs those in its browser job (Linux,
Playwright's Chromium, as the ordinary user), and at the end of its macOS job and of the Windows box's job, each on the
Chrome its machine comes with; no test may be skipped there. `tests/test_browser_driver.py` holds how the browser is
started and ended, with a stand-in browser that speaks the same pipe (on every system), and `tests/test_winspawn.py`
the Windows starter, with a stand-in for Windows' own calls (on every system) and on Windows itself.

## Limits

* Chromium-family browsers only: Firefox and Safari are not driven yet.
* Only what is opened is seen: the pages the site says it has, at most `MOST_PAGES`, and the controls on them, at most
  `MOST_CLICKS` a page, in one order. A problem that needs another order, or a signed-in person, is not found here
  (what a signed-in person may do is `lantern behave`'s).
* Forms are sent once with made-up values: a form that takes only a real value (a code that must exist) comes out as
  refused by the site, which is not broken.
* The visitor check reads "let in" from the answer: a page that asks for a sign-in in words only, with a 200 and no
  password field, is read as let in. A heuristic, like the reading of the code it is compared with.
* The app is served at `http://localhost:<port>`: an app that works only at its real address, or over HTTPS only, may
  answer otherwise there.
* Plain pages and Python ASGI apps, the ones `lantern behave` starts. Other servers, and the development servers of
  JavaScript tools, are not started yet (`not-started`); a built folder of plain pages in the project is opened as
  plain pages.
