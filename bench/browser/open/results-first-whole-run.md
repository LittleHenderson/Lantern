# Browser benchmark: the open part

`python bench/browser/run_browser.py WORKDIR --part open --runs 2`, 2026-11-23 00:16 (UTC), Lantern 000bb39, definition `693d745feb7e932c`, Chrome 153.0.8010.12, Python 3.13.18 on Linux, 3 side by side, 944 s in all. What was tried outside this computer and refused by the run's guard: 0. 

67 versions, 60 as written down, 7 not.
Planted problems found: 45 of 46. Safe sites and look-alikes as written down: 18 of 21.
False alarms (a code given that was not written down): 8: gl-disabled-button leads dead-button; gl-disabled-button leads dead-button; gl-print-button leads dead-button; gl-print-button leads dead-button; l-trapped keyboard not-reached; l-trapped keyboard not-reached; ll-csp-blocks-widget outside outside-script; ll-csp-blocks-widget outside outside-script.
Missed (a code written down and not given): 2: t-no-focus-ring keyboard no-focus-ring; t-no-focus-ring keyboard no-focus-ring.
Another outcome with no code involved: 4: t-chunk-missing keyboard nothing-to-check held; t-chunk-missing keyboard nothing-to-check held; t-blank-render keyboard nothing-to-check held; t-blank-render keyboard nothing-to-check held.
A row written down and not seen: 2: t-no-focus-ring no-focus-ring /index.html; t-no-focus-ring no-focus-ring /index.html.
Runs that could not be made: 0.
Each version opened 2 times; versions whose runs did not agree: 0.
What the browser itself tried to reach, refused at Lantern's door: 0. What the sites' pages asked of another computer, refused inside the browser: 44.

### garden: a community garden's plain pages, served as they are

| Version | Kind | What it is | What the checks gave, where not as on the safe site | As written down |
|---|---|---|---|---|
| `garden` | safe | the garden's five pages as they are | as the safe site | yes |
| `g-empty-page` | planted | a page whose whole content is hidden while it is being written | opens broken (empty) | yes |
| `g-script-raises` | planted | the script shared by every page uses the plot list's field on pages that have none, and stops there | script broken (raised); leads broken (dead-button); forms broken (form-raises) | yes |
| `g-console-error` | planted | the script writes an error on every page that has no events | script broken (console-error) | yes |
| `g-script-missing` | planted | the script was renamed and the pages still name the old file | script broken (not-loaded); leads broken (dead-button) | yes |
| `g-dead-link` | planted | the plot list links to the join page by a name it had before | leads broken (dead-link) | yes |
| `g-empty-link` | planted | a link to the rules that was never filled in | leads broken (empty-link) | yes |
| `g-dead-button` | planted | one reminder button got another class, so its handler is not put on | leads broken (dead-button) | yes |
| `g-button-raises` | planted | a reminder's note was renamed, and its button's handler looks for it | leads broken (button-raises) | yes |
| `g-form-nowhere` | planted | the join form is sent to a page that is not there | forms broken (form-nowhere) | yes |
| `g-form-raises` | planted | the join form's handler tidies a field under a misspelt id | forms broken (form-raises) | yes |
| `g-outside-script` | planted | a visitor counter from another computer on the home page | outside broken (outside-script) | yes |
| `g-outside-file` | planted | the stylesheet takes its font from another computer | outside broken (outside-file) | yes |
| `g-no-name` | planted | the leaf picture became a link home with an empty alt | keyboard broken (no-name) | yes |
| `g-no-label` | planted | the e-mail field's label names a misspelt id | keyboard broken (no-label) | yes |
| `g-not-reached` | planted | the plot list's rows open the join form when clicked, and Tab cannot reach them | keyboard broken (not-reached) | yes |
| `g-no-focus-ring` | planted | the stylesheet takes the outline off every control | keyboard broken (no-focus-ring) | yes |
| `g-trapped` | planted | the name field keeps the keyboard until something is typed in it | keyboard broken (trapped) | yes |
| `gl-disabled-button` | look-alike | a disabled button: the waiting list is full | leads broken (dead-button) | NO: leads: broken ['dead-button'] where held  was written down |
| `gl-print-button` | look-alike | a button that prints the list of events | leads broken (dead-button) | NO: leads: broken ['dead-button'] where held  was written down |
| `gl-section-link` | look-alike | a link to the rules further down the same page | as the safe site | yes |
| `gl-drawing-page` | look-alike | a page that holds only a drawing of the garden, and no text | as the safe site | yes |
| `gl-outside-link` | look-alike | a link to the garden's page on the town's website | as the safe site | yes |
| `gl-outside-form` | look-alike | a newsletter form sent to another computer | as the safe site | yes |
| `gl-console-info` | look-alike | the script writes a line of information, not an error | as the safe site | yes |
| `gl-icon-button` | look-alike | a reminder button that shows a bell and has a label for its name | as the safe site | yes |

### tasks: a list of tasks built into dist/, one page its script draws whole

| Version | Kind | What it is | What the checks gave, where not as on the safe site | As written down |
|---|---|---|---|---|
| `tasks` | safe | the list of tasks as it is built | as the safe site | yes |
| `t-chunk-missing` | planted | the page names the script of an earlier build: nothing is drawn | opens broken (empty); script broken (not-loaded); leads nothing-to-check; forms nothing-to-check | NO: keyboard: held  where nothing-to-check  was written down |
| `t-raises-on-load` | planted | the last line reads a setting that was never saved, and raises | script broken (raised) | yes |
| `t-console-error` | planted | the script writes an error when nothing was saved yet | script broken (console-error) | yes |
| `t-button-raises` | planted | the Done button's handler reads a data field under its old name | leads broken (button-raises) | yes |
| `t-dead-button` | planted | the click handler looks for the Done buttons under a misspelt name | leads broken (dead-button) | yes |
| `t-form-raises` | planted | the add form's handler reads the field under another name | forms broken (form-raises) | yes |
| `t-outside-api` | planted | a tip of the day asked of another service | outside broken (outside-file) | yes |
| `t-trapped` | planted | Tab finishes a task's name in the new-task field, as in a terminal | keyboard broken (trapped) | yes |
| `t-no-label` | planted | the new-task field's label names another id | keyboard broken (no-label) | yes |
| `t-no-focus-ring` | planted | the stylesheet takes the outline off links, buttons and fields | as the safe site | NO: keyboard: held  where broken ['no-focus-ring'] was written down / keyboard: no no-focus-ring seen on /index.html |
| `t-blank-render` | planted | the list shown first was renamed, so the first visit draws nothing | opens broken (empty); leads nothing-to-check; forms nothing-to-check | NO: keyboard: held  where nothing-to-check  was written down |
| `t-dead-link` | planted | a link to a settings page that a server would have to answer | leads broken (dead-link) | yes |
| `tl-ring-by-shadow` | look-alike | no outline, but a shadow shows where the keyboard is | as the safe site | yes |
| `tl-wrapped-label` | look-alike | the new-task field sits inside its label, with no id | as the safe site | yes |
| `tl-shortcut-keys` | look-alike | the page listens for keys: "n" starts a new task | as the safe site | yes |
| `tl-cdn-library` | look-alike | a date library from another computer, which the script then needs | script inconclusive; outside broken (outside-script) | yes |

### library: a library's FastAPI app with a sign-in

| Version | Kind | What it is | What the checks gave, where not as on the safe site | As written down |
|---|---|---|---|---|
| `library` | safe | the library's app as it is | as the safe site | yes |
| `l-server-error` | planted | the book of the week is one no longer in the catalogue | opens broken (server-error) | yes |
| `l-not-found` | planted | the branch's name is written with a capital, so its events are not found | opens broken (not-found) | yes |
| `l-no-answer` | planted | the catalogue waits for the books to be read in, which nothing does | opens broken (no-answer) | yes |
| `l-form-error` | planted | the suggestion form's handler writes to a misspelt list | forms broken (form-error) | yes |
| `l-form-nowhere` | planted | the search form is sent to an address no route answers | forms broken (form-nowhere) | yes |
| `l-let-in` | planted | a developer's shortcut left on: every visitor is a demo reader | visitor broken (let-in) | yes |
| `l-said-not-sent` | planted | the protections are left off the events page | protections broken (said-not-sent) | yes |
| `l-cookie-open` | planted | the session cookie is set without HttpOnly | protections broken (cookie-open) | yes |
| `l-dead-link` | planted | the book of the week links to an address without its s | leads broken (dead-link) | yes |
| `l-button-raises` | planted | the shelf button counts the rows into a part of the page that is gone | leads broken (button-raises) | yes |
| `l-outside-script` | planted | a chat widget from another computer, let in by the site's own policy | outside broken (outside-script) | yes |
| `l-no-name` | planted | the logo that leads home has an empty alt | keyboard broken (no-name) | yes |
| `l-no-label` | planted | the field for the number of copies lost its label | keyboard broken (no-label) | yes |
| `l-not-reached` | planted | the shelf toggle is a piece of text that answers a click | keyboard broken (not-reached) | yes |
| `l-no-focus-ring` | planted | the stylesheet takes the outline off everything | keyboard broken (no-focus-ring) | yes |
| `l-trapped` | planted | the PIN field keeps the keyboard until it has four digits | keyboard broken (not-reached, trapped) | NO: keyboard: broken ['not-reached', 'trapped'] where broken ['trapped'] was written down |
| `l-not-loaded` | planted | every page names a script by a name the static folder does not have | script broken (not-loaded); leads broken (dead-button) | yes |
| `ll-csp-blocks-widget` | look-alike | a chat widget from another computer that the site's own policy keeps out | outside broken (outside-script) | NO: outside: broken ['outside-script'] where held  was written down |
| `ll-icon-search` | look-alike | the search button shows a magnifying glass and has a label | as the safe site | yes |
| `ll-clickable-rows` | look-alike | a whole row of the catalogue leads to its book; the link is in it | as the safe site | yes |
| `ll-slash-shortcut` | look-alike | the page listens for keys: "/" goes to the search field | as the safe site | yes |
| `ll-health-json` | look-alike | an address that answers data, not a page | as the safe site | yes |
| `ll-form-refused` | look-alike | the suggestion form refuses a number of copies that is no number | as the safe site | yes |

### Each code

| Code | Planted in | Found in |
|---|---:|---:|
| `button-raises` | 3 | 3 |
| `console-error` | 2 | 2 |
| `cookie-open` | 1 | 1 |
| `dead-button` | 2 | 2 |
| `dead-link` | 3 | 3 |
| `empty` | 3 | 3 |
| `empty-link` | 1 | 1 |
| `form-error` | 1 | 1 |
| `form-nowhere` | 2 | 2 |
| `form-raises` | 2 | 2 |
| `let-in` | 1 | 1 |
| `no-answer` | 1 | 1 |
| `no-focus-ring` | 3 | 2 |
| `no-label` | 3 | 3 |
| `no-name` | 2 | 2 |
| `not-found` | 1 | 1 |
| `not-loaded` | 3 | 3 |
| `not-reached` | 2 | 2 |
| `outside-file` | 2 | 2 |
| `outside-script` | 2 | 2 |
| `raised` | 2 | 2 |
| `said-not-sent` | 1 | 1 |
| `server-error` | 1 | 1 |
| `trapped` | 3 | 3 |
