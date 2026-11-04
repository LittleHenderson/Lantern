# Changelog

Each release has a section headed `## <version>`. The release workflow (`.github/workflows/release.yml`) puts the
section matching the pushed tag into the GitHub Release body (`v0.9.0-rc1` uses `## 0.9.0-rc1` if present, else `## 0.9.0`).

## Unreleased

- Website home: the warm light behind the headline, as in the mock-ups (the app's home has it too); "Your repositories"
  (GitHub sign-ins) and "Explore GitHub" buttons under the link box, to find a repository to paste; and "Try a sample app":
  Lantern's four built-in starter apps, each with planted problems, checked with one click (written from the package,
  nothing cloned), so a beginner sees a real report without a repository of their own.
- Website: upload an app from your computer. "Upload…" next to the link box (or drop a folder or a .zip on it) sends a
  folder, zipped in the browser without `node_modules`, `.git`, virtual environments and build output, or a .zip
  (`POST /v1/uploads`). The new `lantern.archive` unpacks it inside the sealed box with no network and refuses names
  that leave the folder, links, password-protected files and archives that grow past the size cap; the upload is
  deleted when its check ends. Messages under the link box no longer vanish when the page refreshes its runs.

## 0.10.0

Lantern on the web, and the app redrawn to match the design mock-ups screen by screen.

- Cloud mode (a separate service, `lantern-cloud` 0.1.0, deployed on its own): paste a repository link on the
  website, sign in with GitHub or Google, and Lantern analyzes it in a locked-down sandbox (no network during the
  analysis, limits per person and per day) with a live log. Reports open only for their owner; Share makes a
  read-only link and turning it off retires it. Delete a run or your whole account at any time; results are kept
  until you do. Explanations and Ask Lantern use your free allowance, only after you agree once to the data notice.
  The website is built from the app's own stylesheet, so it looks like the app.
- Ready to ship? (Simple) leads with the grade as designed: a large letter inside the score ring, the score and a
  plain answer beside it, the biggest moves as cards with their gain in green, smaller moves in a row underneath, and
  a right-hand column with what's already good, how the score works, and the starter-files note.
- The Evidence Report reads as a printed document, as designed: paper sheets with a serif heading and opening
  paragraph, the four numbers as a ruled row (fixed in green, open in red), section labels in small capitals, and
  inside the app the moving shapes drift around the sheets. "Save as PDF" works inside the app again: it used an
  inline click handler, which the page's script policy refused.
- What protects you (Simple) is laid out as designed: the protections Lantern found fill the page under an uppercase
  count and a large heading, and what it looked for and didn't find is a full-height column down the right edge, each
  card with its "How do I add one?" under the text instead of squeezing it. On phones the column follows below.
- The moving shapes behind the app now show behind the Atlas too (the report inside the app is see-through, and its
  lanes sit on the page instead of a grey box), and a report opened on its own draws the same shapes: full behind
  About and the other pages, quieter behind the map, findings and fix pages. Settings › Backdrop (off, subtle, bold)
  reaches a report opened in its own tab; with reduced motion turned on the shapes stay still. Dark mode's glow
  matches the design token.
- Paths, as designed: Advanced opens on the whole-app Graph with the riskiest route already selected; Simple opens
  on Lanes, full width, starting on the path that reaches the worst finding, with a line naming where it goes wrong.
  The lanes now fit the screen instead of running off the right edge, and the page title is no longer cut short.
  Flowchart and Graph sit on a dotted canvas, as in the mock-ups.
- Findings in Simple view read as an audit memo, as designed: serif headings, the severity in the margin, entries split by
  thin rules. Each heading is a plain sentence ("The backup button can run shell commands on your server") chosen from a
  fixed list by the rule and filled only with names from the map; the scanner's own words stay right underneath.
- Project screens have one header row, as designed: logo, "My apps" (Simple) or "Projects /" (Advanced), the app's
  name and grade, the tabs (a segmented control in Simple), then the actions and the Simple/Advanced switch. The
  global header and the report's own stats strip no longer stack above it, so at 1200px nothing is cut off. The cloud
  website's run pages get the same single row.
- Phones always show the Simple view, as the design says, even when Advanced was picked on a computer; the
  Simple/Advanced switch is hidden below 760px. Protections no longer says "Lantern found each one in your code" when
  it found none.
- Design drop 01: the Atlas lanes use straight 2px connectors in a staircase, report tabs and stat chips no longer wrap,
  the phone tab row scrolls, finding cards lose the coloured left bar (critical cards get a tinted border), code chips
  don't break mid-word, and Advanced tables drop less important columns on narrower screens.
- Scenarios: every finding now comes with a short story of one tester meeting it ("Priya opens the /admin page, clicks
  the backup button, types `report; whoami`…"), then what goes wrong and what the fix changes. Lantern builds it from
  its own facts (the page, the clicks, the route, whether typed input reaches the line), so it is there with no model.
  Explanations gain a fourth part, Scenario, next to Technical, Everyday and Mapped; a model's story that names code or
  a page the map does not show is removed, never shown. Prompt version `lens-v4`: explanations made before this are
  asked again on the next `lantern explain`.

## 0.9.0

First build for outside testers.

- One-command install: `pip install "git+https://github.com/LittleHenderson/Lantern@v0.9.0"`. Works with no extras;
  `lantern analyze` runs Lantern's own rules and says which optional scanners (Bandit, pip-audit) are off.
  `pip install "lantern[scan] @ git+https://github.com/LittleHenderson/Lantern@v0.9.0"` adds them.
- `lantern serve --check`: starts the app, prints the one-time link, loads the app once and stops (exit 0 if it answered).
- Release workflow: a pushed `v*` tag builds the sdist and wheel, runs the tests against the built wheel in a clean
  environment, and attaches both files to a GitHub Release.
- Clean-install test in CI on Linux, macOS and Windows.
- **Watch my tests run** (Paths): runs the project's test command in a sandbox (Docker with a pinned image, no
  network, read-only project; or a restricted subprocess with Landlock, rlimits and a job object on Windows), stopped
  after 10 minutes. Python tests upgrade the map's links to "seen running"; other languages run untraced for now.
- **Terminal drawer**: runs Lantern's own commands only (`analyze`, `trace`, `explain`, `report`, `verify`, `accept`,
  `packs`, `export`, `learn`); anything else is refused.
- **Screenshots in Ask Lantern**: Tesseract reads a dropped PNG/JPEG/WebP through a pipe on your computer; the image is
  never saved or uploaded. `[ocr]` extra.
- **Analysis packs on/off**: per-pack switches in Settings for every project's packs, with a "Re-check to apply" card.
- **Simple / Advanced** is saved by the app and followed by the Atlas, including after a restart.
- Free allowance gateway: `/v1/health` reports its version and model; CI checks it. Token hashes are deleted after 90
  days without use and per-day counters after 90 days (`LANTERN_RETENTION_DAYS`). The limits are listed in
  `docs/deploy.md`.
- Tester guide `docs/try-lantern.md` and a "Tester report" issue form.
- Live-app browser smoke in CI: the test sheet, the terminal, a screenshot upload and a pack switch, with no JS errors.
