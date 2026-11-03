# Changelog

Each release has a section headed `## <version>`. The release workflow (`.github/workflows/release.yml`) puts the
section matching the pushed tag into the GitHub Release body (`v0.9.0-rc1` uses `## 0.9.0-rc1` if present, else `## 0.9.0`).

## Unreleased

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
