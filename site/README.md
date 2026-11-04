# Lantern website

The landing page from the Claude Design handoff (`Lantern Landing.dc.html`), as a static site.

- `index.html` — the page: 72 px header with the animated lantern mark, hero ("Ship your vibe-coded app like a
  senior engineer built it." / "Build with vibes. Ship with confidence."), "See how it works", the three steps,
  Get Lantern, promises, footer. The same drifting geometric backdrop as the app.
- `intro/intro.js` — the 20-second intro, compiled from the handoff's `lantern-intro.jsx` (five scenes: Dark,
  Click, Lit, Ready, Tagline). Plays on every visit to `/` (nothing is remembered); a deep link (`/#get`) or
  `?intro=0` goes straight to the page. It ends on a card with "Add your app" (lands on the install card with an
  accent ring) and "See a finished report first"; Skip, a click or Escape jumps to that card; "Replay intro" in the
  header; tones muted by default; plays as is under reduced motion (there is no still version). The page under the
  overlay is hidden until the intro is done, and shows straight away if the React scripts do not load.
  `intro/runtime.js` is the small stage/clock it runs on (React 18 from cdnjs, with SRI hashes) and gives the page
  `control.restart()` and `control.seekToEnd()`.
- `demo/report.html` — the live example, built by the workflow at publish time (`python examples/make_demo.py`)
  so it always matches the current viewer; not committed.
- `icon.svg` — the lantern mark.

Published by `.github/workflows/site.yml` to GitHub Pages on every push to `main` that touches `site/`.
To preview locally: `python -m http.server 8000 --directory site` and open http://localhost:8000/.
