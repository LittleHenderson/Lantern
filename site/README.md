# Lantern website

The landing page from the Claude Design handoff (`Lantern Landing.dc.html`), as a static site.

- `index.html` — the page: 72 px header with the animated lantern mark, hero ("Ship your vibe-coded app like a
  senior engineer built it." / "Build with vibes. Ship with confidence."), "See how it works", the three steps,
  Get Lantern, promises, footer. The same drifting geometric backdrop as the app.
- `intro/intro.js` — the 20-second intro, compiled from the handoff's `lantern-intro.jsx` (five scenes: Dark,
  Click, Lit, Ready, Tagline). Plays once per visitor (remembered in the browser), skip anywhere, "Replay intro"
  in the header, tones muted by default, off under reduced motion. `intro/runtime.js` is the small stage/clock
  it runs on (React 18 from cdnjs).
- `demo/report.html` — the live example, built by the workflow at publish time (`python examples/make_demo.py`)
  so it always matches the current viewer; not committed.
- `icon.svg` — the lantern mark.

Published by `.github/workflows/site.yml` to GitHub Pages on every push to `main` that touches `site/`.
To preview locally: `python -m http.server 8000 --directory site` and open http://localhost:8000/.
