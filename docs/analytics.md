# Knowing how Lantern is used

Three places, three different kinds of numbers. None of them ever sees anyone's code.

| Where | What you learn | How |
|---|---|---|
| **Landing page** (public website) | Visitors per day, which pages, how long, where they came from, countries, devices | Cloudflare Web Analytics (free): one `<script>` tag on the page. No cookies, no banner needed |
| **Free allowance** (the gateway) | People using it today / this week / this month, explanations per day, dollars per day, sign-ups, who used up the allowance | Built in: `https://<gateway>/v1/admin` with the admin secret. See `gateway/README.md` |
| **The app** (runs on people's computers) | Installs that report, active installs per day, how many times each feature is used, versions, operating systems | **Opt-in only.** Settings › "Share anonymous usage counts", off by default. Sends a random install id, version, OS name and per-feature counts, nothing else; the gateway refuses anything else |

## Cloudflare Web Analytics for the landing page

1. The landing page is a static site (the design package's "Lantern Landing"). Host it on **Cloudflare Pages**
   (free, deploys from the GitHub repo) or anywhere else.
2. In the Cloudflare dashboard: **Analytics & Logs → Web Analytics → Add a site**. If the site is on Cloudflare
   Pages or proxied through Cloudflare, turn on automatic setup and you are done. Otherwise copy the one
   `<script defer src="https://static.cloudflareinsights.com/beacon.min.js" data-cf-beacon='{"token": "..."}'></script>`
   line it gives you into the landing page's `<head>`.
3. The dashboard shows visits, page views, top pages, referrers, countries, browsers and devices, and Core Web
   Vitals. It uses no cookies and no personal identifiers, so no consent banner is required.

Put the script on the **landing page only**, never in the app or the report: those run on people's own
machines and must make no outside requests.

## What is deliberately not measured

* Anything inside the app without the opt-in: no page views, no timings, no error reports.
* Project names, folders, file names, findings, model names, keys, or prompts, anywhere, ever.
* Individual people on the landing page: Cloudflare's analytics are aggregate by design.

When cloud mode exists (analysis running on Lantern's own servers), product analytics inside the app become
possible because the activity happens on the server; that is the time to add them, with the same rule:
counts and timings, never code.
