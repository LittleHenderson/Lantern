# Knowing how Lantern is used

Three places, three different kinds of numbers. None of them ever sees anyone's code.

| Where | What you learn | How |
|---|---|---|
| **Landing page** (public website) | Visitors per day, which pages, how long, where they came from, countries, devices | Cloudflare Web Analytics (free): one `<script>` tag on the page. No cookies, no banner needed |
| **Free allowance** (the gateway) | People using it today / this week / this month, explanations per day, dollars per day, sign-ups, who used up the allowance | Built in: `https://<gateway>/v1/admin` with the admin secret. See `gateway/README.md` |
| **The app** (runs on people's computers) | Installs that report, active installs per day, how many times each feature is used, versions, operating systems | **Opt-in only.** Settings › "Share anonymous usage counts", off by default. Sends a random install id, version, OS name and per-feature counts, nothing else; the gateway refuses anything else. `lantern usage --show` says where they are sent, or why they are not (below) |

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

## Where the app's counts go

One address: the gateway Lantern is set up with (`LANTERN_GATEWAY_URL`, or the one it ships with), route `/v1/usage`.
`lantern usage --show` prints it as `Sent to: …`, or says why nothing is sent:

* the gateway address does not begin with `https://` (an `http://` address is taken for this computer only), holds a
  name or a password, names no computer, has a port that is not a number, has a `?` or `#` part, or is not plain
  printable text;
* `LANTERN_NO_REAL_PROVIDERS` is set: nothing leaves this computer in that run.

Lantern follows no redirect with the counts. A try the gateway did not take leaves them on the computer for the next
try, and `lantern usage --show` says how the last try ended (`Last try 2026-11-10: not taken (the gateway answered
404). …`). The words are Lantern's own; text a server sent is never shown.

What the gateway does with a report (gateway 0.2.6; `gateway/README.md`, "What anybody can send"): it keeps the
install id, the day and a count for each feature it knows; a version only when it is shaped like one, and an
operating system only when it is Linux, Darwin or Windows (anything else is kept as nothing, or as `other`), so no
free text reaches the owner's page. One network may send 300 reports an hour and add 50 new installs a day, and
everyone together may add 1,000 new installs a day. Past a limit the gateway answers 429 and the app keeps its
counts for its next try (`Last try …: not taken (the gateway answered 429). …`). Until that version, any text sent
as the version or the operating system was kept and listed on the owner's page, and nothing limited how many
installs one sender could add.

Until 2026-11-10 the counts were posted to an address the gateway does not have (`/v1/v1/usage`), so with the
address Lantern ships with none arrived. That is read from the code and shown by a test against the gateway's code
on one computer; the live gateway was not asked. App numbers on the owner's page from before that fix are therefore
missing numbers, not "nobody used it".

## What is deliberately not measured

* Anything inside the app without the opt-in: no page views, no timings, no error reports.
* Project names, folders, file names, findings, model names, keys, or prompts, anywhere, ever.
* Individual people on the landing page: Cloudflare's analytics are aggregate by design.

When cloud mode exists (analysis running on Lantern's own servers), product analytics inside the app become
possible because the activity happens on the server; that is the time to add them, with the same rule:
counts and timings, never code.
