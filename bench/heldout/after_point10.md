# Held-out benchmark · after point 10: 3e38b7d, offline

Engine 3e38b7d3e4b3873ee6f64259acc65db4c301f94a · definition e6b10d91686f · 2026-11-12 23:46 UTC · offline (no dependency audits)

| Measure | Count |
|---|---:|
| Documented problems expected | 79 |
| Found at medium or above | 55 |
| Found only as low | 0 |
| Missed | 24 |
| Safe-twin anchors checked | 17 |
| False alarms on safe twins (medium+) | 0 |
| False links on safe twins | 0 |
| Resolution checks passed | 3 / 3 |
| Protection checks passed | 3 / 3 |
| Found problems with a mapped path | 46 / 55 |
| Vulnerable apps given a green release (Passed) | 0 / 8 (none) |
| Vulnerable apps Blocked | 8 / 8 (dvra, nodegoat, dvna, goof, pygoat, review-unsafe, flows-unsafe, express-unsafe) |
| Vulnerable apps Incomplete, not Blocked | 0 / 8 (none) |
| Clean apps Blocked (refused a green release) | 1 / 6 (fastapi-template) |
| Clean apps Incomplete (not refused: evidence is missing) | 5 / 6 (express-boilerplate, taxonomy, review-safe, flows-safe, express-safe) |
| Clean apps not Passed (the count before the release decision) | 6 / 6 (fastapi-template, express-boilerplate, taxonomy, review-safe, flows-safe, express-safe) |
| Medium+ findings on clean apps (public and twins) | 9 (labelled false alarm: 6) |
| Anchors not found in the pinned code | 0 |

## By class (documented problems)

| Class | Expected | Found medium+ | Found low | Missed |
|---|---:|---:|---:|---:|
| auth | 5 | 3 | 0 | 2 |
| authz | 11 | 3 | 0 | 8 |
| config | 4 | 1 | 0 | 3 |
| csrf | 2 | 1 | 0 | 1 |
| dependency | 2 | 0 | 0 | 2 |
| deserialize | 4 | 4 | 0 | 0 |
| eval | 4 | 3 | 0 | 1 |
| exposure | 2 | 1 | 0 | 1 |
| nosql | 2 | 1 | 0 | 1 |
| path | 4 | 2 | 0 | 2 |
| pollution | 1 | 1 | 0 | 0 |
| redirect | 4 | 3 | 0 | 1 |
| secret | 7 | 7 | 0 | 0 |
| shell | 6 | 6 | 0 | 0 |
| sql | 10 | 10 | 0 | 0 |
| ssrf | 3 | 3 | 0 | 0 |
| xss | 6 | 4 | 0 | 2 |
| xxe | 2 | 2 | 0 | 0 |

## Call sites (one denominator per app)

| App | Total | Resolved | Likely | Possible | Name only | External | Built-in | Unresolved |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| dvra | 1273 | 244 | 0 | 0 | 0 | 517 | 63 | 449 |
| nodegoat | 330 | 32 | 52 | 0 | 0 | 116 | 14 | 116 |
| dvna | 240 | 45 | 0 | 0 | 0 | 129 | 0 | 66 |
| goof | 184 | 22 | 0 | 0 | 0 | 124 | 2 | 36 |
| pygoat | 2973 | 327 | 20 | 5 | 40 | 1783 | 517 | 281 |
| fastapi-template | 2528 | 1065 | 69 | 0 | 0 | 1052 | 56 | 286 |
| express-boilerplate | 956 | 193 | 72 | 0 | 0 | 615 | 4 | 72 |
| taxonomy | 729 | 392 | 8 | 0 | 0 | 156 | 47 | 126 |
| review-unsafe | 17 | 4 | 1 | 0 | 0 | 6 | 1 | 5 |
| review-safe | 17 | 2 | 0 | 0 | 0 | 6 | 3 | 6 |
| flows-unsafe | 59 | 18 | 1 | 0 | 0 | 26 | 6 | 8 |
| flows-safe | 66 | 17 | 1 | 0 | 0 | 31 | 8 | 9 |
| express-unsafe | 29 | 7 | 0 | 0 | 0 | 22 | 0 | 0 |
| express-safe | 32 | 9 | 0 | 0 | 0 | 22 | 1 | 0 |

## Per app

### dvra (vulnerable, Python / FastAPI) · {'critical': 1, 'high': 1, 'medium': 4, 'low': 11} · score 57 F · release Blocked

- release Blocked · failed: findings (1 critical and 1 high findings open outside test code: B602 at app/apis/admin/utils.py:9, B608 at app/apis/orders/services/get_order_status.py:36) · missing: dependencies (Not checked: pip-audit (skipped: offline).); tests (The tests were not run in this check. Lantern runs a project's code only when asked, and tests that were not run prove nothing.)
- dvra-shell · shell · **found** (B602, critical, path)
- dvra-sql · sql · **found** (B608, high, path)
- dvra-bola-order · authz · **missed**
- dvra-mass-assign · authz · **found** (LT-AUTHZ-MASS-ASSIGN, medium, path)
- dvra-bfla-role · authz · **missed**
- dvra-debug · exposure · **missed**
- dvra-pin · auth · **missed**
- scanners: bandit: ok, pip-audit: skipped, npm-audit: skipped, maven-audit: skipped, composer-audit: skipped, gem-audit: skipped, gitleaks: unavailable, lantern-secrets: ok, lantern-web: ok (no JS/TS files; Python-side checks only), lantern-ai: ok (no model, vector or paid API calls found), lantern-flow: ok

### nodegoat (vulnerable, Node / Express + MongoDB) · {'critical': 3, 'high': 2, 'medium': 2, 'low': 0} · score 44 F · release Blocked

- release Blocked · failed: findings (3 critical and 2 high findings open outside test code: LJ-EVAL at app/routes/contributions.js:32, LJ-EVAL at app/routes/contributions.js:33, LJ-EVAL at app/routes/contributions.js:34, LJ-EXEC at Gruntfile.js:165, LT-SSRF at app/routes/research.js:16) · missing: dependencies (Not checked: npm-audit (skipped: offline).); tests (The tests were not run in this check. Lantern runs a project's code only when asked, and tests that were not run prove nothing.)
- ng-eval · eval · **found** (LJ-EVAL, critical, path)
- ng-nosql · nosql · **missed**
- ng-idor · authz · **missed**
- ng-redirect · redirect · **found** (LT-REDIRECT, medium, path)
- ng-ssrf · ssrf · **found** (LT-SSRF, high, path)
- ng-bfla · authz · **missed**
- ng-secret · secret · **found** (LW-SECRET-INLINE, medium)
- ng-cookie · config · **missed**
- ng-csrf · csrf · **missed**
- ng-xss · xss · **missed**
- scanners: bandit: ok, pip-audit: skipped, npm-audit: skipped, maven-audit: skipped, composer-audit: skipped, gem-audit: skipped, gitleaks: unavailable, lantern-secrets: ok, lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found), lantern-flow: ok

### dvna (vulnerable, Node / Express + Sequelize) · {'critical': 4, 'high': 7, 'medium': 8, 'low': 0} · score 35 F · release Blocked

- release Blocked · failed: findings (4 critical and 7 high findings open outside test code: LT-SQL at core/appHandler.js:11, LJ-EXEC at core/appHandler.js:39, LT-EVAL at core/appHandler.js:197, LT-DESERIALIZE at core/appHandler.js:218, LT-XXE at core/appHandler.js:235 and 6 more) · missing: dependencies (19 libraries are named in a file with no lock file beside it, so no version is known and they were not checked (package.json: bcrypt, package.json: csurf, package.json: ejs, package.json: express, package.json: express-fileupload).); tests (The project has no tests.)
- dvna-sql · sql · **found** (LT-SQL, critical, path)
- dvna-shell · shell · **found** (LJ-EXEC, critical, path)
- dvna-eval · eval · **found** (LT-EVAL, critical, path)
- dvna-deser · deserialize · **found** (LT-DESERIALIZE, critical, path)
- dvna-xxe · xxe · **found** (LT-XXE, high, path)
- dvna-redirect · redirect · **found** (LT-REDIRECT, medium, path)
- dvna-reset-token · auth · **missed**
- dvna-secret · secret · **found** (LW-SECRET-INLINE, medium)
- dvna-cookie · config · **missed**
- dvna-xss · xss · **found** (LW-XSS-RAW, high, path)
- dvna-authz-admin · authz · **missed**
- dvna-idor · authz · **found** (LT-AUTHZ-OWNER, medium, path)
- dvna-exposure · exposure · **found** (LT-AUTHZ-ROLE, medium, path)
- dvna-deps · dependency · **missed**
- scanners: bandit: ok, pip-audit: skipped, npm-audit: skipped, maven-audit: skipped, composer-audit: skipped, gem-audit: skipped, gitleaks: unavailable, lantern-secrets: ok, lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found), lantern-flow: ok

### goof (vulnerable, Node / Express + MongoDB (Snyk demo)) · {'critical': 1, 'high': 2, 'medium': 7, 'low': 0} · score 39 F · release Blocked

- release Blocked · failed: findings (1 critical and 2 high findings open outside test code: LJ-EXEC at routes/index.js:174, LT-NOSQL at routes/index.js:52, LW-XSS-RAW at views/admin.ejs:17) · missing: dependencies (Not checked: npm-audit (skipped: offline).); tests (The tests were not run in this check. Lantern runs a project's code only when asked, and tests that were not run prove nothing.)
- goof-nosql · nosql · **found** (LT-NOSQL, high, path)
- goof-redirect · redirect · **missed**
- goof-shell · shell · **found** (LJ-EXEC, critical, path)
- goof-zipslip · path · **missed**
- goof-pollution · pollution · **found** (LT-POLLUTION, medium)
- goof-secret · secret · **found** (LW-SECRET-INLINE, medium, path)
- goof-xss-admin · xss · **found** (LW-XSS-RAW, high, path)
- goof-xss-marked · xss · **found** (LW-XSS-RAW, medium)
- goof-layout · path · **missed**
- goof-deps · dependency · **missed**
- scanners: bandit: ok, pip-audit: skipped, npm-audit: skipped, maven-audit: skipped, composer-audit: skipped, gem-audit: skipped, gitleaks: unavailable, lantern-secrets: ok, lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found), lantern-flow: ok

### pygoat (vulnerable, Python / Django + Flask labs) · {'critical': 10, 'high': 57, 'medium': 41, 'low': 55} · score 34 F · release Blocked

- release Blocked · failed: findings (10 critical and 57 high findings open outside test code: B506 at dockerized_labs/a9_uckv_lab/app.py:62, B602 at dockerized_labs/command_injection_lab/app.py:30, B307 at dockerized_labs/command_injection_lab/app.py:49, B324 at dockerized_labs/crypto_failure_lab/app.py:25, B324 at dockerized_labs/crypto_failure_lab/app.py:38 and 62 more) · missing: dependencies (Not checked: pip-audit (skipped: offline).); tests (The project has no tests.)
- pg-sql · sql · **found** (B608, critical, path)
- pg-shell · shell · **found** (B602, critical, path)
- pg-eval · eval · **found** (B307, critical, path)
- pg-pickle · deserialize · **found** (B301, critical, path)
- pg-xxe · xxe · **found** (B317, high, path)
- pg-ssrf · ssrf · **found** (B113, high, path)
- pg-lfi · path · **found** (LT-PATH, high, path)
- pg-ssti · eval · **missed**
- pg-xss · xss · **missed**
- pg-auth-md5 · auth · **found** (B324, high, path)
- pg-crypto-md5 · auth · **found** (B324, critical, path)
- pg-crypto-sha1 · auth · **found** (B324, critical, path)
- pg-secret-aws · secret · **found** (aws-access-key, critical)
- pg-secret-stripe · secret · **found** (stripe-live-key, critical)
- pg-yaml · deserialize · **found** (B506, critical, path)
- pg-pickle2 · deserialize · **found** (B301, critical, path)
- pg-django-debug · config · **found** (LP-DJANGO-DEBUG, medium)
- pg-django-secret · secret · **found** (LP-DJANGO-SECRET-INLINE, high)
- pg-admin-cookie · authz · **missed**
- pg-csrf-exempt · csrf · **found** (LP-DJANGO-CSRF-EXEMPT, high, path)
- scanners: bandit: ok, pip-audit: skipped, npm-audit: skipped, maven-audit: skipped, composer-audit: skipped, gem-audit: skipped, gitleaks: unavailable, lantern-secrets: ok, lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found), lantern-pack:django: ok (builtin, 8 finding(s)), lantern-flow: ok

### fastapi-template (clean, Python / FastAPI + React) · {'critical': 0, 'high': 1, 'medium': 1, 'low': 6} · score 59 F · release Blocked

- release Blocked · failed: findings (1 high finding open outside test code: LT-XSS at backend/app/api/routes/login.py:121) · missing: scanners (Did not finish, or did not cover everything: bandit (partial: 1 file could not be read), lantern-flow (partial: 1 file(s) could not be read). What they would have found is not in the results.); dependencies (Not checked: pip-audit (skipped: offline), npm-audit (skipped: pnpm-lock.yaml / yarn.lock / bun.lock aren't read yet; run `pnpm audit` or `yarn npm audit`).); tests (The tests were not run in this check. Lantern runs a project's code only when asked, and tests that were not run prove nothing.)
- loud: LT-XSS high backend/app/api/routes/login.py:121 · false alarm · the value does get into the page the way Lantern says (the e-mail address in the route's path, through a jinja2 Template that escapes nothing, into an HTMLResponse), but only a superuser reaches the route and the page is made only when an account with exactly that address exists (404 otherwise), so the text is a stored, validated e-mail address; Lantern does not see that the value has to equal a stored one
- loud: LW-AUTH-MISSING medium backend/app/api/routes/private.py:23 · false alarm · backend/app/api/main.py mounts the private router only when FASTAPI_ENV == 'development'; the route never exists in a deployed app
- scanners: bandit: partial, pip-audit: skipped, npm-audit: skipped, maven-audit: skipped, composer-audit: skipped, gem-audit: skipped, gitleaks: unavailable, lantern-secrets: ok, lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found), lantern-flow: partial

### express-boilerplate (clean, Node / Express + Mongoose) · {'critical': 0, 'high': 0, 'medium': 5, 'low': 0} · score 63 D · release Incomplete

- release Incomplete · missing: dependencies (Not checked: npm-audit (skipped: pnpm-lock.yaml / yarn.lock / bun.lock aren't read yet; run `pnpm audit` or `yarn npm audit`).); tests (The tests were not run in this check. Lantern runs a project's code only when asked, and tests that were not run prove nothing.)
- loud: LW-CORS-ANY medium src/app.js:41 · intended · cors() with no options allows any origin; the boilerplate leaves the origin list to the project that copies it
- loud: LW-CORS-ANY medium src/app.js:42 · intended · same cors() call for preflight requests
- loud: LW-JWT medium src/docs/components.yml:31 · false alarm · an example token in the OpenAPI documentation, not a credential
- loud: LW-JWT medium src/routes/v1/auth.route.js:141 · false alarm · an example token inside a swagger doc comment
- loud: LW-JWT medium src/routes/v1/auth.route.js:167 · false alarm · an example token inside a swagger doc comment
- scanners: bandit: ok, pip-audit: skipped, npm-audit: skipped, maven-audit: skipped, composer-audit: skipped, gem-audit: skipped, gitleaks: unavailable, lantern-secrets: ok, lantern-web: ok, lantern-ai: ok, lantern-flow: ok

### taxonomy (clean, TypeScript / Next.js 13 + Prisma + Stripe) · {'critical': 0, 'high': 0, 'medium': 1, 'low': 0} · score 55 F · release Incomplete

- release Incomplete · missing: dependencies (Not checked: npm-audit (skipped: pnpm-lock.yaml / yarn.lock / bun.lock aren't read yet; run `pnpm audit` or `yarn npm audit`).); tests (The project has no tests.)
- loud: LA-WALLET-DRAIN medium app/api/users/stripe/route.ts:12 · false alarm · getServerSession(authOptions) is checked first and returns 403 without a signed-in user
- scanners: bandit: ok, pip-audit: skipped, npm-audit: skipped, maven-audit: skipped, composer-audit: skipped, gem-audit: skipped, gitleaks: unavailable, lantern-secrets: ok, lantern-web: ok, lantern-ai: ok, lantern-flow: ok

### review-unsafe (vulnerable, Python / FastAPI) · {'critical': 2, 'high': 2, 'medium': 0, 'low': 0} · score 39 F · release Blocked

- release Blocked · failed: findings (2 critical and 2 high findings open outside test code: B608 at app/main.py:20, B608 at app/main.py:42, B608 at app/main.py:30, B608 at app/main.py:55) · missing: dependencies (2 libraries have no exact version written down, so they were not checked.); tests (The project has no tests.)
- rv-match · sql · **found** (B608, critical, path)
- rv-except · sql · **found** (B608, high, path)
- rv-nonlocal · sql · **found** (B608, critical, path)
- rv-global · sql · **found** (B608, high, path)
- rv-list-edge · resolution · **found**
- scanners: bandit: ok, pip-audit: skipped, npm-audit: skipped, maven-audit: skipped, composer-audit: skipped, gem-audit: skipped, gitleaks: unavailable, lantern-secrets: ok, lantern-web: ok (no JS/TS files; Python-side checks only), lantern-ai: ok (no model, vector or paid API calls found), lantern-flow: ok

### review-safe (clean, Python / FastAPI) · {'critical': 0, 'high': 0, 'medium': 0, 'low': 4} · score 52 F · release Incomplete

- release Incomplete · missing: dependencies (2 libraries have no exact version written down, so they were not checked.); tests (The project has no tests.)
- rv-match-safe · sql · **clean** (B608, None, path)
- rv-except-safe · sql · **clean** (B608, None, path)
- rv-nonlocal-safe · sql · **clean** (B608, None, path)
- rv-global-safe · sql · **clean** (B608, None, path)
- rv-list-no-edge · resolution · **clean**
- scanners: bandit: ok, pip-audit: skipped, npm-audit: skipped, maven-audit: skipped, composer-audit: skipped, gem-audit: skipped, gitleaks: unavailable, lantern-secrets: ok, lantern-web: ok (no JS/TS files; Python-side checks only), lantern-ai: ok (no model, vector or paid API calls found), lantern-flow: ok

### flows-unsafe (vulnerable, Python / FastAPI + React) · {'critical': 2, 'high': 4, 'medium': 1, 'low': 2} · score 31 F · release Blocked

- release Blocked · failed: findings (2 critical and 4 high findings open outside test code: B602 at app/main.py:57, B608 at app/service.py:5, LT-PATH at app/files.py:11, LT-PATH at app/files.py:12, LT-SSRF at app/helpers.py:19 and 1 more) · missing: dependencies (5 libraries have no exact version written down, so they were not checked; 2 libraries are named in a file with no lock file beside it, so no version is known and they were not checked (web/package.json: react, web/package.json: react-dom).); tests (The project has no tests.)
- fl-sql-chain · sql · **found** (B608, critical, path)
- fl-sql-htmlescape · sql · **found** (B608, high, path)
- fl-ssrf · ssrf · **found** (LT-SSRF, high, path)
- fl-zipslip · path · **found** (LT-PATH, high, path)
- fl-idor · authz · **found** (LT-AUTHZ-OWNER, medium, path)
- fl-shell-late-guard · shell · **found** (B602, critical, path)
- fl-authz-late-guard · authz · **missed**
- fl-ratelimit-unused · protection · **found** (add)
- fl-sql-chain-path · path-coverage · **covered** (B608, critical, path)
- scanners: bandit: ok, pip-audit: skipped, npm-audit: skipped, maven-audit: skipped, composer-audit: skipped, gem-audit: skipped, gitleaks: unavailable, lantern-secrets: ok, lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found), lantern-flow: ok

### flows-safe (clean, Python / FastAPI + React) · {'critical': 0, 'high': 0, 'medium': 0, 'low': 5} · score 47 F · release Incomplete

- release Incomplete · missing: dependencies (5 libraries have no exact version written down, so they were not checked; 2 libraries are named in a file with no lock file beside it, so no version is known and they were not checked (web/package.json: react, web/package.json: react-dom).); tests (The project has no tests.)
- fl-sql-chain-safe · sql · **clean** (B608, None, path)
- fl-sql-param-safe · sql · **clean**
- fl-ssrf-safe · ssrf · **clean**
- fl-zipslip-safe · path · **clean**
- fl-idor-safe · authz · **clean**
- fl-shell-safe · shell · **clean** (B607, None, path)
- fl-authz-safe · authz · **clean**
- fl-ratelimit-used · protection · **found** (in place)
- fl-ssrf-allowlist · protection · **found** (in place)
- scanners: bandit: ok, pip-audit: skipped, npm-audit: skipped, maven-audit: skipped, composer-audit: skipped, gem-audit: skipped, gitleaks: unavailable, lantern-secrets: ok, lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found), lantern-flow: ok

### express-unsafe (vulnerable, Node / Express) · {'critical': 2, 'high': 1, 'medium': 3, 'low': 0} · score 25 F · release Blocked

- release Blocked · failed: findings (2 critical and 1 high findings open outside test code: LT-SQL at core/handlers.js:7, LJ-EXEC at core/handlers.js:14, LT-XSS at core/handlers.js:9) · missing: dependencies (3 libraries are named in a file with no lock file beside it, so no version is known and they were not checked (package.json: express, package.json: express-session, package.json: mysql2).); tests (The project has no tests.)
- ex-sql · sql · **found** (LT-SQL, critical, path)
- ex-xss · xss · **found** (LT-SQL, critical, path)
- ex-shell · shell · **found** (LJ-EXEC, critical, path)
- ex-redirect · redirect · **found** (LT-REDIRECT, medium, path)
- ex-secret · secret · **found** (LW-SECRET-INLINE, medium)
- ex-cookie · config · **missed**
- ex-authz-delete · authz · **missed**
- ex-link-search · resolution · **found**
- ex-sql-path · path-coverage · **covered** (LT-SQL, critical, path)
- scanners: bandit: ok, pip-audit: skipped, npm-audit: skipped, maven-audit: skipped, composer-audit: skipped, gem-audit: skipped, gitleaks: unavailable, lantern-secrets: ok, lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found), lantern-flow: ok

### express-safe (clean, Node / Express) · {'critical': 0, 'high': 0, 'medium': 1, 'low': 0} · score 35 F · release Incomplete

- release Incomplete · missing: dependencies (3 libraries are named in a file with no lock file beside it, so no version is known and they were not checked (package.json: express, package.json: express-session, package.json: mysql2).); tests (The project has no tests.)
- ex-sql-safe · sql · **clean**
- ex-xss-safe · xss · **clean**
- ex-shell-safe · shell · **clean**
- ex-redirect-safe · redirect · **clean**
- ex-secret-safe · secret · **clean**
- ex-authz-delete-safe · authz · **clean**
- ex-link-search-safe · resolution · **found**
- loud: LT-AUTHZ-OWNER medium core/handlers.js:32 · intended · true as a fact: DELETE /items/:id asks for a login (auth.required) and then removes the item with that id, and nothing compares an owner; the twin's items have no owner at all, so every signed-in caller is meant to be able to remove one. The finding stands on the handler, in another file than the safe-twin anchor (routes/index.js), so the scorer does not count it as a false alarm on that anchor; read strictly it is one new medium finding on a route this benchmark calls safe
- scanners: bandit: ok, pip-audit: skipped, npm-audit: skipped, maven-audit: skipped, composer-audit: skipped, gem-audit: skipped, gitleaks: unavailable, lantern-secrets: ok, lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found), lantern-flow: ok
