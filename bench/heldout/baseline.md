# Held-out benchmark · baseline: main bc7cf10, before any change of this directive

Engine bc7cf10dce35e595bfc9aaf79e484bf1a577c0a4 · definition e6b10d91686f · 2026-11-09 21:50 UTC · online

| Measure | Count |
|---|---:|
| Documented problems expected | 79 |
| Found at medium or above | 28 |
| Found only as low | 2 |
| Missed | 49 |
| Safe-twin anchors checked | 17 |
| False alarms on safe twins (medium+) | 3 |
| False links on safe twins | 0 |
| Resolution checks passed | 1 / 3 |
| Protection checks passed | 2 / 3 |
| Found problems with a mapped path | 21 / 30 |
| Vulnerable apps given a green release | 2 / 8 (dvna, express-unsafe) |
| Clean apps not given a green release | 3 / 6 (taxonomy, review-safe, flows-safe) |
| Medium+ findings on clean apps (public and twins) | 11 (labelled false alarm: 9) |
| Anchors not found in the pinned code | 0 |

## By class (documented problems)

| Class | Expected | Found medium+ | Found low | Missed |
|---|---:|---:|---:|---:|
| auth | 5 | 3 | 0 | 2 |
| authz | 11 | 0 | 0 | 11 |
| config | 4 | 0 | 1 | 3 |
| csrf | 2 | 1 | 0 | 1 |
| dependency | 2 | 1 | 0 | 1 |
| deserialize | 4 | 3 | 0 | 1 |
| eval | 4 | 2 | 0 | 2 |
| exposure | 2 | 0 | 0 | 2 |
| nosql | 2 | 0 | 0 | 2 |
| path | 4 | 0 | 0 | 4 |
| pollution | 1 | 0 | 0 | 1 |
| redirect | 4 | 0 | 0 | 4 |
| secret | 7 | 3 | 0 | 4 |
| shell | 6 | 5 | 1 | 0 |
| sql | 10 | 8 | 0 | 2 |
| ssrf | 3 | 1 | 0 | 2 |
| xss | 6 | 0 | 0 | 6 |
| xxe | 2 | 1 | 0 | 1 |

## Call sites (one denominator per app)

| App | Total | Resolved | Likely | Possible | Name only | External | Built-in | Unresolved |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| dvra | 1273 | 220 | 0 | 0 | 0 | 514 | 62 | 477 |
| nodegoat | 246 | 11 | 2 | 0 | 0 | 0 | 0 | 233 |
| dvna | 206 | 2 | 0 | 0 | 0 | 2 | 0 | 202 |
| goof | 160 | 6 | 0 | 0 | 0 | 0 | 0 | 154 |
| pygoat | 2977 | 327 | 20 | 5 | 40 | 1496 | 161 | 928 |
| fastapi-template | 2433 | 1065 | 69 | 0 | 0 | 797 | 39 | 463 |
| express-boilerplate | 506 | 22 | 2 | 0 | 0 | 85 | 0 | 397 |
| taxonomy | 727 | 381 | 8 | 0 | 0 | 114 | 0 | 224 |
| review-unsafe | 17 | 4 | 1 | 0 | 0 | 6 | 1 | 5 |
| review-safe | 17 | 2 | 0 | 0 | 0 | 6 | 3 | 6 |
| flows-unsafe | 59 | 18 | 1 | 0 | 0 | 26 | 3 | 11 |
| flows-safe | 66 | 17 | 1 | 0 | 0 | 31 | 5 | 12 |
| express-unsafe | 23 | 0 | 0 | 0 | 0 | 0 | 0 | 23 |
| express-safe | 25 | 1 | 0 | 0 | 0 | 0 | 0 | 24 |

## Per app

### dvra (vulnerable, Python / FastAPI) · {'critical': 1, 'high': 126, 'medium': 0, 'low': 12} · score 61 D · release Blocked

- dvra-shell · shell · **found** (B602, critical, path)
- dvra-sql · sql · **found** (B608, high, path)
- dvra-bola-order · authz · **missed**
- dvra-mass-assign · authz · **missed**
- dvra-bfla-role · authz · **missed**
- dvra-debug · exposure · **missed**
- dvra-pin · auth · **missed**
- scanners: bandit: ok, pip-audit: ok, npm-audit: skipped: no package.json, maven-audit: skipped: no Gradle or Maven files, composer-audit: skipped: no composer.lock, gem-audit: skipped: no Gemfile.lock, lantern-secrets: ok (built-in patterns; install gitleaks for full coverage), lantern-web: ok (no JS/TS files; Python-side checks only), lantern-ai: ok (no model, vector or paid API calls found)

### nodegoat (vulnerable, Node / Express + MongoDB) · {'critical': 0, 'high': 56, 'medium': 23, 'low': 9} · score 54 F · release Blocked

- ng-eval · eval · **found** (LJ-EVAL, medium)
- ng-nosql · nosql · **missed**
- ng-idor · authz · **missed**
- ng-redirect · redirect · **missed**
- ng-ssrf · ssrf · **missed**
- ng-bfla · authz · **missed**
- ng-secret · secret · **missed**
- ng-cookie · config · **missed**
- ng-csrf · csrf · **missed**
- ng-xss · xss · **missed**
- scanners: bandit: ok, pip-audit: skipped: no Python dependency files, npm-audit: ok, maven-audit: skipped: no Gradle or Maven files, composer-audit: skipped: no composer.lock, gem-audit: skipped: no Gemfile.lock, lantern-secrets: ok (built-in patterns; install gitleaks for full coverage), lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found)

### dvna (vulnerable, Node / Express + Sequelize) · {'critical': 0, 'high': 0, 'medium': 1, 'low': 0} · score 48 F · release Passed

- dvna-sql · sql · **missed**
- dvna-shell · shell · **found** (LJ-EXEC, medium)
- dvna-eval · eval · **missed**
- dvna-deser · deserialize · **missed**
- dvna-xxe · xxe · **missed**
- dvna-redirect · redirect · **missed**
- dvna-reset-token · auth · **missed**
- dvna-secret · secret · **missed**
- dvna-cookie · config · **missed**
- dvna-xss · xss · **missed**
- dvna-authz-admin · authz · **missed**
- dvna-idor · authz · **missed**
- dvna-exposure · exposure · **missed**
- dvna-deps · dependency · **missed**
- scanners: bandit: ok, pip-audit: skipped: no Python dependency files, npm-audit: skipped: no package-lock.json, so exact versions are unknown (commit your lock file), maven-audit: skipped: no Gradle or Maven files, composer-audit: skipped: no composer.lock, gem-audit: skipped: no Gemfile.lock, lantern-secrets: ok (built-in patterns; install gitleaks for full coverage), lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found)

### goof (vulnerable, Node / Express + MongoDB (Snyk demo)) · {'critical': 0, 'high': 107, 'medium': 61, 'low': 16} · score 48 F · release Blocked

- goof-nosql · nosql · **missed**
- goof-redirect · redirect · **missed**
- goof-shell · shell · **found** (LJ-EXEC, medium)
- goof-zipslip · path · **missed**
- goof-pollution · pollution · **missed**
- goof-secret · secret · **missed**
- goof-xss-admin · xss · **missed**
- goof-xss-marked · xss · **missed**
- goof-layout · path · **missed**
- goof-deps · dependency · **found** (GHSA-xcpc-8h2w-3j85, high)
- scanners: bandit: ok, pip-audit: skipped: no Python dependency files, npm-audit: ok, maven-audit: skipped: no Gradle or Maven files, composer-audit: skipped: no composer.lock, gem-audit: skipped: no Gemfile.lock, lantern-secrets: ok (built-in patterns; install gitleaks for full coverage), lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found)

### pygoat (vulnerable, Python / Django + Flask labs) · {'critical': 4, 'high': 227, 'medium': 8, 'low': 79} · score 32 F · release Blocked

- pg-sql · sql · **found** (B608, high, path)
- pg-shell · shell · **found** (B602, high, path)
- pg-eval · eval · **found** (B307, high, path)
- pg-pickle · deserialize · **found** (B301, high, path)
- pg-xxe · xxe · **found** (B317, high, path)
- pg-ssrf · ssrf · **found** (B113, high, path)
- pg-lfi · path · **missed**
- pg-ssti · eval · **missed**
- pg-xss · xss · **missed**
- pg-auth-md5 · auth · **found** (B324, high, path)
- pg-crypto-md5 · auth · **found** (B324, critical, path)
- pg-crypto-sha1 · auth · **found** (B324, critical, path)
- pg-secret-aws · secret · **found** (aws-access-key, critical)
- pg-secret-stripe · secret · **found** (stripe-live-key, critical)
- pg-yaml · deserialize · **found** (B506, high, path)
- pg-pickle2 · deserialize · **found** (B301, high, path)
- pg-django-debug · config · **found-low** (LP-DJANGO-DEBUG, low)
- pg-django-secret · secret · **found** (LP-DJANGO-SECRET-INLINE, medium)
- pg-admin-cookie · authz · **missed**
- pg-csrf-exempt · csrf · **found** (LP-DJANGO-CSRF-EXEMPT, high, path)
- scanners: bandit: ok, pip-audit: ok, npm-audit: skipped: no package.json, maven-audit: skipped: no Gradle or Maven files, composer-audit: skipped: no composer.lock, gem-audit: skipped: no Gemfile.lock, lantern-secrets: ok (built-in patterns; install gitleaks for full coverage), lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found), lantern-pack:django: ok (builtin, 8 finding(s))

### fastapi-template (clean, Python / FastAPI + React) · {'critical': 0, 'high': 0, 'medium': 1, 'low': 6} · score 81 B · release Passed

- loud: LW-AUTH-MISSING medium backend/app/api/routes/private.py:23 · false alarm · backend/app/api/main.py mounts the private router only when FASTAPI_ENV == 'development'; the route never exists in a deployed app
- scanners: bandit: ok, pip-audit: ok, npm-audit: skipped: pnpm-lock.yaml / yarn.lock / bun.lock aren't read yet; run `pnpm audit` or `yarn npm audit`, maven-audit: skipped: no Gradle or Maven files, composer-audit: skipped: no composer.lock, gem-audit: skipped: no Gemfile.lock, lantern-secrets: ok (built-in patterns; install gitleaks for full coverage), lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found)

### express-boilerplate (clean, Node / Express + Mongoose) · {'critical': 0, 'high': 0, 'medium': 5, 'low': 0} · score 74 C · release Passed

- loud: LW-CORS-ANY medium src/app.js:41 · intended · cors() with no options allows any origin; the boilerplate leaves the origin list to the project that copies it
- loud: LW-CORS-ANY medium src/app.js:42 · intended · same cors() call for preflight requests
- loud: LW-JWT medium src/docs/components.yml:31 · false alarm · an example token in the OpenAPI documentation, not a credential
- loud: LW-JWT medium src/routes/v1/auth.route.js:141 · false alarm · an example token inside a swagger doc comment
- loud: LW-JWT medium src/routes/v1/auth.route.js:167 · false alarm · an example token inside a swagger doc comment
- scanners: bandit: ok, pip-audit: skipped: no Python dependency files, npm-audit: skipped: pnpm-lock.yaml / yarn.lock / bun.lock aren't read yet; run `pnpm audit` or `yarn npm audit`, maven-audit: skipped: no Gradle or Maven files, composer-audit: skipped: no composer.lock, gem-audit: skipped: no Gemfile.lock, lantern-secrets: ok (built-in patterns; install gitleaks for full coverage), lantern-web: ok, lantern-ai: ok

### taxonomy (clean, TypeScript / Next.js 13 + Prisma + Stripe) · {'critical': 0, 'high': 1, 'medium': 1, 'low': 0} · score 54 F · release Blocked

- loud: LA-WALLET-DRAIN high app/api/webhooks/stripe/route.ts:8 · false alarm · a Stripe webhook cannot have a login; stripe.webhooks.constructEvent checks Stripe's signature before any Stripe call
- loud: LA-WALLET-DRAIN medium app/api/users/stripe/route.ts:12 · false alarm · getServerSession(authOptions) is checked first and returns 403 without a signed-in user
- scanners: bandit: ok, pip-audit: skipped: no Python dependency files, npm-audit: skipped: pnpm-lock.yaml / yarn.lock / bun.lock aren't read yet; run `pnpm audit` or `yarn npm audit`, maven-audit: skipped: no Gradle or Maven files, composer-audit: skipped: no composer.lock, gem-audit: skipped: no Gemfile.lock, lantern-secrets: ok (built-in patterns; install gitleaks for full coverage), lantern-web: ok, lantern-ai: ok

### review-unsafe (vulnerable, Python / FastAPI) · {'critical': 0, 'high': 4, 'medium': 0, 'low': 0} · score 46 F · release Blocked

- rv-match · sql · **found** (B608, high, path)
- rv-except · sql · **found** (B608, high, path)
- rv-nonlocal · sql · **found** (B608, high, path)
- rv-global · sql · **found** (B608, high, path)
- rv-list-edge · resolution · **found**
- scanners: bandit: ok, pip-audit: skipped: no exact versions to check (commit a lock file such as uv.lock or poetry.lock, or pin with ==), npm-audit: skipped: no package.json, maven-audit: skipped: no Gradle or Maven files, composer-audit: skipped: no composer.lock, gem-audit: skipped: no Gemfile.lock, lantern-secrets: ok (built-in patterns; install gitleaks for full coverage), lantern-web: ok (no JS/TS files; Python-side checks only), lantern-ai: ok (no model, vector or paid API calls found)

### review-safe (clean, Python / FastAPI) · {'critical': 0, 'high': 2, 'medium': 0, 'low': 2} · score 46 F · release Blocked

- rv-match-safe · sql · **clean** (B608, None, path)
- rv-except-safe · sql · **clean** (B608, None, path)
- rv-nonlocal-safe · sql · **false-alarm** (B608, high, path)
- rv-global-safe · sql · **false-alarm** (B608, high, path)
- rv-list-no-edge · resolution · **clean**
- loud: B608 high app/main.py:38 · false alarm · an inner function sets order to the fixed string 'name' through nonlocal; Lantern stops following at the nonlocal and keeps the rank (the safe direction after #151)
- loud: B608 high app/main.py:51 · false alarm · an inner function sets ORDER to the fixed string 'name' through global; same reason
- scanners: bandit: ok, pip-audit: skipped: no exact versions to check (commit a lock file such as uv.lock or poetry.lock, or pin with ==), npm-audit: skipped: no package.json, maven-audit: skipped: no Gradle or Maven files, composer-audit: skipped: no composer.lock, gem-audit: skipped: no Gemfile.lock, lantern-secrets: ok (built-in patterns; install gitleaks for full coverage), lantern-web: ok (no JS/TS files; Python-side checks only), lantern-ai: ok (no model, vector or paid API calls found)

### flows-unsafe (vulnerable, Python / FastAPI + React) · {'critical': 1, 'high': 2, 'medium': 0, 'low': 2} · score 31 F · release Blocked

- fl-sql-chain · sql · **found** (B608, high, path)
- fl-sql-htmlescape · sql · **found** (B608, high, path)
- fl-ssrf · ssrf · **missed**
- fl-zipslip · path · **missed**
- fl-idor · authz · **missed**
- fl-shell-late-guard · shell · **found** (B602, critical, path)
- fl-authz-late-guard · authz · **missed**
- fl-ratelimit-unused · protection · **missed** (in place)
- fl-sql-chain-path · path-coverage · **covered** (B608, high, path)
- scanners: bandit: ok, pip-audit: skipped: no exact versions to check (commit a lock file such as uv.lock or poetry.lock, or pin with ==), npm-audit: skipped: no package-lock.json, so exact versions are unknown (commit your lock file), maven-audit: skipped: no Gradle or Maven files, composer-audit: skipped: no composer.lock, gem-audit: skipped: no Gemfile.lock, lantern-secrets: ok (built-in patterns; install gitleaks for full coverage), lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found)

### flows-safe (clean, Python / FastAPI + React) · {'critical': 0, 'high': 1, 'medium': 0, 'low': 4} · score 41 F · release Blocked

- fl-sql-chain-safe · sql · **false-alarm** (B608, high, path)
- fl-sql-param-safe · sql · **clean**
- fl-ssrf-safe · ssrf · **clean**
- fl-zipslip-safe · path · **clean**
- fl-idor-safe · authz · **clean**
- fl-shell-safe · shell · **clean** (B607, None, path)
- fl-authz-safe · authz · **clean**
- fl-ratelimit-used · protection · **found** (in place)
- fl-ssrf-allowlist · protection · **found** (in place)
- loud: B608 high app/service.py:5 · false alarm · order_clause is one of two fixed ORDER BY strings chosen in helpers.validate_sort; the value crosses a function boundary, which the input check does not follow
- scanners: bandit: ok, pip-audit: skipped: no exact versions to check (commit a lock file such as uv.lock or poetry.lock, or pin with ==), npm-audit: skipped: no package-lock.json, so exact versions are unknown (commit your lock file), maven-audit: skipped: no Gradle or Maven files, composer-audit: skipped: no composer.lock, gem-audit: skipped: no Gemfile.lock, lantern-secrets: ok (built-in patterns; install gitleaks for full coverage), lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found)

### express-unsafe (vulnerable, Node / Express) · {'critical': 0, 'high': 0, 'medium': 1, 'low': 0} · score 49 F · release Passed

- ex-sql · sql · **missed**
- ex-xss · xss · **missed**
- ex-shell · shell · **found-low** (LJ-EXEC, medium)
- ex-redirect · redirect · **missed**
- ex-secret · secret · **missed**
- ex-cookie · config · **missed**
- ex-authz-delete · authz · **missed**
- ex-link-search · resolution · **missed**
- ex-sql-path · path-coverage · **missed**
- scanners: bandit: ok, pip-audit: skipped: no Python dependency files, npm-audit: skipped: no package-lock.json, so exact versions are unknown (commit your lock file), maven-audit: skipped: no Gradle or Maven files, composer-audit: skipped: no composer.lock, gem-audit: skipped: no Gemfile.lock, lantern-secrets: ok (built-in patterns; install gitleaks for full coverage), lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found)

### express-safe (clean, Node / Express) · {'critical': 0, 'high': 0, 'medium': 0, 'low': 0} · score 51 F · release Passed

- ex-sql-safe · sql · **clean**
- ex-xss-safe · xss · **clean**
- ex-shell-safe · shell · **clean**
- ex-redirect-safe · redirect · **clean**
- ex-secret-safe · secret · **clean**
- ex-authz-delete-safe · authz · **clean**
- ex-link-search-safe · resolution · **missed**
- scanners: bandit: ok, pip-audit: skipped: no Python dependency files, npm-audit: skipped: no package-lock.json, so exact versions are unknown (commit your lock file), maven-audit: skipped: no Gradle or Maven files, composer-audit: skipped: no composer.lock, gem-audit: skipped: no Gemfile.lock, lantern-secrets: ok (built-in patterns; install gitleaks for full coverage), lantern-web: ok, lantern-ai: ok (no model, vector or paid API calls found)
