# Changelog

Each release has a section headed `## <version>`. The release workflow (`.github/workflows/release.yml`) puts the
section matching the pushed tag into the GitHub Release body (`v0.9.0-rc1` uses `## 0.9.0-rc1` if present, else `## 0.9.0`).

## Unreleased

- Fix this for me (optional): pick a coding agent you already use (Claude Code, Codex or Aider) in Advanced
  Settings, and a finding's Fix screen offers "Fix this for me with …". The agent works on a copy of your project;
  Lantern then analyzes the copy and tells you, in one line, whether the problem is gone and whether anything new
  and serious appeared. The changed files are one tap away, and nothing reaches your project until you press
  Apply, which refuses if you changed those files meanwhile. Off by default (directive: user first, step 6).
- Notes on the map (Lantern Cloud): people who can open a report leave short notes on a function for each other
  ("Is this still used?"). They sit behind one "Add a note" or "Notes · 2" button in the function's panel, and a
  small mark on the map shows where notes are. Notes are words only: they never change what Lantern found and are
  never sent to a model. The author or the report's owner deletes a note; a member who sees only some layers sees
  notes only there. New `/v1/runs/{id}/notes` and `DELETE /v1/notes/{id}` (docs/api.md) (directive: user first,
  step 5).
- Per-layer permissions in team workspaces: the owner chooses, per person, which layers of the app (Browser,
  Frontend, Server, Data) they can see in the workspace's reports, from a "Sees everything" button on the Team
  page. That person's report is built on the server without the other layers, so nothing about them reaches their
  browser: where their part calls into a hidden layer the map shows one sealed box ("Something in the Server"),
  and a line at the top says which layers they can see. The overall score, log, evidence report, raw files and Ask
  Lantern describe the whole app, so they stay with people who see everything. The view link carries the layers
  and can't be edited to open more. New `PUT /v1/workspaces/{id}/people/{person}` and `lantern/scope.py`
  (directive: user first, step 4).
- Team workspaces on Lantern Cloud: a few people who can open each other's reports. The owner names a workspace
  and invites people with one-time links (they work once, for 7 days; Lantern keeps only a hash and never asks for
  an email). A report joins only when its own owner puts it there (Share, then Your team, or Add one of my reports
  on the Team page), and teammates can open it but never change, share, explain or delete it. Owners take people
  out or close the workspace; leaving, removing someone or closing gives every report back to its owner, and
  nothing is deleted. The Team page sits in Advanced and appears in Simple only once someone is in a workspace.
  New `/v1/workspaces`, `/v1/invites` and `PUT /v1/runs/{id}/workspace` (docs/api.md) (directive: user first,
  step 3).
- Getting started is one button: Simple's home on Lantern Cloud and in `lantern serve` opens with **Show us your
  project**, then asks one plain question per screen (is it on this computer, on GitHub, or not sure?). The word
  repository never shows; "Where do I find the link?" and "Is my code safe?" sit behind small Why? buttons, and
  "I'm not sure" walks through finding a project an AI builder made, with the practice app as a way out. While a
  check runs, Simple shows a real progress bar with the step it is on in plain words ("Step 2 of 4: Looking for
  problems"), read from the pipeline's own log lines; the raw log is one tap away. Advanced keeps its add bar and
  its log as before (directive: user first, step 2).
- C and C++ are read: programs, libraries and C++ web servers (cpp-httplib, Crow, Drogon, Pistache). Namespaces,
  classes, methods (in the class or `Class::m`), free and `static` functions are on the map with their calls (typed
  locals and members through `const&`, pointers and `std::unique_ptr`, `auto p = std::make_unique<T>()`, `this->`,
  `Class::f()`, `ns::f()`, `new T`); the C library's `system`, `sqlite3_exec`, `fopen` show in the Data lane. Each
  program's `main` is a start point, route lambdas are their own steps, gtest/Catch2 blocks are tests, and copied-in
  single-file libraries (`httplib.h`, `json.hpp`, `sqlite3.c`) and `third_party/` are left out. A React page whose
  search box reaches `snprintf(sql, …, "… LIKE '%%%s%%'", q)` is critical, and so is a command-line tool that runs
  `system()` or `printf(argv[1])` with its argument. 12 new `LX-*` checks: SQL built with `sprintf`/`+`, shell
  commands, `gets`, unbounded `strcpy`/`sprintf`, `scanf("%s")`, format strings, TLS checks off, `rand()` for
  secrets, MD5/SHA-1 passwords, `tmpnam`, files named by the request or `argv`, plain `http://`. Readiness reads
  `CMakeLists.txt`/Conan/vcpkg/Meson and `ctest`. New sample: `tests/fixtures/cppapp`.
- Ruby is read: Rails and Sinatra apps. Classes, modules, methods and top-level methods are on the map with their
  calls (`@svc = NoteService.new` then `@svc.all`, `note = Note.find(id)` then `note.destroy`, included modules,
  `self.`, class methods, `X.new` → `initialize`; Active Record queries and Kernel's `system`/backticks show in the
  Data lane). Routes come from `config/routes.rb` (`resources`, `namespace`, `scope`, `member`/`collection`,
  `get "p", to: "c#a"`, `root`) and Sinatra `get '/p' do`; jobs' `perform` is a start point. A controller's
  `before_action :authenticate_user!` (inherited, `only:`/`except:`, `skip_before_action`) passes the login check, so
  a skipped `destroy` is reported. A React page whose search box reaches `Note.where("… #{q} …")` is critical. 17 new
  `LB-*` checks: SQL built with `#{}`, `order(params[:x])`, shell commands, `eval`/`constantize`, `Marshal.load`,
  `html_safe`/`raw`/`<%==`, mass assignment, redirects and files from `params`, TLS checks off, MD5/SHA-1 passwords
  and tokens, CSRF protection off, CORS `*`, full error pages in production, a written `secret_key_base`, plain
  `http://`. Gems in `Gemfile.lock` are checked against the OSV vulnerability database (`gem-audit`). Readiness reads
  the Gemfile/Gemfile.lock, Rails/Sinatra and `rspec`/`rails test`. New sample: `tests/fixtures/rubyapp`.
  On OWASP RailsGoat: 7 critical findings (SQL, shell, `Marshal.load` of `params`, three `constantize` of `params`).
- The AI-call scan skips lines over 2,000 characters (minified bundles such as `jquery.min.js`): one such line took
  minutes to read, so a Rails app with vendored JavaScript never finished.
- PHP is read: Laravel, Symfony, Slim, WordPress plugins and plain PHP pages. Namespaces, classes, interfaces, traits,
  functions and the top-level code of a page are on the map with their calls (`$this->repo->find()` through typed and
  promoted properties, `new Repo()`, `self::`/`static::`/`parent::`, static calls, interfaces fanning out as
  `possible` edges, `[Controller::class, 'show']`, `'Controller@show'`, `require 'db.php'`). Routes come from Laravel
  (`Route::get`, `resource`, `prefix()->group()`, `routes/api.php` adds `/api`; a route inside an `auth` middleware
  passes the login check), Symfony `#[Route]`/`@Route`, Slim/Lumen `$app->get` and `group`, WordPress
  `wp_ajax_nopriv_*` (anyone can call it) and `register_rest_route`, and plain pages a browser opens directly
  (`ANY /legacy/login.php`). A React page whose search box reaches a Laravel `DB::select("…'%$q%'")` is critical, and
  so is an old login page that builds SQL from `$_POST`. 18 new `LH-*` checks: SQL built from variables (also in
  `whereRaw`/`DB::raw`), shell commands, `eval`, `include` of a visitor-chosen file, `unserialize`, echoing `$_GET`,
  Blade `{!! !!}`, MD5/SHA-1 passwords and tokens, TLS checks off, `extract($_POST)`, CORS `*`, `display_errors`,
  uploads saved under the visitor's name, plain `http://`. PHP libraries in `composer.lock` are checked against the
  OSV vulnerability database (`composer-audit`). Readiness reads `composer.json`/`composer.lock`, Laravel/Symfony/Slim
  and `phpunit`/`artisan test`. New sample: `tests/fixtures/phpapp`.
- C# is read, for ASP.NET servers and .NET MAUI / Xamarin phone apps. Namespaces (block and file-scoped), classes,
  structs, records, interfaces, `partial` classes written across files, constructors and top-level statements are on
  the map with their calls (own class, typed fields, properties and locals, `var x = new T()`, static calls, `this`,
  interfaces and abstract classes fan out as `possible` edges, `button.Clicked += OnSave`, method groups). Routes come
  from controllers (`[Route("api/[controller]")]` + `[HttpGet("{id}")]`) and minimal APIs (`app.MapGet`, `MapGroup`
  prefixes, inline lambdas and `Class.Method` handlers); `HttpClient` calls (`GetStringAsync`, `PostAsJsonAsync`,
  `new HttpRequestMessage(HttpMethod.Put, …)`, paths relative to `BaseAddress`, `const` URLs) link the phone app to the
  server. A MAUI app's pages (`ContentPage`, `Shell`, …: constructor, `OnAppearing`, event handlers), its view models'
  `[RelayCommand]`s and its link handlers (`OnAppLinkRequestReceived` and what it hands the link to) are entry points,
  so a search box whose text reaches server SQL built with `$"…{q}…"` is critical, and so is a shared link whose id
  reaches a local SQLite query. 11 new `LC-*` checks: SQL and shell commands built from variables, trusting any
  certificate, MD5/SHA-1, `BinaryFormatter`/`TypeNameHandling`, CORS for any site, `Html.Raw`, plain `http://`,
  passwords in connection strings (code and `appsettings.json`), and on the phone: tokens in `Preferences` or the log.
  Readiness grades a `.NET MAUI app` (crash reporting, `Console.WriteLine` in release, `packages.lock.json`,
  `HttpClient.Timeout`, Polly retries). The viewer no longer calls Kotlin, Swift, Dart or C# server code "library".
  New sample: `tests/fixtures/csharpapp`.
- Flutter and React Native apps are read as phone apps. Lantern now reads Dart: classes, mixins, extensions and
  functions are on the map with their calls (to their own class, typed fields and locals, `final db = NoteDb();`,
  static methods, interfaces, `onPressed: _load`), and a widget built inside another (`HomeScreen()`) leads to its
  `build` (a StatefulWidget's State `build`). Screens are the widgets a route opens (`MaterialPageRoute`, `routes:`,
  `home:`, `GoRoute`, `Navigator.push…`) and widgets named `…Screen`/`…Page`; the code a `uriLinkStream` /
  `getInitialLink` listener calls is where links start. React Native and Expo apps get their screens from React
  Navigation (`<Stack.Screen component={NoteScreen} />`, the `linking` config) and Expo Router files (`app/**`), and
  their link handlers from `Linking.addEventListener("url", …)` / `getInitialURL()`. In both, a link whose id reaches a
  database query built from text is critical. New checks: 8 `LF-*` for Dart (passwords in the log or in
  SharedPreferences, trusting any certificate, SQL built from variables, web view JavaScript and bridges, plain
  `http://`, weak hashes) and 10 `LN-*` for React Native (tokens in AsyncStorage or the log, SQL built from
  variables, web views open to any site or to files, plain `http://`, and Expo's `app.json`: URL schemes, backups on,
  App Transport Security off, permissions the code never uses). Readiness grades them as a Flutter app or a React
  Native app when there is no `android/` or `ios/` folder to read (crash reporting, logs in release, timeouts and
  retries, ATS and backups in `app.json`, `pubspec.lock`). New samples: `tests/fixtures/flutterapp`,
  `tests/fixtures/rnapp`.
- iOS apps are read as iPhone apps. Lantern now reads Swift: types, extensions, protocols and SwiftUI views are on the map
  with their calls, and the app's screens (UIKit view controllers, SwiftUI views the app or a navigation link opens) and
  the code that handles incoming links (`.onOpenURL`, the app and scene delegates) are where paths start. A link whose
  id reaches a database query built with `\(id)` is critical, with an iPhone story ("Sam sends a link to your app…").
  16 new `LI-*` checks cover Info.plist (App Transport Security off, URL schemes any app can send, file sharing, keys
  written in it, permissions the code never uses), entitlements (`get-task-allow`), the Xcode project (old minimum iOS)
  and Swift code (passwords in the log or in UserDefaults, Keychain items readable while locked, trusting any
  certificate, SQL built from variables, weak hashes, web view file access and bridges, UIWebView, plain `http://`,
  secrets on the clipboard). The "On the phone" card lists what the app asks to use, and Readiness grades it as an iOS
  app (crash reporting, print kept out of release, ATS, debugger, minimum iOS, timeouts, signing files not committed).
  Vapor routes in Swift servers are entry points too. New sample: `tests/fixtures/iosapp`.
- Kotlin is read and mapped, not just checked line by line. Kotlin classes, `object`s, companions and functions are on
  the map with their calls (to their own class, objects, companions, typed properties and locals, interfaces, `::f`
  references), so an Android app written in Kotlin gets the same paths as one in Java: a link that opens a screen and
  whose id reaches a database query is critical. Screens drawn with Jetpack Compose (`@Composable fun HomeScreen`) are screens on the map. Spring routes in Kotlin are
  entry points, Java's server checks (SQL and
  shell commands built from variables, weak hashes, trust-all certificates) run on Kotlin too, and a value put into a
  Kotlin string (`"… '$id'"`) counts as used. New sample: `tests/fixtures/kotlinapp`.
- Android and Java libraries are checked for known security holes. Lantern reads the libraries written in
  `build.gradle`, `build.gradle.kts`, `gradle/libs.versions.toml` and `pom.xml` (test libraries left out, `$version`
  variables and Maven properties filled in) and asks the public OSV database about each exact version. Each finding
  points at the line the library is written on and names the version that fixes it. `--offline` skips it, and the
  Evidence Report says that libraries pulled in by other libraries were not checked.
- Android apps are read as phone apps. Lantern finds the app's screens and the parts other apps can start from
  `AndroidManifest.xml`, so findings get a real path ("a link opens NoteActivity and the id it carries reaches a
  database query" is critical), and the map says Screen and App instead of Browser and Server. 26 new `LM-*` checks
  cover the manifest (debuggable, backups, plain http, components open to other apps, permissions the code never
  uses, Google keys), the network security config (plain http, user certificates), the Gradle build (release
  debuggable or signed with the debug key, no R8, old target SDK, `+` versions, signing passwords) and Java/Kotlin code
  (location or tokens in the log, WebView JavaScript, bridges and file access, ignored SSL errors, shared storage,
  plain-text logins in SharedPreferences, SQLite queries built from text, trust-all certificates, `http://` links,
  broadcasts any app can hear). Findings has an "On the phone" card listing what the app asks to use and what is open
  to other apps. Readiness grades an Android app as one: crash reporting, logs stripped from release, R8, signing key,
  target SDK, network timeouts and retries, and Android Studio's sample tests no longer count as real tests. Each
  Android problem has its own story (another app on the phone, a USB cable, a café Wi-Fi). On devr22/HerSheild: 13
  findings where there were none, readiness 55 instead of 28.
- Cloud: 50 runs per person per day (was 10) and 1000 for everyone together (was 300), the owner's choices of 2026-11-04; `docs/deploy.md` says how to change it with one command.
- Every function has its three lenses from the moment a check ends. Where no model has explained a function yet, the
  Technical, Everyday and Mapped lenses are built from the map alone (file, lines, signature, entry point, calls, HTTP
  links, findings), with a byline that says no model wrote them and every phrase anchored to a real symbol. The
  Explain button still asks a model for the fuller wording and an analogy. The Explanations list now reads "Explained
  by a model" and "From the map so far". `tools/viewer_smoke.js` checks the map-built lenses render.
- Fixed: the analysis crashed outright (a segmentation fault, shown on the website as a bare "stopped with an error")
  on repositories with a function past line 256 of a file, for example devr22/HerSheild. The cause was the
  `tree-sitter` Python package 0.26.0, which frees a node's line number while it is still in use; Lantern now refuses
  that version (`tree-sitter>=0.23,!=0.26.0`) and a test parses past row 256 in a child process so a bad build fails
  the suite instead of killing it. The Java and Rust readers also keep each parse tree alive for as long as its nodes
  are used. The cloud now says when the analysis died before writing anything ("crashed (signal 11) … a bug on
  Lantern's side") instead of a sentence with no cause.
- Website: Connect GitHub, for private repositories. When the owner sets up Lantern's GitHub App (`docs/deploy.md`), a
  private repository's check offers "Connect GitHub": the person picks repositories on GitHub, clicks Try again, and
  Lantern reads them with a one-repository, read-only token that lasts an hour at most, only for someone GitHub says
  may read that repository. The token reaches git through its environment, never a link, file or log. "Connect private
  repositories" also sits beside "Explore GitHub". Off (Upload only) until the app is configured.
- Findings page: its counts now match the summary, the grade and Ask Lantern. Findings in test code (test files and
  fixtures, often planted on purpose) were counted in the page's "open" number and severity tiles but nowhere else; they
  are now listed at the end under "In test code: N, not counted" (Advanced: an "In test code" filter).
- Script written inside HTML pages is now read (an app's own `index.html`, Jinja/Django templates, the pages of a
  server-rendered app): its functions appear on the map with the page's line numbers, its `fetch` calls link to the
  backend routes, and the page sits in the Browser lane with its functions in Frontend. JSON blocks, `src=` tags,
  `text/babel` and `.min.html` are left alone. Lantern's own map now shows its four pages and 389 of their functions,
  and its shape reads "full-stack web app". The pattern rules (`LJ-*`) still read only `.js`/`.ts` files.
- Website: a private repository (or a wrong link) no longer stops with git's "could not read Username… clone it yourself"
  message. The check says in plain words that Lantern could not open it, and offers "Upload your code instead", which
  opens the upload window; git's own words stay in the log.
- Website home: the warm light behind the headline, as in the mock-ups (the app's home has it too); "Your repositories"
  (GitHub sign-ins) and "Explore GitHub" buttons under the link box, to find a repository to paste; and "Try a sample app":
  Lantern's four built-in starter apps, each with planted problems, checked with one click (written from the package,
  nothing cloned), so a beginner sees a real report without a repository of their own.
- Website: upload an app from your computer. "Upload…" next to the link box (or drop a folder or a .zip on it) sends a
  folder, zipped in the browser without `node_modules`, `.git`, virtual environments and build output, or a .zip
  (`POST /v1/uploads`). The new `lantern.archive` unpacks it inside the sealed box with no network and refuses names
  that leave the folder, links, password-protected files and archives that grow past the size cap; the upload is
  deleted when its check ends. Messages under the link box no longer vanish when the page refreshes its runs.
- Website: a check in progress always shows that it is working. The button you clicked spins while the check starts
  ("Starting your check…"), and each running check shows a timer that counts every second ("running for 0:42") on its
  card and its progress page. With animations turned off in Windows or macOS (reduced motion), the progress bar and dots
  now fade in and out instead of standing still. The app (`lantern serve`) shares the bar and dot change.
- Landing page: the intro plays on every visit to `/` (deep links and `?intro=0` skip it) with no flash of the page first,
  and ends on a card with "Add your app" (lands on the install card with an accent ring) and "See a finished report
  first"; Skip and Escape jump to that card. The hero's first button is now "Add your app". The React scripts carry SRI
  hashes, and the page opens even if they do not load. On phones the page is no longer wider than the screen.
- Website (lantern-cloud): the same 20-second intro plays on every visit to the home page, ends on "Add your app" (lands
  on the link box with an accent ring) and "Try a sample app first", and Skip or Escape jump to that card. Links to a
  run or to Help (`#/run/…`, `#/help`) and `?intro=0` skip it. Its scripts and React are served from the website itself
  under the page's nonce, never from another host; if they fail to load, the page shows as before.

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
