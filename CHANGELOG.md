# Changelog

Each release has a section headed `## <version>`. The release workflow (`.github/workflows/release.yml`) puts the
section matching the pushed tag into the GitHub Release body (`v0.9.0-rc1` uses `## 0.9.0-rc1` if present, else `## 0.9.0`).

## Unreleased

- A big project's report no longer leaves the website's run page empty (2026-11-09). Noetic Compass's report is one
  54,909,481-byte page; the cloud sent it uncompressed, and the frame stayed blank while it arrived (28 s on a 20 Mbit/s
  line in a test, longer on slower ones). Result pages and data files now go out gzip-compressed to browsers that ask
  (3,247,600 bytes for that page; 7 s on the same line), each still rebuilt with its own nonce, and at most two are
  built at once so reloading cannot pile up builds. The run page shows "Opening the report" with a counting clock
  until the report has loaded, and says big projects take longer after 12 seconds.
- Fixed two problems an independent review found (2026-11-09). (1) SQL built from text that was first fixed and then
  replaced with input through a `match` capture, `except … as`, or an inner function's `nonlocal`/`global` was called
  "only fixed text" and lowered from high to low; any of those bindings now means "not followed", so the finding keeps
  its rank. (2) `out = list()` was taken as Python's list even when the repo defines its own `list()`, takes a
  parameter named `list`, imports or assigns one; that erased a real link (`out.append` → the repo's `Box.append`).
  A rebound built-in name is now never counted as the built-in (an annotation such as `x: str` does not rebind it).
  On Noetic Compass b574170: no finding changed rank, no link changed, 28 calls move from "built-in" back to "not
  traced" (27,824 → 27,796; 28,519 → 28,547).
- Tests can no longer reach a real model or the network: provider keys and tokens from the developer's shell are
  removed, `LANTERN_HOME` is an empty folder per test, and connecting to any non-local address fails
  (`tests/conftest.py`). The review's full run had called a real model through an inherited key.
- Python built-in calls (`len`, `print`, a list's `append`) are now counted in the call-site total as their own group
  instead of being dropped without a count; they are still not drawn on the map. A method call on a local that is
  always a built-in literal in its function (`out = []` … `out.append(x)`; every binding of the name must be a literal
  of that one type, the name must not be a parameter, and the type must have the method) is counted as a built-in
  call instead of untraced. On one large app: untraced 33,318 → 28,519 call sites, and 23,025 built-in calls that were
  never counted now are; one wrong link (a list's `append` taken for a library call's result) is gone; no link to the
  app's own code changed on 15 other apps.
- How to use Lantern: a guide page at `/guide` (website and `lantern serve`), in the main menu as "How to use Lantern".
  A 60-second tour and 12 tasks, each with a short animated demo (one shared player, each demo is data: a simplified
  copy of Lantern's screens, a moving cursor, gold-glowing instructions), numbered steps and a Good to know box, plus
  keyboard shortcuts and a note on what is simulated. Demos play only while on screen, start paused with less motion,
  and are labelled "Animated demo · not a screen recording".
- Every finding outside test code now carries its case ("The case for this finding" on the finding card and panel, and
  `case` in `security.json`): where, at which revision; the claim in the tool's words; the evidence and where each fact
  came from; what has to be true for it to hurt, each marked yes / no / cannot check; the impact; why it has its rank;
  how sure Lantern is (lower when the path depends on a likely link); what is not known; and the status words reported,
  reproduced (same id as the previous run), fixed, tested and independently reviewed. Lantern never marks the last two
  itself. Ids are unchanged.
- A setting the browser can see (`VITE_…SECRET`, `NEXT_PUBLIC_…`) now says four things apart on its finding: that it is
  visible (and the header it travels in), whether server code checks it (where, and on which routes), that whether a
  stranger can get in is not determined from code alone, and what else guards those routes (other login checks, the
  settings the checking code branches on). It is never called a confirmed bypass, and its rank does not change.
- Two login-check mistakes fixed: a route decorator's `response_model=TokenResponse` and a request body typed
  `TokenRequest` (or `OAuth2PasswordRequestForm`) no longer count as checking who is calling.
- Every call site Lantern read is now sorted on one denominator (About page and Evidence report): linked for certain,
  likely, one of several targets, guessed by method name, known library call, not traced. Untraced calls in test files
  are counted and said apart, and untraced app calls are grouped by shape. The "guessed by method name" figure the map
  showed before counts links between functions (2,100 on one app), not call sites (2,739), and is now labelled as such.
- Fewer false alarms, nothing hidden. A weak hash (MD5/SHA-1) is ranked by what it is for, read from the names around
  it (the value hashed, where the result goes, the function and class, and the callers of a small wrapper): an id,
  a seed, a cache key or S3's `ContentMD5` checksum is `low`; a password, token or signature keeps its rank; when
  Lantern cannot tell, it is at most `medium`. Python SQL that splices only fixed text (a literal, a choice between
  literals, a module constant) while the values go to the driver as parameters is `low`. Every lowered finding keeps
  its id and shows the rank it would have had and why. "Slow password hashing" now needs a password-named value to be
  hashed (a word in a string or a regex list no longer counts, and `\bcrypto` in a regex is no longer read as
  bcrypt); a password value with no hashing in sight is `check`, not `add`. Found on a real app: 3 critical → 0, with
  paired safe/unsafe tests (`tests/test_context.py`).
- Zoomed in, every page stays usable: when a project's top bar does not fit, its tabs move to a second row that
  scrolls sideways (website and app); Readiness and Protections scroll again after the map was opened (the map's
  full-panel layout stayed on and cut them off); the Findings and Readiness tables scroll sideways instead of cutting
  columns; the map fits a short window; the report no longer drifts 9px sideways on a phone.
- Big projects' reports open again. Files a build tool wrote (a Vite/webpack bundle or minified script, whatever
  its name: a few very long lines) are no longer mapped as code, and the report cuts lines over 2,000 characters and
  caps how much source it carries. One 1.3 MB bundle had made a 360 MB report that took 2.3 GB to open and crashed
  lantern-cloud; the same project's report is now 72 MB and opens with about 500 MB.
- Checks on big projects are about three times faster: finding which functions call which now uses an index
  instead of reading every link each time (a 1,300-file project went from 6 minutes to under 2, with identical
  results). lantern-cloud also allows 20 minutes per run (was 10).
- A repository over the size limit is checked without the pictures, video, sound, fonts, archives, compiled
  programs, model weights and datasets Lantern never reads, so only code counts toward the limit; the Evidence report
  says how many files were left out and names the biggest. lantern-cloud's limit is now 500 MB (was 200), with a 3 GB
  data volume and 2 GB of memory; a run that would not fit in the free space says so instead of failing part-way.
- The website has a Settings page (a button in the header, and in the account sheet): theme, Simple or Advanced, what a
  new check keeps by default, plain-words explanations on or off, sign out, delete the account, play the welcome again.
  The Lantern logo now always does something: from any screen it goes to My runs, and on My runs it plays the welcome.
- My runs shows where each run's open findings are in the stack: Browser, Frontend, Server and Data (Screen and App
  for phone apps), with the count and the worst one in each. Runs checked earlier get it from their stored results.
- The Graph and Flowchart views fill the whole panel and are an endless canvas: drag anywhere, zoom with the wheel or
  a pinch toward the pointer, far past the old 35% to 250% (0.01% to 1,000,000%), and they stay sharp because they are
  still vector. The dots behind move and scale with the map. "fit" shows all of it however large, and a new button (or F)
  takes the map full screen; Esc leaves. On the canvas the arrow keys move, plus and minus zoom and 0 fits; a sideways
  trackpad swipe or shift with the wheel moves the map. On a phone the zoom buttons sit at the top, clear of the legend
  and the Ask Lantern button. Reports made before this keep the old view until the project is analysed again.
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
