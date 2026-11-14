# Try Lantern (tester guide, v0.10)

Thanks for testing. This takes about fifteen minutes. If something breaks or confuses you, that is exactly what we
want to hear about: section 7 says how.

## 1. What it does, and the one rule

Lantern reads an app's code and shows you what it does and what to fix. It reads **phone apps** (Android in Java or
Kotlin, iPhone in Swift, Flutter, React Native, .NET MAUI) and **web and server code** (Python, TypeScript/JavaScript,
Go, Rust, Java, Kotlin, Swift, Dart, C#, PHP, Ruby, C/C++), in one map when an app has both sides. It shows you:

* **Paths**: every route from a click or an API call, through the functions it reaches, down to the database.
* **What to fix**: security problems, ranked by whether a visitor can reach them and whether outside input gets there.
* **Ready to ship?**: a 0–100 score across ten areas, with the next things to do and starter files it can write.
* **Evidence**: a report pinned to one commit that a skeptical engineer can check line by line.
* **On the phone** (Android, iPhone, Flutter, React Native apps): the screens, the links other apps can open, the
  permissions the app asks for and whether the code uses them, and phone-specific problems such as a deep link that
  reaches a database query or a secret kept in plain storage.

**The one rule: facts from tools, words from models.** Every path, finding and score comes from deterministic code that
gives the same answer every time. An AI model may only explain what that code found. It never creates, dismisses or
closes a finding, and every sentence it writes must point at real code.

## 2. Install

You need Python 3.11 or newer ([python.org](https://www.python.org/downloads/); on Windows tick "Add python.exe to
PATH") and git. In a terminal (PowerShell on Windows, Terminal on Mac):

```bash
python -m venv lantern-env
# macOS / Linux:
. lantern-env/bin/activate
# Windows PowerShell:
#   lantern-env\Scripts\Activate.ps1
pip install "lantern[scan] @ git+https://github.com/LittleHenderson/Lantern@v0.11.0"
lantern --version
```

`[scan]` adds two optional scanners (Bandit for Python code, pip-audit for Python dependencies). Without it Lantern still
runs all of its own rules and prints an `off` line naming what is not installed.

To read text from screenshots in Ask Lantern (section 6), add the `[ocr]` extra and the Tesseract program:

```bash
pip install "lantern[scan,ocr] @ git+https://github.com/LittleHenderson/Lantern@v0.11.0"
# then Tesseract itself:
#   macOS:    brew install tesseract
#   Windows:  winget install UB-Mannheim.TesseractOCR
#   Linux:    sudo apt install tesseract-ocr
```

## 3. Run

Two ways. **No install at all**: open **https://lantern-cloud.fly.dev/**, sign in with GitHub or Google, and paste the
link of a public repository (or upload a folder or .zip from your computer). The check runs on Lantern's server, the
copy of your code is deleted when it ends, and you can delete the results any time. Android creators: paste your app's
GitHub link; a repository with an `app/` folder and an `AndroidManifest.xml` is read as an Android app.

**On your own computer** (private code, or to watch your tests run):

```bash
lantern serve path/to/your/app
```

Your browser opens Lantern. The terminal prints a one-time link if the browser does not open: copy it into the
browser. The app listens on this computer only (127.0.0.1). You can also start with no path and use **Add a project**
(a folder, or a public GitHub link, which Lantern clones into `~/.lantern/repos`).

No app of your own handy? Use the **Learn** tab: it writes a small starter app with planted problems and walks you
through fixing them.

Press Ctrl-C in the terminal to stop Lantern.

## 4. What to look at

1. **Home**: your project's grade and open findings. The first analysis takes a few seconds (about a minute for a
   large app). For a phone app the grade is for an app, not a website: the checks are about signing, permissions,
   storage, network security and crash reporting.
2. **Paths**: pick a page or route and follow it down to the database. Click any function to see what it does.
   Each link says how sure Lantern is: seen running, confirmed, likely or possible.
3. **What to fix**: open the top finding. It shows the click path a user takes to reach it and how to fix it.
   "Send to…" hands it to your AI assistant. "Accept risk…" needs a written reason and never hides the finding.
4. **Ready to ship?**: the score and the next three moves. "Write them for me" adds starter files and never
   overwrites one.
5. **Evidence**: the report for a reviewer, pinned to your commit.
7. **On the phone** (phone apps only, on the findings page): the card lists your screens, every way another app can
   start yours, and each permission with a plain-words meaning and whether the code uses it. Check it against what you
   know your app does: a permission you never asked for, or a screen you do not recognise, is worth a report.
6. **Simple / Advanced** (top right): Simple uses plain words, Advanced shows the technical detail. Lantern
   remembers your choice.

Things we especially want to know: which screen confused you, a finding you think is wrong (a false alarm or a
missed problem), and anything that took longer than it should. For phone apps: did Lantern see all your screens, and
did the permissions card match the app you know?

If you are part of an organised tester round, your host will give you the four tasks in
[docs/tester-round.md](tester-round.md) and a results sheet to fill in; the whole round takes about forty minutes.

## 5. Explanations

Explanations ("What does this do?") are written by a model, so they need one:

* **Free allowance**: in **Settings**, press **Sign in with GitHub** or **Sign in with Google** (or run
  `lantern login --github`). Lantern stores a token, never your email. Explanations then come from Claude Haiku
  through Lantern's gateway, with daily and lifetime limits. The gateway keeps a fingerprint (hash) of your token
  and how many requests you made each day, never your code, the prompts or the answers. Each day's count is deleted after
  90 days, and the token's hash after 90 days without use; after that, signing in again starts a fresh allowance.
* **Your own key**: in Settings, pick a provider (Anthropic, OpenAI, OpenRouter, Mistral, Gemini, DeepSeek) and
  paste a key. Keys stay in memory unless you tick "remember".
* **Fully local**: pick Ollama or LM Studio. Nothing leaves your computer.

Before any code leaves your computer, Lantern asks once per provider and says where the code goes. Lantern sends the
functions being explained, not your whole project.

## 6. What runs where

Lantern reads your code and does not run it. There are exactly three exceptions, and each one asks first or stays on
your computer:

| Feature | What runs | Where |
|---|---|---|
| **Watch my tests run** (Paths) | Your project's test command, shown to you and confirmed once before the first run | In a sandbox, on a copy of your project that is thrown away afterwards: the tests may change the copy, never your project. With Docker: a pinned image, no way out to the internet, a non-root user. Without Docker: the copy in a temp folder with a cleaned environment, writes anywhere else and the network blocked (Linux also uses Landlock, and gives the tests a network of their own, so a test may start your app's server and call it), CPU, file and memory limits, and on Windows a job object. On Windows and Mac that blocking is done inside Python: tests that are not Python (JavaScript tests, or another program a test starts) are not kept from the network or from your files there, and the sheet tells you so before you run them. The libraries your project names (requirements, `pyproject.toml`, a lock file, `package.json` with its npm lock) are fetched for the run from PyPI and the npm registry, ready-built packages only and with no install script run; that step sends library names and versions, never your code, and the tests then run with the network off wherever the sandbox on your system keeps them from it, which the sheet and the message after the run tell you (offline nothing is fetched and they run on what is installed when every library is there; where a library cannot be had the tests are not run, and Lantern names it). Stopped after 10 minutes and at 2 GB of memory in use unless you set other limits in the sheet (1 to 240 minutes; from 128 MB), or when you press **Stop the tests** (your results then stay as they were). Tests stopped at a limit are neither passed nor failed: the release decision says Incomplete and how to give them more. Whatever way they end, every program they started is ended too. If the sandbox cannot be set up on your computer, the tests are not run and Lantern says why; your code is still checked. Python tests upgrade the map's links to "seen running". Other languages run, but the map only upgrades for Python for now. |
| **Terminal** (the drawer at the bottom) | Lantern's own commands only: `analyze`, `trace`, `explain`, `report`, `verify`, `accept`, `packs`, `export`, `learn` | On your computer, as Lantern. Anything else is refused. It never runs shell commands or your code, and its results go to the project's `.lantern` folder. |
| **Screenshots in Ask Lantern** | Tesseract reads the text in an image you drop in | On your computer. The image is piped to Tesseract and never saved or uploaded. Only the text you then send as a question goes to your model. Without Tesseract, Lantern says how to install it. |

## 7. How to report

Open a **[tester report](https://github.com/LittleHenderson/Lantern/issues/new?template=tester-report.yml)**. The form
asks for:

* `lantern --version` and your operating system;
* what you did, what you expected, and what happened;
* a screenshot if it helps.

Please do not paste API keys, tokens, or code you cannot share. Findings mention file names and lines, so crop
those if your project is private.

## 8. Uninstall

```bash
pip uninstall lantern
```

Then delete what Lantern kept:

* `~/.lantern`: the app's project list, settings, remembered keys and cloned repositories (on Windows,
  `C:\Users\<you>\.lantern`);
* `~/.config/lantern`: your free-allowance token and consent choices (on Windows,
  `C:\Users\<you>\.config\lantern`);
* the `.lantern` folder inside each project you analyzed (results only; your code is untouched);
* the `lantern-env` folder, if you made the virtual environment in section 2.
