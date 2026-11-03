# Try Lantern (v0.9 tester guide)

Thanks for testing. This takes about fifteen minutes. If something breaks or confuses you, that is exactly what we
want to hear about: section 7 says how.

## 1. What it does, and the one rule

Lantern reads an app's code (Python, TypeScript/JavaScript, Go, Rust, Java) and shows you:

* **Paths**: every route from a click or an API call, through the functions it reaches, down to the database.
* **What to fix**: security problems, ranked by whether a visitor can reach them and whether outside input gets there.
* **Ready to ship?**: a 0–100 score across ten areas, with the next things to do and starter files it can write.
* **Evidence**: a report pinned to one commit that a skeptical engineer can check line by line.

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
pip install "lantern[scan] @ git+https://github.com/LittleHenderson/Lantern"
lantern --version
```

`[scan]` adds two optional scanners (Bandit for Python code, pip-audit for Python dependencies). Without it Lantern still
runs all of its own rules and prints an `off` line naming what is not installed.

To read text from screenshots in Ask Lantern (section 6), add the `[ocr]` extra and the Tesseract program:

```bash
pip install "lantern[scan,ocr] @ git+https://github.com/LittleHenderson/Lantern"
# then Tesseract itself:
#   macOS:    brew install tesseract
#   Windows:  winget install UB-Mannheim.TesseractOCR
#   Linux:    sudo apt install tesseract-ocr
```

## 3. Run

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

1. **Home**: your project's grade and open findings. The first analysis takes a few seconds.
2. **Paths**: pick a page or route and follow it down to the database. Click any function to see what it does.
   Each link says how sure Lantern is: seen running, confirmed, likely or possible.
3. **What to fix**: open the top finding. It shows the click path a user takes to reach it and how to fix it.
   "Send to…" hands it to your AI assistant. "Accept risk…" needs a written reason and never hides the finding.
4. **Ready to ship?**: the score and the next three moves. "Write them for me" adds starter files and never
   overwrites one.
5. **Evidence**: the report for a reviewer, pinned to your commit.
6. **Simple / Advanced** (top right): Simple uses plain words, Advanced shows the technical detail. Lantern
   remembers your choice.

Things we especially want to know: which screen confused you, a finding you think is wrong (a false alarm or a
missed problem), and anything that took longer than it should.

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
| **Watch my tests run** (Paths) | Your project's test command, shown to you and confirmed once before the first run | In a sandbox. With Docker: a pinned image, your project mounted read-only, no network, a non-root user. Without Docker: a read-only copy in a temp folder with a cleaned environment, writes and network blocked (Linux also uses Landlock), CPU, file and memory limits, and on Windows a job object. Stopped after 10 minutes. Python tests upgrade the map's links to "seen running". Other languages run, but the map only upgrades for Python for now. |
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
