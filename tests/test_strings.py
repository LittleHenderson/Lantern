"""No line of a project keeps the check busy (2026-11-13).

Four places found string literals with one pattern that had two ways through a backslash. Where a quote is followed
by backslashes and no closing quote it tried every way of pairing them: a comment of 73 characters (an apostrophe
and thirty pairs of backslashes) kept `lantern analyze` busy for days, in a Python file and in a JavaScript one.
Two patterns beside it took four times the time for twice the text (comments and templates that nothing closes).

`lantern/strings.py` finds the same strings in time that grows with the text. Three kinds of test:

* the check ends: the whole analysis of a project with such lines, and each place that read them, in a child
  process with a time limit (on the code before, every one of them runs into the limit);
* nothing else changed: the patterns as they were are kept here and compared with the new functions, match for
  match, on every short text over a small alphabet, on longer texts made at random, and on Lantern's own code;
* the old way does not come back: no module finds a string with that pattern.

No line of this file is such a line: they are put together when the tests run."""

import functools
import itertools
import json
import random
import re
import subprocess
import sys
from pathlib import Path

import pytest

import lantern_files
from lantern import security, strings, websec

ROOT = Path(__file__).resolve().parents[1]

# The patterns as they were. Only ever run on short text, or on lines with few backslashes (`FEW`).
OLD_STRING = {q: re.compile(r"([" + q + r"])(?:\\.|(?!\1).)*\1") for q in ("'\"", "'\"`")}
OLD_TEMPLATE = re.compile(r"`(?:\\.|[^`\\])*`")
OLD_BLOCK = re.compile(r"/\*[\s\S]*?\*/")
FEW = 16

BACK = "\\" * 60                                         # thirty pairs
LINE = "it's a path: " + BACK                            # the line: an apostrophe, backslashes, and the line ends


def old_code_only(text: str, js: bool = False) -> str:
    """`websec.code_only` as it was."""
    blank = websec._blank
    if js:
        text = OLD_TEMPLATE.sub(blank, text)
    else:
        text = re.sub(r"(\"\"\"|''')[\s\S]*?\1", blank, text)
    text = OLD_STRING["'\""].sub(blank, text)
    if js:
        text = OLD_BLOCK.sub(blank, text)
        text = re.sub(r"//[^\n]*", blank, text)
    else:
        text = re.sub(r"#[^\n]*", blank, text)
    return text


def _shown(sub, text: str, quoted: bool = True):
    """What `sub(repl, text)` gives with a replacement function that numbers its matches, and what each match was:
    where it starts and ends, its text and, for a string (`quoted`), its quote and the text the match is of."""
    seen = []

    def repl(m):
        seen.append((m.start(), m.end(), m.group(0), m.group(1) if quoted else "", not quoted or m.string == text))
        return f"<{len(seen)}>"
    return sub(repl, text), seen


def _texts(alphabet: str, longest: int):
    for n in range(longest + 1):
        for t in itertools.product(alphabet, repeat=n):
            yield "".join(t)


def _made(alphabet: str, count: int, longest: int, seed: int):
    """Longer texts at random; a line holds few backslashes, so the old pattern can be asked."""
    rnd = random.Random(seed)
    for _ in range(count):
        t = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, longest)))
        if all(line.count("\\") <= FEW for line in t.split("\n")):
            yield t


# ---------------------------------------------------------------- the check ends

def _child(code: str, *args: str, limit: int = 30):
    try:
        return subprocess.run([sys.executable, "-c", code, *args], capture_output=True, text=True, encoding="utf-8",
                              timeout=limit)
    except subprocess.TimeoutExpired:
        return None


PLACES = {
    "strings and comments blanked in Python":
        "from lantern import websec\nwebsec.code_only('x = 1  # ' + LINE + '\\ny = 2\\n')",
    "strings and comments blanked in JavaScript":
        "from lantern import websec\nwebsec.code_only('let x = 1;  // ' + LINE + '\\nlet y = 2;\\n', js=True)",
    "the statements the input check reads":
        "from lantern import security\nsecurity._statements(['x = 1  # ' + LINE, 'y = x'], 1, 2, False)",
    "a PHP line for the input check":
        "from lantern import security\nsecurity._php_line('$x = 1;  // ' + LINE)",
    "comments that nothing closes":
        "from lantern import websec\nwebsec.code_only('/* ' * 150000, js=True)",
    "a template that nothing closes":
        "from lantern import websec\nwebsec.code_only('`' + chr(92) + '`' * 150000 + (chr(92) + '`') * 150000, js=True)",
}


@pytest.mark.parametrize("place", sorted(PLACES))
def test_no_line_keeps_a_reader_busy(place):
    code = f"LINE = \"it's a path: \" + chr(92) * 60\n{PLACES[place]}\nprint('read')\n"
    r = _child(code)
    assert r is not None, f"{place}: still reading after 30 seconds"
    assert r.returncode == 0 and r.stdout.strip() == "read", (place, r.returncode, r.stderr[-400:])


PROJECT = {
    "requirements.txt": "flask==3.0.3\nopenai==1.30.1\n",
    "app.py": ("import os\n\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
               "@app.post('/save')\ndef save():\n    # {line}\n"
               "    os.system('convert ' + request.form['name'])\n    return 'saved'\n"),
    "helper.py": ("from openai import OpenAI\n\nclient = OpenAI()\n\n\n"
                  "def ask(question):\n    \"\"\"Ask the model.\n\n    {line}\n    \"\"\"\n"
                  "    return client.chat.completions.create(model='m', messages=[{{'role': 'user', 'content': question}}])\n"),
    "web/package.json": '{{"name": "web", "version": "1.0.0", "dependencies": {{"express": "4.19.2"}}}}\n',
    "web/server.js": ("const express = require('express');\nconst app = express();\n"
                      "app.post('/save', (req, res) => {{\n  // {line}\n  res.json({{ok: req.body.x}});\n}});\n"
                      "app.listen(3000);\n"),
    "old/page.php": "<?php\n// {line}\n$name = $_GET['name'];\necho \"<p>\" . $name . \"</p>\";\n",
}


def test_the_whole_check_ends_on_a_project_with_such_lines(tmp_path):
    src, out = tmp_path / "src", tmp_path / "out"
    for rel, text in PROJECT.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text.format(line=LINE), encoding="utf-8")
    try:
        r = subprocess.run([sys.executable, "-m", "lantern.cli", "analyze", str(src), "--offline", "--out", str(out)],
                           capture_output=True, text=True, encoding="utf-8", timeout=180)
    except subprocess.TimeoutExpired:
        pytest.fail("`lantern analyze` was still running after three minutes")
    assert r.returncode == 0, (r.returncode, r.stdout[-600:], r.stderr[-600:])
    sec = json.loads((out / "security.json").read_text(encoding="utf-8"))
    # the line hides nothing that follows it: the command built from the request, two lines below, is still found
    shell = [f for f in sec["findings"] if f["file"] == "app.py" and f["line"] == 11]
    assert shell and {f["rank"] for f in shell} & {"critical", "high"}, [(f["rule"], f["rank"]) for f in shell]


# ---------------------------------------------------------------- nothing else changed

@pytest.mark.parametrize("quotes, alphabet, longest", [("'\"", "'\"\\a\n", 8), ("'\"`", "'\"`\\a\n", 7)])
def test_every_short_text_gives_the_matches_it_gave(quotes, alphabet, longest):
    old, n = OLD_STRING[quotes], 0
    for text in _texts(alphabet, longest):
        was = _shown(old.sub, text)
        now = _shown(functools.partial(strings.sub, quotes), text)
        assert now == was, (text, was, now)
        n += 1
    assert n == sum(len(alphabet) ** k for k in range(longest + 1))


@pytest.mark.parametrize("quotes", sorted(OLD_STRING))
def test_longer_texts_give_the_matches_they_gave(quotes):
    old, n = OLD_STRING[quotes], 0
    for text in _made("'\"`\\\\\\ab =(\n", 20000, 60, 20261113):
        was = _shown(old.sub, text)
        now = _shown(functools.partial(strings.sub, quotes), text)
        assert now == was, (text, was, now)
        assert strings.sub(quotes, "''", text) == old.sub("''", text), text
        n += 1
    assert n > 15000, n


def test_every_short_template_and_block_comment_is_found_as_before():
    for text in _texts("`\\a\n", 9):
        was = _shown(OLD_TEMPLATE.sub, text, quoted=False)
        now = _shown(strings.templates, text, quoted=False)
        assert now == was, (text, was, now)
    for text in _texts("/*a\n", 9):
        was = _shown(OLD_BLOCK.sub, text, quoted=False)
        now = _shown(strings.block_comments, text, quoted=False)
        assert [(s, e, g) for s, e, g, _q, _t in now[1]] == [(s, e, g) for s, e, g, _q, _t in was[1]], text
        assert now[0] == was[0], (text, was, now)


@pytest.mark.parametrize("js, alphabet, longest", [(False, "'\"#\\a\n", 6), (True, "'`/*\\a\n", 6)])
def test_every_short_text_is_blanked_as_before(js, alphabet, longest):
    for text in _texts(alphabet, longest):
        assert websec.code_only(text, js=js) == old_code_only(text, js=js), text


CODE = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html", ".php", ".rb", ".go", ".java", ".kt", ".swift",
        ".dart", ".cs", ".rs", ".c", ".cpp", ".h")


def _own_code():
    """Lantern's own code and its samples: (path from the top, text). Lantern itself is read where Python loaded it
    from (`tests/lantern_files.py`): a release's tests run on the installed package, with the checkout's folder gone."""
    for place in [lantern_files.PACKAGE] + [ROOT / top for top in ("gateway", "cloud", "tests", "tools", "bench",
                                                                   "examples", "site")]:
        for p in sorted(place.rglob("*")):
            name = p.name[:-5] if p.name.endswith(".tmpl") else p.name
            if p.is_file() and name.endswith(CODE) and "node_modules" not in p.parts and p.stat().st_size < 400_000:
                yield lantern_files.named(p), name, p.read_text(encoding="utf-8", errors="replace")


def test_lanterns_own_code_is_read_as_before():
    files = lines = passed_over = own = 0
    for rel, name, text in _own_code():
        own += rel.startswith("lantern/")
        few = all(line.count("\\") <= FEW for line in text.split("\n"))
        if few:
            js = not name.endswith(".py")
            assert websec.code_only(text, js=js) == old_code_only(text, js=js), rel
            files += 1
        else:
            passed_over += 1
        for i, raw in enumerate(text.split("\n"), 1):
            if raw.count("\\") > FEW or len(raw) > 2000:
                continue
            for quotes, old in OLD_STRING.items():
                was = _shown(old.sub, raw)
                now = _shown(functools.partial(strings.sub, quotes), raw)
                assert now == was, (rel, i, quotes)
            assert strings.sub("'\"`", security._blank_string, raw) == \
                OLD_STRING["'\"`"].sub(security._blank_string, raw), (rel, i)
            lines += 1
    # the comparison is of most of the code, not of a corner of it
    assert files > 400 and lines > 100_000 and passed_over < files // 10, (files, lines, passed_over)
    assert own > lantern_files.FEWEST, f"{own} files of Lantern itself in {lantern_files.PACKAGE}"


WRITTEN = [
    ("x = 'a' + \"b\"", "'\"", "x = <1> + <2>"),
    ("x = 'it''s'", "'\"", "x = <1><2>"),
    ("x = 'a\\'b' # c", "'\"", "x = <1> # c"),
    ("x = 'a\\\\' + 'b'", "'\"", "x = <1> + <2>"),
    ("say('a\\", "'\"", "say('a\\"),                                  # the line ends inside the string
    ("x = 'a\\' and \"b\"", "'\"", "x = <1> and <2>"),               # no closing quote: ends at the escaped one
    ("it's `a 'b' c`", "'\"`", "it<1>b' c`"),                         # as before: the first quote that closes wins
    ("x = `a ${b} c`", "'\"`", "x = <1>"),
    ("a 'b\nc' d", "'\"", "a 'b\nc' d"),                             # a string does not go past its line
    ("", "'\"", ""),
]


@pytest.mark.parametrize("text, quotes, gives", WRITTEN)
def test_written_cases(text, quotes, gives):
    now = _shown(functools.partial(strings.sub, quotes), text)
    assert now[0] == gives, now
    assert now == _shown(OLD_STRING[quotes].sub, text)


def test_the_time_grows_with_the_text():
    # each of these took the old patterns minutes to days; a child process, so a way back to them fails and does
    # not hang the run
    code = ("import time\nfrom lantern import strings\nb = chr(92)\nstart = time.perf_counter()\n"
            "e = lambda m: ''\n"
            "for n in (1000, 100000):\n"
            "    for q in ('\\'', '\"', '`'):\n"
            "        strings.sub('\\'\"`', '', 'x = ' + q + b * (2 * n))\n"
            "        strings.sub('\\'\"`', '', ('x = ' + q + b * 40 + '\\n') * (n // 20))\n"
            "        strings.sub('\\'\"`', '', (q + b) * n)\n"
            "    strings.templates(e, '`' + (b + '`') * n)\n    strings.templates(e, ('`' + b + '\\n') * n)\n"
            "    strings.block_comments(e, '/* ' * n)\n    strings.block_comments(e, '/*/' * n)\n"
            "print(time.perf_counter() - start)\n")
    r = _child(code, limit=120)
    assert r is not None, "still reading after two minutes"
    assert r.returncode == 0 and float(r.stdout) < 60, (r.returncode, r.stdout, r.stderr[-400:])


# ---------------------------------------------------------------- the old way does not come back

def test_no_module_finds_a_string_the_old_way():
    """Two ways through one backslash in a repeated group: `(?:\\\\.|(?!\\1).)*`. A new reader of strings uses
    `lantern/strings.py`."""
    shape = re.compile(r"\(\?:\\\\\.\|\(\?!\\1\)\.\)[*+]")
    others = [p for top in ("gateway", "cloud", "tools", "bench") for p in sorted((ROOT / top).rglob("*.py"))]
    found = [f"{lantern_files.named(p)}:{i}" for p in lantern_files.modules(deep=True) + others
             for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if shape.search(line)]
    assert found == [], found
    assert shape.search(OLD_STRING["'\""].pattern)          # the shape it looks for is the old pattern's
