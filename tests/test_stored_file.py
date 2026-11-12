"""Text a request wrote into a file, read back later and run as a template (a target carried from directive point 4).

Until this stage Lantern followed request text to the line that writes it into a file and stopped there: only a
write into the folder the template engine reads was listed, at the write. Code that reads such a file back itself
and runs what it holds (`render_template_string(f.read())`) was listed nowhere near the line where the text is run,
which is where an engineer looks for it and where the held-out benchmark documents it (found by that benchmark; none
of these files comes from it).

Now the write and the read are joined when the code's own fixed words put both files in the same place, and the
finding stands on the line that runs the text. That join is a reading of names and written path pieces, so the flow
says it is a heuristic and ranks medium. Each dangerous shape stands beside the same code made safe.
"""
import pytest

from lantern.engine import build_graph
from lantern.security import scan

FLASK = '''import os

from flask import Flask, render_template_string, request

app = Flask(__name__)
POSTS = os.path.join(os.path.dirname(__file__), "posts")


@app.post("/posts")
def save():
    name = request.form["name"]
{write}
    return "saved"


@app.get("/posts/<name>")
def show(name):
{read}
'''
WRITE = '''    with open(os.path.join(POSTS, name + ".html"), "w") as f:
        f.write(request.form["text"])'''
READ = '''    with open(os.path.join(POSTS, name + ".html")) as f:
        content = f.read()
    return render_template_string(content)'''


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _evals(root, files):
    sec = scan(build_graph(_write(root, files)), offline=True)
    return [f for f in sec["findings"] if f["rule"] == "LT-EVAL"], sec


def _line(text, needle):
    return next(i for i, line in enumerate(text.splitlines(), 1) if needle in line)


def test_text_written_to_a_file_and_run_as_a_template_is_listed_where_it_is_run(tmp_path):
    code = FLASK.format(write=WRITE, read=READ)
    found, _ = _evals(tmp_path, {"requirements.txt": "flask==3.0.0\n", "app.py": code})
    assert len(found) == 1, [(f["file"], f["line"], f["title"]) for f in found]
    f = found[0]
    assert f["line"] == _line(code, "render_template_string(content)") and f["rank"] == "medium"
    flow = f["flow"]
    assert flow["confidence"] == "LOW"                                      # the join of the two files is a reading
    lines = [s["line"] for s in flow["steps"]]
    opened = next(i for i, line in enumerate(code.splitlines(), 1) if "with open(" in line and '"w"' not in line)
    assert _line(code, 'f.write(request.form["text"])') in lines and opened in lines     # the write, then the read
    assert flow["source"]["line"] == _line(code, 'f.write(request.form["text"])')
    assert any("read back" in s["what"] for s in flow["steps"])


DANGEROUS = {
    "the write is in a helper the route calls": (
        '''    store(name, request.form["text"])''',
        READ,
        '''

def store(name, text):
    path = os.path.join(POSTS, f"{name}.html")
    with open(path, "w") as f:
        f.write(text)
'''),
    "the read is in a helper, the page is made in the route": (
        WRITE,
        '''    return render_template_string(load(name))''',
        '''

def load(name):
    with open(os.path.join(POSTS, name + ".html")) as f:
        return f.read()
'''),
    "one fixed file": (
        '''    open("data/banner.html", "w").write(request.form["text"])''',
        '''    return render_template_string(open("data/banner.html").read())''', ""),
    "paths made with pathlib": (
        '''    (FOLDER / "banner.html").write_text(request.form["text"])''',
        '''    return render_template_string((FOLDER / "banner.html").read_text())''',
        '''

from pathlib import Path
FOLDER = Path(__file__).parent / "posts"
'''),
    "paths made with pathlib, the file named by the request": (
        '''    (FOLDER / name).write_text(request.form["text"])''',
        '''    return render_template_string((FOLDER / name).read_text())''',
        '''

from pathlib import Path
FOLDER = Path(__file__).parent / "posts"
'''),
    "the folder under a name in one place and written out in the other": (
        WRITE,
        '''    with open(os.path.join(os.path.dirname(__file__), "posts", name + ".html")) as f:
        return render_template_string(f.read())''', ""),
    "the request names the file that is written, and a fixed one of the folder is run": (
        '''    with open(os.path.join(POSTS, name), "w") as f:
        f.write(request.form["text"])''',
        '''    with open(os.path.join(POSTS, "welcome.html")) as f:
        return render_template_string(f.read())''', ""),
    "the path is put together with text": (
        '''    with open("posts/" + name + ".html", "w") as f:
        f.write(request.form["text"])''',
        '''    with open(f"posts/{name}.html") as f:
        return render_template_string(f.read())''', ""),
    "text escaped for a page is still a template": (
        '''    import html
    with open(os.path.join(POSTS, name + ".html"), "w") as f:
        f.write(html.escape(request.form["text"]))''', READ, ""),
    "jinja's own Template": (
        WRITE,
        '''    from jinja2 import Template
    with open(os.path.join(POSTS, name + ".html")) as f:
        return Template(f.read()).render()''', ""),
}


# Listed before this stage, as request data run as a template, because the request names the file that is read:
# still one finding on that line, its rank as it was.
ALREADY = {"paths made with pathlib, the file named by the request": "critical"}


@pytest.mark.parametrize("case", sorted(DANGEROUS))
def test_the_ways_the_text_gets_into_the_file_and_out_again(tmp_path, case):
    write, read, more = DANGEROUS[case]
    code = FLASK.format(write=write, read=read) + more
    found, _ = _evals(tmp_path, {"requirements.txt": "flask==3.0.0\njinja2==3.1.4\n", "app.py": code})
    assert len(found) == 1 and found[0]["rank"] == ALREADY.get(case, "medium"), \
        (case, [(f["line"], f["title"], f["rank"]) for f in found])
    run = next(i for i, line in enumerate(code.splitlines(), 1) if "render_template_string(" in line and "import" not in line
               or "Template(f.read())" in line)
    assert found[0]["line"] == run, (case, found[0]["line"], run)


SAFE = {
    "nothing writes request text into a file": (
        '''    with open(os.path.join(POSTS, "log.txt"), "a") as f:
        f.write("a post was asked for\\n")''', READ, ""),
    "the request's text goes into another folder": (
        '''    with open(os.path.join(os.path.dirname(__file__), "uploads", name), "w") as f:
        f.write(request.form["text"])''',
        '''    with open(os.path.join(os.path.dirname(__file__), "mail", "welcome.html")) as f:
        return render_template_string(f.read())''', ""),
    "another fixed file of the same folder": (
        '''    open("data/notes.txt", "w").write(request.form["text"])''',
        '''    return render_template_string(open("data/banner.html").read())''', ""),
    "the file that is written cannot be the one that is run: its name ends another way": (
        '''    with open(os.path.join(POSTS, name + ".txt"), "w") as f:
        f.write(request.form["text"])''',
        '''    with open(os.path.join(POSTS, "welcome.html")) as f:
        return render_template_string(f.read())''', ""),
    "a file whose name only begins like the folder": (
        '''    with open("posts_" + name, "w") as f:
        f.write(request.form["text"])''',
        '''    with open("posts/" + name) as f:
        return render_template_string(f.read())''', ""),
    "what is written is a number": (
        '''    with open(os.path.join(POSTS, name + ".html"), "w") as f:
        f.write(str(int(request.form["text"])))''', READ, ""),
    "the file is read back and not run": (
        WRITE,
        '''    with open(os.path.join(POSTS, name + ".html")) as f:
        content = f.read()
    return render_template_string("<pre>{{ text }}</pre>", text=content)''', ""),
    "the template runs in jinja's sandbox": (
        WRITE,
        '''    from jinja2.sandbox import SandboxedEnvironment
    with open(os.path.join(POSTS, name + ".html")) as f:
        return SandboxedEnvironment().from_string(f.read()).render()''', ""),
    "the file that is read may be anywhere": (
        WRITE,
        '''    with open(request.args["file"]) as f:
        content = f.read()
    return content''', ""),
}


@pytest.mark.parametrize("case", sorted(SAFE))
def test_the_same_code_made_safe_is_not_listed(tmp_path, case):
    write, read, more = SAFE[case]
    code = FLASK.format(write=write, read=read) + more
    found, _ = _evals(tmp_path, {"requirements.txt": "flask==3.0.0\njinja2==3.1.4\n", "app.py": code})
    assert found == [], (case, [(f["line"], f["title"], f["rank"]) for f in found])


def test_one_problem_is_one_finding_when_the_file_is_in_the_templates_folder(tmp_path):
    """A write into the folder the template engine reads was listed at the write, as a reading of the path. Where
    the code itself reads the file back and runs it, that is the finding, and the write is one of its steps."""
    write = '''    with open(os.path.join("templates", "posts", name + ".html"), "w") as f:
        f.write(request.form["text"])'''
    read = '''    with open(os.path.join("templates", "posts", name + ".html")) as f:
        return render_template_string(f.read())'''
    code = FLASK.format(write=write, read=read)
    found, _ = _evals(tmp_path / "both", {"requirements.txt": "flask==3.0.0\n", "app.py": code})
    assert [f["line"] for f in found] == [_line(code, "render_template_string(f.read())")], found
    # ... and with nothing that reads it back, the write is listed as before
    only = FLASK.format(write=write, read='    return render_template("posts/" + name + ".html")').replace(
        "render_template_string", "render_template")
    found, _ = _evals(tmp_path / "write", {"requirements.txt": "flask==3.0.0\n", "app.py": only})
    assert [f["line"] for f in found] == [_line(only, 'f.write(request.form["text"])')], found


THREE = {
    "requirements.txt": "flask==3.0.0\n",
    "config.py": 'import os\n\nPOSTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "posts")\n',
    "store.py": '''import os

from config import POSTS


def keep(name, text):
    with open(os.path.join(POSTS, name + ".html"), "w") as f:
        f.write(text)
''',
    "app.py": '''import os

from flask import Flask, render_template_string, request

{load}
from store import keep

app = Flask(__name__)


@app.post("/posts")
def save():
    keep(request.form["name"], request.form["text"])
    return "saved"


@app.get("/posts/<name>")
def show(name):
    with open(os.path.join({folder}, name + ".html")) as f:
        return render_template_string(f.read())
''',
}


def test_the_write_and_the_read_in_two_files(tmp_path):
    """The folder is named once, in a third file. The same code, where the page comes from a folder of its own
    (`drafts`, which nothing writes request text into), is not listed."""
    files = dict(THREE, **{"app.py": THREE["app.py"].format(load="from config import POSTS", folder="POSTS")})
    found, _ = _evals(tmp_path / "a", files)
    assert [(f["file"], f["line"], f["rank"]) for f in found] == \
        [("app.py", _line(files["app.py"], "render_template_string(f.read())"), "medium")], found
    assert found[0]["flow"]["source"]["file"] == "app.py" and \
        any(s["file"] == "store.py" for s in found[0]["flow"]["steps"])
    # the folder loaded as `config.POSTS`
    files = dict(THREE, **{"app.py": THREE["app.py"].format(load="import config", folder="config.POSTS")})
    found, _ = _evals(tmp_path / "b", files)
    assert [f["rank"] for f in found] == ["medium"], found
    # ... and its twin
    files = dict(THREE, **{"app.py": THREE["app.py"].format(
        load='DRAFTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "drafts")', folder="DRAFTS")})
    found, _ = _evals(tmp_path / "c", files)
    assert found == [], found


def test_the_folder_of_the_codes_own_file_is_that_files_folder(tmp_path):
    """`os.path.dirname(__file__)` written in two files of one folder is one place, and in files of two folders two."""
    keep = '''import os

HERE = os.path.dirname(__file__)


def keep(name, text):
    with open(os.path.join(HERE, "posts", name + ".html"), "w") as f:
        f.write(text)
'''
    app = THREE["app.py"].format(load="", folder='os.path.dirname(__file__), "posts"').replace(
        "from store import keep", "from {mod} import keep")
    one = {"requirements.txt": "flask==3.0.0\n", "store.py": keep, "app.py": app.format(mod="store")}
    found, _ = _evals(tmp_path / "one", one)
    assert [f["rank"] for f in found] == ["medium"], found
    two = {"requirements.txt": "flask==3.0.0\n", "jobs/__init__.py": "", "jobs/store.py": keep,
           "app.py": app.format(mod="jobs.store")}
    found, _ = _evals(tmp_path / "two", two)
    assert found == [], found


EXPRESS = '''const express = require('express')
const fs = require('fs')
const path = require('path')
const ejs = require('ejs')

const app = express()
app.use(express.json())
const PAGES = path.join(__dirname, 'pages')

app.post('/pages/:name', (req, res) => {
%s
  res.json({ saved: true })
})

app.get('/pages/:name', (req, res) => {
%s
})

app.listen(3000)
'''
JS_WRITE = "  fs.writeFileSync(path.join(PAGES, req.params.name + '.ejs'), req.body.text)"
JS_READ = ("  const text = fs.readFileSync(path.join(PAGES, req.params.name + '.ejs'), 'utf8')\n"
           "  res.send(ejs.render(text, { name: req.params.name }))")
JS_OTHER = "  fs.writeFileSync(path.join(__dirname, 'notes', req.params.name + '.txt'), req.body.text)"
PKG = '{"dependencies": {"express": "^4.19.0", "ejs": "^3.1.10"}}'


def test_the_same_in_javascript_and_its_twin(tmp_path):
    code = EXPRESS % (JS_WRITE, JS_READ)
    found, _ = _evals(tmp_path / "a", {"package.json": PKG, "server.js": code})
    assert len(found) == 1 and found[0]["line"] == _line(code, "ejs.render(text") and found[0]["rank"] == "medium", found
    found, _ = _evals(tmp_path / "b", {"package.json": PKG, "server.js": EXPRESS % (JS_OTHER, JS_READ)})
    assert found == [], found
