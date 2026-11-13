"""Code nested, or linked, deeper than a reader follows does not end the check (`lantern/deep.py`, 2026-11-13).

A reader goes through code by calling itself once per level, and Python ends a program that calls itself about a
thousand levels deep. Until this change one such piece anywhere in a project ended `lantern analyze` with "maximum
recursion depth exceeded" and no result: 69 of the 136 cases below (eleven shapes of deep code in thirteen kinds of
source file, each in a project of its own; `python tests/test_nested.py CHECKOUT` prints that table for a checkout).

Each kind of source file is given one small project here: one file per shape of deep code (`SHAPES`), the same
shapes a few levels deep beside them (the safe twins, which must be read whole and written down nowhere), a file in
which a name is written in a piece that is not read (`FORGET`), and a Flask route that hands the request to a shell.

What must hold for every kind: the check ends with a result; the route is still reported as critical; in every file
the functions after the deep one are on the map with their call, and so are the call written before the deep piece
and the one written after it; the files named as not read to the end are exactly the ones written down in `NAMED`
(so a reader that stops reading a shape it read before is seen); the log and the Evidence Report say so; and what
the reader knew about a name written in the piece is not used after it.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LIMIT = 240          # seconds for one project of deep shapes; they take a few here
LONG_LIMIT = 120     # seconds for one chain of LONG calls
LONG = 100_000

# How deep each shape goes. A reader that calls itself once per level stops between 300 and 1,000.
SHAPES = {"chain": 2000, "sum": 3000, "calls": 1500, "brackets": 1500, "elseif": 1500, "blocks": 1200,
          "lambdas": 1500, "types": 1500, "lists": 1500, "inherit": 1500, "nested": 1200}
FLAT = 4             # the safe twin of every shape


class Kind:
    def __init__(self, file, whole, stmt, link=".g()", lit='"a"', x="x", long_link=None, extra=()):
        self.file, self.whole, self.stmt, self.link, self.lit, self.x = file, whole, stmt, link, lit, x
        self.long_link = long_link or link
        self.extra = extra          # other files the project needs: (path, text)


C_LIKE = ("JavaScript", "TypeScript", "Java", "Dart", "C#", "PHP", "C++")

KINDS = {
    "Python": Kind("{s}.py",
                   "def first{S}():\n    return 1\n\n\ndef last{S}():\n    return 1\n\n\n"
                   "def f{S}(x):\n    first{S}()\n{body}\n    last{S}()\n    return x\n\n\n"
                   "def ok{S}():\n    return helper{S}()\n\n\ndef helper{S}():\n    return 1\n{more}",
                   "    y = {e}"),
    "JavaScript": Kind("{s}.js",
                       "function first{S}() {{ return 1; }}\nfunction last{S}() {{ return 1; }}\n"
                       "function f{S}(x) {{\n  first{S}();\n{body}\n  last{S}();\n  return x;\n}}\n"
                       "function ok{S}() {{ return helper{S}(); }}\nfunction helper{S}() {{ return 1; }}\n{more}",
                       "  const y = {e};", long_link="\n    .g()"),
    "TypeScript": Kind("{s}.ts",
                       "function first{S}(): number {{ return 1; }}\nfunction last{S}(): number {{ return 1; }}\n"
                       "function f{S}(x: any): any {{\n  first{S}();\n{body}\n  last{S}();\n  return x;\n}}\n"
                       "function ok{S}(): number {{ return helper{S}(); }}\n"
                       "function helper{S}(): number {{ return 1; }}\n{more}",
                       "  const y = {e};", long_link="\n    .g()"),
    "Go": Kind("{s}.go",
               "package main\n\nfunc first{S}() int {{ return 1 }}\nfunc last{S}() int {{ return 1 }}\n"
               "func f{S}(x T) any {{\n\tfirst{S}()\n{body}\n\tlast{S}()\n\treturn x\n}}\n"
               "func ok{S}() int {{ return helper{S}() }}\nfunc helper{S}() int {{ return 1 }}\n{more}",
               "\ty := {e}\n\t_ = y", link=".G()"),
    "Rust": Kind("src/{s}.rs",
                 "fn first{S}() -> i32 {{ 1 }}\nfn last{S}() -> i32 {{ 1 }}\n"
                 "fn f{S}(x: T) -> T {{\n    first{S}();\n{body}\n    last{S}();\n    return x;\n}}\n"
                 "fn ok{S}() -> i32 {{ helper{S}() }}\nfn helper{S}() -> i32 {{ 1 }}\n{more}",
                 "    let y = {e};",
                 extra=(("Cargo.toml", '[package]\nname = "deep"\nversion = "0.1.0"\n'), ("src/main.rs", "fn main() {}\n"))),
    "Java": Kind("Deep{S}.java",
                 "class Deep{S} {{\n  int first{S}() {{ return 1; }}\n  int last{S}() {{ return 1; }}\n"
                 "  Object f{S}(T x) {{\n    first{S}();\n{body}\n    last{S}();\n    return x;\n  }}\n"
                 "  int ok{S}() {{ return helper{S}(); }}\n  int helper{S}() {{ return 1; }}\n}}\n{more}",
                 "    Object y = {e};"),
    "Kotlin": Kind("Deep{S}.kt",
                   "fun first{S}(): Int {{ return 1 }}\nfun last{S}(): Int {{ return 1 }}\n"
                   "fun f{S}(x: T): Any {{\n    first{S}()\n{body}\n    last{S}()\n    return x\n}}\n"
                   "fun ok{S}(): Int {{ return helper{S}() }}\nfun helper{S}(): Int {{ return 1 }}\n{more}",
                   "    val y = {e}"),
    "Swift": Kind("Deep{S}.swift",
                  "func first{S}() -> Int {{ return 1 }}\nfunc last{S}() -> Int {{ return 1 }}\n"
                  "func f{S}(x: T) -> Any {{\n    first{S}()\n{body}\n    last{S}()\n    return x\n}}\n"
                  "func ok{S}() -> Int {{ return helper{S}() }}\nfunc helper{S}() -> Int {{ return 1 }}\n{more}",
                  "    let y = {e}"),
    "Dart": Kind("lib/{s}.dart",
                 "int first{S}() {{ return 1; }}\nint last{S}() {{ return 1; }}\n"
                 "dynamic f{S}(T x) {{\n  first{S}();\n{body}\n  last{S}();\n  return x;\n}}\n"
                 "int ok{S}() {{ return helper{S}(); }}\nint helper{S}() {{ return 1; }}\n{more}",
                 "  var y = {e};", extra=(("pubspec.yaml", "name: deep\n"),)),
    "C#": Kind("Deep{S}.cs",
               "class Deep{S} {{\n  int first{S}() {{ return 1; }}\n  int last{S}() {{ return 1; }}\n"
               "  object f{S}(T x) {{\n    first{S}();\n{body}\n    last{S}();\n    return x;\n  }}\n"
               "  int ok{S}() {{ return helper{S}(); }}\n  int helper{S}() {{ return 1; }}\n}}\n{more}",
               "    var y = {e};", link=".G()"),
    "PHP": Kind("{s}.php",
                "<?php\nfunction first{S}() {{ return 1; }}\nfunction last{S}() {{ return 1; }}\n"
                "function f{S}($x) {{\n    first{S}();\n{body}\n    last{S}();\n    return $x;\n}}\n"
                "function ok{S}() {{ return helper{S}(); }}\nfunction helper{S}() {{ return 1; }}\n{more}",
                "    $y = {e};", link="->g()", x="$x"),
    "Ruby": Kind("{s}.rb",
                 "def first{S}\n  1\nend\ndef last{S}\n  1\nend\n"
                 "def f{S}(x)\n  first{S}()\n{body}\n  last{S}()\n  return x\nend\n"
                 "def ok{S}\n  helper{S}()\nend\ndef helper{S}\n  1\nend\n{more}",
                 "  y = {e}", link=".g", lit="'a'"),
    "C++": Kind("{s}.cpp",
                "int helper{S}();\nint first{S}() {{ return 1; }}\nint last{S}() {{ return 1; }}\n"
                "int f{S}(T x) {{\n    first{S}();\n{body}\n    last{S}();\n    return 0;\n}}\n"
                "int ok{S}() {{ return helper{S}(); }}\nint helper{S}() {{ return 1; }}\n{more}",
                "    auto y = {e};", lit='std::string("a")'),
}
# One Flask route that runs what the request sends: reported as critical whatever else the project holds.
APP = ("import subprocess\n\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
       '@app.route("/run")\ndef run():\n    return subprocess.check_output(request.args["cmd"], shell=True)\n')

# A name in a piece that is not read. `keep` and `drop` each make a `Svc`, hold it in `s`, and call its `run` after a
# deep chain: `keep`'s chain hangs on `x`, `drop`'s on `s` itself. What the reader knew about `s` (that it is a
# `Svc`) may be used after the piece in `keep` and not in `drop`: the part that was not read may have given `s`
# another value. Ruby and Dart read such a chain to its end, so there is no piece to leave.
FORGET = {
    "Python": "class Svc{S}:\n    def run{S}(self):\n        return 1\n\n\n"
              "def keep{S}(x):\n    s = Svc{S}()\n    y = {dx}\n    return s.run{S}()\n\n\n"
              "def drop{S}(x):\n    s = Svc{S}()\n    y = {ds}\n    return s.run{S}()\n",
    "JavaScript": "class Svc{S} {{ run{S}() {{ return 1; }} }}\n"
                  "function keep{S}(x) {{\n  const s = new Svc{S}();\n  const y = {dx};\n  return s.run{S}();\n}}\n"
                  "function drop{S}(x) {{\n  const s = new Svc{S}();\n  const y = {ds};\n  return s.run{S}();\n}}\n",
    "TypeScript": "class Svc{S} {{ run{S}(): number {{ return 1; }} }}\n"
                  "function keep{S}(x: any): number {{\n  const s = new Svc{S}();\n  const y = {dx};\n"
                  "  return s.run{S}();\n}}\n"
                  "function drop{S}(x: any): number {{\n  const s = new Svc{S}();\n  const y = {ds};\n"
                  "  return s.run{S}();\n}}\n",
    "Go": "package main\n\ntype Svc{S} struct{{}}\n\nfunc (s Svc{S}) run{S}() int {{ return 1 }}\n\n"
          "func keep{S}(x T) int {{\n\ts := Svc{S}{{}}\n\ty := {dx}\n\t_ = y\n\treturn s.run{S}()\n}}\n\n"
          "func drop{S}(x T) int {{\n\ts := Svc{S}{{}}\n\ty := {ds}\n\t_ = y\n\treturn s.run{S}()\n}}\n",
    "Rust": "struct Svc{S};\nimpl Svc{S} {{\n    fn new() -> Svc{S} {{ Svc{S} }}\n    fn run{S}(&self) -> i32 {{ 1 }}\n}}\n"
            "fn keep{S}(x: T) -> i32 {{\n    let s = Svc{S}::new();\n    let y = {dx};\n    return s.run{S}();\n}}\n"
            "fn drop{S}(x: T) -> i32 {{\n    let s = Svc{S}::new();\n    let y = {ds};\n    return s.run{S}();\n}}\n",
    "Java": "class Svc{S} {{ int run{S}() {{ return 1; }} }}\nclass Use{S} {{\n"
            "  int keep{S}(T x) {{\n    Svc{S} s = new Svc{S}();\n    Object y = {dx};\n    return s.run{S}();\n  }}\n"
            "  int drop{S}(T x) {{\n    Svc{S} s = new Svc{S}();\n    Object y = {ds};\n    return s.run{S}();\n  }}\n}}\n",
    "Kotlin": "class Svc{S} {{ fun run{S}(): Int {{ return 1 }} }}\n"
              "fun keep{S}(x: T): Int {{\n    val s = Svc{S}()\n    val y = {dx}\n    return s.run{S}()\n}}\n"
              "fun drop{S}(x: T): Int {{\n    val s = Svc{S}()\n    val y = {ds}\n    return s.run{S}()\n}}\n",
    "Swift": "class Svc{S} {{ func run{S}() -> Int {{ return 1 }} }}\n"
             "func keep{S}(x: T) -> Int {{\n    let s = Svc{S}()\n    let y = {dx}\n    return s.run{S}()\n}}\n"
             "func drop{S}(x: T) -> Int {{\n    let s = Svc{S}()\n    let y = {ds}\n    return s.run{S}()\n}}\n",
    "C#": "class Svc{S} {{ public int run{S}() {{ return 1; }} }}\nclass Use{S} {{\n"
          "  int keep{S}(T x) {{\n    var s = new Svc{S}();\n    var y = {dx};\n    return s.run{S}();\n  }}\n"
          "  int drop{S}(T x) {{\n    var s = new Svc{S}();\n    var y = {ds};\n    return s.run{S}();\n  }}\n}}\n",
    "PHP": "<?php\nclass Svc{S} {{ function run{S}() {{ return 1; }} }}\n"
           "function keep{S}($x) {{\n    $s = new Svc{S}();\n    $y = {dx};\n    return $s->run{S}();\n}}\n"
           "function drop{S}($x) {{\n    $s = new Svc{S}();\n    $y = {ds};\n    return $s->run{S}();\n}}\n",
    "C++": "struct Svc{S} {{ int run{S}() {{ return 1; }} }};\n"
           "int keep{S}(T x) {{\n    Svc{S} s;\n    auto y = {dx};\n    return s.run{S}();\n}}\n"
           "int drop{S}(T x) {{\n    Svc{S} s;\n    auto y = {ds};\n    return s.run{S}();\n}}\n",
}
FORGET_DEEP = 2000
# How a reader says that it worked a call out from the type of what the call is made on.
BY_TYPE = {"local-type", "receiver-type"}


def _in_f(kind: str, shape: str, n: int, S: str) -> str | None:
    """The deep piece inside the function `f`, or None where this kind of file has no such shape."""
    k = KINDS[kind]
    x, st = k.x, k.stmt.format
    if shape == "chain":
        return st(e=x + k.link * n)
    if shape == "long":
        return st(e=x + k.long_link * n)
    if shape == "sum":
        return st(e=(" . " if kind == "PHP" else " + ").join([k.lit] * n))
    if shape == "calls":
        return st(e="g(" * n + x + ")" * n)
    if shape == "brackets":
        return st(e="(" * n + x + ")" * n)
    if shape == "elseif":
        if kind == "Python":
            return "    if x == 0:\n        pass\n" + "".join(f"    elif x == {i}:\n        pass\n" for i in range(1, n))
        if kind == "Ruby":
            return "  if x == 0\n    x\n" + "".join(f"  elsif x == {i}\n    x\n" for i in range(1, n)) + "  end"
        cond = f"({x} == {{i}})" if kind in C_LIKE or kind == "Kotlin" else f"{x} == {{i}}"
        return "  " + " else\n  ".join(f"if {cond.format(i=i)} {{ }}" for i in range(n))
    if shape == "blocks":
        if kind == "Python":
            n = min(n, 90)      # Python itself takes no more than a hundred levels of indentation
            return "".join(" " * (i + 4) + "if x:\n" for i in range(n)) + " " * (n + 4) + "pass"
        if kind == "Ruby":
            return "  if x\n" * n + "  x\n" + "  end\n" * n
        cond = f"({x} == 1)" if kind in C_LIKE or kind == "Kotlin" else f"{x} == 1"
        return f"  if {cond} {{\n" * n + "  }\n" * n
    if shape == "lambdas":
        e = {"Python": "lambda: " * n + x, "Go": "func() any { return " * n + x + " }" * n, "Rust": "|| " * n + x,
             "Java": "() -> " * n + x, "Kotlin": "{ " * n + x + " }" * n, "Swift": "{ " * n + x + " }" * n,
             "PHP": "fn() => " * n + x, "Ruby": "-> { " * n + x + " }" * n,
             "C++": "[=]{ return " * n + x + "; }" * n}.get(kind, "() => " * n + x)
        return st(e=e)
    if shape == "types":
        return {"Python": "    y: " + "L[" * n + "int" + "]" * n + " = x",
                "TypeScript": "  const y: " + "Array<" * n + "number" + ">" * n + " = x;",
                "Go": "\tvar y " + "[]" * n + "int\n\t_ = y",
                "Rust": "    let y: " + "Vec<" * n + "i32" + ">" * n + " = x;",
                "Java": "    " + "List<" * n + "Integer" + ">" * n + " y = x;",
                "Kotlin": "    val y: " + "List<" * n + "Int" + ">" * n + " = x",
                "Swift": "    let y: " + "[" * n + "Int" + "]" * n + " = x",
                "Dart": "  " + "List<" * n + "int" + ">" * n + " y = x;",
                "C#": "    " + "List<" * n + "int" + ">" * n + " y = x;",
                "C++": "    " + "std::vector<" * n + "int" + ">" * n + " y = x;"}.get(kind)
    if shape == "lists":
        if kind == "Kotlin":
            return None         # a Kotlin list is written with calls: the shape `calls`
        e = {"Go": "[]any{" * n + x + "}" * n, "Java": "new Object[]{" * n + x + "}" * n,
             "C#": "new object[]{" * n + x + "}" * n, "C++": "{" * n + x + "}" * n}.get(kind, "[" * n + x + "]" * n)
        return st(e=e)
    return ""                   # `inherit` and `nested` are written after the functions: nothing deep in `f`


def _after(kind: str, shape: str, n: int, S: str) -> str | None:
    """What a shape writes after the functions: a long line of classes each made from the one before (`inherit`,
    with a call in the last one to a method of the first), or declarations inside declarations (`nested`)."""
    if shape == "inherit":
        def line(first, each, last):
            return first + "".join(each.format(i=i, p=i - 1) for i in range(1, n)) + last.format(p=n - 1)
        c, m, r = f"C{S}", f"m{S}", f"run{S}"
        if kind == "Python":
            return line(f"\n\nclass {c}0:\n    def {m}(self):\n        return 1\n",
                        f"\n\nclass {c}{{i}}({c}{{p}}):\n    pass\n",
                        f"\n\nclass Last{S}({c}{{p}}):\n    def {r}(self):\n        return self.{m}()\n")
        if kind in ("JavaScript", "TypeScript"):
            return line(f"class {c}0 {{ {m}() {{ return 1; }} }}\n", f"class {c}{{i}} extends {c}{{p}} {{{{}}}}\n",
                        f"class Last{S} extends {c}{{p}} {{{{ {r}() {{{{ return this.{m}(); }}}} }}}}\n")
        if kind == "Go":
            return line(f"type {c}0 struct{{}}\nfunc (c {c}0) {m}() int {{ return 1 }}\n",
                        f"type {c}{{i}} struct{{{{ {c}{{p}} }}}}\n",
                        f"func {r}(c {c}{{p}}) int {{{{ return c.{m}() }}}}\n")
        if kind in ("Java", "Dart"):
            return line(f"class {c}0 {{ int {m}() {{ return 1; }} }}\n", f"class {c}{{i}} extends {c}{{p}} {{{{}}}}\n",
                        f"class Last{S} extends {c}{{p}} {{{{ int {r}() {{{{ return {m}(); }}}} }}}}\n")
        if kind == "Kotlin":
            return line(f"open class {c}0 {{ fun {m}(): Int {{ return 1 }} }}\n", f"open class {c}{{i}} : {c}{{p}}()\n",
                        f"class Last{S} : {c}{{p}}() {{{{ fun {r}(): Int {{{{ return {m}() }}}} }}}}\n")
        if kind == "Swift":
            return line(f"class {c}0 {{ func {m}() -> Int {{ return 1 }} }}\n", f"class {c}{{i}}: {c}{{p}} {{{{}}}}\n",
                        f"class Last{S}: {c}{{p}} {{{{ func {r}() -> Int {{{{ return {m}() }}}} }}}}\n")
        if kind == "C#":
            return line(f"class {c}0 {{ public int {m}() {{ return 1; }} }}\n", f"class {c}{{i}} : {c}{{p}} {{{{}}}}\n",
                        f"class Last{S} : {c}{{p}} {{{{ int {r}() {{{{ return {m}(); }}}} }}}}\n")
        if kind == "PHP":
            return line(f"class {c}0 {{ function {m}() {{ return 1; }} }}\n", f"class {c}{{i}} extends {c}{{p}} {{{{}}}}\n",
                        f"class Last{S} extends {c}{{p}} {{{{ function {r}() {{{{ return $this->{m}(); }}}} }}}}\n")
        if kind == "Ruby":
            return line(f"class {c}0\n  def {m}\n    1\n  end\nend\n", f"class {c}{{i}} < {c}{{p}}\nend\n",
                        f"class Last{S} < {c}{{p}}\n  def {r}\n    {m}\n  end\nend\n")
        if kind == "C++":
            return line(f"struct {c}0 {{ int {m}() {{ return 1; }} }};\n", f"struct {c}{{i}} : {c}{{p}} {{{{}}}};\n",
                        f"struct Last{S} : {c}{{p}} {{{{ int {r}() {{{{ return {m}(); }}}} }}}};\n")
        return None             # Rust has no class made from another
    if shape == "nested":
        opens = {"JavaScript": f"function n{S}() {{\n", "TypeScript": f"function n{S}() {{\n",
                 "Rust": f"mod n{S} {{\n", "Java": f"class N{S} {{\n", "Kotlin": f"class N{S} {{\n",
                 "Swift": f"struct N{S} {{\n", "Dart": f"void n{S}() {{\n", "C#": f"class N{S} {{\n",
                 "PHP": f"function n{S}() {{\n", "Ruby": f"module N{S}\n", "C++": f"namespace n{S} {{\n"}.get(kind)
        if opens is None:
            return None         # Python takes a hundred levels of indentation, Go no function inside a function
        return opens * n + ("end\n" if kind == "Ruby" else "}\n") * n
    return ""


def source(kind: str, shape: str, n: int, tag: str) -> tuple[str, str] | None:
    """(path, text) of one file: the shape `shape`, `n` deep, in a file of kind `kind`. `tag` goes into the file's
    name and into every name it defines, so files of one project do not clash. None where the kind has no such
    shape."""
    k = KINDS[kind]
    S = tag.capitalize() + shape.capitalize()
    if shape == "forget":
        if kind not in FORGET:
            return None
        s = "$s" if kind == "PHP" else "s"
        return k.file.format(s=f"{tag}_forget", S=S), FORGET[kind].format(S=S, dx=k.x + k.link * n, ds=s + k.link * n)
    body, more = _in_f(kind, shape, n, S), _after(kind, shape, n, S)
    if body is None or more is None:
        return None
    body = body or k.stmt.format(e=k.x)
    return k.file.format(s=f"{tag}_{shape}", S=S), k.whole.format(S=S, body=body, more=more)


def project(folder: Path, kind: str, shapes=None, flat: bool = True) -> dict[str, tuple[str, str]]:
    """Write the project of `kind` into `folder`: every shape and the `FORGET` file, or the `shapes` asked for.
    Gives {shape: (path of the deep file, the tag in its names)}."""
    shapes = SHAPES | {"forget": FORGET_DEEP} if shapes is None else shapes
    made = {}

    def put(rel, text):
        p = folder / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    put("app.py", APP)
    for rel, text in KINDS[kind].extra:
        put(rel, text)
    for shape, n in shapes.items():
        deep = source(kind, shape, n, "deep")
        if deep is None:
            continue
        put(*deep)
        made[shape] = (deep[0], "Deep" + shape.capitalize())
        if flat and shape != "long":
            put(*source(kind, shape, FLAT, "flat"))
    return made


def check(folder: Path, out: Path, checkout: Path = ROOT, limit: int = LIMIT) -> dict:
    """`lantern analyze` on `folder` in a process of its own, with a time limit. What it left: the result code, how
    long it took, the map, the findings, what it printed."""
    env = dict(os.environ, LANTERN_CACHE="off")      # `-m` looks in the folder it is started in first: `checkout`
    began = time.monotonic()
    try:
        r = subprocess.run([sys.executable, "-m", "lantern.cli", "analyze", str(folder), "--out", str(out), "--offline"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=limit, env=env,
                           cwd=str(checkout))
        code, said = r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired as e:
        code, said = None, f"not ended after {limit} seconds\n{e.stdout or ''}{e.stderr or ''}"
    res = {"code": code, "seconds": time.monotonic() - began, "said": said, "graph": None, "security": None}
    for name in ("graph", "security"):
        p = out / f"{name}.json"
        if code == 0 and p.is_file():
            res[name] = json.loads(p.read_text(encoding="utf-8"))
    return res


class Map:
    """What a map says, asked by the names of functions."""

    def __init__(self, graph: dict):
        self.ids: dict[str, set[str]] = {}
        for n in graph["nodes"]:
            self.ids.setdefault(n.get("name") or "", set()).add(n["id"])
        self.calls = {(e["src"], e["dst"]) for e in graph["edges"] if e.get("kind") == "calls"}
        self.links = [(e["src"], e["dst"], e.get("via") or "") for e in graph["edges"] if e.get("kind") == "calls"]
        deep = (graph.get("meta") or {}).get("too_deep") or {}
        self.named = set(deep.get("files") or [])
        self.stopped = list(deep.get("readers") or [])

    def has(self, name: str) -> bool:
        return name in self.ids

    def call(self, a: str, b: str) -> bool:
        return any((x, y) in self.calls for x in self.ids.get(a, ()) for y in self.ids.get(b, ()))

    def how(self, a: str, b: str) -> set[str]:
        """How the calls from `a` to `b` were worked out (each link's `via`)."""
        return {via for x, y, via in self.links if x in self.ids.get(a, ()) and y in self.ids.get(b, ())}


# The deep files each kind's reader names as not read to the end. Every other deep file is read whole.
_IN_F = {"chain", "sum", "calls", "brackets", "elseif", "blocks", "lambdas", "lists"}
NAMED = {
    "Python": {"chain", "sum", "calls", "brackets", "lambdas", "types", "lists", "forget"},
    "JavaScript": _IN_F | {"nested", "forget"},
    "TypeScript": _IN_F | {"nested", "forget"},
    "Go": _IN_F | {"types", "forget"},
    "Rust": _IN_F | {"types", "nested", "forget"},
    "Java": _IN_F | {"types", "nested", "forget"},
    "Kotlin": {"chain", "brackets", "nested", "forget"},
    "Swift": {"chain", "brackets", "nested", "forget"},
    "Dart": set(),
    "C#": {"chain", "brackets", "nested", "forget"},
    "PHP": {"chain", "brackets", "forget"},
    "Ruby": {"nested"},
    "C++": {"chain", "nested", "forget"},
}
# The name each kind's reader is written down under (`lantern.deep.READERS`).
READER = {"Python": "python", "JavaScript": "javascript", "TypeScript": "javascript", "Go": "go", "Rust": "rust",
          "Java": "java", "Kotlin": "kotlin", "Swift": "swift", "Dart": "dart", "C#": "csharp", "PHP": "php",
          "Ruby": "ruby", "C++": "cpp"}
# The kinds whose reader finds a method four classes up the family (Go and Kotlin do not, deep or not; Rust has no
# such family). Python and C++ find it 1,500 classes up as well.
INHERITS = {"Python", "JavaScript", "TypeScript", "Java", "Swift", "Dart", "C#", "PHP", "Ruby", "C++"}
INHERITS_FAR = {"Python", "C++"}


@pytest.fixture(scope="module", params=list(KINDS))
def ran(request, tmp_path_factory):
    """One kind's project, checked once in a process of its own: (kind, the deep files, what the check left, the
    project's folder, the results folder)."""
    kind = request.param
    d = tmp_path_factory.mktemp("nested")
    made = project(d / "p", kind)
    return kind, made, check(d / "p", d / "out"), d / "p", d / "out"


def _map(ran) -> Map:
    kind, _, res, _, _ = ran
    assert res["code"] == 0 and res["graph"] is not None, (kind, res["code"], round(res["seconds"]), res["said"][-600:])
    return Map(res["graph"])


def _twin(S: str) -> str:
    return "Flat" + S[len("Deep"):]


def test_the_check_ends_with_a_result(ran):
    _map(ran)


def test_what_else_the_project_holds_is_still_found(ran):
    kind, _, res, _, _ = ran
    _map(ran)
    shell = [f for f in res["security"]["findings"] if f.get("file") == "app.py" and f.get("rank") == "critical"]
    assert shell, (kind, [(f.get("rule"), f.get("file"), f.get("rank")) for f in res["security"]["findings"]])


def test_the_code_around_a_deep_piece_is_on_the_map(ran):
    kind, made, _, _, _ = ran
    m = _map(ran)
    missing = []
    for shape, (_, S) in made.items():
        if shape == "forget":
            continue
        for tag in (S, _twin(S)):
            for a, b in (("f", "first"), ("f", "last"), ("ok", "helper")):
                if not m.call(a + tag, b + tag):
                    missing.append(f"{a}{tag} -> {b}{tag}")
    assert not missing, (kind, missing)


def _piece(text: str, S: str) -> tuple[int, int]:
    """The first and the last line of the deep piece in a file: what stands between the calls of `first` and `last`."""
    lines = [ln.strip().rstrip(";") for ln in text.splitlines()]
    return lines.index(f"first{S}()") + 2, lines.index(f"last{S}()")


def test_exactly_the_pieces_not_read_are_written_down(ran):
    kind, made, res, folder, _ = ran
    m = _map(ran)
    want = {made[shape][0] for shape in NAMED[kind]}
    assert m.named == want, (kind, "named and not expected", sorted(m.named - want), "expected and not named",
                             sorted(want - m.named))
    assert m.stopped == [], (kind, m.stopped)            # no reader gave up on the rest of the project
    rec = res["graph"]["meta"].get("too_deep")
    if not want:
        assert rec is None, (kind, rec)                  # nothing was left out, and nothing says otherwise
        return
    assert rec["pieces"] >= len(want) and len(rec["where"]) == min(rec["pieces"], 40), (kind, rec)
    by_file = {rel: shape for shape, (rel, _) in made.items()}
    for w in rec["where"]:
        assert w["file"] in want and w["reader"] == READER[kind], (kind, w)
        shape = by_file[w["file"]]
        text = (folder / w["file"]).read_text(encoding="utf-8")
        if shape in _IN_F | {"types"}:                   # the place written down is inside the deep piece
            first, last = _piece(text, made[shape][1])
            assert first <= w["line"] <= last, (kind, w, first, last)
        else:
            assert 1 <= w["line"] <= text.count("\n") + 1, (kind, w)


def test_a_method_far_up_a_family_of_classes(ran):
    kind, made, _, _, _ = ran
    m = _map(ran)
    if "inherit" not in made:
        pytest.skip(f"{kind} has no class made from another")
    assert made["inherit"][0] not in m.named             # 1,500 classes in a line are read like four
    if kind in INHERITS:
        assert m.call("runFlatInherit", "mFlatInherit"), kind
    if kind in INHERITS_FAR:
        assert m.call("runDeepInherit", "mDeepInherit"), kind


def test_the_check_says_what_it_did_not_read(ran):
    kind, made, res, _, out = ran
    _map(ran)
    said = [ln for ln in res["said"].splitlines() if ln.startswith("deep ")]
    limits = json.loads((out / "evidence.json").read_text(encoding="utf-8"))["limits"]
    told = [x for x in limits if "nested deeper than Lantern follows" in x]
    page = (out / "evidence.html").read_text(encoding="utf-8")
    if not NAMED[kind]:
        assert not said and not told and "nested deeper than Lantern follows" not in page, (kind, said, told)
        return
    files = sorted(made[shape][0] for shape in NAMED[kind])
    rec = res["graph"]["meta"]["too_deep"]
    assert len(said) == 1 and f" {rec['pieces']} piece" in said[0], (kind, said)
    assert len(told) == 1 and f"{rec['pieces']} piece" in told[0] and f"in {len(files)} file" in told[0], (kind, told)
    for line in (said[0], told[0]):                      # the first three files by name, the rest counted
        assert sum(f in line for f in files) == min(len(files), 3), (kind, line)
        assert (f"and {len(files) - 3} more" in line) == (len(files) > 3), (kind, line)
    assert "no path leads through them" in told[0] and "nested deeper than Lantern follows" in page, kind


def test_a_name_written_in_a_piece_that_was_not_read_is_forgotten(ran):
    kind, made, _, _, _ = ran
    m = _map(ran)
    if "forget" not in made:
        pytest.skip(f"the {kind} reader reads such a chain to its end")
    # the safe twins: nothing is left out, and both calls are worked out from what `s` is
    assert m.how("keepFlatForget", "runFlatForget") & BY_TYPE and m.how("dropFlatForget", "runFlatForget") & BY_TYPE, kind
    # a name the piece does not write is known as before
    assert m.how("keepDeepForget", "runDeepForget") & BY_TYPE, (kind, m.how("keepDeepForget", "runDeepForget"))
    # a name the piece writes is not: the call after it is not worked out from what `s` was before the piece
    assert not m.how("dropDeepForget", "runDeepForget") & BY_TYPE, (kind, m.how("dropDeepForget", "runDeepForget"))


# ------------------------------------------------------------------------------- one very long line

@pytest.mark.parametrize("kind", list(KINDS))
def test_a_chain_of_a_hundred_thousand_calls_is_read_in_time(kind, tmp_path):
    """Not deep for a reader that leaves the piece, and a hundred thousand steps for one that reads it to its end:
    neither may take a step that costs more the longer the chain is (the Ruby reader took each call's whole chain
    as text: not through after four minutes)."""
    made = project(tmp_path / "p", kind, {"long": LONG}, flat=False)
    res = check(tmp_path / "p", tmp_path / "out", limit=LONG_LIMIT)
    assert res["code"] == 0 and res["graph"] is not None, (kind, res["code"], round(res["seconds"]), res["said"][-400:])
    m, S = Map(res["graph"]), made["long"][1]
    assert m.stopped == [], (kind, m.stopped)
    for a, b in (("f", "first"), ("f", "last"), ("ok", "helper")):
        assert m.call(a + S, b + S), (kind, a, b)


# ------------------------------------------------------------------------------- what is written down

def test_what_was_written_down_is_read_back_whatever_its_shape():
    from lantern import deep
    nothing = (None, [], "x", {}, {"too_deep": None}, {"too_deep": 7}, {"too_deep": ["a.py"]},
               {"too_deep": {"pieces": "3", "files": ["a.py"]}}, {"too_deep": {"pieces": True, "files": ["a.py"]}},
               {"too_deep": {"pieces": -1, "files": ["a.py"]}}, {"too_deep": {"pieces": 2.0, "files": ["a.py"]}},
               {"too_deep": {"pieces": 2, "files": "a.py"}}, {"too_deep": {"pieces": 2, "files": [7, None, ["a.py"]]}},
               {"too_deep": {"pieces": 2}}, {"too_deep": {"files": ["a.py"]}},
               {"too_deep": {"pieces": 2, "files": ["a.py"], "readers": "go"}})
    for meta in nothing[:-1]:
        assert deep.read(meta) == (0, [], []) and deep.words(meta) == [] and deep.line_words(meta) == "", meta
    assert deep.read(nothing[-1]) == (2, ["a.py"], [])
    # a reader is named only by a name Lantern gives its readers
    meta = {"too_deep": {"pieces": 0, "files": [], "readers": ["go", "<b>x</b>", 7, None, "ruby"]}}
    assert deep.read(meta) == (0, [], ["go", "ruby"])
    assert [("Go" in w, "Ruby" in w) for w in deep.words(meta)] == [(True, False), (False, True)]
    assert "<b>" not in deep.line_words(meta) + "".join(deep.words(meta))
    assert deep.line_words(meta).startswith("the reading of the project's Go and Ruby code stopped before it was through")


def test_the_words_count_and_cut_what_they_name():
    from lantern import deep
    one = {"too_deep": {"pieces": 1, "files": ["a.py"]}}
    assert deep.line_words(one) == "1 piece of code nested deeper than Lantern follows was not read to the end (a.py)"
    assert deep.words(one)[0].startswith("1 piece of code in 1 file is nested deeper than Lantern follows ")
    odd = "x" * 500 + "\n\x1b[31m.py"
    many = {"too_deep": {"pieces": 7, "files": [odd, "b.py", "c.py", "d.py", "e.py"], "readers": ["cpp"]}}
    line, words = deep.line_words(many), deep.words(many)
    assert line.startswith("7 pieces of code nested deeper than Lantern follows were not read to the end (")
    assert "b.py, c.py and 2 more)" in line and "; the reading of the project's C and C++ code stopped" in line
    assert words[0].startswith("7 pieces of code in 5 files are nested deeper") and len(words) == 2
    for text in (line, *words):                          # a file's name is cut, and nothing in it moves the line
        assert "\n" not in text and "\x1b" not in text and "x" * 121 not in text and len(text) < 700, text


def test_forty_places_are_written_down_and_the_rest_counted():
    from lantern import deep
    from lantern.graph import Graph
    g = Graph("/nowhere")
    for i in range(45):
        deep.note(g, f"f{i % 3}.py", i + 1, "python")
    rec = g.meta["too_deep"]
    assert rec["pieces"] == 45 and rec["files"] == ["f0.py", "f1.py", "f2.py"] and rec["readers"] == []
    assert len(rec["where"]) == 40 and rec["where"][0] == {"file": "f0.py", "line": 1, "reader": "python"}
    deep.stopped(g, "go")
    deep.stopped(g, "go")
    assert rec["readers"] == ["go"]


def test_a_piece_is_left_without_a_map_too():
    """A reader used with no map (a test of the reader alone) forgets the names and writes nothing down."""
    from lantern import deep

    class Piece:                                         # two names and a number, as a parser hands them over
        def __init__(self, kind, text=b"", kids=()):
            self.type, self.text, self.children, self.child_count = kind, text, list(kids), len(kids)
            self.start_point = (4, 0)
    piece = Piece("call", kids=[Piece("identifier", b"s"), Piece("number", b"1"), Piece("call", kids=[Piece("identifier", b"t")])])
    assert deep.names(piece) == {"s", "t"}
    known, own = {"s": "Svc", "u": "Other"}, {"s": "Svc", "u": "Other"}
    deep.leave(None, "a.rb", piece, known)               # a table of the names a type is known for
    deep.leave(None, "a.rb", piece, own, blank="")       # a table that also says which names are the function's own
    assert known == {"u": "Other"} and own == {"s": "", "t": "", "u": "Other"}


# ------------------------------------------------------------------------------- the nets above a piece

SMALL = {
    "app/a.py": "def a():\n    return b()\n\n\ndef b():\n    return 1\n",
    "web/w.js": "function w() { return v(); }\nfunction v() { return 1; }\n",
    "svc/go.mod": "module example.com/svc\n\ngo 1.22\n",
    "svc/main.go": "package main\n\nfunc main() { run() }\n\nfunc run() int { return 1 }\n",
    "lib/r.rb": "def r\n  q()\nend\n\ndef q\n  1\nend\n",
}


def _small(root):
    for rel, text in SMALL.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")


def _names(g, prefix):
    return {n.name for n in g.nodes.values() if n.id.startswith(prefix)}


def test_a_reader_that_stops_keeps_its_map_and_the_others_go_on(tmp_path, monkeypatch):
    """Where a reader meets deep code in a place that leaves no single piece, the reader stops, and only it."""
    from lantern import deep, engine, go_frontend
    _small(tmp_path)
    whole = engine.build_graph(tmp_path)
    assert "too_deep" not in whole.meta and {"main", "run"} <= _names(whole, "go:")

    real = go_frontend.add_go

    def stops(g, repo):
        real(g, repo)                                    # what it had read by then is on the map
        raise RecursionError("maximum recursion depth exceeded")
    monkeypatch.setattr(go_frontend, "add_go", stops)
    g = engine.build_graph(tmp_path)
    assert g.meta["too_deep"] == {"pieces": 0, "files": [], "where": [], "readers": ["go"]}
    assert {"main", "run"} <= _names(g, "go:")           # kept
    assert {"a", "b"} <= _names(g, "py:") and {"w", "v"} <= _names(g, "js:")      # the readers before it
    assert {"r", "q"} <= _names(g, "rb:")                # and the ones after it
    assert {(e.src, e.dst) for e in g.call_edges()} == {(e.src, e.dst) for e in whole.call_edges()}
    assert g.meta["files"] == whole.meta["files"] and g.meta["lines"] == whole.meta["lines"]
    words = deep.words(g.meta)
    assert len(words) == 1 and "Lantern's reading of the project's Go code stopped before it was through" in words[0]
    assert "the rest of the Go code is not" in words[0]


def test_the_whole_check_says_which_reader_stopped(tmp_path, monkeypatch):
    from lantern import pipeline, ruby_frontend
    src, out, said = tmp_path / "src", tmp_path / "out", []
    _small(src)

    def stops(g, repo):
        raise RecursionError("maximum recursion depth exceeded")
    monkeypatch.setattr(ruby_frontend, "add_ruby", stops)
    pipeline.analyze(src, out, log=said.append, offline=True)
    line = [x for x in said if x.startswith("deep ")]
    assert len(line) == 1 and "the reading of the project's Ruby code stopped before it was through" in line[0], said
    limits = json.loads((out / "evidence.json").read_text(encoding="utf-8"))["limits"]
    assert sum("Lantern's reading of the project's Ruby code stopped" in x for x in limits) == 1, limits
    graph = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    assert graph["meta"]["too_deep"]["readers"] == ["ruby"]
    assert not any(n["id"].startswith("rb:") for n in graph["nodes"])       # it had read nothing, and says so


RUBY = ("class Svc\n  def run\n    1\n  end\nend\n\n"
        "def keep(x)\n  s = Svc.new\n  y = marked(x)\n  s.run\nend\n\n"
        "def drop(x)\n  s = Svc.new\n  y = marked(s)\n  s.run\nend\n\n"
        "def after\n  helper()\nend\n\ndef helper\n  1\nend\n")


def test_the_ruby_reader_leaves_a_piece_it_cannot_follow(tmp_path, monkeypatch):
    """The Ruby reader goes through a function's code without calling itself, so none of the shapes above makes it
    leave a piece inside a function. Its net is tried with a stand-in: a look-up that cannot follow one call."""
    from lantern import engine, ruby_frontend
    (tmp_path / "svc.rb").write_text(RUBY, encoding="utf-8")

    def links(g):
        return {(e.src, e.dst, e.via) for e in g.call_edges()}
    whole = engine.build_graph(tmp_path)
    assert "too_deep" not in whole.meta
    assert {("rb:keep", "rb:Svc.run", "receiver-type"), ("rb:drop", "rb:Svc.run", "receiver-type"),
            ("rb:after", "rb:helper", "name")} <= links(whole)

    real = ruby_frontend.Linker._type_of

    def too_deep(self, recv, cls, env):
        if recv is not None and recv.text.startswith(b"marked("):
            raise RecursionError("maximum recursion depth exceeded")
        return real(self, recv, cls, env)
    monkeypatch.setattr(ruby_frontend.Linker, "_type_of", too_deep)
    g = engine.build_graph(tmp_path)
    rec = g.meta["too_deep"]
    assert rec["files"] == ["svc.rb"] and rec["pieces"] == 2 and rec["readers"] == []
    assert rec["where"] == [{"file": "svc.rb", "line": 9, "reader": "ruby"}, {"file": "svc.rb", "line": 15, "reader": "ruby"}]
    got = links(g)
    assert ("rb:keep", "rb:Svc.run", "receiver-type") in got         # `s` is not written in the piece
    assert not any(a == "rb:drop" and b == "rb:Svc.run" for a, b, _ in got)   # `s` is: what it was is not used
    assert ("rb:after", "rb:helper", "name") in got                  # the functions after it are read


def table(checkout: Path, kinds=None, shapes=SHAPES) -> None:
    """Print, for another checkout, which shapes end its check (one project per shape, so one stop hides no other)."""
    import tempfile
    for kind in kinds or KINDS:
        for shape, n in shapes.items():
            with tempfile.TemporaryDirectory() as d:
                made = project(Path(d) / "p", kind, {shape: n}, flat=False)
                if not made:
                    print(f"{kind:11} {shape:9} -", flush=True)
                    continue
                res = check(Path(d) / "p", Path(d) / "out", checkout)
                if res["graph"] is None:
                    last = [ln for ln in res["said"].splitlines() if ln.strip()][-1:] or [""]
                    print(f"{kind:11} {shape:9} STOP code={res['code']} {res['seconds']:6.1f}s | {last[0][:110]}", flush=True)
                    continue
                m, (rel, S) = Map(res["graph"]), made[shape]
                crit = sum(1 for f in res["security"]["findings"] if f.get("rank") == "critical")
                print(f"{kind:11} {shape:9} ok   {res['seconds']:6.1f}s named={rel in m.named!s:5} stopped={m.stopped} "
                      f"f={m.has('f' + S)!s:5} first={m.call('f' + S, 'first' + S)!s:5} "
                      f"last={m.call('f' + S, 'last' + S)!s:5} ok->helper={m.call('ok' + S, 'helper' + S)!s:5} "
                      f"run->m={m.call('run' + S, 'm' + S)!s:5} critical={crit}", flush=True)


if __name__ == "__main__":
    only = [a for a in sys.argv[2:] if a in KINDS]
    which = {a: (SHAPES | {"long": LONG})[a] for a in sys.argv[2:] if a in SHAPES or a == "long"}
    table(Path(sys.argv[1]).resolve(), only or None, which or SHAPES)
