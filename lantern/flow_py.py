"""Python files in the flow engine's small language (`lantern/flow.py`: `N`, `P`, `Fn`, `Mod`).

Read with Python's own `ast` (the file's text is handed in; nothing of the project is run or imported). A file this
Python cannot parse gives None and is counted as skipped. A call node carries the place of its opening parenthesis
(line, 1-based byte column), which is how the call inventory names a call, so the engine can ask the map where a
call goes.

Two things are left out on purpose: `assert` is not a check (Python drops it under `-O`), and a class body's own
assignments are not followed."""

from __future__ import annotations

import ast
import re
import string

from .flow import Fn, Mod, N, P

LINE_END = re.compile(r"\r\n|\r|\n")
PERCENT = re.compile(r"%(?:\((\w+)\))?[#0\- +]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[hlL]?([diouxXeEfFgGcrsa%])")
NUMBER_SPEC = re.compile(r"[bcdeEfFgGnoxX%]$")
NUMBER_CONV = set("diouxXeEfFgG")
OPS = {ast.Add: "+", ast.Mod: "%", ast.Div: "/", ast.Sub: "-", ast.Mult: "*", ast.FloorDiv: "//", ast.Pow: "**",
       ast.BitOr: "|", ast.BitAnd: "&", ast.BitXor: "^", ast.LShift: "<<", ast.RShift: ">>", ast.MatMult: "@"}
CMPS = {ast.In: "in", ast.NotIn: "not in", ast.Eq: "==", ast.NotEq: "!=", ast.Is: "is", ast.IsNot: "is not",
        ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">="}
FRAMEWORKS = (("fastapi", "fastapi"), ("starlette", "fastapi"), ("flask", "flask"), ("quart", "flask"),
              ("django", "django"), ("rest_framework", "django"))
MAX_DEPTH = 150      # expressions nested deeper than this are not read further (a generated table, a long chain)


def build(rel: str, text: str) -> Mod | None:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    try:
        return _Reader(rel, text).module(tree)
    except RecursionError:
        return None


def _src(node) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except Exception:   # noqa: BLE001  text for a person to read; a node `ast` cannot write back has none
        return None


class _Reader:
    def __init__(self, rel: str, text: str):
        self.mod = Mod(rel, "py")
        self.lines = [ln.encode("utf-8") for ln in LINE_END.split(text)]
        self.depth = 0

    # ---- the file
    def module(self, tree: ast.Module) -> Mod:
        mod = self.mod
        body = self.top_block(tree.body, None)
        mod.top = Fn("<module>", [], body, 1, end=len(self.lines))
        return mod

    def top_block(self, stmts, cls: str | None) -> list:
        """Statements at the top of the file (or inside its `if`/`try`/`with`): functions and classes become units of
        their own, plain assignments are remembered as the file's names."""
        out: list = []
        mod = self.mod
        for s in stmts:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn = self.function(s, cls, inline=False)
                mod.fns.append(fn)
                if cls is None:
                    mod.names[s.name] = fn
                continue
            if isinstance(s, ast.ClassDef):
                if cls is None:
                    mod.names.setdefault(s.name, None)
                    mod.bases[s.name] = [t for t in (_src(b) for b in s.bases) if t]
                    mod.fields[s.name] = {x.target.id: _src(x.annotation) for x in s.body
                                          if isinstance(x, ast.AnnAssign) and isinstance(x.target, ast.Name)}
                for d in s.decorator_list:
                    out.append(N("expr", d.lineno, a=self.expr(d)))
                self.top_block(s.body, s.name)      # a class body's own statements are not followed
                continue
            if cls is not None:
                continue
            if isinstance(s, (ast.Import, ast.ImportFrom)):
                for local, dotted in self.imports(s):
                    mod.imports[local] = dotted
                    for head, fw in FRAMEWORKS:
                        if dotted == head or dotted.startswith(head + "."):
                            mod.frameworks.add(fw)
                continue
            if isinstance(s, ast.If):
                out.append(N("if", s.lineno, a=self.expr(s.test), b=self.top_block(s.body, None),
                             c=self.top_block(s.orelse, None)))
                continue
            if isinstance(s, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                out.append(N("try", s.lineno, b=self.top_block(s.body, None) + self.top_block(s.orelse, None),
                             items=[(h.name, self.top_block(h.body, None)) for h in s.handlers],
                             c=self.top_block(s.finalbody, None)))
                continue
            if isinstance(s, (ast.With, ast.AsyncWith)):
                out.append(N("with", s.lineno, b=self.top_block(s.body, None),
                             items=[(self.expr(i.context_expr), self.target(i.optional_vars)
                                     if i.optional_vars is not None else None) for i in s.items]))
                continue
            one = self.stmt(s, None, set(), set())
            if one is None:
                continue
            out.append(one)
            if one.k == "assign" and one.a is not None and not one.name:
                for t in one.items:
                    if t.k == "name":
                        mod.consts.setdefault(t.name, []).append(one.a)
        return out

    @staticmethod
    def imports(s) -> list[tuple[str, str]]:
        out = []
        if isinstance(s, ast.Import):
            for a in s.names:
                out.append((a.asname or a.name.split(".")[0], a.name if a.asname else a.name.split(".")[0]))
        else:
            base = "." * (s.level or 0) + (s.module or "")
            for a in s.names:
                if a.name == "*":
                    continue
                dotted = f"{base}.{a.name}" if s.module else base + a.name
                out.append((a.asname or a.name, dotted))
        return out

    # ---- functions
    def function(self, s, cls: str | None, inline: bool) -> Fn:
        params = self.params(s.args)
        globs: set = set()
        outer: set = set()
        body = self.block(s.body, cls, globs, outer)
        first = min([d.lineno for d in s.decorator_list] + [s.lineno])
        return Fn(s.name, params, body, s.lineno, first=first, end=getattr(s, "end_lineno", None) or s.lineno,
                  decorators=[t for t in (_src(d) for d in s.decorator_list) if t], cls=cls, inline=inline,
                  outer=outer)

    def params(self, a: ast.arguments) -> list[P]:
        out: list[P] = []
        pos = list(a.posonlyargs) + list(a.args)
        defaults = [None] * (len(pos) - len(a.defaults)) + list(a.defaults)
        for arg, d in zip(pos, defaults):
            out.append(self.param(arg, d, "pos"))
        if a.vararg is not None:
            out.append(self.param(a.vararg, None, "star"))
        for arg, d in zip(a.kwonlyargs, a.kw_defaults):
            out.append(self.param(arg, d, "kw"))
        if a.kwarg is not None:
            out.append(self.param(a.kwarg, None, "kwstar"))
        return out

    def param(self, arg: ast.arg, default, kind: str) -> P:
        ann = arg.annotation
        text = _src(default)
        if text is None and isinstance(ann, ast.Subscript) and _src(ann.value) in ("Annotated", "typing.Annotated"):
            inner = ann.slice.elts[1:] if isinstance(ann.slice, ast.Tuple) else []
            call = next((x for x in inner if isinstance(x, ast.Call)), None)
            text = _src(call)       # `db: Annotated[Session, Depends(get_db)]` is handed in like a default would be
        return P(arg.arg, self.expr(default) if default is not None else None, text, _src(ann), kind)

    # ---- statements
    def block(self, stmts, cls, globs: set, outer: set) -> list:
        out = []
        for s in stmts:
            one = self.stmt(s, cls, globs, outer)
            if one is not None:
                out.append(one)
        return out

    def stmt(self, s, cls, globs: set, outer: set) -> N | None:
        line = getattr(s, "lineno", 0)
        if isinstance(s, ast.Expr):
            if isinstance(s.value, ast.Constant) and isinstance(s.value.value, str):
                return None      # a docstring
            return N("expr", line, a=self.expr(s.value))
        if isinstance(s, ast.Assign):
            node = N("assign", line, items=[self.target(t) for t in s.targets], a=self.expr(s.value))
            self.written(node, globs)
            return node
        if isinstance(s, ast.AnnAssign):
            if s.value is None:
                return None
            node = N("assign", line, items=[self.target(s.target)], a=self.expr(s.value))
            self.written(node, globs)
            return node
        if isinstance(s, ast.AugAssign):
            return N("assign", line, items=[self.target(s.target)], a=self.expr(s.value),
                     name=OPS.get(type(s.op), "?"))
        if isinstance(s, ast.Return):
            return N("return", line, a=self.expr(s.value) if s.value is not None else None)
        if isinstance(s, ast.Raise):
            return N("raise", line, a=self.expr(s.exc) if s.exc is not None else None)
        if isinstance(s, (ast.Break, ast.Continue)):
            return N("jump", line, name="break" if isinstance(s, ast.Break) else "continue")
        if isinstance(s, ast.If):
            return N("if", line, a=self.expr(s.test), b=self.block(s.body, cls, globs, outer),
                     c=self.block(s.orelse, cls, globs, outer))
        if isinstance(s, (ast.For, ast.AsyncFor)):
            return N("loop", line, items=[self.target(s.target), self.expr(s.iter), None],
                     b=self.block(s.body, cls, globs, outer), c=self.block(s.orelse, cls, globs, outer))
        if isinstance(s, ast.While):
            return N("loop", line, items=[None, None, self.expr(s.test)], b=self.block(s.body, cls, globs, outer),
                     c=self.block(s.orelse, cls, globs, outer))
        if isinstance(s, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            return N("try", line, b=self.block(s.body, cls, globs, outer) + self.block(s.orelse, cls, globs, outer),
                     items=[(h.name, self.block(h.body, cls, globs, outer)) for h in s.handlers],
                     c=self.block(s.finalbody, cls, globs, outer))
        if isinstance(s, (ast.With, ast.AsyncWith)):
            return N("with", line, b=self.block(s.body, cls, globs, outer),
                     items=[(self.expr(i.context_expr), self.target(i.optional_vars)
                             if i.optional_vars is not None else None) for i in s.items])
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return N("def", line, a=self.function(s, cls, inline=True))
        if isinstance(s, (ast.Import, ast.ImportFrom)):
            return N("import", line, kw=dict(self.imports(s)))
        if isinstance(s, ast.Global):
            globs.update(s.names)
            return None
        if isinstance(s, ast.Nonlocal):
            outer.update(s.names)
            return None
        if isinstance(s, ast.Assert):      # not a check: Python leaves asserts out under -O
            return N("expr", line, a=self.expr(s.test))
        if isinstance(s, ast.Delete):
            return None
        if hasattr(ast, "Match") and isinstance(s, ast.Match):
            subject = self.expr(s.subject)
            cases = []
            for c in s.cases:
                names = sorted({n.name for n in ast.walk(c.pattern)
                                if isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name} |
                               {n.rest for n in ast.walk(c.pattern) if isinstance(n, ast.MatchMapping) and n.rest})
                body = self.block(c.body, cls, globs, outer)
                if names:      # what a case takes out of the value holds what the value held
                    body.insert(0, N("assign", c.pattern.lineno, items=[N("name", c.pattern.lineno, name=n)
                                                                         for n in names],
                                     a=N("unk", c.pattern.lineno, items=[subject])))
                cases.append(body)
            return N("match", line, a=subject, items=cases)
        return None      # pass, a class inside a function, a type alias

    def written(self, node: N, globs: set) -> None:
        """`global x` then `x = value` inside a function: another way the file's name `x` gets a value."""
        if globs:
            for t in node.items:
                if t.k == "name" and t.name in globs:
                    self.mod.gwrites.setdefault(t.name, []).append(node.a)

    def target(self, t) -> N:
        line = getattr(t, "lineno", 0)
        if isinstance(t, ast.Name):
            return N("name", line, name=t.id)
        if isinstance(t, (ast.Tuple, ast.List)):
            return N("seq", line, items=[self.target(x) for x in t.elts])
        if isinstance(t, ast.Starred):
            return N("star", line, a=self.target(t.value))
        return self.expr(t)

    # ---- expressions
    def expr(self, e) -> N:
        self.depth += 1
        try:
            if self.depth > MAX_DEPTH:
                return N("unk", getattr(e, "lineno", 0), items=[])
            return self._expr(e)
        finally:
            self.depth -= 1

    def _expr(self, e) -> N:
        line = getattr(e, "lineno", 0)
        if isinstance(e, ast.Constant):
            return N("const", line, a=e.value)
        if isinstance(e, ast.Name):
            return N("name", line, name=e.id)
        if isinstance(e, ast.Attribute):
            return N("attr", line, a=self.expr(e.value), name=e.attr)
        if isinstance(e, ast.Call):
            return self.call(e)
        if isinstance(e, ast.JoinedStr):
            return N("str", line, items=[self.piece(v) for v in e.values])
        if isinstance(e, ast.BinOp):
            op = OPS.get(type(e.op), "?")
            if op == "%" and isinstance(e.left, (ast.Constant, ast.JoinedStr)) and \
                    (isinstance(e.left, ast.JoinedStr) or isinstance(e.left.value, str)):
                return self.percent(e)
            return N("bin", line, name=op, a=self.expr(e.left), b=self.expr(e.right))
        if isinstance(e, ast.BoolOp):
            return N("bool", line, name="and" if isinstance(e.op, ast.And) else "or",
                     items=[self.expr(v) for v in e.values])
        if isinstance(e, ast.UnaryOp):
            if isinstance(e.op, ast.Not):
                return N("not", line, a=self.expr(e.operand))
            if isinstance(e.operand, ast.Constant) and isinstance(e.operand.value, (int, float)) and \
                    not isinstance(e.operand.value, bool) and isinstance(e.op, ast.USub):
                return N("const", line, a=-e.operand.value)
            return N("arith", line, items=[self.expr(e.operand)])
        if isinstance(e, ast.Compare):
            parts = []
            left = self.expr(e.left)
            for op, right in zip(e.ops, e.comparators):
                r = self.expr(right)
                parts.append(N("cmp", line, name=CMPS.get(type(op), "?"), a=left, b=r))
                left = r
            return parts[0] if len(parts) == 1 else N("bool", line, name="and", items=parts)
        if isinstance(e, ast.IfExp):
            return N("cond", line, a=self.expr(e.test), b=self.expr(e.body), c=self.expr(e.orelse))
        if isinstance(e, (ast.List, ast.Tuple, ast.Set)):
            return N("seq", line, items=[self.expr(x) for x in e.elts])
        if isinstance(e, ast.Dict):
            return N("map", line, items=[(self.expr(k) if k is not None else None, self.expr(v))
                                         for k, v in zip(e.keys, e.values)])
        if isinstance(e, ast.Subscript):
            key = None if isinstance(e.slice, (ast.Slice, ast.Tuple)) else self.expr(e.slice)
            return N("index", line, a=self.expr(e.value), b=key)
        if isinstance(e, ast.Lambda):
            fn = Fn("<lambda>", self.params(e.args), [N("return", line, a=self.expr(e.body))], line,
                    end=getattr(e, "end_lineno", None) or line, inline=True)
            return N("fn", line, a=fn)
        if isinstance(e, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            gens = [(self.target(g.target), self.expr(g.iter), [self.expr(c) for c in g.ifs]) for g in e.generators]
            if isinstance(e, ast.DictComp):
                return N("comp", line, items=gens, a=N("unk", line, items=[self.expr(e.key), self.expr(e.value)]))
            return N("comp", line, items=gens, a=self.expr(e.elt))
        if isinstance(e, ast.Starred):
            return N("star", line, a=self.expr(e.value))
        if isinstance(e, ast.NamedExpr):
            return N("walrus", line, name=e.target.id, a=self.expr(e.value))
        if isinstance(e, (ast.Yield, ast.YieldFrom)):
            return N("yield", line, a=self.expr(e.value) if e.value is not None else None)
        if isinstance(e, ast.Await):
            return self.expr(e.value)
        if isinstance(e, ast.FormattedValue):
            return self.piece(e)
        return N("unk", line, items=[self.expr(c) for c in ast.iter_child_nodes(e) if isinstance(c, ast.expr)])

    def piece(self, v) -> N:
        """One part of an f-string. `{x:d}` and its like can only be a number."""
        if isinstance(v, ast.FormattedValue):
            inner = self.expr(v.value)
            spec = v.format_spec
            if isinstance(spec, ast.JoinedStr) and len(spec.values) == 1 and \
                    isinstance(spec.values[0], ast.Constant) and NUMBER_SPEC.search(str(spec.values[0].value)):
                return N("arith", inner.line, items=[inner])
            return inner
        return self.expr(v)

    def percent(self, e: ast.BinOp) -> N:
        """`"… %s …" % value`: the text and the values in the order they are put in."""
        line = e.lineno
        right = e.right
        if not isinstance(e.left, ast.Constant):
            return N("str", line, items=[self.expr(e.left), self.expr(right)])
        fmt = e.left.value
        if isinstance(right, ast.Tuple):
            given, named = [self.expr(x) for x in right.elts], None
        elif isinstance(right, ast.Dict) and all(isinstance(k, ast.Constant) for k in right.keys):
            given, named = None, {k.value: self.expr(v) for k, v in zip(right.keys, right.values)}
        else:
            given, named = [self.expr(right)], None
        items: list = []
        at = n = 0
        for m in PERCENT.finditer(fmt):
            items.append(N("const", line, a=fmt[at:m.start()]))
            at = m.end()
            key, conv = m.group(1), m.group(2)
            if conv == "%":
                items.append(N("const", line, a="%"))
                continue
            if key is not None and named is not None and key in named:
                val = named[key]
            elif key is None and given is not None and n < len(given):
                val = given[n]
                n += 1
            else:      # the text and the values do not line up as written: every value may be anywhere in it
                rest = given if given is not None else list((named or {}).values())
                return N("str", line, items=[N("const", line, a=fmt)] + rest)
            items.append(N("arith", line, items=[val]) if conv in NUMBER_CONV else val)
        items.append(N("const", line, a=fmt[at:]))
        return N("str", line, items=items)

    def format(self, e: ast.Call, fmt: str) -> N | None:
        """`"… {} …".format(value)`."""
        line = e.lineno
        if any(isinstance(a, ast.Starred) for a in e.args) or any(k.arg is None for k in e.keywords):
            return None
        pos = [self.expr(a) for a in e.args]
        named = {k.arg: self.expr(k.value) for k in e.keywords}
        items: list = []
        auto = 0
        try:
            fields = list(string.Formatter().parse(fmt))
        except ValueError:
            return None
        for literal, field, spec, _conv in fields:
            if literal:
                items.append(N("const", line, a=literal))
            if field is None:
                continue
            head = re.split(r"[.\[]", field, maxsplit=1)[0]
            if head == "":
                val = pos[auto] if auto < len(pos) else None
                auto += 1
            elif head.isdigit():
                val = pos[int(head)] if int(head) < len(pos) else None
            else:
                val = named.get(head)
            if val is None:
                return None
            items.append(N("arith", line, items=[val]) if spec and NUMBER_SPEC.search(spec) else val)
        return N("str", line, items=items or [N("const", line, a="")])

    def call(self, e: ast.Call) -> N:
        f = e.func
        if isinstance(f, ast.Attribute) and f.attr == "format" and isinstance(f.value, ast.Constant) and \
                isinstance(f.value.value, str):
            built = self.format(e, f.value.value)
            if built is not None:
                return built
        line, col = self.paren(f)
        kw: dict = {}
        for k in e.keywords:
            kw[k.arg if k.arg is not None else "**"] = self.expr(k.value)
        return N("call", line, col, a=self.expr(f), items=[self.expr(a) for a in e.args], kw=kw)

    def paren(self, f) -> tuple[int, int]:
        """Where the call's "(" is: the first one after the called expression ends (brackets round the expression
        itself, blanks and line breaks are passed over)."""
        ln = (getattr(f, "end_lineno", None) or getattr(f, "lineno", 1)) - 1
        col = getattr(f, "end_col_offset", None) or 0
        lines = self.lines
        for _ in range(40):
            if ln >= len(lines):
                break
            row = lines[ln]
            while col < len(row):
                ch = row[col:col + 1]
                if ch == b"(":
                    return ln + 1, col + 1
                if ch == b"#":
                    break
                if ch not in (b" ", b"\t", b")", b"\\", b"\x0c"):
                    return ln + 1, col + 1
                col += 1
            ln, col = ln + 1, 0
        return getattr(f, "end_lineno", None) or getattr(f, "lineno", 1), (getattr(f, "end_col_offset", 0) or 0) + 1
