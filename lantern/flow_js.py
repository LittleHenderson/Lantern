"""JavaScript and TypeScript files in the flow engine's small language (`lantern/flow.py`: `N`, `P`, `Fn`, `Mod`).

The files are the ones the map's own reader takes (`js_frontend.discover`: no built bundles, no `node_modules`), parsed
with the same tree-sitter grammars; the script inside an HTML page is read at its own lines. Nothing of the project
is run.

What becomes a unit of its own (a function the engine summarises, so callers in other files can use what it does):
functions and classes written at the top of a file, in whatever form (`function f`, `const f = () =>`, `exports.f =
function`, `X.prototype.f = …`, the functions of an object given to `module.exports` or to a top-level name, class
methods and fields). Every other function, a callback written inside a call or inside another function, is read where
it stands, with the names around it: that is where an Express handler written inline gets `req`."""

from __future__ import annotations

import re

from .flow import Fn, Mod, N, P

FUNCS = {"arrow_function", "function_expression", "function", "generator_function"}
FUNC_DECLS = {"function_declaration", "generator_function_declaration"}
CLASSES = {"class_declaration", "abstract_class_declaration", "class"}
SKIP_STATEMENTS = {"comment", "empty_statement", "debugger_statement", "interface_declaration", "type_alias_declaration",
                   "enum_declaration", "ambient_declaration", "import_alias", "function_signature", "hash_bang_line",
                   "html_comment"}
WRAP = {"parenthesized_expression", "await_expression", "as_expression", "satisfies_expression",
        "non_null_expression", "type_assertion", "instantiation_expression"}
EQ = {"==", "===", "!=", "!=="}
LOGIC = {"||", "&&", "??"}
ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "b": "\b", "f": "\f", "v": "\v"}
ESCAPE = re.compile(r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|u\{([0-9a-fA-F]+)\}|(\r?\n)|(.))", re.S)
MAX_DEPTH = 200


def build_all(repo, max_file: int, stats: dict):
    """Every JavaScript/TypeScript file of the project (and each page's own script) as a `Mod`."""
    from tree_sitter import Parser

    from .js_frontend import HTML_EXTS, LANGS, TEST_RE, discover, inline_script
    from .python_frontend import project_bytes
    parsers: dict = {}
    root = repo.resolve()
    for p in discover(repo):
        try:
            rel = p.relative_to(repo).as_posix()
        except ValueError:
            rel = p.resolve().relative_to(root).as_posix()
        if TEST_RE.search(rel):
            continue
        try:
            src = project_bytes(p, repo)
        except OSError:
            continue
        if len(src) > max_file:
            stats["skipped_files"] += 1
            continue
        html = p.suffix.lower() in HTML_EXTS
        if html:
            src = inline_script(src)
            if src is None:
                continue
        ext = ".js" if html else p.suffix
        if ext not in parsers:
            parsers[ext] = Parser(LANGS[ext])
        try:
            tree = parsers[ext].parse(src)
            mod = _Reader(rel, src).module(tree.root_node)
        except RecursionError:
            stats["skipped_files"] += 1
            continue
        yield mod


def _unescape(m: re.Match) -> str:
    hx, u4, ub, nl, ch = m.groups()
    if hx or u4 or ub:
        try:
            return chr(int(hx or u4 or ub, 16))
        except (ValueError, OverflowError):
            return ""
    if nl:
        return ""
    return ESCAPES.get(ch, ch)


class _Reader:
    def __init__(self, rel: str, src: bytes):
        self.mod = Mod(rel, "js")
        self.src = src
        self.depth = 0

    # ---- small helpers
    def text(self, n) -> str:
        return self.src[n.start_byte:n.end_byte].decode("utf-8", "replace") if n is not None else ""

    @staticmethod
    def line(n) -> int:
        return n.start_point[0] + 1

    @staticmethod
    def unwrap(n):
        while n is not None and n.type in WRAP and n.named_child_count:
            n = n.named_children[0]
        return n

    def string(self, n) -> str:
        raw = self.text(n)
        return ESCAPE.sub(_unescape, raw[1:-1]) if len(raw) >= 2 else ""

    # ---- the file
    def module(self, root) -> Mod:
        body = self.top_block(root.named_children)
        self.mod.top = Fn("<module>", [], body, 1, end=root.end_point[0] + 1)
        return self.mod

    def unit(self, fn_node, name: str, outer, cls: str | None = None) -> Fn:
        fn = self.function(fn_node, name, cls, inline=False, first=self.line(outer if outer is not None else fn_node))
        self.mod.fns.append(fn)
        return fn

    def top_block(self, nodes) -> list:
        out: list = []
        for s in nodes:
            out += self.top_stmt(s)
        return out

    def top_stmt(self, s) -> list:
        """One statement at the top of the file: the functions it defines become units, the rest stays code."""
        mod = self.mod
        t = s.type
        if t in SKIP_STATEMENTS:
            return []
        if t == "export_statement":
            decl = s.child_by_field_name("declaration")
            if decl is not None:
                return self.top_stmt(decl)
            val = self.unwrap(s.child_by_field_name("value"))
            if val is not None:
                if val.type in FUNCS:
                    mod.names.setdefault("default", self.unit(val, "default", s))
                    return []
                if val.type in CLASSES:
                    self.klass(val, "default")
                    return []
                if val.type == "object":
                    return [N("expr", self.line(s), a=self.top_object(val))]
                return [N("expr", self.line(s), a=self.expr(val))]
            return []      # export { a, b } / export * from
        if t in FUNC_DECLS:
            name = self.text(s.child_by_field_name("name")) or "default"
            mod.names[name] = self.unit(s, name, s)
            return []
        if t in CLASSES:
            self.klass(s, self.text(s.child_by_field_name("name")) or "default")
            return []
        if t == "import_statement":
            self.imports(s)
            return []
        if t in ("lexical_declaration", "variable_declaration"):
            out = []
            for d in s.named_children:
                if d.type != "variable_declarator":
                    continue
                name_n, val = d.child_by_field_name("name"), self.unwrap(d.child_by_field_name("value"))
                if val is None:
                    continue
                if name_n is not None and name_n.type == "identifier":
                    name = self.text(name_n)
                    if val.type in FUNCS:
                        mod.names[name] = self.unit(val, name, d)
                        continue
                    if val.type in CLASSES:
                        self.klass(val, name)
                        continue
                    spec = self.required(val)
                    if spec is not None:
                        mod.imports[name] = spec
                        continue
                    value = self.top_object(val) if val.type == "object" else self.expr(val)
                    mod.consts.setdefault(name, []).append(value)
                    out.append(N("assign", self.line(d), items=[N("name", self.line(d), name=name)], a=value))
                    continue
                spec = self.required(val)
                if spec is not None and name_n is not None and name_n.type == "object_pattern":
                    for key, local in self.pattern_names(name_n):
                        mod.imports[local] = f"{spec}.{key}" if not spec.startswith(".") else spec
                    continue
                out.append(N("assign", self.line(d), items=[self.target(name_n)], a=self.expr(val)))
            return out
        if t == "expression_statement":
            e = self.unwrap(s.named_children[0]) if s.named_child_count else None
            if e is not None and e.type == "assignment_expression":
                left, right = e.child_by_field_name("left"), self.unwrap(e.child_by_field_name("right"))
                if right is not None and left is not None and left.type in ("member_expression", "identifier"):
                    chain = self.chain(left)
                    if right.type in FUNCS and chain:
                        # exports.f = function / module.exports = function / X.prototype.f = function / X.f = …
                        cls = chain[-3] if len(chain) >= 3 and chain[-2] == "prototype" else None
                        fn = self.unit(right, chain[-1], e, cls)
                        if len(chain) == 1 or chain[0] in ("exports", "module"):
                            mod.names.setdefault(chain[-1], fn)
                        return []
                    if right.type in CLASSES and chain:
                        self.klass(right, chain[-1])
                        return []
                    if right.type == "object" and chain and chain[0] in ("exports", "module"):
                        return [N("assign", self.line(e), items=[self.expr(left)], a=self.top_object(right))]
            return [N("expr", self.line(s), a=self.expr(e))] if e is not None else []
        if t == "if_statement":
            return [N("if", self.line(s), a=self.expr(s.child_by_field_name("condition")),
                      b=self.top_branch(s.child_by_field_name("consequence")),
                      c=self.top_branch(s.child_by_field_name("alternative")))]
        if t == "statement_block":
            return self.top_block(s.named_children)
        one = self.stmt(s, None)
        return one

    def top_branch(self, n) -> list:
        if n is None:
            return []
        if n.type == "else_clause":
            return self.top_block(n.named_children)
        return self.top_stmt(n)

    def top_object(self, obj) -> N:
        """An object written at the top of a file: its functions are units (`module.exports = { list (req, res) {} }`),
        named in the object by their name."""
        items = []
        for c in obj.named_children:
            if c.type == "pair":
                key, val = c.child_by_field_name("key"), self.unwrap(c.child_by_field_name("value"))
                kname = self.key_name(key)
                if val is not None and val.type in FUNCS and kname:
                    fn = self.unit(val, kname, c)
                    self.mod.names.setdefault(kname, fn)
                    items.append((N("const", self.line(c), a=kname), N("name", self.line(c), name=kname)))
                    continue
            elif c.type == "method_definition":
                kname = self.key_name(c.child_by_field_name("name"))
                if kname:
                    fn = self.unit(c, kname, c)
                    self.mod.names.setdefault(kname, fn)
                    items.append((N("const", self.line(c), a=kname), N("name", self.line(c), name=kname)))
                    continue
            items += self.object_item(c, None)
        return N("map", self.line(obj), items=items)

    def klass(self, n, name: str) -> None:
        self.mod.names.setdefault(name, None)
        body = n.child_by_field_name("body")
        for c in (body.named_children if body is not None else ()):
            if c.type == "method_definition":
                mname = self.key_name(c.child_by_field_name("name"))
                if mname:
                    self.unit(c, mname, c, name)
            elif c.type in ("field_definition", "public_field_definition"):
                val = self.unwrap(c.child_by_field_name("value"))
                key = c.child_by_field_name("property") or c.child_by_field_name("name")
                if val is not None and val.type in FUNCS and key is not None:
                    self.unit(val, self.key_name(key) or "field", c, name)

    def required(self, n) -> str | None:
        """`require('x')` (also `require('x').y`, `await import('x')`): the module's name, as an import says it."""
        n = self.unwrap(n)
        tail = []
        while n is not None and n.type == "member_expression":
            tail.append(self.text(n.child_by_field_name("property")))
            n = self.unwrap(n.child_by_field_name("object"))
        if n is None or n.type != "call_expression":
            return None
        f = n.child_by_field_name("function")
        args = n.child_by_field_name("arguments")
        if f is None or args is None or self.text(f) not in ("require", "import") or args.named_child_count != 1 \
                or args.named_children[0].type != "string":
            return None
        spec = self.spec(self.string(args.named_children[0]))
        if spec.startswith("."):
            return spec
        return ".".join([spec] + list(reversed(tail)))

    @staticmethod
    def spec(s: str) -> str:
        if s.startswith("node:"):
            s = s[5:]
        return s if not s.startswith(("/", "@/", "~/", "#")) else "./" + s.lstrip("/@~#")

    def imports(self, s) -> None:
        src = s.child_by_field_name("source")
        if src is None:
            return
        spec = self.spec(self.string(src))
        lib = not spec.startswith(".")
        mod = self.mod
        for c in s.named_children:
            if c.type != "import_clause":
                continue
            for x in c.named_children:
                if x.type == "identifier":                       # import axios from 'axios'
                    mod.imports[self.text(x)] = spec
                elif x.type == "namespace_import":               # import * as fs from 'fs'
                    for y in x.named_children:
                        if y.type == "identifier":
                            mod.imports[self.text(y)] = spec
                elif x.type == "named_imports":
                    for y in x.named_children:
                        if y.type != "import_specifier":
                            continue
                        name = self.text(y.child_by_field_name("name"))
                        alias = self.text(y.child_by_field_name("alias")) or name
                        mod.imports[alias] = f"{spec}.{name}" if lib else spec

    def chain(self, n) -> list[str]:
        """`a.b.c` as ["a", "b", "c"], or [] when it is anything else."""
        out = []
        n = self.unwrap(n)
        while n is not None and n.type == "member_expression":
            out.append(self.text(n.child_by_field_name("property")))
            n = self.unwrap(n.child_by_field_name("object"))
        if n is None or n.type not in ("identifier", "this"):
            return []
        out.append(self.text(n))
        return list(reversed(out))

    def key_name(self, k) -> str | None:
        if k is None:
            return None
        if k.type in ("property_identifier", "identifier", "private_property_identifier",
                      "shorthand_property_identifier", "shorthand_property_identifier_pattern"):
            return self.text(k)
        if k.type == "string":
            return self.string(k)
        if k.type == "number":
            return self.text(k)
        return None

    def pattern_names(self, pat) -> list[tuple[str, str]]:
        """(key, local name) for each plain name an object pattern takes out."""
        out = []
        for c in pat.named_children:
            if c.type == "shorthand_property_identifier_pattern":
                out.append((self.text(c), self.text(c)))
            elif c.type == "pair_pattern":
                key, val = self.key_name(c.child_by_field_name("key")), c.child_by_field_name("value")
                if key and val is not None and val.type == "identifier":
                    out.append((key, self.text(val)))
            elif c.type == "object_assignment_pattern":
                left = c.child_by_field_name("left")
                if left is not None and left.type == "shorthand_property_identifier_pattern":
                    out.append((self.text(left), self.text(left)))
        return out

    # ---- functions
    def function(self, n, name: str, cls: str | None, inline: bool, first: int | None = None) -> Fn:
        params_n = n.child_by_field_name("parameters")
        if params_n is None:
            one = n.child_by_field_name("parameter")
            params = [P(self.text(one))] if one is not None else []
        else:
            params = [p for p in (self.param(c) for c in params_n.named_children) if p is not None]
        body_n = n.child_by_field_name("body")
        if body_n is None:
            body = []
        elif body_n.type == "statement_block":
            body = self.block(body_n.named_children, cls)
        else:                                                  # an arrow function whose body is one expression
            body = [N("return", self.line(body_n), a=self.expr(body_n))]
        decorators = [self.text(c) for c in n.children if c.type == "decorator"]
        return Fn(name, params, body, self.line(n), first=first or self.line(n), end=n.end_point[0] + 1,
                  decorators=decorators, cls=cls, inline=inline)

    def param(self, c) -> P | None:
        t = c.type
        text = ann = default = None
        if t in ("required_parameter", "optional_parameter"):      # TypeScript
            ty = c.child_by_field_name("type")
            ann = self.text(ty).lstrip(": ").strip() if ty is not None else None
            dec = next((self.text(x) for x in c.children if x.type == "decorator"), None)
            val = c.child_by_field_name("value")
            if val is not None:
                default = self.expr(val)
            text = dec or (self.text(val) if val is not None else None)
            c = c.child_by_field_name("pattern") or (c.named_children[0] if c.named_child_count else None)
            if c is None:
                return None
            t = c.type
        if t == "comment" or t == "decorator":
            return None
        if t == "assignment_pattern":
            left, right = c.child_by_field_name("left"), c.child_by_field_name("right")
            default = self.expr(right) if right is not None else None
            text = self.text(right) if right is not None else None
            c = left
            t = c.type if c is not None else ""
        if c is None:
            return None
        if t in ("identifier", "this"):
            return P(self.text(c), default, text, ann)
        if t == "rest_pattern":
            inner = c.named_children[0] if c.named_child_count else None
            return P(self.text(inner) if inner is not None else "rest", None, None, ann, "star")
        if t in ("object_pattern", "array_pattern"):
            return P("", default, text, ann, "pos", self.target(c))
        return P(self.text(c), default, text, ann)

    # ---- statements
    def block(self, nodes, cls) -> list:
        out: list = []
        later: list = []
        for s in nodes:
            if s.type in FUNC_DECLS:        # a function written in a block can be called above the line it is on
                out += self.stmt(s, cls)
            else:
                later += self.stmt(s, cls)
        return out + later

    def body(self, n, cls) -> list:
        if n is None:
            return []
        if n.type == "statement_block":
            return self.block(n.named_children, cls)
        if n.type == "else_clause":
            return self.block(n.named_children, cls) if not (n.named_child_count == 1 and
                                                             n.named_children[0].type == "statement_block") \
                else self.block(n.named_children[0].named_children, cls)
        return self.stmt(n, cls)

    def stmt(self, s, cls) -> list:
        t = s.type
        ln = self.line(s)
        if t in SKIP_STATEMENTS:
            return []
        if t == "expression_statement":
            return [N("expr", ln, a=self.expr(c, cls)) for c in s.named_children if c.type != "comment"]
        if t in ("lexical_declaration", "variable_declaration"):
            out = []
            for d in s.named_children:
                if d.type != "variable_declarator":
                    continue
                name_n, val = d.child_by_field_name("name"), d.child_by_field_name("value")
                if val is None or name_n is None:
                    continue
                out.append(N("assign", self.line(d), items=[self.target(name_n, cls)], a=self.expr(val, cls)))
            return out
        if t in FUNC_DECLS:
            name = self.text(s.child_by_field_name("name")) or "fn"
            return [N("def", ln, a=self.function(s, name, cls, inline=True))]
        if t == "return_statement":
            val = next((c for c in s.named_children if c.type != "comment"), None)
            return [N("return", ln, a=self.expr(val, cls) if val is not None else None)]
        if t == "throw_statement":
            val = s.named_children[0] if s.named_child_count else None
            return [N("raise", ln, a=self.expr(val, cls) if val is not None else None)]
        if t in ("break_statement", "continue_statement"):
            return [N("jump", ln, name="break" if t == "break_statement" else "continue")]
        if t == "if_statement":
            return [N("if", ln, a=self.expr(s.child_by_field_name("condition"), cls),
                      b=self.body(s.child_by_field_name("consequence"), cls),
                      c=self.body(s.child_by_field_name("alternative"), cls))]
        if t == "for_in_statement":
            left, right = s.child_by_field_name("left"), s.child_by_field_name("right")
            return [N("loop", ln, items=[self.target(left, cls) if left is not None else None,
                                         self.expr(right, cls) if right is not None else None, None],
                      b=self.body(s.child_by_field_name("body"), cls), c=[])]
        if t == "for_statement":
            init, cond, inc = (s.child_by_field_name(k) for k in ("initializer", "condition", "increment"))
            out = self.stmt(init, cls) if init is not None else []
            body = self.body(s.child_by_field_name("body"), cls)
            if inc is not None:
                body = body + [N("expr", self.line(inc), a=self.expr(inc, cls))]
            test = None
            if cond is not None and cond.type != "empty_statement":
                test = self.expr(cond.named_children[0] if cond.type == "expression_statement" and
                                 cond.named_child_count else cond, cls)
            return out + [N("loop", ln, items=[None, None, test], b=body, c=[])]
        if t in ("while_statement", "do_statement"):
            return [N("loop", ln, items=[None, None, self.expr(s.child_by_field_name("condition"), cls)],
                      b=self.body(s.child_by_field_name("body"), cls), c=[])]
        if t == "try_statement":
            handlers = []
            h = s.child_by_field_name("handler")
            if h is not None:
                par = h.child_by_field_name("parameter")
                handlers.append((self.text(par) if par is not None and par.type == "identifier" else None,
                                 self.body(h.child_by_field_name("body"), cls)))
            fin = s.child_by_field_name("finalizer")
            return [N("try", ln, b=self.body(s.child_by_field_name("body"), cls), items=handlers,
                      c=self.body(fin.child_by_field_name("body"), cls) if fin is not None else [])]
        if t == "switch_statement":
            value = self.expr(s.child_by_field_name("value"), cls)
            cases = []
            sb = s.child_by_field_name("body")
            for c in (sb.named_children if sb is not None else ()):
                if c.type in ("switch_case", "switch_default"):
                    val = c.child_by_field_name("value")
                    cases.append(self.block([x for x in c.named_children if val is None or x.id != val.id], cls))
            return [N("match", ln, a=value, items=cases)]
        if t == "statement_block":
            return self.block(s.named_children, cls)
        if t == "labeled_statement":
            inner = s.child_by_field_name("body") or (s.named_children[-1] if s.named_child_count else None)
            return self.stmt(inner, cls) if inner is not None else []
        if t == "export_statement":
            decl = s.child_by_field_name("declaration")
            return self.stmt(decl, cls) if decl is not None else []
        if t in CLASSES or t == "import_statement":
            return []
        if t == "with_statement":
            return self.body(s.child_by_field_name("body"), cls)
        return [N("expr", ln, a=self.expr(s, cls))]      # an expression where a statement stands

    def target(self, n, cls=None) -> N:
        n = self.unwrap(n)
        if n is None:
            return N("unk", 0, items=[])
        t = n.type
        ln = self.line(n)
        if t in ("identifier", "shorthand_property_identifier_pattern"):
            return N("name", ln, name=self.text(n))
        if t in ("lexical_declaration", "variable_declaration"):      # for (const x of xs)
            d = next((c for c in n.named_children if c.type == "variable_declarator"), None)
            return self.target(d.child_by_field_name("name"), cls) if d is not None else N("unk", ln, items=[])
        if t == "object_pattern":
            items = []
            for c in n.named_children:
                if c.type == "shorthand_property_identifier_pattern":
                    items.append((N("const", ln, a=self.text(c)), N("name", self.line(c), name=self.text(c))))
                elif c.type == "pair_pattern":
                    key = c.child_by_field_name("key")
                    kname = self.key_name(key)
                    val = c.child_by_field_name("value")
                    items.append((N("const", ln, a=kname) if kname is not None else self.expr(key, cls),
                                  self.target(val, cls)))
                elif c.type == "object_assignment_pattern":
                    left = c.child_by_field_name("left")
                    if left is not None:
                        items.append((N("const", ln, a=self.text(left)), self.target(left, cls)))
                elif c.type == "rest_pattern" and c.named_child_count:
                    items.append((None, self.target(c.named_children[0], cls)))
            return N("map", ln, items=items)
        if t == "array_pattern":
            return N("seq", ln, items=[self.target(c, cls) for c in n.named_children if c.type != "comment"])
        if t == "assignment_pattern":
            return self.target(n.child_by_field_name("left"), cls)
        if t == "rest_pattern":
            return N("star", ln, a=self.target(n.named_children[0], cls)) if n.named_child_count else \
                N("unk", ln, items=[])
        return self.expr(n, cls)

    # ---- expressions
    def expr(self, n, cls=None) -> N:
        self.depth += 1
        try:
            if n is None or self.depth > MAX_DEPTH:
                return N("unk", self.line(n) if n is not None else 0, items=[])
            return self._expr(n, cls)
        finally:
            self.depth -= 1

    def _expr(self, n, cls) -> N:
        t = n.type
        ln = self.line(n)
        if t in WRAP:
            inner = n.named_children[0] if n.named_child_count else None
            return self.expr(inner, cls)
        if t in ("identifier", "this", "super", "property_identifier", "shorthand_property_identifier", "undefined"):
            if t == "undefined":
                return N("const", ln, a=None)
            return N("name", ln, name=self.text(n))
        if t == "string":
            return N("const", ln, a=self.string(n))
        if t == "template_string":
            return N("str", ln, items=self.template(n, cls))
        if t == "number":
            return N("const", ln, a=self.number(self.text(n)))
        if t in ("true", "false"):
            return N("const", ln, a=t == "true")
        if t == "null":
            return N("const", ln, a=None)
        if t == "regex":
            pat, flags = n.child_by_field_name("pattern"), n.child_by_field_name("flags")
            if flags is not None and "m" in self.text(flags):      # with /m, ^ and $ bound a line, not the value
                return N("unk", ln, items=[])
            return N("regex", ln, a=self.text(pat))
        if t == "member_expression":
            return N("attr", ln, a=self.expr(n.child_by_field_name("object"), cls),
                     name=self.text(n.child_by_field_name("property")).lstrip("#"))
        if t == "subscript_expression":
            return N("index", ln, a=self.expr(n.child_by_field_name("object"), cls),
                     b=self.expr(n.child_by_field_name("index"), cls))
        if t in ("call_expression", "new_expression"):
            return self.call(n, cls)
        if t == "binary_expression":
            op = self.text(n.child_by_field_name("operator"))
            a, b = self.expr(n.child_by_field_name("left"), cls), self.expr(n.child_by_field_name("right"), cls)
            if op in ("||", "&&"):
                return N("bool", ln, name=op, items=[a, b])
            if op == "+" or op in LOGIC:
                return N("bin", ln, name=op, a=a, b=b)
            if op in EQ or op == "in":
                return N("cmp", ln, name=op, a=a, b=b)
            if op in ("<", ">", "<=", ">=", "instanceof"):
                return N("cmp", ln, name=op, a=a, b=b)
            return N("arith", ln, items=[a, b])
        if t == "unary_expression":
            op = self.text(n.child_by_field_name("operator"))
            arg = self.expr(n.child_by_field_name("argument"), cls)
            if op == "!":
                return N("not", ln, a=arg)
            if op == "typeof":
                return N("typeof", ln, a=arg)
            if op in ("-", "+", "~"):
                if arg.k == "const" and isinstance(arg.a, (int, float)) and not isinstance(arg.a, bool) and op == "-":
                    return N("const", ln, a=-arg.a)
                return N("arith", ln, items=[arg])
            return N("unk", ln, items=[arg])
        if t == "update_expression":
            return N("arith", ln, items=[self.expr(n.child_by_field_name("argument"), cls)])
        if t == "assignment_expression":
            return N("assign", ln, items=[self.target(n.child_by_field_name("left"), cls)],
                     a=self.expr(n.child_by_field_name("right"), cls))
        if t == "augmented_assignment_expression":
            op = self.text(n.child_by_field_name("operator")).rstrip("=")
            return N("assign", ln, items=[self.target(n.child_by_field_name("left"), cls)],
                     a=self.expr(n.child_by_field_name("right"), cls), name=op or "?")
        if t == "ternary_expression":
            return N("cond", ln, a=self.expr(n.child_by_field_name("condition"), cls),
                     b=self.expr(n.child_by_field_name("consequence"), cls),
                     c=self.expr(n.child_by_field_name("alternative"), cls))
        if t == "sequence_expression":
            return N("unk", ln, items=[self.expr(c, cls) for c in n.named_children])
        if t == "object":
            items = []
            for c in n.named_children:
                items += self.object_item(c, cls)
            return N("map", ln, items=items)
        if t == "array":
            return N("seq", ln, items=[self.expr(c, cls) for c in n.named_children if c.type != "comment"])
        if t in FUNCS:
            name = self.text(n.child_by_field_name("name")) or "<fn>"
            return N("fn", ln, a=self.function(n, name, cls, inline=True))
        if t == "spread_element":
            return N("star", ln, a=self.expr(n.named_children[0], cls)) if n.named_child_count else \
                N("unk", ln, items=[])
        if t == "yield_expression":
            return N("yield", ln, a=self.expr(n.named_children[0], cls) if n.named_child_count else None)
        if t.startswith("jsx_"):
            return self.jsx(n, cls)
        if t in CLASSES:
            return N("unk", ln, items=[])
        # anything else (a type, a meta property, an error node): what it holds is looked at, nothing more is said
        return N("unk", ln, items=[self.expr(c, cls) for c in n.named_children
                                   if c.type not in ("comment", "type_annotation", "type_arguments")])

    @staticmethod
    def number(s: str):
        s = s.replace("_", "")
        try:
            return int(s, 0) if not re.search(r"[.eE]", s) or s.lower().startswith("0x") else float(s)
        except ValueError:
            try:
                return float(s)
            except ValueError:
                return 0

    def template(self, n, cls) -> list:
        """A template string: its text and the values put into it, in order."""
        items = []
        at = n.start_byte + 1
        for c in n.children:
            if c.type == "template_substitution":
                lit = self.src[at:c.start_byte].decode("utf-8", "replace")
                if lit:
                    items.append(N("const", self.line(n), a=ESCAPE.sub(_unescape, lit)))
                inner = c.named_children[0] if c.named_child_count else None
                items.append(self.expr(inner, cls))
                at = c.end_byte
        lit = self.src[at:max(at, n.end_byte - 1)].decode("utf-8", "replace")
        if lit or not items:
            items.append(N("const", self.line(n), a=ESCAPE.sub(_unescape, lit)))
        return items

    def object_item(self, c, cls) -> list:
        ln = self.line(c)
        t = c.type
        if t == "pair":
            key, val = c.child_by_field_name("key"), c.child_by_field_name("value")
            kname = self.key_name(key)
            k = N("const", ln, a=kname) if kname is not None else \
                self.expr(key.named_children[0] if key is not None and key.named_child_count else key, cls)
            return [(k, self.expr(val, cls))]
        if t == "shorthand_property_identifier":
            return [(N("const", ln, a=self.text(c)), N("name", ln, name=self.text(c)))]
        if t == "spread_element":
            return [(None, self.expr(c.named_children[0], cls))] if c.named_child_count else []
        if t == "method_definition":
            kname = self.key_name(c.child_by_field_name("name")) or "method"
            return [(N("const", ln, a=kname), N("fn", ln, a=self.function(c, kname, cls, inline=True)))]
        return []

    def call(self, n, cls) -> N:
        new = n.type == "new_expression"
        f = n.child_by_field_name("constructor" if new else "function")
        args = n.child_by_field_name("arguments")
        at = args if args is not None else n
        ln, col = at.start_point[0] + 1, at.start_point[1] + 1
        fx = self.expr(f, cls)
        if args is not None and args.type == "template_string":
            # a tagged template: the tag gets the fixed pieces of text apart from the values
            parts = self.template(args, cls)
            items = [N("seq", ln, items=[p for p in parts if p.k == "const"])] + [p for p in parts if p.k != "const"]
        else:
            items = [self.expr(c, cls) for c in (args.named_children if args is not None else ())
                     if c.type != "comment"]
        return N("call", ln, col, a=fx, items=items, kw=None, name="new" if new else None)

    def jsx(self, n, cls) -> N:
        """JSX: React escapes what stands between tags and in attributes; only `dangerouslySetInnerHTML` is raw HTML."""
        ln = self.line(n)
        out = []
        stack = [n]
        while stack:
            c = stack.pop()
            t = c.type
            if t == "jsx_attribute":
                name = c.named_children[0] if c.named_child_count else None
                val = c.named_children[1] if c.named_child_count > 1 else None
                if name is not None and self.text(name) == "dangerouslySetInnerHTML" and val is not None:
                    inner = self.unwrap(val.named_children[0]) if val.type == "jsx_expression" and \
                        val.named_child_count else None
                    html = None
                    if inner is not None and inner.type == "object":
                        for p in inner.named_children:
                            if p.type == "pair" and self.key_name(p.child_by_field_name("key")) == "__html":
                                html = self.expr(p.child_by_field_name("value"), cls)
                    elif inner is not None:
                        html = N("attr", self.line(inner), a=self.expr(inner, cls), name="__html")
                    if html is not None:
                        out.append(N("call", self.line(c), c.start_point[1] + 1,
                                     a=N("name", self.line(c), name="dangerouslySetInnerHTML"), items=[html]))
                    continue
                if val is not None:
                    stack.append(val)
                continue
            if t == "jsx_expression":
                if c.named_child_count:
                    out.append(self.expr(c.named_children[0], cls))
                continue
            stack.extend(c.named_children)
        return N("unk", ln, items=out)
