"""Page templates: where a value is printed without escaping (directive point 4, 2026-11-11).

`lantern/templates.py` reads EJS, Handlebars/Mustache, Pug and Jinja-style templates. Each raw place sits beside the
escaped twin that must not be listed. None of these templates is copied from an app of the held-out benchmark."""

import pytest

from lantern import templates


def _roots(text, kind):
    return [(r.line, r.roots) for r in templates.read(text, kind)]


EJS = {
    "raw": ("<h1><%- name %></h1>\n", [(1, ("name",))]),
    "escaped": ("<h1><%= name %></h1>\n", []),
    "a member of a page value": ("<p>\n  <%- user.profile.bio %>\n</p>\n", [(2, ("user",))]),
    "an include and a layout slot are no values": ("<%- include('head', { title: title }) %>\n<%- body %>\n", []),
    "the loop's name is the list's": ("<% items.forEach(function (item) { %>\n<li><%- item.text %></li>\n<% }) %>\n",
                                      [(2, ("items",))]),
    "an arrow loop": ("<% notes.map((n) => { %><li><%- n %></li><% }) %>\n", [(1, ("notes",))]),
    "a for-of loop": ("<% for (const row of rows) { %>\n<td><%- row.html %></td>\n<% } %>\n", [(2, ("rows",))]),
    "through a function with a neutral name": ("<div><%- marked(note.text) %></div>\n", [(1, ("note",))]),
    "through a function named for escaping": ("<div><%- escapeHtml(note.text) %></div>\n", []),
    "cleaned after the neutral function": ("<div><%- sanitizeHtml(marked(note.text)) %></div>\n", []),
    "as JSON into a script": ("<script>var data = <%- JSON.stringify(data) %></script>\n", [(1, ("data",))]),
    "fixed text": ("<%- '<br>' %>\n", []),
    "trimmed tags": ("<%- title -%>\n<%- lead _%>\n", [(1, ("title",)), (2, ("lead",))]),
}
HBS = {
    "raw": ("<h1>{{{name}}}</h1>\n", [(1, ("name",))]),
    "raw, the older way": ("<h1>{{& name}}</h1>\n", [(1, ("name",))]),
    "escaped": ("<h1>{{name}}</h1>\n", []),
    "the layout's slot": ("<main>{{{body}}}</main>\n{{{_sections.head}}}\n", []),
    "inside a loop": ("{{#each comments}}\n<li>{{{this.text}}}</li>\n{{/each}}\n", [(2, ("comments",))]),
    "after the loop has ended": ("{{#each comments}}<li>{{text}}</li>{{/each}}\n<p>{{{this}}}</p>\n", []),
    "a member": ("<p>{{{ user.bio }}}</p>\n", [(1, ("user",))]),
}
PUG = {
    "raw in text": ("p Hello !{name}\n", [(1, ("name",))]),
    "escaped in text": ("p Hello #{name}\n", []),
    "raw after a tag": ("div.note!= note.html\n", [(1, ("note",))]),
    "raw on its own line": ("!= banner\n", [(1, ("banner",))]),
    "escaped after a tag": ("div.note= note.html\n", []),
    "a comparison is no output": ("if a != b\n  p different\n- var same = a!=b\n", []),
    "inside a loop": ("each c in comments\n  li!= c.text\n", [(2, ("comments",))]),
}
JINJA = {
    "marked safe": ("<h1>{{ name|safe }}</h1>\n", [(1, ("name",))]),
    "marked safe, with spaces": ("<h1>{{ user.bio | safe }}</h1>\n", [(1, ("user",))]),
    "escaped by the engine": ("<h1>{{ name }}</h1>\n", []),
    "escaped first, then marked safe": ("<h1>{{ name|escape|safe }}</h1>\n{{ data|tojson|safe }}\n", []),
    "Twig's word": ("<h1>{{ name|raw }}</h1>\n", [(1, ("name",))]),
    "escaping switched off around it":
        ("{% autoescape off %}\n<p>{{ text }}</p>\n{% endautoescape %}\n<p>{{ text }}</p>\n", [(2, ("text",))]),
    "escaping switched off, Jinja's way": ("{% autoescape false %}{{ text }}{% endautoescape %}\n", [(1, ("text",))]),
    "switched off, but this one is escaped by hand": ("{% autoescape off %}{{ text|escape }}{% endautoescape %}\n", []),
    "the loop's name is the list's":
        ("{% for c in comments %}\n<li>{{ c.text|safe }}</li>\n{% endfor %}\n", [(2, ("comments",))]),
    "a loop over pairs": ("{% for k, v in fields.items() %}{{ v|safe }}{% endfor %}\n", [(1, ("fields",))]),
    "a name set from a page value": ("{% set body = post.html %}\n{{ body|safe }}\n", [(2, ("post",))]),
    "fixed text marked safe": ("{{ '<br>'|safe }}\n", []),
    "a plain page with no template in it": ("<html><body><p>safe | raw</p></body></html>\n", []),
    "a filter with an argument before safe": ("{{ text|truncate(80)|safe }}\n", [(1, ("text",))]),
}


@pytest.mark.parametrize("kind,cases", [("ejs", EJS), ("hbs", HBS), ("pug", PUG), ("jinja", JINJA)])
def test_the_places_that_print_without_escaping(kind, cases):
    got = {name: _roots(text, kind) for name, (text, _want) in cases.items()}
    assert got == {name: want for name, (_text, want) in cases.items()}


def test_a_render_name_finds_its_file():
    paths = ["views/profile.ejs", "views/users/list.ejs", "blog/templates/blog/post.html", "shop/templates/post.html"]
    assert templates.named(paths, "profile") == ["views/profile.ejs"]
    assert templates.named(paths, "users/list") == ["views/users/list.ejs"]
    assert templates.named(paths, "blog/post.html") == ["blog/templates/blog/post.html"]
    assert templates.named(paths, "post.html") == ["blog/templates/blog/post.html", "shop/templates/post.html"]
    assert templates.named(paths, "file") == []          # not `profile`: a whole name, not its ending
    assert templates.named(paths, "") == []


def test_the_templates_of_a_project_are_listed_without_tests_and_libraries(tmp_path):
    for rel, text in {"views/a.ejs": "<%- a %>\n", "views/b.ejs": "<%= b %>\n", "tests/views/c.ejs": "<%- c %>\n",
                      "node_modules/x/views/d.ejs": "<%- d %>\n", "public/e.html": "{{ e|safe }}\n",
                      "src/app/card.component.html": "<p>{{ html | safe }}</p>\n",      # an Angular pipe
                      "app/templates/f.html": "{{ f|safe }}\n"}.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    assert sorted(templates.index(tmp_path)) == ["app/templates/f.html", "views/a.ejs"]
