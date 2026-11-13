"""The map as a report holds it: column by column (directive point 10, 2026-11-12).

A report is one file that has to open on a phone, and most of the time a phone needs to open a large one is the time
it needs to take the file in. The map was most of the file: every node and every link written as a table of its own,
with the name of every field in it, and every link naming its two functions by their full ids. For Django that was
52 of 74 MB.

`pack_graph(graph)` writes the same map another way, and only inside a report (`report.render`; `graph.json` and
every other result file are as they were):

    nodes, edges    {"keys": [the fields, in the rows' own order], "n": how many rows, "cols": [one column a field]}
    a column        ["v", [the value of every row]]                 as it is
                    ["c", value]                                    every row has this one value
                    ["t", [values], [which of them, row by row]]    few different values, each written once
                    ["r", [where, row by row]]                      the id of a node, written as that node's place in
                                                                    the list of nodes; a value that is no such id
                                                                    stands in a list of its own: `["ext:os.path"]`
    packed          1                                               the last entry of the map: how it is written
    as_it_was       a map that came with an entry `packed` of its own (none Lantern writes has one) is not packed:
                    it stands whole under this name, beside `packed`, so it too comes back as it went in

`unpack_graph(packed)` gives back exactly what went in: the same rows, the fields in the same order, every value of
the same kind (`1`, `1.0` and `true` stay three things), every list and table a row's own. The page does the same
with its `unpackGraph` (viewer/report.html), before anything else looks at the map, and `report.read_bundle` does it
for every reader in Python, so nothing but those two places knows how a report is written.

Rows are packed only when all of them are tables with the same fields in the same order; a list of anything else is
written as it is. Only plain values (text, numbers, yes/no,
nothing) are written once for many rows: a list or a table always stands in its own row, so turning a packed map
back makes no more of anything than the file itself holds. A packed map of any other shape is refused with
`ValueError` (it was not written by this Lantern), and a count of rows is believed only where a column has that many
entries.
"""
from __future__ import annotations

FORM = 1
MARK = "packed"
WHOLE = "as_it_was"
ROWS = ("nodes", "edges")
REFER = {"nodes": ("parent",), "edges": ("src", "dst")}     # the fields that mostly hold the id of a node
NOT_A_FIELD = "__proto__"                                   # a field of this name is no entry of a table in a page
NOT_OURS = "this report's map is not written the way this Lantern writes it; analyze again"
_PLAIN = (str, int, float, bool, type(None))


def _same(v):
    """What tells two plain values apart: `1`, `1.0` and `True` are equal in Python and are three values here, and
    so are `0.0` and `-0.0`."""
    return (type(v), repr(v)) if type(v) is float else (type(v), v)


def _digits(i: int) -> int:
    return len(str(i))


def _size(v) -> int:
    """About how long a plain value is when written."""
    return len(v) + 2 if type(v) is str else 5


def _column(values: list, ids: dict | None, refer: bool) -> list:
    if refer and ids:
        at = [ids.get(v) if type(v) is str else None for v in values]
        if sum(i is not None for i in at) * 2 >= len(values):
            return ["r", [i if i is not None else [v] for i, v in zip(at, values)]]
    if not all(type(v) in _PLAIN for v in values):
        return ["v", list(values)]
    seen: dict = {}
    for v in values:
        k = _same(v)
        if k in seen:
            seen[k][1] += 1
        else:
            seen[k] = [v, 1]
    if len(seen) == 1:
        return ["c", values[0]]
    if len(seen) * 2 > len(values):
        return ["v", list(values)]
    order = sorted(seen.items(), key=lambda kv: -kv[1][1])           # the most common first (a stable sort)
    plain = sum((_size(v) + 1) * n for _, (v, n) in order)
    table = sum(_size(v) + 1 + (_digits(i) + 1) * n for i, (_, (v, n)) in enumerate(order))
    if table >= plain:
        return ["v", list(values)]
    place = {k: i for i, (k, _) in enumerate(order)}
    return ["t", [v for _, (v, _) in order], [place[_same(v)] for v in values]]


def pack_rows(rows, ids: dict | None = None, refer: tuple = ()):
    """The rows column by column, or the rows as they are when they cannot be written that way."""
    if type(rows) is not list or not rows or type(rows[0]) is not dict:
        return rows
    keys = list(rows[0])
    if not keys or NOT_A_FIELD in keys or not all(type(k) is str for k in keys):
        return rows
    for row in rows:
        if type(row) is not dict or list(row) != keys:
            return rows
    cols = [_column([row[k] for row in rows], ids, k in refer) for k in keys]
    if all(c[0] == "c" for c in cols):      # a count is believed only where a column has that many entries
        cols[0] = ["v", [row[keys[0]] for row in rows]]
    return {"keys": keys, "n": len(rows), "cols": cols}


def _ids(nodes) -> tuple[list, dict]:
    """The id of every node in the order of the list (None where a node has none that is text), and each id's
    first place."""
    listed = [row.get("id") if type(row) is dict and type(row.get("id")) is str else None
              for row in (nodes if type(nodes) is list else [])]
    first: dict = {}
    for i, v in enumerate(listed):
        if v is not None:
            first.setdefault(v, i)
    return listed, first


def pack_graph(graph):
    """The map as a report holds it. What it is handed is not changed; a map with nothing to pack is handed back."""
    if type(graph) is not dict:
        return graph
    if MARK in graph:
        return {WHOLE: graph, MARK: FORM}
    _, first = _ids(graph.get("nodes"))
    out = dict(graph)
    packed = False
    for part in ROWS:
        if part in graph:
            out[part] = pack_rows(graph[part], first, REFER[part])
            packed = packed or out[part] is not graph[part]
    if not packed:
        return graph
    out[MARK] = FORM
    return out


def _whole(i, below: int) -> bool:
    return type(i) is int and 0 <= i < below


def _copy(v):
    t = type(v)
    if t is list:
        return [_copy(x) for x in v]
    if t is dict:
        return {k: _copy(x) for k, x in v.items()}
    return v


def _length(col) -> int | None:
    """How many rows a column says it has, read from the list it carries; None for the one value of `c`."""
    if type(col) is not list or not col or type(col[0]) is not str:
        raise ValueError(NOT_OURS)
    how = col[0]
    if how == "c" and len(col) == 2:
        return None
    if how in ("v", "r") and len(col) == 2 and type(col[1]) is list:
        return len(col[1])
    if how == "t" and len(col) == 3 and type(col[2]) is list:
        return len(col[2])
    raise ValueError(NOT_OURS)


def _values(col, listed: list | None) -> tuple[str, object]:
    """One column as (how it is written, its values): a list of values, or for `c` the one value."""
    how = col[0]
    if how == "c" and len(col) == 2 and type(col[1]) in _PLAIN:
        return how, col[1]
    if how == "v" and len(col) == 2 and type(col[1]) is list:
        return how, col[1]
    if how == "t" and len(col) == 3 and type(col[1]) is list and type(col[2]) is list:
        table = col[1]
        if not all(type(v) in _PLAIN for v in table) or not all(_whole(i, len(table)) for i in col[2]):
            raise ValueError(NOT_OURS)
        return how, [table[i] for i in col[2]]
    if how == "r" and len(col) == 2 and type(col[1]) is list and listed is not None:
        out = []
        for x in col[1]:
            if _whole(x, len(listed)) and listed[x] is not None:
                out.append(listed[x])
            elif type(x) is list and len(x) == 1:
                out.append(x[0])
            else:
                raise ValueError(NOT_OURS)
        return how, out
    raise ValueError(NOT_OURS)


def unpack_rows(packed, listed: list | None = None, own: bool = False) -> list:
    """Rows written column by column, as rows again. `listed`: the ids of the nodes, for the columns that name
    a node by its place; `own`: these rows are the nodes, and the ids are their own `id` column."""
    if type(packed) is list:
        return packed
    if type(packed) is not dict:
        raise ValueError(NOT_OURS)
    keys, n, cols = packed.get("keys"), packed.get("n"), packed.get("cols")
    if type(keys) is not list or type(cols) is not list or type(n) is not int or n < 0 or len(keys) != len(cols) \
            or not keys or not all(type(k) is str for k in keys) or len(set(keys)) != len(keys) or NOT_A_FIELD in keys:
        raise ValueError(NOT_OURS)
    lengths = [_length(c) for c in cols]
    if all(m is None for m in lengths) or any(m is not None and m != n for m in lengths):
        raise ValueError(NOT_OURS)          # a count is believed only where every list has that many entries
    read: list = [None if c[0] == "r" else _values(c, None) for c in cols]
    if own:
        listed = None
        at = keys.index("id") if "id" in keys else -1
        if at >= 0 and read[at] is not None:
            how, values = read[at]
            listed = [v if type(v) is str else None for v in ([values] * n if how == "c" else values)]
    read = [_values(c, listed) if got is None else got for c, got in zip(cols, read)]
    rows = [{} for _ in range(n)]
    for k, (how, values) in zip(keys, read):
        if how == "c":
            for row in rows:
                row[k] = values
        elif how == "v":
            for row, v in zip(rows, values):
                row[k] = v
        else:
            for row, v in zip(rows, values):
                row[k] = _copy(v)           # what stood in a list of its own is that row's own
    return rows


def unpack_graph(graph):
    """The map a report holds, as rows again. A map that is not packed is handed back as it is; a packed one of a
    shape this Lantern does not write raises ValueError."""
    if type(graph) is not dict or MARK not in graph:
        return graph
    if type(graph[MARK]) is not int or graph[MARK] != FORM:
        raise ValueError(NOT_OURS)
    if WHOLE in graph:
        if len(graph) != 2:
            raise ValueError(NOT_OURS)
        return graph[WHOLE]
    out = {k: v for k, v in graph.items() if k != MARK}
    if "nodes" in out:
        out["nodes"] = unpack_rows(out["nodes"], own=True)
    listed, _ = _ids(out.get("nodes"))
    if "edges" in out:
        out["edges"] = unpack_rows(out["edges"], listed)
    return out
