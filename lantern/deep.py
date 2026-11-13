"""Code nested deeper than a reader follows (2026-11-13).

A reader goes through a file's code by calling itself once for each level of nesting, and Python ends a program that
calls itself about a thousand levels deep. One piece of code nested that deep (a chain of some hundreds of calls, a
sum of a thousand pieces, an `else if` ladder with a thousand arms, brackets inside brackets, functions or classes
written inside each other) used to end the whole check with "maximum recursion depth exceeded" and no result.
Measured on the code before with eleven such shapes in each of the thirteen kinds of source file, every case a
project of its own: 69 of the 136 ended the check (`python tests/test_nested.py CHECKOUT` prints the table).

Now the check ends with a result, and what was not read is the least a reader can leave and is written down. Three
nets, the smallest that holds is the one that catches:

* **A piece.** Where a reader calls itself per level (Python, JavaScript/TypeScript, Go, Rust, Java) a piece is one
  statement: the statements of a block are read one by one and the one nested too deep is left. Where a reader goes
  through a function's code with a list of its own (Kotlin, Swift, C#, PHP, Ruby, C and C++) nesting costs it
  nothing, and a piece is the one place whose type it could not work out that deep. In a reader's first pass (what
  a file declares) a piece is one declaration written inside another. `leave()` and `note()` write the file and the
  line where the piece begins into the map (`meta["too_deep"]`).
* **A file.** Where a first pass has no single piece to leave, what it had taken from the file stays and the file is
  written down as not read to the end (`whole`).
* **A reader.** Where a reader meets such code, or a line of classes or files linked that deep, in a place with no
  net of its own, what it had put on the map stays, the reader is written down as stopped (`stopped`, from
  `engine._part`) and the readers after it run.

What a reader knew about a name is not used after a piece that writes that name (`leave`): the part that was not
read may have given the name another meaning, and a link worked out from the older one would be a guess shown as a
fact. A reader whose table holds only names it knows a type for has them taken out; one whose table also says which
names are the function's own marks every name written in the piece as one it knows nothing about (`blank=""`).

Nothing is raised, lowered or guessed for such a piece. Its calls are not on the map, so no path leads through them,
and the checks that read lines (the pattern rules, the scanners) read the file as they read any other. `lantern
analyze` prints a `deep` line (`line_words`) and the Evidence Report's Limits name the files and the readers
(`words`). It is no criterion of the release decision: like a call nobody could place, it is said, not judged.

The recursion limit is left as it is: raising it trades this stop for a crash of the Python program itself on a
computer with a small stack.
"""
from __future__ import annotations

MOST = 40           # pieces written down one by one; beyond that only the counts go up
# The readers by the names they are written down under, and what a person calls the code each reads.
READERS = {"python": "Python", "javascript": "JavaScript and TypeScript", "go": "Go", "rust": "Rust", "java": "Java",
           "kotlin": "Kotlin", "swift": "Swift", "dart": "Dart", "csharp": "C#", "php": "PHP", "ruby": "Ruby",
           "cpp": "C and C++"}


def _record(g) -> dict:
    return g.meta.setdefault("too_deep", {"pieces": 0, "files": [], "where": [], "readers": []})


def note(g, file: str, line: int, reader: str) -> None:
    """Write down that the piece of `file` beginning at `line` was not read to its end by `reader`."""
    rec = _record(g)
    new = file not in rec["files"]     # asked before anything is written: this runs where Python has little room left
    rec["pieces"] += 1
    if new:
        rec["files"].append(file)
    if len(rec["where"]) < MOST:
        rec["where"].append({"file": file, "line": int(line), "reader": reader})


def stopped(g, reader: str) -> None:
    """Write down that `reader` stopped before it was through with the project: it met code nested, or linked, deeper
    than it follows in a place where it leaves no single piece. What it had put on the map stays there."""
    rec = _record(g)
    if reader not in rec["readers"]:
        rec["readers"].append(reader)


def names(piece, kinds=("identifier",)) -> set[str]:
    """The names written in a piece of code, found without a function that calls itself: the piece is one the reader
    could not follow to its end. A reader forgets what it knew about these names in the scope the piece stands in."""
    out, stack = set(), [piece]
    while stack:
        x = stack.pop()
        if x.type in kinds:
            out.add(x.text.decode("utf-8", "replace"))
        elif x.child_count:
            stack.extend(x.children)
    return out


FORGET = object()   # `leave(blank=FORGET)`: a reader whose table holds only the names it knows a type for


def leave(to, file: str, piece, *tables, kinds=("identifier",), blank=FORGET) -> None:
    """A reader leaves `piece` of `file` where its reading stopped. `to` is (map, reader), or None where a reader is
    used with no map. What the reader's tables (a name's type and the like) held about the names written in the
    piece is not used after it: the part that was not read may have given any of them another meaning. A reader
    whose table holds only the names it knows something about has them taken out; one whose table also says which
    names are the function's own (asked with `name in table`) hands in what it writes for a name it knows nothing
    about (`blank=""`), and every name written in the piece is then such a name."""
    written = names(piece, kinds) if tables else ()   # before the note: if there is no room for this either, the piece
    if to is not None:                                  # around this one is left instead, and written down once
        note(to[0], file, piece.start_point[0] + 1, to[1])
    for name in written:
        for table in tables:
            if blank is FORGET:
                table.pop(name, None)
            else:
                table[name] = blank


def whole(to, file: str, read, *args, **more):
    """A reader's first pass over one file, `read(*args)`. Where the file's declarations are nested deeper than the
    pass follows and it has no single piece to leave, what it had taken from the file stays and the file is written
    down as not read to the end."""
    try:
        return read(*args, **more)
    except RecursionError:
        if to is not None:
            note(to[0], file, 1, to[1])


def _whole(x) -> int:
    return x if isinstance(x, int) and not isinstance(x, bool) and x > 0 else 0


def read(meta) -> tuple[int, list[str], list[str]]:
    """(pieces, files, readers that stopped) out of a map's `meta`, which may be one read back from disk: 0 and empty
    lists when there is none."""
    rec = meta.get("too_deep") if isinstance(meta, dict) else None
    if not isinstance(rec, dict):
        return 0, [], []
    files = [f for f in rec.get("files") or [] if isinstance(f, str)] if isinstance(rec.get("files"), list) else []
    readers = [r for r in rec.get("readers") or [] if isinstance(r, str) and r in READERS] \
        if isinstance(rec.get("readers"), list) else []
    n = _whole(rec.get("pieces"))
    return (n, files, readers) if n and files else (0, [], readers)


def _shown(file: str) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in file[:120])


def _listed(files: list[str]) -> str:
    return ", ".join(_shown(f) for f in files[:3]) + (f" and {len(files) - 3} more" if len(files) > 3 else "")


def _together(words: list[str]) -> str:
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + " and " + words[-1]


def line_words(meta) -> str:
    """The `deep` line of `lantern analyze`, or '' when every piece was read and no reader stopped."""
    n, files, readers = read(meta)
    out = []
    if n:
        out.append(f"{n} piece{'s' if n != 1 else ''} of code nested deeper than Lantern follows "
                   f"{'were' if n != 1 else 'was'} not read to the end ({_listed(files)})")
    if readers:
        out.append(f"the reading of the project's {_together([READERS[r] for r in readers])} code stopped before it "
                   "was through (nested or linked deeper than Lantern follows)")
    return "; ".join(out)


def words(meta) -> list[str]:
    """The Limits lines of the Evidence Report: none when every piece was read and no reader stopped. File names
    are cut and counted, never trusted for their length."""
    n, files, readers = read(meta)
    out = []
    if n:
        out.append(f"{n} piece{'s' if n != 1 else ''} of code in {len(files)} file{'s' if len(files) != 1 else ''} "
                   f"{'are' if n != 1 else 'is'} nested deeper than Lantern follows (for example a chain of several "
                   f"hundred calls, or a sum of a thousand pieces): {_listed(files)}. What is written there was not "
                   "read to the end: its calls are not on the map and no path leads through them. The pattern rules "
                   "and the scanners read those files line by line like any other.")
    for r in readers:
        out.append(f"Lantern's reading of the project's {READERS[r]} code stopped before it was through, on code "
                   f"nested or linked deeper than it follows. What it had read by then is on the map; the rest of the "
                   f"{READERS[r]} code is not, and no path leads through it. The pattern rules and the scanners read "
                   "those files line by line like any other.")
    return out
