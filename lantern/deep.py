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

**A file its parser is not through with in time** (the same day, `Timed`, `slow`). The parsers are tree-sitter's,
written in C, and the time one takes over a file is its own. For nearly every file it grows with the file (the
largest Dart file the reader takes, 1,450,000 bytes of ordinary code, 0.45 seconds); tree-sitter-dart's grows far
faster on a type written inside itself inside a function (`List<List<…>>`: 2,000 levels 0.9 seconds, 4,000 levels
7.5, 10,000 levels, a file of 60,245 bytes, 66, 40,000 not through after two minutes), and until then one such file
kept the whole check waiting. Now a parser gets `PARSE_SECONDS` for one file. A file it is not through with is on
the map as a file, nothing written in it is, it is written down (`meta["too_deep"]["slow"]`) and said like a piece
nested too deep, and the files after it are read as before. Only the Dart reader's parser is such a parser so far:
it is the one grammar this was measured on.
"""
from __future__ import annotations

import time
import warnings

MOST = 40           # pieces written down one by one; beyond that only the counts go up
PARSE_SECONDS = 20  # what a parser gets for one file: forty times what the largest ordinary file takes, and twice
                    # what the slowest file of ordinary code with mistakes in it took (tree-sitter 0.25.2, measured)
PIECE = 1 << 16     # bytes handed to a parser at a time where a file is handed over through a function
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


class Timed:
    """A parser that gets `PARSE_SECONDS` for one file: `parse(src)` gives the tree, or None when the parser was not
    through with the file in time.

    How a parse is given a limit differs from version to version of the library, and each way here was measured:

    * up to 0.25 the limit is the parser's own (`timeout_micros`). 0.25 says the attribute will go, and the way it
      names in its place ends the Python program there with a segmentation fault (0.25.2: a file handed over
      through a function, with a progress function), so that way is not used where the attribute exists;
    * from 0.26 the attribute is gone and a parse asks a function as it goes whether to stop, but only when the
      file is handed over through a function that reads it piece by piece (for a file handed over whole the
      function is never asked, and the library says so). A tree made that way reads every node's text through
      that function again (all the texts of a large file: 40 seconds where 1.5 are usual), so the file is parsed
      once more with the first tree in hand: the parser takes the first tree's nodes as they are, which costs a
      tenth of a parse, and the tree it gives has the file's own bytes behind it. Node for node, place for place
      and text for text it is the tree an unlimited parse gives (`tests/test_slow_file.py`).

    A parser that was stopped goes on with the file it was stopped on when it is given the next one (the next file
    then came out as one error), so it is put back first (`reset`). Only the clock makes a file one the parser was
    not through with: whatever else the library refuses is raised as it was."""

    def __init__(self, parser):
        self.parser = parser
        self.own = hasattr(type(parser), "timeout_micros")    # asked of the class: asking the parser itself warns on 0.25
        self.given = None

    def _limit(self, micros: int) -> None:
        if micros != self.given:
            with warnings.catch_warnings():                    # "Use the progress_callback in parse()": see above
                warnings.simplefilter("ignore", DeprecationWarning)
                self.parser.timeout_micros = micros
            self.given = micros

    def parse(self, src: bytes):
        seconds = PARSE_SECONDS
        began, error, tree = time.monotonic(), None, None
        try:
            if self.own:
                self._limit(int(seconds * 1_000_000))
                tree = self.parser.parse(src)
            else:
                end = began + seconds
                first = self.parser.parse(lambda at, _point: src[at:at + PIECE],
                                          progress_callback=lambda *_state: time.monotonic() > end)
                if first is not None:
                    tree = self.parser.parse(src, old_tree=first)
        except ValueError as e:             # "Parsing failed": how the library says that a parse was stopped
            error = e
        if tree is not None:
            return tree
        self.parser.reset()
        if time.monotonic() - began < seconds * 0.9:           # not the clock
            raise error if error is not None else ValueError("the parser gave no tree")
        return None


def slow(to, file: str) -> None:
    """Write down that the parser was not through with `file` in time. `to` is (map, reader), or None where a reader
    is used with no map."""
    if to is None:
        return
    rec = _record(to[0]).setdefault("slow", {"count": 0, "files": [], "readers": [], "seconds": PARSE_SECONDS})
    rec["count"] += 1
    if len(rec["files"]) < MOST:
        rec["files"].append(file)
    if to[1] not in rec["readers"]:
        rec["readers"].append(to[1])


def read_slow(meta) -> tuple[int, list[str], int]:
    """(how many files a parser was not through with in time, the first of them by name, the seconds a parser got)
    out of a map's `meta`, which may be one read back from disk: 0, no names and 0 when there is none. The seconds
    are 0 where the record does not say them as a number a limit could be."""
    rec = meta.get("too_deep") if isinstance(meta, dict) else None
    rec = rec.get("slow") if isinstance(rec, dict) else None
    if not isinstance(rec, dict) or not isinstance(rec.get("files"), list):
        return 0, [], 0
    files = [f for f in rec["files"] if isinstance(f, str)]
    n = _whole(rec.get("count"))
    if not n or not files:
        return 0, [], 0
    seconds = _whole(rec.get("seconds"))
    return max(n, len(files)), files, seconds if seconds <= 3600 else 0


def _waited(seconds: int) -> str:
    return f"longer than {seconds} second{'s' if seconds != 1 else ''}" if seconds else "longer than Lantern waits"


def _shown(file: str) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in file[:120])


def _listed(files: list[str], of: int = 0) -> str:
    more = max(of, len(files)) - 3
    return ", ".join(_shown(f) for f in files[:3]) + (f" and {more} more" if more > 0 else "")


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
    late, names_, seconds = read_slow(meta)
    if late:
        out.append(f"{late} file{'s' if late != 1 else ''} took {'their' if late != 1 else 'its'} parser "
                   f"{_waited(seconds)} and {'were' if late != 1 else 'was'} not read ({_listed(names_, late)})")
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
    late, names_, seconds = read_slow(meta)
    if late:
        out.append(f"{late} file{'s' if late != 1 else ''} of the project took {'their' if late != 1 else 'its'} "
                   f"parser {_waited(seconds)}{' each' if late != 1 else ''}, and Lantern stopped waiting: "
                   f"{_listed(names_, late)}. Code written by hand is read in a fraction of that time; a type written "
                   "inside itself some thousand times is not. Nothing written in such a file is on the map and no "
                   "path leads through it. The pattern rules and the scanners read those files line by line like any "
                   "other.")
    return out
