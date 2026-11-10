"""The results folder (`PATH/.lantern`, or `--out`): reading back what an earlier run left there (2026-11-10,
directive stage 7).

`lantern analyze` reads three files an earlier run of the same folder wrote: `security.json` (which findings were
there before), `baseline.json` (the first analysis, for "fixed since") and `explanations.json` (a model's words, for
the report). A run can do without each of them, so none of them may stop it. Until this date one that was cut off
(the computer was switched off while it was written), empty, not text, or of another shape ended every later
`lantern analyze` of that folder with a Python error, until someone deleted the file by hand.

`earlier(out, name)` gives the file's table, or nothing and the reason in one sentence made of fixed words (never
text from the file). Only a plain file is read: not a link (the folder lies inside the analysed project by default,
so what is in it may have come with the project), not a folder, a pipe or a device (a pipe would hold the run up for
good), and not one larger than `MAX_BYTES`. `SHAPES` says, per file, what the parts this run uses must look like. A
file with one odd part is passed over whole: a result file is Lantern's own, so an odd part means it is not what
Lantern wrote, and the rest of it is no better known.

Nothing here changes or removes a file. The results a command is about (`lantern evidence`, `explain`, `verify` on a
finished run) are still read strictly (`pipeline.load`): passing those over would turn a damaged scan result into
"no findings".
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

MAX_BYTES = 256 * 1024 * 1024       # the largest real result file seen is a few MB
NOT_OURS = "it does not hold what Lantern writes there"
CUT_OFF = "it is not complete JSON (a run that was cut off while it wrote the file leaves it so)"


def _plain(p: Path) -> tuple[str | None, str | None]:
    """(text, None) for the plain file at `p`, (None, None) when nothing is there, else (None, why)."""
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError) as exc:
        return None, f"it could not be looked at ({type(exc).__name__})"
    if stat.S_ISLNK(st.st_mode):
        return None, "it is a link, and Lantern does not read its results through a link"
    if not stat.S_ISREG(st.st_mode):
        return None, "it is not a plain file"
    if st.st_size > MAX_BYTES:
        return None, f"it is larger than {MAX_BYTES // (1024 * 1024)} MB"
    # The name is opened once and the open file is asked again what it is, so a link or a pipe put there since the
    # look above is not read either (O_NONBLOCK: opening a pipe nobody writes to would otherwise never come back).
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_BINARY", 0))
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return None, "it is not a plain file"
            data = fh.read(MAX_BYTES + 1)
    except (OSError, ValueError) as exc:
        return None, f"it could not be read ({type(exc).__name__})"
    if len(data) > MAX_BYTES:
        return None, f"it is larger than {MAX_BYTES // (1024 * 1024)} MB"
    try:
        return data.decode("utf-8").removeprefix("\ufeff"), None
    except UnicodeDecodeError:
        return None, "it is not text"


def _number(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _text_or_nothing(x) -> bool:
    return x is None or isinstance(x, str)


def scan_shape(d: dict) -> str | None:
    """`security.json` of the run before: this run takes the ids of its findings and nothing else."""
    fs = d.get("findings")
    if fs is not None and not (isinstance(fs, list)
                               and all(isinstance(f, dict) and _text_or_nothing(f.get("id")) for f in fs)):
        return "its findings are not a list of findings with an id each"
    return None


def baseline_shape(d: dict) -> str | None:
    """`baseline.json` as `evidence.baseline_from` writes it, in every release so far (`tests/fixtures/old_results`):
    a field added there has to be let through here."""
    if isinstance(d.get("id_version"), bool) or not isinstance(d.get("id_version"), (int, str, type(None))):
        return "its id_version is not a number"
    for k in ("date", "commit"):
        if not _text_or_nothing(d.get(k)):
            return f"its {k} is not text"
    counts = d.get("counts")
    if counts is not None and not (isinstance(counts, dict) and all(_number(v) for v in counts.values())):
        return "its counts are not numbers"
    rd = d.get("readiness")
    if rd is not None:
        if not isinstance(rd, dict) or not (rd.get("score") is None or _number(rd["score"])) \
                or not _text_or_nothing(rd.get("grade")):
            return "its readiness is not a score and a grade"
        cats = rd.get("categories")
        if cats is not None and not (isinstance(cats, dict) and all(v is None or _number(v) for v in cats.values())):
            return "its readiness categories are not numbers"
    fs = d.get("findings")
    if fs is None:
        return None
    if not isinstance(fs, dict):
        return "its findings are not a table"
    for v in fs.values():
        if not isinstance(v, dict) or not all(isinstance(v.get(k), str) for k in ("rule", "rank", "title")) \
                or not _text_or_nothing(v.get("file")) or not (v.get("line") is None or _number(v["line"])):
            return "one of its findings is not a rule, a rank, a title, a file and a line"
    return None


def explanations_shape(d: dict) -> str | None:
    """`explanations.json` as `explain.run` and `pipeline.explain` write it: the record of each function is a table.
    What is inside a record is the viewer's to escape and is not looked at here."""
    e = d.get("explanations")
    if e is not None and not (isinstance(e, dict) and all(isinstance(r, dict) for r in e.values())):
        return "its explanations are not a table of records"
    for k in ("stats", "metaphor"):
        if d.get(k) is not None and not isinstance(d[k], dict):
            return f"its {k} is not a table"
    return None


SHAPES = {"security.json": scan_shape, "baseline.json": baseline_shape, "explanations.json": explanations_shape}


def earlier(out: Path, name: str) -> tuple[dict | None, str | None]:
    """What an earlier run left in `out` under `name`: (table, None); (None, None) when there is no such file; or
    (None, why) when what is there cannot be taken for what Lantern writes. Never raises for what the file holds."""
    text, why = _plain(Path(out) / name)
    if text is None:
        return None, why
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return None, CUT_OFF
    if not isinstance(data, dict):
        return None, NOT_OURS
    odd = SHAPES[name](data) if name in SHAPES else None
    return (None, f"{NOT_OURS}: {odd}") if odd else (data, None)
