"""Which line patterns can find anything in a file at all (directive point 10, 2026-11-12).

Several checks try a list of patterns on every line of every file: the paid-API calls, the secret patterns, the
rules of a pack. Nearly every file holds nothing any of them is about, and was still searched line by line, pattern
by pattern: 14 million searches for Django's 481,000 lines by the paid-API patterns alone.

`needs(rx)` reads a pattern and names a few pieces of plain text of which every match holds at least one (for
`\\bstripe\\.(?:checkout|charges)\\b|\\bStripe\\(` they are `stripe.` and `Stripe(`). A file that holds none of them
has no line the pattern matches, so `may_match(rx, text)` says no and the caller leaves that pattern out for that
file; when it cannot say, it says yes. Nothing else changes: the lines of a file that may match are searched as
before, by the same pattern, so the findings are the same and no file is read less.

Why "holds none of them" is safe. The pieces come from the pattern's own structure (Python's parser for patterns):
text that stands outside every choice, every optional part and every repeat that may be zero times, or one piece
for every arm of a choice. They are kept only when plain ASCII with no quote and no line break in them. A pattern
that ignores case is asked in lower case, and only of text that is all ASCII: in other text a letter can match
one that `lower()` does not turn into it (the long s, the Kelvin sign), and then the answer is yes. A caller that
searches lines it changed first may ask about the file's text as it is where the change only takes text away or
puts quotes in (strings blanked to `''`, a line cut short): a piece without a quote that is in the changed line is
in the line as it was.
"""
from __future__ import annotations

import functools
import re

try:    # the pattern parser, where Python keeps it since 3.11
    from re import _constants as _c
    from re import _parser as _p
except ImportError:     # pragma: no cover  (another Python: nothing is known about any pattern, every answer is yes)
    _c = _p = None

NOT_IN_A_PIECE = frozenset("'\"`\n\r")
MOST = 24               # a pattern with more arms than this is not asked piece by piece


def _usable(piece: str) -> str:
    """The longest part of a piece of required text that can be looked for as it is: plain ASCII, no quote, no
    line break."""
    best = cur = ""
    for ch in piece:
        if ch.isascii() and ch not in NOT_IN_A_PIECE:
            cur += ch
            if len(cur) > len(best):
                best = cur
        else:
            cur = ""
    return best


def _better(a, b):
    """Of two answers the one that tells more: its shortest piece is longer; then the one with fewer pieces."""
    if a is None or b is None:
        return a if b is None else b
    ka, kb = (min(map(len, a)), -len(a)), (min(map(len, b)), -len(b))
    return a if ka >= kb else b


def _need(seq) -> list[str] | None:
    """Pieces of text of which every match of this sequence of pattern parts holds at least one, or None."""
    best, run = None, []

    def close():
        nonlocal best, run
        if run:
            piece = _usable("".join(run))
            if piece:
                best = _better(best, [piece])
            run = []

    for op, av in seq:
        if op is _c.LITERAL:
            run.append(chr(av))
        elif op in (_c.AT, _c.ASSERT, _c.ASSERT_NOT):
            continue                                    # takes no text: what stands on both sides still joins
        elif op is _c.SUBPATTERN:
            close()
            _, add, take, inner = av
            if not add and not take:                    # a group that changes how its text is read is not read
                best = _better(best, _need(inner))
        elif op in (_c.MAX_REPEAT, _c.MIN_REPEAT, getattr(_c, "POSSESSIVE_REPEAT", None)):
            close()
            least, _, inner = av
            if least >= 1:
                best = _better(best, _need(inner))
        elif op is _c.BRANCH:
            close()
            arms = [_need(arm) for arm in av[1]]
            if all(arms):
                best = _better(best, [piece for arm in arms for piece in arm])
        elif op is getattr(_c, "ATOMIC_GROUP", None):
            close()
            best = _better(best, _need(av))
        else:                                           # a set of characters, any character, a back reference, ...
            close()
    close()
    return best


@functools.lru_cache(maxsize=4096)
def needs(rx: re.Pattern) -> tuple[str, ...] | None:
    """A few pieces of text of which every match of `rx` holds at least one (in lower case for a pattern that
    ignores case), or None when the pattern does not show any."""
    if _p is None or not isinstance(rx.pattern, str):
        return None
    try:
        found = _need(_p.parse(rx.pattern, rx.flags & ~re.DEBUG))
    except Exception:   # noqa: BLE001  (a pattern this reader does not understand: nothing is known about it)
        return None
    if not found or len(found) > MOST:
        return None
    if rx.flags & re.IGNORECASE:
        found = [piece.lower() for piece in found]
    return tuple(dict.fromkeys(found))


class Text:
    """A file's text, asked by many patterns: its lower-case form is made once, and only when a pattern asks."""

    def __init__(self, text: str):
        self.text = text
        self._lower: str | None = None
        self._ascii: bool | None = None

    def may_match(self, rx: re.Pattern) -> bool:
        """False only when no line of the text can match `rx`."""
        pieces = needs(rx)
        if pieces is None:
            return True
        if rx.flags & re.IGNORECASE:
            if self._ascii is None:
                self._ascii = self.text.isascii()
            if not self._ascii:
                return True
            if self._lower is None:
                self._lower = self.text.lower()
            hay = self._lower
        else:
            hay = self.text
        return any(piece in hay for piece in pieces)


def may_match(rx: re.Pattern, text: str) -> bool:
    return Text(text).may_match(rx)
