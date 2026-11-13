"""String literals and block comments found in a line or a file, in time that grows with its length (2026-11-13).

Four places blanked or replaced string literals with one pattern, `(['"])(?:\\\\.|(?!\\1).)*\\1`. Its two ways through
a backslash (`\\\\.` and the plain `.`) both fit, so where a quote is followed by backslashes and no closing quote the
pattern tries every way of pairing them: about 2.6 times the time for each pair more (measured: 18 pairs 2.7 seconds,
20 pairs 18.9 seconds). One line in a project, a quote mark and thirty pairs of backslashes (61 characters, in a
comment or anywhere else), kept `lantern analyze` busy for days. Two patterns beside it in `websec.code_only` took
four times the time for twice the text: `/\\*[\\s\\S]*?\\*/` looked from every `/*` to the end of a file that closes
none of them (60,000 characters 5.3 seconds), and the pattern for a JavaScript template started again at every escaped
backtick of a template that does not end (40,001 characters 4.9 seconds).

`sub(quotes, repl, text)` gives what `re.sub` gave with the first pattern, `templates(repl, text)` and
`block_comments(repl, text)` what it gave with the other two, match for match. Nothing else changes:
`tests/test_strings.py` holds the old patterns and compares them with these on Lantern's own code, on written cases
and on every short text over a small alphabet.

How `sub` keeps the old answer. The old pattern's first try at a quote takes each backslash with the character after
it, and ends at the first quote that is not taken that way. `_pattern` does exactly that and nothing else, so it
cannot try twice. Where it finds the closing quote, that was the old answer. Where it does not (the line ends first),
the old pattern went back and tried the other pairings, and could still end at a quote that follows a backslash:
`_slow` works out the same answer for the rest of that line, from its end backwards, each place once (`_ends`).

How `templates` does. The template pattern has one way through any text, so a start that fails fails for good, and
every backtick between that start and the place it stopped is an escaped one whose own try reads the same characters
to the same place. `_TEMPLATE` takes the text up to that place in one match and hands it back as it was."""

from __future__ import annotations

import re

_patterns: dict[str, re.Pattern] = {}
_WHOLE = re.compile(r"([\s\S])[\s\S]*")
_TEMPLATE = re.compile(r"`(?:\\.|[^`\\])*(?:`|(?P<open>))")
_BLOCK = re.compile(r"/\*[\s\S]*?\*/")


def _pattern(quotes: str) -> re.Pattern:
    rx = _patterns.get(quotes)
    if rx is None:
        rx = _patterns[quotes] = re.compile(
            r"([" + re.escape(quotes) + r"])(?:\\.|(?!\1)[^\\\n])*(?:\1|(?P<open>[^\n]*))")
    return rx


def _ends(text: str, start: int, end: int, quote: str) -> list:
    """For each place in `text[start:end]` (one line, no line end in it): where a string that the old pattern is in
    the middle of would end if it went on from there, or None. The old pattern's order of trying: the backslash with
    the next character, then the character alone, then stopping at a quote."""
    out: list = [None] * (end - start + 1)
    for j in range(end - 1, start - 1, -1):
        c = text[j]
        r = None
        if c == "\\" and j + 1 < end:
            r = out[j + 2 - start]
        if r is None:
            r = j + 1 if c == quote else out[j + 1 - start]
        out[j - start] = r
    return out


def _match(text: str, at: int, stop: int) -> re.Match:
    """A match object for `text[at:stop]` with the quote as its first group, for a replacement function that reads
    `group(0)`, `group(1)`, `start()`, `end()` or `string`."""
    return _WHOLE.match(text, at, stop)


def _slow(m: re.Match, quotes: str, repl) -> str:
    """The rest of a line from a quote that the first try did not close, as the old pattern read it."""
    text, start, end = m.string, m.start(), m.end()
    ends: dict[str, list] = {}
    out, kept, i = [], start, start
    while i < end:
        c = text[i]
        if c in quotes:
            if c not in ends:
                ends[c] = _ends(text, start, end, c)
            stop = ends[c][i + 1 - start]
            if stop is not None:
                out.append(text[kept:i])
                out.append(repl(_match(text, i, stop)) if callable(repl) else repl)
                kept = i = stop
                continue
        i += 1
    out.append(text[kept:end])
    return "".join(out)


def sub(quotes: str, repl, text: str) -> str:
    """`text` with every string literal written in one of `quotes` replaced: by the text `repl` as it is written, or
    by what `repl(match)` returns (the match has the quote as `group(1)`). A string does not go past the end of its
    line."""
    def one(m: re.Match) -> str:
        if m.group("open") is None:
            return repl(m) if callable(repl) else repl
        return _slow(m, quotes, repl)
    return _pattern(quotes).sub(one, text)


def templates(repl, text: str) -> str:
    """`text` with every JavaScript template (backtick to backtick, over as many lines as it takes) replaced by what
    `repl(match)` returns. A backtick that nothing closes is left as it is, with everything up to where it stopped."""
    return _TEMPLATE.sub(lambda m: repl(m) if m.group("open") is None else m.group(0), text)


def block_comments(repl, text: str) -> str:
    """`text` with every `/* … */` replaced by what `repl(match)` returns. A `/*` that nothing closes is left as it
    is, and is not looked at once for every `/*` after it: past the last `*/` there is nothing to find."""
    last = text.rfind("*/")
    if last < 0:
        return text
    return _BLOCK.sub(repl, text[:last + 2]) + text[last + 2:]
