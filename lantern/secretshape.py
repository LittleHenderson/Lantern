"""Text a secret scanner flagged that, by its own shape and the name it is kept under, is no key (2026-11-19).

gitleaks' rule `generic-api-key` flags any long, random-looking text under a name with a word such as `access`,
`auth` or `key` in it. On one project Lantern was measured on, it flagged ten lines, every one ranked critical, and
the release read Blocked for them: eight were the SHA-256 of a file kept under a name that ends in `_sha256`, one
was the SHA-256 kept under the file name it is the fingerprint of, and one was a fixed label in capitals
(`SOME_RECORD_V1`) under a name that says it is a domain. None is a key: a fingerprint is made from something
anybody may have, and a label is the same in every copy of the program.

`shape(match, secret)` reads what the scanner matched (the name and the value) and says which of the two it is, or
None. It is strict on purpose: only a whole hexadecimal text of a digest's length under a name that says digest (or
a file's name), and only capitals in whole words with underscores under a name that says label. A name with a
password's word in it is never passed (a password's hash is still something to keep). The finding stays listed,
ranked low, with the reason written on it; nothing is dropped. The value itself is never kept.
"""
from __future__ import annotations

import re

DIGEST_LENGTHS = {32, 40, 56, 64, 96, 128}   # MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 written in hex
HEX = re.compile(r"[0-9a-fA-F]+")
DIGEST_WORDS = {"sha", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3", "md5", "blake2", "blake2b", "blake3",
                "digest", "hash", "checksum", "fingerprint", "integrity", "crc", "crc32"}
LABEL_WORDS = {"domain", "label", "context", "purpose", "tag", "scheme", "namespace", "prefix", "kind", "type",
               "version", "separator", "realm", "schema", "format"}
PASSWORD_WORDS = {"password", "passwd", "pwd", "passphrase", "pass", "pin"}
FILE_NAME = re.compile(r"(?i)^[\w.\-/]*[\w\-]\.(?:json|ya?ml|toml|txt|md|py|js|ts|xml|csv|html?|bin|tar|gz|tgz|zip|"
                       r"whl|lock|cfg|ini|sql|proto|wasm|jar|so|dll|exe|pdf|png|svg)$")
LABEL = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){2,}")
NAME_TAIL = re.compile(r"[\w.\-/]+$")
MOST = 400      # a match longer than this is not read


def _words(name: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [w.lower() for w in re.split(r"[^A-Za-z0-9]+", spaced) if w]


def _name(match: str, secret: str) -> str:
    at = match.find(secret)
    if at <= 0:
        return ""
    head = match[:at].rstrip(" \t'\"`:=>,(")
    m = NAME_TAIL.search(head)
    return m.group(0) if m else ""


def _label(value: str) -> bool:
    if not LABEL.fullmatch(value):
        return False
    parts = value.split("_")
    words = [p for p in parts if p.isalpha() and len(p) >= 2]
    rest = [p for p in parts if p not in words]
    return len(words) >= 2 and all(re.fullmatch(r"V?\d+", p) for p in rest)


def shape(match, secret) -> dict | None:
    """{"kind": "digest" | "label", "name": the name it is kept under, "why": the sentence} or None."""
    if not isinstance(match, str) or not isinstance(secret, str) or not secret or len(match) > MOST:
        return None
    value = secret[:-2] if secret.endswith("\\n") else secret
    name = _name(match, secret)
    if not name:
        return None
    words = _words(name)
    if PASSWORD_WORDS & set(words):
        return None
    if HEX.fullmatch(value) and len(value) in DIGEST_LENGTHS:
        if DIGEST_WORDS & set(words):
            return {"kind": "digest", "name": name,
                    "why": (f"The text is a {len(value)}-character hexadecimal value, the length of a digest, kept under "
                            f"the name `{name}`, which says it is one. A digest is a fingerprint made from data, not a "
                            "key that opens anything, so Lantern ranks it low; check it is not a key under a wrong name.")}
        if FILE_NAME.match(name):
            return {"kind": "digest", "name": name,
                    "why": (f"The text is a {len(value)}-character hexadecimal value, the length of a digest, kept under "
                            f"the file name `{name}`: the fingerprint of that file. A digest is not a key that opens "
                            "anything, so Lantern ranks it low; check it is not a key under a wrong name.")}
    if _label(value) and LABEL_WORDS & set(words):
        return {"kind": "label", "name": name,
                "why": (f"The text is a fixed label in capitals and underscores, kept under the name `{name}`, which "
                        "says it is a label. A label is the same in every copy of the program and opens nothing, so "
                        "Lantern ranks it low; check it is not used as a secret.")}
    return None
