"""A text a secret scanner flagged that is a digest or a fixed label by its shape and its name (lantern/secretshape.py).

Each case that is passed over stands beside a twin that must stay a key: the same value under a key's name, a
password's hash, a random text under a digest's name, a label under a key's name. Values are made at test time."""
import json
import os
import random
import string
from pathlib import Path

from lantern import secretshape, security

from test_scanners import _after, _run, _stand_in, _write

R = random.Random(7)
HEX64 = "".join(R.choice("0123456789abcdef") for _ in range(64))
HEX40 = "".join(R.choice("0123456789abcdef") for _ in range(40))
RANDOM = "".join(R.choice(string.ascii_letters + string.digits) for _ in range(40))


def m(name: str, value: str, quote: str = '"') -> tuple[str, str]:
    return f'{name}{quote}: {quote}{value}', value


def test_digests_under_a_digest_name_or_a_file_name():
    assert secretshape.shape(*m("checkpoint_access_selection_sha256", HEX64))["kind"] == "digest"
    assert secretshape.shape(*m("accessTokenFingerprint", HEX40))["kind"] == "digest"
    assert secretshape.shape(*m("auth-schema-v1.schema.json", HEX64, "'"))["kind"] == "digest"
    assert secretshape.shape(f"apiKeyChecksum = '{HEX64}", HEX64)["kind"] == "digest"


def test_their_twins_stay_keys():
    assert secretshape.shape(*m("api_key", HEX64)) is None                    # a hex key under a key's name
    assert secretshape.shape(*m("access_token", HEX40)) is None
    assert secretshape.shape(*m("password_sha256", HEX64)) is None            # a password's hash stays
    assert secretshape.shape(*m("admin_pass_hash", HEX64)) is None
    assert secretshape.shape(*m("auth_sha256", RANDOM)) is None               # not hex
    assert secretshape.shape(*m("auth_sha256", HEX64[:50])) is None           # not a digest's length
    assert secretshape.shape(*m("auth_sha256", HEX64 + "x")) is None
    assert secretshape.shape(*m("secret.json.key", HEX64)) is None            # not a file's name
    assert secretshape.shape(HEX64, HEX64) is None                            # no name at all
    assert secretshape.shape(None, HEX64) is None and secretshape.shape("x", None) is None


def test_labels_under_a_label_name():
    assert secretshape.shape(*m("authentication_domain", "SOME_PROTECTED_RECORD_V1"))["kind"] == "label"
    assert secretshape.shape(*m("authentication_domain", "SOME_PROTECTED_RECORD_V1\\n"))["kind"] == "label"
    assert secretshape.shape(*m("tokenContext", "APP_SESSION_TOKEN_2"))["kind"] == "label"


def test_their_twins_stay_keys_too():
    assert secretshape.shape(*m("api_key", "SOME_PROTECTED_RECORD_V1")) is None      # a key's name
    assert secretshape.shape(*m("password_label", "SOME_PROTECTED_RECORD")) is None  # a password's word
    assert secretshape.shape(*m("auth_domain", "AKIAQ3X9_ZK2P7_W8RT")) is None       # parts are not words
    assert secretshape.shape(*m("auth_domain", "SOME_RECORD")) is None               # two parts only
    assert secretshape.shape(*m("auth_domain", "Some_Protected_Record")) is None     # not capitals
    assert secretshape.shape(*m("auth_domain", RANDOM)) is None


def test_the_reason_never_holds_the_value():
    for case in (m("x_sha256", HEX64), m("auth_domain", "SOME_PROTECTED_RECORD_V1")):
        look = secretshape.shape(*case)
        assert case[1] not in look["why"] and case[1] not in json.dumps(look)


def test_gitleaks_findings_of_that_shape_are_ranked_low_and_still_listed(tmp_path, monkeypatch):
    lines = [f'"access_sha256": "{HEX64}"', f'"api_key": "{HEX64}"']
    _write(tmp_path, {"c.json": "\n".join(lines) + "\n"})

    def project(cmd):
        top = _after(cmd, "-s")
        rows = [{"RuleID": "generic-api-key", "Description": "Generic API Key", "StartLine": i + 1,
                 "Match": line.lstrip('"'), "Secret": HEX64, "File": os.path.join(top, "c.json")}
                for i, line in enumerate(lines)]
        Path(cmd[cmd.index("-r") + 1]).write_text(json.dumps(rows), encoding="utf-8")
        return _run(1, "", "")
    _stand_in(monkeypatch, tmp_path, project=project)
    found, _ = security.run_secrets(tmp_path)
    by = {f["line"]: f for f in found}
    assert len(found) == 2
    digest, key = by[1], by[2]
    assert digest["secret_shape"] == {"kind": "digest", "name": "access_sha256"} and digest["fixed_rank"] == "low"
    assert "secret_shape" not in key and "fixed_rank" not in key
    assert security._rank(digest) == "low" and "digest" in security.rank_reason(digest)
    assert security._rank(key) == "critical"
    assert HEX64 not in json.dumps(found)
