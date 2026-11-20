"""Three heuristics written from shapes another review tool named in a project Lantern was measured on, each with
examples of Lantern's own (none copied from that project): a secret taken from a file nobody checked
(lantern/custody.py), a safety limit that gives way when its value is wrong (lantern/failopen.py), money or an order
sent before it is written down (lantern/effectfirst.py). Each dangerous example stands beside safe twins."""
import textwrap

from lantern import custody, effectfirst, failopen
from lantern.engine import build_graph
from lantern.security import scan


def d(text: str) -> str:
    return textwrap.dedent(text).lstrip()


# ---------------------------------------------------------------- a secret from a file nobody checked

TOKEN = d('''
    import os
    from pathlib import Path

    def bearer_secret():
        token_file = os.environ.get("APP_TOKEN_FILE", "")
        path = Path(token_file).resolve()
        if not path.is_file():
            return None
        secret = path.read_text().strip()
        return secret if len(secret) >= 32 else None
''')
KEY_PARAM = d('''
    def load_signing_key(key_path):
        with open(key_path, "rb") as fh:
            return fh.read()
''')

KEPT = d('''
    from pathlib import Path

    class Server:
        def __init__(self, token_file=None):
            self._token_file = Path(token_file).resolve() if token_file else None

        def load_token(self):
            if self._token_file is not None and self._token_file.is_file():
                raw = self._token_file.read_text(encoding="utf-8").strip()
                return raw
            return None
''')


def test_a_secret_read_from_a_file_named_from_outside_is_found():
    assert [(c["line"], c["function"]) for c in custody.read(TOKEN)] == [(9, "bearer_secret")]
    assert [c["function"] for c in custody.read(KEY_PARAM)] == ["load_signing_key"]
    assert [(c["line"], c["function"]) for c in custody.read(KEPT)] == [(9, "load_token")]   # kept on the object


def test_a_place_the_object_keeps_from_its_own_code_is_not():
    own = KEPT.replace("Path(token_file).resolve() if token_file else None", 'Path("/etc/app/token")')
    assert own != KEPT and custody.read(own) == []
    checked = KEPT.replace("            raw = self._token_file", "            if self._token_file.is_symlink():\n"
                           "                return None\n            raw = self._token_file")
    assert checked != KEPT and custody.read(checked) == []


def test_the_secret_files_twins_are_not():
    checked = TOKEN.replace("    secret = path.read_text().strip()",
                            "    st = os.lstat(path)\n    if st.st_uid != os.geteuid() or st.st_mode & 0o077:\n"
                            "        return None\n    secret = path.read_text().strip()")
    assert custody.read(checked) == []
    fixed_place = TOKEN.replace('os.environ.get("APP_TOKEN_FILE", "")', '"/etc/app/token"')
    assert custody.read(fixed_place) == []                              # the place is the code's own
    no_secret = KEY_PARAM.replace("load_signing_key", "load_template").replace("key_path", "page_path")
    assert custody.read(no_secret) == []                                # nothing says it is a secret
    handed = KEY_PARAM.replace('    with open(key_path, "rb") as fh:',
                               '    verify_private_file(key_path)\n    with open(key_path, "rb") as fh:')
    assert custody.read(handed) == []                                   # a check of the project's own
    written = KEY_PARAM.replace('"rb"', '"wb"').replace("return fh.read()", "fh.write(b'x')")
    assert custody.read(written) == []
    public = KEY_PARAM.replace("load_signing_key", "load_public_key")
    assert custody.read(public) == []


# ---------------------------------------------------------------- a limit that gives way

FALLBACK = d('''
    import os
    raw = os.environ.get("MAX_CALLS", "")
    max_calls = int(raw) if raw.isdigit() and int(raw) > 0 else 5000
''')
CAUGHT = d('''
    import os

    def spend_cap():
        try:
            spend_limit = float(os.environ["SPEND_LIMIT"])
        except (KeyError, ValueError):
            spend_limit = 25.0
        return spend_limit
''')
INFINITE = d('''
    import os
    from decimal import Decimal

    def budget():
        raw_spend = os.getenv("DAILY_BUDGET")
        max_spend = Decimal(raw_spend) if raw_spend else Decimal("25.00")
        return max_spend
''')


def test_a_limit_that_gives_way_is_found():
    assert [(c["line"], c["kind"], c["default"]) for c in failopen.read(FALLBACK)] == [(3, "fallback", "5000")]
    caught = failopen.read(CAUGHT)
    assert [c["kind"] for c in caught] == ["fallback"]      # float: the handler's default; and no finite check
    assert [(c["kind"], c["as"]) for c in failopen.read(INFINITE)] == [("infinite", "Decimal")]


def test_the_limits_twins_are_not():
    missing_only = FALLBACK.replace("raw.isdigit() and int(raw) > 0", "raw")
    assert failopen.read(missing_only) == []                    # a wrong value still raises
    stops = CAUGHT.replace("spend_limit = 25.0", "raise SystemExit('SPEND_LIMIT must be a number')")
    assert [c["kind"] for c in failopen.read(stops)] == ["infinite"]   # float with no finite check stays
    finite = INFINITE.replace("    return max_spend", "    if not max_spend.is_finite():\n"
                              "        raise ValueError('budget')\n    return max_spend")
    assert finite != INFINITE
    assert failopen.read(finite) == []
    port = FALLBACK.replace("max_calls", "port").replace("MAX_CALLS", "PORT")
    assert failopen.read(port) == []                            # no limit
    page = FALLBACK.replace("max_calls", "max_page_size")
    assert failopen.read(page) == []
    from_code = FALLBACK.replace('os.environ.get("MAX_CALLS", "")', '"50"')
    assert failopen.read(from_code) == []                       # not from the environment
    as_int = INFINITE.replace("Decimal(raw_spend)", "int(raw_spend)")
    assert failopen.read(as_int) == []                          # a whole number cannot be Infinity
    warning = 'import os\nREAD_THRESHOLD = float(os.getenv("READ_THRESHOLD", 10.0))\n'
    assert failopen.read(warning) == []                         # a threshold for a warning limits nothing


# ---------------------------------------------------------------- money sent before it is written down

SENT_FIRST = d('''
    def pay_out(db, bank, amount, account):
        receipt = bank.withdraw_to_linked_account(amount, account)
        db.execute("INSERT INTO payouts (amount, receipt) VALUES (?, ?)", (amount, receipt))
        db.commit()
        return receipt
''')
ORDER_FIRST = d('''
    import stripe

    def refund(session, order):
        stripe.Refund.create(payment_intent=order.intent)
        order.status = "refunded"
        session.commit()
''')


def test_money_sent_before_it_is_written_down_is_found():
    assert [(c["line"], c["record"]) for c in effectfirst.read(SENT_FIRST)] == [(2, 3)]
    assert [c["effect"] for c in effectfirst.read(ORDER_FIRST)] == ["stripe.Refund.create"]


def test_the_payouts_twins_are_not():
    intent_first = SENT_FIRST.replace(
        "    receipt = bank.withdraw",
        "    db.execute(\"INSERT INTO payouts (amount, state) VALUES (?, 'sending')\", (amount,))\n"
        "    db.commit()\n    receipt = bank.withdraw")
    assert effectfirst.read(intent_first) == []
    keyed = SENT_FIRST.replace("(amount, account)", "(amount, account, idempotency_key=key)")
    assert effectfirst.read(keyed) == []
    deduped = SENT_FIRST.replace("    receipt = bank.withdraw", "    dedup(db, request_id)\n    receipt = bank.withdraw")
    assert deduped != SENT_FIRST and effectfirst.read(deduped) == []
    elsewhere = SENT_FIRST.replace("    receipt = bank.withdraw",
                                   "    verifier.check(token, owner_request_id=request_id)\n    receipt = bank.withdraw")
    assert [c["line"] for c in effectfirst.read(elsewhere)] == [3]   # a request's id handed to another call is no key
    nothing_after = "def pay_out(bank, amount, account):\n    return bank.withdraw_to_linked_account(amount, account)\n"
    assert effectfirst.read(nothing_after) == []                # written down elsewhere, if at all: not judged
    own = SENT_FIRST.replace("bank.withdraw_to_linked_account", "self.withdraw_to_linked_account")
    assert effectfirst.read(own) == []
    read_only = SENT_FIRST.replace('"INSERT INTO payouts (amount, receipt) VALUES (?, ?)", (amount, receipt)',
                                   '"SELECT 1"').replace("    db.commit()\n", "")
    assert effectfirst.read(read_only) == []
    not_money = SENT_FIRST.replace("withdraw_to_linked_account", "lookup_account")
    assert effectfirst.read(not_money) == []


def test_the_three_run_in_a_check_and_skip_test_code(tmp_path):
    for rel, text in {"app/auth.py": TOKEN, "app/limits.py": FALLBACK, "app/payouts.py": SENT_FIRST,
                      "tests/test_payouts.py": SENT_FIRST}.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    found = scan(build_graph(tmp_path), offline=True)["findings"]
    got = {(f["rule"], f["file"]) for f in found if f["rule"] in (custody.RULE, failopen.RULE, effectfirst.RULE)}
    assert got == {(custody.RULE, "app/auth.py"), (failopen.RULE, "app/limits.py"),
                   (effectfirst.RULE, "app/payouts.py")}
    for f in found:
        if f["rule"] in (custody.RULE, failopen.RULE, effectfirst.RULE):
            assert f["tool_confidence"] == "LOW" and f["rank"] == "medium" and f["scenario"]["kind"] != "generic"
