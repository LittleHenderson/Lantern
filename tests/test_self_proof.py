"""Proof written by the side whose word it is (lantern/selfproof.py): a thing marked paid or settled on a value
the caller handed in, and a check that asks for records the checked side may write itself. Examples of Lantern's
own, written after another review tool named both shapes in a project Lantern was measured on (none copied from
it). Each dangerous example stands beside safe twins and look-alikes."""
import textwrap

from lantern import selfproof
from lantern.engine import build_graph
from lantern.security import scan


def d(text: str) -> str:
    return textwrap.dedent(text).lstrip()


def py(text):
    return [(c["line"], c["function"]) for c in selfproof.read_py(text)]


def js(text):
    lines = text.splitlines()
    from lantern.websec import code_only
    code = code_only(text, True).splitlines()
    code += [""] * (len(lines) - len(code))
    got = selfproof.read_js(code, lines)
    return got and (got["line"] + 1, got["proof"])


# ---------------------------------------------------------------- the caller says it is done: dangerous

SQL_SETTLED = d('''
    def confirm_withdrawal(db, transfer_id, provider_tx_id):
        if not provider_tx_id:
            raise ValueError("provider_tx_id is required")
        db.execute(
            "UPDATE transfers SET status = 'SETTLED', provider_tx_id = ? WHERE id = ?",
            (str(provider_tx_id).strip(), transfer_id),
        )
        db.commit()
''')
ORM_PAID = d('''
    from flask import request

    def mark_order_paid(order):
        payment_intent_id = request.json["payment_intent_id"]
        order.payment_intent_id = payment_intent_id
        order.status = "paid"
        order.save()
''')
FLAG = d('''
    def record_receipt(invoice, receipt_number):
        invoice.receipt_number = receipt_number
        invoice.is_paid = True
        invoice.save()
''')
DICT_KEYWORD = d('''
    def settle(store, payout_id, body):
        store.update(payout_id, status="settled", bank_reference=body["bank_reference"])
''')
CONST_SQL = d('''
    def approve_charge(conn, charge_id, external_ref):
        sql = "UPDATE charges SET state = 'APPROVED', external_ref = %s WHERE id = %s"
        conn.execute(sql, (external_ref, charge_id))
''')

JS_PAID = d('''
    export async function POST(req) {
      const { orderId, paymentIntentId } = await req.json();
      await db.order.update({
        where: { id: orderId },
        data: { status: "paid", paymentIntentId },
      });
      return Response.json({ ok: true });
    }
''')
JS_EXPRESS = d('''
    app.post("/payouts/:id/settle", async (req, res) => {
      const providerTxId = req.body.providerTxId;
      await Payout.updateOne({ _id: req.params.id }, { status: "settled", providerTxId });
      res.json({ ok: true });
    });
''')


def test_a_thing_marked_done_on_a_value_the_caller_handed_in_is_found():
    assert py(SQL_SETTLED) == [(4, "confirm_withdrawal")]
    assert py(ORM_PAID) == [(6, "mark_order_paid")]
    assert py(FLAG) == [(3, "record_receipt")]
    assert py(DICT_KEYWORD) == [(2, "settle")]
    assert py(CONST_SQL) == [(3, "approve_charge")]
    assert js(JS_PAID) == (5, "paymentIntentId")
    assert js(JS_EXPRESS) == (3, "providerTxId")
    # looked up in its own table and written into its own audit trail: still only the caller's word
    audited = SQL_SETTLED.replace("    db.execute(\n", "    row = db.execute(\"SELECT status FROM transfers WHERE id = ?\", "
                                  "(transfer_id,)).fetchone()\n    db.execute(\n")
    audited = audited.replace("    db.commit()\n", "    _append_audit(db, \"SETTLED\", {\"provider_tx_id\": provider_tx_id})\n"
                              "    db.commit()\n")
    assert audited != SQL_SETTLED and py(audited) == [(5, "confirm_withdrawal")]
    a_document = d('''
        def write_bundle(out, stop_proof_ref):
            out.write({"approved": True, "stop": stop_proof_ref})
    ''')
    assert py(a_document) == []                              # a flag in a table written out marks no record


# ---------------------------------------------------------------- the caller says it is done: safe twins

def test_asking_the_provider_first_is_not():
    asked = ORM_PAID.replace("    order.payment_intent_id = payment_intent_id\n",
                             "    intent = stripe.PaymentIntent.retrieve(payment_intent_id)\n"
                             "    if intent.status != 'succeeded':\n        return\n"
                             "    order.payment_intent_id = payment_intent_id\n")
    assert py(asked) == []
    handed = SQL_SETTLED.replace('    db.execute(', '    bank.transfer_status_for(provider_tx_id)\n    db.execute(')
    assert py(handed) == []                                  # handed to something that may ask
    js_asked = JS_PAID.replace("  await db.order.update(",
                               "  const intent = await stripe.paymentIntents.retrieve(paymentIntentId);\n"
                               "  await db.order.update(")
    assert js(js_asked) is None


def test_look_alikes_are_not():
    pending = SQL_SETTLED.replace("'SETTLED'", "'PENDING_SETTLEMENT'")
    assert py(pending) == []                                 # not done
    no_proof = SQL_SETTLED.replace("provider_tx_id", "note")
    assert py(no_proof) == []                                # the value is no proof of an outside event
    webhook = SQL_SETTLED.replace("confirm_withdrawal", "handle_webhook")
    assert py(webhook) == []                                 # the provider's own message
    own = d('''
        def finish(order):
            order.status = "completed"
            order.save()
    ''')
    assert py(own) == []                                     # nothing from the caller at all
    unread = FLAG.replace("    invoice.receipt_number = receipt_number\n", "")
    assert py(unread) == []                                  # a proof parameter the function never reads
    failed = ORM_PAID.replace('"paid"', '"payment_failed"')
    assert py(failed) == []
    js_pending = JS_PAID.replace('"paid"', '"pending"')
    assert js(js_pending) is None
    js_no_proof = JS_EXPRESS.replace("providerTxId", "note")
    assert js(js_no_proof) is None


# ---------------------------------------------------------------- a check of records the checked side writes

WRITERS = d('''
    RUNNER_KINDS = frozenset({
        "JOB_STARTED",
        "REQUEST_SENT",
        "RESPONSE_CAPTURED",
        "JOB_FINISHED",
    })
''')
CHECK = d('''
    def verify_job(records):
        kinds = {r["kind"] for r in records}
        for need in ("REQUEST_SENT", "RESPONSE_CAPTURED", "CONTROLLER_SAW_SOCKET"):
            if need not in kinds:
                return False
        return True
''')


def test_a_check_that_asks_for_what_the_checked_side_writes_is_found():
    sets = selfproof.writer_sets(WRITERS)
    assert sets == {"RUNNER_KINDS": (1, {"JOB_STARTED", "REQUEST_SENT", "RESPONSE_CAPTURED", "JOB_FINISHED"})}
    assert [(n, line) for n, line, _ in selfproof.verifiers(CHECK)] == [("verify_job", 1)]


def _project(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return build_graph(tmp_path)


def test_self_written_proof_in_a_project(tmp_path):
    g = _project(tmp_path, {"app/runner.py": WRITERS, "app/checks.py": CHECK})
    got = selfproof.self_written(g)
    assert [(f["file"], f["line"]) for f in got] == [("app/checks.py", 1)]
    assert got[0]["self_proof"]["kinds"] == ["REQUEST_SENT", "RESPONSE_CAPTURED"]
    assert got[0]["self_proof"]["also"] == ["CONTROLLER_SAW_SOCKET"]


def test_self_written_proofs_twins_are_not(tmp_path):
    one = CHECK.replace('"RESPONSE_CAPTURED", ', "")
    assert selfproof.self_written(_project(tmp_path / "a", {"app/runner.py": WRITERS, "app/checks.py": one})) == []
    nothing_happened = CHECK.replace('"REQUEST_SENT", "RESPONSE_CAPTURED"', '"JOB_STARTED", "JOB_FINISHED"')
    assert selfproof.self_written(_project(tmp_path / "b", {"app/runner.py": WRITERS,
                                                            "app/checks.py": nothing_happened})) == []
    trusted = WRITERS.replace("RUNNER_KINDS", "CONTROLLER_KINDS")
    assert selfproof.self_written(_project(tmp_path / "c", {"app/runner.py": trusted, "app/checks.py": CHECK})) == []
    not_a_check = CHECK.replace("verify_job", "summarise_job")
    assert selfproof.self_written(_project(tmp_path / "d", {"app/runner.py": WRITERS,
                                                            "app/checks.py": not_a_check})) == []
    in_tests = selfproof.self_written(_project(tmp_path / "e", {"app/runner.py": WRITERS,
                                                                 "tests/test_checks.py": CHECK}))
    assert in_tests == []


# Four more shapes of the same problem, each a writer list and a check in files of their own, beside a twin.
MORE = [
    (d('''
        AGENT_RECORD_TYPES = ("TOOL_CALLED", "TOOL_RESULT", "AGENT_NOTE")
    '''), d('''
        def approve_task(log):
            seen = [e["type"] for e in log]
            return "TOOL_CALLED" in seen and "TOOL_RESULT" in seen
    '''), "approve_task"),
    (d('''
        class Queue:
            def __init__(self):
                self.worker_allowed = {"PAYMENT_SENT", "PAYMENT_CAPTURED", "HEARTBEAT"}
    '''), d('''
        def certify_payout(store, key):
            sent = store.get("PAYMENT_SENT", key)
            got = store.get("PAYMENT_CAPTURED", key)
            return sent is not None and got is not None
    '''), "certify_payout"),
    (d('''
        CLIENT_EVENTS = ["UPLOAD_STARTED", "UPLOAD_RECEIPT", "UPLOAD_CANCELLED"]
    '''), d('''
        def confirm_upload(events):
            kinds = {e.kind for e in events}
            if not {"UPLOAD_STARTED", "UPLOAD_RECEIPT"} <= kinds:
                raise ValueError("no proof")
            return True
    '''), "confirm_upload"),
    (d('''
        PLUGIN_TYPES = frozenset(["INSTALL_REQUESTED", "INSTALL_OBSERVED", "INSTALL_RESULT"])
    '''), d('''
        def validate_install(rows):
            got = {r["type"]: r for r in rows}
            return all(k in got for k in ("INSTALL_REQUESTED", "INSTALL_OBSERVED"))
    '''), "validate_install"),
]


def test_four_more_shapes_are_found_and_their_twins_are_not(tmp_path):
    for i, (writers, check, name) in enumerate(MORE):
        got = selfproof.self_written(_project(tmp_path / f"bad{i}", {"app/sides.py": writers, "app/checks.py": check}))
        assert [f["title"].split("`")[1] for f in got] == [name], name
        # twin: the check also asks for a record that a list of the trusted side names
        trusted = 'CONTROLLER_KINDS = {"CONTROLLER_SAW_IT", "CONTROLLER_CLOCK"}\n'
        lines = check.splitlines()
        lines.insert(1, '    _ = "CONTROLLER_SAW_IT"')
        twin = "\n".join(lines) + "\n"
        assert selfproof.self_written(_project(tmp_path / f"twin{i}", {"app/sides.py": writers + trusted,
                                                                       "app/checks.py": twin})) == [], name
        # look-alike: the same check under a name that checks nothing
        plain = check.replace(name, "summarise_" + str(i))
        assert selfproof.self_written(_project(tmp_path / f"plain{i}", {"app/sides.py": writers,
                                                                        "app/checks.py": plain})) == [], name


def test_the_first_example_is_quiet_where_the_trusted_side_writes_its_own_record(tmp_path):
    trusted = 'CONTROLLER_KINDS = frozenset({"CONTROLLER_SAW_SOCKET", "CONTROLLER_TICK"})\n'
    got = selfproof.self_written(_project(tmp_path, {"app/runner.py": WRITERS, "app/controller.py": trusted,
                                                     "app/checks.py": CHECK}))
    assert got == []


# ---------------------------------------------------------------- both in a whole check

def test_both_run_in_a_check_and_skip_test_code(tmp_path):
    g = _project(tmp_path, {"app/payouts.py": SQL_SETTLED, "web/api/pay.ts": JS_PAID, "app/runner.py": WRITERS,
                            "app/checks.py": CHECK, "tests/test_payouts.py": SQL_SETTLED})
    found = scan(g, offline=True)["findings"]
    got = {(f["rule"], f["file"]) for f in found if f["rule"] in (selfproof.CALLER_RULE, selfproof.WRITER_RULE)}
    assert got == {(selfproof.CALLER_RULE, "app/payouts.py"), (selfproof.CALLER_RULE, "web/api/pay.ts"),
                   (selfproof.WRITER_RULE, "app/checks.py")}
    for f in found:
        if f["rule"] in (selfproof.CALLER_RULE, selfproof.WRITER_RULE):
            assert f["tool_confidence"] == "LOW" and f["rank"] == "medium" and f["scenario"]["kind"] != "generic"
