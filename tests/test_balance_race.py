"""`LW-NONATOMIC-BALANCE`: a balance read in one step and taken from in another (roadmap of 2026-11-14, stage 5).

A function that reads a balance (credits, points, coins, a wallet's money, stock), checks that there is enough, and
then writes the balance down taken away, as its own step to the database, holds for one request at a time: two
requests sent at the same moment both read the same balance, both pass the check, and both are taken from it. The
balance goes below zero, or one take is lost and the second spend is free. What stops it: the write itself names the
condition (`update … where credits >= cost`, and how many rows it changed is looked at), or the row is locked between
the read and the write (`SELECT … FOR UPDATE`, `select_for_update()`, `with_for_update()`), or, as the roadmap asks, the
read and the write stand in one transaction.

A heuristic (it reads one function's own lines and does not know that the check and the write are about the same
record: they share a name), so each dangerous example stands beside twins that must stay quiet. Nothing here is run.
"""
import time

from lantern import balance
from lantern.engine import build_graph
from lantern.security import scan

RULE = "LW-NONATOMIC-BALANCE"

WALLET_JS = """const express = require('express');
const { prisma, pool, supabase, Account, db, openai, dataSource, User, knex } = require('./things');

const app = express();

// ---- dangerous: the balance is read, checked, then written down taken away as a step of its own
async function spend(req, res) {
  const user = await prisma.user.findUnique({ where: { id: req.userId } });
  if (user.credits < req.body.cost) {
    return res.status(402).json({ error: 'Not enough credits' });
  }
  await prisma.user.update({ where: { id: user.id }, data: { credits: user.credits - req.body.cost } });
  res.json({ ok: true });
}

async function redeem(req, res) {
  const wallet = await prisma.wallet.findFirst({ where: { ownerId: req.userId } });
  if (wallet.balance >= req.body.amount) {
    await prisma.wallet.update({ where: { id: wallet.id }, data: { balance: { decrement: req.body.amount } } });
    return res.json({ ok: true });
  }
  res.status(402).json({ error: 'Not enough' });
}

async function take(req, res) {
  const account = await Account.findById(req.params.id);
  const left = account.points - req.body.points;
  if (left < 0) {
    return res.status(409).json({ error: 'Not enough points' });
  }
  account.points = left;
  await account.save();
  res.json({ left });
}

async function buy(req, res) {
  const { data: profile } = await supabase.from('profiles').select('coins').eq('id', req.userId).single();
  if (!profile || profile.coins < 10) {
    return res.status(402).json({ error: 'Not enough coins' });
  }
  await supabase.from('profiles').update({ coins: profile.coins - 10 }).eq('id', req.userId);
  res.json({ ok: true });
}

async function withdraw(req, res) {
  const { rows } = await pool.query('SELECT balance FROM accounts WHERE id = $1', [req.userId]);
  if (rows[0].balance < req.body.amount) {
    return res.status(400).json({ error: 'Insufficient funds' });
  }
  await pool.query('UPDATE accounts SET balance = balance - $1 WHERE id = $2', [req.body.amount, req.userId]);
  res.json({ ok: true });
}

async function spendThenBatch(req, res) {
  const user = await prisma.user.findUnique({ where: { id: req.userId } });
  if (user.credits < 1) {
    return res.status(402).json({ error: 'No credits' });
  }
  await prisma.$transaction([
    prisma.user.update({ where: { id: user.id }, data: { credits: { decrement: 1 } } }),
    prisma.image.create({ data: { ownerId: user.id } }),
  ]);
  res.json({ ok: true });
}

async function spendSpread(req, res) {
  const user = await prisma.user.findUnique({ where: { id: req.userId } });
  if (user.credits === 0) {
    return res.status(402).json({ error: 'No credits left' });
  }
  await prisma.user.update({
    where: { id: user.id },
    data: { credits: { decrement: 1 } },
  });
  res.json(await openai.chat.completions.create({ model: 'm', messages: req.body.messages }));
}

// a value worked out from the balance that was read, written back under a condition that only bounds the balance:
// two requests both pass the bound and both write the same value, so one spend is free
async function spendBounded(req, res) {
  const user = await prisma.user.findUnique({ where: { id: req.userId } });
  if (user.credits < req.body.amount) return res.status(402).json({ error: 'Not enough credits' });
  const took = await prisma.user.updateMany({
    where: { id: user.id, credits: { gte: req.body.amount } },
    data: { credits: user.credits - req.body.amount },
  });
  res.json({ ok: took.count === 1 });
}

async function spendSupabaseChecked(req, res) {
  const { data: profile } = await supabase.from('profiles').select('coins').eq('id', req.userId).single();
  if (profile.coins < 50) return res.status(402).json({ error: 'Not enough coins' });
  await supabase.from('profiles').update({ coins: profile.coins - 50 }).eq('id', req.userId).gte('coins', 50);
  res.json({ ok: true });
}

// ---- safe: the write names the condition, a lock or a transaction holds the row, nothing is taken away
async function spendSafely(req, res) {
  const user = await prisma.user.findUnique({ where: { id: req.userId } });
  if (user.credits < req.body.price) {
    return res.status(402).json({ error: 'Not enough credits' });
  }
  const took = await prisma.user.updateMany({
    where: { id: user.id, credits: { gte: req.body.price } },
    data: { credits: { decrement: req.body.price } },
  });
  res.json({ ok: took.count === 1 });
}

async function spendInTransaction(req, res) {
  await prisma.$transaction(async (tx) => {
    const user = await tx.user.findUnique({ where: { id: req.userId } });
    if (user.credits < req.body.fee) throw new Error('Not enough credits');
    await tx.user.update({ where: { id: user.id }, data: { credits: { decrement: req.body.fee } } });
  });
  res.json({ ok: true });
}

async function spendMongo(req, res) {
  const user = await db.collection('users').findOne({ _id: req.userId });
  if (user.credits < 1) return res.status(402).json({ error: 'No credits' });
  const r = await db.collection('users').updateOne({ _id: req.userId, credits: { $gte: 1 } }, { $inc: { credits: -1 } });
  res.json({ ok: r.modifiedCount === 1 });
}

async function spendRpc(req, res) {
  const { data: profile } = await supabase.from('profiles').select('coins').eq('id', req.userId).single();
  if (profile.coins < 25) return res.status(402).json({ error: 'Not enough coins' });
  await supabase.rpc('spend_coins', { amount: 25 });
  res.json({ ok: true });
}

async function spendSupabaseOptimistic(req, res) {
  const { data: profile } = await supabase.from('profiles').select('coins').eq('id', req.userId).single();
  if (profile.coins < 60) return res.status(402).json({ error: 'Not enough coins' });
  const { data: changed } = await supabase.from('profiles').update({ coins: profile.coins - 60 })
    .eq('id', req.userId)
    .eq('coins', profile.coins)
    .gte('coins', 60)
    .select();
  res.json({ ok: changed.length === 1 });
}

async function spendEquals(req, res) {
  const user = await prisma.user.findUnique({ where: { id: req.userId } });
  if (user.credits < req.body.size) return res.status(402).json({ error: 'Not enough credits' });
  const took = await prisma.user.updateMany({
    where: { id: user.id, credits: { equals: user.credits, gte: req.body.size } },
    data: { credits: user.credits - req.body.size },
  });
  res.json({ ok: took.count === 1 });
}

async function spendKnex(req, res) {
  const user = await knex('users').where({ id: req.userId }).first();
  if (user.credits < req.body.fee) return res.status(402).json({ error: 'Not enough credits' });
  const changed = await knex('users').where({ id: user.id }).andWhere('credits', '>=', req.body.fee)
    .update({ credits: knex.raw('credits - ?', [req.body.fee]) });
  res.json({ ok: changed === 1 });
}

async function spendQueryBuilder(req, res) {
  const user = await dataSource.getRepository(User).findOneBy({ id: req.userId });
  if (user.credits < req.body.units) return res.status(402).json({ error: 'Not enough credits' });
  const r = await dataSource.createQueryBuilder().update(User)
    .set({ credits: () => 'credits - :units' })
    .where('id = :id AND credits >= :units', { id: user.id, units: req.body.units })
    .execute();
  res.json({ ok: r.affected === 1 });
}

async function spendOptimistic(req, res) {
  const user = await prisma.user.findUnique({ where: { id: req.userId } });
  if (user.credits < req.body.count) return res.status(402).json({ error: 'Not enough credits' });
  const took = await prisma.user.updateMany({ where: { id: user.id, credits: user.credits }, data: { credits: user.credits - req.body.units } });
  res.json({ ok: took.count === 1 });
}

async function topUp(req, res) {
  const user = await prisma.user.findUnique({ where: { id: req.userId } });
  if (user.credits > 1000) return res.status(400).json({ error: 'Too many credits' });
  await prisma.user.update({ where: { id: user.id }, data: { credits: { increment: req.body.amount } } });
  res.json({ ok: true });
}

async function show(req, res) {
  const user = await prisma.user.findUnique({ where: { id: req.userId } });
  if (user.credits < 5) {
    res.set('X-Low-Credits', '1');
  }
  res.json({ credits: user.credits });
}

async function withdrawSafely(req, res) {
  const { rows } = await pool.query('SELECT balance FROM accounts WHERE id = $1', [req.userId]);
  if (rows[0].balance < req.body.sum) return res.status(400).json({ error: 'Insufficient funds' });
  const r = await pool.query('UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND balance >= $1', [req.body.sum, req.userId]);
  res.json({ ok: r.rowCount === 1 });
}

async function stamp(req, res) {
  const user = await prisma.user.findUnique({ where: { id: req.userId } });
  if (user.credits <= 0) return res.status(402).json({ error: 'No credits' });
  await prisma.user.update({ where: { id: user.id }, data: { lastSeen: new Date() } });
  res.json({ ok: true });
}

async function withdrawLocked(req, res) {
  const client = await pool.connect();
  await client.query('BEGIN');
  const { rows } = await client.query('SELECT balance FROM accounts WHERE id = $1 FOR UPDATE', [req.userId]);
  if (rows[0].balance < req.body.total) { await client.query('ROLLBACK'); return res.status(400).end(); }
  await client.query('UPDATE accounts SET balance = balance - $1 WHERE id = $2', [req.body.total, req.userId]);
  await client.query('COMMIT');
  client.release();
  res.json({ ok: true });
}

function spendInMemory(wallets, id, cost) {
  const w = wallets.get(id);
  if (w.balance < cost) throw new Error('Not enough');
  w.balance -= cost;
  return w.balance;
}

// ---- the limit looked at before the work and counted after it: the other rule's finding, not listed twice
async function ask(req, res) {
  const user = await db.user.findUnique({ where: { id: req.userId } });
  if (user.credits <= 0) {
    return res.status(402).json({ error: 'No credits left' });
  }
  const answer = await openai.chat.completions.create({ model: 'm', messages: req.body.messages });
  await db.user.update({ where: { id: user.id }, data: { credits: { decrement: 1 } } });
  res.json(answer);
}

app.post('/spend', spend);
app.post('/redeem', redeem);
app.post('/take/:id', take);
app.post('/buy', buy);
app.post('/withdraw', withdraw);
app.post('/batch', spendThenBatch);
app.post('/spend-spread', spendSpread);
app.post('/spend-bounded', spendBounded);
app.post('/spend-safely', spendSafely);
app.post('/spend-tx', spendInTransaction);
app.post('/spend-mongo', spendMongo);
app.post('/spend-rpc', spendRpc);
app.post('/spend-checked', spendSupabaseChecked);
app.post('/spend-optimistic-coins', spendSupabaseOptimistic);
app.post('/spend-query-builder', spendQueryBuilder);
app.post('/spend-equals', spendEquals);
app.post('/spend-knex', spendKnex);
app.post('/spend-optimistic', spendOptimistic);
app.post('/top-up', topUp);
app.get('/show', show);
app.post('/withdraw-safely', withdrawSafely);
app.post('/stamp', stamp);
app.post('/withdraw-locked', withdrawLocked);
app.post('/ask', ask);

module.exports = { app, spendInMemory };
"""

BILLING_PY = '''from django.db import transaction
from django.db.models import F
from django.http import JsonResponse
from flask import Flask, abort, request
from sqlalchemy import update

from .models import Profile, User, client, current_user_id, db, users

app = Flask(__name__)


# ---- dangerous
@app.post("/spend")
def spend():
    user = db.session.get(User, current_user_id())
    if user.credits < request.json["cost"]:
        abort(402)
    user.credits -= request.json["cost"]
    db.session.commit()
    return {"ok": True}


def redeem(request):
    profile = Profile.objects.get(user=request.user)
    if profile.points < 100:
        return JsonResponse({"error": "Not enough points"}, status=402)
    profile.points = profile.points - 100
    profile.save()
    return JsonResponse({"ok": True})


def redeem_f(request):
    profile = Profile.objects.get(user=request.user)
    if profile.points < 200:
        return JsonResponse({"error": "Not enough points"}, status=402)
    Profile.objects.filter(pk=profile.pk).update(points=F("points") - 200)
    return JsonResponse({"ok": True})


def use_credit(con, user_id):
    (credits,) = con.execute("SELECT credits FROM users WHERE id = ?", (user_id,)).fetchone()
    if credits <= 0:
        raise ValueError("no credits left")
    con.execute("UPDATE users SET credits = credits - 1 WHERE id = ?", (user_id,))
    con.commit()


def redeem_bounded(request):
    profile = Profile.objects.get(user=request.user)
    if profile.points < 700:
        return JsonResponse({"error": "Not enough points"}, status=402)
    taken = Profile.objects.filter(pk=profile.pk, points__gte=700).update(points=profile.points - 700)
    return JsonResponse({"ok": taken == 1})


@app.post("/spend-bounded")
def spend_bounded():
    user = db.session.get(User, current_user_id())
    if user.credits < 2:
        abort(402)
    done = db.session.execute(update(User).where(User.id == user.id, User.credits >= 2).values(credits=user.credits - 2))
    db.session.commit()
    return {"ok": done.rowcount == 1}


# ---- safe
@app.post("/spend-locked")
def spend_locked():
    user = db.session.query(User).filter_by(id=current_user_id()).with_for_update().one()
    if user.credits < request.json["price"]:
        abort(402)
    user.credits -= request.json["price"]
    db.session.commit()
    return {"ok": True}


def redeem_locked(request):
    with transaction.atomic():
        profile = Profile.objects.select_for_update().get(user=request.user)
        if profile.points < 300:
            return JsonResponse({"error": "Not enough points"}, status=402)
        profile.points -= 300
        profile.save()
    return JsonResponse({"ok": True})


def redeem_checked_twice(request):
    profile = Profile.objects.get(user=request.user)
    if profile.points < 400:
        return JsonResponse({"error": "Not enough points"}, status=402)
    taken = Profile.objects.filter(pk=profile.pk, points__gte=400).update(points=F("points") - 400)
    return JsonResponse({"ok": taken == 1})


@app.post("/spend-once")
def spend_once():
    user = db.session.get(User, current_user_id())
    if user.credits < 1:
        abort(402)
    done = db.session.execute(update(User).where(User.id == user.id, User.credits >= 1).values(credits=User.credits - 1))
    db.session.commit()
    return {"ok": done.rowcount == 1}


def redeem_optimistic(request):
    profile = Profile.objects.get(user=request.user)
    if profile.points < 800:
        return JsonResponse({"error": "Not enough points"}, status=402)
    taken = Profile.objects.filter(pk=profile.pk, points=profile.points).update(points=profile.points - 800)
    return JsonResponse({"ok": taken == 1})


@app.post("/spend-core")
def spend_core():
    user = db.session.get(User, current_user_id())
    if user.credits < 3:
        abort(402)
    done = db.session.execute(update(users).where(users.c.id == user.id, users.c.credits >= 3)
                              .values(credits=users.c.credits - 3))
    db.session.commit()
    return {"ok": done.rowcount == 1}


def use_credit_safely(con, user_id):
    (credits,) = con.execute("SELECT credits FROM users WHERE id = ?", (user_id,)).fetchone()
    if credits < 1:
        raise ValueError("no credits left")
    cur = con.execute("UPDATE users SET credits = credits - 1 WHERE id = ? AND credits > 0", (user_id,))
    con.commit()
    return cur.rowcount == 1


def preview(user, cost):
    if user.credits < cost:
        return None
    user.credits -= cost
    return user.credits


# ---- the limit looked at before the work and counted after it: the other rule's finding, not listed twice
@app.post("/draw")
def draw():
    user = db.session.get(User, current_user_id())
    if user.credits <= 0:
        abort(402)
    image = client.images.generate(prompt=request.json["prompt"])
    user.credits -= 1
    db.session.commit()
    return {"url": image.url}
'''

ATOMIC_PY = '''from django.db import transaction
from django.http import JsonResponse

from .models import Profile


@transaction.atomic
def redeem_atomic(request):
    profile = Profile.objects.get(user=request.user)
    if profile.points < 500:
        return JsonResponse({"error": "Not enough points"}, status=402)
    profile.points -= 500
    profile.save()
    return JsonResponse({"ok": True})


def redeem_alone(request):
    profile = Profile.objects.get(user=request.user)
    if profile.points < 600:
        return JsonResponse({"error": "Not enough points"}, status=402)
    profile.points -= 600
    profile.save()
    return JsonResponse({"ok": True})
'''

FILES = {"api/package.json": '{"dependencies": {"express": "^4.19.0"}}', "api/wallet.js": WALLET_JS,
         "server/__init__.py": "", "server/billing.py": BILLING_PY, "server/atomic.py": ATOMIC_PY}


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
    return root


def _at(text: str, line: str) -> int:
    """The line number of the one line of `text` that reads `line` (leading and trailing space aside)."""
    lines = [x.strip() for x in text.split("\n")]
    assert lines.count(line) == 1, line
    return lines.index(line) + 1


def _found(root):
    all_of = scan(build_graph(root))["findings"]
    return all_of, sorted((f["file"], f["line"], f["snippet"]) for f in all_of if f["rule"] == RULE)


def test_a_balance_read_then_taken_from_as_a_step_of_its_own_is_named_and_its_safe_twins_are_not(tmp_path):
    """Dangerous: Prisma writing back a value worked out from what was read, Prisma's decrement after the check
    (also with the check as a guard around the write), a value worked out first and checked under another name, a
    Mongoose document saved, Supabase, SQL that takes away with no condition, a check outside the transaction the
    write is in, a take written over several lines before the work (the older limit check read it as a count after
    the work, from the `decrement:` line inside the take; it is this rule's); a value worked out from what was read
    and written back under a condition that only bounds the balance (Prisma's `gte`, Supabase's `.gte`, Django's
    `__gte`, SQLAlchemy's `>=`): both requests pass the bound and write the same value, so one spend is free (the
    first version of this test had Supabase's `.gte` among the safe twins: that was wrong, corrected here); in
    Python: SQLAlchemy's object committed, Django's object saved, Django's `F()` with no condition, SQLite. Safe
    twins: the write takes from the stored value under its own condition (Prisma's `where` with `decrement`,
    MongoDB's filter with `$inc`, SQL's `SET … = … - $1 WHERE … >=`, Django's `__gte` with `F()`, SQLAlchemy's
    `.where(… >= …)` with the column itself, also SQLAlchemy Core's `users.c.credits`, a query builder whose condition
    is written as SQL text, knex's `andWhere` with `knex.raw('credits - ?')`), the write is held to the value that was
    read (Prisma's `credits: user.credits` and `{ equals: user.credits }` beside a bound, Supabase's
    `.eq('coins', profile.coins)` on a line of its own in a chain and beside a bound, Django's
    `points=profile.points`), the read and the write in a transaction, the
    row locked (`FOR UPDATE`, `with_for_update()`, `select_for_update()`), a function of the database does the work,
    nothing is taken away (a top-up), another field is written, the balance is only looked at, an object of the
    program's own that is never saved. Where the other rule names the check (a limit looked at before the work and
    counted after it), it is not named twice."""
    all_of, found = _found(_write(tmp_path, FILES))
    js, py = "api/wallet.js", "server/billing.py"
    expected = [(js, line) for line in ("if (user.credits < req.body.cost) {", "if (wallet.balance >= req.body.amount) {",
                                        "if (left < 0) {", "if (!profile || profile.coins < 10) {",
                                        "if (rows[0].balance < req.body.amount) {", "if (user.credits < 1) {",
                                        "if (user.credits === 0) {",
                                        "if (user.credits < req.body.amount) return res.status(402).json({ error: "
                                        "'Not enough credits' });",
                                        "if (profile.coins < 50) return res.status(402).json({ error: 'Not enough "
                                        "coins' });")]
    expected += [(py, line) for line in ('if user.credits < request.json["cost"]:', "if profile.points < 100:",
                                         "if profile.points < 200:", "if credits <= 0:", "if profile.points < 700:",
                                         "if user.credits < 2:")]
    expected += [("server/atomic.py", "if profile.points < 600:")]
    text = {js: WALLET_JS, py: BILLING_PY, "server/atomic.py": ATOMIC_PY}
    assert found == sorted((f, _at(text[f], line), line) for f, line in expected), found
    later = sorted((f["file"], f["snippet"]) for f in all_of if f["rule"] == "LW-LIMIT-COUNTED-LATER")
    assert later == [(js, "if (user.credits <= 0) {"), (py, "if user.credits <= 0:")], later
    one = next(f for f in all_of if f["rule"] == RULE and f["file"] == js and f["snippet"].startswith("if (user.cr"))
    assert one["tool_confidence"] == "LOW" and one["rank"] == "medium" and one["cwe"] == 362
    assert one["category"] == "code" and one["more_info"].startswith("Heuristic")
    assert "`spend`" in one["title"], one["title"]
    write = _at(WALLET_JS, "await prisma.user.update({ where: { id: user.id }, data: { credits: user.credits - "
                           "req.body.cost } });")
    assert one["balance"] == {"field": "credits", "check": one["line"], "write": write, "how": "update"}, one["balance"]
    assert f"line {write}" in one["more_info"] and "`credits`" in one["more_info"], one["more_info"]
    story = one["scenario"]
    assert "at the same moment" in " ".join(story["steps"]) and "below zero" in story["harm"], story
    assert one["case"]["claim"].endswith("whether the check and the write are about the same record is not checked."), \
        one["case"]["claim"]


def test_inside_a_transaction_it_says_nothing_as_the_roadmap_asks(tmp_path):
    """The roadmap asks for this rule outside a transaction. A transaction at the database's usual isolation level
    (PostgreSQL's read committed) does not by itself stop two requests from reading the same balance: the rule is
    quiet there, the wrong way, and its documents say so. A function the transaction is not around is named."""
    _all, found = _found(_write(tmp_path, {"server/__init__.py": "", "server/atomic.py": ATOMIC_PY}))
    assert found == [("server/atomic.py", _at(ATOMIC_PY, "if profile.points < 600:"), "if profile.points < 600:")]


def test_nothing_is_said_of_test_code_and_of_examples(tmp_path):
    """Test files and the examples of a project's documents are not the app."""
    _all, found = _found(_write(tmp_path, {"tests/test_wallet.py": BILLING_PY.replace("from .models", "from models"),
                                           "docs/example.py": BILLING_PY, "docs/wallet.js": WALLET_JS}))
    assert found == []


def test_a_function_built_to_hold_the_check_up_is_read_in_bounded_time(tmp_path):
    """Thousands of checks of a balance, each followed by many writes that are not about it."""
    body = "".join(f"    if user.credits < {i}:\n        return {i}\n    user.note{i} = {i}\n"
                   for i in range(3000))
    _write(tmp_path, {"app/__init__.py": "", "app/api.py": "def spend(user, db):\n" + body + "    db.commit()\n"})
    g = build_graph(tmp_path)
    began = time.monotonic()
    assert balance.taken_apart(g, set()) == []
    assert time.monotonic() - began < 5
