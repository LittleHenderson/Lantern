"""A request that is under way counts against the allowance's limits.

The gateway looked at the counters, asked the model, and counted the request when the answer was back (until
2026-11-15). The counters then held finished requests only: requests sent at the same moment all saw the same
room, all of them went to the model, and a person's allowance, the day's limit and the day's budget for everyone
were passed by as many requests as were sent together. A request is now counted as under way before the model is
asked, in the same step as the look at the limits, and the count is put right when the answer is back.

A request that does not fit beside those under way is told "in a moment" (429, `allowance_busy`), not "used up":
one of them may end uncounted or take less than was held for it. Once they are counted it is told what is true.

Each case has its twin: requests sent together that fit are all answered and counted once each.
"""
import asyncio
import sys
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gateway"))

from lantern_gateway.app import Settings, create_app  # noqa: E402

ADMIN = "admin-" + "x" * 20
BODY = {"model": "anything", "max_tokens": 99999,
        "messages": [{"role": "system", "content": "json please"}, {"role": "user", "content": "explain f"}]}
IN, OUT = 700, 1100                 # the tokens the stand-in model says one answer took


class Model:
    """A stand-in model: counts the requests that reached it and answers none until the test opens the gate."""

    def __init__(self, status: int = 200):
        self.calls, self.status, self.gate = 0, status, None

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        await self.gate.wait()
        if self.status != 200:
            return httpx.Response(self.status, json={"error": "no"})
        return httpx.Response(200, json={
            "id": "c1", "model": "deepseek-flash",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "{}"}}],
            "usage": {"prompt_tokens": IN, "completion_tokens": OUT}})


def _gateway(tmp_path, model: Model, **over):
    base = dict(primary="deepseek", deepseek_url="https://upstream.test", deepseek_key="sk-" + "o" * 12,
                deepseek_model="deepseek-flash", admin_secret=ADMIN, db_path=str(tmp_path / "g.db"),
                free_requests=100, free_tokens=10_000_000, daily_requests=100, global_daily_usd=5.0)
    return create_app(Settings(**{**base, **over}), transport=httpx.MockTransport(model))


def _client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


async def _token(client) -> dict:
    r = await client.post("/v1/tokens", json={"label": "tester"}, headers={"authorization": f"Bearer {ADMIN}"})
    return {"authorization": "Bearer " + r.json()["token"]}


async def _together(client, model: Model, who: dict, n: int) -> tuple[list, int]:
    """`n` requests of one person at the same moment. The model answers none of them until each has either reached
    it or been turned away. Gives the answers and how many of them reached the model."""
    model.gate, before = asyncio.Event(), model.calls
    tasks = [asyncio.create_task(client.post("/v1/chat/completions", json=BODY, headers=who)) for _ in range(n)]
    for _ in range(4000):
        if model.calls - before + sum(t.done() for t in tasks) >= n:
            break
        await asyncio.sleep(0.005)
    reached = model.calls - before
    model.gate.set()
    return list(await asyncio.gather(*tasks)), reached


async def _used(client, who: dict) -> dict:
    return (await client.get("/v1/allowance", headers=who)).json()


def _said(answer) -> tuple[int, str]:
    return answer.status_code, "" if answer.status_code == 200 else answer.json()["error"]["type"]


BUSY = (429, "allowance_busy")
# the limit, how many of six fit, and what one more request is told once those are answered and counted
# (3,000 tokens: one answer took 1,800 of them, so one more request still fits)
LIMITS = [({"free_requests": 2}, 2, (402, "quota_exceeded")), ({"daily_requests": 2}, 2, (402, "daily_limit")),
          ({"free_tokens": 3000}, 1, (200, "")), ({"global_daily_usd": 1e-9}, 1, (503, "allowance_paused"))]


@pytest.mark.parametrize("limit, fit, after", LIMITS, ids=[next(iter(row[0])) for row in LIMITS])
def test_requests_sent_together_do_not_pass_a_limit(limit, fit, after, tmp_path):
    """Before: all six reached the model, whatever the limit."""
    async def main():
        model = Model()
        async with _client(_gateway(tmp_path, model, **limit)) as client:
            who = await _token(client)
            answers, reached = await _together(client, model, who, 6)
            assert reached == fit, f"{reached} requests reached the model where {fit} fit"
            assert sorted(_said(a) for a in answers) == sorted([(200, "")] * fit + [BUSY] * (6 - fit))
            assert all(a.headers["retry-after"] == "2" for a in answers if a.status_code == 429)
            used = await _used(client, who)
            assert (used["used_requests"], used["used_tokens"]) == (fit, fit * (IN + OUT))    # what the answers took
            answers, reached = await _together(client, model, who, 1)
            assert (_said(answers[0]), reached) == (after, int(after[0] == 200))
    asyncio.run(main())


def test_somebody_whose_allowance_is_used_is_told_so_also_while_a_request_is_under_way(tmp_path):
    """The twin of "in a moment": what the finished requests alone show is said as before."""
    async def main():
        model = Model()
        async with _client(_gateway(tmp_path, model, free_requests=1)) as client:
            who = await _token(client)
            await _together(client, model, who, 1)
            answers, reached = await _together(client, model, who, 3)
            assert reached == 0 and [_said(a) for a in answers] == [(402, "quota_exceeded")] * 3
    asyncio.run(main())


def test_requests_sent_together_that_fit_are_all_answered_and_counted_once(tmp_path):
    """The twin: six at once with room for six."""
    async def main():
        model = Model()
        async with _client(_gateway(tmp_path, model)) as client:
            who = await _token(client)
            answers, reached = await _together(client, model, who, 6)
            assert reached == 6 and [a.status_code for a in answers] == [200] * 6
            used = await _used(client, who)
            assert (used["used_requests"], used["used_tokens"]) == (6, 6 * (IN + OUT))
            assert used["remaining_today"] == 100 - 6 and used["remaining_requests"] == 100 - 6
            # and one after them is answered as any other
            answers, reached = await _together(client, model, who, 1)
            assert answers[0].status_code == 200 and (await _used(client, who))["used_requests"] == 7
    asyncio.run(main())


def test_two_people_do_not_stand_in_each_others_way(tmp_path):
    """One person's requests under way are not counted against another's allowance."""
    async def main():
        model = Model()
        async with _client(_gateway(tmp_path, model, free_requests=1)) as client:
            one, two = await _token(client), await _token(client)
            model.gate = asyncio.Event()
            tasks = [asyncio.create_task(client.post("/v1/chat/completions", json=BODY, headers=w)) for w in (one, two)]
            for _ in range(4000):
                if model.calls >= 2:
                    break
                await asyncio.sleep(0.005)
            model.gate.set()
            assert [a.status_code for a in await asyncio.gather(*tasks)] == [200, 200]
    asyncio.run(main())


def test_a_request_the_model_did_not_answer_is_not_counted(tmp_path):
    """While two are under way a third is told "in a moment"; when the model answered neither, neither is counted,
    and the next request is let through: "used up" would have been untrue."""
    async def main():
        model = Model(status=500)
        async with _client(_gateway(tmp_path, model, free_requests=2)) as client:
            who = await _token(client)
            answers, reached = await _together(client, model, who, 3)
            assert reached == 2 and sorted(a.status_code for a in answers) == [429, 502, 502]
            assert (await _used(client, who))["used_requests"] == 0
            model.status = 200
            answers, reached = await _together(client, model, who, 1)
            assert answers[0].status_code == 200 and (await _used(client, who))["used_requests"] == 1
    asyncio.run(main())


def test_a_request_that_was_let_through_and_cut_off_is_counted(tmp_path):
    """A request that reached the model and was cut off before the answer came back was the model's work all the
    same. Before: it was counted nowhere."""
    async def main():
        model = Model()
        async with _client(_gateway(tmp_path, model)) as client:
            who = await _token(client)
            model.gate = asyncio.Event()
            task = asyncio.create_task(client.post("/v1/chat/completions", json=BODY, headers=who))
            for _ in range(4000):
                if model.calls:
                    break
                await asyncio.sleep(0.005)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            used = await _used(client, who)
            assert used["used_requests"] == 1 and used["used_tokens"] > 0
            assert used["remaining_today"] == 100 - 1
    asyncio.run(main())
