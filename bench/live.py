"""The live suite: the one place a real model provider is used on purpose.

No test and no ordinary benchmark reaches a model: they run with LANTERN_NO_REAL_PROVIDERS=1 and the network guard
(tools/netguard). The two scripts that measure a real model, bench/explain_eval.py and bench/ask_eval.py, go through
`gate` below, which starts nothing until the person running it has said on the command line:

  --live                  that a real provider is meant at all
  --model PROVIDER/MODEL  which one. There is no default here and no falling back to whatever key the shell holds
  --destination HOST      the one host the sample's code may be sent to; it must be where that model is served from
  --max-requests N        the spending cap: after N questions to the model the run stops and keeps what it has

and --send-this-code as well when the folder is not one of Lantern's own samples (tests/fixtures).

Once the run is approved it is isolated like every benchmark (tools/netguard): a temporary home folder, every key and
saved sign-in out of the environment (the approved provider is made first and holds its own key), and the network
refused except for the approved destination. Anything else that is tried is refused, listed, and fails the run.

    python bench/explain_eval.py tests/fixtures/shop --live --model lantern/claude-haiku-5-5 \\
        --destination lantern-gateway.fly.dev --max-requests 80

In CI this is the model-eval workflow, started by hand from the Actions tab with the same answers as its inputs.
tests/test_live.py runs the gate offline.
"""
from __future__ import annotations

import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

sys.path.insert(0, str(ROOT / "tools" / "netguard"))
import lantern_netguard as netguard  # noqa: E402

from lantern import providers  # noqa: E402

SAMPLES = ROOT / "tests" / "fixtures"
EXAMPLE = ("--live --model lantern/claude-haiku-5-5 --destination lantern-gateway.fly.dev --max-requests 80")


class NotApproved(Exception):
    """The run was not started: something a live run needs was not said. Nothing was sent anywhere."""


class SpendingCap(providers.AllowanceExhausted):
    """The run reached --max-requests. Like a used-up allowance, it stops the run and keeps what is finished."""


class Capped:
    """A provider that counts every question and stops at the cap. Everything else is the provider's own."""

    def __init__(self, provider, max_requests: int, guard=None):
        self._provider, self.max_requests, self.requests, self.guard = provider, max_requests, 0, guard

    def __getattr__(self, name):
        return getattr(self._provider, name)

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> str:
        if self.requests >= self.max_requests:
            raise SpendingCap(f"the spending cap of this live run is reached ({self.max_requests} requests): "
                              "stopped, nothing more was sent")
        self.requests += 1
        return self._provider.complete(system, user, max_tokens)


def add_arguments(ap) -> None:
    ap.add_argument("--live", action="store_true", help="really use a model provider (see bench/live.py)")
    ap.add_argument("--destination", metavar="HOST", help="the one host the code may be sent to")
    ap.add_argument("--max-requests", type=int, metavar="N", help="stop after N questions to the model")
    ap.add_argument("--send-this-code", action="store_true",
                    help="approve sending a folder that is not one of Lantern's own samples")


def served_from(provider) -> str:
    """The host a provider sends to. A stand-in that answers inside this process sends nowhere: `localhost`."""
    host = (urllib.parse.urlsplit(getattr(provider, "base_url", "") or "").hostname or "").lower()
    return host or ("localhost" if isinstance(provider, providers.FixtureProvider) else "")


def gate(a, project: Path) -> Capped:
    """The provider for a live run, capped. Raises NotApproved, having sent nothing, unless everything is said."""
    if not a.live:
        raise NotApproved("This measures a real model: it sends the sample's code to a model provider and spends "
                          f"money or allowance. Nothing was sent. To run it, say so:\n  {EXAMPLE}")
    missing = [flag for flag, value in (("--model PROVIDER/MODEL", a.model), ("--destination HOST", a.destination),
                                        ("--max-requests N", (a.max_requests or 0) > 0)) if not value]
    if missing:
        raise NotApproved("A live run also needs " + " and ".join(missing) + f". Nothing was sent.\n  {EXAMPLE}")
    destination = a.destination.strip().lower().rstrip(".")
    local = providers.on_this_computer(f"http://{destination}/")
    if providers.real_providers_off() and not local:
        raise NotApproved(f"Real model providers are switched off here ({providers.NO_REAL_ENV} is set, as it is in "
                          "every test and benchmark run). A live run is started on its own. Nothing was sent.")
    try:
        provider = providers.make_provider(a.model)
    except ValueError as e:
        raise NotApproved(f"{a.model}: {e}. Nothing was sent.") from None
    host = served_from(provider)
    if host != destination:
        raise NotApproved(f"{a.model} is served from {host or 'an address this script cannot read'}, and the "
                          f"approved destination is {destination}. Nothing was sent.")
    sample = project.resolve().is_relative_to(SAMPLES.resolve())
    if not sample and not a.send_this_code:
        raise NotApproved(f"{project} is not one of Lantern's own samples (tests/fixtures): its code would be sent "
                          f"to {host}. Add --send-this-code to approve that. Nothing was sent.")
    print(f"LIVE RUN: model {provider.label}, destination {host}, at most {a.max_requests} requests, data: the code "
          f"of {project} ({'a Lantern sample' if sample else 'approved with --send-this-code'})", file=sys.stderr)
    # From here the run is isolated like any benchmark: a temporary home folder, every key out of the environment (the
    # provider made above already holds its own, so no program this run starts has one), and the network refused
    # except for the one approved destination.
    guard = netguard.begin(allow=[] if local else [destination], live=True)
    return Capped(provider, a.max_requests, guard)


def finish(provider: Capped) -> int:
    """Last line of a live run. 1 when anything but the approved destination was tried (each attempt was refused and
    is listed), else 0."""
    return netguard.end(provider.guard)
