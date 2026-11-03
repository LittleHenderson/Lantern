"""Sleep when nobody is using it, so a host that bills by the running second (Fly.io) costs almost nothing.

After `minutes` with no request and no run in progress, the service stops itself (SIGTERM to its own process, the
same as a normal shutdown). On Fly the machine then stays stopped until the next visitor, whose request starts it
again in a few seconds (`auto_start_machines = true`, restart policy `on-failure`). A run is never cut short by this:
the check waits while any run is queued or running. `LANTERN_CLOUD_IDLE_MINUTES=0` (the default) turns it off.
"""

from __future__ import annotations

import os
import signal
import threading
import time


class IdleExit:
    def __init__(self, minutes: float, busy, stop=None, every: float = 30.0):
        self.limit = minutes * 60
        self.busy = busy                       # () -> bool: a run is queued or running
        self.stop = stop or (lambda: os.kill(os.getpid(), signal.SIGTERM))
        self.every = every
        self.last = time.monotonic()
        self.stopped = False

    def touch(self) -> None:
        self.last = time.monotonic()

    def check(self) -> bool:
        """Stop when idle long enough; True when it did."""
        if self.stopped or self.limit <= 0:
            return False
        if self.busy():
            self.touch()
            return False
        if time.monotonic() - self.last >= self.limit:
            self.stopped = True
            self.stop()
            return True
        return False

    def start(self) -> None:
        if self.limit <= 0:
            return

        def loop():
            while not self.stopped:
                time.sleep(self.every)
                self.check()
        threading.Thread(target=loop, daemon=True, name="lantern-idle").start()
