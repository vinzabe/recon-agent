"""Per-target rate governor.

A recon run that hammers one host is both rude and self-defeating (you get
rate-limited or blocked). The governor enforces a minimum interval per target and
a global concurrency cap. It is monotonic-clock based and injectable, so tests do
not sleep.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable


class RateGovernor:
    def __init__(self, per_target_interval: float = 1.0, max_concurrency: int = 4,
                 *, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        if per_target_interval < 0:
            raise ValueError("per_target_interval must be >= 0")
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        self._interval = per_target_interval
        self._clock = clock
        self._sleep = sleep
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()
        self._sem = threading.Semaphore(max_concurrency)

    def acquire(self, target: str) -> None:
        """Block until this target may be contacted again."""
        self._sem.acquire()
        with self._lock:
            last = self._last.get(target)
            now = self._clock()
            if last is not None:
                wait = self._interval - (now - last)
                if wait > 0:
                    self._sleep(wait)
                    now = self._clock()
            self._last[target] = now

    def release(self) -> None:
        self._sem.release()

    def __enter__(self) -> RateGovernor:
        return self

    def __exit__(self, *exc: object) -> None:
        pass
