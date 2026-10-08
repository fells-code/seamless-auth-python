"""Refresh sharing: one rotation per refresh token, handed to every caller
presenting it for a few seconds."""

from __future__ import annotations

import itertools
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ._jwt import Claims

# A refresh token presented again within this window gets the rotation it already
# got, so parallel requests from several tabs with one expired session all succeed
# instead of tripping the auth API's reuse detection.
REUSE_WINDOW = 5.0
# How long a caller waits on another's rotation before giving up.
FLIGHT_TIMEOUT = 30.0


@dataclass(frozen=True)
class RefreshOutcome:
    session: Claims | None = None
    status: int = 0
    body: Any = None
    is_json: bool = False
    error: str | None = None


class _Flight:
    def __init__(self, flight_id: int) -> None:
        self.id = flight_id
        self.done = threading.Event()
        self.outcome = RefreshOutcome(error="refresh did not finish")
        self.finished: float | None = None


class Refresher:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._flights: dict[str, _Flight] = {}
        self._ids = itertools.count(1)

    def share(self, key: str, rotate: Callable[[], RefreshOutcome]) -> RefreshOutcome:
        """Runs ``rotate`` once per key at a time, and hands a successful outcome
        to every caller with the same key for the reuse window afterwards. A
        failure is not kept, so each later caller sees it from the auth API itself."""
        with self._lock:
            now = time.monotonic()
            for stale in [
                k
                for k, f in self._flights.items()
                if f.finished is not None and now - f.finished > REUSE_WINDOW
            ]:
                del self._flights[stale]
            flight = self._flights.get(key)
            leader = flight is None
            if flight is None:
                flight = _Flight(next(self._ids))
                self._flights[key] = flight

        if not leader:
            if not flight.done.wait(FLIGHT_TIMEOUT):
                return RefreshOutcome(error="refresh timed out")
            return flight.outcome

        outcome = RefreshOutcome(error="refresh failed")
        try:
            outcome = rotate()
        finally:
            with self._lock:
                if self._flights.get(key) is flight:
                    if outcome.session is not None:
                        flight.finished = time.monotonic()
                    else:
                        del self._flights[key]
            flight.outcome = outcome
            flight.done.set()
        return outcome
