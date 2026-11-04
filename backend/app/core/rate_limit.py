"""Sliding-window rate limiter.

Data-structures lesson: for each key we keep a `deque` of timestamps. New
failures are appended on the right; expired ones are popped from the left. Both
operations are O(1), so the limiter stays fast even under attack.

Limitation (documented honestly): state lives in this process's memory, so with
several API containers each has its own counters. For production scale, move the
counters to Redis or enforce limits at the edge (AWS WAF / API Gateway).
"""

import time
from collections import defaultdict, deque
from collections.abc import Callable


class SlidingWindowRateLimiter:
    def __init__(
        self, max_events: int, window_seconds: float, clock: Callable[[], float] = time.monotonic
    ):
        self.max_events = max_events
        self.window = window_seconds
        self._clock = clock
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str) -> deque[float]:
        events = self._events[key]
        cutoff = self._clock() - self.window
        while events and events[0] <= cutoff:
            events.popleft()
        if not events:
            self._events.pop(key, None)  # don't leak memory for idle keys
        return events

    def is_blocked(self, key: str) -> bool:
        return len(self._prune(key)) >= self.max_events

    def record(self, key: str) -> None:
        self._events[key].append(self._clock())

    def reset(self, key: str) -> None:
        self._events.pop(key, None)

    def clear(self) -> None:
        self._events.clear()

    def retry_after(self, key: str) -> int:
        events = self._prune(key)
        if not events:
            return 0
        return max(1, int(events[0] + self.window - self._clock()) + 1)
