"""Rate limiting helpers for eNote encryption endpoints."""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    reset_at: int
    retry_after_seconds: int = 0


class TokenBucket:
    """Simple token bucket for per-document or per-actor encryption limits."""

    def __init__(self, *, capacity: int, refill_per_second: float) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if refill_per_second <= 0:
            raise ValueError("refill_per_second must be positive")
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._tokens = float(capacity)
        self._updated_at = time.monotonic()

    def allow(self, *, cost: int = 1) -> RateLimitDecision:
        if cost <= 0:
            raise ValueError("cost must be positive")

        self._refill()
        now = int(time.time())
        if self._tokens >= cost:
            self._tokens -= cost
            return RateLimitDecision(
                allowed=True,
                remaining=int(self._tokens),
                reset_at=now + self._seconds_until_full(),
            )

        missing = cost - self._tokens
        retry_after = max(1, int(missing / self.refill_per_second))
        return RateLimitDecision(
            allowed=False,
            remaining=int(self._tokens),
            reset_at=now + retry_after,
            retry_after_seconds=retry_after,
        )

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated_at
        self._updated_at = now
        self._tokens = min(
            float(self.capacity),
            self._tokens + (elapsed * self.refill_per_second),
        )

    def _seconds_until_full(self) -> int:
        missing = float(self.capacity) - self._tokens
        if missing <= 0:
            return 0
        return int(missing / self.refill_per_second)
