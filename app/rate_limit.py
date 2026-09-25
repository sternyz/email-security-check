"""Rate limiting for /api/check. See docs/requirements.md §5 (Tier 3).

Each check fans out to ~20 DNS lookups plus an HTTPS fetch against whatever
domain it's given, on a 1 vCPU / ~460 MB VM, so two guards:

- RateLimiter: per-client-IP sliding windows (e.g. 5/minute and 30/hour).
- a global cap on concurrently running checks.

State is in-process memory. That's correct only because the service runs a
single uvicorn worker (deploy/emailcheck.service) — with multiple workers each
would keep its own counts and the effective limit would multiply.
"""

import threading
import time
from collections import deque
from typing import Callable

# (max requests, window in seconds) per client IP. All limits apply at once.
PER_IP_LIMITS = [(5, 60), (30, 3600)]
MAX_CONCURRENT_CHECKS = 3

_SWEEP_INTERVAL_SECONDS = 300


class RateLimiter:
    def __init__(
        self,
        limits: list[tuple[int, float]],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limits = limits
        self._longest_window = max(window for _, window in limits)
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._last_sweep = clock()

    def hit(self, key: str) -> float | None:
        """Record a request from `key` if it's within every limit.

        Returns None when allowed, otherwise the seconds until the next
        request would be allowed. Rejected requests aren't recorded, so
        retrying while blocked doesn't extend the block.
        """
        now = self._clock()
        with self._lock:
            self._sweep(now)
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= self._longest_window:
                hits.popleft()

            retry_after = 0.0
            for max_requests, window in self._limits:
                in_window = [t for t in hits if now - t < window]
                if len(in_window) >= max_requests:
                    # Allowed again once enough of the oldest hits age out.
                    oldest_blocking = in_window[len(in_window) - max_requests]
                    retry_after = max(retry_after, oldest_blocking + window - now)

            if retry_after > 0:
                return retry_after
            hits.append(now)
            return None

    def _sweep(self, now: float) -> None:
        """Drop clients with no hits inside the longest window, so memory
        stays bounded by recently active IPs."""
        if now - self._last_sweep < _SWEEP_INTERVAL_SECONDS:
            return
        self._last_sweep = now
        stale = [
            key
            for key, hits in self._hits.items()
            if not hits or now - hits[-1] >= self._longest_window
        ]
        for key in stale:
            del self._hits[key]
