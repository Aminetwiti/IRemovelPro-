"""Sliding-window rate limiter for the iAct8 OFFENSIVE  lab (v1.3).

Implements two limiters that the real iRemoval backend enforces via
Redis but we keep in-process for the lab:

  * **Per-IP**     : default 100 requests / 60 seconds
  * **Per-UDID**   : default 10 requests / 60 seconds  (stricter)

The limiter is thread-safe (a single lock covers both dictionaries and
the per-key timestamp list). It exposes:

  * :meth:`RateLimiter.check`  — non-mutating probe
  * :meth:`RateLimiter.consume` — atomic check + record
  * :meth:`RateLimiter.reset`   — drop all counters

For the OFFENSIVE  lab the only ``429 Too Many Requests`` we ever
produce is *synthetic* — the rejected request is still logged with
the ``iRemovalOFFENSIVE Test`` marker so detection engineers can see
it in their SIEM and decide whether their own rules are sensitive
enough.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional, Tuple

log = logging.getLogger("iact_ratelimit")

TEST_MARKER = "iRemovalOFFENSIVE Test"

DEFAULT_PER_IP_LIMIT = 100
DEFAULT_PER_UDID_LIMIT = 10
DEFAULT_WINDOW_SECONDS = 60


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class RateLimitConfig:
    per_ip_limit: int = DEFAULT_PER_IP_LIMIT
    per_udid_limit: int = DEFAULT_PER_UDID_LIMIT
    window_seconds: int = DEFAULT_WINDOW_SECONDS


# --------------------------------------------------------------------------- #
# Per-key sliding window
# --------------------------------------------------------------------------- #

class _Window:
    """Sliding-window counter for a single key (IP or UDID)."""

    __slots__ = ("limit", "window", "_timestamps")

    def __init__(self, limit: int, window: int) -> None:
        self.limit = limit
        self.window = window
        self._timestamps: Deque[float] = deque()

    def consume(self, now: float) -> Tuple[bool, int]:
        """Return ``(allowed, retry_after_seconds)``.

        ``allowed=False`` means the call would exceed ``limit`` within
        the rolling ``window`` seconds. ``retry_after_seconds`` is the
        number of seconds the caller must wait before retrying.
        """
        # Prune timestamps that have fallen out of the window
        cutoff = now - self.window
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
        if len(self._timestamps) >= self.limit:
            retry = max(1, int(self.window - (now - self._timestamps[0])))
            return False, retry
        self._timestamps.append(now)
        return True, 0

    def peek(self, now: float) -> int:
        cutoff = now - self.window
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
        return len(self._timestamps)


# --------------------------------------------------------------------------- #
# Composite limiter
# --------------------------------------------------------------------------- #

@dataclass
class RateLimiter:
    """Composite limiter that enforces both per-IP and per-UDID budgets."""

    config: RateLimitConfig = field(default_factory=RateLimitConfig)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _per_ip: Dict[str, _Window] = field(default_factory=dict)
    _per_udid: Dict[str, _Window] = field(default_factory=dict)
    accepted: int = 0
    refused_ip: int = 0
    refused_udid: int = 0

    def _get_ip_window(self, ip: str) -> _Window:
        w = self._per_ip.get(ip)
        if w is None:
            w = _Window(self.config.per_ip_limit, self.config.window_seconds)
            self._per_ip[ip] = w
        return w

    def _get_udid_window(self, udid: str) -> _Window:
        w = self._per_udid.get(udid)
        if w is None:
            w = _Window(self.config.per_udid_limit, self.config.window_seconds)
            self._per_udid[udid] = w
        return w

    def consume(
        self,
        *,
        ip: str,
        udid: Optional[str] = None,
        now: Optional[float] = None,
    ) -> Tuple[bool, str, int]:
        """Atomic check-and-record. Returns ``(allowed, reason, retry_after)``.

        ``reason`` is one of:
          * ``"ok"``
          * ``"per_ip"``     — IP budget exceeded
          * ``"per_udid"``   — UDID budget exceeded
        """
        if now is None:
            now = time.time()
        with self._lock:
            ip_w = self._get_ip_window(ip)
            ok, retry = ip_w.consume(now)
            if not ok:
                self.refused_ip += 1
                log.info("Rate-limited IP %s (retry %ds)", ip, retry)
                return False, "per_ip", retry
            if udid is not None:
                udid_w = self._get_udid_window(udid)
                ok, retry = udid_w.consume(now)
                if not ok:
                    # Roll back the IP increment so the IP doesn't get
                    # blamed for a UDID-level violation.
                    try:
                        ip_w._timestamps.pop()
                    except IndexError:
                        pass
                    self.refused_udid += 1
                    log.info("Rate-limited UDID %s (retry %ds)", udid, retry)
                    return False, "per_udid", retry
            self.accepted += 1
            return True, "ok", 0

    def reset(self) -> None:
        with self._lock:
            self._per_ip.clear()
            self._per_udid.clear()
            self.accepted = 0
            self.refused_ip = 0
            self.refused_udid = 0

    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            return {
                "marker": TEST_MARKER,
                "config": {
                    "per_ip_limit": self.config.per_ip_limit,
                    "per_udid_limit": self.config.per_udid_limit,
                    "window_seconds": self.config.window_seconds,
                },
                "accepted": self.accepted,
                "refused_ip": self.refused_ip,
                "refused_udid": self.refused_udid,
                "tracked_ips": len(self._per_ip),
                "tracked_udids": len(self._per_udid),
            }
