"""HMAC-SHA256 authentication for the iAct8 OFFENSIVE  lab (v1.2).

This module emulates the **server-side** of the HMAC-SHA256 challenge
that iRemoval PRO uses between the PC client and ``s13.iremovalpro.com``.

Wire protocol (all headers, all ASCII)::

    X-Signature : hex(HMAC-SHA256(secret, canonical))
    X-Timestamp : <unix-seconds, base 10>
    X-Nonce     : <hex(16 random bytes)>
    X-Key-Id    : <optional, identifies which secret to use>

The canonical string is::

    "{method}\\n{path}\\n{timestamp}\\n{nonce}\\n{sha256_hex(body)}"

Validation steps (each refusal increments the ``auth_failures`` counter
on the shared :class:`AuthState`):

  1. All three required headers must be present.
  2. Timestamp must be within +/- ``clock_skew_seconds`` of now.
  3. Nonce must not have been seen in the last ``nonce_ttl_seconds``.
  4. HMAC must verify against the active secret.

Public endpoints (no auth required) are configurable via
``PUBLIC_PATHS`` — the lab defaults to letting ``/health``,
``/ping.ph``, ``/version33.tx`` and ``/`` be open so that
unauthenticated OFFENSIVE  tooling can still probe the server.

The module is **stateless between restarts** except for the in-memory
nonce cache. Nonces are intentionally not persisted: the goal is to
defeat trivial replays in the lab, not to provide a full HSM-backed
anti-replay. The real iRemoval server does this server-side with Redis.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

log = logging.getLogger("iact_hmac_auth")

TEST_MARKER = "iRemovalLabTest"

# Endpoints that do NOT require HMAC auth (health / version probes).
# Everything under /iremovalActivation/* requires a signature.
PUBLIC_PATH_SUFFIXES = (
    "/health",
    "/ping.ph",
    "/version33.tx",
    "/blacklist.ph",
    "/metrics.ph",
    "/",
)

# Configuration constants
DEFAULT_CLOCK_SKEW_SECONDS = 300        # +/- 5 minutes
DEFAULT_NONCE_TTL_SECONDS = 600          # 10 minutes
DEFAULT_SECRET_BYTES = 32


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_canonical(
    *,
    method: str,
    path: str,
    timestamp: int,
    nonce: str,
    body: bytes,
) -> bytes:
    """Return the canonical string that gets HMAC'd."""
    body_hash = sha256_hex(body)
    return f"{method}\n{path}\n{timestamp}\n{nonce}\n{body_hash}".encode("utf-8")


def compute_signature(
    secret: bytes,
    *,
    method: str,
    path: str,
    timestamp: int,
    nonce: str,
    body: bytes,
) -> str:
    """Return the hex HMAC-SHA256 of the canonical string."""
    canonical = build_canonical(
        method=method, path=path, timestamp=timestamp,
        nonce=nonce, body=body,
    )
    return hmac.new(secret, canonical, hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- #
# Shared auth state
# --------------------------------------------------------------------------- #

@dataclass
class AuthState:
    """Thread-safe in-memory state for HMAC validation.

    Holds:
      * the active HMAC secret(s) — keyed by ``key_id`` (string)
      * a nonce cache with TTL (sliding window)
      * counters for accepted / refused requests (observability)
    """

    secrets: Dict[str, bytes] = field(default_factory=dict)
    default_key_id: str = "default"
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS
    nonce_ttl_seconds: int = DEFAULT_NONCE_TTL_SECONDS
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _nonce_seen: Dict[str, float] = field(default_factory=dict)
    accepted: int = 0
    refused: int = 0
    refusal_reasons: Dict[str, int] = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    # Secret management
    # ------------------------------------------------------------------ #
    def add_secret(self, key_id: str, secret: bytes) -> None:
        with self._lock:
            self.secrets[key_id] = secret
        log.info("Added HMAC secret key_id=%s len=%d", key_id, len(secret))

    def set_default(self, key_id: str) -> None:
        with self._lock:
            if key_id not in self.secrets:
                raise KeyError(f"unknown key_id {key_id!r}")
            self.default_key_id = key_id

    # ------------------------------------------------------------------ #
    # Nonce cache maintenance
    # ------------------------------------------------------------------ #
    def _prune_nonces(self, now: float) -> None:
        cutoff = now - self.nonce_ttl_seconds
        stale = [n for n, t in self._nonce_seen.items() if t < cutoff]
        for n in stale:
            del self._nonce_seen[n]
        if stale:
            log.debug("Pruned %d stale nonces (cache size now %d)",
                      len(stale), len(self._nonce_seen))

    def _register_nonce(self, nonce: str, now: float) -> bool:
        """Return True if the nonce is fresh, False if already seen."""
        self._prune_nonces(now)
        if nonce in self._nonce_seen:
            return False
        self._nonce_seen[nonce] = now
        return True

    # ------------------------------------------------------------------ #
    # Public validation entry point
    # ------------------------------------------------------------------ #
    def is_public(self, path: str) -> bool:
        return any(path == p or path.endswith(p) for p in PUBLIC_PATH_SUFFIXES)

    def validate(
        self,
        *,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: bytes,
    ) -> Tuple[bool, Optional[str]]:
        """Return ``(ok, error_message)``.

        ``ok=True`` means the request is authenticated and the caller
        should proceed. ``ok=False`` means a 401 is appropriate.
        """
        if self.is_public(path):
            return True, None

        sig = headers.get("X-Signature")
        ts = headers.get("X-Timestamp")
        nonce = headers.get("X-Nonce")
        key_id = headers.get("X-Key-Id", self.default_key_id)

        if not sig or not ts or not nonce:
            return self._refuse("missing_headers",
                                "X-Signature, X-Timestamp and X-Nonce are required")
        try:
            timestamp = int(ts)
        except (TypeError, ValueError):
            return self._refuse("bad_timestamp", "X-Timestamp must be an integer (unix seconds)")

        now = time.time()
        if abs(now - timestamp) > self.clock_skew_seconds:
            return self._refuse("stale_timestamp",
                                f"timestamp outside +/-{self.clock_skew_seconds}s window")

        with self._lock:
            if not self._register_nonce(nonce, now):
                return self._refuse("replay", "nonce already seen in TTL window")
            secret = self.secrets.get(key_id)
            if secret is None:
                return self._refuse("unknown_key_id", f"unknown key_id {key_id!r}")

            expected = compute_signature(
                secret,
                method=method, path=path, timestamp=timestamp,
                nonce=nonce, body=body,
            )

        if not hmac.compare_digest(expected, sig):
            return self._refuse("bad_signature", "HMAC signature mismatch")

        with self._lock:
            self.accepted += 1
        return True, None

    def _refuse(self, reason: str, message: str) -> Tuple[bool, str]:
        with self._lock:
            self.refused += 1
            self.refusal_reasons[reason] = self.refusal_reasons.get(reason, 0) + 1
        log.warning("Auth refused: %s (%s)", reason, message)
        return False, message

    # ------------------------------------------------------------------ #
    # Snapshot for the dashboard
    # ------------------------------------------------------------------ #
    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            return {
                "marker": TEST_MARKER,
                "accepted": self.accepted,
                "refused": self.refused,
                "refusal_reasons": dict(self.refusal_reasons),
                "key_ids": list(self.secrets.keys()),
                "default_key_id": self.default_key_id,
                "nonce_cache_size": len(self._nonce_seen),
                "clock_skew_seconds": self.clock_skew_seconds,
                "nonce_ttl_seconds": self.nonce_ttl_seconds,
            }


# --------------------------------------------------------------------------- #
# Bootstrap helpers
# --------------------------------------------------------------------------- #

def load_or_create_state(
    *,
    secret_path: Optional[Path] = None,
    key_id: str = "default",
    nbytes: int = DEFAULT_SECRET_BYTES,
) -> AuthState:
    """Build an :class:`AuthState`, loading the secret from disk if it
    exists, otherwise creating a fresh random one and persisting it.

    The secret file is a small JSON document::

        {"key_id": "default", "secret_hex": "...", "marker": "..."}

    so a human can grep for the OFFENSIVE  marker.
    """
    state = AuthState()
    if secret_path is None:
        secret_path = Path("logs/hmac_secret.json").resolve()
    secret_path = Path(secret_path)
    if secret_path.is_file():
        try:
            data = json.loads(secret_path.read_text(encoding="utf-8"))
            secret = bytes.fromhex(data["secret_hex"])
            kid = data.get("key_id", key_id)
            state.add_secret(kid, secret)
            state.set_default(kid)
            log.info("Loaded HMAC secret from %s key_id=%s", secret_path, kid)
            return state
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not load %s (%s); generating fresh secret",
                        secret_path, exc)

    secret_path.parent.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_bytes(nbytes)
    state.add_secret(key_id, secret)
    state.set_default(key_id)
    secret_path.write_text(json.dumps(
        {
            "key_id": key_id,
            "secret_hex": secret.hex(),
            "marker": TEST_MARKER,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        indent=2,
    ), encoding="utf-8")
    log.info("Generated fresh HMAC secret key_id=%s saved to %s", key_id, secret_path)
    return state


# --------------------------------------------------------------------------- #
# Convenience: produce signed headers (used by tests)
# --------------------------------------------------------------------------- #

def make_signed_headers(
    state: AuthState,
    *,
    method: str,
    path: str,
    body: bytes,
    key_id: Optional[str] = None,
) -> Dict[str, str]:
    """Build the X-Signature / X-Timestamp / X-Nonce / X-Key-Id
    headers a real iRemoval client would send. Used by the test rig
    to exercise the auth path of the mock server.
    """
    if key_id is None:
        key_id = state.default_key_id
    secret = state.secrets.get(key_id)
    if secret is None:
        raise KeyError(f"unknown key_id {key_id!r}")
    timestamp = int(time.time())
    nonce = secrets.token_hex(16)
    sig = compute_signature(
        secret, method=method, path=path,
        timestamp=timestamp, nonce=nonce, body=body,
    )
    return {
        "X-Signature": sig,
        "X-Timestamp": str(timestamp),
        "X-Nonce": nonce,
        "X-Key-Id": key_id,
    }
