# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/wire_format.py
"""JSON + base64 wire envelope used by ``iact8.php``.

The iRemoval PRO server expects a JSON body of the rough shape::

    {
      "udid":  "...",
      "b64":   "<base64(bplist00)>",
      "sig":   "<base64(RSA-PKCS1v1.5 signature)>",
      "alg":   "RSA-PKCS1v1.5-SHA256",
      "nonce": "<base64(16 random bytes)>",
      "ts":    "2026-06-22T10:22:58Z"
    }

This module constructs and serialises that envelope. It also knows how
to round-trip back to its parts for verification in tests.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

TEST_MARKER = "iRemovalOFFENSIVE Test"
SUPPORTED_ALGS = {
    "RSA-PKCS1v1.5-SHA1",
    "RSA-PKCS1v1.5-SHA256",
    "RSA-PKCS1v1.5-SHA384",
    "RSA-PKCS1v1.5-SHA512",
}


# --------------------------------------------------------------------------- #
# Envelope dataclass
# --------------------------------------------------------------------------- #

@dataclass
class IActEnvelope:
    """The JSON envelope sent to ``iact8.php``.

    The fields are deliberately the same names (``b64``, ``sig``,
    ``alg``, ``nonce``...) that appear in the captured traffic and in
    the ioc_catalog.
    """

    udid: str
    b64: str                # base64(bplist00 ticket)
    sig: str                # base64(RSA-PKCS1v1.5 signature)
    alg: str                # e.g. "RSA-PKCS1v1.5-SHA256"
    nonce: str              # base64(16-byte nonce)
    ts: str = field(default_factory=lambda: _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    key_fingerprint: Optional[str] = None
    lab_marker: str = TEST_MARKER

    # ------------------------------------------------------------------ #
    # Serialisation helpers
    # ------------------------------------------------------------------ #

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(asdict(self), indent=indent, ensure_ascii=False)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def build_envelope(
    *,
    udid: str,
    bplist_blob: bytes,
    signature: bytes,
    hash_name: str,
    nonce: bytes,
    key_fingerprint: Optional[str] = None,
) -> IActEnvelope:
    """Wrap a signed bplist00 in the JSON envelope used by ``iact8``."""
    alg = f"RSA-PKCS1v1.5-{hash_name.upper()}"
    if alg not in SUPPORTED_ALGS:
        raise ValueError(
            f"Algorithm {alg!r} not in supported set {sorted(SUPPORTED_ALGS)}"
        )

    return IActEnvelope(
        udid=udid,
        b64=_b64(bplist_blob),
        sig=_b64(signature),
        alg=alg,
        nonce=_b64(nonce),
        key_fingerprint=key_fingerprint,
    )


def decode_envelope(env: IActEnvelope) -> Dict[str, bytes]:
    """Inverse of :func:`build_envelope`. Returns the raw byte values
    for verification."""
    return {
        "bplist": base64.b64decode(env.b64),
        "signature": base64.b64decode(env.sig),
        "nonce": base64.b64decode(env.nonce),
    }


# --------------------------------------------------------------------------- #
# Pretty-printer for logs
# --------------------------------------------------------------------------- #

def envelope_summary(env: IActEnvelope) -> str:
    """One-line human-readable summary suitable for log files."""
    return (
        f"udid={env.udid} alg={env.alg} "
        f"b64_len={len(env.b64)} sig_len={len(env.sig)} "
        f"nonce_len={len(env.nonce)} ts={env.ts}"
    )
