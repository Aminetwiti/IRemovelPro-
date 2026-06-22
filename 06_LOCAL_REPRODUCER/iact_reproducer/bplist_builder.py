# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/bplist_builder.py
"""bplist00 builder for the iAct8 reproducer.

Apple's iActivation flow expects the activation ticket to be encoded as
a **binary plist v0** (``bplist00``) carrying a dictionary whose
relevant keys include:

    * ``DeviceCertificate``      – DER-encoded X.509 cert
    * ``SigningIdentity``        – opaque blob (here: SHA-256 of pubkey)
    * ``FairPlayCertificate``    – placeholder DER blob
    * ``WildcardTicket``         – placeholder DER blob
    * ``ActivationTicket``       – the body that gets signed
    * ``nonce``, ``udid``, ``kSep`` – session parameters

In this OFFENSIVE  reproducer every field that would come from Apple
infrastructure is replaced by a clearly-labelled placeholder so that
nothing we emit can be mistaken for a working ticket.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import plistlib
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import keys as _keys


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

TEST_MARKER = _keys.TEST_MARKER  # reuse the same marker everywhere


# --------------------------------------------------------------------------- #
# ActivationTicket payload
# --------------------------------------------------------------------------- #

@dataclass
class DeviceContext:
    """Parameters that an iRemoval client would normally fetch from
    the iPhone (UDID, ECID, model, nonce, ...).

    In a OFFENSIVE  reproducer we **generate** synthetic values so the
    reproducer is fully self-contained. Every value is prefixed with
    the test marker so it can be grepped for.
    """

    udid: str
    ecid: str
    model: str
    board_id: str
    nonce: bytes
    kSep: bytes

    @staticmethod
    def synthetic() -> "DeviceContext":
        """Build a clearly synthetic device context for testing."""
        rand = secrets.token_hex(4)
        return DeviceContext(
            udid=f"OFFENSIVE -TEST-{rand.upper()}",
            ecid=f"0x{rand.upper()}",
            model="iPhone10,1 (TEST)",
            board_id=f"OFFENSIVE -BOARD-{rand.upper()}",
            nonce=secrets.token_bytes(16),
            kSep=secrets.token_bytes(16),
        )


# --------------------------------------------------------------------------- #
# Placeholder builders
# --------------------------------------------------------------------------- #

def _device_certificate_der(material: _keys.KeyMaterial) -> bytes:
    """Return DER bytes for the (self-signed, OFFENSIVE ) device cert."""
    cert = _keys.make_test_self_signed_cert(
        material, common_name=f"{TEST_MARKER}-DeviceCert"
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _signing_identity_blob(material: _keys.KeyMaterial) -> bytes:
    """Apple's ``SigningIdentity`` is an opaque blob; we use a tagged
    SHA-256 of the public key. Clearly *not* a real Apple identity."""
    pub_pem = _keys.derive_public_pem(material)
    digest = hashlib.sha256(pub_pem).digest()
    return TEST_MARKER.encode("ascii") + b":" + digest


def _placeholder_der_blob(label: str) -> bytes:
    """A clearly-labelled 64-byte placeholder used for FairPlay cert,
    WildcardTicket, etc. Real values come from Apple infrastructure."""
    text = f"{TEST_MARKER}-{label}-PLACEHOLDER-NOT-FROM-APPLE"
    return text.encode("ascii").ljust(64, b"\x00")[:64]


# --------------------------------------------------------------------------- #
# Public builder
# --------------------------------------------------------------------------- #

def build_activation_ticket_dict(
    material: _keys.KeyMaterial,
    context: Optional[DeviceContext] = None,
) -> Dict[str, Any]:
    """Build the dictionary that will be serialised to ``bplist00``.

    Returns
    -------
    dict
        The activation ticket as a Python dict, ready for
        ``plistlib.dumps(..., fmt=plistlib.FMT_BINARY)``.
    """
    if context is None:
        context = DeviceContext.synthetic()

    issued_at = _dt.datetime.now(tz=_dt.timezone.utc)
    ticket: Dict[str, Any] = {
        # --- metadata ---------------------------------------------------- #
        "OFFENSIVE Marker": TEST_MARKER,
        "IssuedAt": issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "SchemaVersion": "iact8-reproducer/1.0",

        # --- device context --------------------------------------------- #
        "UDID": context.udid,
        "ECID": context.ecid,
        "Model": context.model,
        "BoardID": context.board_id,
        "Nonce": context.nonce,
        "kSep": context.kSep,

        # --- activation artefacts --------------------------------------- #
        # Real iRemoval PRO supplies DER bytes for each of these; ours
        # are obviously-labelled placeholders.
        "DeviceCertificate": _device_certificate_der(material),
        "SigningIdentity": _signing_identity_blob(material),
        "FairPlayCertificate": _placeholder_der_blob("FairPlayCert"),
        "WildcardTicket": _placeholder_der_blob("WildcardTicket"),

        # --- bookkeeping ----------------------------------------------- #
        "BuildPath": "/Users/josuealonsorodriguez/.../blackhound.x.o",
        "HookTargets": [
            "MobileActivationDaemon",
            "SecKeyRawVerify",
            "SecKeyVerifySignature",
            "SecTrustEvaluateWithError",
        ],
    }
    return ticket


def serialise_bplist00(payload: Dict[str, Any]) -> bytes:
    """Serialise ``payload`` to a ``bplist00`` byte string.

    The ``plistlib`` module picks ``FMT_BINARY`` for ``bplist00`` on
    every supported Python version.
    """
    return plistlib.dumps(payload, fmt=plistlib.FMT_BINARY)


# --------------------------------------------------------------------------- #
# Verification helper
# --------------------------------------------------------------------------- #

def parse_bplist00(blob: bytes) -> Dict[str, Any]:
    """Parse a ``bplist00`` blob and return its dictionary. Used in
    tests to verify the round-trip."""
    return plistlib.loads(blob)
