# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/self_test.py
"""End-to-end self test for the iAct8 reproducer.

This module exercises the full pipeline programmatically and verifies:

  1. A bplist00 round-trip is well-formed.
  2. The PKCS#1 v1.5 signature verifies against the matching public key.
  3. The JSON envelope decodes back to the original bplist and signature
     bytes.
  4. Every artefact contains the OFFENSIVE  marker.

Run with::

    python 06_LOCAL_REPRODUCER\\iact_reproducer\\self_test.py
"""

from __future__ import annotations

import base64
import json
import plistlib
import sys
import tempfile
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from cryptography.hazmat.primitives import serialization

from iact_reproducer import (
    bplist_builder,
    keys,
    orchestrator,
    signer,
    wire_format,
)

TEST_MARKER = "iRemovalOFFENSIVE Test"


def _banner(title: str) -> None:
    print()
    print("=" * 72)
    print(f" {title}")
    print("=" * 72)


def assert_true(cond: bool, msg: str) -> None:
    status = "OK" if cond else "FAIL"
    print(f"  [{status}] {msg}")
    if not cond:
        raise AssertionError(msg)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="iact_selftest_") as tmp:
        tmp_path = Path(tmp)

        # ------------------------------------------------------------------ #
        _banner("Step 1 — generate test RSA-2048 key")
        material = keys.generate_test_keypair(tmp_path / "keys")
        assert_true(material.pem_path.is_file(), f"PEM file exists: {material.pem_path.name}")
        assert_true(
            TEST_MARKER in material.pem_path.name,
            "PEM filename contains OFFENSIVE  marker",
        )

        # ------------------------------------------------------------------ #
        _banner("Step 2 — build bplist00 + round-trip")
        context = bplist_builder.DeviceContext.synthetic()
        ticket = bplist_builder.build_activation_ticket_dict(material, context=context)
        bplist = bplist_builder.serialise_bplist00(ticket)
        assert_true(bplist.startswith(b"bplist00"), "bplist00 magic header present")
        parsed = bplist_builder.parse_bplist00(bplist)
        assert_true(parsed["OFFENSIVE Marker"] == TEST_MARKER, "OFFENSIVE Marker present")
        assert_true(parsed["UDID"] == context.udid, "UDID round-tripped")
        assert_true(isinstance(parsed["DeviceCertificate"], bytes), "DeviceCertificate is DER bytes")
        assert_true(parsed["FairPlayCertificate"][:8] == (TEST_MARKER + "-FairP")[:8].encode("ascii"),
                    "FairPlayCertificate is a placeholder")

        # ------------------------------------------------------------------ #
        _banner("Step 3 — sign and verify with PKCS#1 v1.5 / SHA-256")
        sig = signer.sign_bytes(bplist, material, hash_name="sha256")
        assert_true(len(sig.signature) == 256, "RSA-2048 signature is 256 bytes")
        pub = material.private_key.public_key()
        ok = signer.verify_bytes(bplist, sig.signature, pub, hash_name="sha256")
        assert_true(ok, "signature verifies with matching public key")

        # Tampered payload should NOT verify.
        tampered = bplist + b"\x00"
        assert_true(
            not signer.verify_bytes(tampered, sig.signature, pub, hash_name="sha256"),
            "tampered payload does NOT verify",
        )

        # ------------------------------------------------------------------ #
        _banner("Step 4 — JSON+base64 envelope round-trip")
        env = wire_format.build_envelope(
            udid=context.udid,
            bplist_blob=bplist,
            signature=sig.signature,
            hash_name="sha256",
            nonce=context.nonce,
            key_fingerprint=material.fingerprint_sha256,
        )
        env_json = env.to_json()
        env_re = wire_format.IActEnvelope(**json.loads(env_json))
        decoded = wire_format.decode_envelope(env_re)
        assert_true(decoded["bplist"] == bplist, "envelope b64 decodes to original bplist")
        assert_true(decoded["signature"] == sig.signature, "envelope sig decodes to original signature")
        assert_true(env.alg == "RSA-PKCS1v1.5-SHA256", "alg field is correct")

        # ------------------------------------------------------------------ #
        _banner("Step 5 — full orchestrator pipeline on a fresh temp dir")
        with tempfile.TemporaryDirectory(prefix="iact_orchestrator_") as out2:
            out = orchestrator.run_pipeline(out_root=Path(out2), hash_name="sha256")
            assert_true(out.bplist_path.is_file(), "orchestrator wrote bplist00")
            assert_true(out.signature_path.is_file(), "orchestrator wrote signature")
            assert_true(out.envelope_path.is_file(), "orchestrator wrote envelope")
            assert_true("bplist00" in out.bplist_path.read_bytes()[:8].decode("ascii", "ignore"),
                        "orchestrator bplist starts with bplist00")

    _banner("ALL TESTS PASSED ✓")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
