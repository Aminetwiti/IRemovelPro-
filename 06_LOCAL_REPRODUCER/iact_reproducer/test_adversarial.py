# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/test_adversarial.py
"""Adversarial simulation for the local iAct8 pipeline.

This test answers §22 of `01_REPORTS/BYPASS_CORE.md`:

    "What stops an attacker from just running the local pipeline with
    their own keypair and getting a working bypass?"

The short answer: **nothing** — but signing with an attacker's own key
produces a signature that only the attacker's own public key can
verify. iOS has its own hardcoded Apple pubkey baked into the
`SecKeyRawVerify` path. Without the §20 hook chain
(`_replace_SecKeyRawVerify` etc.) that substitutes the Apple pubkey
with the attacker's, iOS will reject the forged ticket at signature
verification time.

This test exercises 10 attack scenarios:

    1. Baseline — pipeline produces a valid envelope that verifies OK
       with the matching pubkey (positive).
    2. Attacker-forger: signs the bplist with an ATTACKER-controlled
       RSA-2048 keypair, then tries to verify with the lab pubkey →
       FAIL (sig is over the wrong key).
    3. Attacker-self-check: the forger's envelope verifies OK with
       the forger's own pubkey (this is the trap — it looks valid
       locally but iOS will reject it).
    4. Random signature: 256 bytes of `os.urandom(256)` → FAIL.
    5. All-zero signature: 256 bytes of `\x00` → FAIL.
    6. Tampered bplist: flip 1 bit → FAIL (regression for §21.8).
    7. Cross-verify: lab envelope verified with an alien pubkey →
       FAIL.
    8. UDID swap: lab envelope with UDID overwritten in JSON →
       STILL OK (UDID is metadata, not signed).
    9. Nonce swap: lab envelope with nonce overwritten in JSON →
       STILL OK (nonce is metadata, not signed).
   10. Replay: same envelope verified twice → BOTH OK (no
       nonce-replay protection in the offline pipeline — this is
       intentional, see §22.5).

Run:

    python 06_LOCAL_REPRODUCER/iact_reproducer/test_adversarial.py

Exit code:

    0  every case matches its expected outcome
    1  at least one case diverged
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent  # 06_LOCAL_REPRODUCER
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from iact_reproducer import (  # noqa: E402
    bplist_builder,
    orchestrator,
    signer,
    wire_format,
)

_TS = _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
_ADV_ROOT = _PKG_ROOT / "adversarial_tests" / _TS


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _run() -> orchestrator.ReproducerOutput:
    return orchestrator.run_pipeline(
        out_root=_ADV_ROOT,
        existing_pem=None,
        hash_name="sha256",
        udid=None,
    )


def _pub(pem_or_path):
    if isinstance(pem_or_path, (str, Path)):
        return serialization.load_pem_public_key(Path(pem_or_path).read_bytes())
    return serialization.load_pem_public_key(pem_or_path)


def _env_from_disk(path: Path) -> wire_format.IActEnvelope:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return wire_format.IActEnvelope(**raw)


def _verify_blob(bplist: bytes, signature: bytes, pub) -> bool:
    return signer.verify_bytes(bplist, signature, pub, hash_name="sha256")


def _verify_envelope(env: wire_format.IActEnvelope, pub) -> bool:
    decoded = wire_format.decode_envelope(env)
    return _verify_blob(decoded["bplist"], decoded["signature"], pub)


def _fresh_attacker_keypair(keys_dir: Path):
    """Generate a brand-new RSA-2048 keypair representing the attacker."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = keys_dir / f"attacker_{_TS}.pem"
    pub_path = keys_dir / f"attacker_{_TS}.pub"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


def _build_envelope_from_b64_sig(
    *, udid: str, b64: str, sig: str
) -> wire_format.IActEnvelope:
    return wire_format.IActEnvelope(
        udid=udid,
        b64=b64,
        sig=sig,
        alg="RSA-PKCS1v1.5-SHA256",
        nonce=base64.b64encode(secrets.token_bytes(24)).decode("ascii"),
        ts=_dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        key_fingerprint=None,
        lab_marker="iRemovalOFFENSIVE Test",
    )


# --------------------------------------------------------------------------- #
# Test cases
# --------------------------------------------------------------------------- #

def main() -> int:
    print("=" * 72)
    print(f"iAct8 adversarial simulation — root: {_ADV_ROOT}")
    print("=" * 72)

    out = _run()
    pub_path = out.key_pem_path.with_suffix(".pub")
    if not pub_path.is_file():
        priv = serialization.load_pem_private_key(
            out.key_pem_path.read_bytes(), password=None
        )
        pub_path.write_bytes(priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    pub_lab = _pub(pub_path)
    env_lab = _env_from_disk(out.envelope_path)
    decoded = wire_format.decode_envelope(env_lab)
    bplist_lab = decoded["bplist"]
    sig_lab = decoded["signature"]
    # Wire-format field names on IActEnvelope are `b64` and `sig`
    # (decode_envelope normalises them to `bplist`/`signature` after
    # base64-decoding the bytes — see wire_format.decode_envelope).
    b64_lab = env_lab.b64

    keys_dir = out.key_pem_path.parent
    attacker_priv_path, attacker_pub_path = _fresh_attacker_keypair(keys_dir)
    attacker_priv = serialization.load_pem_private_key(
        attacker_priv_path.read_bytes(), password=None
    )
    attacker_pub = _pub(attacker_pub_path)

    cases: list[tuple[str, bool, bool]] = []

    # ------------------------------------------------------------------ #
    # Case 1: baseline — legitimate envelope verifies with its pubkey
    # ------------------------------------------------------------------ #
    ok = _verify_blob(bplist_lab, sig_lab, pub_lab)
    cases.append(("baseline: lab env verifies with lab pub → OK", True, ok))

    # ------------------------------------------------------------------ #
    # Case 2: attacker re-signs the bplist with their own private key,
    # then claims the result is valid. Verify with the LAB pubkey → FAIL.
    # ------------------------------------------------------------------ #
    attacker_sig = signer.sign_bytes(bplist_lab, attacker_priv, hash_name="sha256").signature
    ok = _verify_blob(bplist_lab, attacker_sig, pub_lab)
    cases.append((
        "attacker re-signs with own key, verify with LAB pub → FAIL",
        False, ok,
    ))

    # ------------------------------------------------------------------ #
    # Case 3: attacker-self check — verify with the attacker's pubkey.
    # This LOOKS valid locally but iOS will reject it because iOS has
    # the Apple pubkey hardcoded. Document this trap.
    # ------------------------------------------------------------------ #
    ok = _verify_blob(bplist_lab, attacker_sig, attacker_pub)
    cases.append((
        "TRAP: attacker re-sign verifies OK with attacker pub → OK (cosmetic)",
        True, ok,
    ))

    # ------------------------------------------------------------------ #
    # Case 4: random signature (256 bytes of os.urandom) → FAIL
    # ------------------------------------------------------------------ #
    rand_sig = os.urandom(256)
    ok = _verify_blob(bplist_lab, rand_sig, pub_lab)
    cases.append(("random 256-byte signature → FAIL", False, ok))

    # ------------------------------------------------------------------ #
    # Case 5: all-zero signature → FAIL
    # ------------------------------------------------------------------ #
    zero_sig = b"\x00" * 256
    ok = _verify_blob(bplist_lab, zero_sig, pub_lab)
    cases.append(("all-zero 256-byte signature → FAIL", False, ok))

    # ------------------------------------------------------------------ #
    # Case 6: tampered bplist (regression for §21.8) → FAIL
    # ------------------------------------------------------------------ #
    tampered = bytearray(bplist_lab)
    tampered[0] ^= 0x01
    ok = _verify_blob(bytes(tampered), sig_lab, pub_lab)
    cases.append(("bplist tampered (1 bit @ offset 0) → FAIL", False, ok))

    # ------------------------------------------------------------------ #
    # Case 7: cross-verify — lab envelope with an alien pubkey → FAIL
    # ------------------------------------------------------------------ #
    alien_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    alien_pub = alien_priv.public_key()
    ok = _verify_blob(bplist_lab, sig_lab, alien_pub)
    cases.append(("lab env verified with alien pub → FAIL", False, ok))

    # ------------------------------------------------------------------ #
    # Case 8: UDID swap on JSON envelope — verification ignores UDID
    # because the bplist (signed payload) does not contain the UDID.
    # ------------------------------------------------------------------ #
    swapped = _build_envelope_from_b64_sig(
        udid="ATTACKER-FAKE-UDID",
        b64=b64_lab,
        sig=base64.b64encode(sig_lab).decode("ascii"),
    )
    ok = _verify_envelope(swapped, pub_lab)
    cases.append(("UDID swap in JSON envelope → STILL OK (UDID is metadata)", True, ok))

    # ------------------------------------------------------------------ #
    # Case 9: nonce swap on JSON envelope — verification ignores nonce
    # because the bplist does not contain the nonce. The lab does not
    # enforce nonce-replay protection (see §22.5).
    # ------------------------------------------------------------------ #
    swapped2 = wire_format.IActEnvelope(
        udid=env_lab.udid,
        b64=b64_lab,
        sig=base64.b64encode(sig_lab).decode("ascii"),
        alg=env_lab.alg,
        nonce=base64.b64encode(secrets.token_bytes(24)).decode("ascii"),
        ts=env_lab.ts,
        key_fingerprint=env_lab.key_fingerprint,
        lab_marker=env_lab.lab_marker,
    )
    ok = _verify_envelope(swapped2, pub_lab)
    cases.append(("nonce swap in JSON envelope → STILL OK (nonce is metadata)", True, ok))

    # ------------------------------------------------------------------ #
    # Case 10: replay — same envelope verified twice → both OK
    # ------------------------------------------------------------------ #
    ok1 = _verify_blob(bplist_lab, sig_lab, pub_lab)
    ok2 = _verify_blob(bplist_lab, sig_lab, pub_lab)
    cases.append((
        "replay: same envelope verified twice → BOTH OK",
        True, ok1 and ok2,
    ))

    # ------------------------------------------------------------------ #
    # Print and tally
    # ------------------------------------------------------------------ #
    print()
    print(f"{'#':<3} {'expected':<8} {'observed':<9} {'label'}")
    print("-" * 72)
    passed = 0
    failed = 0
    for i, (label, expected, observed) in enumerate(cases, start=1):
        ok = expected == observed
        if ok:
            passed += 1
        else:
            failed += 1
        marker = "✓" if ok else "✗"
        exp = "OK" if expected else "FAIL"
        obs = "OK" if observed else "FAIL"
        print(f"{i:<3} {exp:<8} {obs:<9} {marker} {label}")

    print()
    print(
        f"TOTAL: {passed}/{len(cases)} adversarial checks passed",
        end="",
    )
    if failed:
        print(f"  ({failed} FAILED — see cases above)")
    else:
        print("  (adversarial model is consistent with §22 expectations)")

    # ------------------------------------------------------------------ #
    # Print the takeaway
    # ------------------------------------------------------------------ #
    print()
    print("=" * 72)
    print("§22 TAKEAWAY")
    print("=" * 72)
    print(
        "  Signing locally with ANY key produces a signature that\n"
        "  only the SAME key can verify (cases 2 and 3 above).\n"
        "  iOS has its own Apple pubkey baked into SecKeyRawVerify.\n"
        "  Without the §20 hook chain (_replace_SecKeyRawVerify etc.)\n"
        "  that substitutes iOS's pubkey with the attacker's, iOS\n"
        "  will reject the forged ticket at signature verification time.\n"
        "\n"
        "  Net: §21 (local pipeline) alone is HARMLESS. The bypass\n"
        "  only materializes when §21 (ticket forgery) is combined\n"
        "  with §20 (client-side hook chain) — see BYPASS_CORE.md §20."
    )
    print("=" * 72)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())