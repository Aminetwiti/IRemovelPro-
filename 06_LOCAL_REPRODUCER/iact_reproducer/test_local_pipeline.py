# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/test_local_pipeline.py
"""Tamper-matrix test for the local iAct8 pipeline.

This test exercises §21 of `01_REPORTS/BYPASS_CORE.md` ("COMPLETE LOCAL
BYPASS PIPELINE — Zero License, Zero Server") by demonstrating that the
four-step pipeline is **cryptographically self-consistent**:

    1. The unmodified 4 artefacts (key, bplist00, sig, envelope) verify OK.
    2. Any single-byte modification of the bplist00 → verification FAILS.
    3. Any single-byte modification of the signature → verification FAILS.
    4. Verifying against a different RSA-2048 public key → FAILS.
    5. Truncating the bplist00 by 16 bytes → FAILS.
    6. An empty signature → FAILS (length ≠ 256).
    7. An empty bplist00 → FAILS.

The test runs the live reproducer (`orchestrator.run_pipeline`) so it
exercises every layer end-to-end. All artefacts are written under a
fresh timestamped subdirectory of `keys/`, `requests/`, and `responses/`
so they do not collide with manual runs.

Exit code
---------
- 0  every assertion matched its expected outcome
- 1  at least one assertion diverged
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import sys
from pathlib import Path

# Allow `python iact_reproducer/test_local_pipeline.py` from any cwd.
_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent  # 06_LOCAL_REPRODUCER
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402

from iact_reproducer import orchestrator, signer, wire_format  # noqa: E402

# ---------------------------------------------------------------------------
# Output root (fresh sub-dir each run, so successive runs do not collide)
# ---------------------------------------------------------------------------
_TS = _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
_TAMPER_ROOT = _PKG_ROOT / "tamper_tests" / _TS


def _run_pipeline() -> orchestrator.ReproducerOutput:
    """Run the 4-step pipeline into a fresh sub-root."""
    return orchestrator.run_pipeline(
        out_root=_TAMPER_ROOT,
        existing_pem=None,  # always generate a fresh key
        hash_name="sha256",
        udid=None,           # let the builder synthesise a tagged UDID
    )


def _pub_from_pem(pem_path: Path):
    return serialization.load_pem_public_key(pem_path.read_bytes())


def _reload_envelope(env_path: Path) -> wire_format.IActEnvelope:
    raw = json.loads(env_path.read_text(encoding="utf-8"))
    return wire_format.IActEnvelope(**raw)


def _verify(envelope_path: Path, pubkey_path: Path) -> bool:
    pub = _pub_from_pem(pubkey_path)
    env = _reload_envelope(envelope_path)
    decoded = wire_format.decode_envelope(env)
    return signer.verify_bytes(
        decoded["bplist"],
        decoded["signature"],
        pub,
        hash_name="sha256",
    )


def _flip_one_byte(buf: bytes, offset: int = 0) -> bytes:
    """Flip the lowest bit of one byte to keep the file mostly intact."""
    if not buf:
        return buf
    b = bytearray(buf)
    b[offset] ^= 0x01
    return bytes(b)


def _mutate_envelope_signature(env_path: Path, mutate) -> Path:
    """Produce a tampered copy of `env_path` with the `sig` field
    rewritten by `mutate(bytes) -> bytes`. Returns the new path."""
    raw = json.loads(env_path.read_text(encoding="utf-8"))
    sig = base64.b64decode(raw["sig"])
    new_sig = mutate(sig)
    raw["sig"] = base64.b64encode(new_sig).decode("ascii")
    out = env_path.with_name(env_path.stem + ".tampered.json")
    out.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    return out


def _mutate_envelope_bplist(env_path: Path, mutate) -> Path:
    raw = json.loads(env_path.read_text(encoding="utf-8"))
    blob = base64.b64decode(raw["b64"])
    new_blob = mutate(blob)
    raw["b64"] = base64.b64encode(new_blob).decode("ascii")
    out = env_path.with_name(env_path.stem + ".tampered.json")
    out.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    return out


def _fresh_alien_keypair(keys_dir: Path) -> Path:
    """Generate a brand-new RSA-2048 keypair unrelated to the pipeline."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_path = keys_dir / f"alien_pub_{_TS}.pem"
    pub_path.write_bytes(pub_pem)
    return pub_path


# ---------------------------------------------------------------------------
# Test matrix
# ---------------------------------------------------------------------------

def main() -> int:
    print("=" * 72)
    print(f"iAct8 pipeline tamper matrix — root: {_TAMPER_ROOT}")
    print("=" * 72)

    out = _run_pipeline()
    pub_path = out.key_pem_path.with_suffix(".pub")
    if not pub_path.is_file():
        # Extract pub from priv if .pub not present (it normally is)
        priv = serialization.load_pem_private_key(
            out.key_pem_path.read_bytes(), password=None
        )
        pub_path.write_bytes(priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    alien_pub = _fresh_alien_keypair(out.key_pem_path.parent)

    cases: list[tuple[str, bool, bool]] = []  # (label, expected, observed)

    # 1. Positive — unmodified envelope verifies OK
    ok = _verify(out.envelope_path, pub_path)
    cases.append(("positive: unmodified envelope verifies OK", True, ok))

    # 2. bplist tampered at offset 0 (flip 1 bit)
    tampered_env = _mutate_envelope_bplist(
        out.envelope_path, lambda b: _flip_one_byte(b, 0)
    )
    ok = _verify(tampered_env, pub_path)
    cases.append(("bplist tampered (1 bit @ offset 0) → FAIL", False, ok))

    # 3. signature tampered at offset 32
    tampered_env = _mutate_envelope_signature(
        out.envelope_path, lambda s: _flip_one_byte(s, 32)
    )
    ok = _verify(tampered_env, pub_path)
    cases.append(("signature tampered (1 bit @ offset 32) → FAIL", False, ok))

    # 4. verifying with a different (alien) public key
    ok = _verify(out.envelope_path, alien_pub)
    cases.append(("verify with alien pubkey → FAIL", False, ok))

    # 5. truncate the bplist by 16 bytes
    tampered_env = _mutate_envelope_bplist(
        out.envelope_path, lambda b: b[:-16]
    )
    ok = _verify(tampered_env, pub_path)
    cases.append(("bplist truncated (-16 bytes) → FAIL", False, ok))

    # 6. empty signature (length 0)
    tampered_env = _mutate_envelope_signature(
        out.envelope_path, lambda s: b""
    )
    ok = _verify(tampered_env, pub_path)
    cases.append(("empty signature (len=0) → FAIL", False, ok))

    # 7. empty bplist
    tampered_env = _mutate_envelope_bplist(
        out.envelope_path, lambda b: b""
    )
    ok = _verify(tampered_env, pub_path)
    cases.append(("empty bplist (len=0) → FAIL", False, ok))

    # 8. positive with a different fresh pipeline (also OK)
    out2 = _run_pipeline()
    pub2 = out2.key_pem_path.with_suffix(".pub")
    if not pub2.is_file():
        priv2 = serialization.load_pem_private_key(
            out2.key_pem_path.read_bytes(), password=None
        )
        pub2.write_bytes(priv2.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    ok = _verify(out2.envelope_path, pub2)
    cases.append(("positive: fresh 2nd pipeline verifies OK", True, ok))

    # 9. bplist tampered at offset -1 (last byte)
    tampered_env = _mutate_envelope_bplist(
        out.envelope_path, lambda b: _flip_one_byte(b, len(b) - 1)
    )
    ok = _verify(tampered_env, pub_path)
    cases.append(("bplist tampered (1 bit @ last byte) → FAIL", False, ok))

    # 10. signature tampered at offset -1 (last byte)
    tampered_env = _mutate_envelope_signature(
        out.envelope_path, lambda s: _flip_one_byte(s, len(s) - 1)
    )
    ok = _verify(tampered_env, pub_path)
    cases.append(("signature tampered (1 bit @ last byte) → FAIL", False, ok))

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
    print(f"TOTAL: {passed}/{len(cases)} matrix checks passed", end="")
    if failed:
        print(f"  ({failed} FAILED — pipeline is NOT self-consistent)")
    else:
        print("  (pipeline is cryptographically self-consistent)")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())