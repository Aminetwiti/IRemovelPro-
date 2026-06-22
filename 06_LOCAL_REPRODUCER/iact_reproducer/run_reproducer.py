# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/run_reproducer.py
"""Command-line entry point for the iAct8 local reproducer.

Usage
-----

    # Default: generate a fresh test RSA-2048 key and produce artefacts
    python -m iact_reproducer.run_reproducer

    # Reuse an existing PEM key
    python -m iact_reproducer.run_reproducer --key keys/iact8-test_…pem

    # Use a different hash
    python -m iact_reproducer.run_reproducer --hash sha1

    # Custom output root
    python -m iact_reproducer.run_reproducer --out-root 06_LOCAL_REPRODUCER

    # Verify a previously produced envelope against the matching public key
    python -m iact_reproducer.run_reproducer --verify responses/iact_envelope_….json
                                               --pubkey keys/…pem
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import sys
from pathlib import Path

# Allow `python iact_reproducer/run_reproducer.py` from any cwd.
# The package root (containing the `iact_reproducer/` directory) is the
# parent of this file's directory.
_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent  # 06_LOCAL_REPRODUCER
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from iact_reproducer import bplist_builder, orchestrator, signer, wire_format  # noqa: E402


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )


# --------------------------------------------------------------------------- #
# Sub-commands
# --------------------------------------------------------------------------- #

def cmd_run(args: argparse.Namespace) -> int:
    out = orchestrator.run_pipeline(
        out_root=Path(args.out_root).resolve(),
        existing_pem=Path(args.key).resolve() if args.key else None,
        hash_name=args.hash,
        udid=args.udid,
    )
    print()
    print("=" * 72)
    print("iAct8 reproducer — OFFENSIVE  TEST artefacts produced")
    print("=" * 72)
    print(f"  Key (PEM)        : {out.key_pem_path}")
    print(f"  bplist00         : {out.bplist_path}  ({out.bplist_size} bytes)")
    print(f"  Signature (raw)  : {out.signature_path}  ({out.signature_size} bytes)")
    print(f"  JSON envelope    : {out.envelope_path}")
    print(f"  Algorithm        : {out.envelope.alg}")
    print(f"  UDID             : {out.envelope.udid}")
    print(f"  Key SHA-256      : {out.signature.key_fingerprint_sha256}")
    print("=" * 72)
    print("These artefacts are clearly tagged as TEST FIXTURES.")
    print("They will not unlock any device and must never be used off-lab.")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    envelope_path = Path(args.verify).resolve()
    pubkey_path = Path(args.pubkey).resolve()

    if not envelope_path.is_file():
        print(f"!! envelope not found: {envelope_path}", file=sys.stderr)
        return 2
    if not pubkey_path.is_file():
        print(f"!! public key not found: {pubkey_path}", file=sys.stderr)
        return 2

    from cryptography.hazmat.primitives import serialization
    pub_key = serialization.load_pem_public_key(pubkey_path.read_bytes())

    raw = json.loads(envelope_path.read_text(encoding="utf-8"))
    env = wire_format.IActEnvelope(**raw)
    decoded = wire_format.decode_envelope(env)

    hash_name = env.alg.split("-")[-1].lower()
    ok = signer.verify_bytes(
        decoded["bplist"],
        decoded["signature"],
        pub_key,
        hash_name=hash_name,
    )

    print(f"Envelope : {envelope_path}")
    print(f"Algorithm: {env.alg}")
    print(f"Signature: {decoded['signature'].hex()[:64]}…  ({len(decoded['signature'])} bytes)")
    print(f"bplist  : {len(decoded['bplist'])} bytes")
    print(f"Verification: {'OK ✓' if ok else 'FAILED ✗'}")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# argparse
# --------------------------------------------------------------------------- #

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iact_reproducer",
        description=(
            "OFFENSIVE  reproducer for the iRemoval PRO iact8.php ticket "
            "generation flow. Produces clearly-tagged test artefacts only."
        ),
    )
    p.add_argument(
        "--out-root",
        default=str(_THIS_DIR.parent),
        help="Output root directory (default: 06_LOCAL_REPRODUCER).",
    )
    p.add_argument(
        "--key",
        default=None,
        help="Path to an existing RSA-2048 PEM private key.",
    )
    p.add_argument(
        "--hash",
        default="sha256",
        choices=["sha1", "sha256", "sha384", "sha512"],
        help="Hash algorithm for PKCS#1 v1.5 signing (default: sha256).",
    )
    p.add_argument(
        "--udid",
        default=None,
        help="Override the synthetic UDID (test value, clearly tagged).",
    )
    p.add_argument(
        "--verify",
        default=None,
        help="Path to a JSON envelope to verify (use with --pubkey).",
    )
    p.add_argument(
        "--pubkey",
        default=None,
        help="Path to a PEM public key for --verify.",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    _setup_logging(args.verbose)

    if args.verify:
        return cmd_verify(args)
    return cmd_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
