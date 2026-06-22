# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/orchestrator.py
"""End-to-end pipeline for the iAct8 local reproducer.

This module ties together:

    1. :mod:`keys`            – RSA-2048 keypair handling
    2. :mod:`bplist_builder`  – bplist00 ticket construction
    3. :mod:`signer`          – PKCS#1 v1.5 RSA-2048 signing
    4. :mod:`wire_format`     – JSON+base64 envelope

The result is a self-contained reproducer that mirrors the server-side
flow of ``iact8.php`` *without ever contacting the iRemoval server*.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import bplist_builder, keys, signer, wire_format


# --------------------------------------------------------------------------- #
# Logger
# --------------------------------------------------------------------------- #

log = logging.getLogger("iact_reproducer")


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ReproducerOutput:
    """Everything the reproducer produced on disk."""

    key_pem_path: Path
    bplist_path: Path
    signature_path: Path
    envelope_path: Path
    envelope: wire_format.IActEnvelope
    signature: signer.Signature
    bplist_size: int
    signature_size: int

    def to_manifest(self) -> dict:
        return {
            "classification": "OFFENSIVE _RESEARCH",
            "generated_at": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
            "key_pem": str(self.key_pem_path),
            "bplist_path": str(self.bplist_path),
            "bplist_size": self.bplist_size,
            "signature_path": str(self.signature_path),
            "signature_size": self.signature_size,
            "envelope_path": str(self.envelope_path),
            "alg": self.envelope.alg,
            "udid": self.envelope.udid,
            "key_fingerprint_sha256": self.signature.key_fingerprint_sha256,
        }


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #

def run_pipeline(
    *,
    out_root: Path,
    existing_pem: Optional[Path] = None,
    hash_name: str = "sha256",
    udid: Optional[str] = None,
) -> ReproducerOutput:
    """Run the full reproducer pipeline.

    Parameters
    ----------
    out_root:
        Root directory in which ``keys/``, ``requests/``, ...
        subdirectories will be populated.
    existing_pem:
        If given, load this PEM instead of generating a new key.
    hash_name:
        Hash algorithm to use for the PKCS#1 v1.5 signature.
    udid:
        Optional UDID. If absent, a clearly-tagged synthetic one is
        used.
    """
    out_root = Path(out_root).resolve()
    keys_dir = out_root / "keys"
    requests_dir = out_root / "requests"
    responses_dir = out_root / "responses"
    logs_dir = out_root / "logs"

    for d in (keys_dir, requests_dir, responses_dir, logs_dir):
        d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Step 1: key material
    # ------------------------------------------------------------------ #
    log.info("Step 1/4 — loading or generating RSA-2048 key…")
    material = keys.ensure_keymaterial(keys_dir, existing_pem=existing_pem)
    log.info("  → %s (sha256=%s)", material.pem_path.name, material.fingerprint_sha256)

    # ------------------------------------------------------------------ #
    # Step 2: build bplist00 ticket
    # ------------------------------------------------------------------ #
    log.info("Step 2/4 — building bplist00 activation ticket…")
    context = bplist_builder.DeviceContext.synthetic()
    if udid is not None:
        context.udid = udid
    ticket = bplist_builder.build_activation_ticket_dict(material, context=context)
    bplist_blob = bplist_builder.serialise_bplist00(ticket)

    timestamp = _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bplist_path = requests_dir / f"activation_ticket_{timestamp}.bplist"
    bplist_path.write_bytes(bplist_blob)
    log.info("  → %s (%d bytes)", bplist_path.name, len(bplist_blob))

    # ------------------------------------------------------------------ #
    # Step 3: sign with PKCS#1 v1.5 RSA-2048
    # ------------------------------------------------------------------ #
    log.info("Step 3/4 — signing with PKCS#1 v1.5 / %s…", hash_name.upper())
    sig = signer.sign_bytes(bplist_blob, material, hash_name=hash_name)
    signature_path = requests_dir / f"activation_ticket_{timestamp}.sig"
    signature_path.write_bytes(sig.signature)
    log.info("  → %s (%d bytes)", signature_path.name, len(sig.signature))

    # ------------------------------------------------------------------ #
    # Step 4: wrap as JSON+base64 envelope
    # ------------------------------------------------------------------ #
    log.info("Step 4/4 — wrapping as JSON+base64 envelope…")
    envelope = wire_format.build_envelope(
        udid=context.udid,
        bplist_blob=bplist_blob,
        signature=sig.signature,
        hash_name=hash_name,
        nonce=context.nonce,
        key_fingerprint=material.fingerprint_sha256,
    )

    envelope_path = responses_dir / f"iact_envelope_{timestamp}.json"
    envelope_path.write_text(envelope.to_json(indent=2), encoding="utf-8")
    log.info("  → %s", envelope_path.name)
    log.info("  %s", wire_format.envelope_summary(envelope))

    # ------------------------------------------------------------------ #
    # Manifest for downstream tooling
    # ------------------------------------------------------------------ #
    output = ReproducerOutput(
        key_pem_path=material.pem_path,
        bplist_path=bplist_path,
        signature_path=signature_path,
        envelope_path=envelope_path,
        envelope=envelope,
        signature=sig,
        bplist_size=len(bplist_blob),
        signature_size=len(sig.signature),
    )
    manifest_path = logs_dir / f"reproducer_manifest_{timestamp}.json"
    manifest_path.write_text(
        json.dumps(output.to_manifest(), indent=2), encoding="utf-8"
    )
    log.info("Manifest → %s", manifest_path)

    return output
