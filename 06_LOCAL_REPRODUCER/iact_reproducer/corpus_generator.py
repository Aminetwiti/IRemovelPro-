# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/corpus_generator.py
"""Corpus generator — produce N labelled variations of the iAct8 envelope.

Why?
----
A single test artefact is not enough to train a SIEM rule, an IDS
signature, or a machine-learning detector. This module produces a
**corpus** of N envelope variations with controlled differences:

  * different hash algorithms (sha1, sha256, sha384, sha512)
  * different key sizes — but we always stay at RSA-2048 (real iRemoval
    only uses 2048), with optional "expired-cert" and "wrong-cn"
    variants for negative testing
  * different synthetic device profiles
  * optional tampering (bplist corruption, signature truncation, alg
    field mutation) for **negative** examples

Every artefact is logged in a CSV manifest so detection engineers can
read the matrix at a glance.
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import hashlib
import json
import logging
import secrets
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator, List, Optional

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from iact_reproducer import (  # noqa: E402
    bplist_builder,
    keys,
    orchestrator,
    signer,
    wire_format,
)

log = logging.getLogger("iact_corpus")

TEST_MARKER = "iRemovalOFFENSIVE Test"


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

@dataclass
class Variant:
    """One row of the corpus matrix."""
    variant_id: str
    label: str            # "positive" | "negative_tampered_bplist" | "negative_truncated_sig" | ...
    hash_name: str
    udid: str
    tamper_bplist: bool = False
    tamper_signature: bool = False
    tamper_alg: bool = False
    description: str = ""


def _variants_matrix(samples: int, *, include_negatives: bool) -> List[Variant]:
    """Build the matrix of variants to generate."""
    hash_algos = ["sha1", "sha256", "sha384", "sha512"]
    matrix: List[Variant] = []
    for i in range(samples):
        algo = hash_algos[i % len(hash_algos)]
        variant = Variant(
            variant_id=f"V{i:04d}",
            label="positive",
            hash_name=algo,
            udid=f"OFFENSIVE -CORPUS-{i:05d}-{secrets.token_hex(2).upper()}",
            description=f"Clean envelope, hash={algo}",
        )
        matrix.append(variant)
        if include_negatives and i % 5 == 0:
            # Negative: tampered bplist
            matrix.append(Variant(
                variant_id=f"N{i:04d}b",
                label="negative_tampered_bplist",
                hash_name=algo,
                udid=variant.udid,
                tamper_bplist=True,
                description="bplist00 tail byte flipped",
            ))
            # Negative: truncated signature
            matrix.append(Variant(
                variant_id=f"N{i:04d}s",
                label="negative_truncated_signature",
                hash_name=algo,
                udid=variant.udid,
                tamper_signature=True,
                description="signature truncated to 32 bytes",
            ))
            # Negative: alg field mismatch
            matrix.append(Variant(
                variant_id=f"N{i:04d}a",
                label="negative_alg_mismatch",
                hash_name=algo,
                udid=variant.udid,
                tamper_alg=True,
                description="alg field claims sha256 but signature is sha1",
            ))
    return matrix


# --------------------------------------------------------------------------- #
# Worker
# --------------------------------------------------------------------------- #

@dataclass
class CorpusArtefact:
    variant: Variant
    bplist_path: Path
    signature_path: Path
    envelope_path: Path
    bplist_size: int
    signature_size: int
    key_fingerprint_sha256: str


def _apply_tamper(blob: bytes, kind: str) -> bytes:
    if kind == "bplist":
        # flip the last byte
        return blob[:-1] + bytes([blob[-1] ^ 0xFF])
    if kind == "signature":
        return blob[:32]
    return blob


def generate_one(
    variant: Variant,
    material: keys.KeyMaterial,
    out_dir: Path,
) -> CorpusArtefact:
    """Generate a single corpus artefact according to ``variant``."""
    context = bplist_builder.DeviceContext(
        udid=variant.udid,
        ecid=f"0x{secrets.token_hex(4).upper()}",
        model="iPhone10,1 (TEST)",
        board_id=f"OFFENSIVE -BOARD-{secrets.token_hex(2).upper()}",
        nonce=secrets.token_bytes(16),
        kSep=secrets.token_bytes(16),
    )
    ticket = bplist_builder.build_activation_ticket_dict(material, context=context)
    bplist_blob = bplist_builder.serialise_bplist00(ticket)

    # Optional tampering
    signed_blob = bplist_blob
    if variant.tamper_bplist:
        bplist_blob = _apply_tamper(bplist_blob, "bplist")

    sig = signer.sign_bytes(signed_blob, material, hash_name=variant.hash_name)
    signature_blob = sig.signature
    if variant.tamper_signature:
        signature_blob = _apply_tamper(signature_blob, "signature")

    env_alg = variant.hash_name
    if variant.tamper_alg:
        env_alg = "sha256" if variant.hash_name != "sha256" else "sha1"
    envelope = wire_format.build_envelope(
        udid=context.udid,
        bplist_blob=bplist_blob,
        signature=signature_blob,
        hash_name=env_alg,
        nonce=context.nonce,
        key_fingerprint=material.fingerprint_sha256,
    )

    sub = out_dir / variant.label
    sub.mkdir(parents=True, exist_ok=True)
    bplist_path = sub / f"{variant.variant_id}.bplist"
    signature_path = sub / f"{variant.variant_id}.sig"
    envelope_path = sub / f"{variant.variant_id}.json"
    bplist_path.write_bytes(bplist_blob)
    signature_path.write_bytes(signature_blob)
    envelope_path.write_text(envelope.to_json(indent=2), encoding="utf-8")

    return CorpusArtefact(
        variant=variant,
        bplist_path=bplist_path,
        signature_path=signature_path,
        envelope_path=envelope_path,
        bplist_size=len(bplist_blob),
        signature_size=len(signature_blob),
        key_fingerprint_sha256=material.fingerprint_sha256,
    )


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def generate_corpus(
    *,
    out_dir: Path,
    samples: int = 50,
    include_negatives: bool = True,
    key_dir: Path,
) -> List[CorpusArtefact]:
    """Generate ``samples`` (plus optional negatives) envelope variants."""
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    log.info("Generating keypair for corpus…")
    material = keys.generate_test_keypair(key_dir, label="corpus")
    log.info("  key = %s", material.pem_path.name)

    matrix = _variants_matrix(samples, include_negatives=include_negatives)
    log.info("Variants to produce: %d (include_negatives=%s)",
             len(matrix), include_negatives)

    artefacts: List[CorpusArtefact] = []
    for v in matrix:
        art = generate_one(v, material, out_dir)
        artefacts.append(art)

    # Write the CSV manifest.
    manifest = out_dir / "corpus_manifest.csv"
    with manifest.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow([
            "variant_id", "label", "hash_name", "udid",
            "tamper_bplist", "tamper_signature", "tamper_alg",
            "bplist_path", "signature_path", "envelope_path",
            "bplist_size", "signature_size",
            "key_fingerprint_sha256", "description",
        ])
        for art in artefacts:
            v = art.variant
            w.writerow([
                v.variant_id, v.label, v.hash_name, v.udid,
                int(v.tamper_bplist), int(v.tamper_signature), int(v.tamper_alg),
                str(art.bplist_path), str(art.signature_path), str(art.envelope_path),
                art.bplist_size, art.signature_size,
                art.key_fingerprint_sha256, v.description,
            ])
    log.info("Manifest: %s", manifest)

    summary = out_dir / "corpus_summary.json"
    summary.write_text(json.dumps(
        {
            "generated_at": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
            "samples": samples,
            "include_negatives": include_negatives,
            "total_variants": len(matrix),
            "by_label": _count_by_label(matrix),
        },
        indent=2,
    ), encoding="utf-8")
    log.info("Summary: %s", summary)
    return artefacts


def _count_by_label(matrix: List[Variant]) -> dict:
    out: dict = {}
    for v in matrix:
        out[v.label] = out.get(v.label, 0) + 1
    return out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="iact_corpus",
        description=(
            "Generate a labelled corpus of iAct8 envelope variants for "
            "SIEM/IDS/ML training and detection-rule regression testing."
        ),
    )
    p.add_argument("--out-dir", default="06_LOCAL_REPRODUCER/corpus")
    p.add_argument("--key-dir", default="06_LOCAL_REPRODUCER/keys")
    p.add_argument("--samples", type=int, default=50)
    p.add_argument("--no-negatives", action="store_true",
                   help="Skip the negative examples (bplist tamper, sig truncate, alg mismatch).")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    artefacts = generate_corpus(
        out_dir=Path(args.out_dir).resolve(),
        samples=args.samples,
        include_negatives=not args.no_negatives,
        key_dir=Path(args.key_dir).resolve(),
    )
    print()
    print(f"Generated {len(artefacts)} envelope variants in {args.out_dir}")
    print(f"Manifest: {Path(args.out_dir) / 'corpus_manifest.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
