"""Multi-endpoint corpus generator for the iRemoval OFFENSIVE  lab.

The :mod:`corpus_generator` module focuses on the **iact8.php** wire
format (bplist00 + RSA signature + JSON envelope). The iRemoval
backend exposes **12 other endpoints** (``pub.ph``, ``mf5.ph``,
``mf6.ph``, ``mf7.ph``, ``license.ph``, ``telemetry.ph``, ``admin.ph``,
``version33.tx``, ``blacklist.ph``, ``ping.ph``, ``metrics.ph``).

This module generates a labelled corpus of **request bodies** for
every one of those endpoints so the lab can exercise the entire
mock-server surface. All bodies carry the ``iRemovalOFFENSIVE Test``
marker and a synthetic device profile; nothing here ever unlocks a
real device.

Output
------

::

    06_LOCAL_REPRODUCER/corpus_multi/
        pub_positive_0001.json
        pub_positive_0002.json
        pub_negative_oversize_0001.json
        mf5_positive_0001.json
        mf6_positive_0001.json
        ...
        multi_endpoint_manifest.csv
        multi_endpoint_summary.json
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
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))


log = logging.getLogger("iact_multi_corpus")

TEST_MARKER = "iRemovalOFFENSIVE Test"


# --------------------------------------------------------------------------- #
# Endpoint catalogue (kept in sync with mock_server._ALL_ENDPOINTS)
# --------------------------------------------------------------------------- #

ENDPOINTS = {
    "iact8":      {"method": "POST", "path": "/iremovalActivation/iact8.php"},
    "pub":        {"method": "POST", "path": "/iremovalActivation/pub.ph"},
    "mf5":        {"method": "POST", "path": "/iremovalActivation/mf5.ph"},
    "mf6":        {"method": "POST", "path": "/iremovalActivation/mf6.ph"},
    "mf7":        {"method": "POST", "path": "/iremovalActivation/mf7.ph"},
    "license":    {"method": "POST", "path": "/iremovalActivation/license.ph"},
    "telemetry":  {"method": "POST", "path": "/iremovalActivation/telemetry.ph"},
    "admin":      {"method": "POST", "path": "/iremovalActivation/admin.ph"},
    "version":    {"method": "GET",  "path": "/version33.tx"},
    "blacklist":  {"method": "GET",  "path": "/blacklist.ph"},
    "ping":       {"method": "GET",  "path": "/ping.ph"},
    "metrics":    {"method": "GET",  "path": "/metrics.ph"},
}


# --------------------------------------------------------------------------- #
# Variant matrix
# --------------------------------------------------------------------------- #

@dataclass
class MultiVariant:
    variant_id: str
    endpoint: str
    method: str
    path: str
    label: str             # "positive" | "negative_*"
    description: str
    body: Dict[str, object] = field(default_factory=dict)
    body_path: Optional[Path] = None


# --------------------------------------------------------------------------- #
# Body builders
# --------------------------------------------------------------------------- #

def _synthetic_udid(idx: int) -> str:
    return f"OFFENSIVE -{idx:05d}-{secrets.token_hex(2).upper()}"


def _positive_pub_body(idx: int) -> Dict[str, object]:
    return {
        "udid": _synthetic_udid(idx),
        "product_type": "iPhone10,1",
        "ios_version": "14.3",
        "ecid": f"0x{secrets.token_hex(4).upper()}",
        "OFFENSIVE _marker": TEST_MARKER,
    }


def _positive_mf_body(idx: int) -> Dict[str, object]:
    return {
        "udid": _synthetic_udid(idx),
        "imei": "358000000000000",
        "meid": "0xA0000000000000",
        "soc": "A12",
        "OFFENSIVE _marker": TEST_MARKER,
    }


def _positive_license_body(idx: int) -> Dict[str, object]:
    return {
        "license_key": f"{TEST_MARKER}-{idx:05d}",
        "client_version": "5.2.0",
        "hwid": hashlib.sha256(secrets.token_bytes(16)).hexdigest(),
        "OFFENSIVE _marker": TEST_MARKER,
    }


def _positive_telemetry_body(idx: int) -> Dict[str, object]:
    return {
        "event": "bypass_attempt",
        "udid": _synthetic_udid(idx),
        "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
        "OFFENSIVE _marker": TEST_MARKER,
    }


def _positive_admin_body(idx: int) -> Dict[str, object]:
    return {
        "command": "list_sessions",
        "admin_token": f"{TEST_MARKER}-TOKEN-{idx:05d}",
        "OFFENSIVE _marker": TEST_MARKER,
    }


# Negative variants
def _negative_oversize_body(idx: int) -> Dict[str, object]:
    return {
        "udid": _synthetic_udid(idx),
        "blob": "A" * 4096,
        "OFFENSIVE _marker": TEST_MARKER,
    }


def _negative_missing_field_body(idx: int) -> Dict[str, object]:
    return {
        # No "udid" field
        "product_type": "iPhone10,1",
        "OFFENSIVE _marker": TEST_MARKER,
    }


def _negative_garbage_body(idx: int) -> Dict[str, object]:
    return {
        "udid": _synthetic_udid(idx),
        "ecid": "NOT-A-HEX-VALUE",
        "ios_version": {"nested": ["object", "instead", "of", "string"]},
        "OFFENSIVE _marker": TEST_MARKER,
    }


# --------------------------------------------------------------------------- #
# Matrix construction
# --------------------------------------------------------------------------- #

def _build_matrix(samples: int, *, include_negatives: bool) -> List[MultiVariant]:
    matrix: List[MultiVariant] = []

    builders_positive = {
        "pub":       _positive_pub_body,
        "mf5":       _positive_mf_body,
        "mf6":       _positive_mf_body,
        "mf7":       _positive_mf_body,
        "license":   _positive_license_body,
        "telemetry": _positive_telemetry_body,
        "admin":     _positive_admin_body,
    }

    for ep, builder in builders_positive.items():
        for i in range(samples):
            meta = ENDPOINTS[ep]
            matrix.append(MultiVariant(
                variant_id=f"{ep.upper()}_P_{i:04d}",
                endpoint=ep,
                method=meta["method"],
                path=meta["path"],
                label="positive",
                description=f"Synthetic valid {ep} request",
                body=builder(i),
            ))

    if include_negatives:
        # Add negatives for the most-tested endpoints
        for ep in ("pub", "mf6", "license"):
            for i in range(max(1, samples // 5)):
                meta = ENDPOINTS[ep]
                matrix.append(MultiVariant(
                    variant_id=f"{ep.upper()}_N_oversize_{i:04d}",
                    endpoint=ep,
                    method=meta["method"],
                    path=meta["path"],
                    label="negative_oversize",
                    description="Oversized blob field (DoS-style)",
                    body=_negative_oversize_body(i),
                ))
                matrix.append(MultiVariant(
                    variant_id=f"{ep.upper()}_N_missing_{i:04d}",
                    endpoint=ep,
                    method=meta["method"],
                    path=meta["path"],
                    label="negative_missing_field",
                    description="Missing required field (udid)",
                    body=_negative_missing_field_body(i),
                ))
                matrix.append(MultiVariant(
                    variant_id=f"{ep.upper()}_N_garbage_{i:04d}",
                    endpoint=ep,
                    method=meta["method"],
                    path=meta["path"],
                    label="negative_type_mismatch",
                    description="Field has wrong type (ecid not hex)",
                    body=_negative_garbage_body(i),
                ))

    return matrix


# --------------------------------------------------------------------------- #
# Disk write
# --------------------------------------------------------------------------- #

@dataclass
class MultiArtefact:
    variant: MultiVariant
    body_path: Path


def _write_variant(v: MultiVariant, out_dir: Path) -> MultiArtefact:
    out_dir.mkdir(parents=True, exist_ok=True)
    body_path = out_dir / f"{v.variant_id}.json"
    body_path.write_text(
        json.dumps(v.body, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    v.body_path = body_path
    return MultiArtefact(variant=v, body_path=body_path)


def generate_multi_corpus(
    out_dir: Path,
    *,
    samples: int = 5,
    include_negatives: bool = True,
) -> List[MultiArtefact]:
    """Build and write the multi-endpoint corpus.

    Parameters
    ----------
    out_dir:
        Directory where the JSON request bodies are written.
    samples:
        Number of positive variants per POST endpoint.
    include_negatives:
        Whether to also generate negative variants for pub/mf6/license.
    """
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    matrix = _build_matrix(samples, include_negatives=include_negatives)
    artefacts = [_write_variant(v, out_dir) for v in matrix]

    # Manifest CSV
    manifest = out_dir / "multi_endpoint_manifest.csv"
    with manifest.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow([
            "variant_id", "endpoint", "method", "path", "label",
            "description", "body_path", "body_size",
        ])
        for a in artefacts:
            v = a.variant
            w.writerow([
                v.variant_id, v.endpoint, v.method, v.path, v.label,
                v.description, str(a.body_path), a.body_path.stat().st_size,
            ])
    log.info("Manifest: %s", manifest)

    # Summary JSON
    summary = out_dir / "multi_endpoint_summary.json"
    by_label: Dict[str, int] = {}
    by_endpoint: Dict[str, int] = {}
    for a in artefacts:
        by_label[a.variant.label] = by_label.get(a.variant.label, 0) + 1
        by_endpoint[a.variant.endpoint] = by_endpoint.get(a.variant.endpoint, 0) + 1
    summary.write_text(json.dumps(
        {
            "generated_at": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
            "samples": samples,
            "include_negatives": include_negatives,
            "total_variants": len(matrix),
            "by_label": by_label,
            "by_endpoint": by_endpoint,
            "endpoints_covered": list(ENDPOINTS.keys()),
            "marker": TEST_MARKER,
        },
        indent=2,
    ), encoding="utf-8")
    log.info("Summary: %s", summary)

    return artefacts


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="iact_multi_corpus",
        description=(
            "Generate a labelled corpus of multi-endpoint request bodies. "
            f"Every body is tagged {TEST_MARKER!r}."
        ),
    )
    p.add_argument("--out-dir", default="06_LOCAL_REPRODUCER/corpus_multi")
    p.add_argument("--samples", type=int, default=5)
    p.add_argument("--no-negatives", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    artefacts = generate_multi_corpus(
        out_dir=Path(args.out_dir).resolve(),
        samples=args.samples,
        include_negatives=not args.no_negatives,
    )
    print(f"-> {len(artefacts)} variants in {args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
