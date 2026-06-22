"""Activation-ticket dump analyser (bplist00 → JSON / IoC summary).

Reads the ``activation_ticket_<ts>.bplist`` artefacts produced by the lab
and surfaces:
  * every top-level key with type + value
  * the device identifiers (UDID, IMEI, MEID, SerialNumber) when present
  * the bypass-specific markers (iRemovalRecord, iRemovalSignature)
  * a hex dump of the trailing signature
  * a comparison against a known-good baseline (when --baseline is passed)

Useful for SOC analysts when they need to triage a captured ticket in
seconds — no Ghidra, no full iOS toolchain required.

Usage::

    py 06_LOCAL_REPRODUCER/ir_playbook/ticket_analyser.py \\
        --ticket 06_LOCAL_REPRODUCER/requests/activation_ticket_20260622T191241Z.bplist
"""

from __future__ import annotations

import argparse
import binascii
import json
import logging
import plistlib
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("iact_ticket_analyser")

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))


# --------------------------------------------------------------------------- #
# IoC markers
# --------------------------------------------------------------------------- #

# Fields that strongly suggest iRemoval PRO / blackhound tampering
BYPASS_FIELDS = (
    "iRemovalRecord",
    "iRemovalSignature",
    "iRemovalTicket",
    "iRemovalActivation",
    "BypassActivationLock",
    "BypassTicket",
    "BlackHound",
)

# Device-identifying fields (used to count privacy surface area)
DEVICE_ID_FIELDS = (
    "UDID",
    "UniqueDeviceID",
    "IMEI",
    "MEID",
    "SerialNumber",
    "ICCID",
    "BluetoothAddress",
    "WiFiAddress",
    "ProductType",
    "BoardID",
    "ChipID",
    "SecurityDomain",
    "ProductionStatus",
    "CertificateSecurityMode",
    "BasebandSerialNumber",
    "BasebandFirmwareVersion",
)

# Apple-internal DMD operations that should NEVER be missing
EXPECTED_DMD_OPS = (
    "ActivationLockStatus",
    "DeviceLockState",
    "BackupPasswordProtected",
)


@dataclass
class TicketAnalysis:
    path: str
    bplist_size: int
    root_type: str
    keys: List[str] = field(default_factory=list)
    bypass_fields_found: List[str] = field(default_factory=list)
    device_id_fields_found: List[str] = field(default_factory=list)
    dmd_ops_found: List[str] = field(default_factory=list)
    dmd_ops_missing: List[str] = field(default_factory=list)
    sig_present: bool = False
    sig_size: int = 0
    sig_sha256_prefix: str = ""
    verdicts: List[str] = field(default_factory=list)
    raw_root: Optional[Dict[str, Any]] = None


def analyse_ticket(path: Path) -> TicketAnalysis:
    """Parse a single bplist00 ticket and return a structured analysis."""
    path = Path(path).resolve()
    raw = path.read_bytes()
    try:
        root = plistlib.loads(raw)
    except Exception as e:  # malformed plist
        return TicketAnalysis(
            path=str(path),
            bplist_size=len(raw),
            root_type="MALFORMED",
            verdicts=[f"plist parse error: {e}"],
        )

    if not isinstance(root, dict):
        return TicketAnalysis(
            path=str(path),
            bplist_size=len(raw),
            root_type=type(root).__name__,
            verdicts=[f"unexpected root type: {type(root).__name__}"],
        )

    keys = list(root.keys())
    analysis = TicketAnalysis(
        path=str(path),
        bplist_size=len(raw),
        root_type="dict",
        keys=keys,
    )

    # Bypass markers
    analysis.bypass_fields_found = [k for k in keys if k in BYPASS_FIELDS]
    for k in analysis.bypass_fields_found:
        analysis.verdicts.append(
            f"BYPASS_MARKER: champ '{k}' présent — réservé au bypass iRemoval"
        )

    # Device-ID surface
    analysis.device_id_fields_found = [k for k in keys if k in DEVICE_ID_FIELDS]
    if len(analysis.device_id_fields_found) >= 4:
        analysis.verdicts.append(
            f"PRIVACY_SURFACE: {len(analysis.device_id_fields_found)} identifiants device exposés "
            f"({', '.join(analysis.device_id_fields_found)})"
        )

    # DMD ops — look in a nested dict (Apple uses 'DMDOperations' or 'DMD')
    dmd_root: Optional[Dict[str, Any]] = None
    for candidate in ("DMDOperations", "DMD", "DeviceManagement", "MDM"):
        if candidate in root and isinstance(root[candidate], dict):
            dmd_root = root[candidate]
            break
    if dmd_root is not None:
        analysis.dmd_ops_found = [k for k in dmd_root.keys() if k in EXPECTED_DMD_OPS]
    analysis.dmd_ops_missing = [k for k in EXPECTED_DMD_OPS if k not in analysis.dmd_ops_found]
    if analysis.dmd_ops_missing:
        analysis.verdicts.append(
            f"DMD_MISSING: ops critiques absentes {analysis.dmd_ops_missing} — MDM contourné"
        )

    # Signature
    for sig_key in ("Signature", "AppleSignature", "iRemovalSignature"):
        if sig_key in root and isinstance(root[sig_key], bytes):
            sig = root[sig_key]
            analysis.sig_present = True
            analysis.sig_size = len(sig)
            analysis.sig_sha256_prefix = _sha256_prefix(sig)
            break

    if not analysis.sig_present:
        analysis.verdicts.append("NO_SIGNATURE: aucune signature binaire embarquée")

    analysis.raw_root = root
    return analysis


def _sha256_prefix(data: bytes, n: int = 16) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()[:n]


# --------------------------------------------------------------------------- #
# Compare against a baseline
# --------------------------------------------------------------------------- #

def compare_with_baseline(analysis: TicketAnalysis, baseline: TicketAnalysis) -> List[str]:
    """Return human-readable diffs between an analysis and a known-good baseline."""
    diffs: List[str] = []
    base_keys = set(baseline.keys)
    new_keys = set(analysis.keys) - base_keys
    missing_keys = base_keys - set(analysis.keys)
    if new_keys:
        diffs.append(f"NEW_KEYS: {sorted(new_keys)}")
    if missing_keys:
        diffs.append(f"MISSING_KEYS: {sorted(missing_keys)}")
    if analysis.bypass_fields_found:
        diffs.append(
            f"BYPASS_ADDED: {analysis.bypass_fields_found} — baseline n'en contient aucune"
        )
    if baseline.sig_size and analysis.sig_size != baseline.sig_size:
        diffs.append(
            f"SIG_SIZE_DIFF: baseline={baseline.sig_size} ticket={analysis.sig_size}"
        )
    if baseline.sig_sha256_prefix and analysis.sig_sha256_prefix != baseline.sig_sha256_prefix:
        diffs.append(
            f"SIG_SHA_DIFF: baseline={baseline.sig_sha256_prefix} ticket={analysis.sig_sha256_prefix}"
        )
    return diffs


# --------------------------------------------------------------------------- #
# Pretty printing
# --------------------------------------------------------------------------- #

def render_report(analysis: TicketAnalysis, *, diffs: Optional[List[str]] = None) -> str:
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append(f"iAct8 ticket analysis — {analysis.path}")
    lines.append("=" * 72)
    lines.append(f"  bplist_size        : {analysis.bplist_size} bytes")
    lines.append(f"  root_type          : {analysis.root_type}")
    lines.append(f"  # keys             : {len(analysis.keys)}")
    lines.append(f"  bypass_fields      : {analysis.bypass_fields_found or '—'}")
    lines.append(f"  device_id_fields   : {len(analysis.device_id_fields_found)} ({', '.join(analysis.device_id_fields_found[:6])}…)")
    lines.append(f"  dmd_ops_found      : {analysis.dmd_ops_found or '—'}")
    lines.append(f"  dmd_ops_missing    : {analysis.dmd_ops_missing or '—'}")
    lines.append(f"  signature          : {'present ' + str(analysis.sig_size) + ' bytes' if analysis.sig_present else 'MISSING'}")
    if analysis.sig_present:
        lines.append(f"  sig sha256 prefix  : {analysis.sig_sha256_prefix}")
    lines.append("--- verdicts ---")
    if not analysis.verdicts:
        lines.append("  (no anomaly detected)")
    for v in analysis.verdicts:
        lines.append(f"  • {v}")
    if diffs:
        lines.append("--- diff vs baseline ---")
        for d in diffs:
            lines.append(f"  • {d}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="iact_ticket_analyser",
        description="Parse activation_ticket.bplist artefacts and surface iRemoval IoCs.",
    )
    p.add_argument("--ticket", required=True, help="Path to activation_ticket_*.bplist")
    p.add_argument("--baseline", default=None,
                   help="Optional path to a known-good ticket for diff comparison")
    p.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    ticket_path = Path(args.ticket)
    if not ticket_path.is_file():
        log.error("Ticket not found: %s", ticket_path)
        return 2

    analysis = analyse_ticket(ticket_path)
    diffs: Optional[List[str]] = None
    if args.baseline:
        baseline_path = Path(args.baseline)
        if not baseline_path.is_file():
            log.error("Baseline not found: %s", baseline_path)
            return 2
        baseline = analyse_ticket(baseline_path)
        diffs = compare_with_baseline(analysis, baseline)

    if args.json:
        payload = {
            "path": analysis.path,
            "bplist_size": analysis.bplist_size,
            "root_type": analysis.root_type,
            "keys": analysis.keys,
            "bypass_fields_found": analysis.bypass_fields_found,
            "device_id_fields_found": analysis.device_id_fields_found,
            "dmd_ops_found": analysis.dmd_ops_found,
            "dmd_ops_missing": analysis.dmd_ops_missing,
            "sig_present": analysis.sig_present,
            "sig_size": analysis.sig_size,
            "sig_sha256_prefix": analysis.sig_sha256_prefix,
            "verdicts": analysis.verdicts,
        }
        if diffs is not None:
            payload["diffs_vs_baseline"] = diffs
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(render_report(analysis, diffs=diffs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
