#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Search for additional bundle IDs in the extracted iRemoval PRO binaries.

This script enumerates bundle ID candidates in the binary dumps and
checks if any are NOT already in apple_drm_defense.FORBIDDEN_BUNDLE_IDS.

Output: new candidates that should be considered for §14 #12 extension.

Usage:
    python search_bundle_ids.py
"""
import re
from pathlib import Path

ROOT = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")

EXTRACTED_DIR = ROOT / "04_EXTRACTED"
DUMP_DIR = ROOT / "__analysis" / "extracted"
IOC_CATALOG = ROOT / "05_IOC" / "ioc_catalog.md"

# Already known (do not re-add)
KNOWN_BUNDLE_IDS = {
    "com.panyolsoft.blackhound",
    "com.iremovalpro.bypass",
    "com.blackhound.eraser",
}

# Bundle ID regex — case-sensitive, lowercase + dots + optional hyphens
BUNDLE_ID_RE = re.compile(
    rb"com\.[a-z0-9][a-z0-9\-]{1,40}(?:\.[a-z0-9][a-z0-9\-]{1,40}){1,5}",
    re.IGNORECASE,
)

# Also catch org.* and net.* variants
WIDER_RE = re.compile(
    rb"(?:com|org|net|io)\.[a-z0-9][a-z0-9\-]{1,40}(?:\.[a-z0-9][a-z0-9\-]{1,40}){1,5}",
    re.IGNORECASE,
)

# Whitelist of legitimate Apple bundle IDs (do not flag these)
APPLE_WHITELIST_PREFIXES = (
    b"com.apple.",
    b"com.icloud.",
    b"com.itunes.",
    b"com.me.",
)


def is_apple_whitelisted(bid: bytes) -> bool:
    return any(bid.startswith(p) for p in APPLE_WHITELIST_PREFIXES)


def is_known(bid: str) -> bool:
    return bid in KNOWN_BUNDLE_IDS


def collect_from_file(path: Path) -> set:
    """Return a set of candidate bundle ID strings found in `path`."""
    if not path.exists() or not path.is_file():
        return set()
    try:
        # Read as latin-1 to preserve byte patterns; we work on bytes anyway.
        data = path.read_bytes()
    except OSError:
        return set()
    candidates = set()
    for m in WIDER_RE.finditer(data):
        bid = m.group(0)
        if is_apple_whitelisted(bid):
            continue
        # Filter out strings that look like URLs (s13.iremovalpro.com etc.)
        # — those are domain names, not bundle IDs.
        if b"://" in data[max(0, m.start() - 8):m.start()]:
            continue
        # Filter out excessively long matches (false positives)
        if len(bid) > 80:
            continue
        # Filter out binary garbage — require only valid bundle-id chars.
        try:
            s = bid.decode("ascii")
        except UnicodeDecodeError:
            continue
        if re.search(r"[^a-z0-9.\-]", s, re.IGNORECASE):
            continue
        candidates.add(s)
    return candidates


def main() -> int:
    all_candidates: dict = {}
    scanned = 0

    # Scan all files in __analysis/extracted (raw binary dumps)
    if DUMP_DIR.exists():
        for p in DUMP_DIR.rglob("*"):
            if p.is_file() and p.stat().st_size > 100:
                scanned += 1
                for s in collect_from_file(p):
                    all_candidates.setdefault(s, set()).add(p.name)

    # Also scan iRemovalPro/ref/* for the source DLL strings if present
    iref = ROOT / "IRemovalPro" / "ref"
    if iref.exists():
        for p in iref.rglob("*"):
            if p.is_file() and p.stat().st_size > 100:
                scanned += 1
                for s in collect_from_file(p):
                    all_candidates.setdefault(s, set()).add(f"IRemovalPro/ref/{p.name}")

    # Split into known vs new
    new = sorted(s for s in all_candidates if not is_known(s))

    print(f"Files scanned: {scanned}")
    print(f"Total candidates: {len(all_candidates)}")
    print(f"Known (already in FORBIDDEN_BUNDLE_IDS): {len(all_candidates) - len(new)}")
    print(f"NEW candidates: {len(new)}")
    print()
    print("=== NEW candidates (sorted) ===")
    for s in new[:200]:  # cap to 200
        files = sorted(all_candidates[s])[:3]
        print(f"  {s}    [found in: {', '.join(files)}]")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
