"""Persistent blacklist for the iAct8 OFFENSIVE  lab (v1.4).

The real iRemoval backend keeps a server-side blacklist of UDIDs,
serials, IMEIs and IP addresses that have been flagged (stolen-device
reports, abusive clients, double-billing, etc.). We emulate the same
shape on disk so OFFENSIVE  tools can be tested against the full set of
identification keys, not just UDIDs.

File format (``logs/blacklist.json``)::

    {
      "marker": "iRemovalOFFENSIVE Test",
      "updated_at": "2026-06-22T14:00:00Z",
      "udids":        ["OFFENSIVE -BLACKLISTED-001", ...],
      "serials":      ["F2L..."],
      "imeis":        ["358000000000001"],
      "ip_addresses": ["10.0.0.99"]
    }

The store is **read-on-start, write-on-update**, with a per-process
lock for concurrent updates. The intent is not to be a high-throughput
KV store (the real iRemoval server uses Redis for that) — it is to
give the OFFENSIVE  lab a *real* on-disk artifact that detection
engineers can grep / diff / version-control.

The module deliberately pre-populates a few entries that are obvious
test fixtures so the lab is interesting from the first request:

  * ``"00000000-0000000000000000"`` (canonical "all-zero" UDID)
  * a fake serial that starts with ``LAB-BLACKLISTED``
  * a fake IMEI ending in ``0001``
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

log = logging.getLogger("iact_blacklist")

TEST_MARKER = "iRemovalDefensiveTest"

# Pre-populated fixtures (DEFENSIVE-only)
_SEED_UDIDS: List[str] = [
    "LAB-BLACKLISTED-0001",
    "LAB-BLACKLISTED-0002",
    "00000000-0000000000000000",
]
_SEED_SERIALS: List[str] = [
    "LAB-BLACKLISTED-SN-A1B2C3",
]
_SEED_IMEIS: List[str] = [
    "358000000000001",
    "358000000000002",
]
_SEED_IPS: List[str] = [
    # Reserved for tests of the IP-based block (set to 127.0.0.99
    # to avoid blocking ourselves by default).
    "127.0.0.99",
]


# --------------------------------------------------------------------------- #
# Data class
# --------------------------------------------------------------------------- #

@dataclass
class BlacklistEntry:
    identifier: str
    reason: str
    added_at: str
    added_by: str = "system"


@dataclass
class Blacklist:
    """Persistent blacklist keyed by UDID / serial / IMEI / IP.

    All four sets are kept in memory and persisted as one JSON file.
    """

    path: Path
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _udids: Set[str] = field(default_factory=set)
    _serials: Set[str] = field(default_factory=set)
    _imeis: Set[str] = field(default_factory=set)
    _ips: Set[str] = field(default_factory=set)
    _audit: Dict[str, BlacklistEntry] = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #
    @classmethod
    def load(cls, path: Path) -> "Blacklist":
        path = Path(path)
        bl = cls(path=path)
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                # Defensive marker check — refuse corrupted or
                # tampered files. The lab is supposed to *only* carry
                # artefacts tagged with iRemovalDefensiveTest.
                marker = data.get("marker", "")
                if marker != TEST_MARKER:
                    log.error(
                        "Blacklist file %s has wrong marker %r "
                        "(expected %r). REFUSING to load — please "
                        "inspect or delete the file.",
                        path, marker, TEST_MARKER,
                    )
                    # Fall through to seeding below; in-memory state
                    # stays empty (no in-file content trusted).
                else:
                    bl._udids.update(data.get("udids", []))
                    bl._serials.update(data.get("serials", []))
                    bl._imeis.update(data.get("imeis", []))
                    bl._ips.update(data.get("ip_addresses", []))
                    for e in data.get("audit", []):
                        bl._audit[e["identifier"]] = BlacklistEntry(**e)
                    log.info("Loaded blacklist from %s "
                             "(udids=%d serials=%d imeis=%d ips=%d)",
                             path, len(bl._udids), len(bl._serials),
                             len(bl._imeis), len(bl._ips))
                    return bl
            except Exception as exc:  # noqa: BLE001
                log.warning("Could not load %s (%s); starting empty",
                            path, exc)
        # Pre-populate fixtures on first creation
        bl._udids.update(_SEED_UDIDS)
        bl._serials.update(_SEED_SERIALS)
        bl._imeis.update(_SEED_IMEIS)
        bl._ips.update(_SEED_IPS)
        bl._save()
        return bl

    def _save(self) -> None:
        import datetime as _dt
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "marker": TEST_MARKER,
            "updated_at": _dt.datetime.now(tz=_dt.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "udids": sorted(self._udids),
            "serials": sorted(self._serials),
            "imeis": sorted(self._imeis),
            "ip_addresses": sorted(self._ips),
            "audit": [vars(v) for v in self._audit.values()],
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                       encoding="utf-8")
        tmp.replace(self.path)

    # ------------------------------------------------------------------ #
    # Mutations
    # ------------------------------------------------------------------ #
    def add(self, kind: str, identifier: str,
            *, reason: str = "manual", added_by: str = "admin") -> bool:
        """Add an entry. Returns True if it was new, False if already present."""
        import datetime as _dt
        target = self._bucket(kind)
        if target is None:
            raise ValueError(
                f"unknown kind {kind!r}; expected udid|serial|imei|ip"
            )
        with self._lock:
            if identifier in target:
                return False
            target.add(identifier)
            self._audit[f"{kind}:{identifier}"] = BlacklistEntry(
                identifier=identifier,
                reason=reason,
                added_at=_dt.datetime.now(tz=_dt.timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                added_by=added_by,
            )
            self._save()
        log.info("Blacklisted %s %s (%s)", kind, identifier, reason)
        return True

    def remove(self, kind: str, identifier: str) -> bool:
        target = self._bucket(kind)
        if target is None:
            raise ValueError(
                f"unknown kind {kind!r}; expected udid|serial|imei|ip"
            )
        with self._lock:
            if identifier not in target:
                return False
            target.remove(identifier)
            self._audit.pop(f"{kind}:{identifier}", None)
            self._save()
        log.info("Un-blacklisted %s %s", kind, identifier)
        return True

    # ------------------------------------------------------------------ #
    # Lookups
    # ------------------------------------------------------------------ #
    def check(self, *, udid: Optional[str] = None,
              serial: Optional[str] = None,
              imei: Optional[str] = None,
              ip: Optional[str] = None) -> Tuple[bool, List[Tuple[str, str]]]:
        """Return ``(allowed, [(kind, identifier), ...])``.

        ``allowed=True`` means the caller may proceed. Otherwise
        ``allowed=False`` and the second tuple lists every block
        reason (there can be more than one).
        """
        hits: List[Tuple[str, str]] = []
        for kind, value in (("udid", udid), ("serial", serial),
                            ("imei", imei), ("ip", ip)):
            if value is None:
                continue
            target = self._bucket(kind)
            assert target is not None
            if value in target:
                hits.append((kind, value))
        return (len(hits) == 0), hits

    # ------------------------------------------------------------------ #
    # Snapshot for the dashboard
    # ------------------------------------------------------------------ #
    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            return {
                "marker": TEST_MARKER,
                "path": str(self.path),
                "udids": sorted(self._udids),
                "serials": sorted(self._serials),
                "imeis": sorted(self._imeis),
                "ip_addresses": sorted(self._ips),
                "audit_count": len(self._audit),
            }

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #
    def _bucket(self, kind: str):
        return {
            "udid": self._udids,
            "serial": self._serials,
            "imei": self._imeis,
            "ip": self._ips,
        }.get(kind)
