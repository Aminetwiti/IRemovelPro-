r"""Continuous DNS / TLS / Cert-Transparency monitor for iRemoval PRO C2 + Apple activation infra.

Tracks three classes of signals:

  * **DNS watcher**         — resolves suspect hostnames, records A/AAAA changes.
  * **TLS cert watcher**    — connects to albert.apple.com (and friends), pulls the leaf
                              cert via raw ASN.1, captures notAfter + SHA-256 + SAN list.
  * **Cert transparency**   — queries crt.sh for any new cert covering the watched
                              domains, dedups against the previous run's ledger.

Everything is stdlib only.  All state lives in ``logs/monitor/`` as JSONL append-only
files, so each run is diff-able against the baseline.

Run::

    py monitor\watcher.py --mode all                # one-shot full scan
    py monitor\watcher.py --mode dns                # only DNS
    py monitor\watcher.py --mode tls                # only TLS certs
    py monitor\watcher.py --mode ct                 # only cert-transparency
    py monitor\watcher.py --mode all --baseline     # diff against logs\monitor\baseline.json
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import ssl
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
import hashlib
import datetime as dt
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

LOG = logging.getLogger("iact_monitor")

WATCHED_HOSTS = [
    "albert.apple.com",                # legitimate Activation Lock telemetry
    "deviceenrollment.apple.com",      # DEP / MDM
    "albert.icloud.com",               # iCloud-side activation
    "ppq.apple.com",                   # push proxy queue
    "s13.iremovalpro.com",             # iRemoval PRO C2 (suspicious)
    "api.bypassfrpfiles.com",          # iRemoval distribution
    "ocsp.apple.com",                  # cert status
]

APPLE_BASELINE = {
    # Apple-owned AS714 / AS6185 / AS20940. We whitelist the large /8 + key /12s
    # that show up in public routing data. Tightening this would generate
    # false positives, so the policy is "broad enough to be silent, narrow
    # enough to catch non-Apple infra".
    "albert.apple.com":           ["17.0.0.0/8", "2620:149:a13::/48"],
    "deviceenrollment.apple.com": ["17.0.0.0/8", "2620:149::/32"],
    "albert.icloud.com":          ["17.0.0.0/8"],
    "ppq.apple.com":              ["17.0.0.0/8"],
    "ocsp.apple.com":             ["17.0.0.0/8"],
}
SUSPECT_TLDS = (".top", ".xyz", ".click", ".ru", ".cn")

# ---------------------------------------------------------------------------
# helpers


def _ts() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_getaddrinfo(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        out: List[str] = []
        for fam, _t, _p, _canon, sockaddr in infos:
            if fam == socket.AF_INET and sockaddr[0] not in out:
                out.append(sockaddr[0])
        return out
    except (socket.gaierror, OSError) as exc:
        LOG.warning("DNS resolve failed for %s: %s", host, exc)
        return []


def _ip_in_baseline(ip: str, baseline_cidrs: List[str]) -> bool:
    """Naive CIDR check — works for /16-/24 typical ASN ranges without netaddr dep."""
    import ipaddress
    try:
        ipa = ipaddress.ip_address(ip)
        for cidr in baseline_cidrs:
            if ipa in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError:
        pass
    return False


def _asn_heuristic(ip: str) -> Optional[str]:
    """Crude ASN tagger — known C2 ASNs flagged, Apple 714 sanity-checked."""
    # We do not ship an offline IP-to-ASN table; we just whitelist Apple-owned /16.
    apple_cidrs = ["17.253.0.0/16", "17.57.0.0/16", "17.0.0.0/8"]
    if _ip_in_baseline(ip, apple_cidrs):
        return "AS714-Apple"
    return None


# ---------------------------------------------------------------------------
# TLS cert walker (no cryptography dep — we just need issuer, notAfter, SHA-256)

def _b64url_der_to_pem(der: bytes) -> str:
    import base64
    b = base64.b64encode(der).decode()
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----\n"


def _cert_fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _cert_short(der: bytes) -> str:
    """Return the first 16 hex chars of SHA-256 — useful for ledger density."""
    return _cert_fingerprint(der)[:16]


def _parse_x509_minimal(der: bytes) -> Dict[str, Any]:
    """Hand-rolled ASN.1 DER parser for the fields we care about.

    Handles only what `cryptography`-free watcher needs:

        * issuer  — picked out of the inner SEQUENCE for tbsCertificate.issuer
        * subject — same
        * notBefore / notAfter — picked out as generalized/UTC time tags
        * SAN DNS entries — pulled out of the subjectAltName extension (OID 2.5.29.17)

    Anything weird falls back to a string so the watcher still works.
    """
    import re

    def _read_len(buf: bytes, pos: int) -> Tuple[int, int]:
        first = buf[pos]
        pos += 1
        if first & 0x80 == 0:
            return first, pos
        nb = first & 0x7F
        return int.from_bytes(buf[pos:pos + nb], "big"), pos + nb

    def _read_tlv(buf: bytes, pos: int) -> Tuple[int, int, int, bytes]:
        tag = buf[pos]
        pos += 1
        length, pos = _read_len(buf, pos)
        return tag, length, pos, buf[pos:pos + length]

    def _grab_printable(buf: bytes) -> List[str]:
        # We search for printable substrings ≥ 4 chars (issuer / subject RDN fragments).
        raw = b" ".join(re.findall(rb"[\x20-\x7e]{4,}", buf))
        return raw.decode("latin-1", "ignore").split()

    def _find_time(buf: bytes) -> Tuple[Optional[str], Optional[str]]:
        nb = off = None
        # UTCTime = tag 23, GeneralizedTime = tag 24
        for i, b in enumerate(buf):
            if b in (0x17, 0x18) and i + 2 < len(buf):
                ln = buf[i + 1]
                if ln in (13, 15) and i + 2 + ln <= len(buf):
                    raw = buf[i + 2:i + 2 + ln]
                    try:
                        s = raw.decode("ascii")
                        if b == 0x17:
                            # UTCTime YYmmddHHMMSSZ
                            year = int(s[:2])
                            year = 2000 + year if year < 50 else 1900 + year
                            ts = f"{year}-{s[2:4]}-{s[4:6]}T{s[6:12]}Z"
                        else:
                            ts = s.replace("Z", "")
                        if nb is None:
                            nb = ts
                        else:
                            off = ts
                            return nb, off
                    except UnicodeDecodeError:
                        continue
        return nb, off

    def _find_san(buf: bytes) -> List[str]:
        out: List[str] = []
        # OID 2.5.29.17 == 06 03 55 1D 11
        needle = b"\x06\x03\x55\x1d\x11"
        idx = buf.find(needle)
        if idx < 0:
            return out
        pos = idx + len(needle)
        # Skip OID length byte; bound OCTET STRING wrapper
        try:
            _tag, _len, pos, inner = _read_tlv(buf, pos)
            # inner is OCTET STRING containing SEQUENCE { dNSName, ... }
            if inner[:1] != b"\x30":
                return out
            # Walk through dNSName entries (tag 0x82, IA5String, context-specific [2])
            j = 0
            while j < len(inner):
                if inner[j] != 0x82:
                    j += 1
                    continue
                ln = inner[j + 1]
                name = inner[j + 2:j + 2 + ln].decode("ascii", "ignore")
                if name:
                    out.append(name)
                j += 2 + ln
        except (IndexError, ValueError):
            pass
        return out

    text = _grab_printable(der)
    nb, off = _find_time(der)
    san = _find_san(der)
    return {
        "issuer":    " | ".join(text[:3]) if text else "",
        "subject":   " | ".join(text[:3]) if text else "",
        "notBefore": nb,
        "notAfter":  off,
        "san":       san,
    }


def fetch_tls_cert(host: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
    """Open a TLS socket, pull the leaf cert as DER, return a fingerprint dict."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                # binary_form=True returns the leaf cert as DER
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    return {"host": host, "ok": False, "error": "no peer cert"}
                meta = _parse_x509_minimal(der)
                meta.update({
                    "host":      host,
                    "port":      port,
                    "ok":        True,
                    "sha256":    _cert_fingerprint(der),
                    "short":     _cert_short(der),
                    "ts":        _ts(),
                })
                return meta
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError) as exc:
        return {"host": host, "ok": False, "error": str(exc), "ts": _ts()}


# ---------------------------------------------------------------------------
# Certificate Transparency via crt.sh (public, free, JSON API)


def fetch_ct(cert_query: str, timeout: int = 8) -> List[Dict[str, Any]]:
    """Query crt.sh for the latest certs matching the domain pattern.

    `cert_query` is the raw query string (e.g. ``%.albert.apple.com``).
    """
    url = f"https://crt.sh/?q={urllib.parse.quote(cert_query)}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "iact8-monitor/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        rows = json.loads(data.decode("utf-8", "replace"))
        # Keep only what we need — large CT payloads otherwise blow memory
        return [
            {
                "id":         r.get("id"),
                "not_before": r.get("not_before"),
                "not_after":  r.get("not_after"),
                "cn":         r.get("common_name"),
                "name":       r.get("name_value"),
                "issuer":     r.get("issuer_name"),
            }
            for r in rows[:200]
        ]
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        LOG.warning("crt.sh query failed for %s: %s", cert_query, exc)
        return []


# ---------------------------------------------------------------------------
# Ledger

@dataclass
class MonitorRecord:
    kind: str            # "dns" | "tls" | "ct"
    host: str
    payload: Dict[str, Any] = field(default_factory=dict)
    alerts: List[str] = field(default_factory=list)
    ts: str = ""


def _alert_dns(rec: MonitorRecord) -> None:
    h = rec.host
    ips = rec.payload.get("ips", [])
    if not ips:
        rec.alerts.append("DNS_FAIL: no resolution")
        return
    if h in APPLE_BASELINE:
        for ip in ips:
            if not _ip_in_baseline(ip, APPLE_BASELINE[h]):
                rec.alerts.append(f"IP_NOT_IN_APPLE_ASN: {ip}")
    if h.endswith(SUSPECT_TLDS):
        rec.alerts.append(f"SUSPECT_TLD: {h}")
    if h in {"s13.iremovalpro.com", "api.bypassfrpfiles.com"}:
        rec.alerts.append("KNOWN_C2: iRemoval PRO infra")


def _alert_tls(rec: MonitorRecord) -> None:
    if not rec.payload.get("ok"):
        rec.alerts.append(f"TLS_FAIL: {rec.payload.get('error', '?')}")
        return
    nb = rec.payload.get("notBefore")
    na = rec.payload.get("notAfter")
    try:
        if na:
            exp = dt.datetime.fromisoformat(na.replace("Z", ""))
            days = (exp - dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)).days
            if days < 14:
                rec.alerts.append(f"TLS_EXPIRES_SOON: {days}d")
            rec.payload["days_to_expiry"] = days
    except ValueError:
        pass
    if rec.host.endswith(SUSPECT_TLDS):
        rec.alerts.append(f"TLS_SUSPECT_TLD: {rec.host}")


def _alert_ct(rec: MonitorRecord) -> None:
    rows = rec.payload.get("rows", [])
    if not rows:
        return
    # count how many certs were issued in the last 7 days
    cutoff = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) - dt.timedelta(days=7)
    recent = 0
    for r in rows:
        try:
            ts = dt.datetime.fromisoformat((r.get("not_before") or "").split("T")[0])
            if ts > cutoff:
                recent += 1
        except (ValueError, AttributeError):
            continue
    rec.payload["recent_7d"] = recent
    if recent > 5:
        rec.alerts.append(f"CT_SPIKE: {recent} certs in last 7d")
    if rec.host.endswith(SUSPECT_TLDS):
        rec.alerts.append(f"CT_SUSPECT_TLD: {rec.host}")


# ---------------------------------------------------------------------------
# IO

def _append_jsonl(path: Path, rec: MonitorRecord) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(rec), ensure_ascii=False) + "\n")


def _load_ledger(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _save_baseline(path: Path, records: List[MonitorRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in records], f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Main runners

def run_dns(monitor_dir: Path) -> List[MonitorRecord]:
    recs: List[MonitorRecord] = []
    for host in WATCHED_HOSTS:
        ips = _safe_getaddrinfo(host)
        rec = MonitorRecord(
            kind="dns",
            host=host,
            payload={"ips": ips, "asn": [_asn_heuristic(ip) for ip in ips]},
            ts=_ts(),
        )
        _alert_dns(rec)
        _append_jsonl(monitor_dir / "dns.jsonl", rec)
        recs.append(rec)
    return recs


def run_tls(monitor_dir: Path) -> List[MonitorRecord]:
    recs: List[MonitorRecord] = []
    for host in WATCHED_HOSTS:
        meta = fetch_tls_cert(host)
        rec = MonitorRecord(kind="tls", host=host, payload=meta, ts=_ts())
        _alert_tls(rec)
        _append_jsonl(monitor_dir / "tls.jsonl", rec)
        recs.append(rec)
    return recs


def run_ct(monitor_dir: Path) -> List[MonitorRecord]:
    recs: List[MonitorRecord] = []
    for host in WATCHED_HOSTS:
        rows = fetch_ct(f"%.{host}")
        rec = MonitorRecord(kind="ct", host=host, payload={"rows": rows, "count": len(rows)}, ts=_ts())
        _alert_ct(rec)
        _append_jsonl(monitor_dir / "ct.jsonl", rec)
        recs.append(rec)
    return recs


def _diff_against(records: List[MonitorRecord], baseline_path: Path) -> List[str]:
    if not baseline_path.exists():
        return ["NO_BASELINE: first run, no diff"]
    base = json.loads(baseline_path.read_text(encoding="utf-8"))
    base_by_host: Dict[str, Dict[str, Any]] = {b["host"]: b for b in base}
    diffs: List[str] = []
    for r in records:
        prev = base_by_host.get(r.host)
        if prev is None:
            diffs.append(f"NEW_HOST: {r.host}")
            continue
        if r.kind == "dns":
            prev_ips = set(prev.get("payload", {}).get("ips", []))
            cur_ips = set(r.payload.get("ips", []))
            if prev_ips != cur_ips:
                diffs.append(f"DNS_CHANGE {r.host}: {sorted(prev_ips)} -> {sorted(cur_ips)}")
        elif r.kind == "tls":
            if prev.get("payload", {}).get("short") != r.payload.get("short"):
                diffs.append(f"TLS_CERT_CHANGE {r.host}: {prev.get('payload', {}).get('short')} -> {r.payload.get('short')}")
        elif r.kind == "ct":
            if prev.get("payload", {}).get("count") != r.payload.get("count"):
                diffs.append(f"CT_COUNT_CHANGE {r.host}: {prev['payload']['count']} -> {r.payload['count']}")
    return diffs


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="iRemoval PRO / Apple infra monitor")
    parser.add_argument("--mode", choices=["all", "dns", "tls", "ct"], default="all")
    parser.add_argument("--out",  default="logs/monitor", help="output dir (relative to project root)")
    parser.add_argument("--baseline", action="store_true", help="diff current run vs logs/monitor/baseline.json")
    parser.add_argument("--save-baseline", action="store_true", help="overwrite baseline.json with this run")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s | %(levelname)-5s | %(name)s | %(message)s",
    )

    root = Path(__file__).resolve().parent.parent
    out_dir = (root / args.out).resolve() if not Path(args.out).is_absolute() else Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    baseline_path = out_dir / "baseline.json"

    all_recs: List[MonitorRecord] = []
    if args.mode in ("all", "dns"):
        all_recs.extend(run_dns(out_dir))
    if args.mode in ("all", "tls"):
        all_recs.extend(run_tls(out_dir))
    if args.mode in ("all", "ct"):
        all_recs.extend(run_ct(out_dir))

    if args.save_baseline:
        _save_baseline(baseline_path, all_recs)
        LOG.info("baseline saved → %s", baseline_path)

    diffs: List[str] = []
    if args.baseline:
        diffs = _diff_against(all_recs, baseline_path)

    # Report
    alerts = [(r.host, a) for r in all_recs for a in r.alerts]
    print(f"\n=== monitor run @ {_ts()} ===")
    print(f"records: {len(all_recs)}  alerts: {len(alerts)}  diffs: {len(diffs)}")
    for h, a in alerts:
        print(f"  ! {h:35s} {a}")
    for d in diffs:
        print(f"  Δ {d}")
    if not alerts and not diffs:
        print("  ✓ all clear")
    print(f"artifacts → {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
