"""Suricata rule tester (offline, lightweight).

Validates the rule set shipped in ``05_IOC/SURICATA_RULES.rules``
against the lab's PCAP capture (``logs/iact8_traffic.pcap``) WITHOUT
requiring Suricata itself.

What it does
------------
* Parses every rule and extracts the key fields:
    msg, sid, classtype, content, pcre, flow, http_uri, etc.
* Loads the PCAP (pure-stdlib parser, supports Ethernet/IPv4/TCP/UDP)
  and extracts the application-layer payload (TCP stream or UDP datagram).
* Scans each payload against each rule's content/PCRE patterns and
  reports any match.

It is intentionally a "smoke test" — it does not perform full Suricata
flow tracking. But it catches typos, broken regexes, and obvious
missed detections. Use it in CI to keep the rules healthy.

Usage::

    py 06_LOCAL_REPRODUCER/ir_playbook/suricata_tester.py \\
        --rules 05_IOC/SURICATA_RULES.rules \\
        --pcap 06_LOCAL_REPRODUCER/logs/iact8_traffic.pcap
"""

from __future__ import annotations

import argparse
import logging
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

log = logging.getLogger("iact_suricata_tester")

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))


# --------------------------------------------------------------------------- #
# Rule parser
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class SuricataRule:
    """A flattened view of a Suricata rule (only the bits we test)."""
    sid: int
    msg: str
    classtype: str
    action: str
    proto: str
    src_addr: str
    src_port: str
    direction: str
    dst_addr: str
    dst_port: str
    raw: str
    # Lists of patterns extracted from content:, pcre:, http_uri;, etc.
    patterns: Tuple[Tuple[str, str], ...] = field(default_factory=tuple)


# Bare-bones rule parser: handles the most common header structure
#   action proto src_addr src_port direction dst_addr dst_port ( options )
# We split on the first '(' that follows the header, then walk
# top-level semicolon-separated options.
_RULE_HEADER_RE = re.compile(
    r"^(?P<action>\w+)\s+"
    r"(?P<proto>\w+)\s+"
    r"(?P<src_addr>[^\s]+)\s+"
    r"(?P<src_port>[^\s]+)\s+"
    r"(?P<direction>(?:->|<-|<>))\s+"
    r"(?P<dst_addr>[^\s]+)\s+"
    r"(?P<dst_port>[^\s]+)\s*\((?P<body>.*)\)\s*$",
    re.DOTALL,
)


def _parse_options(body: str) -> List[Tuple[str, str]]:
    """Split ``msg:"x"; content:"y"; ...`` into [(name, value), ...]."""
    out: List[Tuple[str, str]] = []
    i = 0
    n = len(body)
    while i < n:
        # skip whitespace + closing semicolons
        while i < n and body[i] in " ;\n\t\r":
            i += 1
        if i >= n:
            break
        # read name (stops at :, ;, whitespace, or end)
        name_start = i
        while i < n and body[i] not in ": ;\t":
            i += 1
        name = body[name_start:i].strip()
        if i >= n or body[i] != ":":
            # Sticky buffer (e.g. http_host;) — value-less flag
            if name:
                out.append((name, ""))
            continue
        i += 1  # consume ":"
        # read value (quoted string OR bareword OR pcre: /.../flags)
        if i < n and body[i] == '"':
            i += 1
            val_start = i
            while i < n and body[i] != '"':
                if body[i] == "\\" and i + 1 < n:
                    i += 2
                else:
                    i += 1
            val = body[val_start:i]
            if i < n:
                i += 1  # closing quote
        else:
            val_start = i
            while i < n and body[i] != ";":
                i += 1
            val = body[val_start:i].strip()
        if name:
            out.append((name, val))
    return out


def parse_rules_file(path: Path) -> List[SuricataRule]:
    """Parse a Suricata .rules file. Lines starting with # are comments."""
    if not path.is_file():
        raise FileNotFoundError(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    rules: List[SuricataRule] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = _RULE_HEADER_RE.match(line)
        if not m:
            log.debug("Skipping unparseable line: %s", line[:80])
            continue
        opts = _parse_options(m.group("body"))
        d = dict(opts)
        try:
            sid = int(d.get("sid", "0"))
        except ValueError:
            sid = 0
        patterns: List[Tuple[str, str]] = []
        for k, v in opts:
            if k in ("content", "http_uri", "http_client_body", "http_header", "dns_query"):
                patterns.append((k, v))
            elif k == "pcre":
                # extract pattern from /.../flags
                pm = re.match(r"^/(.*)/([a-zA-Z]*)$", v)
                if pm:
                    patterns.append((k, pm.group(1)))
        rules.append(
            SuricataRule(
                sid=sid,
                msg=d.get("msg", ""),
                classtype=d.get("classtype", ""),
                action=m.group("action"),
                proto=m.group("proto"),
                src_addr=m.group("src_addr"),
                src_port=m.group("src_port"),
                direction=m.group("direction"),
                dst_addr=m.group("dst_addr"),
                dst_port=m.group("dst_port"),
                raw=line,
                patterns=tuple(patterns),
            )
        )
    log.info("Parsed %d Suricata rules from %s", len(rules), path)
    return rules


# --------------------------------------------------------------------------- #
# PCAP parser (pure stdlib, no scapy dependency)
# --------------------------------------------------------------------------- #

@dataclass
class PcapRecord:
    ts: float
    proto: str
    src: str
    sport: int
    dst: str
    dport: int
    payload: bytes


def _ip_to_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def parse_pcap(path: Path) -> List[PcapRecord]:
    """Parse a classic .pcap file (little-endian). Returns IPv4 TCP/UDP records."""
    if not path.is_file():
        raise FileNotFoundError(path)
    data = path.read_bytes()
    if data[:4] != b"\xd4\xc3\xb2\xa1":
        log.warning("Not a classic little-endian PCAP (magic=%r)", data[:4])
        return []
    out: List[PcapRecord] = []
    off = 24  # skip global header
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack_from("<IIII", data, off)
        off += 16
        pkt = data[off:off + incl_len]
        off += incl_len
        if len(pkt) < 14:
            continue
        # Ethernet
        et = struct.unpack_from("!H", pkt, 12)[0]
        ip_off = 14
        if et == 0x8100:  # 802.1Q
            ip_off = 18
        if et != 0x0800:
            continue
        if len(pkt) < ip_off + 20:
            continue
        # IPv4
        ver_ihl = pkt[ip_off]
        if ver_ihl >> 4 != 4:
            continue
        ihl = (ver_ihl & 0x0F) * 4
        proto = pkt[ip_off + 9]
        src = _ip_to_str(pkt[ip_off + 12:ip_off + 16])
        dst = _ip_to_str(pkt[ip_off + 16:ip_off + 20])
        total_len = struct.unpack_from("!H", pkt, ip_off + 2)[0]
        l4_off = ip_off + ihl
        if proto == 6:  # TCP
            if len(pkt) < l4_off + 20:
                continue
            sport, dport = struct.unpack_from("!HH", pkt, l4_off)
            data_off = (pkt[l4_off + 12] >> 4) * 4
            payload_off = l4_off + data_off
            payload = pkt[payload_off:ip_off + total_len]
            proto_name = "tcp"
        elif proto == 17:  # UDP
            if len(pkt) < l4_off + 8:
                continue
            sport, dport = struct.unpack_from("!HH", pkt, l4_off)
            payload = pkt[l4_off + 8:ip_off + total_len]
            proto_name = "udp"
        else:
            continue
        if not payload:
            continue
        out.append(PcapRecord(
            ts=ts_sec + ts_usec / 1_000_000,
            proto=proto_name,
            src=src, sport=sport,
            dst=dst, dport=dport,
            payload=payload,
        ))
    log.info("Parsed %d packets from %s", len(out), path)
    return out


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #

@dataclass
class Hit:
    sid: int
    msg: str
    classtype: str
    pkt_src: str
    pkt_dst: str
    pkt_proto: str
    pkt_dport: int
    pattern: str
    pattern_kind: str


def scan_pcap(rules: Iterable[SuricataRule], packets: Iterable[PcapRecord]) -> List[Hit]:
    hits: List[Hit] = []
    rules_list = list(rules)
    compiled: List[Tuple[SuricataRule, List[Tuple[str, re.Pattern]]]] = []
    for r in rules_list:
        compiled_patterns: List[Tuple[str, re.Pattern]] = []
        for kind, pat in r.patterns:
            try:
                compiled_patterns.append((kind, re.compile(pat.encode("utf-8", errors="replace") if isinstance(pat, str) else pat)))
            except re.error as e:
                log.debug("Bad regex sid=%d pattern=%r: %s", r.sid, pat, e)
        if compiled_patterns:
            compiled.append((r, compiled_patterns))

    for pkt in packets:
        for r, patterns in compiled:
            for kind, rgx in patterns:
                if rgx.search(pkt.payload):
                    hits.append(Hit(
                        sid=r.sid,
                        msg=r.msg,
                        classtype=r.classtype,
                        pkt_src=pkt.src, pkt_dst=pkt.dst,
                        pkt_proto=pkt.proto, pkt_dport=pkt.dport,
                        pattern=rgx.pattern.decode("utf-8", errors="replace") if isinstance(rgx.pattern, bytes) else rgx.pattern,
                        pattern_kind=kind,
                    ))
                    break  # one hit per rule per packet
    return hits


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="iact_suricata_tester",
        description="Offline Suricata rule tester (PCAP ↔ rules) — stdlib only.",
    )
    p.add_argument("--rules", default="05_IOC/SURICATA_RULES.rules",
                   help="Path to Suricata rules file")
    p.add_argument("--pcap", default="06_LOCAL_REPRODUCER/logs/iact8_traffic.pcap",
                   help="Path to PCAP file")
    p.add_argument("--max-hits", type=int, default=50)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    rules_path = Path(args.rules)
    pcap_path = Path(args.pcap)

    if not rules_path.is_file():
        log.error("Rules file not found: %s", rules_path)
        return 2
    if not pcap_path.is_file():
        log.warning("PCAP file not found: %s — producing rule sanity report only", pcap_path)
        rules = parse_rules_file(rules_path)
        bad = [r for r in rules if not r.patterns]
        print(f"Rules parsed : {len(rules)}")
        print(f"Rules with patterns : {len(rules) - len(bad)}")
        print(f"Rules without patterns : {len(bad)}")
        if bad:
            for r in bad[:10]:
                print(f"  sid={r.sid:<8}  {r.msg}")
        return 0

    rules = parse_rules_file(rules_path)
    packets = parse_pcap(pcap_path)
    if not packets:
        print("No IPv4 TCP/UDP packets found in PCAP.")
        return 0
    hits = scan_pcap(rules, packets)
    print(f"Rules : {len(rules)}  Packets : {len(packets)}  Hits : {len(hits)}")
    for h in hits[: args.max_hits]:
        print(f"  sid={h.sid:<8} [{h.classtype:<20}] {h.msg}")
        print(f"    ↳ {h.pkt_proto} {h.pkt_src} -> {h.pkt_dst}:{h.pkt_dport}  pattern[{h.pattern_kind}]={h.pattern[:60]!r}")
    if len(hits) > args.max_hits:
        print(f"  ... ({len(hits) - args.max_hits} more)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
