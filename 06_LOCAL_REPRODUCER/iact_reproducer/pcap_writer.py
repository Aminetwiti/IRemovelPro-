# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/pcap_writer.py
"""Synthesise a PCAP of the wire traffic between the iRemoval client
and the ``iact8.php`` endpoint.

Real iRemoval PRO uses HTTPS to ``s13.iremovalpro.com``. We obviously
cannot decrypt the real session, but we *can* synthesise a PCAP file
that contains the exact same HTTP/1.1 message shapes (URL, method,
headers, body) so that:

  * Suricata rules from ``05_IOC/SURICATA_RULES.rules`` can be tested
  * Zeek logs can be generated end-to-end against the iRemoval HTTP
    shape without ever hitting the real server
  * analysts can replay the traffic in Wireshark for training

The PCAP uses the standard libpcap file format. Each HTTP request is
written as a single TCP stream with the appropriate client → server
and server → client exchanges.

This file is generated **for OFFENSIVE  training**. The body is a
bplist00 envelope produced by our reproducer; the synthetic server
response is also produced by our mock. No real activation ticket
bytes ever appear in the trace.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import logging
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Tuple

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from iact_reproducer import wire_format  # noqa: E402

log = logging.getLogger("iact_pcap")

TEST_MARKER = "iRemovalOFFENSIVE Test"

# ---------------------------------------------------------------------------- #
# PCAP constants
# ---------------------------------------------------------------------------- #

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCPCAP_VERSION_MINOR = 4
PCAP_LINKTYPE_RAW = 101   # Raw IP
PCAP_LINKTYPE_ETHERNET = 1

DEFAULT_CLIENT_IP = "10.0.0.42"
DEFAULT_SERVER_IP = "5.252.32.98"   # the real StormWall IP we fingerprinted
DEFAULT_SERVER_PORT = 443
DEFAULT_CLIENT_PORT = 51432


# ---------------------------------------------------------------------------- #
# PCAP writer (libpcap format, little-endian)
# ---------------------------------------------------------------------------- #

@dataclass
class _Record:
    ts_sec: int
    ts_usec: int
    payload: bytes


class PcapWriter:
    """Tiny libpcap writer. Writes Ethernet/IPv4/TCP frames with
    pseudo-MD5 checksums (set to 0 for our purposes — Wireshark still
    parses them as long as the IP/TCP lengths are correct)."""

    def __init__(self, path: Path, linktype: int = PCAP_LINKTYPE_ETHERNET) -> None:
        self.path = Path(path)
        self.linktype = linktype
        self._fh = self.path.open("wb")
        self._write_global_header()

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -------------------------------------------------------------- #
    # File-level
    # -------------------------------------------------------------- #
    def _write_global_header(self) -> None:
        self._fh.write(struct.pack(
            "<IHHIIII",
            PCAP_MAGIC_LE,
            PCAP_VERSION_MAJOR,
            PCPCAP_VERSION_MINOR,
            0,                       # thiszone
            0,                       # sigfigs
            65535,                   # snaplen
            self.linktype,
        ))

    def _write_packet(self, ts: _dt.datetime, payload: bytes) -> None:
        sec = int(ts.timestamp())
        usec = ts.microsecond
        # Packet header: ts_sec, ts_usec, incl_len, orig_len
        self._fh.write(struct.pack("<IIII", sec, usec, len(payload), len(payload)))
        self._fh.write(payload)

    # -------------------------------------------------------------- #
    # Frame builders
    # -------------------------------------------------------------- #
    def write_eth_ip_tcp(
        self,
        ts: _dt.datetime,
        *,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        src_mac: bytes = b"\x02\x00\x00\x00\x00\x01",
        dst_mac: bytes = b"\x02\x00\x00\x00\x00\x02",
        flags: int = 0x18,   # PSH+ACK by default
        seq: int = 1000,
        ack: int = 0,
        payload: bytes = b"",
    ) -> None:
        tcp = self._build_tcp(
            src_port=src_port, dst_port=dst_port,
            flags=flags, seq=seq, ack=ack, payload=payload,
        )
        ip = self._build_ipv4(src_ip=src_ip, dst_ip=dst_ip, payload=tcp)
        eth = dst_mac + src_mac + b"\x08\x00" + ip
        self._write_packet(ts, eth)

    # -------------------------------------------------------------- #
    # Low-level protocol helpers
    # -------------------------------------------------------------- #
    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) | data[i + 1]
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return (~s) & 0xFFFF

    def _build_ipv4(self, *, src_ip: str, dst_ip: str, payload: bytes) -> bytes:
        s = bytes(int(x) for x in src_ip.split("."))
        d = bytes(int(x) for x in dst_ip.split("."))
        total_len = 20 + len(payload)
        ver_ihl = (4 << 4) | 5
        tos = 0
        ident = 0x1234
        flags_frag = 0x4000  # don't fragment
        ttl = 64
        proto = 6  # TCP
        header = struct.pack(
            ">BBHHHBBH4s4s",
            ver_ihl, tos, total_len, ident, flags_frag, ttl, proto, 0, s, d,
        )
        csum = self._checksum(header)
        header = header[:10] + struct.pack(">H", csum) + header[12:]
        return header + payload

    def _build_tcp(
        self, *,
        src_port: int, dst_port: int,
        flags: int, seq: int, ack: int,
        payload: bytes,
    ) -> bytes:
        data_offset = 5
        offset_reserved = (data_offset << 4)
        window = 65535
        header = struct.pack(
            ">HHIIBBHHH",
            src_port, dst_port, seq, ack,
            offset_reserved, flags, window, 0, 0,
        )
        # Pseudo-header for checksum
        pseudo = struct.pack(
            ">4s4sBBH",
            b"\x00\x00\x00\x00",  # src (not used)
            b"\x00\x00\x00\x00",  # dst
            0, 6, 20 + len(payload),
        )
        csum = self._checksum(pseudo + header + payload)
        header = header[:16] + struct.pack(">H", csum) + header[18:]
        return header + payload


# ---------------------------------------------------------------------------- #
# HTTP request/response synthesis
# ---------------------------------------------------------------------------- #

def _http_request(envelope: wire_format.IActEnvelope,
                  host: str = "s13.iremovalpro.com") -> bytes:
    body = envelope.to_json(indent=None).encode("utf-8")
    req = (
        f"POST /iremovalActivation/iact8.php HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: iRemovalPro/5.2 (OFFENSIVE Test)\r\n"
        f"Content-Type: application/json; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"X-iRemovalPRO-Version: 7.2\r\n"
        f"X-OFFENSIVE -Marker: {TEST_MARKER}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode("ascii") + body
    return req


def _http_response(body: bytes, status: int = 200) -> bytes:
    reason = {200: "OK", 400: "Bad Request", 404: "Not Found"}.get(status, "OK")
    resp = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Server: 5.252.32.98\r\n"
        f"Content-Type: application/json; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"X-OFFENSIVE -Marker: {TEST_MARKER}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii") + body
    return resp


# ---------------------------------------------------------------------------- #
# PCAP assembly
# ---------------------------------------------------------------------------- #

def synth_pcap(
    envelopes: List[wire_format.IActEnvelope],
    out_path: Path,
    *,
    client_ip: str = DEFAULT_CLIENT_IP,
    server_ip: str = DEFAULT_SERVER_IP,
) -> Path:
    """Write a PCAP with one full HTTP exchange per envelope."""
    out_path = Path(out_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    base_ts = _dt.datetime.now(tz=_dt.timezone.utc)
    client_port = DEFAULT_CLIENT_PORT

    with PcapWriter(out_path) as pcap:
        for i, env in enumerate(envelopes):
            ts = base_ts + _dt.timedelta(milliseconds=i * 250)
            # 3-way handshake
            pcap.write_eth_ip_tcp(
                ts, src_ip=client_ip, dst_ip=server_ip,
                src_port=client_port, dst_port=DEFAULT_SERVER_PORT,
                flags=0x02, seq=900 + i * 1000, ack=0, payload=b"",
            )
            pcap.write_eth_ip_tcp(
                ts + _dt.timedelta(milliseconds=10),
                src_ip=server_ip, dst_ip=client_ip,
                src_port=DEFAULT_SERVER_PORT, dst_port=client_port,
                flags=0x12, seq=500 + i * 1000, ack=901 + i * 1000, payload=b"",
            )
            pcap.write_eth_ip_tcp(
                ts + _dt.timedelta(milliseconds=20),
                src_ip=client_ip, dst_ip=server_ip,
                src_port=client_port, dst_port=DEFAULT_SERVER_PORT,
                flags=0x10, seq=901 + i * 1000, ack=501 + i * 1000, payload=b"",
            )

            # HTTP request
            request = _http_request(env)
            pcap.write_eth_ip_tcp(
                ts + _dt.timedelta(milliseconds=30),
                src_ip=client_ip, dst_ip=server_ip,
                src_port=client_port, dst_port=DEFAULT_SERVER_PORT,
                flags=0x18, seq=901 + i * 1000, ack=501 + i * 1000,
                payload=request,
            )

            # Server response
            server_body = json.dumps({
                "request_id": f"OFFENSIVE -{i:04d}",
                "status": "OFFENSIVE _MOCK_REFUSED",
                "OFFENSIVE _marker": TEST_MARKER,
                "udid": env.udid,
            }).encode("utf-8")
            response = _http_response(server_body)
            pcap.write_eth_ip_tcp(
                ts + _dt.timedelta(milliseconds=200),
                src_ip=server_ip, dst_ip=client_ip,
                src_port=DEFAULT_SERVER_PORT, dst_port=client_port,
                flags=0x18, seq=501 + i * 1000, ack=901 + i * 1000 + len(request),
                payload=response,
            )

            # FIN
            pcap.write_eth_ip_tcp(
                ts + _dt.timedelta(milliseconds=210),
                src_ip=client_ip, dst_ip=server_ip,
                src_port=client_port, dst_port=DEFAULT_SERVER_PORT,
                flags=0x11, seq=901 + i * 1000 + len(request),
                ack=501 + i * 1000 + len(response), payload=b"",
            )
            client_port += 1
    log.info("Wrote PCAP: %s", out_path)
    return out_path


# ---------------------------------------------------------------------------- #
# CLI
# ---------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="iact_pcap",
        description=(
            "Synthesise a PCAP of POST requests to iact8.php using the "
            "envelopes in a corpus directory. For IDS/Suricata training."
        ),
    )
    p.add_argument("--corpus", default="06_LOCAL_REPRODUCER/corpus")
    p.add_argument("--out", default="06_LOCAL_REPRODUCER/logs/iact8_traffic.pcap")
    p.add_argument("--limit", type=int, default=20,
                   help="Maximum number of envelopes to embed.")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    corpus = Path(args.corpus).resolve()
    envelopes: List[wire_format.IActEnvelope] = []
    for jpath in sorted(corpus.rglob("*.json")):
        if jpath.name == "corpus_summary.json":
            continue
        try:
            raw = json.loads(jpath.read_text(encoding="utf-8"))
            env = wire_format.IActEnvelope(**raw)
            envelopes.append(env)
        except Exception as exc:  # noqa: BLE001
            log.warning("Skipping %s: %s", jpath, exc)
        if len(envelopes) >= args.limit:
            break

    if not envelopes:
        print("No envelopes found in corpus. Run corpus_generator first.")
        return 2

    out = synth_pcap(envelopes, Path(args.out).resolve())
    print()
    print(f"PCAP written: {out}")
    print(f"Envelopes embedded: {len(envelopes)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
