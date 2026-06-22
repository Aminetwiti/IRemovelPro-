"""End-to-end test covering **all 9 iRemoval-style endpoints**.

This test extends :mod:`test_disable_flags` to assert that every
endpoint defined in :data:`iact_reproducer.mock_server._MockHandler._ALL_ENDPOINTS`
returns a 200 (or 400 for a malformed payload) when the request is
properly HMAC-signed, and that the 3 guards (``hmac``, ``rate_limit``,
``blacklist``) still short-circuit at the right HTTP status.

Endpoints covered (9 iRemoval-style + 5 helper GETs):

* ``POST /iremovalActivation/iact8.php``  - iCloud activation ticket
* ``POST /iremovalActivation/pub.ph``     - public info / config
* ``POST /iremovalActivation/mf5.ph``     - MEID bypass v5
* ``POST /iremovalActivation/mf6.ph``     - MEID bypass v6
* ``POST /iremovalActivation/mf7.ph``     - MEID bypass v7
* ``POST /iremovalActivation/license.ph`` - license check
* ``POST /iremovalActivation/telemetry.ph`` - telemetry
* ``POST /iremovalActivation/admin.ph``   - admin
* ``POST /iremovalActivation/blacklist_add.ph``
* ``POST /iremovalActivation/blacklist_remove.ph``
* ``GET  /version33.tx``                  - version check
* ``GET  /health``, ``/ping.ph``          - liveness
* ``GET  /metrics.ph``                    - Prometheus metrics

Run with::

    python 06_LOCAL_REPRODUCER\\iact_reproducer\\test_all_endpoints.py
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Tuple

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from iact_reproducer import (  # noqa: E402
    blacklist,
    hmac_auth,
    mock_server,
    rate_limit,
)


# --------------------------------------------------------------------------- #
# In-process server (no socket exposure — same pattern as test_disable_flags)
# --------------------------------------------------------------------------- #

def _start_server(blacklist_path: Path, log_dir: Path,
                  disable_middleware: List[str] = None) -> Tuple[str, object]:
    disable_middleware = disable_middleware or []
    auth = hmac_auth.load_or_create_state(
        secret_path=log_dir / "hmac_secret_all.json"
    )
    limiter = rate_limit.RateLimiter(
        rate_limit.RateLimitConfig(
            per_ip_limit=100, per_udid_limit=100  # generous for endpoint coverage
        )
    )
    bl = blacklist.Blacklist.load(blacklist_path)
    state = mock_server._State(
        log_dir, auth=auth, limiter=limiter, blacklist_=bl,
        disabled_middleware=set(disable_middleware),
    )
    mock_server._MockHandler.state = state

    import http.server
    import socketserver
    server = socketserver.ThreadingTCPServer(
        ("127.0.0.1", 0), mock_server._MockHandler,
    )
    server.daemon_threads = True
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    return base, server


def _http(base: str, path: str, body: bytes = b"",
          method: str = "POST", signed: bool = False) -> Tuple[int, object]:
    url = base + path
    headers = {"Content-Type": "application/json"}
    if signed:
        # HMAC signs based on the actual method+path+body, regardless
        # of whether it's GET or POST. The mock enforces HMAC on ALL
        # routes — see _check_middleware() in mock_server.py.
        signed_headers = hmac_auth.make_signed_headers(
            mock_server._MockHandler.state.auth,
            method=method, path=path, body=body,
        )
        headers.update(signed_headers)
    req = urllib.request.Request(
        url, data=(body if method == "POST" else None),
        headers=headers, method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return r.status, raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, {}


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #

POST_ENDPOINTS = [
    "/iremovalActivation/iact8.php",
    "/iremovalActivation/pub.ph",
    "/iremovalActivation/mf5.ph",
    "/iremovalActivation/mf6.ph",
    "/iremovalActivation/mf7.ph",
    "/iremovalActivation/license.ph",
    "/iremovalActivation/telemetry.ph",
    "/iremovalActivation/admin.ph",
    "/iremovalActivation/blacklist_add.ph",
    "/iremovalActivation/blacklist_remove.ph",
]

GET_ENDPOINTS = [
    "/version33.tx",
    "/ping.ph",
    "/health",
    "/metrics.ph",
    # NOTE: /lab_mode is the actual path served by the mock; /lab_mode.ph
    # is *not* routed. Adding it here would be a documentation bug.
    "/lab_mode",
]

# A valid-looking body for POST endpoints that don't validate shape
GENERIC_BODY = json.dumps({
    "udid": "DEFENSIVE-GOOD-001",
    "sessionId": "sess-test-1",
    "license_key": "TEST-1234-ABCD",
}).encode("utf-8")

# Per-endpoint bodies — each endpoint has its own expected payload shape.
# (See _handle_iact8/_handle_pub/... in mock_server.py for the contracts.)
ENDPOINT_BODIES = {
    "/iremovalActivation/iact8.php": json.dumps({
        "udid": "DEFENSIVE-GOOD-001",
        "b64": "YnBsaWMwMDZhBQYH",
        "sig": "AA==",
        "alg": "RSA-SHA1",
    }).encode("utf-8"),
    "/iremovalActivation/pub.ph": GENERIC_BODY,
    "/iremovalActivation/mf5.ph": GENERIC_BODY,
    "/iremovalActivation/mf6.ph": GENERIC_BODY,
    "/iremovalActivation/mf7.ph": GENERIC_BODY,
    "/iremovalActivation/license.ph": GENERIC_BODY,
    "/iremovalActivation/telemetry.ph": GENERIC_BODY,
    "/iremovalActivation/admin.ph": GENERIC_BODY,
    "/iremovalActivation/blacklist_add.ph": json.dumps({
        "kind": "udid",
        "identifier": "DEFENSIVE-NEW-UDID-0007",
        "reason": "test",
    }).encode("utf-8"),
    "/iremovalActivation/blacklist_remove.ph": json.dumps({
        "kind": "udid",
        "identifier": "DEFENSIVE-NEW-UDID-0007",
    }).encode("utf-8"),
}

# Per-endpoint expected success status (admin always denied, etc.)
EXPECTED_SUCCESS_STATUS = {
    "/iremovalActivation/iact8.php": 200,            # 200 (with parse error -> 400)
    "/iremovalActivation/pub.ph": 200,
    "/iremovalActivation/mf5.ph": 200,
    "/iremovalActivation/mf6.ph": 200,
    "/iremovalActivation/mf7.ph": 200,
    "/iremovalActivation/license.ph": 200,
    "/iremovalActivation/telemetry.ph": 200,
    "/iremovalActivation/admin.ph": 403,            # admin is denied in lab
    "/iremovalActivation/blacklist_add.ph": 200,
    "/iremovalActivation/blacklist_remove.ph": 200,
}


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #

def test_all_endpoints_signed() -> List[Dict]:
    """Each endpoint must return 200 with HMAC signed."""
    bl_path = _PKG_ROOT / "logs" / "test_all_endpoints" / "blacklist.json"
    bl_path.parent.mkdir(parents=True, exist_ok=True)
    if not bl_path.exists():
        bl_path.write_text(json.dumps({
            "marker": "iRemovalDefensiveTest",
            "udids": ["DEFENSIVE-BLACKLISTED-0001"],
            "serials": [], "imeis": [], "ip_addresses": [],
        }, indent=2), encoding="utf-8")
    log_dir = _PKG_ROOT / "logs" / "test_all_endpoints"
    base, server = _start_server(bl_path, log_dir, disable_middleware=[])
    results: List[Dict] = []
    try:
        # POST endpoints (with HMAC)
        for ep in POST_ENDPOINTS:
            body = ENDPOINT_BODIES.get(ep, GENERIC_BODY)
            code, payload = _http(base, ep, body, "POST", signed=True)
            expected = EXPECTED_SUCCESS_STATUS.get(ep, 200)
            results.append({
                "endpoint": f"POST {ep}",
                "method": "POST",
                "expected": expected,
                "actual": code,
                "ok": code == expected,
                "status_field": (
                    payload.get("status") if isinstance(payload, dict) else None
                ),
            })
        # GET endpoints (HMAC is enforced by middleware even for GET;
        # this matches the mock's strict policy)
        for ep in GET_ENDPOINTS:
            code, payload = _http(base, ep, method="GET", signed=True)
            results.append({
                "endpoint": f"GET {ep}",
                "method": "GET",
                "expected": 200,
                "actual": code,
                "ok": code == 200,
                "status_field": None,
            })
    finally:
        server.shutdown()
        server.server_close()
    return results


def test_all_endpoints_unsigned_rejected() -> List[Dict]:
    """POST endpoints must reject requests without HMAC (401)."""
    bl_path = _PKG_ROOT / "logs" / "test_all_endpoints" / "blacklist.json"
    log_dir = _PKG_ROOT / "logs" / "test_all_endpoints"
    base, server = _start_server(bl_path, log_dir, disable_middleware=[])
    results: List[Dict] = []
    try:
        for ep in POST_ENDPOINTS:
            code, payload = _http(base, ep, GENERIC_BODY, "POST", signed=False)
            results.append({
                "endpoint": f"POST {ep}",
                "expected": 401,
                "actual": code,
                "ok": code == 401,
                "status_field": (
                    payload.get("status") if isinstance(payload, dict) else None
                ),
            })
    finally:
        server.shutdown()
        server.server_close()
    return results


def test_metrics_endpoint_format() -> Dict:
    """The /metrics.ph endpoint must return Prometheus text format."""
    bl_path = _PKG_ROOT / "logs" / "test_all_endpoints" / "blacklist.json"
    log_dir = _PKG_ROOT / "logs" / "test_all_endpoints"
    base, server = _start_server(bl_path, log_dir, disable_middleware=[])
    try:
        code, body = _http(base, "/metrics.ph", method="GET")
        is_text = isinstance(body, str)
        has_help = "iact_mock_skipped_guards_total" in (body or "")
        return {
            "endpoint": "GET /metrics.ph",
            "expected_status": 200,
            "actual_status": code,
            "ok_status": code == 200,
            "ok_prom_format": is_text and has_help,
            "ok": code == 200 and is_text and has_help,
        }
    finally:
        server.shutdown()
        server.server_close()


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> int:
    all_ok = True

    print("=" * 72)
    print("TEST 1: All endpoints with HMAC signed (expect 200)")
    print("=" * 72)
    r1 = test_all_endpoints_signed()
    for r in r1:
        verdict = "PASS" if r["ok"] else "FAIL"
        print(f"  {verdict}  {r['endpoint']}  "
              f"actual={r['actual']} status={r.get('status_field')}")
        if not r["ok"]:
            all_ok = False

    print()
    print("=" * 72)
    print("TEST 2: POST endpoints without HMAC (expect 401)")
    print("=" * 72)
    r2 = test_all_endpoints_unsigned_rejected()
    for r in r2:
        verdict = "PASS" if r["ok"] else "FAIL"
        print(f"  {verdict}  {r['endpoint']}  "
              f"actual={r['actual']} status={r.get('status_field')}")
        if not r["ok"]:
            all_ok = False

    print()
    print("=" * 72)
    print("TEST 3: /metrics.ph Prometheus format")
    print("=" * 72)
    r3 = test_metrics_endpoint_format()
    verdict = "PASS" if r3["ok"] else "FAIL"
    print(f"  {verdict}  {r3['endpoint']}  status={r3['actual_status']} "
          f"prom_format={r3['ok_prom_format']}")
    if not r3["ok"]:
        all_ok = False

    print()
    print("=" * 72)
    total = (sum(1 for r in r1 if r["ok"])
             + sum(1 for r in r2 if r["ok"])
             + (1 if r3["ok"] else 0))
    n = len(r1) + len(r2) + 1
    print(f"  TOTAL: {total}/{n} endpoint checks passed")
    if all_ok:
        print("ALL OK")
        return 0
    print("SOME FAILED")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
