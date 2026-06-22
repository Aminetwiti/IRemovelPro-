"""End-to-end smoke test for the /apple_drm_check endpoint.

Spins the mock_server up in a background thread, sends three POSTs
(forged / legit / replay) and prints the JSONL log line for each so
we can see the defender counters increment.

Run with ::

    python 06_LOCAL_REPRODUCER\\iact_reproducer\\smoke_apple_drm.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# Use a 1024-bit modulus (too short) to trigger BY-EXT-002.
# (We don't import the banned SHA-1 here — using a short key is enough
# to exercise the static + session checks on the forged path.)
# We do however force the BY-MOD-001 path by reusing the *exact* banned
# modulus hex value from BYPASS_CORE.md §3.
_BANNED_MODULUS_HEX = (
    "b83b6e2f23ade61c4a324fa7b9223306"
    "6d9a588d961ea8ccfe3c7224ae2545fe"
    "62fd9cd30c947a454b05250f49ac3404"
    "afd38614164f21105dc0f7ab85022bc2"
    "a7f868a83fc4ac461d2991139b192695"
    "3a9feabdd9f3901613acfe6d59d94b20"
    "06f450b1c4a61f06eb43d688cf41f189"
    "9c821ed0c61428c4b6c276f6c6cc8581"
)

import threading  # noqa: E402
from http.server import HTTPServer  # noqa: E402

# Start the lab server in a thread (same module used by the CLI).
from iact_reproducer.mock_server import _MockHandler, _State  # noqa: E402
from iact_reproducer import hmac_auth, rate_limit, blacklist  # noqa: E402


def _start_server(port: int) -> HTTPServer:
    log_dir = _PKG_ROOT / "logs" / f"smoke_{int(time.time())}"
    log_dir.mkdir(parents=True, exist_ok=True)
    auth = hmac_auth.load_or_create_state()
    limiter = rate_limit.RateLimiter(rate_limit.RateLimitConfig(
        per_ip_limit=1000, per_udid_limit=1000,
    ))
    bl = blacklist.Blacklist.load(log_dir / "blacklist.json")
    state = _State(log_dir, auth=auth, limiter=limiter, blacklist_=bl,
                   disabled_middleware={"hmac", "rate_limit", "blacklist"})
    _MockHandler.state = state
    server = HTTPServer(("127.0.0.1", port), _MockHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    return server


def _post(port: int, path: str, payload: dict) -> tuple[int, dict]:
    url = f"http://127.0.0.1:{port}{path}"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # 403 is an *expected* response for a forged ticket — the
        # defender explicitly returns 403 + LAB_DRM_FORGERY_DETECTED.
        body = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, {"raw": body}


def _get(port: int, path: str) -> tuple[int, object]:
    url = f"http://127.0.0.1:{port}{path}"
    with urllib.request.urlopen(url, timeout=5) as resp:
        body = resp.read().decode("utf-8")
        try:
            return resp.status, json.loads(body)
        except json.JSONDecodeError:
            return resp.status, body


def main() -> int:
    port = 18802
    server = _start_server(port)
    try:
        print(f"smoke_apple_drm: server on 127.0.0.1:{port}")

        # 1. Forged ticket — RSA-1024 + iRemovalRecord + build marker
        forged_mod = bytes.fromhex(_BANNED_MODULUS_HEX)
        forged = {
            "udid": "00000000-DEAD-BEEF-CAFE-000000000000",
            "public_key_modulus": base64.b64encode(forged_mod).decode("ascii"),
            "plist": {
                "ActivationState": "Activated",
                "iRemovalRecord": "FAKE==",
                "iRemovalSignature": "FAKE==",
            },
            "client_build_marker": "Blackhound iRemovalPro Public build 0.7.1 @2022",
            "nonce": "forged-nonce-1",
            "sequence_number": 1,
            "client_hwid": "hwid-pirate",
            "client_timestamp": time.time() - 3600,
            "server_proc_ms": 0.4,
        }
        code, body = _post(port, "/iremovalActivation/apple_drm_check.ph",
                           forged)
        print(f"\n--- forged ticket ---  HTTP {code}")
        print(json.dumps(body, ensure_ascii=False, indent=2))

        # 2. Legit ticket
        legit = {
            "udid": "00000000-AAAA-BBBB-CCCC-AAAAAAAAAAAA",
            "public_key_modulus": base64.b64encode(os.urandom(256)).decode("ascii"),
            "plist": {"ActivationState": "Activated",
                      "SerialNumber": "F2LXX0000000"},
            "nonce": "legit-nonce-1",
            "sequence_number": 1,
            "client_hwid": "hwid-legit-1",
            "client_timestamp": time.time(),
            "server_proc_ms": 12.5,
        }
        code, body = _post(port, "/iremovalActivation/apple_drm_check.ph",
                           legit)
        print(f"\n--- legit ticket ---  HTTP {code}")
        print(json.dumps(body, ensure_ascii=False, indent=2))

        # 3. Replay of legit (same nonce) -> BY-SES-001
        code, body = _post(port, "/iremovalActivation/apple_drm_check.ph",
                           legit)
        print(f"\n--- replay of legit ---  HTTP {code}")
        print(json.dumps(body, ensure_ascii=False, indent=2))

        # 4. /lab_mode.ph to confirm defender counters updated
        code, body = _get(port, "/lab_mode.ph")
        print(f"\n--- /lab_mode.ph ---  HTTP {code}")
        print(json.dumps(body, ensure_ascii=False, indent=2))
        return 0
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
