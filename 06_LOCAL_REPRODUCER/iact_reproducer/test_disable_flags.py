"""End-to-end matrix test for the mock-server ``--disable-*`` flags.

Exercises all 8 on/off combinations of the three v1.2 / v1.3 / v1.4
guards and asserts that each guard, when active, blocks the matching
attack vector:

  * ``blacklist``    (v1.4) blocks a UDID known to be in the seed list
  * ``rate_limit``   (v1.3) blocks a request burst beyond the per-IP budget
  * ``hmac``         (v1.2) blocks a request that lacks ``X-Signature``

The test boots an **in-process** server (no socket, no extra process) by
subclassing ``_MockHandler`` and using ``http.server.HTTPServer`` on an
ephemeral port. The matrix is asserted in a single process for speed.

Run with::

    python 06_LOCAL_REPRODUCER\\iact_reproducer\\test_disable_flags.py
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

# Make the iact_reproducer package importable when run as a script.
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
# In-process server
# --------------------------------------------------------------------------- #

def _start_server(blacklist_path: Path, log_dir: Path,
                  disable_hmac: bool, disable_blacklist: bool,
                  disable_rate_limit: bool) -> Tuple[str, mock_server._State]:
    """Boot the mock server in-process and return ``(base_url, state)``."""
    auth = hmac_auth.load_or_create_state(
        secret_path=log_dir / "hmac_secret_e2e.json"
    )
    # Tight rate-limit budget so the test is fast.
    limiter = rate_limit.RateLimiter(
        rate_limit.RateLimitConfig(per_ip_limit=2, per_udid_limit=2)
    )
    bl = blacklist.Blacklist.load(blacklist_path)
    state = mock_server._State(
        log_dir, auth=auth, limiter=limiter, blacklist_=bl,
        disabled_middleware={
            *([] if not disable_hmac else ["hmac"]),
            *([] if not disable_blacklist else ["blacklist"]),
            *([] if not disable_rate_limit else ["rate_limit"]),
        },
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
    return base, state, server


def _http(base: str, path: str, body: bytes,
          signed: bool = False) -> Tuple[int, Dict]:
    url = base + path
    headers = {"Content-Type": "application/json"}
    if signed:
        signed_headers = hmac_auth.make_signed_headers(
            mock_server._MockHandler.state.auth,
            method="POST", path=path, body=body,
        )
        headers.update(signed_headers)
    req = urllib.request.Request(
        url, data=body, headers=headers, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, {}


# --------------------------------------------------------------------------- #
# Matrix
# --------------------------------------------------------------------------- #

# A UDID we know is in the seed list of the blacklist module.
BAD_UDID = "DEFENSIVE-BLACKLISTED-0001"
GOOD_UDID = "DEFENSIVE-GOOD-001"

PUB_PATH = "/iremovalActivation/pub.ph"


def _hit_until_blocked(base: str, signed: bool) -> int:
    """Send requests until the limiter blocks or we hit a cap of 10."""
    for i in range(10):
        body = json.dumps({"udid": GOOD_UDID}).encode("utf-8")
        code, _ = _http(base, PUB_PATH, body, signed=signed)
        if code == 429:
            return 429
    return code  # last code we saw


def _matrix_case(base: str, d_hmac: bool, d_bl: bool, d_rl: bool) -> Dict:
    """Run one (hmac, blacklist, rate_limit) combination.

    Order is important: blacklist (cheapest) -> rate_limit (modifies
    internal state) -> hmac (last so its check is not perturbed by a
    429 from a previous burst on the same IP/UDID). After each check
    the limiter is reset so the next check starts with a clean budget.
    """
    result: Dict = {
        "combo": (d_hmac, d_bl, d_rl),
        "checks": {},
    }

    # 1) Blacklist check: BAD_UDID should be blocked iff blacklist active.
    # We disable rate_limit temporarily for this check by resetting the
    # limiter so the burst above (if any) doesn't poison the budget.
    mock_server._MockHandler.state.limiter.reset()
    body = json.dumps({"udid": BAD_UDID}).encode("utf-8")
    code, payload = _http(base, PUB_PATH, body, signed=True)
    expected = 403 if not d_bl else 200
    result["checks"]["blacklist_blocks_bad_udid"] = {
        "expected_status": expected,
        "actual_status": code,
        "ok": code == expected,
        "response_status": payload.get("status"),
    }

    # 2) Rate limit check: a burst of 5 requests should yield 429 iff
    #    rate_limit is active.
    mock_server._MockHandler.state.limiter.reset()
    rl_code = _hit_until_blocked(base, signed=True)
    expected_rl_blocked = not d_rl
    rl_ok = (rl_code == 429) == expected_rl_blocked
    result["checks"]["rate_limit_burst"] = {
        "expected_blocked": expected_rl_blocked,
        "actual_code": rl_code,
        "ok": rl_ok,
    }

    # 3) HMAC check: an UNSIGNED request should yield 401 iff hmac active.
    # Use a fresh UDID and reset the limiter so previous bursts don't
    # leak into this check.
    mock_server._MockHandler.state.limiter.reset()
    body = json.dumps({"udid": f"FRESH-HMAC-{time.time_ns()}"}).encode("utf-8")
    code, payload = _http(base, PUB_PATH, body, signed=False)
    expected_h = 401 if not d_hmac else 200
    result["checks"]["hmac_blocks_unsigned"] = {
        "expected_status": expected_h,
        "actual_status": code,
        "ok": code == expected_h,
        "response_status": payload.get("status"),
    }

    return result


def main() -> int:
    log_dir = _PKG_ROOT / "logs" / "test_disable_flags"
    log_dir.mkdir(parents=True, exist_ok=True)
    bl_path = log_dir / "blacklist_e2e.json"
    if not bl_path.exists():
        # Marker must match blacklist.TEST_MARKER ("iRemovalDefensiveTest")
        # or Blacklist.load() will refuse the file.
        bl_path.write_text(json.dumps({
            "marker": "iRemovalDefensiveTest",
            "udids": [BAD_UDID],
            "serials": [], "imeis": [], "ip_addresses": [],
        }, indent=2), encoding="utf-8")

    cases: List[Dict] = []
    for d_hmac in (False, True):
        for d_bl in (False, True):
            for d_rl in (False, True):
                print(f"\n=== combo hmac={'OFF' if d_hmac else 'ON'}  "
                      f"bl={'OFF' if d_bl else 'ON'}  "
                      f"rl={'OFF' if d_rl else 'ON'} ===")
                base, state, server = _start_server(
                    bl_path, log_dir,
                    disable_hmac=d_hmac,
                    disable_blacklist=d_bl,
                    disable_rate_limit=d_rl,
                )
                try:
                    res = _matrix_case(base, d_hmac, d_bl, d_rl)
                    for cname, c in res["checks"].items():
                        verdict = "PASS" if c["ok"] else "FAIL"
                        print(f"  {verdict}  {cname}: {c}")
                    cases.append(res)
                finally:
                    server.shutdown()
                    server.server_close()

    print("\n" + "=" * 72)
    total = sum(
        1 for c in cases for chk in c["checks"].values() if chk["ok"]
    )
    n_checks = sum(len(c["checks"]) for c in cases)
    print(f"  TOTAL: {total}/{n_checks} matrix checks passed")

    failed = [
        (c["combo"], name, chk)
        for c in cases
        for name, chk in c["checks"].items()
        if not chk["ok"]
    ]
    if failed:
        print("\n  FAILURES:")
        for combo, name, chk in failed:
            print(f"    {combo}  {name}  ->  {chk}")
        return 1
    print("ALL OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
