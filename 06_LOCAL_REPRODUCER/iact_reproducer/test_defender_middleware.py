"""Smoke test for the new defender middleware (Axe #3).

Spawns the mock server on an ephemeral port with `--disable-hmac`,
posts (a) a forged ticket to /iremovalActivation/iact8.php — expecting
403 from the defender middleware, and (b) the same forged ticket with
`--disable-defender` — expecting the middleware to let it through.

This complements test_disable_flags.py (which only checks CLI plumbing)
and smoke_apple_drm.py (which hits the legacy explicit endpoint).
"""
import json
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
import http.server
import socketserver
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent

# Make apple_drm_defense importable for the same constants
sys.path.insert(0, str(ROOT))
import apple_drm_defense  # noqa: E402

from iact_reproducer import mock_server  # noqa: E402


# Module-level temp dir so server threads don't race the cleanup
TEMP_ROOT = Path(tempfile.mkdtemp(prefix="defender_test_"))
LOG_DIR = TEMP_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


def _forge_ticket():
    """Build a clearly-forged iActivation ticket payload.

    Triggers the defender with several checks:
      - BY-MOD-001  (modulus too short — 1024 bits)
      - BY-EXT-001  (bundle ID Cydia Substrate)
      - BY-EXT-005  (build marker iRemovalProWPF)
    """
    import base64
    return {
        "udid": "00000000-0000-0000-0000-DEADBEEF0001",
        "public_key_modulus": base64.b64encode(b"\x00" * 128).decode("ascii"),
        "plist": {
            "ActivationInfo": {
                "BundleIdentifier": "com.panyolsoft.blackhound",
            },
            "iRemovalRecord": "FAKE",
        },
        "client_build_marker": "iRemovalProWPF",
        "nonce": "N" * 32,
        "sequence_number": 1,
        "client_hwid": "FAKE-HWID-1234",
        "client_timestamp": 1700000000.0,
        "server_proc_ms": 0.5,
    }


def _spawn_server(disable_defender):
    """Boot the mock server in a thread on an ephemeral port."""
    from iact_reproducer import blacklist, hmac_auth, rate_limit

    auth = hmac_auth.load_or_create_state(secret_path=LOG_DIR / "hmac.json")
    limiter = rate_limit.RateLimiter(
        rate_limit.RateLimitConfig(per_ip_limit=10_000, per_udid_limit=10_000)
    )
    bl = blacklist.Blacklist.load(LOG_DIR / "bl.json")
    disabled = {"hmac", "blacklist", "rate_limit"}
    if disable_defender:
        disabled.add("defender")
    state = mock_server._State(
        LOG_DIR, auth=auth, limiter=limiter, blacklist_=bl,
        disabled_middleware=disabled,
    )
    mock_server._MockHandler.state = state

    class _TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    srv = _TS(("127.0.0.1", 0), mock_server._MockHandler)
    host, port = srv.server_address
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    return host, port, srv


def _post(host, port, path, body):
    url = f"http://{host}:{port}{path}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _get(host, port, path):
    url = f"http://{host}:{port}{path}"
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def _check_defender_blocks_iact8():
    host, port, srv = _spawn_server(disable_defender=False)
    try:
        forged = _forge_ticket()
        code, body = _post(host, port, "/iremovalActivation/iact8.php", forged)
        assert code == 403, f"expected 403 from defender middleware, got {code}"
        assert body.get("status") == "LAB_DRM_FORGERY_DETECTED", body
        assert body.get("intercepted_by") == "middleware:defender", body
        reasons = body.get("reasons", [])
        joined = " ".join(reasons)
        # At least BY-MOD-001, BY-EXT-001, BY-EXT-005 should be present
        assert "BY-MOD-001" in joined or "trop courte" in joined, reasons
        assert "BY-EXT-001" in joined, reasons
        return True, code
    finally:
        srv.shutdown()
        srv.server_close()


def _check_defender_skipped_when_disabled():
    host, port, srv = _spawn_server(disable_defender=True)
    try:
        forged = _forge_ticket()
        # With --disable-defender, the middleware passes through to the
        # iact8 handler. That handler will fail on parse_envelope (no
        # 'sig'/'alg'/'b64' fields), so we get 400 with a parse error.
        # The point: the defender must NOT short-circuit at 403.
        try:
            code, body = _post(host, port, "/iremovalActivation/iact8.php",
                               forged)
        except urllib.error.HTTPError as e:
            code = e.code
            try:
                body = json.loads(e.read().decode("utf-8"))
            except Exception:
                body = {"raw": e.reason}
        assert code != 403, (
            f"defender was NOT supposed to fire when --disable-defender: "
            f"code={code} body={body}"
        )
        assert "LAB_DRM_FORGERY_DETECTED" not in str(body), body
        return True, code
    finally:
        srv.shutdown()
        srv.server_close()


def _check_untouched_endpoints():
    """Endpoints without public_key_modulus must pass through the defender."""
    host, port, srv = _spawn_server(disable_defender=False)
    try:
        # /license.ph accepts any JSON shape and replies 200 — and it
        # does NOT carry public_key_modulus, so the defender must skip.
        code, body = _post(host, port, "/iremovalActivation/license.ph",
                           {"udid": "ABC"})
        assert code == 200, f"license.ph must remain 200: code={code} body={body}"
        assert body.get("status") == "LAB_LICENSE_VALID", body
        return True, code
    finally:
        srv.shutdown()
        srv.server_close()


def _check_lab_mode_exposes_defender():
    host, port, srv = _spawn_server(disable_defender=False)
    try:
        code, data = _get(host, port, "/lab_mode.ph")
        assert code == 200, f"/lab_mode.ph must be 200: {code}"
        guards = data.get("guards", {})
        assert "defender" in guards, f"defender missing from /lab_mode: {data}"
        assert guards["defender"]["active"] is True
        assert guards["defender"]["version"] == apple_drm_defense.AppleDRMDefender.VERSION
        return True, guards["defender"]
    finally:
        srv.shutdown()
        srv.server_close()


def _check_metrics_has_defender():
    host, port, srv = _spawn_server(disable_defender=False)
    try:
        # Fire one forged request so the defender runs at least once
        _post(host, port, "/iremovalActivation/iact8.php", _forge_ticket())
        url = f"http://{host}:{port}/metrics.ph"
        with urllib.request.urlopen(url, timeout=5) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
        # /metrics.ph is Prometheus text format, not JSON.
        assert 'iact_mock_skipped_guards_total{guard="defender"}' in body, body[:400]
        return True, "metric line present"
    finally:
        srv.shutdown()
        srv.server_close()


def main():
    checks = []
    for label, fn in [
        ("M1 defender blocks forged ticket on /iact8.php", _check_defender_blocks_iact8),
        ("M2 defender skips when --disable-defender", _check_defender_skipped_when_disabled),
        ("M3 non-ticket endpoints untouched", _check_untouched_endpoints),
        ("M4 /lab_mode.ph exposes defender guard", _check_lab_mode_exposes_defender),
        ("M5 /metrics.ph exposes defender counter", _check_metrics_has_defender),
    ]:
        try:
            ok, info = fn()
            checks.append((label, ok, str(info)[:80]))
            print(f"  [OK] {label}  -> {info}")
        except AssertionError as e:
            checks.append((label, False, str(e)))
            print(f"  [X]  {label}  -> {e}")
    passed = sum(1 for _, ok, _ in checks if ok)
    print()
    print(f"  M-checks: {passed}/{len(checks)} pass")
    if passed != len(checks):
        print(">>>  RESULT: FAIL")
        return 1
    print(">>>  RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())