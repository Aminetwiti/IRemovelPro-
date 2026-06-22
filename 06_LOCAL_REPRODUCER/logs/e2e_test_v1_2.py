"""End-to-end test of v1.2 mock server (HMAC + rate limit + blacklist)."""
import sys
import time
sys.path.insert(0, "06_LOCAL_REPRODUCER")

from iact_reproducer import mock_server, hmac_auth, blacklist, rate_limit
import urllib.request, urllib.error, json, os

print("=== v1.2 mock_server smoke test ===")
print("marker mock_server :", mock_server.TEST_MARKER)
print("marker hmac_auth   :", hmac_auth.TEST_MARKER)
print("marker blacklist   :", blacklist.TEST_MARKER)
print("marker rate_limit  :", rate_limit.TEST_MARKER)
assert mock_server.TEST_MARKER == hmac_auth.TEST_MARKER == rate_limit.TEST_MARKER
print("core markers consistent")

auth_state = hmac_auth.load_or_create_state(
    secret_path="06_LOCAL_REPRODUCER/logs/hmac_secret.json"
)
limiter = rate_limit.RateLimiter(
    rate_limit.RateLimitConfig(per_ip_limit=3, per_udid_limit=2)
)
bl_path = "06_LOCAL_REPRODUCER/logs/blacklist_e2e.json"
if os.path.exists(bl_path):
    os.remove(bl_path)
bl = blacklist.Blacklist.load(bl_path)

state = mock_server._State(
    log_dir=__import__("pathlib").Path("06_LOCAL_REPRODUCER/logs/e2e"),
    auth=auth_state, limiter=limiter, blacklist_=bl,
)
mock_server._MockHandler.state = state

import threading, socketserver
httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0),
                                        mock_server._MockHandler)
httpd.allow_reuse_address = True
port = httpd.server_address[1]
t = threading.Thread(target=httpd.serve_forever, daemon=True)
t.start()
print(f"Server up on 127.0.0.1:{port}")
BASE = f"http://127.0.0.1:{port}"


def hit(method, path, body=None, sign=False, force_nonce=None):
    data = json.dumps(body or {}).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, method=method, data=data)
    req.add_header("Content-Type", "application/json")
    if sign:
        hdrs = hmac_auth.make_signed_headers(
            auth_state, method=method, path=path, body=data or b""
        )
        if force_nonce is not None:
            hdrs["X-Nonce"] = force_nonce
        for k, v in hdrs.items():
            req.add_header(k, v)
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"_raw": raw[:80].decode("utf-8", "replace")}


results = []

print("\n-- Test 1: public GET (no auth) --")
code, body = hit("GET", "/ping.ph")
print(f"  /ping.ph         -> {code} status={body.get('status')}")
results.append(("public GET", code == 200))

print("\n-- Test 2: POST without auth (should 401) --")
code, body = hit("POST", "/iremovalActivation/pub.ph", {"udid": "DEF-1"})
print(f"  pub.ph unsigned  -> {code} status={body.get('status')}")
results.append(("unsigned POST blocked", code == 401))

print("\n-- Test 3: POST with valid HMAC --")
code, body = hit("POST", "/iremovalActivation/pub.ph",
                 {"udid": "DEF-1"}, sign=True)
print(f"  pub.ph signed    -> {code} status={body.get('status')}")
results.append(("signed POST allowed", code == 200))

print("\n-- Test 4: rate limit (limit=3) --")
codes = []
for i in range(5):
    code, body = hit("POST", "/iremovalActivation/pub.ph",
                     {"udid": f"UDID-RL-{i}"}, sign=True)
    reason = body.get('reason') or body.get('status') or ''
    print(f"  req {i+1}         -> {code} status={body.get('status')} {reason}")
    codes.append(code)
results.append(("rate limit kicks in",
                429 in codes and codes.count(200) == 3))

print("\n-- Test 5: blacklist (UDID in seed list) --")
code, body = hit("POST", "/iremovalActivation/pub.ph",
                 {"udid": "LAB-BLACKLISTED-0001"}, sign=True)
print(f"  blocked UDID     -> {code} status={body.get('status')}")
print(f"  blocked_by       -> {body.get('blocked_by')}")
results.append(("blacklist blocks", code == 403))

print("\n-- Test 6: blacklist admin (add + remove) --")
code, body = hit("POST", "/iremovalActivation/blacklist_add.ph",
                 {"kind": "udid", "identifier": "TEMP-ADD-001",
                  "reason": "test"}, sign=True)
print(f"  add new          -> {code} added={body.get('added')}")
add_ok = code == 200 and body.get('added') is True
code, body = hit("POST", "/iremovalActivation/blacklist_remove.ph",
                 {"kind": "udid", "identifier": "TEMP-ADD-001"},
                 sign=True)
print(f"  remove same      -> {code} removed={body.get('removed')}")
rm_ok = code == 200 and body.get('removed') is True
results.append(("blacklist add/remove", add_ok and rm_ok))

print("\n-- Test 7: blacklist admin (no auth -> 401) --")
code, body = hit("POST", "/iremovalActivation/blacklist_add.ph",
                 {"kind": "udid", "identifier": "X"})
print(f"  no auth          -> {code} status={body.get('status')}")
results.append(("admin requires auth", code == 401))

print("\n-- Test 8: replay protection (same nonce twice) --")
code1, _ = hit("POST", "/iremovalActivation/pub.ph",
               {"udid": "REPLAY-1"}, sign=True,
               force_nonce="fixed-replay-nonce-1234")
code2, body2 = hit("POST", "/iremovalActivation/pub.ph",
                   {"udid": "REPLAY-1"}, sign=True,
                   force_nonce="fixed-replay-nonce-1234")
print(f"  first call       -> {code1}")
print(f"  replay call      -> {code2}  (should be 401)")
print(f"  replay err       -> {body2.get('error')}")
results.append(("replay protection", code1 == 200 and code2 == 401))

httpd.shutdown()

print("\n=== RESULTS ===")
for name, ok in results:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")
all_ok = all(ok for _, ok in results)
print(f"\n  TOTAL: {sum(ok for _, ok in results)}/{len(results)} passed")
if not all_ok:
    raise SystemExit(1)
print("ALL OK")
