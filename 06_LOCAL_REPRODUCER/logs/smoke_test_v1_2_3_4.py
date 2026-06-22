"""Quick smoke test for the 3 new defensive-lab modules."""
import sys
sys.path.insert(0, "06_LOCAL_REPRODUCER")

from iact_reproducer import hmac_auth, rate_limit, blacklist

print("hmac_auth   :", hmac_auth.__name__)
print("rate_limit  :", rate_limit.__name__)
print("blacklist   :", blacklist.__name__)

# ---------------------------------------------------------------- HMAC
state = hmac_auth.load_or_create_state(
    secret_path="06_LOCAL_REPRODUCER/logs/hmac_secret.json"
)
print("AuthState   : accepted=%d refused=%d key_ids=%s" % (
    state.accepted, state.refused, list(state.secrets.keys())
))
# Sign and verify
headers = hmac_auth.make_signed_headers(
    state, method="POST",
    path="/iremovalActivation/iact8.php",
    body=b'{"udid":"DEF-1"}',
)
print("Signed hdrs :", {k: v[:16] + "..." for k, v in headers.items()})
ok, err = state.validate(
    method="POST", path="/iremovalActivation/iact8.php",
    headers=headers, body=b'{"udid":"DEF-1"}',
)
print("Validate    : ok=%s err=%s" % (ok, err))

# Refuse unsigned
ok, err = state.validate(
    method="POST", path="/iremovalActivation/iact8.php",
    headers={}, body=b'{"udid":"DEF-1"}',
)
print("Unsigned    : ok=%s err=%s" % (ok, err))

# Public endpoint should pass without headers
ok, err = state.validate(
    method="GET", path="/ping.ph", headers={}, body=b""
)
print("Public path : ok=%s err=%s" % (ok, err))

# ---------------------------------------------------------------- RL
rl = rate_limit.RateLimiter(rate_limit.RateLimitConfig(per_ip_limit=2))
for i in range(4):
    ok, why, retry = rl.consume(ip="127.0.0.1", udid="TEST-1")
    print("  RL test %d: ok=%s reason=%s retry=%ds" % (i, ok, why, retry))

# ---------------------------------------------------------------- BL
bl = blacklist.Blacklist.load("06_LOCAL_REPRODUCER/logs/blacklist.json")
ok, hits = bl.check(udid="DEFENSIVE-BLACKLISTED-0001")
print("Blacklist blocked UDID -> ok=%s hits=%s" % (ok, hits))
ok, hits = bl.check(udid="DEFENSIVE-GOOD-001")
print("Blacklist good UDID    -> ok=%s hits=%s" % (ok, hits))
snap = bl.snapshot()
print("Blacklist entries      : udids=%d serials=%d imeis=%d ips=%d" % (
    len(snap["udids"]), len(snap["serials"]),
    len(snap["imeis"]), len(snap["ip_addresses"]),
))
print("ALL OK")
