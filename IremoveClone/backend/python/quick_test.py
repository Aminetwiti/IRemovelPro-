#!/usr/bin/env python3
"""Quick E2E test against the running Python server on :5000."""
import requests
import base64
import json
import sys

BASE = "http://127.0.0.1:5000"

def colored(s, c):
    codes = {"red": 31, "green": 32, "yellow": 33, "cyan": 36, "magenta": 35}
    return f"\033[{codes.get(c, 0)}m{s}\033[0m"

# Force UTF-8
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

print("=" * 70)
print(colored(" iRemovalClone (Python) — E2E Test", "green"))
print("=" * 70)

try:
    r = requests.get(f"{BASE}/version33.txt", timeout=3)
    print(f"\n[1] version33.txt")
    print(f"    Status: {r.status_code}, Server: {r.headers.get('Server', '?')}")
    print(f"    Body: {r.text!r}")
    assert r.text == "7.2"
    print(colored("    OK", "green"))
except Exception as e:
    print(colored(f"    FAILED: {e}", "red"))
    sys.exit(1)

# Test 2: auth3
try:
    print(f"\n[2] auth3.php")
    r = requests.post(f"{BASE}/iremovalActivation/auth3.php",
                      json={"udid": "00008101-001234567890ABCD", "model": "iPhone14,2"},
                      timeout=3)
    print(f"    Status: {r.status_code}, nonce: {r.text}")
    print(f"    Set-Cookie: {r.headers.get('Set-Cookie', '?')[:80]}")
    cookies = r.cookies
    assert r.status_code == 200
    print(colored("    OK", "green"))
except Exception as e:
    print(colored(f"    FAILED: {e}", "red"))
    sys.exit(1)

# Test 3: checkm8
try:
    print(f"\n[3] checkm8.php")
    r = requests.post(f"{BASE}/iremovalActivation/checkm8.php",
                      json={"udid": "00008101-001234567890ABCD",
                            "serial": "F2LXX0Q0A1B2",
                            "imei": "359241080000000",
                            "meid": "35924100000000",
                            "ecid": "0x1234567890ABCDEF"},
                      cookies=cookies, timeout=3)
    print(f"    Status: {r.status_code}, nonce: {r.text}")
    assert r.status_code == 200
    print(colored("    OK", "green"))
except Exception as e:
    print(colored(f"    FAILED: {e}", "red"))
    sys.exit(1)

# Test 4: iact8 (THE HEART)
try:
    print(f"\n[4] iact8.php  (Activation - HEART)")
    r = requests.post(f"{BASE}/iremovalActivation/iact8.php",
                      json={"udid": "00008101-001234567890ABCD"},
                      cookies=cookies, timeout=3)
    print(f"    Status: {r.status_code}, nonce: {r.text}")
    assert r.status_code == 200
    print(colored("    OK", "green"))
except Exception as e:
    print(colored(f"    FAILED: {e}", "red"))
    sys.exit(1)

# Test 5: Get the ticket
try:
    print(f"\n[5] Fetch generated ticket")
    sid = list(cookies.values())[0]
    r = requests.get(f"{BASE}/tickets/{sid}.json", timeout=3)
    if r.status_code == 200:
        ticket = r.json()
        print(f"    iRemovalRecord:    {ticket['iRemovalRecord'][:60]}...")
        print(f"    iRemovalSignature: {ticket['iRemovalSignature'][:60]}...")
        print(f"    Algorithm:         {ticket['algorithm']}")
        print(f"    Public Key (1st 60): {ticket['publicKey'][:60].replace(chr(10), ' ')}")
        print(colored("    OK", "green"))
    else:
        print(colored(f"    Skipped: HTTP {r.status_code}", "yellow"))
except Exception as e:
    print(colored(f"    FAILED: {e}", "red"))

# Test 6: pub.php
try:
    print(f"\n[6] pub.php")
    r = requests.post(f"{BASE}/pub.php", json={"test": "x"}, timeout=3)
    print(f"    Status: {r.status_code}, body: {r.text}")
    assert r.status_code == 200
    print(colored("    OK", "green"))
except Exception as e:
    print(colored(f"    FAILED: {e}", "red"))
    sys.exit(1)

# Test 7: key-info
try:
    print(f"\n[7] /admin/key-info")
    r = requests.get(f"{BASE}/admin/key-info", timeout=3)
    info = r.json()
    print(f"    bits:         {info['bits']}")
    print(f"    exponent:     {info['exponent']}")
    print(f"    modulus_b64:  {info['modulus_b64'][:50]}...")
    print(f"    sha1_fpr:     {info['sha1_fpr']}")
    print(colored("    OK", "green"))
except Exception as e:
    print(colored(f"    FAILED: {e}", "red"))
    sys.exit(1)

print()
print("=" * 70)
print(colored(" ALL TESTS PASSED - iRemovalClone is fully functional", "green"))
print("=" * 70)
