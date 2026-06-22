#!/usr/bin/env python3
"""
test_clone_server.py — Test du clone iRemovalClone standalone

Teste les 6 phases du flux bypass :
   1. version33.txt
   2. auth3.php
   3. checkm8.php
   4. iact8.php  (cœur du bypass)
   5. mf5/mf6/mf7.php
   6. pub.php

Usage :
   pip install requests
   py test_clone_server.py [host:port]
"""
import sys
import json
import base64
import requests

DEFAULT_HOST = "http://127.0.0.1:8080"


def b64_dec(s: str) -> bytes:
    """Décode du base64 (24 chars = 16 octets typique)."""
    return base64.b64decode(s)


def colored(s, c):
    codes = {"red": 31, "green": 32, "yellow": 33, "cyan": 36, "magenta": 35}
    return f"\033[{codes.get(c, 0)}m{s}\033[0m"


def test_version(base_url: str) -> bool:
    print(colored("\n[1] GET /version33.txt", "cyan"))
    r = requests.get(f"{base_url}/version33.txt")
    print(f"    Status: {r.status_code}, Server: {r.headers.get('Server', '?')}")
    print(f"    Body:   {r.text!r}")
    return r.status_code == 200 and r.text == "7.2"


def test_full_flow(base_url: str, device: dict) -> dict:
    print(colored("\n[2] POST /auth3.php  (Authentication)", "cyan"))
    r = requests.post(
        f"{base_url}/iremovalActivation/auth3.php",
        json={
            "udid":  device["udid"],
            "model": device["model"],
            "ios":   device["ios"],
        },
    )
    nonce_a = r.text.strip()
    print(f"    Status: {r.status_code}, nonceA: {nonce_a}")
    assert r.status_code == 200
    assert len(b64_dec(nonce_a)) == 16

    print(colored("\n[3] POST /checkm8.php  (Exploit ack)", "cyan"))
    cookies = r.cookies
    r = requests.post(
        f"{base_url}/iremovalActivation/checkm8.php",
        json={
            "udid":    device["udid"],
            "serial":  device["serial"],
            "imei":    device["imei"],
            "meid":    device["meid"],
            "ecid":    device["ecid"],
            "apnonce": device["apnonce"],
        },
        cookies=cookies,
    )
    nonce_b = r.text.strip()
    print(f"    Status: {r.status_code}, nonceB: {nonce_b}")
    assert r.status_code == 200
    assert len(b64_dec(nonce_b)) == 16

    print(colored("\n[4] POST /iact8.php  (Activation — HEART)", "magenta"))
    r = requests.post(
        f"{base_url}/iremovalActivation/iact8.php",
        json={"udid": device["udid"]},
        cookies=cookies,
    )
    nonce_c = r.text.strip()
    print(f"    Status: {r.status_code}, nonceC: {nonce_c}")
    assert r.status_code == 200
    assert len(b64_dec(nonce_c)) == 16

    # Try to fetch the generated ticket
    sess_id = list(cookies.values())[0] if cookies else None
    if sess_id:
        print(f"    Fetching ticket: /tickets/{sess_id}.json")
        tr = requests.get(f"{base_url}/tickets/{sess_id}.json")
        if tr.status_code == 200:
            ticket = tr.json()
            print(f"    ✓ iRemovalRecord:    {ticket['iRemovalRecord'][:60]}...")
            print(f"    ✓ iRemovalSignature: {ticket['iRemovalSignature'][:60]}...")
            print(f"    ✓ Algorithm:         {ticket['algorithm']}")
            return ticket

    return {}


def test_mf567(base_url: str, cookies) -> bool:
    print(colored("\n[5] POST /mf5.php + mf6.php + mf7.php", "cyan"))
    for ep in ["mf5", "mf6", "mf7"]:
        r = requests.post(
            f"{base_url}/iremovalActivation/{ep}.php",
            json={},
            cookies=cookies,
        )
        print(f"    {ep}: status={r.status_code}, nonce={r.text.strip()}")
        assert r.status_code == 200
        assert len(b64_dec(r.text.strip())) == 16
    return True


def test_pub(base_url: str) -> bool:
    print(colored("\n[6] POST /pub.php", "cyan"))
    r = requests.post(f"{base_url}/pub.php", json={"test": "x"})
    print(f"    Status: {r.status_code}, body: {r.text}")
    return r.status_code == 200


def main():
    base_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST

    print("=" * 70)
    print(colored(" iRemovalClone — Test E2E", "green"))
    print("=" * 70)
    print(f"Server: {base_url}")

    device = {
        "udid":   "00008101-001234567890ABCD",
        "serial": "F2LXX0Q0A1B2",
        "imei":   "359241080000000",
        "meid":   "35924100000000",
        "ecid":   "0x1234567890ABCDEF",
        "model":  "iPhone14,2",
        "ios":    "16.5",
        "apnonce": "0xDEADBEEF12345678",
    }

    try:
        if not test_version(base_url):
            print(colored("  ✗ version33.txt failed", "red"))
            return 1
        print(colored("  ✓ version33.txt OK", "green"))

        ticket = test_full_flow(base_url, device)
        if ticket:
            print(colored(f"\n  ✓ iact8.php OK — full ticket generated", "green"))
            print(f"    Public key in response:")
            pub = ticket.get("publicKey", "")
            if pub:
                # Find modulus
                import re
                m = re.search(r"Modulus:\s*\n([0-9A-Fa-f:\s]+)", pub, re.MULTILINE)
                if m:
                    print(f"      {m.group(1)[:60]}...")

        # Get cookies from previous session
        cookies = requests.post(
            f"{base_url}/iremovalActivation/auth3.php",
            json={"udid": device["udid"]},
        ).cookies

        if not test_mf567(base_url, cookies):
            return 1
        print(colored("  ✓ mf5/mf6/mf7.php OK", "green"))

        if not test_pub(base_url):
            return 1
        print(colored("  ✓ pub.php OK", "green"))

        print()
        print("=" * 70)
        print(colored(" ✓ ALL TESTS PASSED", "green"))
        print("=" * 70)
        return 0

    except AssertionError as e:
        print(colored(f"\n  ✗ ASSERTION FAILED: {e}", "red"))
        return 1
    except requests.exceptions.ConnectionError:
        print(colored(f"\n  ✗ Cannot connect to {base_url}", "red"))
        print("    Start the server with: cd backend/standalone && start.bat")
        return 1


if __name__ == "__main__":
    sys.exit(main())
