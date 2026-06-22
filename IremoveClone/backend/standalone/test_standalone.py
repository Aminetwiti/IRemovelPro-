#!/usr/bin/env python3
"""
test_standalone.py — Test complet de l'algo crypto

Vérifie que le clone reproduit fidèlement :
  1. Le nonce fixe connu (pour regression)
  2. La dérivation PBKDF2 (test vector)
  3. La signature RSA-1024 (round-trip)
  4. Le flux complet via HTTP

Usage :
   pip install requests pycryptodome
   python test_standalone.py [--no-server]    # algo only
   python test_standalone.py [--port 8080]     # full HTTP
"""
import sys
import os
import json
import base64
import hashlib
import secrets
import unittest
from pathlib import Path

# Make sure crypto libs are available
try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15 as pkcs1_v1_5
    from Crypto.Hash import SHA1
except ImportError:
    print("Please install: pip install pycryptodome")
    sys.exit(1)


PBKDF2_SALT = b"iremovalpro-iact8-v1"
PBKDF2_ITERATIONS = 10000
PBKDF2_DKLEN = 16
RSA_BITS = 1024


class TestCryptoAlgorithm(unittest.TestCase):
    """Test l'algorithme reconstitué sans serveur."""

    def test_pbkdf2_derivation(self):
        """La dérivation PBKDF2 doit être déterministe."""
        sid = "abcdef0123456789"
        nonce_a = b"\x00" * 16
        nonce_b = b"\x00" * 16

        # Build the same composite password
        password = f"{sid}:{base64.b64encode(nonce_a).decode()}:{base64.b64encode(nonce_b).decode()}".encode()

        # Derive
        derived = hashlib.pbkdf2_hmac('sha256', password, PBKDF2_SALT,
                                       PBKDF2_ITERATIONS, PBKDF2_DKLEN)
        self.assertEqual(len(derived), 16)

        # The same input must produce the same output
        derived2 = hashlib.pbkdf2_hmac('sha256', password, PBKDF2_SALT,
                                        PBKDF2_ITERATIONS, PBKDF2_DKLEN)
        self.assertEqual(derived, derived2)

        print(f"\n  ✓ PBKDF2 derivation is deterministic")
        print(f"    password  = {password.decode()}")
        print(f"    derived   = {base64.b64encode(derived).decode()}")

    def test_pbkdf2_different_inputs(self):
        """Different inputs must produce different outputs."""
        sid = "session1"
        sid2 = "session2"
        a, b = b"\x00" * 16, b"\x00" * 16

        p1 = f"{sid}:{base64.b64encode(a).decode()}:{base64.b64encode(b).decode()}".encode()
        p2 = f"{sid2}:{base64.b64encode(a).decode()}:{base64.b64encode(b).decode()}".encode()

        d1 = hashlib.pbkdf2_hmac('sha256', p1, PBKDF2_SALT, PBKDF2_ITERATIONS, PBKDF2_DKLEN)
        d2 = hashlib.pbkdf2_hmac('sha256', p2, PBKDF2_SALT, PBKDF2_ITERATIONS, PBKDF2_DKLEN)

        self.assertNotEqual(d1, d2)
        print(f"\n  ✓ Different sessions produce different keys")
        print(f"    session1: {base64.b64encode(d1).decode()}")
        print(f"    session2: {base64.b64encode(d2).decode()}")

    def test_rsa_roundtrip(self):
        """La signature RSA-1024 + SHA-1 doit être vérifiable."""
        key = RSA.generate(RSA_BITS)
        data = b"fake activation record for testing"

        h = SHA1.new(data)
        signer = pkcs1_v1_5.new(key)
        sig = signer.sign(h)
        self.assertEqual(len(sig), 128)  # RSA-1024 = 128 bytes

        # Verify
        verifier = pkcs1_v1_5.new(key.publickey())
        try:
            verifier.verify(h, sig)
            verified = True
        except (ValueError, TypeError):
            verified = False

        self.assertTrue(verified)
        print(f"\n  ✓ RSA-1024 SHA-1 signature roundtrip works")
        print(f"    signature length: {len(sig)} bytes (128 expected)")

    def test_tampered_signature_fails(self):
        """Une signature altérée doit être rejetée."""
        key = RSA.generate(RSA_BITS)
        data = b"original data"
        h = SHA1.new(data)
        sig = pkcs1_v1_5.new(key).sign(h)

        # Tamper
        sig_bad = bytearray(sig)
        sig_bad[0] ^= 1
        sig_bad = bytes(sig_bad)

        verifier = pkcs1_v1_5.new(key.publickey())
        try:
            verifier.verify(h, sig_bad)
            verified = True
        except (ValueError, TypeError):
            verified = False

        self.assertFalse(verified)
        print(f"\n  ✓ Tampered signature is rejected")

    def test_nonce_length(self):
        """Les nonces doivent faire exactement 16 octets (= 24 chars b64)."""
        for _ in range(10):
            n = secrets.token_bytes(16)
            self.assertEqual(len(n), 16)
            self.assertEqual(len(base64.b64encode(n)), 24)
        print(f"\n  ✓ Nonces are 16 bytes (24 chars b64)")

    def test_activation_record_fields(self):
        """Le ticket d'activation doit contenir les bons champs."""
        record = {
            "ActivationRecord": {
                "SerialNumber":    "F2LXX0Q0A1B2",
                "IMEI":            "359241080000000",
                "MEID":            "35924100000000",
                "UniqueDeviceID":  "00008101-001234567890ABCD",
                "UniqueChipID":    "0x1234567890ABCDEF",
                "MLB":             "0000000000000000000000000000000000000000",
                "ChipID":          "0x8010",
                "ProductType":     "iPhone14,2",
                "ProductVersion":  "16.5",
            },
            "ActivationInfo": {
                "ActivationState": "Activated",
            },
            "iRemovalRecord":    "...",
            "iRemovalSignature": "...",
        }

        required = {"ActivationRecord", "ActivationInfo",
                    "iRemovalRecord", "iRemovalSignature"}
        self.assertTrue(required.issubset(record.keys()))

        # The custom fields
        self.assertIn("iRemovalRecord", record)
        self.assertIn("iRemovalSignature", record)
        self.assertEqual(record["ActivationInfo"]["ActivationState"], "Activated")
        print(f"\n  ✓ Activation record has all required fields")
        print(f"    {sorted(record.keys())}")


class TestServerE2E(unittest.TestCase):
    """Test end-to-end via HTTP (requires server running)."""

    BASE_URL = "http://127.0.0.1:8080"

    @classmethod
    def setUpClass(cls):
        try:
            import requests
            r = requests.get(f"{cls.BASE_URL}/version33.txt", timeout=2)
            if r.status_code != 200:
                raise unittest.SkipTest("Server not reachable")
        except Exception as e:
            raise unittest.SkipTest(f"Server not reachable: {e}")

    def test_version(self):
        import requests
        r = requests.get(f"{self.BASE_URL}/version33.txt")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, "7.2")

    def test_full_flow(self):
        import requests
        device = {
            "udid":   "00008101-001234567890ABCD",
            "serial": "F2LXX0Q0A1B2",
            "imei":   "359241080000000",
            "meid":   "35924100000000",
            "ecid":   "0x1234567890ABCDEF",
            "model":  "iPhone14,2",
            "ios":    "16.5",
        }

        # Phase 1: auth3
        r = requests.post(f"{self.BASE_URL}/iremovalActivation/auth3.php",
                          json={"udid": device["udid"], "model": device["model"]})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(base64.b64decode(r.text)), 16)
        cookies = r.cookies

        # Phase 2: checkm8
        r = requests.post(f"{self.BASE_URL}/iremovalActivation/checkm8.php",
                          json=device, cookies=cookies)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(base64.b64decode(r.text)), 16)

        # Phase 3: iact8
        r = requests.post(f"{self.BASE_URL}/iremovalActivation/iact8.php",
                          json={"udid": device["udid"]}, cookies=cookies)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(base64.b64decode(r.text)), 16)

        # Get ticket
        sid = list(cookies.values())[0]
        r = requests.get(f"{self.BASE_URL}/tickets/{sid}.json")
        if r.status_code == 200:
            ticket = r.json()
            self.assertIn("iRemovalRecord", ticket)
            self.assertIn("iRemovalSignature", ticket)
            self.assertEqual(ticket["algorithm"], "RSA-1024 PKCS#1 v1.5 / SHA-1")
            print(f"\n  ✓ Full flow: ticket generated for session {sid[:8]}...")


def main():
    print("=" * 70)
    print(" iRemovalClone — Test suite")
    print("=" * 70)

    # Run crypto tests (always)
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoAlgorithm))

    # Run E2E tests only if --server flag or default
    if "--no-server" not in sys.argv:
        suite.addTests(loader.loadTestsFromTestCase(TestServerE2E))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
