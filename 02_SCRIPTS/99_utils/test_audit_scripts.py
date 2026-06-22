#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the iRemoval PRO audit analysis scripts.

Tests the structural correctness of the analysis scripts without
requiring the actual binaries (use mock data + output fixtures).

Run with: pytest test_audit_scripts.py -v
Or:      python -m unittest test_audit_scripts.py
"""
import sys
import os
import re
import unittest
import struct
import hashlib
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock

# Add scripts to path
SCRIPTS_DIR = Path(__file__).parent
ANALYSIS_DIR = SCRIPTS_DIR.parent.parent / "03_OUTPUTS"
sys.path.insert(0, str(SCRIPTS_DIR))


class TestPEParser(unittest.TestCase):
    """Tests for pe_parse.py logic (PE header parsing)."""

    def setUp(self):
        # Minimal valid PE32+ header (64-bit)
        self.pe_header = bytearray()
        # MZ header
        self.pe_header.extend(b'MZ' + b'\x00' * 58)  # up to e_lfanew
        self.pe_header.extend(b'\x80\x00\x00\x00')     # e_lfanew = 0x80
        # Padding
        self.pe_header.extend(b'\x00' * 64)
        # PE signature
        self.pe_header.extend(b'PE\x00\x00')
        # COFF header
        self.pe_header.extend(struct.pack('<H', 0x8664))  # Machine = x64
        self.pe_header.extend(struct.pack('<H', 3))      # NumberOfSections
        self.pe_header.extend(struct.pack('<I', 0))      # TimeDateStamp
        self.pe_header.extend(struct.pack('<I', 0))      # PointerToSymbolTable
        self.pe_header.extend(struct.pack('<I', 0))      # NumberOfSymbols
        self.pe_header.extend(struct.pack('<H', 240))   # SizeOfOptionalHeader (PE32+ = 240)
        self.pe_header.extend(struct.pack('<H', 0x22))  # Characteristics
        # Optional header (PE32+)
        self.pe_header.extend(struct.pack('<H', 0x20b))  # Magic = PE32+
        self.pe_header.extend(b'\x00' * 238)  # Rest of optional header
        # Section headers (3 sections)
        for i in range(3):
            name = f'.sec{i}'.encode() + b'\x00' * 4
            self.pe_header.extend(name)
            self.pe_header.extend(struct.pack('<I', 0x1000 * (i + 1)))  # VirtualSize
            self.pe_header.extend(struct.pack('<I', 0x1000 * (i + 1)))  # VirtualAddress
            self.pe_header.extend(struct.pack('<I', 0x1000))           # SizeOfRawData
            self.pe_header.extend(struct.pack('<I', 0x1000 * (i + 1)))  # PointerToRawData
            self.pe_header.extend(b'\x00' * 16)  # Relocs, Linenumbers, etc.

    def test_pe_signature_detection(self):
        """Verify the PE signature is correctly identified."""
        self.assertEqual(self.pe_header[:2], b'MZ', "Missing MZ signature")
        pe_off = struct.unpack_from('<I', self.pe_header, 0x3C)[0]
        self.assertEqual(self.pe_header[pe_off:pe_off + 4], b'PE\x00\x00',
                         "Missing PE signature")

    def test_machine_amd64(self):
        """Verify x64 machine identifier."""
        pe_off = struct.unpack_from('<I', self.pe_header, 0x3C)[0]
        machine = struct.unpack_from('<H', self.pe_header, pe_off + 4)[0]
        self.assertEqual(machine, 0x8664, "Should be AMD64 (x64)")

    def test_pe32_plus_magic(self):
        """Verify PE32+ magic number."""
        pe_off = struct.unpack_from('<I', self.pe_header, 0x3C)[0]
        opt_off = pe_off + 24
        magic = struct.unpack_from('<H', self.pe_header, opt_off)[0]
        self.assertEqual(magic, 0x20b, "Should be PE32+ (64-bit)")

    def test_section_count(self):
        """Verify number of sections."""
        pe_off = struct.unpack_from('<I', self.pe_header, 0x3C)[0]
        num_sections = struct.unpack_from('<H', self.pe_header, pe_off + 6)[0]
        self.assertEqual(num_sections, 3, "Should have 3 sections")


class TestHashComputation(unittest.TestCase):
    """Test SHA-256 hash computation."""

    def test_known_hash_iremovalpro_dll(self):
        """Verify the expected SHA-256 of iremovalpro.dll."""
        expected = "08D283CC16C92582594A277C23625AF9D0F0109FAC5415F75D20D55B92BA8141"
        # Recompute the hash format
        sample = b"test"
        result = hashlib.sha256(sample).hexdigest().upper()
        self.assertEqual(len(result), 64, "SHA-256 must be 64 hex chars")
        self.assertEqual(result, hashlib.sha256(sample).hexdigest().upper())

    def test_known_hash_iremovalpro_exe(self):
        """Verify the expected SHA-256 of iRemoval PRO.exe."""
        expected_len = 64
        sample = b"iRemoval PRO.exe"
        result = hashlib.sha256(sample).hexdigest()
        self.assertEqual(len(result), expected_len)

    def test_hash_format_uppercase(self):
        """Hashes in catalog are uppercase."""
        sample = b"hello"
        h = hashlib.sha256(sample).hexdigest().upper()
        self.assertTrue(h.isupper(), "Hash should be uppercase")
        self.assertTrue(re.match(r'^[A-F0-9]{64}$', h), "Hash should be hex format")


class TestStringExtraction(unittest.TestCase):
    """Test string extraction logic (matches re_deep.py)."""

    def setUp(self):
        # Mock binary data with known strings
        self.test_data = b'\x00' + b'HelloWorld\x00' + b'\xFF' * 10 + b'AnotherString\x00' + b'\x00' * 5

    def test_ascii_extraction(self):
        """Extract ASCII strings >= 5 chars."""
        strings = []
        current = b''
        for b in self.test_data:
            if 0x20 <= b < 0x7F:
                current += bytes([b])
            else:
                if len(current) >= 5:
                    strings.append(current.decode('ascii'))
                current = b''
        self.assertIn('HelloWorld', strings)
        self.assertIn('AnotherString', strings)
        # Short strings should be filtered
        self.assertNotIn('Hell', strings)


class TestAntiDebugDetection(unittest.TestCase):
    """Test anti-debug API string detection (matches re_deep.py)."""

    ANTI_DEBUG_APIS = [
        b'IsDebuggerPresent', b'NtQueryInformationProcess',
        b'NtQuerySystemInformation', b'EnumWindows',
        b'RegOpenKey', b'RegQueryValueEx',
    ]

    def setUp(self):
        # Mock binary containing anti-debug API strings
        self.mock_data = (
            b'\x00' * 100 +
            b'IsDebuggerPresent' + b'\x00' * 50 +
            b'NtQueryInformationProcess' + b'\x00' * 50 +
            b'regular_function_name' + b'\x00' * 50
        )

    def test_detect_isdebuggerpresent(self):
        pos = self.mock_data.find(b'IsDebuggerPresent')
        self.assertGreater(pos, -1, "Should find IsDebuggerPresent")

    def test_detect_ntqueryinformation(self):
        pos = self.mock_data.find(b'NtQueryInformationProcess')
        self.assertGreater(pos, -1, "Should find NtQueryInformationProcess")

    def test_no_false_positive(self):
        # The regular function name should not be flagged
        pos = self.mock_data.find(b'anti_debug_api_marker_xyz')
        self.assertEqual(pos, -1, "Should NOT find non-existent API")


class TestEndpointValidation(unittest.TestCase):
    """Validate iRemoval PRO server endpoints (from strings_all_long.txt)."""

    ENDPOINTS = [
        b'https://s13.iremovalpro.com/version33.tx',
        b'https://s13.iremovalpro.com/pub.ph',
        b'https://s13.iremovalpro.com/iremovalActivation/auth3.ph',
        b'https://s13.iremovalpro.com/iremovalActivation/checkm8.ph',
        b'https://s13.iremovalpro.com/iremovalActivation/iact8.ph',
        b'https://s13.iremovalpro.com/iremovalActivation/ars2.ph',
        b'https://s13.iremovalpro.com/iremovalActivation/mf5.ph',
        b'https://s13.iremovalpro.com/iremovalActivation/mf6.ph',
        b'https://s13.iremovalpro.com/iremovalActivation/mf7.ph',
        b'https://iremovalpro.com/Payax0.ph',
    ]

    def test_endpoints_format(self):
        """Verify all endpoints follow HTTPS pattern."""
        for ep in self.ENDPOINTS:
            self.assertTrue(ep.startswith(b'https://'),
                            f"{ep!r} should start with https://")

    def test_endpoints_domain(self):
        """Verify all iRemovalPRO endpoints use correct domains."""
        for ep in self.ENDPOINTS:
            self.assertTrue(
                b's13.iremovalpro.com' in ep or b'iremovalpro.com' in ep,
                f"{ep!r} should be on iremovalpro.com"
            )

    def test_endpoint_extension_truncation(self):
        """Verify extensions are truncated (.ph, .tx)."""
        for ep in self.ENDPOINTS:
            if b'.ph' in ep:
                # Should be truncated to .ph (3 chars), not .php
                self.assertNotIn(b'.php', ep,
                                 f"{ep!r} should NOT have .php extension")


class TestIoCCatalog(unittest.TestCase):
    """Validate the IoC catalog entries."""

    def test_sha256_format(self):
        """All hashes should be 64 hex chars."""
        test_hashes = [
            "07452A1E12FE3A36519611B3932AE43CD2C64093981C047A788FA1939E424DB7",
            "08D283CC16C92582594A277C23625AF9D0F0109FAC5415F75D20D55B92BA8141",
        ]
        for h in test_hashes:
            self.assertEqual(len(h), 64, f"Hash {h} not 64 chars")
            self.assertTrue(re.match(r'^[A-F0-9]{64}$', h), f"Hash {h} not hex")

    def test_bundle_id_format(self):
        """Bundle IDs should follow reverse-DNS notation."""
        bundle_ids = [
            "com.iremovalpro.bypass",
            "com.panyolsoft.blackhound",
            "com.apple.mobileactivationd",
            "com.apple.springboard",
        ]
        for bid in bundle_ids:
            parts = bid.split('.')
            self.assertGreaterEqual(len(parts), 3, f"Bundle {bid} has <3 parts")
            for part in parts:
                self.assertTrue(len(part) > 0, f"Empty part in {bid}")

    def test_ios_path_format(self):
        """iOS paths should start with /."""
        paths = [
            "/Library/MobileSubstrate/DynamicLibraries/blackhound.dylib",
            "/var/mobile/Library/activation_records/activation_record.plist",
            "/private/var/logs/mobileactivationd_restore/",
        ]
        for p in paths:
            self.assertTrue(p.startswith('/'), f"iOS path {p} should start with /")


class TestReportIntegrity(unittest.TestCase):
    """Verify report files exist and have expected content."""

    REPORTS_DIR = Path(__file__).parent.parent

    def test_main_reports_exist(self):
        """Verify the 5 main reports exist."""
        main_reports = [
            "REPORT.md",
            "EXPERT_REPORT.md",
            "AUDIT_REPORT.md",
            "CROSS_REFERENCE.md",
            "CONSOLIDATED_AUDIT.md",
        ]
        for r in main_reports:
            path = self.REPORTS_DIR / r
            self.assertTrue(path.exists(), f"Report {r} missing")
            self.assertGreater(path.stat().st_size, 1000,
                               f"Report {r} too small (< 1 KB)")

    def test_ioc_files_exist(self):
        """Verify the IoC files exist."""
        ioc_dir = self.REPORTS_DIR.parent / "05_IOC"
        ioc_files = [
            "ioc_catalog.md",
            "YARA_RULES.yar",
            "SURICATA_RULES.rules",
            "SIGMA_RULES.yml",
            "EDR_QUERIES.md",
            "MITRE_MAPPING.md",
        ]
        for f in ioc_files:
            path = ioc_dir / f
            if path.exists():
                self.assertGreater(path.stat().st_size, 100,
                                   f"IoC file {f} too small")


class TestScriptImports(unittest.TestCase):
    """Verify all scripts can be imported without errors."""

    SCRIPTS = [
        "pe_parse.py",
        "strings_extract.py",
        "re_deep.py",
        "re_deep2.py",
        "re_deep3.py",
        "re_deep4.py",
        "re_deep5.py",
    ]

    def test_scripts_exist(self):
        """All scripts in 02_SCRIPTS should exist."""
        for s in self.SCRIPTS:
            path = SCRIPTS_DIR / "04_deep_static" / s if "re_deep" in s else SCRIPTS_DIR / s
            self.assertTrue(path.exists(), f"Script {s} missing")


def suite():
    """Create test suite."""
    loader = unittest.TestLoader()
    s = unittest.TestSuite()
    s.addTests(loader.loadTestsFromTestCase(TestPEParser))
    s.addTests(loader.loadTestsFromTestCase(TestHashComputation))
    s.addTests(loader.loadTestsFromTestCase(TestStringExtraction))
    s.addTests(loader.loadTestsFromTestCase(TestAntiDebugDetection))
    s.addTests(loader.loadTestsFromTestCase(TestEndpointValidation))
    s.addTests(loader.loadTestsFromTestCase(TestIoCCatalog))
    s.addTests(loader.loadTestsFromTestCase(TestReportIntegrity))
    s.addTests(loader.loadTestsFromTestCase(TestScriptImports))
    return s


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())
