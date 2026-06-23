#!/usr/bin/env python3
"""
afc_injection_detector.py
Windows host forensic scanner for AFC injection traces left by iRemoval PRO / BlackHound.

Usage:
    python afc_injection_detector.py --scan-all
    python afc_injection_detector.py --quick
    python afc_injection_detector.py --ioc-path "C:\\custom\\path"

Output: JSON report + console summary.
"""
import os
import sys
import json
import re
import hashlib
import argparse
from datetime import datetime, timezone
from pathlib import Path, PurePath
from collections import defaultdict
from typing import List, Dict, Any

# --- Configuration ---
TOOL_NAMES = ["iRemoval", "iRemovalPro", "BlackHound", "blackhound", "minaeraser", "A12Eraser"]
AFC_PROCESS_NAMES = ["ideviceproxy.exe", "afcclient.exe", "idevicesyslog.exe", "ideviceinfo.exe"]
AFC_COMMAND_PATTERNS = ["--stream", "afc://", "com.apple.mobile.afc", "/var/mobile"]
SUSPICIOUS_REGISTRY_KEYS = [
    r"SOFTWARE\iRemovalPro",
    r"SOFTWARE\BlackHound",
    r"SOFTWARE\iRemoval",
]
TARGET_DIRECTORIES = [
    Path(os.environ.get("LOCALAPPDATA", "")) / "iRemovalPro",
    Path(os.environ.get("LOCALAPPDATA", "")) / "BlackHound",
    Path(os.environ.get("PROGRAMDATA", "")) / "iRemovalPro",
    Path(os.environ.get("PROGRAMDATA", "")) / "BlackHound",
    Path(os.environ.get("TEMP", "")) / "iremoval",
    Path(os.environ.get("TEMP", "")) / "blackhound",
]
SUSPICIOUS_FILENAMES = [
    "activation_record.plist",
    "activation_record",
    "version33.txt",
    "iRemovalSignature",
    "BlackHound-Public-Build",
    "device_info.json",
    "pubkey.txt",
]

# IOC severity mapping
SEVERITY_P1 = "P1"  # Confirmed tool artifacts
SEVERITY_P2 = "P2"  # Suspicious AFC patterns
SEVERITY_P3 = "P3"  # Informational


class AFCInjectionDetector:
    def __init__(self, ioc_path: Path = None, verbose: bool = False):
        self.ioc_path = ioc_path
        self.verbose = verbose
        self.findings: List[Dict[str, Any]] = []
        self.stats = defaultdict(int)
        self.now = datetime.now(timezone.utc)

    def _log(self, msg: str):
        if self.verbose:
            print(f"[DETAIL] {msg}")

    def _add_finding(self, category: str, severity: str, description: str, path: str = None, extra: Dict = None):
        finding = {
            "ts": self.now.isoformat(),
            "category": category,
            "severity": severity,
            "description": description,
            "path": path,
            "extra": extra or {},
        }
        self.findings.append(finding)
        self.stats[severity] += 1
        self.stats[f"cat_{category}"] += 1
        self._log(f"[{severity}] {category}: {description} @ {path}")

    # ------------------------------------------------------------------
    # 1. Registry scan (Windows only)
    # ------------------------------------------------------------------
    def scan_registry(self):
        if sys.platform != "win32":
            self._add_finding("registry", SEVERITY_P3, "Registry scan skipped (non-Windows)")
            return

        try:
            import winreg
        except ImportError:
            self._add_finding("registry", SEVERITY_P3, "winreg module unavailable")
            return

        for root_name, root_key in [("HKLM", winreg.HKEY_LOCAL_MACHINE), ("HKCU", winreg.HKEY_CURRENT_USER)]:
            for key_pattern in SUSPICIOUS_REGISTRY_KEYS:
                full_key = f"{root_name}\\{key_pattern}"
                try:
                    with winreg.OpenKey(root_key, key_pattern) as key:
                        self._add_finding(
                            "registry",
                            SEVERITY_P1,
                            f"Suspicious registry key exists: {full_key}",
                            path=full_key,
                        )
                        # Enumerate values
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                if any(t.lower() in str(value).lower() for t in TOOL_NAMES):
                                    self._add_finding(
                                        "registry",
                                        SEVERITY_P1,
                                        f"Registry value contains tool name: {name}={value}",
                                        path=full_key,
                                        extra={"name": name, "value": str(value)},
                                    )
                                i += 1
                            except OSError:
                                break
                except FileNotFoundError:
                    self._log(f"Registry key not found: {full_key}")
                except Exception as e:
                    self._add_finding("registry", SEVERITY_P3, f"Registry error: {e}", path=full_key)

    # ------------------------------------------------------------------
    # 2. Filesystem artifact scan
    # ------------------------------------------------------------------
    def scan_filesystem(self, max_depth: int = 4):
        dirs_to_scan = [d for d in TARGET_DIRECTORIES if d.exists()]

        if not dirs_to_scan:
            self._add_finding("filesystem", SEVERITY_P3, "No known tool directories found on disk")

        for base_dir in dirs_to_scan:
            for root, _, files in os.walk(base_dir):
                depth = len(Path(root).parts) - len(base_dir.parts)
                if depth > max_depth:
                    break
                for fname in files:
                    fpath = Path(root) / fname
                    if any(s.lower() in fname.lower() for s in SUSPICIOUS_FILENAMES):
                        extra = {"size": fpath.stat().st_size}
                        if fname.lower().endswith(".plist"):
                            extra["note"] = "Plist may contain forged activation record"
                        self._add_finding(
                            "filesystem",
                            SEVERITY_P1,
                            f"Suspicious artifact file: {fname}",
                            path=str(fpath),
                            extra=extra,
                        )
                    # Also check for log files with AFC strings
                    if fname.lower().endswith((".log", ".txt")):
                        self._scan_text_file(fpath)

    def _scan_text_file(self, fpath: Path):
        try:
            text = fpath.read_text(errors="replace")
            for pat in AFC_COMMAND_PATTERNS:
                if pat in text:
                    self._add_finding(
                        "filesystem",
                        SEVERITY_P2,
                        f"Log file contains AFC command pattern: {pat}",
                        path=str(fpath),
                        extra={"pattern": pat, "lines": text.count("\n")},
                    )
                    break
        except Exception as e:
            self._log(f"Could not read {fpath}: {e}")

    # ------------------------------------------------------------------
    # 3. Process memory / running process check (Windows)
    # ------------------------------------------------------------------
    def scan_processes(self):
        if sys.platform != "win32":
            self._add_finding("process", SEVERITY_P3, "Process scan skipped (non-Windows)")
            return

        try:
            import subprocess
            result = subprocess.run(["tasklist", "/FO", "CSV"], capture_output=True, text=True, check=False)
            if result.returncode != 0:
                self._add_finding("process", SEVERITY_P3, f"tasklist failed: {result.stderr}")
                return
        except Exception as e:
            self._add_finding("process", SEVERITY_P3, f"Could not enumerate processes: {e}")
            return

        found = []
        for line in result.stdout.splitlines():
            for proc in AFC_PROCESS_NAMES:
                if proc.lower() in line.lower():
                    found.append((proc, line.strip()))
        if found:
            for proc, line in found:
                self._add_finding(
                    "process",
                    SEVERITY_P2,
                    f"AFC-related process running: {proc}",
                    extra={"tasklist_line": line},
                )
        else:
            self._add_finding("process", SEVERITY_P3, "No AFC-related processes currently running")

    # ------------------------------------------------------------------
    # 4. Event log quick scan (Sysmon / PowerShell)
    # ------------------------------------------------------------------
    def scan_event_logs(self):
        if sys.platform != "win32":
            self._add_finding("eventlog", SEVERITY_P3, "Event log scan skipped (non-Windows)")
            return

        try:
            import subprocess
            # Check for Sysmon Event ID 1 in the last 24h (heuristic)
            # We use wevtutil to filter quickly
            cmd = [
                "wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
                "/q:",
                "*[System[(EventID=1)]]",
                "/f:text", "/c:50"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=15)
            if result.returncode == 0 and result.stdout:
                for proc in AFC_PROCESS_NAMES:
                    if proc.lower() in result.stdout.lower():
                        self._add_finding(
                            "eventlog",
                            SEVERITY_P1,
                            f"Sysmon Event ID 1 contains AFC process: {proc}",
                            extra={"process": proc},
                        )
            else:
                self._add_finding("eventlog", SEVERITY_P3, "Sysmon log not available or empty")
        except FileNotFoundError:
            self._add_finding("eventlog", SEVERITY_P3, "wevtutil not found (Windows Event Tools not installed)")
        except subprocess.TimeoutExpired:
            self._add_finding("eventlog", SEVERITY_P3, "Event log query timed out")
        except Exception as e:
            self._add_finding("eventlog", SEVERITY_P3, f"Event log scan error: {e}")

    # ------------------------------------------------------------------
    # 5. Custom IOC path scan
    # ------------------------------------------------------------------
    def scan_custom_ioc(self):
        if not self.ioc_path or not self.ioc_path.exists():
            return
        for root, _, files in os.walk(self.ioc_path):
            for fname in files:
                if any(s.lower() in fname.lower() for s in SUSPICIOUS_FILENAMES):
                    self._add_finding(
                        "custom_ioc",
                        SEVERITY_P2,
                        f"Custom IOC path contains suspicious file: {fname}",
                        path=str(Path(root) / fname),
                    )

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def generate_report(self, out_path: Path = None) -> Dict[str, Any]:
        report = {
            "scanner": "afc_injection_detector.py",
            "version": "1.0",
            "ts": self.now.isoformat(),
            "platform": sys.platform,
            "hostname": os.environ.get("COMPUTERNAME", "unknown"),
            "summary": {
                "total_findings": len(self.findings),
                "severity_counts": dict(self.stats),
            },
            "findings": self.findings,
        }
        if out_path:
            out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"[+] Report written to {out_path}")
        return report

    def print_console_summary(self):
        print("\n" + "=" * 70)
        print("AFC INJECTION DETECTOR — SUMMARY")
        print("=" * 70)
        print(f"Total findings : {len(self.findings)}")
        print(f"P1 (Critical)  : {self.stats.get(SEVERITY_P1, 0)}")
        print(f"P2 (Suspicious): {self.stats.get(SEVERITY_P2, 0)}")
        print(f"P3 (Info)      : {self.stats.get(SEVERITY_P3, 0)}")
        print("-" * 70)
        for f in self.findings:
            if f["severity"] in (SEVERITY_P1, SEVERITY_P2):
                print(f"[{f['severity']}] [{f['category']}] {f['description']}")
                if f.get("path"):
                    print(f"         -> {f['path']}")
        print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="Windows AFC injection forensic scanner")
    parser.add_argument("--scan-all", action="store_true", help="Run all scans (registry, filesystem, processes, eventlogs)")
    parser.add_argument("--quick", action="store_true", help="Quick scan: filesystem + processes only")
    parser.add_argument("--ioc-path", type=Path, help="Custom IOC directory to scan")
    parser.add_argument("--output", type=Path, help="JSON report output path")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if not args.scan_all and not args.quick and not args.ioc_path:
        parser.print_help()
        sys.exit(1)

    det = AFCInjectionDetector(ioc_path=args.ioc_path, verbose=args.verbose)

    if args.scan_all or args.quick:
        det.scan_filesystem()
        det.scan_processes()
    if args.scan_all:
        det.scan_registry()
        det.scan_event_logs()
    if args.ioc_path:
        det.scan_custom_ioc()

    det.print_console_summary()
    if args.output:
        det.generate_report(args.output)
    else:
        det.generate_report(Path("afc_injection_report.json"))


if __name__ == "__main__":
    main()
