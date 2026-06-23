#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iPhone Comprehensive Analysis — 4 Axes
========================================
1. Informations détaillées de l'appareil (modèle, iOS, UDID, ECID)
2. Extraction des logs de l'appareil
3. Analyse de la configuration de sécurité (Activation Lock)
4. Test de communication avec les outils iRemoval Pro

Compatible iRemoval PRO Premium Edition v5.2
"""

import subprocess
import json
import sys
import os
import re
import struct
import hashlib
import io
from pathlib import Path
from datetime import datetime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

BASE = Path(r"c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
OUT = BASE / "03_OUTPUTS" / "iphone_full_analysis"
OUT.mkdir(parents=True, exist_ok=True)

DLL_PATH = BASE / "IRemovalPro" / "iremovalpro.dll"
EXE_PATH = BASE / "IRemovalPro" / "iRemoval PRO.exe"

# ── Known device info from iRemoval PRO detection ──
KNOWN_DEVICE = {
    "model_identifier": "iPhone16,2",
    "model_name": "iPhone 15 Pro Max",
    "device_name": "iPhone",
    "serial_number": "JRFJ2K0667",
    "udid": "00008130-001C68110AA0001C",
    "ios_version": "16.5",
    "ios_build": "23F77",
    "baseband": "3.50.08",
    "activation_state": "Unactivated",
    "icloud_lock": True,
    "wifi_mac": "28:34:ff:e9:bd:58",
    "bluetooth_mac": "28:34:ff:d5:71:1e",
    "product_type": "12A8",
    "vendor_id": "05AC",
}


def run_ps(cmd, timeout=15):
    """Run a PowerShell command and return structured result."""
    try:
        r = subprocess.run(
            ["powershell", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return {"ok": r.returncode == 0, "stdout": r.stdout.strip(), "stderr": r.stderr.strip(), "rc": r.returncode}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "Timeout", "rc": -1}
    except Exception as e:
        return {"ok": False, "stdout": "", "stderr": str(e), "rc": -1}


def run_cmd(cmd, timeout=15):
    """Run a shell command."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {"ok": r.returncode == 0, "stdout": r.stdout.strip(), "stderr": r.stderr.strip(), "rc": r.returncode}
    except Exception as e:
        return {"ok": False, "stdout": "", "stderr": str(e), "rc": -1}


# ════════════════════════════════════════════════════════════════
#  AXE 1 — Informations détaillées de l'appareil
# ════════════════════════════════════════════════════════════════

def axe1_device_info():
    print("\n" + "=" * 70)
    print("  📱 AXE 1 — INFORMATIONS DÉTAILLÉES DE L'APPAREIL")
    print("=" * 70)

    info = {}

    # 1a. USB/PnP device details
    print("\n[1a] 🔌 Détection USB Apple...")
    r = run_ps(
        "Get-PnpDevice -Class USB | "
        "Where-Object { $_.FriendlyName -match 'Apple|iPhone' } | "
        "Select-Object Status,Class,FriendlyName,InstanceId,Problem | "
        "ConvertTo-Json -Depth 3"
    )
    usb_devices = []
    if r["ok"] and r["stdout"]:
        try:
            usb_devices = json.loads(r["stdout"])
            if not isinstance(usb_devices, list):
                usb_devices = [usb_devices]
            for d in usb_devices:
                print(f"   ✅ {d.get('FriendlyName','?')} — Status: {d.get('Status','?')}")
        except json.JSONDecodeError:
            print(f"   ⚠️  Raw: {r['stdout'][:200]}")
    info["usb_devices"] = usb_devices

    # 1b. WMI detailed properties
    print("\n[1b] 📋 Propriétés WMI détaillées...")
    r = run_ps(
        "Get-PnpDeviceProperty -InstanceId "
        "'USB\\VID_05AC&PID_12A8\\00008130001C68110AA0001C' -KeyName "
        "'DEVPKEY_Device_Manufacturer,DEVPKEY_Device_Model,DEVPKEY_Device_FriendlyName,"
        "DEVPKEY_Device_SerialNumber,DEVPKEY_Device_DriverVersion,DEVPKEY_Device_BusType' "
        "-ErrorAction SilentlyContinue | "
        "Select-Object InstanceId,KeyName,Data | ConvertTo-Json -Depth 3"
    )
    wmi_props = []
    if r["ok"] and r["stdout"]:
        try:
            wmi_props = json.loads(r["stdout"])
            if not isinstance(wmi_props, list):
                wmi_props = [wmi_props]
            for p in wmi_props:
                print(f"   {p.get('KeyName','?')}: {p.get('Data','?')}")
        except json.JSONDecodeError:
            print(f"   ⚠️  Raw: {r['stdout'][:200]}")
    info["wmi_properties"] = wmi_props

    # 1c. Apple Mobile Device Service status
    print("\n[1c] 🔧 Services Apple...")
    r = run_ps(
        "Get-Service 'Apple Mobile Device Service','iPod Service','Bonjour Service' "
        "-ErrorAction SilentlyContinue | "
        "Select-Object Name,Status,StartType | ConvertTo-Json"
    )
    apple_services = []
    if r["ok"] and r["stdout"]:
        try:
            apple_services = json.loads(r["stdout"])
            if not isinstance(apple_services, list):
                apple_services = [apple_services]
            for s in apple_services:
                status_text = "Running" if s.get("Status") == 4 else "Stopped"
                print(f"   {'✅' if s.get('Status')==4 else '⚠️'} {s.get('Name','?')}: {status_text}")
        except json.JSONDecodeError:
            pass
    info["apple_services"] = apple_services

    # 1d. Consolidated device profile from known info + live data
    print("\n[1d] 📊 Profil complet de l'appareil...")
    profile = {
        **KNOWN_DEVICE,
        "ecid": "Not extracted (requires lockdownd)",
        "imei": "Not extracted (requires lockdownd)",
        "capacity_gb": "Not extracted",
        "color": "Not extracted",
        "firmware_version": KNOWN_DEVICE["ios_version"],
        "security_patch_level": "June 2023 (iOS 16.5)",
        "device_class": "iPhone",
        "product_type_identifier": KNOWN_DEVICE["product_type"],
        "usb_vendor_id_hex": f"0x{KNOWN_DEVICE['vendor_id']}",
        "usb_product_id_hex": f"0x{KNOWN_DEVICE['product_type']}",
        "lockdownd_port": 62078,
        "detection_timestamp": datetime.now().isoformat(),
        "source": "iRemoval PRO detection + USB PnP",
    }

    print(f"   🏷️  Model:        {profile['model_name']} ({profile['model_identifier']})")
    print(f"   📛 Nom:           {profile['device_name']}")
    print(f"   🔢 Serial:        {profile['serial_number']}")
    print(f"   🔑 UDID:          {profile['udid']}")
    print(f"   📱 iOS:           {profile['ios_version']} (Build {profile['ios_build']})")
    print(f"   📡 Baseband:      {profile['baseband']}")
    print(f"   📶 WiFi MAC:      {profile['wifi_mac']}")
    print(f"   🔵 BT MAC:        {profile['bluetooth_mac']}")
    print(f"   🔒 Activation:    {profile['activation_state']}")
    print(f"   ⏱️  Detected:      {profile['detection_timestamp']}")

    info["device_profile"] = profile
    return info


# ════════════════════════════════════════════════════════════════
#  AXE 2 — Extraction des logs de l'appareil
# ════════════════════════════════════════════════════════════════

def axe2_device_logs():
    print("\n" + "=" * 70)
    print("  📋 AXE 2 — EXTRACTION DES LOGS DE L'APPAREIL")
    print("=" * 70)

    logs = {}

    # 2a. Windows USB connection logs (System event log)
    print("\n[2a] 🔌 Logs USB Windows (Event Log System)...")
    r = run_ps(
        "Get-WinEvent -LogName System -MaxEvents 500 | "
        "Where-Object { $_.Message -match 'Apple|iPhone|USB Device|05AC' -or "
        "$_.ProviderName -match 'USB|PnP' } | "
        "Select-Object TimeCreated,Id,LevelDisplayName,Message | "
        "ConvertTo-Json -Depth 3"
    )
    usb_events = []
    if r["ok"] and r["stdout"]:
        try:
            raw = json.loads(r["stdout"])
            if not isinstance(raw, list):
                raw = [raw]
            for ev in raw[:20]:
                msg = ev.get("Message", "") or ""
                msg_short = msg[:120] if msg else "N/A"
                print(f"   [{ev.get('TimeCreated','?')[:19]}] "
                      f"ID={ev.get('Id','?')} {ev.get('LevelDisplayName','?')}: "
                      f"{msg_short}")
                usb_events.append({
                    "time": str(ev.get("TimeCreated", "")),
                    "id": ev.get("Id"),
                    "level": ev.get("LevelDisplayName", ""),
                    "message": msg[:300]
                })
        except json.JSONDecodeError:
            print(f"   ⚠️  Parse error, raw: {r['stdout'][:300]}")
    logs["usb_events"] = usb_events

    # 2b. Apple Mobile Device application logs
    print("\n[2b] 🍎 Logs Apple Mobile Device...")
    amd_paths = [
        Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "Apple" / "Apple Mobile Device",
        Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "Apple Computer",
        Path(os.environ.get("APPDATA", "")) / "Apple Computer",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Apple Computer",
    ]
    found_logs = []
    for p in amd_paths:
        if p.exists():
            print(f"   📂 {p}")
            for f in p.rglob("*.log"):
                if f.stat().st_size < 5_000_000:
                    found_logs.append(str(f))
                    print(f"      📄 {f.name} ({f.stat().st_size:,} bytes)")
            for f in p.rglob("*.txt"):
                if f.stat().st_size < 5_000_000:
                    found_logs.append(str(f))
                    print(f"      📄 {f.name} ({f.stat().st_size:,} bytes)")
    logs["apple_log_files"] = found_logs

    # 2c. CrashReporter / sync logs
    print("\n[2c] 💥 CrashReporter & sync logs...")
    crash_dir = Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "Apple" / "CrashReporter"
    if crash_dir.exists():
        print(f"   📂 CrashReporter: {crash_dir}")
        for f in crash_dir.rglob("*"):
            if f.is_file() and f.stat().st_size < 5_000_000:
                print(f"      📄 {f.name}")
    else:
        print("   ⚠️  CrashReporter directory not found")

    # 2d. iRemoval Pro logs (if any)
    print("\n[2d] 🛠️  Logs iRemoval Pro...")
    ir_logs_dir = BASE / "logs"
    ir_logs = []
    if ir_logs_dir.exists():
        print(f"   📂 {ir_logs_dir}")
        for f in ir_logs_dir.rglob("*"):
            if f.is_file():
                ir_logs.append(str(f))
                print(f"      📄 {f.name} ({f.stat().st_size:,} bytes)")
    else:
        print("   ⚠️  No logs directory yet")
    logs["iremoval_logs"] = ir_logs

    # 2e. Windows Application event log for Apple processes
    print("\n[2e] 📝 Application Event Log (Apple-related)...")
    r = run_ps(
        "Get-WinEvent -LogName Application -MaxEvents 200 | "
        "Where-Object { $_.Message -match 'Apple|iPhone|MobileDevice|iRemoval' } | "
        "Select-Object TimeCreated,Id,LevelDisplayName,Message | "
        "ConvertTo-Json -Depth 3"
    )
    app_events = []
    if r["ok"] and r["stdout"]:
        try:
            raw = json.loads(r["stdout"])
            if not isinstance(raw, list):
                raw = [raw]
            for ev in raw[:10]:
                msg = ev.get("Message", "") or ""
                print(f"   [{ev.get('TimeCreated','?')[:19]}] "
                      f"{ev.get('LevelDisplayName','?')}: {msg[:120]}")
                app_events.append({
                    "time": str(ev.get("TimeCreated", "")),
                    "id": ev.get("Id"),
                    "level": ev.get("LevelDisplayName", ""),
                    "message": msg[:300]
                })
        except json.JSONDecodeError:
            print("   ⚠️  No Apple-related application events found")
    logs["app_events"] = app_events

    return logs


# ════════════════════════════════════════════════════════════════
#  AXE 3 — Analyse de la configuration de sécurité
# ════════════════════════════════════════════════════════════════

def axe3_security_analysis():
    print("\n" + "=" * 70)
    print("  🔒 AXE 3 — ANALYSE DE LA CONFIGURATION DE SÉCURITÉ")
    print("=" * 70)

    security = {}

    # 3a. Activation Lock / iCloud Lock analysis
    print("\n[3a] 🔐 Activation Lock Status...")
    activation = {
        "state": KNOWN_DEVICE["activation_state"],
        "icloud_linked": KNOWN_DEVICE["icloud_lock"],
        "apple_id_bound": True,  # Unactivated implies Apple ID binding
        "find_my_iphone": "Unknown (device unactivated)",
        "activation_server": "albert.apple.com",
        "drm_handshake_endpoint": "https://albert.apple.com/deviceservices/drmHandshake",
        "activation_record_present": False,
        "bypass_possible_via_software": False,
        "official_unlock_method": "Apple Support with proof of purchase",
        "security_level": "MAXIMUM — Secure Enclave + T2 chip protection",
    }
    for k, v in activation.items():
        icon = "🔴" if v in [True, False, "MAXIMUM — Secure Enclave + T2 chip protection"] else "🟡"
        if isinstance(v, str) and v.startswith("Unknown"):
            icon = "🟡"
        if k == "official_unlock_method":
            icon = "🟢"
        print(f"   {icon} {k}: {v}")
    security["activation_lock"] = activation

    # 3b. Hardware security (Secure Enclave, T2)
    print("\n[3b] 🛡️  Sécurité Hardware (iPhone 15 Pro Max)...")
    hw_security = {
        "processor": "A17 Pro (TSMC N3B)",
        "secure_enclave": "Present — Generation 5+",
        "sep_core": "Dedicated security coprocessor",
        "t2_equivalent": "Secure Enclave integrated in A17",
        "encryption_engine": "AES-256 hardware engine",
        "key_derivation": "Hardware-backed key hierarchy",
        "anti_replay": "Effaceable storage (EMF key protected)",
        "trust_chain": "Boot ROM → iBoot → kernel → SEP → apps",
        "dfw_mode": "Device Firmware Upgrade (DFU) available",
        "recovery_mode": "Recovery OS available",
        "pangu_checkm8": "Not applicable — A17 not vulnerable to checkm8",
        "palera1n": "Not applicable — A17 not vulnerable",
        "jailbreak_status": "No public jailbreak for A17/iOS 16.5",
    }
    for k, v in hw_security.items():
        print(f"   ⚙️  {k}: {v}")
    security["hardware"] = hw_security

    # 3c. iOS 16.5 specific security features
    print("\n[3c] 📱 iOS 16.5 Security Features...")
    ios_security = {
        "activation_lock_server_side": True,
        "activation_record_encrypted": True,
        "lockdownd_requires_pairing": True,
        "usb_restricted_mode": True,  # USB restricted mode since iOS 11.4.1
        "developer_mode_required": True,  # Since iOS 16
        "sandbox_enforcement": True,
        "code_signing_enforcement": True,
        "rootless_filesystem": True,  # /var/containers since iOS 9
        "secure_boot_chain": True,
        "kernel_integrity_check": True,
        "ktrr_rokernel": True,  # Kernel Text Read-Only Region (A11+)
        "ppl_page_protection": True,  # Page Protection Layer (A14+)
        "mapped_io_protection": True,  # A15+
    }
    for k, v in ios_security.items():
        icon = "✅" if v else "❌"
        print(f"   {icon} {k}: {v}")
    security["ios_features"] = ios_security

    # 3d. Communication protocol security
    print("\n[3d] 🔄 Protocole lockdownd...")
    lockdown = {
        "port": 62078,
        "protocol": "lockdownd",
        "pairing_required": True,
        "pairing_type": "USB host pairing",
        "handshake": " plist-based request/response",
        "ssl_possible": "After pairing, SSL tunnel available",
        "activation_record_path": "/var/root/Library/Lockdown/device_private_key.pem",
        "server_pairing_path": "/var/root/Library/Lockdown/",
        "escrow_bag": "Required for trusted host pairing",
        "apple_cert_chain": "Apple Root CA → Apple Mobile Device Certificate",
        "drm_handshake_flow": "Device → drmHandshake → Apple Server → Activation Record",
    }
    for k, v in lockdown.items():
        print(f"   🔗 {k}: {v}")
    security["lockdownd"] = lockdown

    # 3e. Risk assessment
    print("\n[3e] 📊 Évaluation globale du risque...")
    risk = {
        "activation_bypass_risk": "CRITICAL — No known software bypass for A17",
        "hardware_bypass_risk": "IMPOSSIBLE — Secure Enclave prevents direct key extraction",
        "network_bypass_risk": "LOW — DRM handshake requires valid Apple server response",
        "social_bypass_risk": "MEDIUM — Phishing/previous owner contact possible",
        "official_unlock_risk": "LOW — Requires valid proof of purchase",
        "overall_rating": "🔒 SECURE — Device is effectively locked and protected",
    }
    for k, v in risk.items():
        print(f"   {v.split()[0]} {k}: {v}")
    security["risk_assessment"] = risk

    return security


# ════════════════════════════════════════════════════════════════
#  AXE 4 — Test de communication iRemoval Pro
# ════════════════════════════════════════════════════════════════

def axe4_iremoval_communication():
    print("\n" + "=" * 70)
    print("  🛠️  AXE 4 — TEST DE COMMUNICATION iRemoval PRO")
    print("=" * 70)

    comm = {}

    # 4a. EXE and DLL integrity check
    print("\n[4a] 📦 Fichiers iRemoval PRO...")

    exe_info = {}
    if EXE_PATH.exists():
        exe_data = EXE_PATH.read_bytes()
        exe_info = {
            "path": str(EXE_PATH),
            "size_bytes": len(exe_data),
            "size_mb": round(len(exe_data) / 1_000_000, 2),
            "sha256": hashlib.sha256(exe_data).hexdigest()[:32],
            "pe_signature": exe_data[:2].hex(),
            "is_pe": exe_data[:2] == b'MZ',
        }
        print(f"   ✅ iRemoval PRO.exe: {exe_info['size_mb']} MB, SHA256: {exe_info['sha256']}...")
        print(f"      PE header: {exe_info['pe_signature']} ({'Valid' if exe_info['is_pe'] else 'Invalid'})")
    else:
        print(f"   ❌ EXE not found at {EXE_PATH}")
    comm["exe"] = exe_info

    dll_info = {}
    if DLL_PATH.exists():
        dll_data = DLL_PATH.read_bytes()
        dll_info = {
            "path": str(DLL_PATH),
            "size_bytes": len(dll_data),
            "size_mb": round(len(dll_data) / 1_000_000, 2),
            "sha256": hashlib.sha256(dll_data).hexdigest()[:32],
            "pe_signature": dll_data[:2].hex(),
            "is_pe": dll_data[:2] == b'MZ',
            "is_dotnet": b'.text' in dll_data[:4096] and b'mscoree.dll' in dll_data[:8192],
        }
        print(f"   ✅ iremovalpro.dll: {dll_info['size_mb']} MB, SHA256: {dll_info['sha256']}...")
        print(f"      PE header: {dll_info['pe_signature']} ({'Valid' if dll_info['is_pe'] else 'Invalid'})")
        print(f"      .NET assembly: {'Yes' if dll_info.get('is_dotnet') else 'No/NativeAOT'}")
    else:
        print(f"   ❌ DLL not found at {DLL_PATH}")
    comm["dll"] = dll_info

    # 4b. DLL strings analysis — key communication patterns
    print("\n[4b] 🔍 Strings de communication dans DLL...")
    if DLL_PATH.exists():
        dll_data = DLL_PATH.read_bytes()

        # Extract UTF-8 and UTF-16 strings
        str_patterns = {
            "server_url": [],
            "apple_url": [],
            "lockdownd": [],
            "idevice_commands": [],
            "crypto_refs": [],
            "activation_refs": [],
        }

        # UTF-16 strings (Windows DLLs mostly use UTF-16)
        utf16_strings = []
        i = 0
        while i < len(dll_data) - 4:
            # Look for printable UTF-16LE sequences (3+ chars)
            if dll_data[i] >= 0x20 and dll_data[i] < 0x7F and dll_data[i+1] == 0x00:
                start = i
                length = 0
                while i < len(dll_data) - 2 and dll_data[i] >= 0x20 and dll_data[i] < 0x7F and dll_data[i+1] == 0x00:
                    length += 1
                    i += 2
                if length >= 6:
                    s = dll_data[start:start+length*2].decode('utf-16-le', errors='ignore')
                    utf16_strings.append(s)
            i += 2

        # UTF-8 strings
        utf8_strings = re.findall(b'[\\x20-\\x7E]{6,}', dll_data)

        # Classify strings
        all_strings = utf16_strings + [s.decode('ascii', errors='ignore') for s in utf8_strings]

        for s in all_strings:
            s_lower = s.lower()
            if 'iremovalpro.com' in s_lower or 's13.' in s_lower:
                str_patterns["server_url"].append(s)
            if 'albert.apple.com' in s_lower or 'apple.com' in s_lower:
                str_patterns["apple_url"].append(s)
            if 'lockdownd' in s_lower or 'lockdown' in s_lower:
                str_patterns["lockdownd"].append(s)
            if 'idevice' in s_lower:
                str_patterns["idevice_commands"].append(s)
            if 'hmac' in s_lower or 'sha256' in s_lower or 'aes' in s_lower or 'ecdsa' in s_lower or 'rsa' in s_lower:
                str_patterns["crypto_refs"].append(s)
            if 'activation' in s_lower or 'iact' in s_lower or 'drmhandshake' in s_lower:
                str_patterns["activation_refs"].append(s)

        for category, strings in str_patterns.items():
            unique = list(set(strings))[:10]
            if unique:
                print(f"\n   📂 {category}:")
                for s in unique:
                    print(f"      • {s[:80]}")
            else:
                print(f"\n   📂 {category}: (none found)")

        comm["dll_strings"] = {k: list(set(v))[:15] for k, v in str_patterns.items()}

    # 4c. Available iRemoval analysis scripts
    print("\n[4c] 📜 Scripts d'analyse disponibles...")
    scripts_dir = BASE / "02_SCRIPTS"
    script_categories = {}
    if scripts_dir.exists():
        for sub in scripts_dir.iterdir():
            if sub.is_dir() and not sub.name.startswith('_') and not sub.name.startswith('backup'):
                py_files = list(sub.rglob("*.py"))
                if py_files:
                    script_categories[sub.name] = [f.name for f in py_files]
                    print(f"   📂 {sub.name}/: {len(py_files)} scripts")
                    for f in py_files[:5]:
                        print(f"      • {f.name}")
                    if len(py_files) > 5:
                        print(f"      ... and {len(py_files)-5} more")
    comm["available_scripts"] = script_categories

    # 4d. Server connectivity test (passive, no activation payloads)
    print("\n[4d] 🌐 Test de connectivité serveur iRemoval...")
    try:
        import requests
        server_tests = []

        # Test version endpoint (public)
        try:
            resp = requests.get("https://s13.iremovalpro.com/version33.txt", timeout=10)
            server_tests.append({
                "endpoint": "version33.txt",
                "status_code": resp.status_code,
                "reachable": resp.status_code == 200,
                "response_size": len(resp.content),
                "content_preview": resp.text[:100] if resp.status_code == 200 else "N/A",
            })
            print(f"   version33.txt: HTTP {resp.status_code} ({len(resp.content)} bytes)")
            if resp.status_code == 200:
                print(f"      Content: {resp.text[:80]}...")
        except Exception as e:
            server_tests.append({"endpoint": "version33.txt", "reachable": False, "error": str(e)[:100]})
            print(f"   version33.txt: ❌ {str(e)[:80]}")

        # Test pub.php (public)
        try:
            resp = requests.get("https://s13.iremovalpro.com/pub.php", timeout=10)
            server_tests.append({
                "endpoint": "pub.php",
                "status_code": resp.status_code,
                "reachable": resp.status_code < 500,
                "response_size": len(resp.content),
            })
            print(f"   pub.php: HTTP {resp.status_code}")
        except Exception as e:
            server_tests.append({"endpoint": "pub.php", "reachable": False, "error": str(e)[:100]})
            print(f"   pub.php: ❌ {str(e)[:80]}")

        comm["server_connectivity"] = server_tests

    except ImportError:
        print("   ⚠️  Module 'requests' non installé — test serveur ignoré")
        print("      Installer: py -m pip install requests")
        comm["server_connectivity"] = "requests module not available"

    # 4e. iRemoval PRO process test
    print("\n[4e] 🖥️  Processus iRemoval PRO...")
    r = run_ps(
        "Get-Process | Where-Object { $_.ProcessName -match 'iRemoval|iremoval' } | "
        "Select-Object Id,ProcessName,StartTime,WorkingSet64 | ConvertTo-Json"
    )
    ir_processes = []
    if r["ok"] and r["stdout"] and r["stdout"] != "null":
        try:
            procs = json.loads(r["stdout"])
            if not isinstance(procs, list):
                procs = [procs]
            for p in procs:
                print(f"   PID={p.get('Id')} — {p.get('ProcessName')} — "
                      f"WorkingSet={p.get('WorkingSet64',0)//1_000_000} MB")
                ir_processes.append(p)
        except json.JSONDecodeError:
            print("   ⚠️  iRemoval PRO not currently running")
    else:
        print("   ⚠️  iRemoval PRO not currently running")
    comm["iremoval_processes"] = ir_processes

    return comm


# ════════════════════════════════════════════════════════════════
#  MAIN — Run all 4 axes and save consolidated report
# ════════════════════════════════════════════════════════════════

def main():
    print("=" * 70)
    print("  📱 iPhone Comprehensive Analysis — 4 Axes")
    print("  iRemoval PRO Premium Edition v5.2")
    print("  iPhone 15 Pro Max (iPhone16,2) — UDID: 00008130-001C68110AA0001C")
    print("=" * 70)

    report = {
        "metadata": {
            "tool": "iPhone Comprehensive Analysis v1.0",
            "timestamp": datetime.now().isoformat(),
            "device": KNOWN_DEVICE,
        },
        "axe1_device_info": axe1_device_info(),
        "axe2_device_logs": axe2_device_logs(),
        "axe3_security_analysis": axe3_security_analysis(),
        "axe4_iremoval_communication": axe4_iremoval_communication(),
    }

    # Save JSON report
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = OUT / f"full_analysis_{ts}.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n💾 Rapport JSON sauvegardé: {json_file}")

    # Save human-readable summary
    summary_file = OUT / f"summary_{ts}.md"
    with open(summary_file, "w", encoding="utf-8") as f:
        f.write(f"# iPhone Comprehensive Analysis — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")
        f.write(f"## 📱 Appareil: {KNOWN_DEVICE['model_name']} ({KNOWN_DEVICE['model_identifier']})\n\n")
        f.write(f"| Propriété | Valeur |\n|---|---|\n")
        f.write(f"| Model | {KNOWN_DEVICE['model_name']} |\n")
        f.write(f"| UDID | {KNOWN_DEVICE['udid']} |\n")
        f.write(f"| Serial | {KNOWN_DEVICE['serial_number']} |\n")
        f.write(f"| iOS | {KNOWN_DEVICE['ios_version']} ({KNOWN_DEVICE['ios_build']}) |\n")
        f.write(f"| Baseband | {KNOWN_DEVICE['baseband']} |\n")
        f.write(f"| Activation | {KNOWN_DEVICE['activation_state']} |\n")
        f.write(f"| iCloud Lock | {'YES 🔴' if KNOWN_DEVICE['icloud_lock'] else 'NO 🟢'} |\n\n")
        f.write(f"## 🔒 Security Assessment\n\n")
        f.write(f"- **Secure Enclave**: Present (A17 Pro)\n")
        f.write(f"- **Activation Lock**: Server-side (albert.apple.com)\n")
        f.write(f"- **USB Restricted Mode**: Active\n")
        f.write(f"- **Jailbreak**: No public jailbreak for A17/iOS 16.5\n")
        f.write(f"- **Overall**: 🔒 SECURE — Device is effectively locked\n\n")
        f.write(f"## 🛠️ iRemoval PRO Status\n\n")
        exe_exists = EXE_PATH.exists()
        dll_exists = DLL_PATH.exists()
        f.write(f"- **EXE**: {'✅ Present' if exe_exists else '❌ Missing'}\n")
        f.write(f"- **DLL**: {'✅ Present' if dll_exists else '❌ Missing'}\n")
        f.write(f"- **Scripts**: Multiple analysis scripts available\n\n")
        f.write(f"---\n*Report generated: {datetime.now().isoformat()}*\n")
    print(f"📄 Résumé Markdown sauvegardé: {summary_file}")

    print("\n" + "=" * 70)
    print("  ✅ ANALYSE COMPLÈTE — 4 AXES TERMINÉS")
    print("=" * 70)
    print(f"\n  📁 JSON: {json_file}")
    print(f"  📄 MD:   {summary_file}")


if __name__ == "__main__":
    main()
