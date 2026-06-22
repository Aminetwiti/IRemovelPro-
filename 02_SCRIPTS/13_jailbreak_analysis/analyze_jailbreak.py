#!/usr/bin/env python3
"""
Analyse des 5 binaires Mach-O iOS extraits du bundle iRemoval PRO.
Identifie les techniques de jailbreak utilisées.
"""
import re
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
EXTR = WORK / "04_EXTRACTED"
OUT  = WORK / "03_OUTPUTS" / "jailbreak_analysis.txt"
OUT.parent.mkdir(parents=True, exist_ok=True)

# Markers des jailbreaks et outils associés
JAILBREAK_MARKERS = {
    "checkm8 (A5-A11)": [
        b"checkm8", b"check_m8", b"check-m8", b"checkra1n", b"check_ra1n",
        b"gaster", b"gaster.pwn", b"gaster_exploit",
        b"pwn", b"PwnedDFU", b"limera1n", b"limera1n_payload", b"SHA1TER",
    ],
    "palera1n (A12-A16)": [b"palera1n", b"pale", b"rootless", b"procursus", b"roothide", b"ellekit"],
    "A12 Eraser (NAND)": [b"eraser", b"A12Eraser", b"a12_eraser", b"NAND", b"nand", b"minaeraser", b"minacriss"],
    "DFU / Restore mode": [b"DFU", b"PwnDFU", b"recovery", b"iBEC", b"iBSS", b"iBoot", b"LLB"],
    "SoC / Chip IDs": [b"s8000", b"t8000", b"t8010", b"t8015", b"t8020", b"t8027", b"t8030", b"t8101", b"0x8010", b"A7", b"A8", b"A9", b"A10", b"A11", b"A12", b"A13", b"A14", b"A15", b"A16", b"A17"],
    "libimobiledevice tools": [b"idevice_id", b"ideviceinfo", b"idevicepair", b"ideviceprox", b"idevicerestore", b"usbmuxd", b"lockdownd", b"lockdown"],
    "SSH deployment": [b"sshpass", b"openssh", b"dropbear", b"ecdsa-sha2-nistp", b"SSH-2.0", b"alpine"],
    "Activation daemon": [b"MobileActivation", b"mobileactivationd", b"handleActivation", b"validateActivation", b"ActivationRecord"],
}

BINARIES = {
    "macho_8534d3_DYLIB_ARM64_ALL.bin":         "blackhound.dylib (ARM64)",
    "macho_86b4d3_DYLIB_ARM64_ARM64E.bin":      "blackhound.dylib (ARM64E)",
    "macho_8812f8_EXECUTE_ARM64_ALL.bin":       "iRemovalPro host #1",
    "macho_8a3dcd_EXECUTE_ARM64_ALL.bin":       "iRemovalPro host #2 / minaeraser",
    "macho_8ea1a8_EXECUTE_ARM64_ALL.bin":       "iRemovalPro host #3 (main app)",
}

def analyze_binary(path):
    if not path.exists():
        return {}
    data = path.read_bytes()
    results = {}
    for category, markers in JAILBREAK_MARKERS.items():
        hits = []
        for marker in markers:
            if marker in data:
                hits.append((marker.decode('ascii', errors='ignore'), data.count(marker)))
        if hits:
            results[category] = hits
    return results

print("=" * 80)
print(" iRemoval PRO — iOS Binary Jailbreak Analysis")
print("=" * 80)

output_lines = ["=" * 80, " iRemoval PRO — Analyse jailbreak iPhone", "=" * 80, ""]
output_lines.append("Recherche de markers caractéristiques des exploits de jailbreak")
output_lines.append("dans les 5 binaires Mach-O extraits du bundle .NET 8 NativeAOT.\n")

summary = {}
for filename, role in BINARIES.items():
    path = EXTR / filename
    results = analyze_binary(path)
    summary[role] = results

    output_lines.append(f"### {filename}")
    output_lines.append(f"**Rôle probable**: {role}\n")

    if not results:
        output_lines.append("Aucun marker de jailbreak trouvé.\n")
        continue

    for category, hits in results.items():
        total = sum(c for _, c in hits)
        output_lines.append(f"#### {category} ({total} occurrences)")
        for marker_name, count in hits:
            output_lines.append(f"- **{marker_name}**: {count}")
        output_lines.append("")

# === Conclusion ===
output_lines.append("=" * 80)
output_lines.append("## CONCLUSION — Comment iRemoval PRO jailbreak l'iPhone")
output_lines.append("=" * 80)
output_lines.append("")
output_lines.append("### Phase 1 : Mise en DFU (Device Firmware Update)")
output_lines.append("- Détection iPhone via USB (libimobiledevice)")
output_lines.append("- Mode DFU via USB control transfer")
output_lines.append("")
output_lines.append("### Phase 2 : Exploit checkm8 (A5-A11) ou palera1n (A12-A16)")
output_lines.append("- **checkm8** = exploit bootrom non-patchable (axi0mX, 2018)")
output_lines.append("- Heap buffer overflow dans le code DFU de la SecureROM")
output_lines.append("- Exécute du code en mode Pongo (avant iBoot)")
output_lines.append("- Affecte A5-A11 (iPhone 4S à iPhone X)")
output_lines.append("- **palera1n** = fork checkra1n pour A12+")
output_lines.append("")
output_lines.append("### Phase 3 : Injection du kernel jailbreaké")
output_lines.append("- Kernel custom poussé via USB")
output_lines.append("- Désactive AMFI, code signing, trust cache, sandbox")
output_lines.append("")
output_lines.append("### Phase 4 : SSH + installation Cydia")
output_lines.append("- OpenSSH sur port 22 (root:alpine)")
output_lines.append("- Cydia + MobileSubstrate installés via dpkg/apt")
output_lines.append("")
output_lines.append("### Phase 5 : Déploiement blackhound.dylib")
output_lines.append("- Tweak `com.panyolsoft.blackhound` poussé via SCP")
output_lines.append("- Installé dans `/Library/MobileSubstrate/DynamicLibraries/`")
output_lines.append("- 5 hooks s'activent au boot")
output_lines.append("")
output_lines.append("### Phase 6 : Bypass Activation Lock")
output_lines.append("- PC contacte s13.iremovalpro.com (iact8.php)")
output_lines.append("- Serveur signe faux ticket avec RSA-1024")
output_lines.append("- Ticket poussé via SSH vers /var/mobileactivationd/")
output_lines.append("- Hooks acceptent le ticket forgé")
output_lines.append("- iPhone démarre sans iCloud lock")
output_lines.append("")
output_lines.append("=" * 80)
output_lines.append("## RÉFÉRENCES")
output_lines.append("=" * 80)
output_lines.append("- checkm8 : https://github.com/axi0mX/ipwnder")
output_lines.append("- checkra1n : https://checkra.in")
output_lines.append("- palera1n : https://palera.in")
output_lines.append("- libimobiledevice : https://libimobiledevice.org")
output_lines.append("- Cydia Substrate : http://www.cydiasubstrate.com/")

OUT.write_text('\n'.join(output_lines), encoding='utf-8')
print(f"\n[+] Saved: {OUT}")
print(f"[+] {OUT.stat().st_size:,} bytes")
