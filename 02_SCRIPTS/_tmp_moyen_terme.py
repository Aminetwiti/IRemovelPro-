"""Moyen terme tasks #11 (DMD ops categorization) and #17 (XOR payload analysis).

Tasks:
  #11 - Categorize the 24 DMD operations: read/write/critical/abuse vector
  #17 - Identify XOR key for payload 0xa6bace-0xa6c000 of iremovalpro.dll
"""
import os, re, struct, hashlib, binascii, collections, json

BASE = r'C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2'

# ============ #11 — DMD ops categorization ============
# Pull from NOUVELLES_DECOUVERTES.md §3 (already documented)
# Each operation: name, apple_doc_role, category (READ/WRITE/CRITICAL), abuse_vector

dmd_ops = [
    # name, role, category, abuse_vector
    ("com.apple.dmd.operation.clear-activation-lock-bypass-code",
     "Efface le code bypass d'activation lock",
     "CRITICAL-WRITE",
     "Permet de supprimer le cache du code bypass — combine avec fetch-* = re-attaque"),
    ("com.apple.dmd.operation.fetch-activation-lock-bypass-code",
     "Recupere le code bypass d'activation lock officiel (Apple)",
     "CRITICAL-READ",
     "Cible principale iRemoval PRO — permet d'obtenir un code legit pour un device non supervise"),
    ("com.apple.dmd.operation.fetch-unlock-token",
     "Recupere le token de deverrouillage officiel",
     "CRITICAL-READ",
     "Cible secondaire — permet d'activer un device bloque"),
    ("com.apple.dmd.operation.erase-device",
     "Efface le device a distance",
     "WRITE-DANGEROUS",
     "Si appele sur un device iRemoval-attaque, detruit les artefacts forensiques"),
    ("com.apple.dmd.operation.lock-device",
     "Verrouille le device a distance",
     "WRITE",
     "Outil de containment — peut-etre invoque legitime par MDM enterprise"),
    ("com.apple.dmd.operation.restart-device",
     "Redemarre le device",
     "WRITE",
     "Faible interet pour bypass"),
    ("com.apple.dmd.operation.install-profile",
     "Installe un profil de configuration",
     "WRITE",
     "Vecteur d'installation de profiles malicieux (.mobileconfig)"),
    ("com.apple.dmd.operation.remove-profile",
     "Supprime un profil",
     "WRITE",
     "Cleanup — peut-etre utilise pour effacer le profil enterprise"),
    ("com.apple.dmd.operation.install-provisioning-profile",
     "Installe un profil de provisionnement",
     "WRITE",
     "Similaire a install-profile, plus specifique dev"),
    ("com.apple.dmd.operation.remove-provisioning-profile",
     "Supprime un profil de provisionnement",
     "WRITE",
     "Cleanup"),
    ("com.apple.dmd.operation.clear-device-passcode",
     "Supprime le code de verrouillage",
     "CRITICAL-WRITE",
     "Si appele SANS supervision = bypass de l'authentification utilisateur"),
    ("com.apple.dmd.operation.clear-restrictions-password",
     "Supprime le mot de passe Restrictions",
     "WRITE",
     "Faible — Restrictions = controles parentaux"),
    ("com.apple.dmd.operation.fetch-device-properties",
     "Recupere les proprietes du device",
     "READ",
     "Reconnaissance — inventaire (model, ECID, MEID, IMEI)"),
    ("com.apple.dmd.operation.fetch-applications",
     "Liste les apps installees",
     "READ",
     "Reconnaissance — detection de tweaks jailbreak"),
    ("com.apple.dmd.operation.fetch-profiles",
     "Liste les profiles installes",
     "READ",
     "Reconnaissance — detection de MDM enterprise"),
    ("com.apple.dmd.operation.fetch-provisioning-profiles",
     "Liste les profils de provisionnement",
     "READ",
     "Reconnaissance dev"),
    ("com.apple.dmd.operation.fetch-certificates",
     "Liste les certificats",
     "READ",
     "Exfiltration de certificats (PKI)"),
    ("com.apple.dmd.operation.fetch-security-information",
     "Recupere les infos de securite",
     "READ",
     "Reconnaissance — jailbreak status, passcode set, etc."),
    ("com.apple.dmd.operation.fetch-restrictions",
     "Recupere les restrictions",
     "READ",
     "Reconnaissance"),
    ("com.apple.dmd.operation.fetch-available-os-updates",
     "Liste les MAJ OS dispo",
     "READ",
     "Reconnaissance — version iOS pour exploitation"),
    ("com.apple.dmd.operation.fetch-os-update-status",
     "Statut MAJ OS en cours",
     "READ",
     "Reconnaissance"),
    ("com.apple.dmd.operation.schedule-os-update",
     "Programme une MAJ OS",
     "WRITE",
     "Faible interet pour bypass — peut-etre utilise pour forcer upgrade pre-bypass"),
    ("com.apple.dmd.operation.invite-to-volume-purchase-program",
     "Invite au VPP",
     "WRITE",
     "Hors-perimetre bypass"),
    ("com.apple.dmd.operation.request-airplay-mirroring",
     "Demande AirPlay Mirroring",
     "WRITE",
     "Hors-perimetre bypass"),
]

# Categorize
by_cat = collections.Counter()
for name, role, cat, abuse in dmd_ops:
    by_cat[cat] += 1

print('=' * 70)
print('#11 - 24 DMD OPERATIONS CATEGORIZATION')
print('=' * 70)
print(f'Total operations: {len(dmd_ops)}')
print()
print('By category:')
for cat, count in sorted(by_cat.items()):
    print(f'  {cat:20s} : {count}')

critical = [op for op in dmd_ops if 'CRITICAL' in op[2]]
writes = [op for op in dmd_ops if 'WRITE' in op[2]]
reads = [op for op in dmd_ops if 'READ' in op[2]]

print()
print(f'CRITICAL operations ({len(critical)}):')
for op in critical:
    print(f'  - {op[0].split(".")[-1]}')
print()
print(f'WRITE operations ({len(writes)}):')
for op in writes:
    print(f'  - {op[0].split(".")[-1]}')
print()
print(f'READ operations ({len(reads)}):')
for op in reads:
    print(f'  - {op[0].split(".")[-1]}')

# Save for later
out_dir = os.path.join(BASE, '05_IOC')
with open(os.path.join(out_dir, 'dmd_operations_classified.json'), 'w', encoding='utf-8') as f:
    json.dump({
        'total': len(dmd_ops),
        'by_category': dict(by_cat),
        'critical_count': len(critical),
        'write_count': len(writes),
        'read_count': len(reads),
        'operations': [
            {'name': op[0], 'role': op[1], 'category': op[2], 'abuse_vector': op[3]}
            for op in dmd_ops
        ],
    }, f, indent=2, ensure_ascii=False)
print()
print(f'Saved to: 05_IOC/dmd_operations_classified.json')

# ============ #17 — XOR payload analysis ============
print()
print('=' * 70)
print('#17 - XOR PAYLOAD ANALYSIS (0xa6bace - 0xa6c000)')
print('=' * 70)

# We don't have the raw DLL, but we have strings_all_long.txt
# Search for known XOR-encrypted markers like "https://", "ssh-rsa", "BEGIN"
strings_file = os.path.join(BASE, '03_OUTPUTS', 'strings_all_long.txt')
data = open(strings_file, encoding='utf-8', errors='replace').read()

# Known plaintext candidates (typical XOR targets in bypass tools)
xor_targets = [
    ('https://', 'URL prefix'),
    ('ssh-rsa ', 'SSH key marker'),
    ('BEGIN ', 'PEM/cert marker'),
    ('-----BEGIN', 'PEM begin'),
    ('ACTIVATION', 'iOS activation record'),
    ('com.apple', 'Bundle ID prefix'),
    ('iRemoval', 'Tool name'),
    ('localhost', 'Localhost'),
]

# Try single-byte XOR on all candidates and see what we get
print('XOR key search against known plaintext markers:')
for target, descr in xor_targets:
    target_bytes = target.encode('ascii')
    # Search the strings dump for the XOR of target with each byte
    for key_byte in range(256):
        xored = bytes([b ^ key_byte for b in target_bytes])
        xored_str = xored.decode('ascii', errors='replace')
        if xored_str in data:
            pos = data.find(xored_str)
            print(f'  HIT: {descr:20s} key=0x{key_byte:02x} ({key_byte:3d}) "{target}" XOR -> "{xored_str}" at pos {pos}')

# Also try looking for high-entropy regions that might be XOR-encrypted
print()
print('Searching for high-entropy ASCII regions (potential XOR ciphertext):')
# Split into ~16-char chunks and check entropy
chunk_size = 16
n_chunks = 0
high_entropy = 0
for i in range(0, len(data) - chunk_size, chunk_size):
    chunk = data[i:i+chunk_size]
    # Quick entropy check: count unique chars
    unique = len(set(chunk))
    if unique > 12:  # Most ASCII chars are present
        high_entropy += 1
    n_chunks += 1
print(f'  Total chunks analyzed: {n_chunks}')
print(f'  High-entropy chunks (>12 unique chars in 16): {high_entropy}')
print(f'  Ratio: {high_entropy/n_chunks:.1%}')

# Look for repeating 4-byte patterns (potential XOR key length markers)
print()
print('Searching for repeating 4-byte patterns (Kasiski-style, key length 4-16):')
all_ascii_runs = re.findall(r'[A-Za-z0-9+/=]{20,}', data)
print(f'  ASCII runs >= 20 chars: {len(all_ascii_runs)}')
# Show some long ones
for run in sorted(all_ascii_runs, key=len, reverse=True)[:5]:
    print(f'  [{len(run):4d}] {run[:80]}')

print()
print('=== Summary ===')
print('XOR key not directly identifiable from strings alone.')
print('Requires:')
print('  - Raw DLL bytes (not strings dump)')
print('  - Disassembly to find XOR loop in the code')
print('  - Reference plaintext (URL, key, etc.) for known-plaintext attack')
