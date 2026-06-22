#!/usr/bin/env python3
"""
Analyse approfondie des mots-clés cryptographiques
Identifie les points critiques et les algorithmes utilisés
"""

import re
from pathlib import Path
from collections import Counter

dll_path = r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\IRemovalPro\iremovalpro.dll"
output_path = r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\03_OUTPUTS\crypto_deep_analysis.txt"

print("=" * 80)
print("ANALYSE APPROFONDIE DES MOTS-CLÉS CRYPTOGRAPHIQUES")
print("=" * 80)

def extract_strings(filepath, min_length=4):
    """Extrait les strings ASCII et Unicode"""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    # ASCII
    ascii_pattern = rb'[ -~]{' + str(min_length).encode() + rb',}'
    ascii_strings = re.findall(ascii_pattern, data)
    
    # Unicode UTF-16 LE
    unicode_pattern = rb'(?:[ -~]\x00){' + str(min_length).encode() + rb',}'
    unicode_strings = re.findall(unicode_pattern, data)
    
    results = []
    for s in ascii_strings:
        try:
            results.append(s.decode('ascii'))
        except:
            pass
    
    for s in unicode_strings:
        try:
            results.append(s.decode('utf-16-le'))
        except:
            pass
    
    return results

print("\n[1] Extraction des strings...")
all_strings = extract_strings(dll_path, min_length=6)
print(f"    Total: {len(all_strings)} strings")

# Catégorisation cryptographique détaillée
crypto_categories = {
    'Algorithmes AES': [],
    'Algorithmes RSA': [],
    'Hashing (SHA/MD5)': [],
    'Certificats & PKI': [],
    'BCrypt/NCrypt': [],
    'Clés & KeyStore': [],
    'Chiffrement/Déchiffrement': [],
    'Signatures': [],
    'HMAC & MAC': [],
    'Protocoles SSL/TLS': [],
    'Random & IV': [],
    'Padding': [],
    'Apple Crypto': [],
    'Activation & Token': [],
    'Autres Crypto': []
}

# Patterns de détection
patterns = {
    'Algorithmes AES': r'(?i)(aes|rijndael|aes128|aes256|aes-cbc|aes-gcm)',
    'Algorithmes RSA': r'(?i)(rsa|rsa-?2048|rsa-?4096|rsaEncryption|publickey|privatekey)',
    'Hashing (SHA/MD5)': r'(?i)(sha-?1|sha-?256|sha-?384|sha-?512|md5|hash)',
    'Certificats & PKI': r'(?i)(certificate|cert|x509|pkcs|pem|der|crl|ocsp)',
    'BCrypt/NCrypt': r'(?i)(bcrypt|ncrypt|cng)',
    'Clés & KeyStore': r'(?i)(key|keystore|keychain|keycontainer|secretkey|masterkey)',
    'Chiffrement/Déchiffrement': r'(?i)(encrypt|decrypt|cipher|decipher|crypt)',
    'Signatures': r'(?i)(sign|signature|verify|signed)',
    'HMAC & MAC': r'(?i)(hmac|mac|authenticate)',
    'Protocoles SSL/TLS': r'(?i)(ssl|tls|https|handshake)',
    'Random & IV': r'(?i)(random|rng|iv|nonce|salt)',
    'Padding': r'(?i)(padding|pkcs|oaep|pss)',
    'Apple Crypto': r'(?i)(seckey|secitem|sectrust|security\.framework|keychain|codesign)',
    'Activation & Token': r'(?i)(activation|token|license|auth|credential)',
}

# Analyse
for string in all_strings:
    for category, pattern in patterns.items():
        if re.search(pattern, string):
            crypto_categories[category].append(string)

# Déduplication
for category in crypto_categories:
    crypto_categories[category] = list(set(crypto_categories[category]))

# Affichage des résultats
print("\n" + "=" * 80)
print("RÉSULTATS PAR CATÉGORIE")
print("=" * 80)

total_crypto = 0
for category, items in crypto_categories.items():
    count = len(items)
    total_crypto += count
    if count > 0:
        icon = "🔴" if count > 50 else "🟡" if count > 10 else "🟢"
        print(f"\n{icon} {category}: {count} occurrences")
        
        # Top 10 de chaque catégorie
        for item in sorted(items)[:10]:
            if len(item) < 120:  # Éviter les strings trop longues
                print(f"    - {item}")
        
        if len(items) > 10:
            print(f"    ... et {len(items) - 10} autres")

print(f"\n\n📊 TOTAL CRYPTO DÉTECTÉ: {total_crypto} strings uniques")

# Points critiques
print("\n" + "=" * 80)
print("🔥 POINTS CRITIQUES IDENTIFIÉS")
print("=" * 80)

critical_findings = []

# 1. Algorithmes faibles
weak_algos = [s for s in all_strings if re.search(r'(?i)(md5|des|rc4|sha-?1\b)', s)]
if weak_algos:
    critical_findings.append({
        'severity': 'HIGH',
        'type': 'Algorithmes faibles détectés',
        'count': len(set(weak_algos)),
        'items': list(set(weak_algos))[:5]
    })

# 2. Clés hardcodées potentielles
hardcoded_keys = [s for s in all_strings if re.search(r'(?i)(key\s*=|password\s*=|secret\s*=)', s)]
if hardcoded_keys:
    critical_findings.append({
        'severity': 'CRITICAL',
        'type': 'Clés potentiellement hardcodées',
        'count': len(set(hardcoded_keys)),
        'items': list(set(hardcoded_keys))[:5]
    })

# 3. Certificats Apple
apple_certs = [s for s in all_strings if 'apple' in s.lower() and any(x in s.lower() for x in ['cert', 'key', 'sign', 'trust'])]
if apple_certs:
    critical_findings.append({
        'severity': 'MEDIUM',
        'type': 'Références certificats Apple',
        'count': len(set(apple_certs)),
        'items': list(set(apple_certs))[:5]
    })

# 4. Activation/License
activation_strings = [s for s in all_strings if any(x in s.lower() for x in ['activation', 'license', 'serial', 'unlock'])]
if activation_strings:
    critical_findings.append({
        'severity': 'HIGH',
        'type': 'Mécanisme d\'activation',
        'count': len(set(activation_strings)),
        'items': list(set(activation_strings))[:5]
    })

# 5. Bypass keywords
bypass_keywords = [s for s in all_strings if any(x in s.lower() for x in ['bypass', 'crack', 'patch', 'keygen', 'unlock'])]
if bypass_keywords:
    critical_findings.append({
        'severity': 'CRITICAL',
        'type': 'Keywords de bypass/crack',
        'count': len(set(bypass_keywords)),
        'items': list(set(bypass_keywords))[:5]
    })

# Affichage des points critiques
for finding in critical_findings:
    severity_icon = "🔴" if finding['severity'] == 'CRITICAL' else "🟠" if finding['severity'] == 'HIGH' else "🟡"
    print(f"\n{severity_icon} [{finding['severity']}] {finding['type']}")
    print(f"   Occurrences: {finding['count']}")
    print(f"   Exemples:")
    for item in finding['items']:
        if len(item) < 120:
            print(f"     - {item}")

# Analyse des APIs cryptographiques Windows
print("\n" + "=" * 80)
print("🔧 APIs CRYPTOGRAPHIQUES WINDOWS")
print("=" * 80)

windows_crypto_apis = [
    'CryptAcquireContext', 'CryptCreateHash', 'CryptHashData', 'CryptGetHashParam',
    'CryptEncrypt', 'CryptDecrypt', 'CryptImportKey', 'CryptExportKey',
    'BCryptOpenAlgorithmProvider', 'BCryptGenerateSymmetricKey', 'BCryptEncrypt', 'BCryptDecrypt',
    'NCryptOpenStorageProvider', 'NCryptCreatePersistedKey', 'NCryptSetProperty',
    'CertOpenStore', 'CertGetCertificateChain', 'CertVerifyCertificateChainPolicy'
]

detected_apis = []
for api in windows_crypto_apis:
    matches = [s for s in all_strings if api in s]
    if matches:
        detected_apis.append((api, len(matches)))

if detected_apis:
    for api, count in sorted(detected_apis, key=lambda x: x[1], reverse=True):
        print(f"  ✓ {api}: {count} références")
else:
    print("  ℹ️  Aucune API crypto Windows explicite détectée")

# Sauvegarde du rapport
with open(output_path, 'w', encoding='utf-8') as f:
    f.write("=" * 80 + "\n")
    f.write("ANALYSE APPROFONDIE DES MOTS-CLÉS CRYPTOGRAPHIQUES\n")
    f.write("iremovalpro.dll\n")
    f.write("=" * 80 + "\n\n")
    
    f.write(f"Total crypto strings: {total_crypto}\n\n")
    
    # Par catégorie
    f.write("=" * 80 + "\n")
    f.write("RÉSULTATS PAR CATÉGORIE\n")
    f.write("=" * 80 + "\n\n")
    
    for category, items in crypto_categories.items():
        if len(items) > 0:
            f.write(f"\n[{category}] - {len(items)} occurrences\n")
            f.write("-" * 80 + "\n")
            for item in sorted(items):
                if len(item) < 200:
                    f.write(f"  {item}\n")
    
    # Points critiques
    f.write("\n\n" + "=" * 80 + "\n")
    f.write("POINTS CRITIQUES\n")
    f.write("=" * 80 + "\n\n")
    
    for finding in critical_findings:
        f.write(f"\n[{finding['severity']}] {finding['type']}\n")
        f.write(f"Occurrences: {finding['count']}\n")
        f.write("Exemples:\n")
        for item in finding['items']:
            if len(item) < 200:
                f.write(f"  - {item}\n")
    
    # APIs
    f.write("\n\n" + "=" * 80 + "\n")
    f.write("APIs CRYPTOGRAPHIQUES WINDOWS DÉTECTÉES\n")
    f.write("=" * 80 + "\n\n")
    
    if detected_apis:
        for api, count in sorted(detected_apis, key=lambda x: x[1], reverse=True):
            f.write(f"  {api}: {count} références\n")

print(f"\n✅ Rapport complet sauvegardé : {output_path}")
print("=" * 80)
