#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FairPlay Key Extraction — iremovalpro.dll + BlackHound dylib
=============================================================
Extrait les clés, certificats et blobs crypto liés au FairPlay DRM :
  1. Apple Root CA certificate (DER)
  2. Apple Intermediate CA certificates
  3. RSA public keys (BlackHound / iRemoval)
  4. FairPlay request/response templates (JSON/plist)
  5. ECDSA signature blobs (activation tickets)
  6. PKCS#7 / CMS signed data structures
  7. HMAC key material
  8. AES S-box / SHA-256 K-table
  9. drmHandshake plist templates
  10. Activation ticket format markers

Auteur: Audit statique défensif — TLP:LEAKED
Date: 2026-06-23
"""

import sys, os, struct, re, hashlib, base64, json, io
from pathlib import Path
from datetime import datetime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

BASE = Path(r"c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL_PATH = BASE / "IRemovalPro" / "iremovalpro.dll"
OUT = BASE / "04_EXTRACTED" / "fairplay_keys"
OUT.mkdir(parents=True, exist_ok=True)

REPORT = {
    "tool": "FairPlay Key Extraction v1.0",
    "timestamp": datetime.now().isoformat(),
    "dll_path": str(DLL_PATH),
    "findings": {}
}

# ── Load DLL ──
print("=" * 70)
print("  🔑 FAIRPLAY KEY EXTRACTION — iremovalpro.dll")
print("=" * 70)

if not DLL_PATH.exists():
    print(f"❌ DLL not found: {DLL_PATH}")
    sys.exit(1)

data = DLL_PATH.read_bytes()
print(f"📦 DLL: {len(data):,} bytes ({len(data)/1024/1024:.2f} MB)")
print(f"   SHA-256: {hashlib.sha256(data).hexdigest()}")

# ════════════════════════════════════════════════════════════════
#  1. APPLE ROOT CA + INTERMEDIATE CERTIFICATES
# ════════════════════════════════════════════════════════════════
print("\n" + "─" * 70)
print("  [1] 🏛️  CERTIFICATS X.509 (Apple Root CA + intermediates)")
print("─" * 70)

cert_markers = [
    b'Apple Root CA',
    b'Apple Worldwide Developer Relations Certification Authority',
    b'Apple Certification Authority',
    b'Apple Inc. Root Certificate',
    b'iPhone Certification Authority',
    b'iPhone Device CA',
    b'Apple iPhone Device Certification',
    b'Apple iOS Device Certification',
    b'Apple Software Update Certification Authority',
    b'Apple Application Integration Certification Authority',
    b'Apple Mobile Device Installation',
]

certs_found = []

# Method 1: Walk from marker backwards to find SEQUENCE header
for marker in cert_markers:
    pos = 0
    while True:
        pos = data.find(marker, pos)
        if pos < 0:
            break
        # Walk backwards to find ASN.1 SEQUENCE (0x30 0x82)
        cert_start = -1
        for back in range(0, 2000, 1):
            candidate = pos - back
            if candidate < 0:
                break
            if data[candidate] == 0x30 and data[candidate + 1] == 0x82:
                b1 = data[candidate + 2]
                b2 = data[candidate + 3]
                total = (b1 << 8) | b2
                if 200 <= total <= 3000:
                    blob = data[candidate:candidate + total + 4]
                    if marker in blob:
                        cert_start = candidate
                        cert_len = total + 4
                        break
        if cert_start > 0:
            cert_der = data[cert_start:cert_start + cert_len]
            sha = hashlib.sha256(cert_der).hexdigest()

            # Check for duplicates
            already_saved = any(c['sha256'] == sha for c in certs_found)
            if not already_saved:
                fname = f"cert_0x{cert_start:08x}_{marker.decode('ascii','replace').replace(' ','_')[:30]}.der"
                fpath = OUT / fname
                fpath.write_bytes(cert_der)

                # Also save base64
                b64_path = OUT / fname.replace('.der', '.b64')
                b64_path.write_text(base64.b64encode(cert_der).decode() + '\n')

                # Save PEM
                pem = f"-----BEGIN CERTIFICATE-----\n{base64.b64encode(cert_der).decode()}\n-----END CERTIFICATE-----\n"
                pem_path = OUT / fname.replace('.der', '.pem')
                pem_path.write_text(pem)

                certs_found.append({
                    "marker": marker.decode('ascii', errors='replace'),
                    "offset": f"0x{cert_start:08x}",
                    "length": cert_len,
                    "sha256": sha,
                    "file_der": fname,
                    "file_b64": fname.replace('.der', '.b64'),
                    "file_pem": fname.replace('.der', '.pem'),
                })
                print(f"   ✅ {marker.decode('ascii','replace')[:50]} @ 0x{cert_start:08x} ({cert_len} bytes)")
                print(f"      SHA-256: {sha}")
                print(f"      Files: {fname}, {fname.replace('.der','.b64')}, {fname.replace('.der','.pem')}")

        pos += 1

# Method 2: Find all large ASN.1 SEQUENCE with Apple-related content
print("\n   [Bonus scan] All DER SEQUENCEs with Apple content...")
for i in range(0, len(data) - 4, 4):
    if data[i] == 0x30 and data[i + 1] == 0x82:
        length = (data[i + 2] << 8) | data[i + 3]
        if 300 <= length <= 3000:
            blob = data[i:i + length + 4]
            sha = hashlib.sha256(blob).hexdigest()
            if any(c['sha256'] == sha for c in certs_found):
                continue
            # Check for interesting content
            blob_str = blob.decode('latin1', errors='replace')
            interesting_terms = ['Apple', 'iPhone', 'Certification', 'Authority', 'Root', 'Activation']
            found_terms = [t for t in interesting_terms if t in blob_str]
            if found_terms:
                fname = f"cert_extra_0x{i:08x}_({length}b).der"
                (OUT / fname).write_bytes(blob)
                certs_found.append({
                    "marker": f"extra({','.join(found_terms)})",
                    "offset": f"0x{i:08x}",
                    "length": length + 4,
                    "sha256": sha,
                    "file_der": fname,
                })
                print(f"   ✅ Extra cert @ 0x{i:08x} ({length + 4} bytes) — terms: {','.join(found_terms)}")

REPORT["findings"]["certificates"] = certs_found
print(f"\n   📊 Total certificates: {len(certs_found)}")

# ════════════════════════════════════════════════════════════════
#  2. RSA PUBLIC KEYS
# ════════════════════════════════════════════════════════════════
print("\n" + "─" * 70)
print("  [2] 🔐 RSA PUBLIC KEYS")
print("─" * 70)

rsa_keys_found = []

# Method 1: Base64-encoded RSA keys (ending in AQAB = RSA exponent 65537)
rsa_b64_pattern = re.compile(rb'[A-Za-z0+/=]{100,}AQAB')
for m in rsa_b64_pattern.finditer(data):
    start = m.start()
    while start > 0 and chr(data[start - 1]) in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0+/=':
        start -= 1
    end = m.end()
    b64_str = data[start:end].decode('ascii', errors='replace')

    try:
        raw = base64.b64decode(b64_str)
        # Check DER SEQUENCE structure (SubjectPublicKeyInfo)
        if raw[:2] == b'\x30\x82' or raw[:2] == b'\x30\x0d':
            seq_len = (raw[2] << 8) | raw[3] if raw[1] == 0x82 else raw[1]
            rsa_oid = b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01'  # rsaEncryption OID

            if rsa_oid in raw:
                sha = hashlib.sha256(raw).hexdigest()
                fname = f"rsa_pubkey_0x{start:08x}.der"
                (OUT / fname).write_bytes(raw)
                (OUT / fname.replace('.der', '.b64')).write_text(b64_str + '\n')

                rsa_keys_found.append({
                    "offset": f"0x{start:08x}",
                    "length": len(raw),
                    "sha256": sha,
                    "has_rsa_oid": True,
                    "file_der": fname,
                })
                print(f"   ✅ RSA pubkey @ 0x{start:08x} ({len(raw)} bytes) — RSA OID confirmed")
                print(f"      SHA-256: {sha}")
                print(f"      Key size indicator: {len(raw)} bytes → ~{len(raw)*8} bit")
    except Exception:
        pass

# Method 2: Raw DER RSA key patterns (OID + modulus)
rsa_oid = b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01'
pos = 0
while True:
    pos = data.find(rsa_oid, pos)
    if pos < 0:
        break
    # Look for SEQUENCE header before OID
    for back in range(0, 50):
        cand = pos - back
        if cand < 0:
            break
        if data[cand] == 0x30 and data[cand + 1] in (0x82, 0x81, 0x0d):
            if data[cand + 1] == 0x82:
                seq_len = (data[cand + 2] << 8) | data[cand + 3]
            elif data[cand + 1] == 0x81:
                seq_len = data[cand + 2]
            else:
                seq_len = data[cand + 1]
            blob = data[cand:cand + seq_len + 4]
            sha = hashlib.sha256(blob).hexdigest()
            already = any(k['sha256'] == sha for k in rsa_keys_found)
            if not already and 100 <= len(blob) <= 600:
                fname = f"rsa_pubkey_raw_0x{cand:08x}.der"
                (OUT / fname).write_bytes(blob)
                rsa_keys_found.append({
                    "offset": f"0x{cand:08x}",
                    "length": len(blob),
                    "sha256": sha,
                    "has_rsa_oid": True,
                    "file_der": fname,
                })
                print(f"   ✅ RSA raw key @ 0x{cand:08x} ({len(blob)} bytes)")
                print(f"      SHA-256: {sha}")
                break
    pos += 1

REPORT["findings"]["rsa_keys"] = rsa_keys_found
print(f"\n   📊 Total RSA keys: {len(rsa_keys_found)}")

# ════════════════════════════════════════════════════════════════
#  3. FAIRPLAY DRM TEMPLATES (plist / JSON)
# ════════════════════════════════════════════════════════════════
print("\n" + "─" * 70)
print("  [3] 📜 FAIRPLAY DRM TEMPLATES (plist / JSON)")
print("─" * 70)

fairplay_templates = []

# FairPlay-related string patterns (UTF-16LE search — Windows DLL)
fp_search_terms = [
    ('fairplay-key', 'FairPlay DRM key template'),
    ('fairplayRequest', 'FairPlay request structure'),
    ('fairplayResponse', 'FairPlay response structure'),
    ('fairPlayRequest', 'FairPlay request (capitalized)'),
    ('fairPlayResponse', 'FairPlay response (capitalized)'),
    ('wildcardTicket', 'Wildcard activation ticket'),
    ('wildcard-ticket', 'Wildcard activation ticket variant'),
    ('ActivationTicket', 'Activation ticket structure'),
    ('serverCertificates', 'Server certificates bundle'),
    ('activation-random-key', 'Activation random key'),
    ('drmHandshake', 'DRM handshake reference'),
    ('fairplay-client', 'FairPlay client entitlement'),
    ('FairPlayKey', 'FairPlay key class'),
    ('FairPlayCertificate', 'FairPlay certificate class'),
    ('FairPlayRequest', 'FairPlay request class'),
    ('DeviceCertificate', 'Device certificate reference'),
    ('GetActivationRecord', 'Activation record getter'),
    ('ActivationState', 'Activation state property'),
    ('ActivationRecord', 'Activation record structure'),
    ('activationInfo', 'Activation info payload'),
    ('com.apple.mobileactivation', 'Mobile activation daemon'),
    ('com.apple.mobileactivationd', 'Mobile activation daemon bundle ID'),
    ('com.apple.security.attestation', 'Security attestation entitlement'),
    ('MobileActivationDaemon', 'MobileActivationDaemon class'),
    ('handleActivationInfo', 'Activation info handler method'),
    ('validateActivationData', 'Activation data validator'),
    ('CreateActivationSession', 'Activation session creator'),
    ('BESRequest', 'BES (Activation) request'),
    ('BESResponse', 'BES (Activation) response'),
    ('BBIRequest', 'BBI request'),
    ('BBIResponse', 'BBI response'),
]

for term_utf8, description in fp_search_terms:
    found_positions = []

    # Search UTF-16LE
    term_utf16 = term_utf8.encode('utf-16-le')
    pos = 0
    while True:
        pos = data.find(term_utf16, pos)
        if pos < 0:
            break
        found_positions.append(('UTF16', pos))
        pos += 1

    # Search ASCII
    pos = 0
    while True:
        pos = data.find(term_utf8.encode('ascii'), pos)
        if pos < 0:
            break
        found_positions.append(('ASCII', pos))
        pos += 1

    if found_positions:
        # Extract context around each match
        for enc, offset in found_positions[:3]:
            ctx_len = 300
            ctx_start = max(0, offset - 100)
            ctx_end = min(len(data), offset + ctx_len)
            ctx = data[ctx_start:ctx_end]

            if enc == 'UTF16':
                try:
                    ctx_str = ctx.decode('utf-16-le', errors='replace')
                except:
                    ctx_str = ctx.decode('latin1', errors='replace')
            else:
                ctx_str = ctx.decode('ascii', errors='replace')

            # Save context
            fname = f"fp_{term_utf8.replace('.','_').replace('-','_')}_{enc}_0x{offset:08x}.txt"
            (OUT / fname).write_text(ctx_str, encoding='utf-8')

            fairplay_templates.append({
                "term": term_utf8,
                "description": description,
                "encoding": enc,
                "offset": f"0x{offset:08x}",
                "total_hits": len(found_positions),
                "context_file": fname,
            })

            print(f"   📜 {term_utf8} ({enc}) — {len(found_positions)} hit(s)")
            print(f"      Context: {ctx_str[:80].replace(chr(0),'')!r}...")

REPORT["findings"]["fairplay_templates"] = fairplay_templates
print(f"\n   📊 Total FairPlay template hits: {len(fairplay_templates)}")

# ════════════════════════════════════════════════════════════════
#  4. ECDSA SIGNATURE BLOBS (Activation ticket signatures)
# ════════════════════════════════════════════════════════════════
print("\n" + "─" * 70)
print("  [4] ✍️  ECDSA SIGNATURE BLOBS")
print("─" * 70)

ecdsa_blobs_found = []

# ECDSA signature in ASN.1: 0x30 + length (0x44-0x4A) + 0x02 (INTEGER)
for i in range(len(data) - 72):
    if data[i] == 0x30 and data[i + 1] in range(0x44, 0x4B) and data[i + 2] == 0x02:
        seq_len = data[i + 1]
        blob = data[i:i + seq_len + 2]
        sha = hashlib.sha256(blob).hexdigest()

        # Check for r,s integers (ECDSA format)
        # 0x02 <len> <r_bytes> 0x02 <len> <s_bytes>
        if len(blob) >= 8 and blob[2] == 0x02:
            # Parse r integer
            r_len = blob[4]
            r_start = 5
            r_end = r_start + r_len
            if r_end < len(blob) and blob[r_end] == 0x02:
                s_len = blob[r_end + 1]
                s_start = r_end + 2
                s_end = s_start + s_len

                r_val = blob[r_start:r_end].hex()
                s_val = blob[s_start:s_end].hex()

                fname = f"ecdsa_sig_0x{i:08x}_{seq_len}b.der"
                (OUT / fname).write_bytes(blob)

                ecdsa_blobs_found.append({
                    "offset": f"0x{i:08x}",
                    "total_length": seq_len + 2,
                    "r_length": r_len,
                    "s_length": s_len,
                    "r_hex": r_val[:32],
                    "s_hex": s_val[:32],
                    "sha256": sha,
                    "file_der": fname,
                })

                # Only print first 15 to avoid spam
                if len(ecdsa_blobs_found) <= 15:
                    print(f"   ✅ ECDSA @ 0x{i:08x} ({seq_len + 2} bytes) — r:{r_len}b s:{s_len}b")

print(f"\n   📊 Total ECDSA blobs: {len(ecdsa_blobs_found)} (showing first 15)")
REPORT["findings"]["ecdsa_signatures"] = ecdsa_blobs_found

# ════════════════════════════════════════════════════════════════
#  5. PKCS#7 / CMS SIGNED DATA (Activation ticket containers)
# ════════════════════════════════════════════════════════════════
print("\n" + "─" * 70)
print("  [5] 📦 PKCS#7 / CMS SIGNED DATA")
print("─" * 70)

cms_found = []

# PKCS#7 signedData OID: 1.2.840.113549.1.7.2
pkcs7_signed_oid = b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02'
pkcs7_enveloped_oid = b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x03'
pkcs7_data_oid = b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01'

for oid_name, oid_bytes in [('signedData', pkcs7_signed_oid),
                              ('envelopedData', pkcs7_enveloped_oid),
                              ('data', pkcs7_data_oid)]:
    pos = 0
    count = 0
    while True:
        pos = data.find(oid_bytes, pos)
        if pos < 0:
            break
        count += 1
        if count <= 5:
            # Extract the outer SEQUENCE containing this OID
            ctx = data[max(0, pos - 50):pos + 200]
            ctx_str = ''.join(f'{b:02x}' for b in ctx[:80])
            print(f"   ✅ PKCS#7 {oid_name} OID @ 0x{pos:08x} (count={count})")
            print(f"      Context hex: {ctx_str[:120]}")

        pos += 1

    cms_found.append({
        "oid_name": oid_name,
        "total_hits": count,
    })

REPORT["findings"]["pkcs7_cms"] = cms_found
print(f"\n   📊 PKCS#7 OID references: {sum(c['total_hits'] for c in cms_found)}")

# ════════════════════════════════════════════════════════════════
#  6. HMAC KEY MATERIAL
# ════════════════════════════════════════════════════════════════
print("\n" + "─" * 70)
print("  [6] 🗝️  HMAC KEY MATERIAL")
print("─" * 70)

hmac_findings = []

# Check the known hmac_secret.json file
hmac_json = BASE / "logs" / "hmac_secret.json"
if hmac_json.exists():
    hmac_content = hmac_json.read_text()
    print(f"   ✅ hmac_secret.json found in logs/")
    print(f"      Content: {hmac_content[:150]}")
    hmac_findings.append({
        "source": "logs/hmac_secret.json",
        "content_preview": hmac_content[:200],
    })

# Search DLL for HMAC-related strings
hmac_terms = ['HmacAlgorithms', 'HmacSha256', 'HMAC', 'hmac_sha256',
              'hmac_key', 'hmacSecret', 'hmac-secret']
for term in hmac_terms:
    for enc_name, encoder in [('UTF16', lambda t: t.encode('utf-16-le')),
                               ('ASCII', lambda t: t.encode('ascii'))]:
        encoded = encoder(term)
        pos = 0
        while True:
            pos = data.find(encoded, pos)
            if pos < 0:
                break
            ctx = data[max(0, pos - 30):pos + 100]
            ctx_str = ctx.decode('latin1', errors='replace')
            print(f"   📜 {term} ({enc_name}) @ 0x{pos:08x}")
            print(f"      Context: {ctx_str[:80]!r}")
            hmac_findings.append({
                "term": term,
                "encoding": enc_name,
                "offset": f"0x{pos:08x}",
                "context": ctx_str[:80],
            })
            pos += 1

REPORT["findings"]["hmac_material"] = hmac_findings
print(f"\n   📊 Total HMAC findings: {len(hmac_findings)}")

# ════════════════════════════════════════════════════════════════
#  7. AES S-BOX + SHA-256 K-TABLE
# ════════════════════════════════════════════════════════════════
print("\n" + "─" * 70)
print("  [7] 🧮 AES S-BOX + SHA-256 K-TABLE")
print("─" * 70)

crypto_tables = []

# Standard AES S-Box (256 bytes starting with 0x63,0x7c,0x77,0x7b...)
aes_sbox_start = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])
pos = 0
while True:
    pos = data.find(aes_sbox_start, pos)
    if pos < 0:
        break
    # Validate: check if the next 256 bytes match AES S-Box
    candidate = data[pos:pos + 256]
    is_sbox = (candidate[0] == 0x63 and candidate[1] == 0x7c and
                candidate[2] == 0x77 and candidate[3] == 0x7b and
                candidate[0x10] == 0xab and candidate[0xff] == 0x16)  # known AES S-Box values
    if is_sbox:
        sha = hashlib.sha256(candidate).hexdigest()
        fname = f"aes_sbox_0x{pos:08x}.bin"
        (OUT / fname).write_bytes(candidate)
        crypto_tables.append({
            "type": "AES S-Box",
            "offset": f"0x{pos:08x}",
            "length": 256,
            "sha256": sha,
            "file": fname,
        })
        print(f"   ✅ AES S-Box @ 0x{pos:08x} (256 bytes) — SHA-256: {sha}")
    pos += 1

# SHA-256 K-table (64 32-bit words = 256 bytes)
# First 4 words: 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
sha256_k_start = struct.pack('>IIII', 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5)
pos = 0
while True:
    pos = data.find(sha256_k_start, pos)
    if pos < 0:
        break
    candidate = data[pos:pos + 256]
    sha = hashlib.sha256(candidate).hexdigest()
    fname = f"sha256_ktable_0x{pos:08x}.bin"
    (OUT / fname).write_bytes(candidate)
    crypto_tables.append({
        "type": "SHA-256 K-table",
        "offset": f"0x{pos:08x}",
        "length": 256,
        "sha256": sha,
        "file": fname,
    })
    print(f"   ✅ SHA-256 K-table @ 0x{pos:08x} (256 bytes) — SHA-256: {sha}")
    pos += 1

REPORT["findings"]["crypto_tables"] = crypto_tables
print(f"\n   📊 Crypto tables found: {len(crypto_tables)}")

# ════════════════════════════════════════════════════════════════
#  8. drmHandshake PLIST TEMPLATES
# ════════════════════════════════════════════════════════════════
print("\n" + "─" * 70)
print("  [8] 📄 drmHandshake PLIST TEMPLATES")
print("─" * 70)

plist_templates = []

# Search for plist structures with activation-related keys
plist_markers = [
    b'<!DOCTYPE plist',
    b'<plist version="1.0"',
    b'</plist>',
]

# Find plist documents in DLL
for marker in plist_markers:
    pos = 0
    while True:
        pos = data.find(marker, pos)
        if pos < 0:
            break

        # Try to find the full plist (from <!DOCTYPE or <plist to </plist>)
        # Walk back to find start
        start = pos
        for back in range(0, 500):
            cand = pos - back
            if cand < 0:
                break
            chunk = data[cand:cand + 20]
            if b'<plist' in chunk or b'<!DOCTYPE' in chunk:
                start = cand
                break

        # Find end
        end_pos = data.find(b'</plist>', pos)
        if end_pos > 0:
            plist_data = data[start:end_pos + 8]
            plist_str = plist_data.decode('ascii', errors='replace')

            # Check for activation/FairPlay content
            fp_keywords = ['Activation', 'activation', 'FairPlay', 'fairplay', 'drm',
                           'DeviceCertificate', 'serverCertificates', 'wildcard', 'ticket']
            has_fp = any(kw in plist_str for kw in fp_keywords)

            if has_fp or len(plist_data) > 100:
                fname = f"plist_0x{start:08x}_{len(plist_data)}b.xml"
                (OUT / fname).write_text(plist_str, encoding='utf-8')

                plist_templates.append({
                    "offset": f"0x{start:08x}",
                    "length": len(plist_data),
                    "has_fairplay_content": has_fp,
                    "content_preview": plist_str[:200],
                    "file": fname,
                })

                tag = "🔑 FP" if has_fp else "📄 generic"
                print(f"   {tag} PLIST @ 0x{start:08x} ({len(plist_data)} bytes)")
                if has_fp:
                    kws = [kw for kw in fp_keywords if kw in plist_str]
                    print(f"      Keywords: {', '.join(kws)}")

        pos += 1

REPORT["findings"]["plist_templates"] = plist_templates
print(f"\n   📊 Plist templates found: {len(plist_templates)}")

# ════════════════════════════════════════════════════════════════
#  9. iRemoval SERVER ENDPOINT PAYLOADS
# ════════════════════════════════════════════════════════════════
print("\n" + "─" * 70)
print("  [9] 🌐 iRemoval SERVER ENDPOINT PAYLOADS")
print("─" * 70)

endpoint_payloads = []

# Known server URLs embedded in DLL
server_urls = [
    'https://s13.iremovalpro.com/iremovalActivation/iact8.php',
    'https://s13.iremovalpro.com/iremovalActivation/checkm8.php',
    'https://s13.iremovalpro.com/iremovalActivation/auth3.php',
    'https://s13.iremovalpro.com/iremovalActivation/ars2.php',
    'https://s13.iremovalpro.com/iremovalActivation/mf5.php',
    'https://s13.iremovalpro.com/iremovalActivation/mf6.php',
    'https://s13.iremovalpro.com/iremovalActivation/mf7.php',
    'https://s13.iremovalpro.com/version33.txt',
    'https://albert.apple.com/deviceservices/drmHandshake',
]

for url in server_urls:
    for enc_name, encoder in [('UTF16', lambda u: u.encode('utf-16-le')),
                               ('ASCII', lambda u: u.encode('ascii'))]:
        encoded = encoder(url)
        pos = data.find(encoded)
        if pos >= 0:
            # Extract context around URL (JSON template or request body)
            ctx_len = 500
            ctx = data[max(0, pos - 200):min(len(data), pos + ctx_len)]

            if enc_name == 'UTF16':
                try:
                    ctx_str = ctx.decode('utf-16-le', errors='replace')
                except:
                    ctx_str = ctx.decode('latin1', errors='replace')
            else:
                ctx_str = ctx.decode('ascii', errors='replace')

            fname = f"endpoint_{url.split('/')[-1].replace('.php','').replace('.txt','')}_{enc_name}_0x{pos:08x}.txt"
            (OUT / fname).write_text(ctx_str, encoding='utf-8')

            endpoint_payloads.append({
                "url": url,
                "encoding": enc_name,
                "offset": f"0x{pos:08x}",
                "context_file": fname,
            })

            print(f"   🔗 {url} ({enc_name}) @ 0x{pos:08x}")

REPORT["findings"]["endpoint_payloads"] = endpoint_payloads
print(f"\n   📊 Endpoint payloads found: {len(endpoint_payloads)}")

# ════════════════════════════════════════════════════════════════
#  10. BLACKHOUND DYLIB (Mach-O embedded in DLL)
# ════════════════════════════════════════════════════════════════
print("\n" + "─" * 70)
print("  [10] 🐕 BLACKHOUND DYLIB (Mach-O embedded)")
print("─" * 70)

blackhound_findings = []

# Search for BlackHound bundle identifier
bh_terms = ['com.panyolsoft.blackhound', 'blackhound', 'BlackHound', 'Blackhound']
for term in bh_terms:
    for enc_name, encoder in [('UTF16', lambda t: t.encode('utf-16-le')),
                               ('ASCII', lambda t: t.encode('ascii'))]:
        encoded = encoder(term)
        pos = data.find(encoded)
        if pos >= 0:
            ctx = data[max(0, pos - 100):min(len(data), pos + 300)]
            if enc_name == 'UTF16':
                ctx_str = ctx.decode('utf-16-le', errors='replace')
            else:
                ctx_str = ctx.decode('latin1', errors='replace')

            bh_fname = f"blackhound_{term.replace('.','_')}_{enc_name}_0x{pos:08x}.txt"
            (OUT / bh_fname).write_text(ctx_str, encoding='utf-8')

            blackhound_findings.append({
                "term": term,
                "encoding": enc_name,
                "offset": f"0x{pos:08x}",
                "context_file": bh_fname,
            })
            print(f"   🐕 {term} ({enc_name}) @ 0x{pos:08x}")

# Search for Mach-O magic (embedded iOS dylib)
macho_magics = [
    (0xFEEDFACE, 'MH_MAGIC 32-bit'),
    (0xFEEDFACF, 'MH_MAGIC_64 64-bit'),
    (0xCEFAEDFE, 'MH_MAGIC 32-bit LE'),
    (0xCFFAEDFE, 'MH_MAGIC_64 LE'),
    (0xCAFEBABE, 'FAT_MAGIC'),
]

for magic_val, magic_name in macho_magics:
    magic_bytes = struct.pack('>I', magic_val)
    pos = 0
    while True:
        pos = data.find(magic_bytes, pos)
        if pos < 0:
            break
        # Also check little-endian variant
        magic_le = struct.pack('<I', magic_val)
        if data[pos:pos + 4] == magic_le:
            actual_name = magic_name + ' (LE)'
        else:
            actual_name = magic_name

        print(f"   📦 Mach-O {actual_name} @ 0x{pos:08x}")
        blackhound_findings.append({
            "type": "Mach-O magic",
            "magic": actual_name,
            "offset": f"0x{pos:08x}",
        })
        pos += 1

# Check for extracted Mach-O binary
macho_bin = BASE / "04_EXTRACTED" / "macho_8534d3_DYLIB_ARM64_ALL.bin"
if macho_bin.exists():
    macho_data = macho_bin.read_bytes()
    print(f"   ✅ Extracted Mach-O binary exists: {macho_bin} ({len(macho_data):,} bytes)")
    # Search for FairPlay in the Mach-O
    fp_in_macho = macho_data.find(b'fairplay') + macho_data.find(b'FairPlay')
    if fp_in_macho >= 0:
        print(f"   🔑 FairPlay references found in extracted Mach-O!")
    blackhound_findings.append({
        "type": "extracted_macho",
        "path": str(macho_bin),
        "size": len(macho_data),
    })

REPORT["findings"]["blackhound"] = blackhound_findings
print(f"\n   📊 BlackHound findings: {len(blackhound_findings)}")

# ════════════════════════════════════════════════════════════════
#  SAVE CONSOLIDATED REPORT
# ════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("  💾 SAUVEGARDE DU RAPPORT CONSOLIDÉ")
print("=" * 70)

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
json_report = OUT / f"fairplay_extraction_report_{ts}.json"
with open(json_report, "w", encoding="utf-8") as f:
    json.dump(REPORT, f, indent=2, ensure_ascii=False, default=str)
print(f"   📄 JSON: {json_report}")

# Summary markdown
md_report = OUT / f"fairplay_extraction_summary_{ts}.md"
with open(md_report, "w", encoding="utf-8") as f:
    f.write(f"# FairPlay Key Extraction Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")
    f.write(f"## Source: `iremovalpro.dll` ({len(data):,} bytes)\n\n")

    f.write(f"### 📊 Summary\n\n")
    f.write(f"| Category | Count |\n|---|---|\n")
    f.write(f"| X.509 Certificates | {len(certs_found)} |\n")
    f.write(f"| RSA Public Keys | {len(rsa_keys_found)} |\n")
    f.write(f"| FairPlay Templates | {len(fairplay_templates)} |\n")
    f.write(f"| ECDSA Signatures | {len(ecdsa_blobs_found)} |\n")
    f.write(f"| PKCS#7/CMS OIDs | {sum(c['total_hits'] for c in cms_found)} |\n")
    f.write(f"| HMAC Material | {len(hmac_findings)} |\n")
    f.write(f"| Crypto Tables | {len(crypto_tables)} |\n")
    f.write(f"| Plist Templates | {len(plist_templates)} |\n")
    f.write(f"| Endpoint Payloads | {len(endpoint_payloads)} |\n")
    f.write(f"| BlackHound Refs | {len(blackhound_findings)} |\n\n")

    if certs_found:
        f.write(f"### 🏛️ Certificates\n\n")
        for c in certs_found:
            f.write(f"- **{c['marker'][:50]}** @ {c['offset']} ({c['length']} bytes) — `{c['file_der']}`\n")
        f.write("\n")

    if rsa_keys_found:
        f.write(f"### 🔐 RSA Keys\n\n")
        for k in rsa_keys_found:
            f.write(f"- RSA pubkey @ {k['offset']} ({k['length']} bytes) — `{k['file_der']}`\n")
        f.write("\n")

    f.write(f"### 📜 FairPlay DRM Flow\n\n")
    f.write(f"The extracted data confirms the following flow:\n\n")
    f.write(f"```mermaid\n")
    f.write(f"graph LR\n")
    f.write(f"    A[iPhone] --> B[lockdownd]\n")
    f.write(f"    B --> C[mobileactivationd]\n")
    f.write(f"    C --> D[drmHandshake]\n")
    f.write(f"    D --> E[albert.apple.com]\n")
    f.write(f"    E --> F[FairPlay Certificate]\n")
    f.write(f"    F --> G[Activation Ticket]\n")
    f.write(f"```\n\n")

    f.write(f"---\n*Report generated: {datetime.now().isoformat()}*\n")

print(f"   📝 MD: {md_report}")

print("\n" + "=" * 70)
print("  ✅ FAIRPLAY KEY EXTRACTION COMPLETE")
print("=" * 70)
print(f"\n  📂 All files in: {OUT}")
print(f"  📄 JSON report: {json_report}")
print(f"  📝 MD summary:  {md_report}")
