#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deep RE pass 5: function call graph reconstruction, look for wrappers around server endpoints."""
import sys, struct, re, io
from collections import Counter, defaultdict
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll'
with open(DLL, 'rb') as f:
    data = f.read()

# Sections
PE_SECTIONS = {
    '.text': (0x400, 0xc8c00, 0x1000),
    '.managed': (0xc9000, 0x676000, 0xca000),
    'hydrated': (None, None, 0x740000),
    '.rdata': (0x73f000, 0x5e5e00, 0x9f3000),
    '.data': (0xd24e00, 0xb200, 0xfd9000),
    '.pdata': (0xd30000, 0x83200, 0x100f000),
    '.k^q': (0xdb3200, 0x7fb400, 0x1093000),
    '.IE_': (0x15ae600, 0x200, 0x188f000),
    '.^%L': (0x15ae800, 0x820400, 0x1890000),
    '.rsrc': (0x1dcec00, 0x400, 0x20b1000),
    '.reloc': (0x1dcf000, 0x2000, 0x20b2000),
}

# ==== A) Find all functions that reference server URLs ====
# Strategy: find the strings in .rdata, then look for LEA instructions that reference them
print("="*80)
print("[1] FUNCTIONS REFERENCING SERVER ENDPOINTS")
print("="*80)
server_urls = [
    b'https://s13.iremovalpro.com/iremovalActivation/ars2.php',
    b'https://s13.iremovalpro.com/iremovalActivation/auth3.php',
    b'https://s13.iremovalpro.com/iremovalActivation/checkm8.php',
    b'https://s13.iremovalpro.com/iremovalActivation/iact8.php',
    b'https://s13.iremovalpro.com/iremovalActivation/mf5.php',
    b'https://s13.iremovalpro.com/iremovalActivation/mf6.php',
    b'https://s13.iremovalpro.com/iremovalActivation/mf7.php',
    b'https://s13.iremovalpro.com/pub.php',
    b'https://s13.iremovalpro.com/version33.txt',
    b'https://iremovalpro.com/Payax0.php',
]
rdata_raw, rdata_size, _ = PE_SECTIONS['.rdata']
rdata_va = 0x180000000 + 0x9f3000
for url in server_urls:
    pos = data.find(url)
    if pos < 0: continue
    rva = 0x9f3000 + (pos - rdata_raw)
    va = 0x180000000 + rva
    print(f"    URL: {url.decode()[:60]}")
    print(f"        @ 0x{pos:x} (RVA 0x{rva:x}, VA 0x{va:x})")
    # Find references in .text (lea rax, [rip + disp] where disp points to URL)
    text_raw, text_size, text_va = PE_SECTIONS['.text']
    text = data[text_raw:text_raw+text_size]
    # 48 8d 05 XX XX XX XX  => lea rax, [rip + disp32]
    refs = []
    i = 0
    while i < text_size - 7:
        if text[i] == 0x48 and text[i+1] == 0x8d and text[i+2] == 0x05:
            disp = struct.unpack_from('<i', text, i+3)[0]
            target_va = 0x180000000 + text_va + i + 7 + disp
            # Check if target is the URL VA
            if target_va == va:
                refs.append(i)
        i += 1
    if refs:
        for ref in refs:
            # Find function start (look backwards for prologue)
            start = ref
            for back in range(min(200, ref), 0, -1):
                # Check for ret at start - 5
                if text[ref-back] == 0xC3 or text[ref-back:ref-back+1] == b'\xC3':
                    start = ref - back + 1
                    break
            print(f"        ref @ .text+0x{ref:x} (function starts ~0x{start:x}, VA 0x{0x180000000+text_va+start:x})")
    else:
        print(f"        (no direct LEA ref found in .text)")

# ==== B) Look for string-encoding/decoding helpers ====
print("\n" + "="*80)
print("[2] ENCODING / DECODING (Base64, Hex, AES)")
print("="*80)
for kw in [b'FromBase64String', b'ToBase64String', b'FromBase64CharArray', b'ToBase64CharArray',
            b'FromHexString', b'ToHexString', b'Convert.ToBase64String', b'Convert.FromBase64String',
            b'AesManaged', b'AesCng', b'AesCryptoServiceProvider', b'AesGcm', b'AesCcm',
            b'DesCng', b'DesCryptoServiceProvider', b'TripleDES',
            b'HMACSHA256', b'HMACSHA1', b'HMACSHA384', b'HMACSHA512',
            b'PBKDF2', b'Rfc2898DeriveBytes', b'PasswordDeriveBytes',
            b'RSACryptoServiceProvider', b'RSACng', b'DSACryptoServiceProvider',
            b'ECDsa', b'ECDiffieHellman', b'ECParameters', b'ECCurve',
            b'XMLDsig', b'SignedXml', b'EncryptedXml', b'XmlEncryption',
            b'SignatureDescription', b'KeyInfo', b'KeyInfoX509Data',
            b'X509Chain', b'X509ChainStatus', b'X509ChainPolicy',
            b'X509FindType', b'X509FindType.FindByThumbprint', b'X509FindType.FindBySubjectName',
            b'X509Store', b'X509Certificate2', b'X509Certificate2Collection',
            b'Aes.Create', b'Aes.CreateDecryptor', b'Aes.CreateEncryptor',
            b'CryptoStream', b'CryptoStreamMode', b'ICryptoTransform',
            b'RijndaelManaged', b'Rijndael', b'SymmetricAlgorithm',
            b'PKCS7', b'PKCS12', b'CMS', b'PKCS7SignedData', b'PKCS7EnvelopedData',
            b'CNG', b'BCryptOpenAlgorithmProvider', b'BCryptCreateHash',
            b'BCryptHashData', b'BCryptFinishHash', b'BCryptDestroyHash',
            b'BCryptGenerateSymmetricKey', b'BCryptEncrypt', b'BCryptDecrypt',
            b'BCryptSetProperty', b'BCryptGetProperty', b'BCryptCloseAlgorithmProvider',
            b'BCryptGenerateKeyPair', b'BCryptFinalizeKeyPair', b'BCryptImportKeyPair',
            b'NCryptCreatePersistedKey', b'NCryptOpenKey', b'NCryptOpenStorageProvider',
            b'NCryptEncrypt', b'NCryptDecrypt', b'NCryptSignHash', b'NCryptVerifySignature',
            b'NCryptDeleteKey', b'NCryptFreeObject', b'NCryptFreeBuffer',
            b'CertOpenStore', b'CertOpenSystemStore', b'CertFindCertificateInStore',
            b'CertVerifyCertificateChainPolicy', b'CertGetCertificateChain',
            b'CertFreeCertificateContext', b'CertFreeCertificateChain',
            b'CertEnumCertificatesInStore', b'CertAddCertificateContextToStore',
            b'CertGetIntendedKeyUsage', b'CryptStringToBinary', b'CryptBinaryToString',
            b'PFXImportCertStore', b'PFXVerifyPassword', b'PFXExportCertStore',
            b'PFXImportCertStore', b'CryptAcquireContext', b'CryptReleaseContext',
            b'CryptGenRandom', b'CryptCreateHash', b'CryptHashData',
            b'CryptSignHash', b'CryptVerifySignature', b'CryptDestroyHash',
            b'CryptImportPublicKeyInfo', b'CryptFindOIDInfo', b'CryptDecodeObject']:
    pos = data.find(kw)
    if pos >= 0:
        sec = next((s for s, (raw, sz, _) in PE_SECTIONS.items() if raw and raw <= pos < raw+sz), '?')
        print(f"    {kw.decode('latin1','replace'):50}  @ 0x{pos:08x}  in {sec}")
