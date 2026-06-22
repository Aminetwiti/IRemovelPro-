#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deep RE pass 2: HTTP/JSON structure, encryption, certificates, payload blobs."""
import sys, struct, os, re, io
from collections import Counter
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll'
with open(DLL, 'rb') as f:
    data = f.read()

# ==== A) HTTP / JSON / RestSharp signatures ====
print("="*80)
print("[1] HTTP REQUEST STRUCTURE & REST ENDPOINTS")
print("="*80)
# JSON keys
json_keys = [b'UDID', b'IMEI', b'Serial', b'ECID', b'Model', b'ProductType', b'Version',
             b'Build', b'AppleID', b'orderId', b'orderID', b'order', b'invoice',
             b'payment', b'amount', b'currency', b'status', b'error', b'success',
             b'token', b'Token', b'apiKey', b'api_key', b'key', b'secret',
             b'session', b'Session', b'userId', b'user', b'email', b'password',
             b'auth', b'Authorization', b'Bearer', b'Basic',
             b'X-API-Key', b'X-Auth', b'X-Sig', b'Signature', b'x-sig', b'sig',
             b'Timestamp', b'timestamp', b'nonce', b'Nonce',
             b'hwid', b'HWID', b'machineId', b'MachineId', b'hash', b'Hash',
             b'checksum', b'Checksum', b'fingerprint', b'Fingerprint',
             b'POST', b'GET', b'PUT', b'DELETE', b'PATCH',
             b'Content-Type', b'application/json', b'application/x-www-form-urlencoded',
             b'multipart/form-data', b'text/xml', b'text/plain',
             b'Accept', b'Accept-Encoding', b'gzip', b'deflate', b'User-Agent',
             b'Mozilla', b'curl', b'Python', b'OK', b'fail', b'pending', b'processing',
             b'checkm8', b'checkm8Status', b'checkm8Response', b'activation', b'Activation',
             b'Bypass', b'bypass', b'BY', b'orderType', b'orderStatus', b'ticket',
             b'Ticket', b'activationTicket', b'ActivationTicket', b'wildcardTicket',
             b'fairPlay', b'fairplay', b'FairPlay', b'account', b'Account',
             b'result', b'response', b'request', b'data', b'meta', b'Meta',
             b'reason', b'code', b'message', b'Message', b'description', b'Description']
for k in json_keys:
    pos = data.find(k + b'"')
    if pos < 0: pos = data.find(b'"' + k + b'"')
    if pos < 0: pos = data.find(b'"' + k + b':')
    if pos >= 0:
        # Look for context (URL nearby?)
        sec = next((s['name'] for s in [{'name':n,'Raw':0} for n in ['?'] for s in []]), '?')
        # Better: just count and find positions
        c = Counter()
        p = 0
        while True:
            p = data.find(k, p+1)
            if p < 0: break
            c[p] = data[p:p+min(80,len(data)-p)]
        sample = list(c.items())[:3]
        print(f"    {k.decode():30}  hits={sum(1 for _ in c):3}  first3: {[(hex(p),repr(s)[:50]) for p,s in sample]}")

# ==== B) AES / encryption patterns ====
print("\n" + "="*80)
print("[2] CRYPTO CONSTANTS & ALGORITHMS")
print("="*80)
# AES S-box
AES_SBOX = bytes.fromhex('637c777bf26b6fc53001672bfed7ab76'
                          'ca82c97dfa5947f0add4a2af9ca472c0'
                          'b7fd9326363ff7cc34a5e5f171d83115'
                          '04c723c31896059a071280e2eb27b275'
                          '09832c1a1b6e5aa0523bd6b329e32f84'
                          '53d100ed20fcb15b6acbbe394a4c58cf'
                          'd0efaafb434d3385459021f5a0f8d80c'
                          '4cd0b0d8a36dc6b2d3c0e1d2e3f4f5f6'
                          'f7f8f9fafbfcfdfeff')
pos = data.find(AES_SBOX)
print(f"    AES S-box (256 bytes): {'FOUND' if pos>=0 else 'NOT FOUND'}  @ 0x{pos:x}" if pos>=0 else "    AES S-box NOT FOUND")

# SHA constants
SHA1_INIT = bytes.fromhex('0123456789abcdeffedcba9876543210f0e1d2c3')
SHA256_K = bytes.fromhex('428a2f9871374491b5c0fbcfe9b5dba5' '3956c25b59f111f1923f82a4ab1c5ed5'
                          'd807aa9812835b012885dae2b19f0e9235916beb1c5e5d4d0a4d2c6db3a0c19e'
                          '80a47f7eb6e0c1ce4f9b5d3a4c2d0e0f0a1b2c3d4e5f60718293a4b5c6d7e8f9')
SHA1_pos = data.find(SHA1_INIT)
SHA256_pos = data.find(SHA256_K[:4])  # 0x428a2f98
print(f"    SHA-1 init constants: {'FOUND' if SHA1_pos>=0 else 'NOT FOUND'}")
print(f"    SHA-256 K[0]=0x428a2f98: {'FOUND' if SHA256_pos>=0 else 'NOT FOUND'} @ 0x{SHA256_pos:x}" if SHA256_pos>=0 else "")

# Base64 alphabet
B64 = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
pos = data.find(B64)
print(f"    Base64 alphabet: {'FOUND' if pos>=0 else 'NOT FOUND'} @ 0x{pos:x}" if pos>=0 else "")

# ==== C) Frozen / Encrypted blobs ====
print("\n" + "="*80)
print("[3] ENCRYPTED BLOB / FROZEN DATA REGIONS")
print("="*80)
# Scan for high-entropy regions of size > 4 KB
import math
def entropy(b):
    if not b: return 0
    n=len(b); c=Counter(b)
    return -sum((x/n)*math.log2(x/n) for x in c.values())
# Just summarize per-section
PE_SECTIONS = {
    '.text': (0x400, 0xc8c00),
    '.managed': (0xc9000, 0x676000),
    'hydrated': (None, None),  # not on disk
    '.rdata': (0x73f000, 0x5e5e00),
    '.data': (0xd24e00, 0xb200),
    '.pdata': (0xd30000, 0x83200),
    '.k^q': (0xdb3200, 0x7fb400),
    '.IE_': (0x15ae600, 0x200),
    '.^%L': (0x15ae800, 0x820400),
    '.rsrc': (0x1dcec00, 0x400),
    '.reloc': (0x1dcf000, 0x2000),
}
for name, (raw, size) in PE_SECTIONS.items():
    if raw is None: continue
    seg = data[raw:raw+size]
    e = entropy(seg)
    print(f"    {name:12}  size=0x{size:08x} ({size/1024:.1f} KB)  entropy={e:.4f}")

# ==== D) Strings near anti-debug APIs ====
print("\n" + "="*80)
print("[4] ANTI-DEBUG SURROUNDINGS")
print("="*80)
for api in [b'IsDebuggerPresent', b'NtQueryInformationProcess', b'RDTSC', b'QueryPerformanceCounter']:
    for kw in [api, b'CPUID', b'fs:[30h]', b'gs:[30h]']:
        idx = 0
        cnt = 0
        while cnt < 5:
            idx = data.find(kw, idx+1)
            if idx < 0: break
            ctx = data[max(0,idx-40):idx+len(kw)+40]
            # Filter to readable
            txt = ''.join(chr(b) if 32<=b<127 else '.' for b in ctx)
            print(f"    {kw.decode('latin1','replace'):30}  @ 0x{idx:08x}  ctx: {txt}")
            cnt += 1

# ==== E) Network/HttpClient / TLS / Schannel patterns ====
print("\n" + "="*80)
print("[5] NETWORK / TLS / SCHANNEL")
print("="*80)
for kw in [b'HttpClient', b'HttpRequestMessage', b'HttpResponseMessage', b'HttpClientHandler',
           b'SslStream', b'SslProtocols', b'Tls12', b'Tls13', b'RemoteCertificateValidationCallback',
           b'ServerCertificateValidationCallback', b'Socket', b'IPAddress', b'IPEndPoint',
           b'SecurityProtocolType', b'AuthenticationLevel', b'AllowSelfSignedCert',
           b'WebException', b'HttpRequestException', b'TaskCanceledException',
           b'WebHeaderCollection', b'HttpResponseHeaders', b'HttpRequestHeaders',
           b'StreamContent', b'ByteArrayContent', b'StringContent', b'FormUrlEncodedContent',
           b'MultipartFormDataContent', b'MediaTypeHeaderValue', b'HttpContent',
           b'SetUpRemoteCertificateValidationCallback', b'EstablishSslConnectionAsync',
           b'GetClientCertificate', b'BypassSslValidation', b'TrustServerCertificate']:
    pos = data.find(kw)
    if pos >= 0:
        print(f"    {kw.decode('latin1','replace'):50}  @ 0x{pos:08x}")

# ==== F) Activation ticket signatures ====
print("\n" + "="*80)
print("[6] ACTIVATION TICKET / CRYPTO BLOB MARKERS")
print("="*80)
for kw in [b'FairPlayKey', b'FairPlayCert', b'BES', b'BBI', b'BLS',
           b'Ticket', b'Activation', b'Hactivate', b'hacktiv', b'SignRequest',
           b'nonce', b'Nonce', b'IMG4', b'IM4M', b'IM4P', b'IBEC', b'IBoot',
           b'iBoot', b'LLB', b'iBSS', b'kernelcache', b'BootChain',
           b'rooted', b'jailbreak', b'JB', b'BYPASS',
           b'Activation ticket', b'wildcard', b'Wildcard', b'TicketRequest',
           b'TicketResponse', b'BESRequest', b'BESResponse', b'BBIRequest',
           b'BLSRequest', b'NORData', b'NANDData', b'Baseband', b'BasebandCert',
           b'BasebandTicket']:
    pos = data.find(kw)
    if pos >= 0:
        ctx = data[max(0,pos-20):pos+80]
        txt = ''.join(chr(b) if 32<=b<127 else '.' for b in ctx)
        print(f"    {kw.decode('latin1','replace'):30}  @ 0x{pos:08x}  ctx: {txt}")
