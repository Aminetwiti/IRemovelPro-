#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DEEP RE for .NET NativeAOT DLL.
- ReadyToRun header parse
- Frozen object heap detection
- Anti-debug: scan .text for xrefs to anti-debug APIs
- NativeAOT MethodMap
- String literals tied to functions
"""
import sys, struct, os, math, re, io
from collections import Counter, defaultdict
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll'
OUT_DIR = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\__analysis'

# ==== A) Parse PE properly with full sections ====
class PE:
    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as f:
            self.data = f.read()
        self.parse()
    def parse(self):
        d = self.data
        if d[:2] != b'MZ': raise ValueError('not MZ')
        pe_off = struct.unpack_from('<I', d, 0x3C)[0]
        if d[pe_off:pe_off+4] != b'PE\x00\x00': raise ValueError('not PE')
        (machine, nsects, _, _, _, optsize, _) = struct.unpack_from('<HHIIIHH', d, pe_off+4)
        self.sections = []
        sec_off = pe_off + 24 + optsize
        for i in range(nsects):
            s = d[sec_off+i*40 : sec_off+(i+1)*40]
            name = s[:8].rstrip(b'\0').decode('latin1','replace')
            vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', s, 8)
            self.sections.append({'name':name,'VA':vaddr,'VSize':vsize,'Raw':raddr,'RSize':rsize,'Chars':struct.unpack_from('<I',s,36)[0]})
        opt_off = pe_off + 24
        magic = struct.unpack_from('<H', d, opt_off)[0]
        self.pe32_plus = magic == 0x20b
        fmt = '<' + ('Q' if self.pe32_plus else 'I')
        self.ep_rva = struct.unpack_from(fmt, d, opt_off+16)[0]
        self.image_base = struct.unpack_from(fmt, d, opt_off+(24 if self.pe32_plus else 28))[0]
        ndirs_off = opt_off + (108 if self.pe32_plus else 92)
        self.ndirs = struct.unpack_from('<I', d, ndirs_off)[0]
        self.dd_off = ndirs_off + 4
    def rva2off(self, rva):
        for s in self.sections:
            if s['VA'] <= rva < s['VA']+max(s['VSize'], s['RSize']):
                return s['Raw'] + (rva - s['VA'])
        return None
    def va2off(self, va):
        return self.rva2off(va - self.image_base)

pe = PE(DLL)
print(f"[+] ImageBase: 0x{pe.image_base:x}, EP RVA: 0x{pe.ep_rva:x}, VA: 0x{pe.image_base+pe.ep_rva:x}")
print(f"[+] Sections:")
for s in pe.sections:
    print(f"    {s['name']:12} VA=0x{s['VA']:08x} VSize=0x{s['VSize']:08x} Raw=0x{s['Raw']:08x} RSize=0x{s['RSize']:08x}")

# ==== B) ReadyToRun Header detection ====
# In NativeAOT, the first bytes of .text are a READYTORUN_HEADER
# (or CORCOMPILE_HEADER for older versions)
# R2R header signature: 0x0052543D  ("RTR\0" little-endian) or specific
# The header starts with a uint32 Magic followed by MajorVersion
text_sec = [s for s in pe.sections if s['name'] == '.text'][0]
text_raw = pe.data[text_sec['Raw'] : text_sec['Raw']+min(text_sec['RSize'], 0x1000)]
# Try multiple known R2R/CORCOMPILE headers
candidates = {
    0x0052543D: 'R2R_MAGIC (RTR\\0)',  # Readytorun
    0x0700FACE: 'CORCOMPILE_HEADER',    # ngenned / ngen
    0x424A5342: 'BSJB (.NET metadata)', # BSJB = 0x424A5342
}
for off in range(0, min(64, len(text_raw)-4), 4):
    val = struct.unpack_from('<I', text_raw, off)[0]
    if val in candidates:
        print(f"[+] Magic at .text+0x{off:x}: {candidates[val]} = 0x{val:08x}")
# Check .managed section for metadata
for s in pe.sections:
    if s['name'] == '.managed':
        off = pe.rva2off(s['VA'])
        if off is None: continue
        head = pe.data[off:off+16]
        sig = struct.unpack_from('<I', head, 0)[0]
        print(f"[+] .managed starts with magic: 0x{sig:08x}  ({head[:4]!r})")
        if sig == 0x424A5342:
            print(f"    -> BSJB signature: this is .NET metadata header (StorageSignature)")

# ==== C) Anti-debug / anti-VM API string scan ====
ANTI_DEBUG_APIS = [
    b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent', b'NtQueryInformationProcess',
    b'NtQuerySystemInformation', b'NtSetInformationThread', b'OutputDebugString',
    b'OutputDebugStringA', b'OutputDebugStringW', b'ContinueDebugEvent',
    b'DebugActiveProcess', b'DebugActiveProcessStop', b'WaitForDebugEvent',
    b'DebugBreak', b'DebugBreakProcess', b'QueryPerformanceCounter', b'QueryPerformanceFrequency',
    b'GetTickCount', b'GetTickCount64', b'rdtsc', b'RDTSC',
    b'FindWindow', b'EnumWindows', b'GetForegroundWindow',
    b'CreateToolhelp32Snapshot', b'Process32First', b'Process32Next',
    b'Module32First', b'Module32Next', b'OpenProcess',
    b'RegOpenKey', b'RegQueryValueEx', b'RegCloseKey',
    b'CheckSumMappedFile', b'NtQueryVirtualMemory',
    b'WudfIsDebuggerPresent', b'IsProcessorFeaturePresent',
    b'HypervisorPresent', b'CPUID', b'GetSystemFirmwareTable',
    b'SetUnhandledExceptionFilter', b'UnhandledExceptionFilter',
    b'AddVectoredExceptionHandler', b'RemoveVectoredExceptionHandler',
]
ANTI_DEBUG_PATTERNS = [
    (b'\\x0f\\x31', 'RDTSC instruction (0F 31)'),
    (b'\\x0f\\xa2', 'CPUID instruction (0F A2)'),
    (b'security_cookie', 'Stack cookie /GS'),
    (b'__report_gsfailure', 'GS failure'),
    (b'__security_check', 'security_check'),
    (b'NtQueryVirtualMemory', 'NtQueryVirtualMemory'),
    (b'SetUnhandledExceptionFilter', 'VEH setup'),
]
print("\n[+] Anti-debug API string presence:")
for api in ANTI_DEBUG_APIS:
    pos = pe.data.find(api)
    if pos >= 0:
        sec = next((s['name'] for s in pe.sections if s['Raw'] <= pos < s['Raw']+s['RSize']), '?')
        print(f"    {api.decode('latin1', 'replace'):40} @ file:0x{pos:08x}  in {sec}")

# ==== D) x86 opcodes for anti-debug techniques ====
# Search for known opcode sequences
print("\n[+] Anti-debug opcodes scan (.text):")
text_full = pe.data[text_sec['Raw']:text_sec['Raw']+text_sec['RSize']]
opcodes = {
    b'\x0f\x31': 'RDTSC',
    b'\x0f\xa2': 'CPUID',
    b'\x64\xa1\x30\x00\x00\x00': 'mov eax, fs:[0x30] (PEB)',
    b'\x64\x8b\x05\x30\x00\x00\x00': 'mov eax, fs:[0x30]',
    b'\x64\x8b\x0d\x30\x00\x00\x00': 'mov ecx, fs:[0x30]',
    b'\x64\x8b\x15\x30\x00\x00\x00': 'mov edx, fs:[0x30]',
    b'\x64\x8b\x1d\x30\x00\x00\x00': 'mov ebx, fs:[0x30]',
    b'\x64\x8b\x35\x30\x00\x00\x00': 'mov esi, fs:[0x30]',
    b'\x64\x8b\x3d\x30\x00\x00\x00': 'mov edi, fs:[0x30]',
    b'\x64\x48\x8b\x05\x30\x00\x00\x00': 'mov rax, gs:[0x30] (PEB x64)',
    b'\x64\x48\x8b\x0d\x30\x00\x00\x00': 'mov rcx, gs:[0x30]',
    b'\x64\x48\x8b\x15\x30\x00\x00\x00': 'mov rdx, gs:[0x30]',
    b'\x64\x48\x8b\x1d\x30\x00\x00\x00': 'mov rbx, gs:[0x30]',
    b'\x64\x48\x8b\x35\x30\x00\x00\x00': 'mov rsi, gs:[0x30]',
    b'\x64\x48\x8b\x3d\x30\x00\x00\x00': 'mov rdi, gs:[0x30]',
    b'\x65\x48\x8b\x04\x25\x30\x00\x00\x00': 'mov rax, gs:[0x30] (alt encoding)',
    b'\x65\x48\x8b\x0c\x25\x30\x00\x00\x00': 'mov rcx, gs:[0x30]',
    b'\x65\x48\x8b\x14\x25\x30\x00\x00\x00': 'mov rdx, gs:[0x30]',
    b'\x65\x48\x8b\x1c\x25\x30\x00\x00\x00': 'mov rbx, gs:[0x30]',
    b'\x65\x48\x8b\x34\x25\x30\x00\x00\x00': 'mov rsi, gs:[0x30]',
    b'\x65\x48\x8b\x3c\x25\x30\x00\x00\x00': 'mov rdi, gs:[0x30]',
}
for op, name in opcodes.items():
    count = text_full.count(op)
    if count:
        first = text_full.find(op)
        sec_off = text_sec['Raw']
        first_va = pe.image_base + text_sec['VA'] + first
        print(f"    {name:50}  count={count:5}  first @ .text+0x{first:x} VA=0x{first_va:x}")

# ==== E) NativeAOT GC/MethodMap detection ====
# Look for frozen object heap patterns
print("\n[+] Frozen Object / Method map regions:")
# In NativeAOT, R2R header is followed by a method map
# Look for GUIDs / TypeRef
for marker, label in [(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'zero block'),
                       (b'BSJB', 'BSJB metadata sig'),
                       (b'_CorExeMain', '_CorExeMain'),
                       (b'mscoree.dll', 'mscoree')]:
    pos = pe.data.find(marker)
    if pos >= 0:
        sec = next((s['name'] for s in pe.sections if s['Raw'] <= pos < s['Raw']+s['RSize']), '?')
        print(f"    {label}: 0x{pos:08x}  in {sec}")

# ==== F) iOS protocol string scan ====
print("\n[+] iOS protocol / Lockdown / AFC / MobileBackup2 strings:")
ios_patterns = [
    b'com.apple.mobile.lockdown', b'com.apple.MobileDevice', b'com.apple.afc',
    b'com.apple.mobile.backup', b'com.apple.mobile.iTunes', b'com.apple.mobile.restoration',
    b'com.apple.mobile.installation_proxy', b'com.apple.mobile.MobileBackup2',
    b'com.apple.mobile.notification_proxy', b'com.apple.mobile.crashreporter',
    b'com.apple.mobile.diagnostics_relay', b'com.apple.mobile.house_arrest',
    b'com.apple.syslog', b'com.apple.mobile.file_relay', b'com.apple.mobile.screenshotr',
    b'com.apple.purplebuddy', b'com.apple.iosdiagnostics',
    b'com.apple.mobileactivationd', b'com.apple.mobileactivation',
    b'com.apple.springboard', b'com.apple.preferences',
    b'DeviceName', b'BoardID', b'ChipID', b'ProductType', b'SerialNumber',
    b'UniqueDeviceID', b'IMEI', b'IMSI', b'ICCID', b'FirmwareVersion',
    b'HardwarePlatform', b'ModelNumber', b'ActivationState',
    b'BrickState', b'BasebandVersion', b'TimeZone', b'RegionInfo',
    b'SIMStatus', b'PhoneNumber', b'MCC', b'MNC', b'IsJailbroken',
    b'PasswordProtected', b'ProductionMode', b'ActivationStateAcknowledged',
    b'RestorationOSVersion', b'RestoreVersion', b'RestoreBundle',
    b'AwaitDeviceLocked', b'DeviceLocked', b'Requested', b'Response',
    b'Request', b'Status', b'Error', b'ErrorCode', b'ErrorDescription',
]
for p in ios_patterns:
    pos = pe.data.find(p)
    if pos >= 0:
        sec = next((s['name'] for s in pe.sections if s['Raw'] <= pos < s['Raw']+s['RSize']), '?')
        print(f"    {p.decode():45}  @ 0x{pos:08x}  in {sec}")

# ==== G) iOS Activation protocol ====
print("\n[+] MobileActivation tokens (Apple internal protocol):")
for kw in [b'ActivationTicket', b'ActivationTicketRequest', b'WildcardTicket',
            b'AccountToken', b'AccountInfo', b'AccountLogin', b'AccountLogout',
            b'AccountSettings', b'AccountList', b'AccountState',
            b'AccountPhoneNumber', b'AccountEmail', b'AccountValidated',
            b'AccountCredential', b'AccountSession', b'AccountNonce',
            b'AccountAnonymousRequest', b'AccountInformation',
            b'Bypass', b'Hactivat', b'BypassTicket', b'SignRequest',
            b'FairPlayKey', b'FairPlayCertificate', b'FairPlayRequest',
            b'FMiPSign', b'FMiPRequest', b'FMiP']:
    pos = pe.data.find(kw)
    if pos >= 0:
        sec = next((s['name'] for s in pe.sections if s['Raw'] <= pos < s['Raw']+s['RSize']), '?')
        # Show context
        start = max(0, pos-30)
        end = min(len(pe.data), pos+60)
        ctx = pe.data[start:end].decode('latin1', 'replace').replace('\n', ' ')
        print(f"    {kw.decode():35}  @ 0x{pos:08x} in {sec}  ctx: ...{ctx}...")

# ==== H) NSException / Crash dump analysis ====
print("\n[+] Crash / dump / error paths:")
for kw in [b'crash', b'crashreporter', b'panic', b'segfault', b'SIGSEGV',
            b'SIGABRT', b'EXC_BAD', b'mini-dump', b'.ips', b'.crash',
            b'Writabl', b'fault', b'termin', b'fatal']:
    cnt = pe.data.lower().count(kw)
    if cnt > 5:
        print(f"    {kw.decode():30}  count={cnt}")
