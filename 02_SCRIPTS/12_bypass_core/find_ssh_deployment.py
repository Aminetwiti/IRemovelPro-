#!/usr/bin/env python3
"""Map the SSH/SCP deployment to iOS device."""
import re
from pathlib import Path

WORK = Path(r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2")
DLL = WORK / "IRemovalPro" / "iremovalpro.dll"
data = DLL.read_bytes()

def find_all_around(keyword, ctx=300):
    """Find all UTF-16LE occurrences of keyword with surrounding context."""
    kw_u = keyword.encode('utf-16-le')
    results = []
    idx = 0
    while True:
        idx = data.find(kw_u, idx)
        if idx == -1:
            break
        s = max(0, idx - ctx)
        e = min(len(data), idx + ctx)
        chunk = data[s:e]
        # Extract all printable UTF-16LE strings
        strings = []
        for m in re.finditer(rb'(?:[\x20-\x7e]\x00){2,}', chunk):
            st = m.group().decode('utf-16-le', errors='ignore')
            if st and len(st) > 1:
                strings.append((m.start() + s, st))
        results.append((idx, strings))
        idx += 1
    return results

# 1. Find all "scp" patterns
print("="*80)
print("SCP commands in detail")
print("="*80)
res = find_all_around('scp -f', 500)
for idx, strings in res[:1]:
    print(f"  At 0x{idx:08x}, surrounding strings:")
    for off, s in strings:
        if 'scp' in s or 'ssh' in s or 'mobile' in s or '.dylib' in s or 'app' in s:
            print(f"    0x{off:08x}: {s[:200]}")

# 2. Find SSH private key / identity file
print("\n" + "="*80)
print("SSH identity/keys")
print("="*80)
for kw in ['id_rsa', 'identity', 'openssh', 'openssh_key', 'private_key',
           'sshkey', 'key_file', 'hostkey', 'serverkey', '.ppk', '.pem',
           'rsa-key', 'openssh.com', 'ecdsa-sha2', 'ssh-rsa',
           'AAAAB3NzaC1', 'openssh.key', 'openssh_key', 'openssh-format']:
    res = find_all_around(kw, 200)
    if res:
        for idx, strings in res[:1]:
            for off, s in strings:
                if len(s) > 2 and (kw in s or '.ssh' in s):
                    print(f"  [{kw}] 0x{off:x}: {s[:200]}")

# 3. Find iOS app installation paths
print("\n" + "="*80)
print("iOS app installation paths")
print("="*80)
for kw in ['.app/', 'Bypass.app', 'iRemovalRa1n', '/Applications/',
           '/var/containers/Bundle/Application', 'install_app',
           'installApplication', 'uninstallApplication',
           '/var/mobile/Containers', 'mobile/Library/Caches',
           'com.apple.mobile.installd', 'installd', 'AFC', 'afc://',
           '/private/var/root', '/var/root', '/var/mobile',
           '/private/var/mobile', 'MobileSubstrate', 'blackhound.dylib',
           'BypassTweak', 'iremo.dylib', 'iremovaldylib', 'tweak.dylib']:
    res = find_all_around(kw, 200)
    if res:
        cnt = len(res)
        print(f"  [{kw}]: {cnt} occurrences")
        for idx, strings in res[:1]:
            for off, s in strings:
                if len(s) > 2 and (kw in s or 'Bundle' in s):
                    print(f"    0x{off:x}: {s[:200]}")

# 4. Find activation record path on iOS
print("\n" + "="*80)
print("Activation record path on iOS")
print("="*80)
for kw in ['/private/var/mobileactivationd', '/Library/Logs/mobileactivationd',
           '/var/mobile/Library/Logs', '/private/var/root',
           '/private/var/mobile/Library/com.apple.mobileactivationd',
           'Library/Preferences', 'com.apple.mobileactivationd.plist',
           'activation_records', 'activation_record',
           'iRemovalRecord.bin', 'ticket.bin', 'ticket.plist',
           'data.plist', 'payload.bin', 'activation.plist']:
    res = find_all_around(kw, 200)
    if res:
        for idx, strings in res[:1]:
            for off, s in strings:
                if len(s) > 2:
                    print(f"  [{kw}] 0x{off:x}: {s[:200]}")

# 5. Find libimobiledevice / usbmuxd operations
print("\n="*80)
print("libimobiledevice operations")
print("="*80)
for kw in ['usbmuxd', 'muxer', 'lockdownd', 'lockdown',
           'iTunesMobileDevice', 'AppleMobileDevice',
           'AFCConnectionOpen', 'AFCFileRefOpen', 'AFCDirectoryOpen',
           'AFCDirectoryRead', 'AFCFileRefWrite', 'AFCFileRefClose',
           'usbmuxd_read', 'usbmuxd_write', 'usbmuxd_listen',
           'mux_connect', 'mux_listen', 'mux_open',
           'idevice_connect', 'idevice_disconnect',
           'lockdown_start_service', 'lockdown_start_ssl',
           'lockdown_get_value', 'lockdown_set_value',
           'lockdown_pair', 'lockdown_unpair',
           'lockdown_activate', 'lockdown_deactivate',
           'lockdown_request_pair',
           'afc_upload_file', 'afc_download_file', 'afc_get_device_info']:
    res = find_all_around(kw, 200)
    if res:
        for idx, strings in res[:1]:
            for off, s in strings:
                if len(s) > 2:
                    print(f"  [{kw}] 0x{off:x}: {s[:200]}")

# 6. Find activation error codes
print("\n="*80)
print("Activation error codes")
print("="*80)
for kw in ['-1', 'kAMDSuccess', 'kAMDInvalidActivationRecord',
           'kAMDNoIMSI', 'kAMDUnsupported', 'kAMDNoActivationData',
           'ActivationError', 'kCFError', 'kMobileActivationError',
           'iActError', 'iRemovalError', 'kError', 'ERR_']:
    res = find_all_around(kw, 100)
    if res:
        for idx, strings in res[:1]:
            for off, s in strings:
                if len(s) > 2 and ('Error' in s or 'Failed' in s or 'k' in s[:1]):
                    print(f"  [{kw}] 0x{off:x}: {s[:200]}")