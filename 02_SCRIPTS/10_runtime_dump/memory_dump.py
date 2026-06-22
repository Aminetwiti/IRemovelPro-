#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T1 - Dump mémoire runtime de iRemoval PRO Premium Edition + iremovalpro.dll
===========================================================================

⚠️ AVERTISSEMENT SÉCURITÉ
-------------------------
Ce script ATTACHE un débogueur à un processus iRemoval PRO en cours d'exécution.
Il DOIT être exécuté dans une machine virtuelle / sandbox isolée :

  1. **VM obligatoire** — Pas sur le poste hôte
  2. **Réseau coupé ou filtré** — iRemoval appelle s13.iremovalpro.com (Moscou ?)
  3. **Pas d'iPhone branché** — Le tool pourrait flasher un device
  4. **Windows Defender désactivé** — Sinon il va kill le process
  5. **Snapshot avant** — Pour restaurer après analyse

Trois modes disponibles :

  --mode procdump     : Utilise procdump.exe (Sysinternals) pour dumper tout le process
  --mode frida        : Utilise Frida pour hooks sélectifs + dump ciblé
  --mode custom       : Écrit un mini-dumper en C (DbgHelp) et l'injecte

Usage :
  py memory_dump.py --mode frida --spawn
  py memory_dump.py --mode procdump --pid 1234
  py memory_dump.py --mode custom --pid 1234 --out memory.dmp

Prérequis :
  - Python 3.8+
  - pip install frida
  - procdump.exe (optionnel) : https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
"""
import argparse
import os
import sys
import time
import subprocess
import json
from pathlib import Path
from datetime import datetime

# === CONFIGURATION ===
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DLL_PATH = PROJECT_ROOT / "IRemovalPro" / "iremovalpro.dll"
EXE_PATH = PROJECT_ROOT / "IRemovalPro" / "iRemoval PRO.exe"
OUT_DIR = PROJECT_ROOT / "03_OUTPUTS" / "runtime_dump"
OUT_DIR.mkdir(parents=True, exist_ok=True)


# === FRIDA SCRIPT : Dump mémoire ciblé ===
FRIDA_DUMP_SCRIPT = r"""
'use strict';

console.log('[*] iRemoval PRO memory dumper starting...');
console.log('[*] PID: ' + Process.id + ' arch=' + Process.arch);

var target_modules = ['iremovalpro.dll'];
var interesting_strings = [];
var crypto_candidates = [];
var foh_regions = [];   // Frozen Object Heap candidate regions
var heap_regions = [];   // GC heap candidate regions
var stack_regions = [];  // Stack candidate regions
var modules = [];

// === 1. Enumerate modules ===
Process.enumerateModules().forEach(function(m) {
    if (m.name.toLowerCase().includes('iremoval') ||
        m.name.toLowerCase().includes('restsharp') ||
        m.name.toLowerCase().includes('sshnet') ||
        m.name.toLowerCase().includes('bouncy')) {
        var mod = {
            name: m.name,
            base: '0x' + m.base.toString(16),
            size: m.size,
            path: m.path
        };
        modules.push(mod);
        console.log('[+] MODULE: ' + m.name + ' @ ' + mod.base + ' size=' + m.size);
    }
});

// === 2. Enumerate memory regions ===
var regions = Process.enumerateRanges('---');
console.log('[*] Total memory regions: ' + regions.length);

// === 3. Look for managed heap and interesting regions ===
var heap_candidates = regions.filter(function(r) {
    return r.protection.includes('r') && r.size > 65536;
});
console.log('[*] Readable regions > 64KB: ' + heap_candidates.length);

// === 4. Scan for RSA key patterns (DER ASN.1) ===
function scanForRSA(base, size) {
    try {
        var data = Memory.readByteArray(base, Math.min(size, 1024 * 1024));
        var bytes = new Uint8Array(data);
        var found = [];
        // ASN.1 SEQUENCE marker for RSA private keys: 30 82 XX XX 02 01 00 02 ...
        // Or RSA public key in PKCS#1: 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01
        for (var i = 0; i < bytes.length - 20; i++) {
            // DER sequence start + RSA OID
            if (bytes[i] === 0x30 && bytes[i+1] === 0x82 &&
                bytes[i+2] === 0x01 && bytes[i+3] === 0x22 &&
                bytes[i+4] === 0x30 && bytes[i+5] === 0x0d &&
                bytes[i+6] === 0x06 && bytes[i+7] === 0x09 &&
                bytes[i+8] === 0x2a && bytes[i+9] === 0x86 &&
                bytes[i+10] === 0x48 && bytes[i+11] === 0x86 &&
                bytes[i+12] === 0xf7 && bytes[i+13] === 0x0d) {
                found.push({offset: i, type: 'RSA-PUBKEY-PKCS1', addr: '0x' + (base.add(i)).toString(16)});
            }
            // RSA PRIVATE key DER: 30 82 04 ... or 30 82 02 ...
            if (bytes[i] === 0x30 && bytes[i+1] === 0x82 &&
                ((bytes[i+2] & 0xfc) === 0x04) &&
                bytes[i+6] === 0x02 && bytes[i+7] === 0x01 && bytes[i+8] === 0x00) {
                found.push({offset: i, type: 'RSA-PRIVKEY-PKCS1', addr: '0x' + (base.add(i)).toString(16)});
            }
        }
        return found;
    } catch(e) { return []; }
}

// === 5. Scan for AES key patterns (16/24/32 byte aligned) ===
function scanForAES(base, size) {
    // Heuristic: look for 16/24/32 byte sequences of high entropy
    // (true random-looking bytes) preceded by crypto operations
    var found = [];
    try {
        var data = Memory.readByteArray(base, Math.min(size, 1024 * 1024));
        var bytes = new Uint8Array(data);
        for (var i = 0; i < bytes.length - 32; i += 16) {
            // Compute simple entropy proxy
            var uniq = new Set();
            for (var j = 0; j < 32; j++) uniq.add(bytes[i+j]);
            if (uniq.size > 24) {
                // High entropy, candidate AES key
                var hex = '';
                for (var j = 0; j < 32; j++) hex += ('0' + bytes[i+j].toString(16)).slice(-2);
                found.push({offset: i, length: 32, hex: hex, addr: '0x' + (base.add(i)).toString(16)});
            }
        }
    } catch(e) {}
    return found;
}

// === 6. Scan for PEM headers (RSA private keys in clear text) ===
function scanForPEM(base, size) {
    var found = [];
    try {
        var data = Memory.readByteArray(base, Math.min(size, 1024 * 1024));
        var ascii = '';
        for (var i = 0; i < Math.min(data.byteLength, 1024*1024); i++) {
            var b = new Uint8Array(data)[i];
            ascii += (b >= 32 && b < 127) ? String.fromCharCode(b) : '\x00';
        }
        var patterns = ['-----BEGIN RSA PRIVATE KEY-----',
                       '-----BEGIN PRIVATE KEY-----',
                       '-----BEGIN ENCRYPTED PRIVATE KEY-----',
                       '-----BEGIN EC PRIVATE KEY-----',
                       '-----BEGIN CERTIFICATE-----',
                       'MII',  // DER header
                       'Proc-Type: 4,ENCRYPTED'];
        patterns.forEach(function(p) {
            var idx = 0;
            while ((idx = ascii.indexOf(p, idx)) >= 0) {
                found.push({pattern: p, offset: idx, addr: '0x' + (base.add(idx)).toString(16)});
                idx += p.length;
            }
        });
    } catch(e) {}
    return found;
}

// === 7. Hook BCryptEncrypt/Decrypt and capture keys in registers ===
var bcrypt = Process.findModuleByName('bcrypt.dll');
var crypto_log = [];

if (bcrypt) {
    ['BCryptEncrypt', 'BCryptDecrypt'].forEach(function(fname) {
        var exp = bcrypt.findExportByName(fname);
        if (exp) {
            Interceptor.attach(exp, {
                onEnter: function(args) {
                    // args[0] = key handle, args[1] = pbInput
                    // We can hook key handle access via NtQueryVirtualMemory or just dump
                    var cbInput = args[2].toInt32();
                    this.cbInput = cbInput;
                    if (cbInput > 0 && cbInput < 65536) {
                        try {
                            var hex = '';
                            var data = Memory.readByteArray(args[1], Math.min(cbInput, 256));
                            var bytes = new Uint8Array(data);
                            for (var i = 0; i < Math.min(bytes.length, 256); i++) {
                                hex += ('0' + bytes[i].toString(16)).slice(-2);
                            }
                            crypto_log.push({
                                op: fname,
                                dir: 'in',
                                size: cbInput,
                                hex: hex,
                                ts: Date.now()
                            });
                            console.log('[CRYPTO ' + fname + ' IN] size=' + cbInput + ' hex=' + hex.substring(0, 96));
                        } catch(e) {}
                    }
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0) {
                        // Read output buffer (args[6] = pbOutput, args[7] = cbOutput)
                        try {
                            var outLen = args[7].toInt32();
                            if (outLen > 0 && outLen < 65536) {
                                var hex = '';
                                var data = Memory.readByteArray(args[6], Math.min(outLen, 256));
                                var bytes = new Uint8Array(data);
                                for (var i = 0; i < Math.min(bytes.length, 256); i++) {
                                    hex += ('0' + bytes[i].toString(16)).slice(-2);
                                }
                                crypto_log.push({
                                    op: fname,
                                    dir: 'out',
                                    size: outLen,
                                    hex: hex,
                                    ts: Date.now()
                                });
                                console.log('[CRYPTO ' + fname + ' OUT] size=' + outLen + ' hex=' + hex.substring(0, 96));
                            }
                        } catch(e) {}
                    }
                }
            });
        }
    });
}

// === 8. Periodic scan for crypto material ===
var scan_count = 0;
var scan_interval = setInterval(function() {
    scan_count++;
    if (scan_count > 60) {  // Stop after 60 scans (~10 min)
        clearInterval(scan_interval);
        finish();
        return;
    }
    // Scan all readable regions
    var scan_regions = Process.enumerateRanges('r---');
    var found_count = 0;
    scan_regions.forEach(function(r) {
        if (r.size > 4096 && r.size < 1024*1024*64) {
            var rsa = scanForRSA(r.base, r.size);
            var pem = scanForPEM(r.base, r.size);
            if (rsa.length > 0 || pem.length > 0) {
                rsa.forEach(function(f) {
                    crypto_candidates.push({type: f.type, addr: f.addr, offset: f.offset, region: r.base + '+' + (r.base - r.base)});
                });
                pem.forEach(function(f) {
                    crypto_candidates.push({type: 'PEM:' + f.pattern, addr: f.addr, offset: f.offset});
                });
                found_count++;
            }
        }
    });
    if (found_count > 0) {
        console.log('[*] Scan #' + scan_count + ' found ' + found_count + ' regions with crypto material');
    }
}, 10000);

function finish() {
    console.log('');
    console.log('[*] === DUMP COMPLETE ===');
    console.log('[*] Modules: ' + modules.length);
    console.log('[*] Crypto operations captured: ' + crypto_log.length);
    console.log('[*] Crypto candidates: ' + crypto_candidates.length);

    // Send final report via Frida messaging
    var report = {
        modules: modules,
        crypto_log: crypto_log.slice(0, 500),  // cap
        crypto_candidates: crypto_candidates,
        timestamp: Date.now()
    };
    send(JSON.stringify({type: 'dump_complete', payload: report}));
}

// Send metadata immediately
send(JSON.stringify({type: 'metadata', payload: {modules: modules, pid: Process.id}}));

console.log('[*] Hooks installed. Will scan for crypto material every 10s.');
"""


def run_frida_dump():
    """Mode Frida : Attache au process et hook les fonctions crypto."""
    import frida

    print(f'[*] Mode: Frida memory dump')
    print(f'[*] Output: {OUT_DIR}')

    # Trouver le PID
    target_pid = None
    for proc in frida.get_local_device().enumerate_processes():
        if 'iRemoval' in proc.name or 'iremoval' in proc.name.lower():
            target_pid = proc.pid
            print(f'[*] Found {proc.name} PID={proc.pid}')
            break

    if not target_pid:
        print('[!] No iRemoval PRO process found.')
        print('[!] Start iRemoval PRO.exe first, then run this script.')
        return

    session = frida.get_local_device().attach(target_pid)
    print(f'[*] Attached to PID {target_pid}')

    script = session.create_script(FRIDA_DUMP_SCRIPT)
    messages = []

    def on_message(message, data):
        if message['type'] == 'send':
            payload = json.loads(message['payload'])
            messages.append(payload)
            print(f'[MSG] type={payload.get("type")} keys={list(payload.get("payload", {}).keys())}')
        elif message['type'] == 'error':
            print(f'[ERROR] {message.get("stack", "")}', file=sys.stderr)

    script.on('message', on_message)
    script.load()

    print('[*] Running for 10 minutes (Ctrl+C to stop earlier)...')
    try:
        time.sleep(600)
    except KeyboardInterrupt:
        print('\n[!] Stopped by user')

    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_file = OUT_DIR / f'frida_dump_{timestamp}.json'
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(messages, f, indent=2, ensure_ascii=False)
    print(f'[*] Saved {len(messages)} events to {out_file}')


def run_procdump(pid):
    """Mode procdump : Utilise Sysinternals procdump pour dumper le process."""
    procdump = r'C:\Tools\procdump.exe'
    if not os.path.exists(procdump):
        print(f'[!] procdump not found at {procdump}')
        print('[!] Download from https://learn.microsoft.com/en-us/sysinternals/downloads/procdump')
        return

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_file = OUT_DIR / f'iremo_procdump_{timestamp}.dmp'
    cmd = [procdump, '-ma', str(pid), str(out_file)]
    print(f'[*] Running: {" ".join(cmd)}')
    try:
        subprocess.run(cmd, check=True)
        print(f'[*] Dump saved to {out_file}')
    except subprocess.CalledProcessError as e:
        print(f'[!] procdump failed: {e}')


def write_custom_dumper(pid, out_path):
    """Écrit un mini-dumper C# .NET utilisant DbgHelp."""
    cs_code = f"""
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

class MiniDumper {{
    [DllImport("dbghelp.dll", EntryPoint="MiniDumpWriteDump", CallingConvention=CallingConvention.StdCall)]
    static extern bool MiniDumpWriteDump(
        IntPtr hProcess, uint processId, IntPtr hFile, uint dumpType,
        IntPtr exceptionParam, IntPtr userStreamParam, IntPtr callbackParam);

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    const uint MiniDumpWithFullMemory = 0x00000002;
    const uint MiniDumpWithDataSegs = 0x00000001;

    static void Main(string[] args) {{
        uint pid = {pid};
        string outFile = @"{out_path}";
        Console.WriteLine($"[*] Dumping PID {{pid}} to {{outFile}}");
        IntPtr hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProc == IntPtr.Zero) {{
            Console.Error.WriteLine($"[!] OpenProcess failed: {{Marshal.GetLastWin32Error()}}");
            return;
        }}
        using (var fs = new FileStream(outFile, FileMode.Create, FileAccess.Write)) {{
            bool ok = MiniDumpWriteDump(hProc, pid, fs.SafeFileHandle.DangerousGetHandle(),
                MiniDumpWithFullMemory | MiniDumpWithDataSegs,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (!ok) {{
                Console.Error.WriteLine($"[!] MiniDumpWriteDump failed: {{Marshal.GetLastWin32Error()}}");
            }} else {{
                Console.WriteLine($"[+] Dump written: {{new FileInfo(outFile).Length:N0}} bytes");
            }}
        }}
        CloseHandle(hProc);
    }}
}}
"""
    cs_file = OUT_DIR / 'MiniDumper.cs'
    cs_file.write_text(cs_code)
    print(f'[*] Wrote C# dumper: {cs_file}')
    print('[*] Compile:')
    print(f'    csc /out:MiniDumper.exe {cs_file}')
    print(f'    MiniDumper.exe')


def main():
    parser = argparse.ArgumentParser(description='Dump memory of iRemoval PRO + iremovalpro.dll')
    parser.add_argument('--mode', choices=['frida', 'procdump', 'custom'], default='frida',
                        help='Dumping method')
    parser.add_argument('--pid', type=int, help='Process ID to dump')
    parser.add_argument('--spawn', action='store_true', help='Spawn iRemoval PRO.exe (requires manual run)')
    args = parser.parse_args()

    print('=' * 70)
    print('iRemoval PRO Memory Dumper - Phase 5')
    print('=' * 70)
    print()
    print('⚠️  AVERTISSEMENT')
    print('  - Exécute UNIQUEMENT dans une VM isolée')
    print('  - Coupe le réseau OU filtre les domaines iRemoval')
    print('  - NE BRANCHE PAS d\'iPhone')
    print('  - Désactive Windows Defender')
    print('  - Fais un snapshot avant')
    print()

    if args.mode == 'frida':
        run_frida_dump()
    elif args.mode == 'procdump':
        if not args.pid:
            print('[!] --pid required for procdump mode')
            return
        run_procdump(args.pid)
    elif args.mode == 'custom':
        if not args.pid:
            print('[!] --pid required for custom mode')
            return
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        out_path = str(OUT_DIR / f'iremo_custom_{timestamp}.dmp')
        write_custom_dumper(args.pid, out_path)


if __name__ == '__main__':
    main()