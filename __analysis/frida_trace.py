#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
frida_trace.py - Dynamic tracing of iremovalpro.dll

Uses the Frida Python API to:
1. Spawn or attach to iRemoval PRO.exe
2. Inject a JavaScript tracer that hooks:
   - HttpClient/HttpRequestMessage (RestSharp HTTP calls)
   - BCryptEncrypt/Decrypt (AES payloads)
   - Sockets (low-level network)
   - CreateProcessW (idevicepair/ideviceproxy spawns)
3. Print all captured data to stdout

Usage:
  py frida_trace.py                    # Attach to running iRemoval PRO
  py frida_trace.py --spawn            # Spawn the EXE
  py frida_trace.py --device 192.168.1.x  # Connect to iOS device
"""
import frida
import sys
import argparse
import time
import threading
import os

JS_SCRIPT = r"""
'use strict';

// Track all modules
console.log('[*] Frida dynamic tracer started');
console.log('[*] PID: ' + Process.id + ', Arch: ' + Process.arch);

var interesting_modules = [];
Process.enumerateModules().forEach(function(m) {
    if (m.name.indexOf('iremovalpro') >= 0 || m.name.indexOf('iRemoval') >= 0) {
        interesting_modules.push(m);
        console.log('[+] MODULE: ' + m.name + ' @ 0x' + m.base.toString(16) + ' size=' + m.size);
    }
});

// ==== 1. Hook CreateProcessW (spawns of idevicepair/ideviceproxy) ====
var kernel32 = Process.findModuleByName('kernel32.dll');
if (kernel32) {
    var createProcessW = kernel32.findExportByName('CreateProcessW');
    if (createProcessW) {
        Interceptor.attach(createProcessW, {
            onEnter: function(args) {
                if (args[1].isNull()) return;
                try {
                    var cmdLine = args[1].readUtf16String();
                    if (cmdLine && (cmdLine.indexOf('idevice') >= 0 || cmdLine.indexOf('/c ') >= 0)) {
                        console.log('[SPAWN] CreateProcessW: ' + cmdLine);
                    }
                } catch(e) {}
            }
        });
        console.log('[+] Hooked CreateProcessW');
    }
}

// ==== 2. Hook WS2_32 send/recv (low-level socket I/O) ====
var ws2_32 = Process.findModuleByName('WS2_32.dll');
if (ws2_32) {
    ['send', 'recv', 'WSASend', 'WSARecv'].forEach(function(fname) {
        var exp = ws2_32.findExportByName(fname);
        if (exp) {
            Interceptor.attach(exp, {
                onEnter: function(args) {
                    if (fname === 'send' || fname === 'WSASend') {
                        var fd = args[0].toInt32();
                        var buf = args[1];
                        var len = (fname === 'send') ? args[2].toInt32() : args[2].toInt32();
                        try {
                            var data = Memory.readByteArray(buf, Math.min(len, 512));
                            var hex = Array.from(new Uint8Array(data)).map(function(b) {
                                return ('0' + b.toString(16)).slice(-2);
                            }).join(' ');
                            console.log('[NET/' + fname + '] fd=' + fd + ' len=' + len + ' ' + hex);
                        } catch(e) {}
                    } else {
                        this.buf = args[1];
                    }
                },
                onLeave: function(retval) {
                    if (fname === 'recv' || fname === 'WSARecv') {
                        var len = retval.toInt32();
                        if (len > 0) {
                            try {
                                var data = Memory.readByteArray(this.buf, Math.min(len, 512));
                                var hex = Array.from(new Uint8Array(data)).map(function(b) {
                                    return ('0' + b.toString(16)).slice(-2);
                                }).join(' ');
                                console.log('[NET/' + fname + '] len=' + len + ' ' + hex);
                            } catch(e) {}
                        }
                    }
                }
            });
        }
    });
    console.log('[+] Hooked WS2_32 socket functions');
}

// ==== 3. Hook BCryptEncrypt/Decrypt ====
var bcrypt = Process.findModuleByName('bcrypt.dll');
if (bcrypt) {
    ['BCryptEncrypt', 'BCryptDecrypt'].forEach(function(fname) {
        var exp = bcrypt.findExportByName(fname);
        if (exp) {
            Interceptor.attach(exp, {
                onEnter: function(args) {
                    this.cbInput = args[2].toInt32();
                    if (this.cbInput > 0 && this.cbInput < 65536) {
                        try {
                            var data = Memory.readByteArray(args[1], Math.min(this.cbInput, 256));
                            var hex = Array.from(new Uint8Array(data)).map(function(b) {
                                return ('0' + b.toString(16)).slice(-2);
                            }).join(' ');
                            console.log('[CRYPTO/' + fname + '] input(' + this.cbInput + '): ' + hex);
                        } catch(e) {}
                    }
                },
                onLeave: function(retval) {
                    if (retval.toInt32() == 0 && args[6]) {
                        try {
                            var out = Memory.readByteArray(args[6], Math.min(args[7].toInt32(), 256));
                            var hex = Array.from(new Uint8Array(out)).map(function(b) {
                                return ('0' + b.toString(16)).slice(-2);
                            }).join(' ');
                            console.log('[CRYPTO/' + fname + '] output(' + args[7].toInt32() + '): ' + hex);
                        } catch(e) {}
                    }
                }
            });
        }
    });
    console.log('[+] Hooked BCrypt crypto functions');
}

// ==== 4. Hook IsDebuggerPresent / NtQueryInformationProcess ====
['IsDebuggerPresent', 'CheckRemoteDebuggerPresent'].forEach(function(fname) {
    var k32 = Process.findModuleByName('kernel32.dll');
    if (k32) {
        var exp = k32.findExportByName(fname);
        if (exp) {
            Interceptor.attach(exp, {
                onEnter: function(args) {},
                onLeave: function(retval) {
                    var v = retval.toInt32();
                    if (v != 0) {
                        console.log('[ANTI-DEBUG] ' + fname + ' returned ' + v);
                    }
                }
            });
        }
    }
});

// ==== 5. Hook file system access to known iOS paths ====
var ios_paths = ['/private/var', '/var/mobile', '/var/Keychains', '/activation_records',
                 '/Library/MobileSubstrate', '/private/var/mobile/Media'];
['CreateFileW', 'NtCreateFile'].forEach(function(fname) {
    var mod = Process.findModuleByName(fname === 'CreateFileW' ? 'kernel32.dll' : 'ntdll.dll');
    if (mod) {
        var exp = mod.findExportByName(fname);
        if (exp) {
            Interceptor.attach(exp, {
                onEnter: function(args) {
                    var path = null;
                    try {
                        if (fname === 'CreateFileW') {
                            path = args[0].readUtf16String();
                        } else {
                            var objName = args[0].add ? args[0] : args[0];
                            if (args[0].isNull()) return;
                            try { path = args[0].readWideString(); } catch(e) {}
                        }
                    } catch(e) {}
                    if (path) {
                        for (var i = 0; i < ios_paths.length; i++) {
                            if (path.indexOf(ios_paths[i]) >= 0) {
                                console.log('[FS] ' + fname + ': ' + path);
                                break;
                            }
                        }
                    }
                }
            });
        }
    }
});

console.log('[*] All hooks installed. Watching events...');

// Keep the script alive
setInterval(function() {}, 1000);
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--spawn', action='store_true', help='Spawn iRemoval PRO.exe')
    parser.add_argument('--device', help='Device ID for iOS')
    parser.add_argument('--pid', type=int, help='Attach to existing PID')
    args = parser.parse_args()

    try:
        if args.device:
            device = frida.get_device(args.device)
            print(f'[*] Connected to device: {device.name}')
        else:
            device = frida.get_local_device()
            print(f'[*] Connected to local device')
    except Exception as e:
        print(f'[!] Failed to connect: {e}')
        return

    if args.pid:
        session = device.attach(args.pid)
        print(f'[*] Attached to PID {args.pid}')
    elif args.spawn:
        pid = device.spawn(['iRemoval PRO.exe'])
        print(f'[*] Spawned iRemoval PRO.exe (PID {pid})')
        session = device.attach(pid)
        session.enable_jit()
    else:
        # List processes and let user choose
        processes = device.enumerate_processes()
        target = None
        for p in processes:
            if 'iRemoval' in p.name or 'iremovalpro' in p.name.lower():
                target = p
                break
        if not target:
            print('[!] iRemoval PRO process not found. Use --spawn or --pid')
            print('[*] Available processes with iRemoval:')
            for p in processes:
                if 'removal' in p.name.lower() or 'iRemov' in p.name:
                    print(f'    {p.name} (PID {p.pid})')
            return
        session = device.attach(target.pid)
        print(f'[*] Attached to {target.name} (PID {target.pid})')

    script = session.create_script(JS_SCRIPT)
    script.on('message', on_message)
    script.load()

    if args.spawn:
        device.resume(pid)

    print('[*] Tracing active. Press Ctrl+C to stop.')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('\n[*] Stopping...')
        session.detach()

if __name__ == '__main__':
    main()