#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Frida dynamic tracer for iremovalpro.dll + iRemoval PRO EXE.
Captures all HTTP requests to s13.iremovalpro.com and crypto operations.
"""
import frida
import sys
import time
import json
import argparse
import os
from datetime import datetime

JS_SCRIPT = r"""
'use strict';

console.log('[*] iRemoval PRO Frida tracer started');
console.log('[*] PID: ' + Process.id + ' on ' + Process.arch);
console.log('');

// Track interesting modules
Process.enumerateModules().forEach(function(m) {
    if (m.name.toLowerCase().indexOf('iremoval') >= 0 ||
        m.name.toLowerCase().indexOf('restsharp') >= 0 ||
        m.name.toLowerCase().indexOf('sshnet') >= 0) {
        console.log('[+] MODULE: ' + m.name + ' @ 0x' + m.base.toString(16) + ' size=' + m.size);
    }
});

var req_log = [];
var crypto_log = [];

// ==== 1. Hook CreateProcessW (idevicepair/ideviceproxy) ====
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
                        console.log('[SPAWN] ' + cmdLine);
                    }
                } catch(e) {}
            }
        });
        console.log('[+] Hooked CreateProcessW');
    }
}

// ==== 2. Hook WS2_32 socket I/O ====
var ws2_32 = Process.findModuleByName('WS2_32.dll');
if (ws2_32) {
    ['send', 'WSASend'].forEach(function(fname) {
        var exp = ws2_32.findExportByName(fname);
        if (exp) {
            Interceptor.attach(exp, {
                onEnter: function(args) {
                    var fd = args[0].toInt32();
                    var buf = args[1];
                    var len = args[2].toInt32();
                    if (len <= 0 || len > 65536) return;
                    try {
                        var data = Memory.readByteArray(buf, Math.min(len, 2048));
                        var hex = Array.from(new Uint8Array(data)).map(function(b) {
                            return ('0' + b.toString(16)).slice(-2);
                        }).join(' ');
                        var ascii = Array.from(new Uint8Array(data)).map(function(b) {
                            return (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
                        }).join('');
                        console.log('[NET/' + fname + '] fd=' + fd + ' len=' + len);
                        if (ascii.indexOf('s13.iremovalpro') >= 0 || ascii.indexOf('POST') >= 0) {
                            console.log('  >>> ' + ascii);
                            req_log.push({ts: Date.now(), dir: 'send', fd: fd, len: len, data: ascii});
                        }
                    } catch(e) {}
                }
            });
        }
    });
    ['recv', 'WSARecv'].forEach(function(fname) {
        var exp = ws2_32.findExportByName(fname);
        if (exp) {
            Interceptor.attach(exp, {
                onEnter: function(args) { this.buf = args[1]; },
                onLeave: function(retval) {
                    var len = retval.toInt32();
                    if (len > 0 && len < 65536) {
                        try {
                            var data = Memory.readByteArray(this.buf, Math.min(len, 4096));
                            var ascii = Array.from(new Uint8Array(data)).map(function(b) {
                                return (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
                            }).join('');
                            console.log('[NET/' + fname + '] len=' + len);
                            if (ascii.indexOf('HTTP/') === 0 || ascii.indexOf('{') >= 0) {
                                console.log('  <<< ' + ascii);
                                req_log.push({ts: Date.now(), dir: 'recv', len: len, data: ascii});
                            }
                        } catch(e) {}
                    }
                }
            });
        }
    });
    console.log('[+] Hooked WS2_32');
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
                            var data = Memory.readByteArray(args[1], Math.min(this.cbInput, 512));
                            var hex = Array.from(new Uint8Array(data)).map(function(b) {
                                return ('0' + b.toString(16)).slice(-2);
                            }).join(' ');
                            var ascii = Array.from(new Uint8Array(data)).map(function(b) {
                                return (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
                            }).join('');
                            console.log('[CRYPTO/' + fname + '] in(' + this.cbInput + ') hex=' + hex.substring(0, 200));
                            crypto_log.push({ts: Date.now(), op: fname, dir: 'in', len: this.cbInput, hex: hex, ascii: ascii});
                        } catch(e) {}
                    }
                },
                onLeave: function(retval) {
                    if (retval.toInt32() == 0 && args[6]) {
                        try {
                            var out = Memory.readByteArray(args[6], Math.min(args[7].toInt32(), 512));
                            var hex = Array.from(new Uint8Array(out)).map(function(b) {
                                return ('0' + b.toString(16)).slice(-2);
                            }).join(' ');
                            console.log('[CRYPTO/' + fname + '] out(' + args[7].toInt32() + ') hex=' + hex.substring(0, 200));
                            crypto_log.push({ts: Date.now(), op: fname, dir: 'out', len: args[7].toInt32(), hex: hex});
                        } catch(e) {}
                    }
                }
            });
        }
    });
    console.log('[+] Hooked BCrypt');
}

// ==== 4. Hook winsock connect (target detection) ====
if (ws2_32) {
    var connect = ws2_32.findExportByName('connect');
    if (connect) {
        Interceptor.attach(connect, {
            onEnter: function(args) {
                this.sockaddr = args[1];
            },
            onLeave: function(retval) {
                if (retval.toInt32() == 0 && this.sockaddr) {
                    try {
                        var family = Memory.readU16(this.sockaddr);
                        if (family === 2) {  // AF_INET
                            var port = Memory.readU16(this.sockaddr.add(2));
                            port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                            var ip = Memory.readU8(this.sockaddr.add(4)) + '.' +
                                     Memory.readU8(this.sockaddr.add(5)) + '.' +
                                     Memory.readU8(this.sockaddr.add(6)) + '.' +
                                     Memory.readU8(this.sockaddr.add(7));
                            console.log('[CONNECT] ' + ip + ':' + port);
                        }
                    } catch(e) {}
                }
            }
        });
        console.log('[+] Hooked connect()');
    }
}

// Periodic dump
setInterval(function() {
    if (req_log.length > 0 || crypto_log.length > 0) {
        console.log('---');
        console.log('[*] Stats: ' + req_log.length + ' HTTP events, ' + crypto_log.length + ' crypto events');
    }
}, 10000);

console.log('');
console.log('[*] Hooks installed. Watching traffic...');
"""

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        print(payload)
        sys.stdout.flush()
    elif message['type'] == 'error':
        print(f"[ERROR] {message.get('stack','')}", file=sys.stderr)
        sys.stderr.flush()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--spawn', action='store_true', help='Spawn iRemoval PRO.exe')
    parser.add_argument('--device', help='Device ID for iOS')
    parser.add_argument('--pid', type=int, help='Attach to existing PID')
    parser.add_argument('--target', default='iRemoval PRO.exe', help='Process to spawn')
    args = parser.parse_args()

    if args.device:
        device = frida.get_device(args.device)
        print(f'[*] Device: {device.name}')
    else:
        device = frida.get_local_device()
        print(f'[*] Local device')

    if args.pid:
        session = device.attach(args.pid)
        print(f'[*] Attached to PID {args.pid}')
    elif args.spawn:
        try:
            pid = device.spawn([args.target])
            print(f'[*] Spawned {args.target} (PID {pid})')
            session = device.attach(pid)
            session.enable_jit()
        except Exception as e:
            print(f'[!] Spawn failed: {e}')
            return
    else:
        processes = device.enumerate_processes()
        target = None
        for p in processes:
            if 'iRemoval' in p.name or 'iremoval' in p.name.lower():
                target = p
                break
        if not target:
            print(f'[!] iRemoval PRO process not found. Available:')
            for p in processes:
                if 'remov' in p.name.lower():
                    print(f'    {p.name} (PID {p.pid})')
            return
        session = device.attach(target.pid)
        print(f'[*] Attached to {target.name} (PID {target.pid})')

    script = session.create_script(JS_SCRIPT)
    script.on('message', on_message)
    script.load()

    if args.spawn:
        device.resume(device.spawn([args.target])[0] if False else None)
        # Resume manually
        for p in device.enumerate_processes():
            if p.name == args.target and p.pid > 0:
                try:
                    device.resume(p.pid)
                except:
                    pass
                break

    print('[*] Tracing. Press Ctrl+C to stop.')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('\n[*] Stopping...')
        session.detach()

if __name__ == '__main__':
    main()
