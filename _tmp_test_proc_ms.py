import sys
import time
from pathlib import Path

sys.path.insert(0, r'06_LOCAL_REPRODUCER')
sys.path.insert(0, r'06_LOCAL_REPRODUCER\iact_reproducer')

import mock_server as m
import json, base64, os, threading, http.client, hmac
from iact_reproducer import hmac_auth, rate_limit, blacklist

log_dir = Path(r'06_LOCAL_REPRODUCER\iact_reproducer\_tmp_proc_ms_test')
log_dir.mkdir(parents=True, exist_ok=True)

auth = hmac_auth.AuthState()
auth.secrets['default'] = b'test-secret'
limiter = rate_limit.RateLimiter(rate_limit.RateLimitConfig(per_ip_limit=100, per_udid_limit=100, window_seconds=60))
bl = blacklist.Blacklist.load(Path(r'06_LOCAL_REPRODUCER\iact_reproducer\_tmp_proc_ms_test\bl.json'))
state = m._State(log_dir, auth=auth, limiter=limiter, blacklist_=bl)

class _T(m._MockHandler):
    pass
m._MockHandler.state = state  # inject like the real server does
import socketserver
srv = socketserver.ThreadingTCPServer(('127.0.0.1', 0), _T)
srv.state = state
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

try:
    udid = '11111111-2222-3333-4444-555555555555'
    plist = {
        'ActivationState': 'Activated',
        'BoardID': 0x02, 'ChipID': 0x8015, 'SecurityDomain': 1,
        'ProductionStatus': 1, 'CertificateSecurityMode': 1,
        'DMDOperations': {
            'ActivationLockStatus': 'OFF', 'DeviceLockState': 'Unlocked',
            'BackupPasswordProtected': True,
        },
    }
    payload = {
        'udid': udid,
        'public_key_modulus': base64.b64encode(os.urandom(256)).decode(),
        'plist': plist,
        'nonce': 'a' * 32,
        'sequence_number': 1,
        'client_hwid': 'hwid-1',
        'client_timestamp': time.time(),
        'client_build_marker': 'legit build marker',
        'server_proc_ms': 8.0,
        'device_cert_issuer': 'CN=Apple Device CA, O=Apple Inc.',
        'client_cert_sha256': 'A0B1C2D3E4F5' + '0' * 58,
        'devicecheck_token': 'h.p.s',
    }
    body = json.dumps(payload).encode()
    path = '/iremovalActivation/apple_drm_check.ph'
    headers = {'Content-Type': 'application/json'}
    headers.update(hmac_auth.make_signed_headers(auth, method='POST', path=path, body=body, key_id='default'))
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request('POST', path, body=body, headers=headers)
    resp = conn.getresponse()
    body_resp = resp.read()
    print('Status:', resp.status)
    print('Body:', body_resp[:500].decode('utf-8', errors='replace'))
    assert resp.status in (200, 403)

    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request('GET', '/metrics.ph')
    resp = conn.getresponse()
    metrics = resp.read().decode('utf-8')
    for line in [
        'iact_mock_server_proc_ms_measured',
        'iact_mock_server_proc_ms_client_claim',
        'iact_mock_server_proc_ms_delta',
        'iact_mock_server_proc_ms_last',
        'iact_mock_server_proc_ms_max',
        'quantile="0.5"',
        'quantile="0.95"',
    ]:
        assert line in metrics, f'missing metric: {line}'
    print('[OK] All Item 14 metrics present')
    for line in metrics.splitlines():
        if 'server_proc_ms' in line:
            print('  ', line)
    conn.close()
finally:
    srv.shutdown()
    srv.server_close()
    print('DONE')
