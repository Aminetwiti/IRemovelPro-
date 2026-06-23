"""Test d'injection UDID 00008130-001C68110AA0001C dans le mock_server"""
import sys
sys.path.insert(0, r'06_LOCAL_REPRODUCER\iact_reproducer')

import mock_server as m
import hmac_auth
import rate_limit
import blacklist
from pathlib import Path

# Setup state
auth = hmac_auth.HMACAuth(secret='test-secret')
limiter = rate_limit.RateLimiter(rate_limit.RateLimitConfig())
bl = blacklist.Blacklist(Path('_test_bl.json'))
state = m._State('_test_udid_inject', auth=auth, limiter=limiter, blacklist_=bl)

# Reset counters for clean test
state.defender_hits = {k: 0 for k in state.defender_hits}
state.alert_log.clear()
for k in state.defender_alerts:
    state.defender_alerts[k] = 0

# Severity map
state.CHECK_SEVERITY = {
    'BY-MOD-001': 'P1',
    'BY-PLI-001': 'P2', 'BY-EXT-001': 'P2',
    'BY-G-001': 'P2', 'BY-G-002': 'P2', 'BY-G-003': 'P2', 'BY-G-004': 'P2',
    'BY-F-001': 'P2', 'BY-F-002': 'P2'
}


class T(m._MockHandler):
    pass


T.state = state

payload = {
    'udid': '00008130-001C68110AA0001C',
    'public_key_modulus': b'\x00' * 256,
    'plist': {
        'ProductType': 'iPhone16,2',
        'BuildVersion': '26.5',
        'ActivationLockStatus': 'OFF',
        'BackupPasswordProtected': True
    },
    'ClientBuildMarker': 'legit marker',
    'device_cert_issuer': 'CN=Apple Device CA, O=Apple Inc.',
    'server_proc_ms': 8.0,
    'devicecheck_token': 'mock_token',
    'timestamp': '2026-06-23T12:00:00Z',
    'nonce': 'test_nonce',
    'session_sequence': 1,
}

handler = T

r = m._MockHandler._run_defender(
    handler, payload,
    request_id='test-udid-001',
    udid='00008130-001C68110AA0001C',
    source='endpoint:test'
)

print('--- UDID Injection Test ---')
print('UDID: 00008130-001C68110AA0001C')
print('Device: iPhone16,2, iOS 26.5')
print('ok:', r['ok'])
print('reasons:')
for reason in r['reasons']:
    print('  -', reason)

print('\n--- Defender hits (non-zero) ---')
for k, v in sorted(state.defender_hits.items()):
    if v > 0:
        print(' ', k, ':', v)

print('\n--- Alert log (%d entries) ---' % len(state.alert_log))
for a in list(state.alert_log):
    print(' [%s] %s: %s' % (a['severity'], a['check_id'], a['reason'][:80]))

print('\n--- Analysis ---')
if not r['ok']:
    print('ALERT: Payload FLAGGED by defender with %d reason(s)' % len(r['reasons']))
    p1 = sum(1 for a in state.alert_log if a['severity'] == 'P1')
    p2 = sum(1 for a in state.alert_log if a['severity'] == 'P2')
    p3 = sum(1 for a in state.alert_log if a['severity'] == 'P3')
    print('P1 alerts:', p1)
    print('P2 alerts:', p2)
    print('P3 alerts:', p3)
else:
    print('INFO: Payload ACCEPTED as clean (no triggers)')
