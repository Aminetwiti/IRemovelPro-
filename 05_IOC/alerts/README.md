# SIEM Alert Rules — iRemoval PRO / Apple DRM Defender

> Companion rules for `06_LOCAL_REPRODUCER/iact_reproducer/mock_server.py`
> and `06_LOCAL_REPRODUCER/apple_drm_defense.py`. The mock server
> exports severity-tiered alert counters via `/metrics.ph` (Prometheus
> exposition format) and a JSON view via `/alerts.ph`.

## Files in this directory

| File | Format | Coverage |
| --- | --- | --- |
| `siem_alert_rules.yml` | Prometheus AlertManager | 9 alerts (P1 × 1, P2 × 6, P3 × 2) with runbook annotations, severity rationale, and **Splunk SPL / Elastic KQL equivalents** at the bottom. **Read this first.** |
| `SIGMA_RULES.yml` | SIGMA v2 | 5 process-creation rules (`ire-0015-p1/p2/p3`, `ire-0016`, `ire-0017`) for the host side. |
| `README.md` | — | this file — explains the severity model and metric names. |

## Severity tiers (mock_server side)

| Tier | Trigger | Mean |
|------|---------|------|
| **P1** | `BY-MOD-001` — public-key modulus matches the v5.2 RSA-1024 bypass key (SHA-1 `032476fc5c2ff5e65e5ae6ae81b2c45433bf32a8`). | Page immediately. Forged/relayed ticket. |
| **P2** | `BY-PLI-001` (forbidden plist keys), `BY-EXT-001..005` (forbidden Bundle IDs / build markers / extension fields), `BY-G-001..004` (missing DeviceCheck, mTLS, geolocation, network reachability), `BY-F-001/002` (replay / pre-signed cache). | Escalate within 15 min. High-confidence bypass marker. |
| **P3** | `BY-SES-001..007` (session/timing heuristics), `BY-INT-001..005` (interceptor fingerprints), `BY-E-001/002` (entropy), `BY-D-001/002` (deep-static indicators). | Correlate bursts. Single P3 rarely conclusive. |

**Why 27 codes map to 3 tiers:** P1 is single-shot deterministic (the
v5.2 public bypass pubkey). P2 covers explicit, hand-curated markers
that the iRemoval PRO toolchain *must* emit. P3 covers heuristics
that are noisy on their own. The full code catalogue is in
`06_LOCAL_REPRODUCER/apple_drm_defense.py::CHECK_SEVERITY`.

## Counter names (Prometheus)

- `iact_mock_defender_alerts_total{severity="P1|P2|P3"}` — cumulative counters, monotonic.
- `iact_mock_defender_hits_total{check="BY-XXX-NNN"}` — per-check-ID hit counts.
- `iact_mock_skipped_guards_total{guard="hmac|rate_limit|blacklist|defender|any"}` — middleware bypass counters (lab-only).
- `iact_mock_server_proc_ms_measured{quantile="0.5|0.95|0.99"}` — server-side processing time summary.
- `iact_mock_server_proc_ms_client_claim{quantile="0.5|0.95|0.99"}` — what the client said the server took.
- `iact_mock_server_proc_ms_delta{quantile="0.5|0.95|0.99"}` — `|measured - client_claim|` — useful for catching time-spoofed clients.
- `iact_mock_server_proc_ms_last` — gauge, last observed measured value.
- `iact_mock_server_proc_ms_max` — gauge, max since server start.

## SIGMA rules

See `SIGMA_RULES.yml` in this directory:

| ID | Tier | What it detects |
|----|------|-----------------|
| `8f4a1b3c-ire-0015-p1` | critical | P1 alert raised by mock_server (process creation matching `P1` + mock_server.py). |
| `8f4a1b3c-ire-0015-p2` | high | P2 alert raised by mock_server. |
| `8f4a1b3c-ire-0015-p3` | medium | P3 alert raised by mock_server. |
| `8f4a1b3c-ire-0016` | high | Mock server started with `--disable-*` flag (permissive middleware). |
| `8f4a1b3c-ire-0017` | medium | Anomalous drop in `server_proc_ms_measured` (pre-signed ticket batch). |

## Prometheus alert definitions

```yaml
# prometheus_alerts.yml
groups:
  - name: iremovalpro_defender
    rules:
      - alert: IRemovalPRO_DefenderP1Critical
        expr: increase(iact_mock_defender_alerts_total{severity="P1"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
          tier: P1
        annotations:
          summary: "iRemoval PRO defender raised P1 alert (forged/relayed ticket)"
          runbook: "https://wiki.internal/runbooks/iremovalpro-p1"

      - alert: IRemovalPRO_DefenderP2High
        expr: increase(iact_mock_defender_alerts_total{severity="P2"}[5m]) > 0
        for: 0m
        labels:
          severity: high
          tier: P2
        annotations:
          summary: "iRemoval PRO defender raised P2 alert (bypass marker in plist)"

      - alert: IRemovalPRO_DefenderP3Burst
        expr: increase(iact_mock_defender_alerts_total{severity="P3"}[5m]) > 5
        for: 0m
        labels:
          severity: medium
          tier: P3
        annotations:
          summary: "Burst of P3 alerts from iRemoval PRO defender (possible pre-attack probe)"

      - alert: IRemovalPRO_ServerProcMsDrop
        expr: |
          iact_mock_server_proc_ms_measured{quantile="0.5"} < 5
          and rate(iact_mock_requests_total[5m]) > 10
        for: 1m
        labels:
          severity: medium
        annotations:
          summary: "Mock server processing time dropped below 5ms p50 (pre-signed ticket batch?)"

      - alert: IRemovalPRO_SkippedGuard
        expr: increase(iact_mock_skipped_guards_total{guard!="any"}[5m]) > 0
        for: 0m
        labels:
          severity: high
        annotations:
          summary: "Mock server started with --disable-* flag in production-like mode"
```

## JSON view

`/alerts.ph` returns the last 100 alerts (deque) plus cumulative counts:

```json
{
  "lab_marker": "iRemovalLabTest",
  "ts": "2026-06-22T10:30:00Z",
  "counts": {"P1": 0, "P2": 0, "P3": 0},
  "recent": [
    {
      "ts": "2026-06-22T10:29:59Z",
      "severity": "P1",
      "check_id": "BY-MOD-001",
      "reason": "public_key_modulus SHA-1 matches iRemoval PRO v5.2 bypass",
      "request_id": "mw-20260622T102959123456",
      "udid": "00008110-...",
      "ip": "192.168.1.42",
      "source": "middleware:defender",
      "lab_marker": "iRemovalLabTest"
    }
  ]
}
```
