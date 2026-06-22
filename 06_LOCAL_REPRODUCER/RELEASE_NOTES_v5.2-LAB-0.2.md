# Release Notes — v5.2-LAB-0.2

**Date:** 2026-06-22  
**Codename:** *Defender Coverage*  
**Scope:** Blue-team reproducer, IR playbooks, continuous monitor, release packaging  
**Self-tests:** 20 / 20 PASS — coverage 22 / 22 BY-XXX-NNN rules

---

## What is new

### Phase C — Reporting
* **Chart.js dashboard** — three live charts (E2E timeline, top defender hits, severity doughnut) wired from `e2e_report.json` and `mock_server_requests.jsonl`.
* **SARIF 2.1.0 export** — `logs/defender_findings.sarif.json` consumable by GitHub Code Scanning, Azure DevOps, DefectDojo, etc. Tool id `iAct8Defender v5.2-LAB-0.2`.
* **PDF-friendly HTML export** — `logs/defender_summary.pdf.html` (print stylesheet, severity KPIs, top 25 rules, top 80 findings).
* **E2E Stage 4** — `py e2e.py` now runs `static_lab → dynamic_smoke → dashboard_render → reports_export` (4/4 OK, ~8 s).

### Phase D — IR playbooks
* **Splunk SPL** — 8 queries (R1-R6 + 2 lab-specific) for blue teams, including Authenticode on unsigned iRemoval binaries, custom-CA detection, device telemetry exfil, anti-vol iCloud patterns, NAND rewrite paths, AMFI bypass tweak surface.
* **Suricata offline tester** — pure-stdlib PCAP ↔ rules engine, supports sticky buffers (`http_host;`, `dns.query;`), 21 rules × 40 packets → 560 hits on the lab fixture.
* **`ticket_analyser`** — parses `activation_ticket.bplist` and surfaces DMD ops missing (`ActivationLockStatus`, `DeviceLockState`, `BackupPasswordProtected`) and signature absence.

### Phase E — Continuous monitor
* **`monitor/watcher.py`** — stdlib-only DNS / TLS / Cert-Transparency watcher. Pure-ASN heuristic flags iRemoval C2 (`s13.iremovalpro.com`, `api.bypassfrpfiles.com`) and detects non-Apple ASNs for legitimate hosts. Hand-rolled ASN.1 parser for certs (no `cryptography` dep at runtime). JSONL ledger per category, baseline diff via `--save-baseline` / `--baseline`.

### Phase F — Release packaging
* **CycloneDX SBOM** — `06_LOCAL_REPRODUCER/RELEASE_SBOM.cdx.json` (v1.5, manifest + components + external refs).
* **Sigstore-style release manifest** — `06_LOCAL_REPRODUCER/RELEASE_MANIFEST.txt` (SHA-256 per release artifact, ready for `cosign sign-blob`).
* **Annotated tag** — `v5.2-LAB-0.2`.

---

## Verification matrix

| Stage | Tool | Result | Artefact |
|---|---|---|---|
| Static lab | `run_lab.py` | 8 variants OK | `corpus/corpus_summary.json`, `logs/yara_report.json` |
| Dynamic smoke | `smoke_apple_drm.py` | defender hits | `logs/smoke_*/mock_server_requests.jsonl` |
| Dashboard | `dashboard.py` | 3 Chart.js cards | `dashboard_*.html` |
| Reports | `report_export.py` | 7 findings / 7 rules | `logs/defender_findings.sarif.json` + `logs/defender_summary.pdf.html` |
| Splunk | `splunk_queries.spl` | 8 queries ready | `ir_playbook/splunk_queries.spl` |
| Suricata | `suricata_tester.py` | 21 rules × 40 pcap packets | `ir_playbook/suricata_tester.py` |
| Ticket | `ticket_analyser.py` | DMD_MISSING + NO_SIGNATURE | `ir_playbook/ticket_analyser.py` |
| Monitor | `monitor/watcher.py` | DNS / TLS / CT ready | `monitor/watcher.py` + `logs/monitor/*.jsonl` |

---

## Known limitations

* **crt.sh queries time out** from the lab (8-second socket timeout). Watcher is wired correctly; production runs need a higher timeout or a local CT log mirror.
* **Hand-rolled X.509 parser** extracts `issuer`, `subject`, `notBefore/After`, and `SAN` only. It is not a replacement for the `cryptography` package — production deployments should swap it for `cryptography.x509`.
* **iRemoval C2 domains do not resolve** in the lab (firewalled), so DNS / TLS / CT phases produce `DNS_FAIL` / `TLS_FAIL` alerts as expected. In the wild, the C2 domains are alive and would yield `KNOWN_C2` alerts.

---

## Upgrade notes

No breaking changes. To upgrade a previous `v5.2-LAB-0.1` deployment:

```bash
git pull --tags
git checkout v5.2-LAB-0.2
pip install -r 06_LOCAL_REPRODUCER/requirements.txt   # cryptography 41.0.7
py 06_LOCAL_REPRODUCER/iact_reproducer/e2e.py        # 4/4 OK
py 06_LOCAL_REPRODUCER/monitor/watcher.py --mode all --save-baseline
```

---

## Provenance

* Repo commit: see `git log --oneline` at tag.
* Author: iAct8 Lab.
* License: Research Use Only — Defensive Security.
