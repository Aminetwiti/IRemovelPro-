# iAct8 local reproducer — OFFENSIVE  research harness

> **Classification** : OFFENSIVE _RESEARCH
> **Version** : 1.1.0 (étend le lab à 12 endpoints)
> **Purpose** : Reproduce the LOCAL flow that iRemoval PRO's
> `iact8.php` endpoint triggers on the server side, **without ever
> contacting the iRemoval server** and **without extracting or using
> the real iRemoval private key**.

This module recreates, end to end, the pipeline that produces a forged
iActivation ticket AND a complete local mock of the iRemoval cloud
backend (12 endpoints) for traffic analysis and detection engineering.

```
┌──────────────────────────────────────────────────────────────────────┐
│ 1. Générer clé privée RSA-2048 (TEST KEY ONLY, marquée)            │
│ 2. Construire bplist00 avec DeviceCertificate, SigningIdentity,     │
│    FairPlayCertificate, WildcardTicket, ...                         │
│ 3. openssl_sign() → PKCS#1 v1.5 RSA-2048                            │
│ 4. Wrap en JSON + base64                                             │
│ 5. Servir 12 endpoints sur 127.0.0.1 (iact8, pub, mf*, license,    │
│    telemetry, admin, version, blacklist, ping, metrics)             │
└──────────────────────────────────────────────────────────────────────┘
```

Voir [`../RECONSTRUCTION.md`](../RECONSTRUCTION.md) pour le détail complet
de l'architecture reconstruite.

All artefacts produced by this reproducer are **clearly marked as test
fixtures** (the literal string `iRemovalOFFENSIVE Test` appears in every
certificate subject, every plist payload, and every envelope). They are
useless against any real device and exist solely so blue teams can:

* study the wire format used by `iact8.php`
* exercise YARA / SIGMA / Suricata rules from `05_IOC/`
* train ML models on realistic-looking positive samples
* regression-test detection pipelines when iRemoval ships a new build

---

## Layout

```
iact_reproducer/
├── __init__.py
├── keys.py             # Step 1 - RSA-2048 keypair (generate / load)
├── bplist_builder.py   # Step 2 - build bplist00 with all artefacts
├── signer.py           # Step 3 - PKCS#1 v1.5 RSA-2048 signing
├── wire_format.py      # Step 4 - JSON + base64 envelope
├── orchestrator.py     # Ties 1-4 together
├── run_reproducer.py   # CLI entry point (single artefact)
│
├── corpus_generator.py # NEW - generate N labelled envelope variants
├── yara_runner.py      # NEW - run 05_IOC YARA rules against the corpus
├── mock_server.py      # NEW - offline mock of iact8.php (logs only)
├── pcap_writer.py      # NEW - synthesise a PCAP of the wire traffic
├── dashboard.py        # NEW - static HTML dashboard of the lab state
├── run_lab.py          # NEW - one-shot orchestrator of the whole lab
│
├── self_test.py        # 15-assertion round-trip self test
└── README.md           # this file
```

The artefacts are written under `06_LOCAL_REPRODUCER/`:

| Subdir       | Content                                                       |
|--------------|---------------------------------------------------------------|
| `keys/`      | RSA-2048 PEMs (always tagged `iRemovalOFFENSIVE Test`)         |
| `requests/`  | The `bplist00` ticket and the raw signature                   |
| `responses/` | The full JSON envelope (what the client would POST to iact8)  |
| `corpus/`    | N labelled envelope variants (positive + tampered negatives)  |
| `logs/`      | Manifests, YARA report, mock-server JSONL, PCAP, dashboard    |

---

## Quick start

### A) Single clean artefact

```powershell
python 06_LOCAL_REPRODUCER\iact_reproducer\run_reproducer.py
```

### B) Full OFFENSIVE  lab (recommended)

```powershell
# 30 positive envelope variants + auto-generated negatives
# + YARA scan on the binary + wire-format rules
# + synthetic PCAP + HTML dashboard
python 06_LOCAL_REPRODUCER\iact_reproducer\run_lab.py --samples 30
```

Then open the dashboard in a browser:

```powershell
start 06_LOCAL_REPRODUCER\logs\dashboard.html
```

### C) Run the offline mock server

```powershell
# Pick a free port (default 8443)
python 06_LOCAL_REPRODUCER\iact_reproducer\mock_server.py --port 8765
```

Health check:

```powershell
curl http://127.0.0.1:8765/health
# {"status":"ok","marker":"iRemovalOFFENSIVE Test"}
```

Submit one of your OFFENSIVE  envelopes:

```powershell
curl -X POST -H "Content-Type: application/json" `
     --data-binary "@06_LOCAL_REPRODUCER\corpus\positive\V0000.json" `
     http://127.0.0.1:8765/iremovalActivation/iact8.php
```

The mock logs every request to
`06_LOCAL_REPRODUCER\logs\mock\mock_server_requests.jsonl` and returns a
refusal response with the OFFENSIVE  marker.

### D) Verify a previously produced envelope

```powershell
# Extract the matching public key
openssl rsa -in 06_LOCAL_REPRODUCER\keys\iact8-test_....pem -pubout `
            -out 06_LOCAL_REPRODUCER\keys\iact8-test_....pub

python 06_LOCAL_REPRODUCER\iact_reproducer\run_reproducer.py `
    --verify 06_LOCAL_REPRODUCER\responses\iact_envelope_....json `
    --pubkey 06_LOCAL_REPRODUCER\keys\iact8-test_....pub
```

### E) Re-run just the YARA scan

```powershell
python 06_LOCAL_REPRODUCER\iact_reproducer\yara_runner.py `
    --rules 05_IOC\YARA_RULES.yar 05_IOC\YARA_RULES_WIRE.yar `
    --corpus 06_LOCAL_REPRODUCER\corpus
```

### F) Regenerate the PCAP / dashboard

```powershell
python 06_LOCAL_REPRODUCER\iact_reproducer\pcap_writer.py --limit 25
python 06_LOCAL_REPRODUCER\iact_reproducer\dashboard.py
```

---

## Lab architecture

```
                            +--------------------------+
                            |   run_lab.py (orchestr)  |
                            +-------------+------------+
                                          |
            +-------------+---------------+-----------------+--------------+
            |             |               |                 |              |
            v             v               v                 v              v
     run_reproducer.py corpus_generator yara_runner   pcap_writer   dashboard
     (single artefact) (N variants)    (detect)       (PCAP)        (HTML)
            |             |               |                 |              |
            v             v               v                 v              v
   +--------------+ +-----------+ +------------+ +----------------+ +-----------+
   | keys.py      | | keys.py   | | yara-python| | pcap_writer.py | | dashboard |
   | bplist_*     | | bplist_*  | |            | |                | | .py       |
   | signer.py    | | signer.py | |            | |                | |           |
   | wire_format  | | wire_fmt  | |            | |                | |           |
   +------+-------+ +-----+-----+ +-----+------+ +-------+--------+ +-----+-----+
          |               |             |                |                 |
          v               v             v                v                 v
   +--------------+ +-----------+ +-----------+ +----------------+ +-----------+
   | keys/        | | corpus/   | | yara_     | | logs/          | | logs/     |
   | requests/    | |  +/pos    | |  report.  | |  iact8_traffic | |  dashboard|
   | responses/   | |  +/neg    | |  json/csv | |  .pcap         | |  .html    |
   | logs/        | |           | |           | |                | |           |
   +--------------+ +-----------+ +-----------+ +----------------+ +-----------+

   mock_server.py is started independently and logs to logs/mock/...
   It can be pointed at by the iRemoval client (or any HTTP client
   sending the iact8 envelope) for traffic capture.
```

---

## YARA detection

The reproducer ships with **two** YARA rule files:

* `05_IOC/YARA_RULES.yar` — the original rules from the audit, targeting
  the **iRemoval PRO binaries** (PE, iOS dylib).
* `05_IOC/YARA_RULES_WIRE.yar` — **new** rules targeting the **wire
  format** (bplist00 ticket, JSON envelope, HTTP request, mix of
  endpoint URLs). These close the detection gap that the binary rules
  leave on the network.

The `iRemovalPro_OFFENSIVE Lab_Marker` rule is informational and
explicitly matches the `iRemovalOFFENSIVE Test` marker so lab artefacts
are easily distinguished from real-world captures.

Example detection summary (30 positive + 9 negative variants):

| Rule                                     | Hits |
|------------------------------------------|------|
| `iRemovalPro_Bplist00Ticket_Marker`      | 320  |
| `iRemovalPro_OFFENSIVE Lab_Marker`        | 160  |
| `iRemovalPro_WireEnvelope_Fields`        | 202  |
| `iRemovalPro_Generic_Indicators`         | 0*   |

\* The binary rules don't fire on the wire corpus by design — they
target PE/Mach-O headers. Run them against the real iRemoval PRO EXE
to see them hit.

---

## What gets put in the bplist00

```python
{
    "OFFENSIVE Marker":   "iRemovalOFFENSIVE Test",   # always present
    "IssuedAt":          "2026-06-22T10:22:58Z",
    "SchemaVersion":     "iact8-reproducer/1.0",

    "UDID":              "OFFENSIVE -TEST-XXXXXXXX",
    "ECID":              "0xXXXXXXXX",
    "Model":             "iPhone10,1 (TEST)",
    "BoardID":           "OFFENSIVE -BOARD-XXXXXXXX",
    "Nonce":             <16 random bytes>,
    "kSep":              <16 random bytes>,

    "DeviceCertificate":  <DER of self-signed cert, CN contains iRemovalOFFENSIVE Test>,
    "SigningIdentity":    "iRemovalOFFENSIVE Test:<sha256(pubkey)>",
    "FairPlayCertificate":"iRemovalOFFENSIVE Test-FairPlayCert-PLACEHOLDER-NOT-FROM-APPLE…" (64 bytes),
    "WildcardTicket":     "iRemovalOFFENSIVE Test-WildcardTicket-PLACEHOLDER-NOT-FROM-APPLE…" (64 bytes),

    "BuildPath":          "/Users/josuealonsorodriguez/.../blackhound.x.o",
    "HookTargets":        ["MobileActivationDaemon", "SecKeyRawVerify",
                           "SecKeyVerifySignature", "SecTrustEvaluateWithError"],
}
```

Every value that would have come from Apple infrastructure in a real
attack (FairPlay cert, WildcardTicket, DeviceCertificate from
`albert.apple.com`, …) is replaced by a clearly-labelled placeholder.
The reproducer therefore *cannot* produce a ticket that iOS would
accept.

---

## What the JSON envelope looks like

```json
{
  "udid": "OFFENSIVE -TEST-XXXXXXXX",
  "b64":  "YnBsaXN0AwAA…",        // base64(bplist00)
  "sig":  "Abc123…",              // base64(PKCS1v1.5 signature)
  "alg":  "RSA-PKCS1v1.5-SHA256",
  "nonce":"koY+rla/7ol+LX8kepekEw==",  // 16 random bytes
  "ts":   "2026-06-22T10:22:58Z",
  "key_fingerprint": "9f2c…",
  "OFFENSIVE _marker": "iRemovalOFFENSIVE Test"
}
```

Field names match what `iact8.php` and the ioc_catalog
(`05_IOC/ioc_catalog.md`) describe, so the envelope is byte-for-byte in
the same shape as the captured real traffic — only the *contents* are
obviously synthetic.

---

## Limitations

* We do not extract the real iRemoval RSA private key from the binary.
  `keys.py` only ever produces or loads a **fresh test key** clearly
  tagged `iRemovalOFFENSIVE Test`.
* We do not contact `s13.iremovalpro.com`. The reproducer is fully
  offline.
* Placeholder blobs for `FairPlayCertificate`, `WildcardTicket` etc.
  will fail any real Apple-side check. They are not bypasses.
* The `UDID` / `ECID` / `BoardID` values are synthetic and do not
  match any real device.
* No anti-replay / nonce-reuse protection is implemented — this is a
  research harness, not a client.

See `01_REPORTS/LIMITATIONS.md` for the broader analysis limitations.

---

## Cross-references

* `01_REPORTS/ENDPOINT_IACT8.md` — endpoint analysis
* `01_REPORTS/REPORT_SERVER_PROTOCOL.md` — full server protocol
* `01_REPORTS/CRYPTO_CRITICAL_ANALYSIS.md` — why PKCS#1 v1.5 + RSA-2048
* `01_REPORTS/PHASE5_RUNTIME_NATIVEAOT.md` — the dylib that injects the
  resulting ticket
* `05_IOC/ioc_catalog.md` — detection rules to test against
* `05_IOC/YARA_RULES.yar` / `SIGMA_RULES.yml` — sample detectors
