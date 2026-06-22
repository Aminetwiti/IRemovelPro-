"""Generate the release manifest (one row per artefact: <sha256>  <size>  <path>)."""
import hashlib
from pathlib import Path

FILES = [
    "06_LOCAL_REPRODUCER/RELEASE_SBOM.cdx.json",
    "06_LOCAL_REPRODUCER/RELEASE_NOTES_v5.2-LAB-0.2.md",
    "06_LOCAL_REPRODUCER/iact_reproducer/e2e.py",
    "06_LOCAL_REPRODUCER/iact_reproducer/dashboard.py",
    "06_LOCAL_REPRODUCER/iact_reproducer/report_export.py",
    "06_LOCAL_REPRODUCER/ir_playbook/splunk_queries.spl",
    "06_LOCAL_REPRODUCER/ir_playbook/suricata_tester.py",
    "06_LOCAL_REPRODUCER/ir_playbook/ticket_analyser.py",
    "06_LOCAL_REPRODUCER/monitor/watcher.py",
    "05_IOC/YARA_RULES.yar",
    "05_IOC/YARA_RULES_ADVERSARIAL.yar",
    "05_IOC/SIGMA_RULES.yml",
    "05_IOC/SURICATA_RULES.rules",
    "05_IOC/ioc_catalog.md",
]

rows = []
for f in FILES:
    p = Path(f)
    if not p.exists():
        rows.append((f, None, 0, False))
        continue
    h = hashlib.sha256(p.read_bytes()).hexdigest()
    rows.append((f, h, p.stat().st_size, True))

out = Path("06_LOCAL_REPRODUCER/RELEASE_MANIFEST.txt")
with out.open("w", encoding="utf-8") as fh:
    fh.write("# iAct8 Lab release manifest - v5.2-LAB-0.2\n")
    fh.write("# Format: each row is <sha256>  <size>  <path>\n")
    fh.write("# Use `cosign sign-blob --key cosign.key RELEASE_MANIFEST.txt` to sign.\n\n")
    present = 0
    for f, h, sz, ok in rows:
        if ok:
            fh.write(f"{h}  {sz:>10d}  {f}\n")
            present += 1
        else:
            fh.write(f"# MISSING: {f}\n")
    fh.write(f"\n# total artefacts: {present}/{len(rows)}\n")
    fh.write("# tag: v5.2-LAB-0.2\n")

print("manifest written:", out, out.stat().st_size, "bytes")
print("artefacts present:", present, "/", len(rows))
