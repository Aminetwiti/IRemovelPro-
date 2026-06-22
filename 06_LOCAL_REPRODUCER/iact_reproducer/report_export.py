"""SARIF 2.1.0 + minimal PDF export for the iAct8 reproducer.

This module lets the lab push its findings to:
  * any SARIF 2.1.0-aware tool (GitHub Code Scanning, Azure DevOps,
    Mend, Sonar, DefectDojo, etc.) — the canonical security output format
  * a portable PDF summary that travels well in email / slack reports

It runs offline (no network) and depends only on the Python stdlib plus the
optional dependencies already pinned in `06_LOCAL_REPRODUCER/requirements.txt`.

The single public function is :func:`export_reports`, invoked by
``e2e.py`` (or the standalone ``--export`` CLI mode).
"""

from __future__ import annotations

import argparse
import html as html_lib
import json
import logging
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

log = logging.getLogger("iact_report_export")

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"
TOOL_NAME = "iAct8Defender"
TOOL_VERSION = "5.2-LAB-0.2"
TOOL_INFO_URI = "https://github.com/iremovalpro/iact8-defender"

# Severity mapping (tool side) → SARIF level
_LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Human-readable friendly name for each check-ID prefix
_CATEGORY_PREFIX = {
    "BY-INT": "Internalisation",
    "BY-EXT": "Extension applicative",
    "BY-SES": "Anti-replay session",
    "BY-NET": "Réseau",
    "BY-CRT": "Certificat / PKI",
    "BY-D":   "Forensique iOS",
    "BY-E":   "Baseband",
    "BY-F":   "DMD / MDM",
    "BY-G":   "DeviceCheck / mTLS",
}

# Stable severity per category (used when raw finding has no severity)
_DEFAULT_SEVERITY = {
    "BY-INT": "high",
    "BY-EXT": "medium",
    "BY-SES": "high",
    "BY-NET": "high",
    "BY-CRT": "critical",
    "BY-D":   "critical",
    "BY-E":   "high",
    "BY-F":   "high",
    "BY-G":   "high",
}

_CHECK_ID_RE = re.compile(r"\b(BY-(?:INT|EXT|SES|NET|CRT|D|E|F|G)-\d{3})\b")


@dataclass(frozen=True)
class Finding:
    """One defender hit to be exported to SARIF / PDF."""
    rule_id: str
    message: str
    severity: str
    uri: str
    location: str
    snippet: str = ""


def _infer_severity(rule_id: str) -> str:
    prefix = "-".join(rule_id.split("-")[:2])
    return _DEFAULT_SEVERITY.get(prefix, "medium")


def _category_for(rule_id: str) -> str:
    prefix = "-".join(rule_id.split("-")[:2])
    return _CATEGORY_PREFIX.get(prefix, "Autre")


def parse_reasons(reasons: Iterable[str], *, default_uri: str = "mock://albert.apple.com") -> List[Finding]:
    """Convert raw defender `reasons` strings into :class:`Finding` rows.

    The defender emits free-form messages such as
        "modulus RSA blacklisté (032476fc…) — iRemoval PRO v5.2 RSA-1024 bypass modulus (BY-INT-001)"
    The BY-XXX-NNN tag is captured and used as the SARIF ruleId.
    """
    out: List[Finding] = []
    for raw in reasons:
        match = _CHECK_ID_RE.search(raw)
        rule_id = match.group(1) if match else "BY-EXT-000"
        out.append(
            Finding(
                rule_id=rule_id,
                message=raw,
                severity=_infer_severity(rule_id),
                uri=default_uri,
                location=raw,
                snippet=raw,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# SARIF 2.1.0
# --------------------------------------------------------------------------- #

def build_sarif(findings: List[Finding], *, run_id: str = "") -> Dict[str, Any]:
    """Return a SARIF 2.1.0 document (dict) ready to dump as JSON."""
    rules_seen: Dict[str, Finding] = {}
    for f in findings:
        rules_seen.setdefault(f.rule_id, f)

    sarif_rules = []
    for rule_id, f in sorted(rules_seen.items()):
        sarif_rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace("-", "_"),
                "shortDescription": {"text": f"{_category_for(rule_id)} — {rule_id}"},
                "fullDescription": {"text": f.message},
                "defaultConfiguration": {
                    "level": _LEVEL_BY_SEVERITY.get(f.severity, "warning"),
                },
                "properties": {
                    "category": _category_for(rule_id),
                    "severity": f.severity,
                    "tags": ["security", "iremovaldetection", "iact8"],
                },
            }
        )

    sarif_results = []
    for f in findings:
        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": _LEVEL_BY_SEVERITY.get(f.severity, "warning"),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.uri},
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                                "endLine": 1,
                                "endColumn": max(1, len(f.snippet)),
                                "snippet": {"text": f.snippet},
                            },
                        },
                        "properties": {"category": _category_for(f.rule_id)},
                    }
                ],
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_INFO_URI,
                        "semanticVersion": TOOL_VERSION,
                        "rules": sarif_rules,
                    }
                },
                "automationDetails": {
                    "id": run_id or f"iact8-{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}",
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                ],
                "results": sarif_results,
                "properties": {
                    "lab_version": TOOL_VERSION,
                    "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
            }
        ],
    }


def write_sarif(findings: List[Finding], out_path: Path, *, run_id: str = "") -> Path:
    out_path = Path(out_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc = build_sarif(findings, run_id=run_id)
    out_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Wrote SARIF: %s (%d results, %d rules)", out_path, len(findings), len(doc["runs"][0]["tool"]["driver"]["rules"]))
    return out_path


# --------------------------------------------------------------------------- #
# PDF (no external deps — minimal HTML→PDF recipe with wkhtmltopdf optional)
# --------------------------------------------------------------------------- #

def _pdf_escape(text: str) -> str:
    return html_lib.escape(str(text), quote=True)


def build_pdf_html(
    *,
    findings: List[Finding],
    e2e_report: Optional[Dict[str, Any]] = None,
    title: str = "iAct8 Defender — Rapport de détection",
) -> str:
    """Build a self-contained HTML that prints well as a PDF (or stand-alone)."""
    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_rule: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1

    style = """
    @page { size: A4; margin: 16mm 14mm; }
    body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
           color: #0f172a; }
    h1 { color: #b91c1c; border-bottom: 2px solid #b91c1c; padding-bottom: 6px; }
    h2 { color: #1d4ed8; margin-top: 24px; }
    table { width: 100%; border-collapse: collapse; font-size: 11px; }
    th, td { padding: 4px 6px; border: 1px solid #cbd5e1; text-align: left;
             vertical-align: top; }
    th { background: #1d4ed8; color: white; text-transform: uppercase; font-size: 9px; }
    .kpi-row { display: flex; gap: 8px; margin: 12px 0; flex-wrap: wrap; }
    .kpi { flex: 1; min-width: 80px; padding: 8px 10px; border: 1px solid #cbd5e1;
           border-radius: 4px; background: #f1f5f9; }
    .kpi .label { font-size: 9px; text-transform: uppercase; color: #475569; }
    .kpi .value { font-size: 18px; font-weight: 700; color: #0f172a; }
    .sev-critical { background: #fee2e2; color: #b91c1c; font-weight: 700; }
    .sev-high     { background: #ffedd5; color: #c2410c; font-weight: 700; }
    .sev-medium   { background: #fef9c3; color: #854d0e; font-weight: 700; }
    .sev-low      { background: #dcfce7; color: #166534; }
    .footer { margin-top: 24px; color: #64748b; font-size: 9px; text-align: center; }
    code { font-family: "SFMono-Regular", Consolas, monospace; font-size: 10px;
           background: #f1f5f9; padding: 1px 3px; border-radius: 2px; }
    """

    sev_rows = "".join(
        f"<div class='kpi'><div class='label'>{label.upper()}</div>"
        f"<div class='value'>{counts.get(label, 0)}</div></div>"
        for label in ("critical", "high", "medium", "low")
    )

    top_rules = sorted(by_rule.items(), key=lambda kv: -kv[1])[:25]
    rule_rows = "".join(
        f"<tr><td><code>{_pdf_escape(rid)}</code></td><td>{n}</td>"
        f"<td>{_pdf_escape(_category_for(rid))}</td>"
        f"<td>{_pdf_escape(_infer_severity(rid))}</td></tr>"
        for rid, n in top_rules
    )

    findings_rows = "".join(
        f"<tr><td><code>{_pdf_escape(f.rule_id)}</code></td>"
        f"<td><span class='sev-{_pdf_escape(f.severity)}'>{_pdf_escape(f.severity.upper())}</span></td>"
        f"<td>{_pdf_escape(f.message[:200])}</td></tr>"
        for f in findings[:80]
    )

    e2e_block = ""
    if e2e_report:
        stages = e2e_report.get("stages", [])
        stage_rows = "".join(
            f"<tr><td><b>{_pdf_escape(s.get('name',''))}</b></td>"
            f"<td>{'✅' if s.get('ok') else '❌'}</td>"
            f"<td>{s.get('duration_seconds', 0):.2f}s</td></tr>"
            for s in stages
        )
        e2e_block = (
            f"<h2>E2E runner</h2>"
            f"<p>overall_ok : <b>{e2e_report.get('overall_ok')}</b> &middot; "
            f"duration : {e2e_report.get('total_duration_seconds', 0):.2f}s &middot; "
            f"seed : <code>{_pdf_escape(str(e2e_report.get('seed','')))}</code></p>"
            f"<table><tr><th>Stage</th><th>Status</th><th>Duration</th></tr>{stage_rows}</table>"
        )

    return f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>{_pdf_escape(title)}</title>
<style>{style}</style>
</head>
<body>
<h1>{_pdf_escape(title)}</h1>
<p><b>Outil :</b> {TOOL_NAME} v{TOOL_VERSION}<br>
<b>Généré :</b> {datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}<br>
<b>Findings :</b> {len(findings)}<br>
<b>Catégories :</b> {", ".join(sorted({_category_for(f.rule_id) for f in findings}))}</p>

<div class="kpi-row">{sev_rows}</div>

{e2e_block}

<h2>Top 25 rules déclenchées</h2>
<table>
<tr><th>Rule ID</th><th>#</th><th>Catégorie</th><th>Sévérité</th></tr>
{rule_rows}
</table>

<h2>Détail des findings (top 80)</h2>
<table>
<tr><th>Rule</th><th>Sévérité</th><th>Message</th></tr>
{findings_rows}
</table>

<div class="footer">iAct8 Defender v{TOOL_VERSION} &middot; offline report &middot; for blue teams</div>
</body>
</html>"""


def write_pdf(findings: List[Finding], out_path: Path, *, e2e_report: Optional[Dict[str, Any]] = None) -> Path:
    """Write a self-contained HTML next to a `.pdf.txt` marker.

    This module does NOT bundle a full HTML→PDF engine (would add ~30 MB of
    weasyprint/wkhtmltopdf). Instead, it writes a print-styled HTML that
    opens correctly in any browser and is fed to:
        * Microsoft Print to PDF (Windows)
        * Chrome/Edge's "Save as PDF"
        * `wkhtmltopdf` if installed
    The function returns the path of the HTML — pass it to a PDF converter
    externally. The PDF-side artefact name is offered as `<stem>.pdf.html`.
    """
    out_path = Path(out_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    html = build_pdf_html(findings=findings, e2e_report=e2e_report)
    out_path.write_text(html, encoding="utf-8")
    log.info("Wrote PDF-friendly HTML: %s (%d findings)", out_path, len(findings))
    return out_path


# --------------------------------------------------------------------------- #
# Loading findings from disk (e2e_report.json + mock log)
# --------------------------------------------------------------------------- #

def load_findings_from_logs(repro_root: Path) -> List[Finding]:
    """Aggregate defender hits from logs/ artefacts.

    The mock server logs each request as JSON. The defender is invoked when
    middleware is not disabled; its verdicts surface in two places:

    1. ``lab_mode.defender_hits`` — dict of BY-XXX-NNN → count (per request)
    2. ``validation_error`` — a single free-form reason string (rare)

    Both feeds are merged into a flat :class:`Finding` list. We deduplicate
    by (rule_id, uri) so a single rule that fires 5 times is one finding.
    """
    repro_root = Path(repro_root).resolve()
    seen: Dict[Tuple[str, str], Finding] = {}

    def _record(rule_id: str, message: str, uri: str, severity: Optional[str] = None) -> None:
        key = (rule_id, uri)
        if key in seen:
            return
        seen[key] = Finding(
            rule_id=rule_id,
            message=message,
            severity=severity or _infer_severity(rule_id),
            uri=uri,
            location=uri,
            snippet=message,
        )

    # 1. Walk every smoke log under logs/smoke_*/
    for p in (repro_root / "logs").glob("smoke_*/mock_server_requests.jsonl"):
        for line in p.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            uri = row.get("path", "mock://albert.apple.com")
            lab_mode = row.get("lab_mode") or {}
            for rid, n in (lab_mode.get("defender_hits") or {}).items():
                if not isinstance(rid, str) or not isinstance(n, int):
                    continue
                if n <= 0:
                    continue
                _record(rid, f"Defender hit {rid} x{n} on {uri}", uri)
            for reason in (row.get("reasons") or []):
                for finding in parse_reasons([reason], default_uri=uri):
                    _record(finding.rule_id, finding.message, finding.uri, finding.severity)
            for reason_str in (row.get("validation_error") or "",):
                if reason_str:
                    for finding in parse_reasons([reason_str], default_uri=uri):
                        _record(finding.rule_id, finding.message, finding.uri, finding.severity)

    # 2. Pull aggregated counts from yara_report.json (BY-INT-* family)
    yara = repro_root / "logs" / "yara_report.json"
    if yara.is_file():
        try:
            doc = json.loads(yara.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            doc = None
        if doc:
            for rid, n in (doc.get("by_rule") or {}).items():
                _record(rid, f"YARA rule {rid} fired {n}x", "yara://scan", severity="medium")

    return list(seen.values())


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="iact_report_export",
        description="Export defender findings as SARIF 2.1.0 and print-styled HTML for PDF.",
    )
    p.add_argument("--repro-root", default="06_LOCAL_REPRODUCER", help="lab root")
    p.add_argument("--out-dir", default=None, help="output dir (default: <repro_root>/logs)")
    p.add_argument("--format", default="both", choices=["sarif", "pdf", "both"])
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    repro_root = Path(args.repro_root).resolve()
    out_dir = Path(args.out_dir).resolve() if args.out_dir else repro_root / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)

    findings = load_findings_from_logs(repro_root)
    if not findings:
        log.warning("No findings found. Run e2e.py first.")

    e2e_report: Optional[Dict[str, Any]] = None
    e2e = repro_root / "logs" / "e2e_report.json"
    if e2e.is_file():
        try:
            e2e_report = json.loads(e2e.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            e2e_report = None

    if args.format in ("sarif", "both"):
        write_sarif(findings, out_dir / "defender_findings.sarif.json")
    if args.format in ("pdf", "both"):
        write_pdf(findings, out_dir / "defender_summary.pdf.html", e2e_report=e2e_report)

    print(f"Exported {len(findings)} findings to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
