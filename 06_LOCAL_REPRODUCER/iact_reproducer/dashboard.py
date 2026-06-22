# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/dashboard.py
"""Generate a self-contained HTML dashboard for the iAct8 reproducer.

Pulls the corpus manifest, YARA report, mock-server log and PCAP info
together into a single HTML page that a defender can open in a browser
to get a one-glance view of the lab state. The page is fully static
(no JavaScript needed) and uses inline CSS so it can be archived.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import logging
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

log = logging.getLogger("iact_dashboard")

TEST_MARKER = "iRemovalOFFENSIVE Test"


# --------------------------------------------------------------------------- #
# Loaders
# --------------------------------------------------------------------------- #

def _safe_load_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _safe_load_csv(path: Path) -> List[Dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _read_jsonl_tail(path: Path, limit: int = 20) -> List[Dict[str, Any]]:
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    rows: List[Dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

_CSS = """
:root { color-scheme: light dark; }
body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
       margin: 0; padding: 24px; background: #0f172a; color: #e2e8f0; }
h1, h2, h3 { color: #f8fafc; }
h1 { border-bottom: 2px solid #334155; padding-bottom: 8px; }
.card { background: #1e293b; border: 1px solid #334155; border-radius: 8px;
        padding: 16px; margin: 16px 0; }
.kpi-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 12px; }
.kpi { background: #0b1220; border: 1px solid #334155; border-radius: 6px;
       padding: 12px; }
.kpi .label { color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
.kpi .value { color: #38bdf8; font-size: 22px; font-weight: 600; margin-top: 4px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 6px 8px; border-bottom: 1px solid #334155; text-align: left;
         font-size: 13px; }
th { color: #94a3b8; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 9999px;
         font-size: 11px; font-weight: 600; }
.badge.pos { background: #064e3b; color: #6ee7b7; }
.badge.neg { background: #7f1d1d; color: #fca5a5; }
.badge.marker { background: #312e81; color: #c4b5fd; }
code { background: #0b1220; padding: 2px 6px; border-radius: 4px;
       font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; }
.muted { color: #94a3b8; }
.mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; }
.footer { color: #475569; font-size: 11px; margin-top: 32px; text-align: center; }
"""


def _html_page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>iAct8 reproducer — OFFENSIVE  dashboard <span class="badge marker">{html.escape(TEST_MARKER)}</span></h1>
{body}
<div class="footer">
Generated {datetime.utcnow().isoformat()}Z &middot; iAct8 local reproducer v1.0 &middot; for blue teams
</div>
</body>
</html>"""


def _kpi(label: str, value: str) -> str:
    return (
        f'<div class="kpi"><div class="label">{html.escape(label)}</div>'
        f'<div class="value">{html.escape(value)}</div></div>'
    )


# --------------------------------------------------------------------------- #
# Builder
# --------------------------------------------------------------------------- #

def build_dashboard(
    *,
    repro_root: Path,
    out_path: Path,
) -> Path:
    repro_root = Path(repro_root).resolve()
    out_path = Path(out_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    corpus_dir = repro_root / "corpus"
    keys_dir = repro_root / "keys"
    requests_dir = repro_root / "requests"
    responses_dir = repro_root / "responses"
    logs_dir = repro_root / "logs"

    summary = _safe_load_json(corpus_dir / "corpus_summary.json")
    manifest = _safe_load_csv(corpus_dir / "corpus_manifest.csv")
    yara = _safe_load_json(logs_dir / "yara_report.json")
    mock_log = _read_jsonl_tail(logs_dir / "mock_server_requests.jsonl", limit=10)
    pcap = logs_dir / "iact8_traffic.pcap"
    pcap_info = "present, " + _human_size(pcap.stat().st_size) if pcap.is_file() else "missing"

    # ----------------- KPIs ----------------- #
    kpis = []
    kpis.append(_kpi("Corpus variants", str(summary.get("total_variants", 0)) if summary else "n/a"))
    if summary:
        for label, n in summary.get("by_label", {}).items():
            kpis.append(_kpi(f"  ↳ {label}", str(n)))
    if yara:
        kpis.append(_kpi("YARA scanned", str(yara.get("scanned", 0))))
        kpis.append(_kpi("YARA matched", str(yara.get("matched", 0))))
        for rule, n in yara.get("by_rule", {}).items():
            kpis.append(_kpi(f"  ↳ {rule}", str(n)))
    kpis.append(_kpi("PCAP", pcap_info))
    kpis.append(_kpi("Mock-server requests (last 10)", str(len(mock_log))))

    kpi_html = '<div class="kpi-grid">' + "".join(kpis) + "</div>"

    # ----------------- Manifest table ----------------- #
    table_rows = []
    for row in manifest[:200]:
        label_cls = "pos" if row.get("label") == "positive" else "neg"
        table_rows.append(
            "<tr>"
            f"<td class='mono'>{html.escape(row.get('variant_id', ''))}</td>"
            f"<td><span class='badge {label_cls}'>{html.escape(row.get('label', ''))}</span></td>"
            f"<td class='mono'>{html.escape(row.get('hash_name', ''))}</td>"
            f"<td class='mono'>{html.escape(row.get('udid', ''))}</td>"
            f"<td class='mono'>{row.get('bplist_size', '')}</td>"
            f"<td class='mono'>{row.get('signature_size', '')}</td>"
            f"<td class='mono'>{html.escape(row.get('description', ''))}</td>"
            "</tr>"
        )
    manifest_html = (
        '<div class="card">'
        '<h2>Corpus manifest (first 200)</h2>'
        '<table>'
        '<tr><th>ID</th><th>Label</th><th>Hash</th><th>UDID</th>'
        '<th>bplist</th><th>sig</th><th>Notes</th></tr>'
        + "".join(table_rows)
        + '</table>'
        '</div>'
    )

    # ----------------- YARA matches ----------------- #
    yara_html = '<div class="card"><h2>YARA report (top 25)</h2>'
    if yara:
        rows = []
        for a in yara.get("artefacts", [])[:25]:
            real = [m for m in a.get("matches", []) if "error" not in m]
            label_cls = "pos" if a.get("label") == "positive" else "neg"
            rules = ", ".join(sorted({m["rule"] for m in real})) or "—"
            rows.append(
                "<tr>"
                f"<td class='mono'>{html.escape(a.get('artefact', ''))}</td>"
                f"<td><span class='badge {label_cls}'>{html.escape(a.get('label', ''))}</span></td>"
                f"<td class='mono'>{html.escape(rules)}</td>"
                f"<td class='mono'>{len(real)}</td>"
                "</tr>"
            )
        yara_html += (
            '<table>'
            '<tr><th>Artefact</th><th>Label</th><th>Rules fired</th><th>#</th></tr>'
            + "".join(rows)
            + '</table>'
        )
    else:
        yara_html += '<p class="muted">No YARA report found. Run <code>yara_runner.py</code> first.</p>'
    yara_html += '</div>'

    # ----------------- Mock log ----------------- #
    mock_html = '<div class="card"><h2>Mock server — last 10 requests</h2>'
    if mock_log:
        rows = []
        for r in mock_log:
            ok = r.get("validation_ok")
            cls = "pos" if ok else "neg"
            rows.append(
                "<tr>"
                f"<td class='mono'>{html.escape(r.get('ts', ''))}</td>"
                f"<td class='mono'>{html.escape(r.get('peer', ''))}</td>"
                f"<td class='mono'>{html.escape(r.get('path', ''))}</td>"
                f"<td><span class='badge {cls}'>{html.escape(str(r.get('outcome', '')))}</span></td>"
                f"<td class='mono'>{html.escape(r.get('raw_size', ''))}</td>"
                "</tr>"
            )
        mock_html += (
            '<table>'
            '<tr><th>ts</th><th>peer</th><th>path</th><th>outcome</th><th>bytes</th></tr>'
            + "".join(rows) + '</table>'
        )
    else:
        mock_html += '<p class="muted">No requests logged. Start <code>mock_server.py</code> and exercise it.</p>'
    mock_html += '</div>'

    # ----------------- File index ----------------- #
    file_index_rows = []
    for sub in (keys_dir, requests_dir, responses_dir, corpus_dir, logs_dir):
        if not sub.is_dir():
            continue
        for f in sorted(sub.rglob("*")):
            if f.is_file():
                file_index_rows.append(
                    f"<tr><td class='mono'>{html.escape(str(f.relative_to(repro_root)))}</td>"
                    f"<td class='mono'>{_human_size(f.stat().st_size)}</td></tr>"
                )
    file_index_html = (
        '<div class="card"><h2>Artefact index</h2>'
        '<table><tr><th>Path</th><th>Size</th></tr>'
        + "".join(file_index_rows)
        + '</table></div>'
    )

    body = (
        kpi_html
        + manifest_html
        + yara_html
        + mock_html
        + file_index_html
    )
    out_path.write_text(_html_page("iAct8 OFFENSIVE  dashboard", body), encoding="utf-8")
    log.info("Wrote dashboard: %s", out_path)
    return out_path


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="iact_dashboard",
        description=(
            "Render a static HTML dashboard summarising the corpus, "
            "YARA report, mock-server log and artefact index."
        ),
    )
    p.add_argument("--repro-root", default="06_LOCAL_REPRODUCER")
    p.add_argument("--out", default="06_LOCAL_REPRODUCER/logs/dashboard.html")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    out = build_dashboard(
        repro_root=Path(args.repro_root).resolve(),
        out_path=Path(args.out).resolve(),
    )
    print()
    print(f"Dashboard: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
