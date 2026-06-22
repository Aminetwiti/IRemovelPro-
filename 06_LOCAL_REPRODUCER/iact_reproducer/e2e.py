# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/e2e.py
"""Unified end-to-end runner for the iAct8 OFFENSIVE  lab.

This is a thin orchestrator that wires together the two existing
pieces of the lab:

    1. ``run_lab``        — static pipeline (corpus + YARA + PCAP +
                            dashboard)
    2. ``smoke_apple_drm`` — dynamic pipeline (mock server +
                            /apple_drm_check.ph endpoint +
                            3-scenario smoke test)

After both pipelines finish, this script writes a single,
machine-parseable JSON summary at ``logs/e2e_report.json`` so a
defender can attach the whole run to a SIEM ticket or a CI artefact.

Usage::

    # Default (small corpus, all guards enabled)
    python 06_LOCAL_REPRODUCER\\iact_reproducer\\e2e.py

    # Fast CI mode (skip YARA + PCAP for speed)
    python 06_LOCAL_REPRODUCER\\iact_reproducer\\e2e.py --skip-yara --skip-pcap

    # Larger corpus
    python 06_LOCAL_REPRODUCER\\iact_reproducer\\e2e.py --samples 50

Exit code is ``0`` only if every stage reports success.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from iact_reproducer import dashboard, run_lab, smoke_apple_drm  # noqa: E402

log = logging.getLogger("iact_e2e")

TEST_MARKER = "iRemovalOFFENSIVE Test"
REPORT_VERSION = "1.0.0"


@dataclass
class StageResult:
    """Result of a single pipeline stage."""

    name: str
    ok: bool
    started_at: str
    finished_at: str
    duration_seconds: float
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


def _step(title: str) -> None:
    bar = "=" * 72
    print(f"\n{bar}\n {title}\n{bar}")


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def run_static_lab(args: argparse.Namespace, repro_root: Path) -> StageResult:
    """Invoke run_lab.main with the same flags, capture outcome."""
    started = _utc_now()
    t0 = time.monotonic()
    details: Dict[str, Any] = {"args": vars(args), "artifacts": {}}
    error: Optional[str] = None
    ok = True
    try:
        argv: List[str] = ["--repro-root", str(repro_root)]
        if args.samples:
            argv += ["--samples", str(args.samples)]
        if args.skip_yara:
            argv += ["--skip-yara"]
        if args.skip_pcap:
            argv += ["--skip-pcap"]
        rc = run_lab.main(argv)
        if rc != 0:
            ok = False
            error = f"run_lab.main returned {rc}"

        # Capture generated artefacts for the report.
        corpus_summary = repro_root / "corpus" / "corpus_summary.json"
        if corpus_summary.is_file():
            details["artifacts"]["corpus_summary"] = str(corpus_summary)
        yara_report = repro_root / "logs" / "yara_report.json"
        if yara_report.is_file():
            details["artifacts"]["yara_report"] = str(yara_report)
        pcap = repro_root / "logs" / "iact8_traffic.pcap"
        if pcap.is_file():
            details["artifacts"]["pcap"] = str(pcap)
            details["pcap_bytes"] = pcap.stat().st_size
        dash_html = repro_root / "logs" / "dashboard.html"
        if dash_html.is_file():
            details["artifacts"]["dashboard"] = str(dash_html)
            details["dashboard_bytes"] = dash_html.stat().st_size
    except Exception:
        ok = False
        error = traceback.format_exc()
    return StageResult(
        name="static_lab",
        ok=ok,
        started_at=started,
        finished_at=_utc_now(),
        duration_seconds=round(time.monotonic() - t0, 3),
        details=details,
        error=error,
    )


def run_dynamic_smoke(args: argparse.Namespace, repro_root: Path) -> StageResult:
    """Invoke smoke_apple_drm.main, capture counters from stdout."""
    started = _utc_now()
    t0 = time.monotonic()
    details: Dict[str, Any] = {"artifacts": {}, "scenarios": {}}
    error: Optional[str] = None
    ok = True
    try:
        rc = smoke_apple_drm.main()
        if rc != 0:
            ok = False
            error = f"smoke_apple_drm.main returned {rc}"
    except SystemExit as exc:
        if exc.code != 0:
            ok = False
            error = f"smoke_apple_drm exited with code {exc.code}"
    except Exception:
        ok = False
        error = traceback.format_exc()

    # Find the latest smoke_<ts> log dir and aggregate defender hits.
    smoke_logs = sorted(
        (repro_root / "logs").glob("smoke_*"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if smoke_logs:
        log_dir = smoke_logs[0]
        details["artifacts"]["smoke_log_dir"] = str(log_dir)
        for jl in log_dir.glob("mock_server_requests.jsonl"):
            details["artifacts"]["mock_log"] = str(jl)
            with jl.open(encoding="utf-8") as fh:
                for line in fh:
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    path = rec.get("path", "")
                    outcome = rec.get("outcome", "")
                    if "apple_drm_check.ph" in path:
                        details["scenarios"][rec.get("request_id", "?")] = {
                            "outcome": outcome,
                            "validation_ok": rec.get("validation_ok"),
                            "reasons_count": len(rec.get("defender_reasons") or []),
                            "reasons": rec.get("defender_reasons") or [],
                            "defender_version": rec.get("defender_version"),
                        }

    return StageResult(
        name="dynamic_smoke",
        ok=ok,
        started_at=started,
        finished_at=_utc_now(),
        duration_seconds=round(time.monotonic() - t0, 3),
        details=details,
        error=error,
    )


def render_dashboard(repro_root: Path, out_path: Path) -> StageResult:
    """Regenerate the dashboard with the new KPIs (YARA/SIGMA counts etc.)."""
    started = _utc_now()
    t0 = time.monotonic()
    error: Optional[str] = None
    ok = True
    try:
        dashboard.build_dashboard(repro_root=repro_root, out_path=out_path)
    except Exception:
        ok = False
        error = traceback.format_exc()
    return StageResult(
        name="dashboard_render",
        ok=ok,
        started_at=started,
        finished_at=_utc_now(),
        duration_seconds=round(time.monotonic() - t0, 3),
        details={"dashboard": str(out_path)},
        error=error,
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="iact_e2e",
        description=(
            "End-to-end runner: static lab (run_lab) + dynamic smoke "
            "(smoke_apple_drm) + dashboard refresh. Writes a unified "
            "JSON report."
        ),
    )
    p.add_argument("--repro-root", default="06_LOCAL_REPRODUCER")
    p.add_argument("--samples", type=int, default=20,
                   help="Number of positive envelope variants for run_lab")
    p.add_argument("--skip-yara", action="store_true")
    p.add_argument("--skip-pcap", action="store_true")
    p.add_argument("--skip-smoke", action="store_true",
                   help="Skip the dynamic smoke test (mock server + defender)")
    p.add_argument("--skip-dashboard", action="store_true")
    p.add_argument("--dashboard-out",
                   default="06_LOCAL_REPRODUCER/dashboard_20260622_v2.html")
    p.add_argument("--report-out",
                   default="06_LOCAL_REPRODUCER/logs/e2e_report.json")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    repro_root = Path(args.repro_root).resolve()
    report_out = Path(args.report_out).resolve()
    dashboard_out = Path(args.dashboard_out).resolve()
    report_out.parent.mkdir(parents=True, exist_ok=True)

    _step(f"E2E runner — {TEST_MARKER}")
    print(f" repro_root : {repro_root}")
    print(f" samples    : {args.samples}")
    print(f" stages     : static_lab + dynamic_smoke + dashboard_render")

    stages: List[StageResult] = []
    overall_ok = True

    _step("Stage 1/3 — Static lab (corpus + YARA + PCAP)")
    static_res = run_static_lab(args, repro_root)
    stages.append(static_res)
    overall_ok = overall_ok and static_res.ok
    print(f"   {'OK ' if static_res.ok else 'FAIL'}  "
          f"duration={static_res.duration_seconds}s")

    if not args.skip_smoke:
        _step("Stage 2/3 — Dynamic smoke (mock server + defender)")
        smoke_res = run_dynamic_smoke(args, repro_root)
        stages.append(smoke_res)
        overall_ok = overall_ok and smoke_res.ok
        print(f"   {'OK ' if smoke_res.ok else 'FAIL'}  "
              f"duration={smoke_res.duration_seconds}s")
        # Summary of scenarios
        for rid, info in smoke_res.details.get("scenarios", {}).items():
            print(f"     • {rid[:24]}... outcome={info.get('outcome')} "
                  f"reasons={info.get('reasons_count')}")
    else:
        stages.append(StageResult(
            name="dynamic_smoke",
            ok=True,
            started_at=_utc_now(),
            finished_at=_utc_now(),
            duration_seconds=0.0,
            details={"skipped": True},
        ))
        print("   --  dynamic smoke skipped (--skip-smoke)")

    if not args.skip_dashboard:
        _step("Stage 3/3 — Dashboard render")
        dash_res = render_dashboard(repro_root, dashboard_out)
        stages.append(dash_res)
        overall_ok = overall_ok and dash_res.ok
        print(f"   {'OK ' if dash_res.ok else 'FAIL'}  "
              f"-> {dash_res.details.get('dashboard')}")
    else:
        stages.append(StageResult(
            name="dashboard_render",
            ok=True,
            started_at=_utc_now(),
            finished_at=_utc_now(),
            duration_seconds=0.0,
            details={"skipped": True},
        ))
        print("   --  dashboard skipped (--skip-dashboard)")

    # ----------------- Final report ----------------- #
    total_duration = sum(s.duration_seconds for s in stages)
    summary = {
        "report_version": REPORT_VERSION,
        "test_marker": TEST_MARKER,
        "generated_at": _utc_now(),
        "repro_root": str(repro_root),
        "overall_ok": overall_ok,
        "total_duration_seconds": round(total_duration, 3),
        "stages": [asdict(s) for s in stages],
    }

    report_out.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    _step("E2E summary")
    print(f" overall_ok        : {overall_ok}")
    print(f" total duration    : {total_duration:.2f}s")
    print(f" stages            : {len(stages)}")
    for s in stages:
        flag = "OK  " if s.ok else "FAIL"
        print(f"   [{flag}] {s.name:<20} {s.duration_seconds:6.2f}s")
    print(f" report            : {report_out}")
    if not args.skip_dashboard:
        print(f" dashboard         : {dashboard_out}")

    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())