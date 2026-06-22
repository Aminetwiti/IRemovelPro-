# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/run_lab.py
"""One-shot orchestrator: corpus -> YARA -> PCAP -> dashboard.

Runs the full OFFENSIVE  lab in a single command:

    python 06_LOCAL_REPRODUCER\\iact_reproducer\\run_lab.py
        --samples 30                # positive envelope variants
        # negatives auto-generated for every 5 positives
        # YARA rules from 05_IOC/YARA_RULES.yar
        # PCAP written to logs/iact8_traffic.pcap
        # Dashboard written to logs/dashboard.html

Then optionally start the mock server in a separate terminal::

    python 06_LOCAL_REPRODUCER\\iact_reproducer\\mock_server.py
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from iact_reproducer import (  # noqa: E402
    corpus_generator,
    dashboard,
    orchestrator,
    pcap_writer,
    yara_runner,
)

log = logging.getLogger("iact_lab")

TEST_MARKER = "iRemovalOFFENSIVE Test"


def _step(title: str) -> None:
    bar = "=" * 72
    print(f"\n{bar}\n {title}\n{bar}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="iact_lab",
        description=(
            "One-shot orchestrator for the iAct8 OFFENSIVE  lab. "
            f"Every artefact is tagged {TEST_MARKER!r}."
        ),
    )
    p.add_argument("--repro-root", default="06_LOCAL_REPRODUCER")
    p.add_argument("--samples", type=int, default=30,
                   help="Number of positive envelope variants to generate.")
    p.add_argument("--no-negatives", action="store_true")
    p.add_argument("--skip-pcap", action="store_true")
    p.add_argument("--pcap-limit", type=int, default=20)
    p.add_argument("--skip-yara", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    repro_root = Path(args.repro_root).resolve()
    keys_dir = repro_root / "keys"
    corpus_dir = repro_root / "corpus"
    logs_dir = repro_root / "logs"
    for d in (keys_dir, corpus_dir, logs_dir):
        d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    _step("Step 0/5 - single clean reference artefact")
    base = orchestrator.run_pipeline(out_root=repro_root, hash_name="sha256")
    print(f"  bplist00  : {base.bplist_path}")
    print(f"  envelope  : {base.envelope_path}")

    # ------------------------------------------------------------------ #
    _step("Step 1/5 - generating labelled corpus")
    t0 = time.perf_counter()
    artefacts = corpus_generator.generate_corpus(
        out_dir=corpus_dir,
        samples=args.samples,
        include_negatives=not args.no_negatives,
        key_dir=keys_dir,
    )
    print(f"  -> {len(artefacts)} variants in {time.perf_counter() - t0:.1f}s")

    # ------------------------------------------------------------------ #
    if not args.skip_yara:
        _step("Step 2/5 - running YARA rules (binary + wire format)")
        report = yara_runner.run_scan(
            rules_paths=[
                Path("05_IOC/YARA_RULES.yar").resolve(),
                Path("05_IOC/YARA_RULES_WIRE.yar").resolve(),
            ],
            corpus_dir=corpus_dir,
        )
        out_json = logs_dir / "yara_report.json"
        out_json.write_text(
            __import__("json").dumps(report.to_dict(), indent=2),
            encoding="utf-8",
        )
        print(f"  scanned : {report.scanned}")
        print(f"  matched : {report.matched}")
        print(f"  by rule : {report.by_rule}")
        print(f"  -> {out_json}")
    else:
        _step("Step 2/5 - YARA scan (skipped)")

    # ------------------------------------------------------------------ #
    if not args.skip_pcap:
        _step("Step 3/5 - synthesising PCAP traffic")
        out_pcap = logs_dir / "iact8_traffic.pcap"
        # Re-load envelopes from the corpus.
        import json
        from iact_reproducer import wire_format
        envs = []
        for jp in sorted(corpus_dir.rglob("*.json")):
            if jp.name == "corpus_summary.json":
                continue
            try:
                raw = json.loads(jp.read_text(encoding="utf-8"))
                envs.append(wire_format.IActEnvelope(**raw))
            except Exception:
                continue
            if len(envs) >= args.pcap_limit:
                break
        pcap_writer.synth_pcap(envs, out_pcap)
        print(f"  -> {out_pcap} ({out_pcap.stat().st_size} bytes, {len(envs)} exchanges)")
    else:
        _step("Step 3/5 - PCAP synthesis (skipped)")

    # ------------------------------------------------------------------ #
    _step("Step 4/5 - rendering HTML dashboard")
    out_html = logs_dir / "dashboard.html"
    dashboard.build_dashboard(repro_root=repro_root, out_path=out_html)
    print(f"  -> {out_html}")

    # ------------------------------------------------------------------ #
    _step("Step 5/5 - done")
    print(f"  Reproduction root : {repro_root}")
    print(f"  Open the dashboard : file:///{str(out_html).replace(chr(92), '/')}")
    print(f"  Optional next step : start the mock server with mock_server.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
