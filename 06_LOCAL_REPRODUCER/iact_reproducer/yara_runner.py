# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/yara_runner.py
"""Run the YARA rules from ``05_IOC/YARA_RULES.yar`` against our corpus.

This module loads the iRemoval YARA rule set and scans every artefact
produced by :mod:`corpus_generator`. It produces a JSON report with
per-rule, per-artefact match results so detection engineers can:

  * see which of their rules fire on the labelled corpus
  * confirm the **positive** examples hit at least one rule
  * confirm the **negative** (tampered) examples do **not** hit
    rules that would cause false positives in a real deployment

Requires ``yara-python`` (already installed in this environment).
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

import yara  # type: ignore

log = logging.getLogger("iact_yara")

TEST_MARKER = "iRemovalOFFENSIVE Test"

DEFAULT_RULES_PATH = Path("05_IOC/YARA_RULES.yar")
DEFAULT_RULES_EXTRA = Path("05_IOC/YARA_RULES_WIRE.yar")
DEFAULT_CORPUS_DIR = Path("06_LOCAL_REPRODUCER/corpus")


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #

@dataclass
class ArtefactResult:
    artefact: str
    label: str
    matches: List[Dict[str, str]] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class YaraReport:
    rules_paths: List[str]
    corpus_dir: str
    scanned: int
    matched: int
    by_rule: Dict[str, int]
    by_label: Dict[str, int]
    artefacts: List[ArtefactResult]

    def to_dict(self) -> dict:
        return {
            "rules_paths": self.rules_paths,
            "corpus_dir": self.corpus_dir,
            "scanned": self.scanned,
            "matched": self.matched,
            "by_rule": self.by_rule,
            "by_label": self.by_label,
            "artefacts": [asdict(a) for a in self.artefacts],
        }


# --------------------------------------------------------------------------- #
# Core
# --------------------------------------------------------------------------- #

def _load_rules(rules_paths: List[Path]) -> yara.Rules:
    """Compile one or more YARA files into a single namespace."""
    if not rules_paths:
        raise ValueError("No YARA rules paths provided")
    sources = {f"ns{i}": str(p) for i, p in enumerate(rules_paths)}
    return yara.compile(filepaths=sources)


def _scan_file(rules: yara.Rules, file_path: Path) -> List[Dict[str, str]]:
    matches: List[Dict[str, str]] = []
    try:
        for m in rules.match(str(file_path)):
            for s in m.strings:
                # ``s`` is a YARA StringMatch; we only keep short snippets
                # to keep the report readable.
                instances = getattr(s, "instances", None) or []
                if instances:
                    sample = instances[0]
                    snippet = getattr(sample, "matched_data", b"")[:64]
                    offset_str = str(sample.offset)
                else:
                    snippet = b""
                    offset_str = "0"
                matches.append({
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "meta_severity": m.meta.get("severity", ""),
                    "meta_description": m.meta.get("description", ""),
                    "string_identifier": s.identifier,
                    "string_offset": offset_str,
                    "snippet_hex": snippet.hex(),
                })
    except yara.Error as exc:
        return [{"error": str(exc)}]
    return matches


def _label_for(file_path: Path, corpus_dir: Path) -> str:
    """Infer the corpus label from the parent directory name."""
    rel = file_path.relative_to(corpus_dir)
    parts = rel.parts
    if len(parts) >= 2:
        return parts[0]
    return "unknown"


def run_scan(
    rules_paths: List[Path],
    corpus_dir: Path = DEFAULT_CORPUS_DIR,
) -> YaraReport:
    """Scan every artefact under ``corpus_dir`` with the given rules."""
    rules_paths = [Path(p).resolve() for p in rules_paths]
    corpus_dir = Path(corpus_dir).resolve()

    rules = _load_rules(rules_paths)
    log.info("Loaded YARA rules from %s", rules_paths)

    artefacts: List[ArtefactResult] = []
    by_rule: Dict[str, int] = {}
    by_label: Dict[str, int] = {}
    matched = 0
    scanned = 0

    for path in sorted(corpus_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in {".bplist", ".json", ".sig", ".pem", ".der", ".pcap"}:
            continue
        scanned += 1
        label = _label_for(path, corpus_dir)
        matches = _scan_file(rules, path)
        # Drop the error-marker entries from the "match count" tally.
        real_matches = [m for m in matches if "error" not in m]
        if real_matches:
            matched += 1
            for m in real_matches:
                by_rule[m["rule"]] = by_rule.get(m["rule"], 0) + 1
        by_label[label] = by_label.get(label, 0) + 1
        artefacts.append(ArtefactResult(
            artefact=str(path),
            label=label,
            matches=matches,
        ))

    return YaraReport(
        rules_paths=[str(p) for p in rules_paths],
        corpus_dir=str(corpus_dir),
        scanned=scanned,
        matched=matched,
        by_rule=by_rule,
        by_label=by_label,
        artefacts=artefacts,
    )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="iact_yara_runner",
        description=(
            "Run 05_IOC/YARA_RULES*.yar against the OFFENSIVE  corpus and "
            "produce a JSON + CSV detection report."
        ),
    )
    p.add_argument(
        "--rules", nargs="+",
        default=[str(DEFAULT_RULES_PATH), str(DEFAULT_RULES_EXTRA)],
        help="One or more YARA rule files.",
    )
    p.add_argument("--corpus", default=str(DEFAULT_CORPUS_DIR))
    p.add_argument("--out-json", default="06_LOCAL_REPRODUCER/logs/yara_report.json")
    p.add_argument("--out-csv", default="06_LOCAL_REPRODUCER/logs/yara_report.csv")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    report = run_scan(
        rules_paths=[Path(r) for r in args.rules],
        corpus_dir=Path(args.corpus).resolve(),
    )

    out_json = Path(args.out_json).resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

    out_csv = Path(args.out_csv).resolve()
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["artefact", "label", "rules_fired", "match_count"])
        for a in report.artefacts:
            real = [m for m in a.matches if "error" not in m]
            w.writerow([
                a.artefact, a.label,
                "|".join(sorted({m["rule"] for m in real})),
                len(real),
            ])

    print()
    print("=" * 72)
    print(" YARA detection report")
    print("=" * 72)
    for rp in report.rules_paths:
        print(f"  Rule         : {rp}")
    print(f"  Corpus      : {report.corpus_dir}")
    print(f"  Scanned     : {report.scanned}")
    print(f"  Matched ≥1  : {report.matched}")
    print(f"  By label    : {report.by_label}")
    print(f"  By rule     : {report.by_rule}")
    print(f"  JSON report : {out_json}")
    print(f"  CSV report  : {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
