"""Self-test for 05_IOC/YARA_RULES.yar.

Goals
-----
1. The whole rule file compiles without syntax errors.
2. The file contains the new defensive rule `iRemovalPro_ChaosCrypto_Namespace`
   announced in §17.5 / §17.6 of NOUVELLES_DECOUVERTES.md.
3. The `Chaos.Crypto` rule fires on a synthetic sample that embeds the
   `An assertion in Chaos.Crypto failed` string (the exact .NET Debug.Assert
   blob found in both the Windows DLL and the iOS Mono dylib).
4. The rule does NOT fire on a clean control blob (no false positive).
5. The consolidated canonical rule is unique (the old duplicate
   `iRemovalPro_AntiRE_Chaos_Crypto` was removed during cleanup).

Run from anywhere::

    PYTHONIOENCODING=utf-8 python test_yara_rules_load.py
    PYTHONIOENCODING=utf-8 python test_yara_rules_load.py --verbose

Exit code 0 on success, 1 on any failure. Stdlib only + yara-python.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

try:
    import yara  # type: ignore
except ImportError as exc:  # pragma: no cover
    print(f"[FATAL] yara-python is required: {exc}", file=sys.stderr)
    raise SystemExit(2)


_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR  # 06_LOCAL_REPRODUCER/ (test lives next to its peers)
_PROJECT_ROOT = _PKG_ROOT.parent
YARA_FILE = (_PROJECT_ROOT / "05_IOC" / "YARA_RULES.yar").resolve()


# -- Check helpers ---------------------------------------------------------- #

class Check:
    __slots__ = ("label", "ok", "detail")

    def __init__(self, label: str, ok: bool, detail: str = "") -> None:
        self.label = label
        self.ok = ok
        self.detail = detail


def _check_compile() -> Check:
    try:
        rules = yara.compile(filepath=str(YARA_FILE))
    except yara.SyntaxError as exc:  # type: ignore[attr-defined]
        return Check("C1 YARA file compiles", False, f"SyntaxError: {exc}")
    except yara.Error as exc:  # type: ignore[attr-defined]
        return Check("C1 YARA file compiles", False, f"YARA error: {exc}")
    return Check("C1 YARA file compiles", True, str(YARA_FILE))


def _check_chaos_rule_present() -> Check:
    # yara-python doesn't expose rule names through the public compiled
    # object, so we fall back to a textual source-level check. This is
    # good enough for our purposes — the rule name MUST appear in the
    # source even if someone refactors.
    text = YARA_FILE.read_text(encoding="utf-8")
    if "rule iRemovalPro_ChaosCrypto_Namespace" not in text:
        return Check(
            "C2 rule iRemovalPro_ChaosCrypto_Namespace is defined",
            False,
            "rule header not found in YARA source",
        )
    return Check(
        "C2 rule iRemovalPro_ChaosCrypto_Namespace is defined",
        True,
        "rule header found",
    )


def _check_duplicate_removed() -> Check:
    text = YARA_FILE.read_text(encoding="utf-8")
    if "rule iRemovalPro_AntiRE_Chaos_Crypto" in text:
        return Check(
            "C3 duplicate iRemovalPro_AntiRE_Chaos_Crypto was removed",
            False,
            "stale duplicate rule still in YARA source",
        )
    return Check(
        "C3 duplicate iRemovalPro_AntiRE_Chaos_Crypto was removed",
        True,
        "consolidated into ChaosCrypto_Namespace",
    )


def _check_match_forgery_sample(rules: "yara.Rules") -> Check:
    """Synthetic sample = .NET Debug.Assert blob with the Chaos.Crypto string."""
    blob = (
        b"An action was attempted during deserialization that could lead to a "
        b"security vulnerability. The action has been aborted. To allow the action, "
        b"set the 'Switch.Legacy{0}' AppContext switch to true. "
        b"An assertion in Chaos.Crypto failed. "
        b"An async read operation has already been started on the stream."
    )
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
        fh.write(blob)
        sample_path = fh.name
    try:
        hits = list(rules.match(sample_path))
        matching_names = {h.rule for h in hits}
        if "iRemovalPro_ChaosCrypto_Namespace" not in matching_names:
            return Check(
                "C4 Chaos.Crypto sample matches iRemovalPro_ChaosCrypto_Namespace",
                False,
                f"matched rules: {sorted(matching_names) or 'none'}",
            )
        return Check(
            "C4 Chaos.Crypto sample matches iRemovalPro_ChaosCrypto_Namespace",
            True,
            f"also matched: {sorted(matching_names)}",
        )
    finally:
        Path(sample_path).unlink(missing_ok=True)


def _check_no_false_positive(rules: "yara.Rules") -> Check:
    """Clean control = random printable ASCII + some unicode but NO iRemoval IoC."""
    import random
    random.seed(20260622)
    blob = bytes(
        (random.choice(range(0x20, 0x7E)) for _ in range(4096))
    )
    # Make sure the seed does not accidentally include any of our strings.
    forbidden_substrings = [
        b"Chaos.Crypto",
        b"s13.iremovalpro.com",
        b"com.panyolsoft.blackhound",
        b"Blackhound iRemovalPro",
        b"iRemovalRecord",
        b"iRemovalSignature",
    ]
    for needle in forbidden_substrings:
        if needle in blob:
            return Check(
                "C5 clean control yields no false positive",
                False,
                f"control blob accidentally contained {needle!r}; reseed",
            )
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
        fh.write(blob)
        sample_path = fh.name
    try:
        hits = list(rules.match(sample_path))
        matching_names = {h.rule for h in hits}
        # Filter out rules that intentionally match anything-PEZ (e.g.
        # BuildMarker_Generic which only needs an MZ + a few strings —
        # our control has no MZ so it should NOT match any iRemoval rule).
        false_positives = {
            n for n in matching_names if n.startswith("iRemovalPro_")
        }
        if false_positives:
            return Check(
                "C5 clean control yields no false positive",
                False,
                f"unexpected matches: {sorted(false_positives)}",
            )
        return Check(
            "C5 clean control yields no false positive",
            True,
            f"clean control matched {len(matching_names)} unrelated rule(s)",
        )
    finally:
        Path(sample_path).unlink(missing_ok=True)


# -- Runner ----------------------------------------------------------------- #

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="YARA_RULES.yar self-test (compile + ChaosCrypto sanity).",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    started = time.monotonic()
    if not YARA_FILE.exists():
        print(f"[FATAL] YARA file not found: {YARA_FILE}", file=sys.stderr)
        return 2

    checks: list[Check] = []
    checks.append(_check_compile())
    # All subsequent checks need the compiled rules object.
    rules = yara.compile(filepath=str(YARA_FILE))
    checks.append(_check_chaos_rule_present())
    checks.append(_check_duplicate_removed())
    checks.append(_check_match_forgery_sample(rules))
    checks.append(_check_no_false_positive(rules))

    passed = sum(1 for c in checks if c.ok)
    total = len(checks)
    elapsed = time.monotonic() - started

    bar = "=" * 78
    print(bar)
    print(f"  YARA loader self-test — 05_IOC/YARA_RULES.yar")
    print(f"  file : {YARA_FILE}")
    print(bar)
    for c in checks:
        mark = "[OK]" if c.ok else "[X]"
        print(f"  {mark:<5} {c.label}")
        if args.verbose or not c.ok:
            print(f"        -> {c.detail}")
    print(bar)
    print(f"  checks : {passed}/{total} pass")
    print(f"  elapsed: {elapsed:.2f}s")
    print(bar)
    if passed != total:
        print(">>>  RESULT: FAIL")
        return 1
    print(">>>  RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())