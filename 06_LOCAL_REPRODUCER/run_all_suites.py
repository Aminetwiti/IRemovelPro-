#!/usr/bin/env python3
# filepath: 06_LOCAL_REPRODUCER/run_all_suites.py
"""
run_all_suites.py — Lab test runner (orchestrator) for the iRemoval PRO
v5.2 defensive extension.

Exécute les 5 suites de tests en série et produit un rapport PASS/FAIL
agrégé, avec code de sortie CI-friendly.

Suites (ordre d'exécution) :
  S1. apple_drm_defense.py --self-test       (13 checks)
  S2. test_apple_drm_defense.py              (19 checks)
  S3. test_all_endpoints.py                  (26 checks)
  S4. test_disable_flags.py                  (24 checks)
  S5. smoke_apple_drm.py                     (4 scénarios)
  S6. test_yara_rules_load.py                (5 checks)  [détection Chaos.Crypto]
  S7. test_defender_middleware.py            (5 checks)  [middleware v1.5]

Code de sortie :
  0  → toutes les suites OK
  1  → au moins une suite a échoué
  2  → erreur d'orchestration (fichier manquant, etc.)

Usage :
  py run_all_suites.py                  # exécution standard
  py run_all_suites.py --verbose        # stdout complet de chaque suite
  py run_all_suites.py --json           # résumé JSON machine-readable
  py run_all_suites.py --timeout 120    # timeout par suite (défaut: 60s)
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ------------------------------------------------------------------ paths
SUITE_DIR = Path(__file__).parent.resolve()
REPRODUCER_DIR = SUITE_DIR / "iact_reproducer"

# Force UTF-8 (cp1252 sur Windows par défaut)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

# ------------------------------------------------------------------ suites
SUITES = [
    {
        "id": "S1",
        "name": "apple_drm_defense --self-test",
        "path": SUITE_DIR / "apple_drm_defense.py",
        "args": ["--self-test"],
        "expected": 13,
        "category": "defender",
    },
    {
        "id": "S2",
        "name": "test_apple_drm_defense.py",
        "path": REPRODUCER_DIR / "test_apple_drm_defense.py",
        "args": [],
        "expected": 19,
        "category": "defender",
    },
    {
        "id": "S3",
        "name": "test_all_endpoints.py",
        "path": REPRODUCER_DIR / "test_all_endpoints.py",
        "args": [],
        "expected": 26,
        "category": "endpoint",
    },
    {
        "id": "S4",
        "name": "test_disable_flags.py",
        "path": REPRODUCER_DIR / "test_disable_flags.py",
        "args": [],
        "expected": 24,
        "category": "middleware",
    },
    {
        "id": "S5",
        "name": "smoke_apple_drm.py",
        "path": REPRODUCER_DIR / "smoke_apple_drm.py",
        "args": [],
        "expected": 4,
        "category": "integration",
    },
    {
        "id": "S6",
        "name": "test_yara_rules_load.py",
        "path": SUITE_DIR / "test_yara_rules_load.py",
        "args": [],
        "expected": 5,
        "category": "detection",
    },
    {
        "id": "S7",
        "name": "test_defender_middleware.py",
        "path": REPRODUCER_DIR / "test_defender_middleware.py",
        "args": [],
        "expected": 5,
        "category": "middleware",
    },
]


# ------------------------------------------------------------------ runner
def run_suite(suite, timeout):
    """Exécute une suite. Retourne (ok, stdout, stderr, elapsed_seconds)."""
    if not suite["path"].exists():
        return False, "", f"FILE NOT FOUND: {suite['path']}", 0.0

    cmd = [sys.executable, str(suite["path"]), *suite["args"]]
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(SUITE_DIR),  # pour que `import apple_drm_defense` marche
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return proc.returncode == 0, proc.stdout, proc.stderr, time.monotonic() - t0
    except subprocess.TimeoutExpired:
        return False, "", f"TIMEOUT after {timeout}s", time.monotonic() - t0
    except Exception as exc:  # noqa: BLE001
        return False, "", f"ORCHESTRATOR ERROR: {exc!r}", time.monotonic() - t0


def _tail(text, n=3):
    """Renvoie les n dernières lignes non-vides d'un texte."""
    if not text:
        return ""
    lines = [l for l in text.splitlines() if l.strip()]
    return "\n".join(lines[-n:]) if lines else ""


# ------------------------------------------------------------------ main
def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Affiche stdout complet de chaque suite")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Timeout par suite en secondes (défaut: 60)")
    parser.add_argument("--json", action="store_true",
                        help="Émet un résumé JSON machine-readable à la fin")
    args = parser.parse_args()

    total_expected = sum(s["expected"] for s in SUITES)

    print("=" * 78)
    print("  LAB TEST RUNNER  —  iRemoval PRO v5.2 defensive extension")
    print(f"  Started : {datetime.now(timezone.utc).isoformat()}")
    print(f"  Base    : {SUITE_DIR}")
    print(f"  Suites  : {len(SUITES)} ({total_expected} checks attendus)")
    print("=" * 78)

    results = []
    t0_all = time.monotonic()

    for suite in SUITES:
        rel = suite["path"].relative_to(SUITE_DIR)
        print(f"\n[{suite['id']}] {suite['name']}  (attendus: {suite['expected']})")
        print(f"        {rel}")

        ok, out, err, elapsed = run_suite(suite, timeout=args.timeout)
        status = "PASS" if ok else "FAIL"
        print(f"        [{status}]  exit={0 if ok else 1}  elapsed={elapsed:.2f}s")

        # Toujours montrer les 3 dernières lignes (convention du lab)
        tail_out = _tail(out, 3)
        if tail_out:
            for line in tail_out.splitlines():
                print(f"          | {line}")

        if not ok and err.strip():
            for line in _tail(err, 5).splitlines():
                print(f"          ! {line}")

        if args.verbose and ok:
            for line in out.splitlines():
                print(f"          > {line}")

        results.append({
            "id": suite["id"],
            "name": suite["name"],
            "category": suite["category"],
            "ok": ok,
            "expected": suite["expected"],
            "elapsed_s": round(elapsed, 3),
            "stdout_tail": _tail(out, 3),
            "stderr_tail": _tail(err, 5),
        })

    total_elapsed = time.monotonic() - t0_all
    n_ok = sum(1 for r in results if r["ok"])
    n_total = len(results)
    overall_ok = (n_ok == n_total)
    total_checks = sum(r["expected"] for r in results if r["ok"])

    # ---------------------------------------- summary
    print("\n" + "=" * 78)
    print("  SUMMARY")
    print("=" * 78)
    print(f"  Suites   : {n_ok}/{n_total} PASS")
    print(f"  Checks   : {total_checks}/{total_expected}  (~estimation)")
    print(f"  Elapsed  : {total_elapsed:.2f}s")
    print()
    print("  Per-suite :")
    for r in results:
        mark = "[OK]" if r["ok"] else "[FAIL]"
        print(f"    {mark}  [{r['id']}] {r['name']:<38s}  {r['elapsed_s']:6.2f}s  "
              f"(attendus: {r['expected']})")

    if overall_ok:
        print(f"\n  >>>  RESULT: ALL GREEN ({total_checks} checks passants)")
    else:
        failed = n_total - n_ok
        print(f"\n  >>>  RESULT: {failed} suite(s) FAILED")

    if args.json:
        summary = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_ok": overall_ok,
            "suites_ok": n_ok,
            "suites_total": n_total,
            "checks_ok": total_checks,
            "checks_expected": total_expected,
            "elapsed_s": round(total_elapsed, 3),
            "results": results,
        }
        print("\n----- JSON SUMMARY -----")
        print(json.dumps(summary, indent=2, ensure_ascii=False))

    print()
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
