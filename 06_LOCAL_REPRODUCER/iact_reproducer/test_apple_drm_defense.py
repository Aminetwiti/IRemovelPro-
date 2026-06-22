"""Formal test suite for :mod:`apple_drm_defense`.

.. important::

   100% **defensive** — this module only validates that the defender
   rejects forged tickets. It does not exercise or provide any bypass
   technique.

This suite complements the in-process self-test of
``apple_drm_defense.py --self-test`` with a structured, named-check
format.  The structure follows the same pattern as
:mod:`iact_reproducer.test_all_endpoints` so the lab can run the two
side-by-side.

Coverage (16 named checks, organised in 4 categories) :

=================  ==========================================================
Category            Checks
=================  ==========================================================
Static policy      S1–S6   modulus blacklist, plist iRemoval*, bundle ID,
                            short key, build marker, legit ticket
Anti-replay         R1–R3   first-OK / replay-blocked / new-nonce-OK
Sequence             Q1–Q3   monotonic-OK / regression-blocked / gap-blocked
HWID binding         H1–H3   first-OK / mismatch-blocked / legit-replay-OK
Timing / drift       T1–T3   no-timing-skip-OK / fast-blocked / drift-blocked
Combined             C1      multi-marker-ticket-stacks-all-reasons
=================  ==========================================================

Run with ::

    python 06_LOCAL_REPRODUCER\\iact_reproducer\\test_apple_drm_defense.py
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import List, Tuple

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from apple_drm_defense import (  # noqa: E402
    AppleDRMDefender,
    ActivationTicket,
    SessionState,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _make_legit_ticket(udid: str, **kwargs) -> ActivationTicket:
    """Build a *legit-looking* ticket (RSA-2048, clean plist, fresh nonce)."""
    return ActivationTicket(
        udid=udid,
        public_key_modulus=os.urandom(256),  # RSA-2048 random
        plist_data={"ActivationState": "Activated"},
        nonce=kwargs.pop("nonce", os.urandom(16).hex()),
        sequence_number=kwargs.pop("sequence_number", 1),
        client_hwid=kwargs.pop("client_hwid", "hwid-default"),
        client_timestamp=kwargs.pop("client_timestamp", time.time()),
        **kwargs,
    )


def _expect(check_id: str, ok: bool, expected: bool, reasons: List[str]
            ) -> Tuple[bool, str]:
    """Format a single check result line.

    Returns ``(passed, line)``.
    """
    passed = (ok == expected)
    status = "PASS" if passed else "FAIL"
    expectation = "ALLOW" if expected else "DENY"
    snippet = "; ".join(reasons[:2])[:80] if reasons else "(no reasons)"
    line = f"  [{status}] {check_id:<5} expected={expectation:<5} :: {snippet}"
    return passed, line


# --------------------------------------------------------------------------- #
# Check definitions — 16 named checks
# --------------------------------------------------------------------------- #

def check_static_policy(defender: AppleDRMDefender
                        ) -> List[Tuple[bool, str]]:
    """Static policy checks (S1-S6)."""
    out: List[Tuple[bool, str]] = []

    # S1: modulus RSA-1024 blacklisté
    bad_mod = bytes.fromhex(
        "b83b6e2f23ade61c4a324fa7b9223306"
        "6d9a588d961ea8ccfe3c7224ae2545fe"
        "62fd9cd30c947a454b05250f49ac3404"
        "afd38614164f21105dc0f7ab85022bc2"
        "a7f868a83fc4ac461d2991139b192695"
        "3a9feabdd9f3901613acfe6d59d94b20"
        "06f450b1c4a61f06eb43d688cf41f189"
        "9c821ed0c61428c4b6c276f6c6cc8581"
    )
    t = ActivationTicket(udid="S1-udid", public_key_modulus=bad_mod)
    ok, reasons = defender.validate_ticket(t)
    p, line = _expect("S1", ok, expected=False, reasons=reasons)
    out.append((p, line))

    # S2: plist iRemovalRecord + iRemovalSignature
    t = ActivationTicket(
        udid="S2-udid", public_key_modulus=os.urandom(256),
        plist_data={"iRemovalRecord": b"x", "iRemovalSignature": b"y"},
    )
    ok, reasons = defender.validate_ticket(t)
    p, line = _expect("S2", ok, expected=False, reasons=reasons)
    out.append((p, line))

    # S3: bundle ID Cydia Substrate
    t = ActivationTicket(
        udid="S3-udid", public_key_modulus=os.urandom(256),
        plist_data={
            "ActivationInfo": {"BundleIdentifier": "com.panyolsoft.blackhound"},
        },
    )
    ok, reasons = defender.validate_ticket(t)
    p, line = _expect("S3", ok, expected=False, reasons=reasons)
    out.append((p, line))

    # S4: clé trop courte (1024 bits)
    t = ActivationTicket(udid="S4-udid", public_key_modulus=os.urandom(128))
    ok, reasons = defender.validate_ticket(t)
    p, line = _expect("S4", ok, expected=False, reasons=reasons)
    out.append((p, line))

    # S5: build marker original
    t = ActivationTicket(
        udid="S5-udid", public_key_modulus=os.urandom(256),
        client_build_marker="Blackhound iRemovalPro Public build 0.7.1 @2022",
    )
    ok, reasons = defender.validate_ticket(t)
    p, line = _expect("S5", ok, expected=False, reasons=reasons)
    out.append((p, line))

    # S6: ticket légitime
    t = _make_legit_ticket("S6-udid")
    ok, reasons = defender.validate_ticket(t)
    p, line = _expect("S6", ok, expected=True, reasons=reasons)
    out.append((p, line))

    return out


def check_anti_replay(defender: AppleDRMDefender
                      ) -> List[Tuple[bool, str]]:
    """Anti-replay checks (R1-R3)."""
    out: List[Tuple[bool, str]] = []
    state = SessionState()
    fixed_nonce = "fixed-test-nonce-1234567890"

    # R1: first presentation is accepted
    t = _make_legit_ticket("R-udid-1", nonce=fixed_nonce,
                            sequence_number=1, client_hwid="h1")
    ok, reasons = defender.validate_ticket(t, session=state)
    p, line = _expect("R1", ok, expected=True, reasons=reasons)
    out.append((p, line))

    # R2: same nonce replayed -> blocked
    t2 = _make_legit_ticket("R-udid-1", nonce=fixed_nonce,
                             sequence_number=2, client_hwid="h1")
    ok, reasons = defender.validate_ticket(t2, session=state)
    p, line = _expect("R2", ok, expected=False, reasons=reasons)
    out.append((p, line))

    # R3: new nonce on the same session is accepted
    t3 = _make_legit_ticket("R-udid-1", nonce="new-nonce-9876543210",
                             sequence_number=3, client_hwid="h1")
    ok, reasons = defender.validate_ticket(t3, session=state)
    p, line = _expect("R3", ok, expected=True, reasons=reasons)
    out.append((p, line))

    return out


def check_sequence(defender: AppleDRMDefender
                   ) -> List[Tuple[bool, str]]:
    """Sequence monotonicity checks (Q1-Q3)."""
    out: List[Tuple[bool, str]] = []
    state = SessionState()
    udid = "Q-udid"

    # Q1: monotonic increment is OK
    t1 = _make_legit_ticket(udid, nonce="q1", sequence_number=1)
    t2 = _make_legit_ticket(udid, nonce="q2", sequence_number=2)
    t3 = _make_legit_ticket(udid, nonce="q3", sequence_number=3)
    ok1, r1 = defender.validate_ticket(t1, session=state)
    ok2, r2 = defender.validate_ticket(t2, session=state)
    ok3, r3 = defender.validate_ticket(t3, session=state)
    p = ok1 and ok2 and ok3
    line = f"  [{'PASS' if p else 'FAIL'}] Q1    expected=ALLOW   :: 1->2->3 all OK"
    out.append((p, line))

    # Q2: regression blocked
    t_b = _make_legit_ticket(udid, nonce="qb", sequence_number=2)
    ok, reasons = defender.validate_ticket(t_b, session=state)
    p, line = _expect("Q2", ok, expected=False, reasons=reasons)
    out.append((p, line))

    # Q3: gap > MAX_SEQUENCE_GAP blocked
    t_c = _make_legit_ticket(udid, nonce="qc", sequence_number=10_000)
    ok, reasons = defender.validate_ticket(t_c, session=state)
    p, line = _expect("Q3", ok, expected=False, reasons=reasons)
    out.append((p, line))

    return out


def check_hwid_binding(defender: AppleDRMDefender
                       ) -> List[Tuple[bool, str]]:
    """HWID binding checks (H1-H3)."""
    out: List[Tuple[bool, str]] = []
    state = SessionState()
    udid = "H-udid"

    # H1: first contact with a new HWID is accepted (registered)
    t1 = _make_legit_ticket(udid, nonce="h1", sequence_number=1,
                             client_hwid="hwid-original")
    ok, reasons = defender.validate_ticket(t1, session=state)
    p, line = _expect("H1", ok, expected=True, reasons=reasons)
    out.append((p, line))

    # H2: pirate presents a different HWID -> blocked
    t2 = _make_legit_ticket(udid, nonce="h2", sequence_number=2,
                             client_hwid="hwid-pirate")
    ok, reasons = defender.validate_ticket(t2, session=state)
    p, line = _expect("H2", ok, expected=False, reasons=reasons)
    out.append((p, line))

    # H3: legit user replays their own ticket -> OK (already registered)
    t3 = _make_legit_ticket(udid, nonce="h3", sequence_number=3,
                             client_hwid="hwid-original")
    ok, reasons = defender.validate_ticket(t3, session=state)
    p, line = _expect("H3", ok, expected=True, reasons=reasons)
    out.append((p, line))

    return out


def check_timing_and_drift(defender: AppleDRMDefender
                           ) -> List[Tuple[bool, str]]:
    """Timing + timestamp drift checks (T1-T3)."""
    out: List[Tuple[bool, str]] = []

    # T1: timing check skipped (server_proc_ms=0) -> OK
    t = _make_legit_ticket("T-udid-1")
    ok, reasons = defender.validate_ticket(t, server_proc_ms=0.0)
    p, line = _expect("T1", ok, expected=True, reasons=reasons)
    out.append((p, line))

    # T2: timing anomaly (0.42ms < 5ms) -> blocked
    t = _make_legit_ticket("T-udid-2")
    ok, reasons = defender.validate_ticket(t, server_proc_ms=0.42)
    p, line = _expect("T2", ok, expected=False, reasons=reasons)
    out.append((p, line))

    # T3: timestamp drift (+1h in future) -> blocked
    t = _make_legit_ticket("T-udid-3", client_timestamp=time.time() + 3600)
    ok, reasons = defender.validate_ticket(t)
    p, line = _expect("T3", ok, expected=False, reasons=reasons)
    out.append((p, line))

    return out


def check_combined(defender: AppleDRMDefender
                   ) -> List[Tuple[bool, str]]:
    """Multi-marker combined attack (C1)."""
    out: List[Tuple[bool, str]] = []
    t = ActivationTicket(
        udid="C-udid",
        public_key_modulus=os.urandom(64),  # trop court (512 bits)
        plist_data={
            "ActivationState": "Activated",
            "iRemovalRecord": b"x",  # plist suspect
        },
        client_build_marker="Blackhound iRemovalPro Public build 0.7.1 @2022",
        nonce="combined",
        sequence_number=1,
        client_hwid="h",
    )
    ok, reasons = defender.validate_ticket(t)
    p = (not ok) and len(reasons) >= 3
    line = (f"  [{'PASS' if p else 'FAIL'}] C1    expected=DENY    :: "
            f"{len(reasons)} raisons cumulées")
    out.append((p, line))
    return out


# --------------------------------------------------------------------------- #
# Main runner
# --------------------------------------------------------------------------- #

def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass

    defender = AppleDRMDefender()
    print(f"AppleDRMDefender v{defender.VERSION} — formal test suite")
    print("=" * 60)

    categories: List[Tuple[str, List[Tuple[bool, str]]]] = [
        ("Static policy (S1-S6)", check_static_policy(defender)),
        ("Anti-replay   (R1-R3)", check_anti_replay(defender)),
        ("Sequence      (Q1-Q3)", check_sequence(defender)),
        ("HWID binding  (H1-H3)", check_hwid_binding(defender)),
        ("Timing/drift  (T1-T3)", check_timing_and_drift(defender)),
        ("Combined      (C1)   ", check_combined(defender)),
    ]

    total = 0
    passed = 0
    for name, results in categories:
        print(f"\n  {name}")
        for p, line in results:
            print(line)
            total += 1
            if p:
                passed += 1

    print("\n" + "=" * 60)
    print(f"  {passed}/{total} checks passed.")
    if passed == total:
        print(f"  All green (defender v{defender.VERSION}).")
        return 0
    print(f"  FAILURES present — investigate above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
