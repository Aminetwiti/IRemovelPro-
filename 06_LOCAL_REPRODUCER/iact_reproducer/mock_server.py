"""Local mock of the iRemoval ``iact8.php`` endpoint (v1.2).

This module is a **completely offline** HTTP server that mimics the
behaviour of ``https://s13.iremovalpro.com/iremovalActivation/iact8.php``
along with the rest of the iRemoval backend surface. It is intended
for protocol analysis, traffic capture and detection-engineering
without paying for an iRemoval account.

The server **never**:
  * returns a working iActivation ticket
  * contacts any network resource
  * performs any cryptographic operation against a real key
  * accepts or processes Apple infrastructure material

Every request is logged to ``logs/`` and every response embeds the
literal string ``iRemovalLabTest`` so the capture is unmistakably
synthetic.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import http.server
import json
import logging
import socketserver
import ssl
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from iact_reproducer import (  # noqa: E402
    bplist_builder,
    blacklist,
    hmac_auth,
    rate_limit,
    wire_format,
)
from apple_drm_defense import (  # noqa: E402
    AppleDRMDefender,
    ActivationTicket,
    SessionState,
)

log = logging.getLogger("iact_mock_server")

# Lab marker — same shape as the rest of the lab but spelt out so the
# toolchain does not try to "auto-correct" the word during writes.
TEST_MARKER = "iRemovalLabTest"


# --------------------------------------------------------------------------- #
# Request parsing
# --------------------------------------------------------------------------- #

def parse_envelope(raw_body: bytes) -> Dict[str, Any]:
    text = raw_body.decode("utf-8", errors="replace").strip()
    if not text:
        return {"ok": False, "error": "empty body"}
    if text.startswith("{") or text.startswith("["):
        try:
            data = json.loads(text)
            if isinstance(data, list) and data:
                data = data[0]
            if not isinstance(data, dict):
                return {"ok": False, "error": "JSON not an object"}
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": f"JSON parse error: {exc}"}
        return {"ok": True, "fields": data}
    if "=" in text and "&" in text:
        from urllib.parse import parse_qs
        qs = parse_qs(text)
        flat = {k: v[0] for k, v in qs.items() if v}
        return {"ok": True, "fields": flat}
    return {"ok": False, "error": "unrecognised body shape"}


def validate_envelope(fields: Dict[str, Any]) -> Dict[str, Any]:
    checks: Dict[str, Any] = {}
    for required in ("udid", "b64", "sig", "alg"):
        if required not in fields:
            checks[f"has_{required}"] = False
            return {"ok": False, "error": f"missing field: {required}",
                    "checks": checks}
        checks[f"has_{required}"] = True
    import base64
    try:
        bplist = base64.b64decode(fields["b64"])
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"b64 decode failed: {exc}",
                "checks": checks}
    checks["bplist_size"] = len(bplist)
    checks["bplist00_magic"] = bplist.startswith(b"bplist00")
    try:
        parsed = bplist_builder.parse_bplist00(bplist)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"bplist parse failed: {exc}",
                "checks": checks}
    checks["udid_matches"] = parsed.get("UDID") == fields["udid"]
    checks["has_lab_marker"] = parsed.get("LabMarker") == TEST_MARKER
    return {"ok": True, "error": None, "checks": checks,
            "bplist": bplist, "parsed": parsed}


def make_lab_response(envelope: Dict[str, Any],
                      validation: Dict[str, Any],
                      request_id: str) -> Dict[str, Any]:
    return {
        "request_id": request_id,
        "status": "LAB_MOCK_REFUSED",
        "lab_marker": TEST_MARKER,
        "received": {
            "udid": envelope.get("udid"),
            "alg": envelope.get("alg"),
            "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
        },
        "validation": {
            "ok": validation.get("ok"),
            "error": validation.get("error"),
            "checks": validation.get("checks"),
        },
        "ticket_b64": None,
        "activation_ticket": None,
        "message": (
            "This response was produced by the local lab mock. "
            f"No iActivation ticket has been generated. [{TEST_MARKER}]"
        ),
    }


# --------------------------------------------------------------------------- #
# Shared state
# --------------------------------------------------------------------------- #

class _State:
    """Shared state across requests — log + v1.2/v1.3/v1.4 subsystems.

    The ``disabled_middleware`` set mirrors the ``--disable-*`` CLI flags
    so the lab can be made permissive **per feature** without touching
    the rest of the middleware. Each entry is one of:

      * ``"hmac"``        — skip HMAC-SHA256 verification (v1.2)
      * ``"rate_limit"``  — short-circuit the limiter with huge budgets (v1.3)
      * ``"blacklist"``   — skip the blacklist lookup (v1.4)
      * ``"defender"``    — skip the Apple DRM defender (v1.5) — **DANGEROUS**
    """

    def __init__(
        self,
        log_dir: Path,
        *,
        auth: hmac_auth.AuthState,
        limiter: rate_limit.RateLimiter,
        blacklist_: blacklist.Blacklist,
        disabled_middleware: Optional[set] = None,
    ) -> None:
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.requests_log = self.log_dir / "mock_server_requests.jsonl"
        self.auth = auth
        self.limiter = limiter
        self.blacklist_ = blacklist_
        self.disabled_middleware: set = set(disabled_middleware or ())
        # Counters that mirror the disable set so the dashboard and JSONL
        # can show exactly which guard the operator turned off (v1.2/v1.3/v1.4).
        self.disabled_counters: Dict[str, int] = {
            "hmac": 0, "rate_limit": 0, "blacklist": 0, "defender": 0,
        }
        # Apple DRM defender (defensive simulator). One instance per
        # server lifetime so the session-state dictionary (anti-replay,
        # sequence, HWID) survives across requests. The 5 new check
        # categories map directly to the weaknesses documented in
        # BYPASS_CORE.md §16 (9-step handshake, Step 9 = Apple's only
        # visibility point on a forged activation record).
        self.defender = AppleDRMDefender()
        self.defender_session = SessionState()
        # Counters so the JSONL can show how many forged tickets the
        # defender caught per check ID.
        self.defender_hits: Dict[str, int] = {
            "BY-MOD-001": 0, "BY-PLI-001": 0, "BY-EXT-001": 0,
            "BY-EXT-002": 0, "BY-EXT-003": 0, "BY-EXT-004": 0,
            "BY-SES-001": 0, "BY-SES-002": 0, "BY-SES-003": 0,
            "BY-SES-004": 0, "BY-SES-005": 0, "BY-SES-006": 0,
            "BY-SES-007": 0,
        }

    def record(self, record: Dict[str, Any]) -> None:
        with self.lock:
            with self.requests_log.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #

class _MockHandler(http.server.BaseHTTPRequestHandler):
    server_version = "iAct8Mock/1.2 (LabResearch)"
    state: _State  # injected by the server

    _ALL_ENDPOINTS = [
        ("POST", "/iremovalActivation/iact8.php"),
        ("POST", "/iremovalActivation/pub.ph"),
        ("POST", "/iremovalActivation/mf5.ph"),
        ("POST", "/iremovalActivation/mf6.ph"),
        ("POST", "/iremovalActivation/mf7.ph"),
        ("POST", "/iremovalActivation/license.ph"),
        ("POST", "/iremovalActivation/telemetry.ph"),
        ("POST", "/iremovalActivation/admin.ph"),
        ("POST", "/iremovalActivation/blacklist_add.ph"),
        ("POST", "/iremovalActivation/blacklist_remove.ph"),
        ("POST", "/iremovalActivation/apple_drm_check.ph"),
        ("GET",  "/version33.tx"),
        ("GET",  "/blacklist.ph"),
        ("GET",  "/ping.ph"),
        ("GET",  "/metrics.ph"),
    ]

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        log.info("%s - - %s", self.address_string(), format % args)

    # ------------------------------------------------------------------ #
    # Middleware (v1.2/v1.3/v1.4): blacklist, rate limit, HMAC, defender
    # ------------------------------------------------------------------ #
    # Each guard can be individually turned off via the matching
    # ``--disable-*`` CLI flag. When disabled, the guard is short-circuited
    # AND the per-guard counter is incremented so detection engineers can
    # see in the JSONL log exactly which guard was skipped.
    def _check_middleware(self, body: bytes) -> Optional[Tuple[int, Dict[str, Any], Dict[str, str]]]:
        ip = self.client_address[0]
        udid = None
        payload: Optional[Dict[str, Any]] = None
        if self.command == "POST" and body:
            try:
                payload = json.loads(body.decode("utf-8", errors="replace"))
                if isinstance(payload, dict):
                    udid = payload.get("udid")
            except (ValueError, AttributeError):
                pass
        disabled = self.state.disabled_middleware
        # 1. Blacklist (v1.4)
        if "blacklist" in disabled:
            self.state.disabled_counters["blacklist"] += 1
            log.debug("middleware: blacklist SKIPPED (--disable-blacklist)")
        else:
            allowed, hits = self.state.blacklist_.check(udid=udid, ip=ip)
            if not allowed:
                response = {
                    "status": "BLACKLISTED",
                    "lab_marker": TEST_MARKER,
                    "blocked_by": [{"kind": k, "value": v} for k, v in hits],
                    "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
                }
                return 403, response, {}
        # 2. Rate limit (v1.3)
        if "rate_limit" in disabled:
            self.state.disabled_counters["rate_limit"] += 1
            log.debug("middleware: rate_limit SKIPPED (--disable-rate-limit)")
        else:
            ok, why, retry = self.state.limiter.consume(ip=ip, udid=udid)
            if not ok:
                response = {
                    "status": "RATE_LIMITED",
                    "lab_marker": TEST_MARKER,
                    "reason": why,
                    "retry_after_seconds": retry,
                    "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
                }
                return 429, response, {"Retry-After": str(retry)}
        # 3. HMAC auth (v1.2)
        if "hmac" in disabled:
            self.state.disabled_counters["hmac"] += 1
            log.debug("middleware: hmac SKIPPED (--disable-hmac)")
        else:
            hdrs = {k: v for k, v in self.headers.items()}
            ok, err = self.state.auth.validate(
                method=self.command, path=self.path, headers=hdrs, body=body,
            )
            if not ok:
                response = {
                    "status": "UNAUTHENTICATED",
                    "lab_marker": TEST_MARKER,
                    "error": err,
                    "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
                }
                return 401, response, {}
        # 4. Apple DRM defender (v1.5) — middleware variant
        # The defender only fires on POSTs whose body contains
        # ``public_key_modulus`` (the signal that the caller is attempting
        # to forge / relay an iActivation ticket). Endpoints that do not
        # carry a ticket (license, telemetry, blacklist_add, …) are
        # passed through untouched so we do not break the lab surface.
        # When ``--disable-defender`` is set we still bump the counter
        # for transparency but skip validation entirely.
        if payload and isinstance(payload, dict) and \
                payload.get("public_key_modulus"):
            if "defender" in disabled:
                self.state.disabled_counters["defender"] += 1
                log.debug(
                    "middleware: defender SKIPPED (--disable-defender) "
                    "— request body carried public_key_modulus"
                )
            else:
                denied = self._run_defender(payload)
                if denied is not None:
                    return denied
        return None

    # ------------------------------------------------------------------ #
    # Defender helper (middleware variant)
    # ------------------------------------------------------------------ #
    def _run_defender(self, payload: Dict[str, Any]) -> Optional[Tuple[int, Dict[str, Any], Dict[str, str]]]:
        """Validate ``payload`` as a tentative iActivation ticket.

        Returns ``None`` if the ticket is **legit** (no forgery detected),
        or ``(403, response, {})`` if at least one check flagged the
        request. The defender's session state (``defender_session``) is
        shared across requests so anti-replay / sequence / HWID checks
        work end-to-end.

        This is the **middleware variant** (v1.5) of the defender. The
        older explicit endpoint ``/iremovalActivation/apple_drm_check.ph``
        still works for callers that prefer an explicit verdict.
        """
        import base64
        try:
            mod_bytes = base64.b64decode(
                payload.get("public_key_modulus", "") or "", validate=True
            )
        except Exception:  # noqa: BLE001
            mod_bytes = b""
        plist = payload.get("plist") or {}
        ticket = ActivationTicket(
            udid=str(payload.get("udid", "") or ""),
            public_key_modulus=mod_bytes,
            plist_data=plist if isinstance(plist, dict) else {},
            client_build_marker=str(
                payload.get("client_build_marker", "") or ""
            ),
            nonce=payload.get("nonce"),
            sequence_number=payload.get("sequence_number"),
            client_hwid=payload.get("client_hwid"),
            client_timestamp=payload.get("client_timestamp"),
        )
        server_proc_ms = float(payload.get("server_proc_ms") or 0.0)
        try:
            ok, reasons = self.state.defender.validate_ticket(
                ticket,
                session=self.state.defender_session,
                server_proc_ms=server_proc_ms,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("defender raised: %s", exc)
            return 500, {
                "status": "LAB_DEFENDER_ERROR",
                "lab_marker": TEST_MARKER,
                "error": f"defender raised: {exc}",
                "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
            }, {}
        with self.state.lock:
            for r in reasons:
                for code in self.state.defender_hits:
                    if code in r:
                        self.state.defender_hits[code] += 1
        if ok:
            return None
        response = {
            "status": "LAB_DRM_FORGERY_DETECTED",
            "lab_marker": TEST_MARKER,
            "ok": False,
            "reasons": reasons,
            "defender_version": self.state.defender.VERSION,
            "policy_snapshot": self.state.defender.policy_snapshot(),
            "intercepted_by": "middleware:defender",
            "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
        }
        return 403, response, {}

    # ------------------------------------------------------------------ #
    # Routing
    # ------------------------------------------------------------------ #
    def do_GET(self) -> None:  # noqa: N802
        result = self._check_middleware(b"")
        if result is not None:
            code, payload, extra = result
            self._json(code, payload, extra)
            return
        if self.path == "/health" or self.path == "/ping.ph":
            self._json(200, {
                "status": "ok",
                "lab_marker": TEST_MARKER,
                "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
            })
            return
        if self.path == "/" or self.path == "":
            self._json(200, {
                "server": self.server_version,
                "lab_marker": TEST_MARKER,
                "endpoints": [f"{m} {p}" for m, p in self._ALL_ENDPOINTS]
                             + ["GET /health", "GET /"],
            })
            return
        if self.path == "/version33.tx":
            self._json(200, {
                "version": "5.2-LAB-0.0",
                "lab_marker": TEST_MARKER,
                "min_client": "5.0.0",
                "recommended": "5.2.0",
            })
            return
        if self.path == "/blacklist.ph":
            self._json(200, self.state.blacklist_.snapshot())
            return
        if self.path == "/lab_mode" or self.path == "/lab_mode.ph":
            # Live introspection of the middleware mode. Useful for
            # dashboards and for self-tests that want to know the active
            # guard set without re-reading the CLI.
            self._json(200, {
                "lab_marker": TEST_MARKER,
                "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
                "guards": {
                    "hmac": {
                        "active": "hmac" not in self.state.disabled_middleware,
                        "skipped": self.state.disabled_counters["hmac"],
                    },
                    "rate_limit": {
                        "active": "rate_limit" not in self.state.disabled_middleware,
                        "skipped": self.state.disabled_counters["rate_limit"],
                    },
                    "blacklist": {
                        "active": "blacklist" not in self.state.disabled_middleware,
                        "skipped": self.state.disabled_counters["blacklist"],
                    },
                    "defender": {
                        "active": "defender" not in self.state.disabled_middleware,
                        "skipped": self.state.disabled_counters["defender"],
                        "version": self.state.defender.VERSION,
                        "hits_total": sum(self.state.defender_hits.values()),
                    },
                },
                "limiter": self.state.limiter.snapshot(),
                "blacklist_entries": {
                    "udids": len(self.state.blacklist_._udids),
                    "serials": len(self.state.blacklist_._serials),
                    "imeis": len(self.state.blacklist_._imeis),
                    "ips": len(self.state.blacklist_._ips),
                },
            })
            return
        if self.path == "/metrics.ph":
            # Prometheus-style scrape. Includes one counter per guard so
            # the SIEM can alert when a previously-seen guard flips to
            # ``skipped > 0`` (unexpected permissive mode in prod-like
            # captures).
            total_skipped = sum(self.state.disabled_counters.values())
            body = (
                f"# HELP iact_mock_requests_total Lab request counter "
                f"[{TEST_MARKER}]\n"
                f"# TYPE iact_mock_requests_total counter\n"
                f'iact_mock_requests_total{{path="iact8.php"}} 0\n'
                f'iact_mock_requests_total{{path="pub.ph"}} 0\n'
                f"# HELP iact_mock_skipped_guards_total Guards bypassed "
                f"via --disable-* [{TEST_MARKER}]\n"
                f"# TYPE iact_mock_skipped_guards_total counter\n"
                f'iact_mock_skipped_guards_total{{guard="hmac"}} '
                f'{self.state.disabled_counters["hmac"]}\n'
                f'iact_mock_skipped_guards_total{{guard="rate_limit"}} '
                f'{self.state.disabled_counters["rate_limit"]}\n'
                f'iact_mock_skipped_guards_total{{guard="blacklist"}} '
                f'{self.state.disabled_counters["blacklist"]}\n'
                f'iact_mock_skipped_guards_total{{guard="defender"}} '
                f'{self.state.disabled_counters["defender"]}\n'
                f'iact_mock_skipped_guards_total{{guard="any"}} '
                f'{total_skipped}\n'
                f"# HELP iact_mock_defender_hits_total Apple DRM defender "
                f"check-ID hit counts [{TEST_MARKER}]\n"
                f"# TYPE iact_mock_defender_hits_total counter\n"
            ).encode("utf-8")
            for code, hits in self.state.defender_hits.items():
                body += (
                    f'iact_mock_defender_hits_total{{check="{code}"}} '
                    f'{hits}\n'
                ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._json(404, {"error": "not found", "lab_marker": TEST_MARKER})

    def do_POST(self) -> None:  # noqa: N802
        request_id = _dt.datetime.now(tz=_dt.timezone.utc).strftime(
            "%Y%m%dT%H%M%S%f"
        )
        body = self._read_body()
        result = self._check_middleware(body)
        if result is not None:
            # Middleware may return 2-tuple (legacy) or 3-tuple (with headers)
            if len(result) == 3:
                code, payload, extra = result
            else:
                code, payload = result
                extra = {}
            # If rate-limited, add Retry-After header properly
            if code == 429 and isinstance(payload, dict) and "Retry-After" not in (extra or {}):
                retry = payload.get("retry_after_seconds")
                if retry is not None:
                    extra = dict(extra or {})
                    extra["Retry-After"] = str(retry)
            self._json(code, payload, extra_headers=extra or None)
            self._record(request_id, body, None, payload,
                         f"middleware_{code}")
            return
        path = self.path
        if path.endswith("iact8.php"):
            return self._handle_iact8(request_id, body)
        if path.endswith("pub.ph"):
            return self._handle_pub(request_id, body)
        if path.endswith("mf5.ph") or path.endswith("mf6.ph") or path.endswith("mf7.ph"):
            return self._handle_mf(request_id, path, body)
        if path.endswith("license.ph"):
            return self._handle_license(request_id, body)
        if path.endswith("telemetry.ph"):
            return self._handle_telemetry(request_id, body)
        if path.endswith("admin.ph"):
            return self._handle_admin(request_id, body)
        if path.endswith("blacklist_add.ph"):
            return self._handle_blacklist_add(request_id, body)
        if path.endswith("blacklist_remove.ph"):
            return self._handle_blacklist_remove(request_id, body)
        if path.endswith("apple_drm_check.ph"):
            return self._handle_apple_drm_check(request_id, body)
        self._json(404, {
            "error": "unknown endpoint",
            "lab_marker": TEST_MARKER,
            "known_endpoints": [p for _, p in self._ALL_ENDPOINTS],
        })

    # ------------------------------------------------------------------ #
    # Per-endpoint handlers
    # ------------------------------------------------------------------ #
    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length) if length > 0 else b""

    def _handle_iact8(self, request_id: str, body: bytes) -> None:
        raw = body
        parsed = parse_envelope(raw)
        if not parsed["ok"]:
            response = {
                "request_id": request_id,
                "status": "LAB_MOCK_REFUSED",
                "lab_marker": TEST_MARKER,
                "error": parsed["error"],
            }
            self._record(request_id, raw, None, response, "parse_error")
            self._json(400, response)
            return
        validation = validate_envelope(parsed["fields"])
        response = make_lab_response(parsed["fields"], validation, request_id)
        self._record(request_id, raw, validation, response,
                     "ok" if validation["ok"] else "invalid")
        self._json(200, response)

    def _handle_pub(self, request_id: str, body: bytes) -> None:
        response = {
            "request_id": request_id,
            "status": "LAB_MOCK_ACK",
            "lab_marker": TEST_MARKER,
            "received_bytes": len(body),
            "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
            "note": f"Synthetic /pub.ph ack. [{TEST_MARKER}]",
        }
        self._json(200, response)
        self._record(request_id, body, None, response, "pub_ok")

    def _handle_mf(self, request_id: str, path: str, body: bytes) -> None:
        variant = path.rsplit("/", 1)[-1]
        response = {
            "request_id": request_id,
            "status": "LAB_MOCK_REFUSED",
            "lab_marker": TEST_MARKER,
            "endpoint": variant,
            "synthetic_meid": f"{TEST_MARKER}-MEID-0000-0000-0000",
            "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
            "note": f"Synthetic MEID response. [{TEST_MARKER}]",
        }
        self._json(200, response)
        self._record(request_id, body, None, response, f"mf_ok:{variant}")

    def _handle_license(self, request_id: str, body: bytes) -> None:
        response = {
            "request_id": request_id,
            "status": "LAB_LICENSE_VALID",
            "lab_marker": TEST_MARKER,
            "license": {
                "plan": "lab",
                "credits_remaining": 9999,
                "expires": "2099-12-31T23:59:59Z",
            },
            "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
        }
        self._json(200, response)
        self._record(request_id, body, None, response, "license_ok")

    def _handle_telemetry(self, request_id: str, body: bytes) -> None:
        response = {
            "request_id": request_id,
            "status": "LAB_TELEMETRY_ACK",
            "lab_marker": TEST_MARKER,
            "received_bytes": len(body),
            "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
        }
        self._json(200, response)
        self._record(request_id, body, None, response, "telemetry_ok")

    def _handle_admin(self, request_id: str, body: bytes) -> None:
        response = {
            "request_id": request_id,
            "status": "LAB_ADMIN_DENIED",
            "lab_marker": TEST_MARKER,
            "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
            "note": "Admin endpoint refused in lab.",
        }
        self._json(403, response)
        self._record(request_id, body, None, response, "admin_denied")

    def _handle_blacklist_add(self, request_id: str, body: bytes) -> None:
        try:
            payload = json.loads(body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            payload = {}
        kind = payload.get("kind", "udid")
        identifier = payload.get("identifier", "")
        reason = payload.get("reason", "manual")
        if not identifier:
            response = {
                "status": "BAD_REQUEST",
                "lab_marker": TEST_MARKER,
                "error": "missing 'identifier'",
            }
            self._json(400, response)
            self._record(request_id, body, None, response, "bl_add_bad")
            return
        try:
            added = self.state.blacklist_.add(kind, identifier, reason=reason)
        except ValueError as exc:
            response = {
                "status": "BAD_REQUEST",
                "lab_marker": TEST_MARKER,
                "error": str(exc),
            }
            self._json(400, response)
            self._record(request_id, body, None, response, "bl_add_bad_kind")
            return
        response = {
            "request_id": request_id,
            "status": "BLACKLIST_UPDATED",
            "lab_marker": TEST_MARKER,
            "action": "add",
            "kind": kind,
            "identifier": identifier,
            "added": added,
            "snapshot": self.state.blacklist_.snapshot(),
            "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
        }
        self._json(200, response)
        self._record(request_id, body, None, response, "bl_add_ok")

    def _handle_apple_drm_check(self, request_id: str, body: bytes) -> None:
        """Apple DRM defensive validator.

        Body expected (JSON)::

            {
              "udid": "00000000-...",
              "public_key_modulus": "<base64>",
              "plist": {"ActivationState": "...", ...},
              "nonce": "<32 chars>",
              "sequence_number": 1,
              "client_hwid": "...",
              "client_timestamp": 1700000000.0,
              "client_build_marker": "...",
              "server_proc_ms": 12.3
            }

        Returns a JSON object with ``ok`` and ``reasons``. The defender
        increments per-check counters in ``state.defender_hits`` so the
        dashboard can show which forgery vector each request triggered.
        Never returns a working iActivation ticket.
        """
        import base64
        try:
            payload = json.loads(body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            response = {
                "request_id": request_id,
                "status": "LAB_BAD_REQUEST",
                "lab_marker": TEST_MARKER,
                "error": f"JSON parse error: {exc}",
            }
            self._json(400, response)
            self._record(request_id, body, None, response, "drm_bad_json")
            return
        if not isinstance(payload, dict):
            response = {
                "request_id": request_id,
                "status": "LAB_BAD_REQUEST",
                "lab_marker": TEST_MARKER,
                "error": "body must be a JSON object",
            }
            self._json(400, response)
            self._record(request_id, body, None, response, "drm_bad_shape")
            return
        try:
            mod_bytes = base64.b64decode(
                payload.get("public_key_modulus", "") or "", validate=True
            )
        except Exception:  # noqa: BLE001
            mod_bytes = b""
        plist = payload.get("plist") or {}
        ticket = ActivationTicket(
            udid=str(payload.get("udid", "") or ""),
            public_key_modulus=mod_bytes,
            plist_data=plist if isinstance(plist, dict) else {},
            client_build_marker=str(
                payload.get("client_build_marker", "") or ""
            ),
            nonce=payload.get("nonce"),
            sequence_number=payload.get("sequence_number"),
            client_hwid=payload.get("client_hwid"),
            client_timestamp=payload.get("client_timestamp"),
        )
        server_proc_ms = float(payload.get("server_proc_ms") or 0.0)
        try:
            ok, reasons = self.state.defender.validate_ticket(
                ticket,
                session=self.state.defender_session,
                server_proc_ms=server_proc_ms,
            )
        except Exception as exc:  # noqa: BLE001
            response = {
                "request_id": request_id,
                "status": "LAB_DEFENDER_ERROR",
                "lab_marker": TEST_MARKER,
                "error": f"defender raised: {exc}",
            }
            self._json(500, response)
            self._record(request_id, body, None, response, "drm_error")
            return
        with self.state.lock:
            for r in reasons:
                for code in self.state.defender_hits:
                    if code in r:
                        self.state.defender_hits[code] += 1
        response = {
            "request_id": request_id,
            "status": "LAB_DRM_VERDICT" if ok else "LAB_DRM_FORGERY_DETECTED",
            "lab_marker": TEST_MARKER,
            "ok": ok,
            "reasons": reasons,
            "defender_version": self.state.defender.VERSION,
            "policy_snapshot": self.state.defender.policy_snapshot(),
            "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
        }
        http_code = 200 if ok else 403
        self._json(http_code, response)
        self._record(
            request_id, body, None, response,
            "drm_ok" if ok else "drm_forgery_detected",
        )

    def _handle_blacklist_remove(self, request_id: str, body: bytes) -> None:
        try:
            payload = json.loads(body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            payload = {}
        kind = payload.get("kind", "udid")
        identifier = payload.get("identifier", "")
        if not identifier:
            response = {
                "status": "BAD_REQUEST",
                "lab_marker": TEST_MARKER,
                "error": "missing 'identifier'",
            }
            self._json(400, response)
            self._record(request_id, body, None, response, "bl_rm_bad")
            return
        try:
            removed = self.state.blacklist_.remove(kind, identifier)
        except ValueError as exc:
            response = {
                "status": "BAD_REQUEST",
                "lab_marker": TEST_MARKER,
                "error": str(exc),
            }
            self._json(400, response)
            self._record(request_id, body, None, response, "bl_rm_bad_kind")
            return
        response = {
            "request_id": request_id,
            "status": "BLACKLIST_UPDATED",
            "lab_marker": TEST_MARKER,
            "action": "remove",
            "kind": kind,
            "identifier": identifier,
            "removed": removed,
            "snapshot": self.state.blacklist_.snapshot(),
            "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
        }
        self._json(200, response)
        self._record(request_id, body, None, response, "bl_rm_ok")

    def _json(self, code: int, body: Dict[str, Any],
              extra_headers: Optional[Dict[str, str]] = None) -> None:
        data = json.dumps(body, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Lab-Marker", TEST_MARKER)
        self.send_header("Server", self.server_version)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _record(self, request_id: str, raw: bytes,
                validation: Optional[Dict[str, Any]],
                response: Dict[str, Any], outcome: str) -> None:
        # Snapshot the lab mode at request time so an analyst reading the
        # JSONL offline can tell which guards were off, even if the server
        # has been restarted with a different configuration.
        record = {
            "ts": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
            "request_id": request_id,
            "method": self.command,
            "peer": self.client_address[0],
            "path": self.path,
            "raw_size": len(raw),
            "raw_b64_snippet": raw[:64].hex(),
            "outcome": outcome,
            "validation_ok": validation.get("ok") if validation else None,
            "validation_error": validation.get("error") if validation else None,
            "response_status": response.get("status"),
            "lab_mode": {
                "disabled_middleware": sorted(self.state.disabled_middleware),
                "skipped_guards": dict(self.state.disabled_counters),
                "defender_version": self.state.defender.VERSION,
                "defender_hits": dict(self.state.defender_hits),
            },
        }
        self.state.record(record)


# --------------------------------------------------------------------------- #
# Server bootstrap
# --------------------------------------------------------------------------- #

class _ThreadingHTTPServer(socketserver.ThreadingMixIn,
                           http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def run_server(
    host: str = "127.0.0.1",
    port: int = 8443,
    log_dir: Path = Path("logs"),
    tls_cert: Optional[Path] = None,
    tls_key: Optional[Path] = None,
    *,
    hmac_secret_path: Optional[Path] = None,
    blacklist_path: Optional[Path] = None,
    rate_per_ip: int = 100,
    rate_per_udid: int = 10,
    disable_hmac: bool = False,
    disable_blacklist: bool = False,
    disable_rate_limit: bool = False,
    disable_defender: bool = False,
) -> None:
    log_dir = Path(log_dir).resolve()
    auth = hmac_auth.load_or_create_state(secret_path=hmac_secret_path)
    limiter = rate_limit.RateLimiter(
        rate_limit.RateLimitConfig(per_ip_limit=rate_per_ip,
                                   per_udid_limit=rate_per_udid)
    )
    if blacklist_path is None:
        blacklist_path = log_dir / "blacklist.json"
    bl = blacklist.Blacklist.load(Path(blacklist_path))
    disabled: set = set()
    if disable_hmac:
        disabled.add("hmac")
    if disable_blacklist:
        disabled.add("blacklist")
    if disable_rate_limit:
        disabled.add("rate_limit")
    if disable_defender:
        disabled.add("defender")
    state = _State(
        log_dir, auth=auth, limiter=limiter, blacklist_=bl,
        disabled_middleware=disabled,
    )
    _MockHandler.state = state

    httpd = _ThreadingHTTPServer((host, port), _MockHandler)
    if tls_cert and tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(tls_cert), keyfile=str(tls_key))
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"

    log.info("iAct8 mock server listening on %s://%s:%d", scheme, host, port)
    log.info("Log file        : %s", state.requests_log)
    log.info("Blacklist file  : %s", bl.path)
    log.info("HMAC secret     : %s",
             hmac_secret_path or "logs/hmac_secret.json")
    log.info("Rate limits     : per_ip=%d per_udid=%d / %ds",
             rate_per_ip, rate_per_udid, 60)
    if disabled:
        # Make the permissive mode unmissable in the log output.
        bar = "!" * 72
        log.warning(bar)
        log.warning("!!  LAB PERMISSIF MODE  ".ljust(72) + "!!")
        log.warning("!!  Guards disabled     : %s".ljust(72) + "!!",
                    ", ".join(sorted(disabled)))
        log.warning("!!  Every request is counted in mock_server_requests.jsonl".ljust(72) + "!!")
        log.warning("!!  via record.lab_mode.disabled_middleware".ljust(72) + "!!")
        log.warning(bar)
    else:
        log.info("Lab permissif mode: none (all v1.2/v1.3/v1.4 guards active)")
    log.info("Lab marker      : %r", TEST_MARKER)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down (Ctrl-C).")
    finally:
        httpd.server_close()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iact_mock_server",
        description=(
            "Local offline mock of the iRemoval cloud backend "
            "(12 endpoints + blacklist + rate limit + HMAC)."
        ),
    )
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--log-dir", default="logs",
                   help="Directory for the JSONL request log.")
    p.add_argument("--tls-cert", default=None,
                   help="Optional PEM cert to serve HTTPS.")
    p.add_argument("--tls-key", default=None,
                   help="Optional PEM key to serve HTTPS.")
    p.add_argument("--hmac-secret", default=None,
                   help="Path to the JSON file holding the HMAC secret "
                        "(created on first run if missing).")
    p.add_argument("--blacklist", default=None,
                   help="Path to the persistent blacklist JSON file.")
    p.add_argument("--rate-per-ip", type=int, default=100,
                   help="Max requests per IP per 60s window.")
    p.add_argument("--rate-per-udid", type=int, default=10,
                   help="Max requests per UDID per 60s window.")
    p.add_argument("--disable-rate-limit", action="store_true",
                   help="Disable rate limit (lab-only convenience, v1.3).")
    p.add_argument("--disable-hmac", action="store_true",
                   help="Disable HMAC-SHA256 auth (lab-only convenience, v1.2).")
    p.add_argument("--disable-blacklist", action="store_true",
                   help="Disable blacklist check (lab-only convenience, v1.4).")
    p.add_argument("--disable-defender", action="store_true",
                   help="Disable Apple DRM defender middleware (lab-only, "
                        "v1.5). FORGERED TICKETS WILL PASS THROUGH. "
                        "Use only when validating the defender itself.")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: Optional[list] = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    if args.disable_rate_limit:
        rate_per_ip = 1_000_000
        rate_per_udid = 1_000_000
    else:
        rate_per_ip = args.rate_per_ip
        rate_per_udid = args.rate_per_udid
    run_server(
        host=args.host,
        port=args.port,
        log_dir=Path(args.log_dir).resolve(),
        tls_cert=Path(args.tls_cert).resolve() if args.tls_cert else None,
        tls_key=Path(args.tls_key).resolve() if args.tls_key else None,
        hmac_secret_path=(Path(args.hmac_secret).resolve()
                          if args.hmac_secret else None),
        blacklist_path=(Path(args.blacklist).resolve()
                        if args.blacklist else None),
        rate_per_ip=rate_per_ip,
        rate_per_udid=rate_per_udid,
        disable_hmac=args.disable_hmac,
        disable_blacklist=args.disable_blacklist,
        disable_rate_limit=args.disable_rate_limit,
        disable_defender=args.disable_defender,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
