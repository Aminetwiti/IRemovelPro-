#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_endpoints.py - Reconnaissance passive des endpoints iRemoval PRO.

Observe:
- Type de réponse (JSON / base64 / HTML / Cloudflare challenge)
- Status codes, headers
- Timing des réponses

N'ENVOIE PAS de payloads actifs. Pas de bypass d'auth.
"""
import json
import time
import sys
import io
import base64
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

try:
    import requests
except ImportError:
    print("[!] Module 'requests' requis. Installer: py -m pip install requests")
    sys.exit(1)

BASE = "https://s13.iremovalpro.com"
OUT_DIR = Path(r"c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\03_OUTPUTS\server_probe")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Endpoints découverts lors de la phase 1
ENDPOINTS = [
    # (label, path, method)
    ("version33", "version33.txt", "GET"),
    ("auth3",     "iremovalActivation/auth3.php",     "POST"),
    ("checkm8",   "iremovalActivation/checkm8.php",   "POST"),
    ("iact8",     "iremovalActivation/iact8.php",     "POST"),
    ("ars2",      "iremovalActivation/ars2.php",      "POST"),
    ("mf5",       "iremovalActivation/mf5.php",       "POST"),
    ("mf6",       "iremovalActivation/mf6.php",       "POST"),
    ("mf7",       "iremovalActivation/mf7.php",       "POST"),
    ("pub",       "pub.php",                            "GET"),
    # Apple endpoint référencé dans le DLL
    ("albert_apple", "https://albert.apple.com/deviceservices/drmHandshake", "GET"),
]

# Payloads minimaux pour observer le comportement
PAYLOADS = {
    "empty": {},
    "udid_only": {"UDID": "00008101-0000000000000001"},
    "device_full": {
        "UDID": "00008101-001234567890ABCD",
        "ECID": "0x1234567890ABCDEF",
        "IMEI": "356123456789012",
        "SerialNumber": "F4GW4XYZQ1GR",
        "ProductType": "iPhone10,1",
        "ProductVersion": "16.0",
        "ChipID": 8020,
        "BoardID": 6,
    },
}

def detect_response_type(content: bytes, headers: dict) -> str:
    """Détecte le type de réponse HTTP."""
    if not content:
        return "empty"
    sample_bytes = content[:1024]

    if b"gorizontal-vertikal" in content or b"<title>Just a moment" in content:
        return "cloudflare_challenge"
    if b"cf-mitigated" in sample_bytes:
        return "cloudflare_challenge"

    try:
        text_sample = sample_bytes.decode("utf-8", errors="replace")
    except:
        return f"binary_{len(content)}b"

    tl = text_sample.lstrip()[:200].lower()
    if tl.startswith("<?xml") or "<plist" in text_sample[:100]:
        return "plist"
    if tl.startswith("{") or tl.startswith("["):
        try:
            json.loads(text_sample)
            return "json"
        except:
            pass
    if "<!doctype" in tl or "<html" in tl or "<head" in tl:
        return "html"
    if len(content) == 16:
        return f"raw_16bytes_b64:{base64.b64encode(content).decode()}"
    if len(content) <= 24 and all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in content):
        return f"base64:{content.decode()}"
    if len(text_sample) < 100:
        return f"short_text:{text_sample.strip()!r}"
    return f"raw_{len(content)}_bytes"

def probe_endpoint(name: str, path: str, method: str) -> dict:
    """Probe un endpoint avec différents payloads."""
    url = path if path.startswith("http") else f"{BASE}/{path}"
    result = {
        "endpoint": name,
        "url": url,
        "method": method,
        "tests": [],
    }

    print(f"\n{'='*70}")
    print(f"[*] Probing: {name} ({method} {url})")
    print('='*70)

    for plabel, payload in PAYLOADS.items():
        try:
            start = time.time()
            if method == "GET":
                r = requests.get(url, timeout=15, allow_redirects=True)
            else:
                r = requests.post(url, json=payload, timeout=15,
                                  headers={"Content-Type": "application/json"})
            elapsed_ms = int((time.time() - start) * 1000)

            rtype = detect_response_type(r.content, dict(r.headers))
            preview = r.content[:300].decode("utf-8", errors="replace")

            # Headers clés
            interesting_headers = {
                k: v for k, v in r.headers.items()
                if k.lower() in ("server", "content-type", "set-cookie",
                                  "cf-ray", "cf-cache-status", "x-powered-by",
                                  "strict-transport-security", "x-frame-options",
                                  "access-control-allow-origin")
            }

            test = {
                "payload_label": plabel,
                "status": r.status_code,
                "response_type": rtype,
                "size": len(r.content),
                "elapsed_ms": elapsed_ms,
                "headers": interesting_headers,
                "body_preview": preview,
            }
            result["tests"].append(test)

            print(f"  [{plabel:12}] {r.status_code} {elapsed_ms:4}ms {len(r.content):5}B → {rtype}")
            if rtype not in ("html", "cloudflare_challenge", "json", "empty"):
                print(f"     Preview: {preview[:200]}")

        except requests.exceptions.SSLError as e:
            print(f"  [{plabel:12}] SSL error: {e}")
            result["tests"].append({"payload_label": plabel, "error": "ssl", "detail": str(e)[:200]})
        except requests.exceptions.Timeout as e:
            print(f"  [{plabel:12}] timeout")
            result["tests"].append({"payload_label": plabel, "error": "timeout"})
        except requests.exceptions.ConnectionError as e:
            print(f"  [{plabel:12}] connection error: {str(e)[:100]}")
            result["tests"].append({"payload_label": plabel, "error": "connection", "detail": str(e)[:200]})
        except Exception as e:
            print(f"  [{plabel:12}] error: {e}")
            result["tests"].append({"payload_label": plabel, "error": str(e)[:200]})

        time.sleep(0.6)  # Rate limit gentil

    return result

def main():
    print(f"[*] Target: {BASE}")
    print(f"[*] Output: {OUT_DIR}")
    print(f"[*] Endpoints to probe: {len(ENDPOINTS)}")

    all_results = []
    for name, path, method in ENDPOINTS:
        result = probe_endpoint(name, path, method)
        all_results.append(result)

    # Save
    out_json = OUT_DIR / "endpoint_probes.json"
    out_json.write_text(json.dumps(all_results, indent=2, ensure_ascii=False))
    print(f"\n[+] Saved JSON: {out_json}")

    # Summary
    print(f"\n{'='*70}\nSUMMARY\n{'='*70}")
    for r in all_results:
        if not r["tests"]:
            print(f"  {r['endpoint']:15} NO TESTS")
            continue
        statuses = set(t.get("status", "?") for t in r["tests"] if "status" in t)
        types = set(t.get("response_type", "?") for t in r["tests"] if "response_type" in t)
        print(f"  {r['endpoint']:15} status={sorted(statuses)} types={sorted(set(t.split(':')[0] for t in types))}")

if __name__ == "__main__":
    main()
