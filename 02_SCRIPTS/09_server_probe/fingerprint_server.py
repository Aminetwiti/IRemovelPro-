#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fingerprint_server.py - Fingerprint passif du serveur iRemoval.

Collecte:
- TLS cert (issuer, validity, SAN, fingerprint)
- HTTP security headers
- Cookies Cloudflare (cf_ray, cf_clearance pattern)
- Timing analysis (CDN detection)
- ASN/IP info via DNS (sans IP directe)
"""
import json
import socket
import ssl
import sys
import io
import time
import re
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

try:
    import requests
except ImportError:
    print("[!] Module 'requests' requis. Installer: py -m pip install requests")
    sys.exit(1)

OUT_DIR = Path(r"c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\03_OUTPUTS\server_probe")
OUT_DIR.mkdir(parents=True, exist_ok=True)

TARGETS = [
    "s13.iremovalpro.com",
    "iremovalpro.com",
    "iremovalpro.co",
    "albert.apple.com",
]

def resolve_dns(host: str) -> dict:
    """DNS lookup passif."""
    info = {"host": host, "ips": [], "cname": None}
    try:
        # Get all IPs
        ips = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        seen = set()
        for ip_info in ips:
            ip = ip_info[4][0]
            if ip not in seen:
                info["ips"].append(ip)
                seen.add(ip)
    except Exception as e:
        info["error"] = str(e)
    return info

def get_tls_info(host: str, port: int = 443, timeout: int = 10) -> dict:
    """Récupère le certificat TLS."""
    info = {"host": host, "port": port}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    info["subject"] = dict(x[0] for x in cert.get("subject", []))
                    info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    info["version"] = cert.get("version")
                    info["serial"] = cert.get("serialNumber")
                    info["notBefore"] = cert.get("notBefore")
                    info["notAfter"] = cert.get("notAfter")
                    info["subjectAltName"] = cert.get("subjectAltName", [])
                    sig = cert.get("subjectAltName", [])
                    info["san"] = [v for t, v in sig if t == "DNS"]
                # TLS version + cipher
                info["tls_version"] = ssock.version()
                info["cipher"] = ssock.cipher()[0] if ssock.cipher() else None
    except socket.timeout:
        info["error"] = "timeout"
    except Exception as e:
        info["error"] = str(e)[:200]
    return info

def get_http_headers(host: str, path: str = "/", timeout: int = 10) -> dict:
    """Récupère headers HTTP + cookies Cloudflare."""
    info = {"url": f"https://{host}{path}"}
    try:
        r = requests.get(f"https://{host}{path}", timeout=timeout,
                          allow_redirects=False, headers={"User-Agent": "Mozilla/5.0 (research)"})
        info["status"] = r.status_code
        # Garder headers pertinents
        interesting = {}
        for k, v in r.headers.items():
            kl = k.lower()
            if kl in ("server", "via", "x-powered-by", "x-amz-cf-id",
                      "x-amz-cf-pop", "cf-ray", "cf-cache-status",
                      "cf-request-id", "strict-transport-security",
                      "x-frame-options", "x-content-type-options",
                      "x-xss-protection", "content-security-policy",
                      "server-timing", "alt-svc", "age", "x-served-by",
                      "x-cache", "x-timer", "set-cookie", "x-amz-id"):
                interesting[k] = v[:200]
        info["headers"] = interesting
        info["cookies"] = [{"name": c.split("=")[0], "value": c.split("=")[1].split(";")[0][:100]}
                            for c in r.headers.get("set-cookie", "").split("\n") if "=" in c]
    except Exception as e:
        info["error"] = str(e)[:200]
    return info

def timing_analysis(host: str) -> dict:
    """Analyse du timing des réponses (CDN detection)."""
    info = {"host": host, "timings_ms": {}}
    for path in ["/", "/version33.txt", "/favicon.ico"]:
        try:
            start = time.time()
            r = requests.get(f"https://{host}{path}", timeout=15, allow_redirects=False)
            elapsed = int((time.time() - start) * 1000)
            info["timings_ms"][path] = elapsed
        except Exception as e:
            info["timings_ms"][path] = f"error: {str(e)[:50]}"
    return info

def main():
    print(f"[*] Fingerprinting {len(TARGETS)} targets")
    results = {}

    for host in TARGETS:
        print(f"\n{'='*70}\n{host}\n{'='*70}")

        # DNS
        print("[*] DNS lookup...")
        dns = resolve_dns(host)
        print(f"    IPs: {dns.get('ips', [])}")

        # TLS
        print("[*] TLS cert...")
        tls = get_tls_info(host)
        if "error" not in tls:
            print(f"    Subject:  {tls.get('subject', {})}")
            print(f"    Issuer:   {tls.get('issuer', {})}")
            print(f"    Valid:    {tls.get('notBefore')} -> {tls.get('notAfter')}")
            print(f"    TLS ver:  {tls.get('tls_version')}")
            print(f"    Cipher:   {tls.get('cipher')}")
            print(f"    SAN:      {tls.get('san', [])[:5]}")
        else:
            print(f"    Error: {tls['error']}")

        # HTTP headers
        print("[*] HTTP headers (GET /)...")
        http = get_http_headers(host)
        if "error" not in http:
            print(f"    Status:   {http.get('status')}")
            cloudflare = {k: v for k, v in http.get("headers", {}).items() if k.lower().startswith("cf-") or "cloudflare" in str(v).lower()}
            server = {k: v for k, v in http.get("headers", {}).items() if k.lower() in ("server", "via", "x-powered-by")}
            print(f"    Server:   {server}")
            print(f"    Cloudflare: {cloudflare}")
        else:
            print(f"    Error: {http['error']}")

        # Timing
        print("[*] Timing analysis...")
        timing = timing_analysis(host)
        print(f"    Timings: {timing.get('timings_ms', {})}")

        results[host] = {
            "dns": dns,
            "tls": tls,
            "http": http,
            "timing": timing,
        }
        time.sleep(1)

    # Save
    out = OUT_DIR / "server_fingerprint.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\n[+] Saved: {out}")

    # Detect CDN
    print(f"\n{'='*70}\nCDN DETECTION\n{'='*70}")
    for host, r in results.items():
        cdn = "unknown"
        headers = r.get("http", {}).get("headers", {})
        if "cf-ray" in headers or "cf-cache-status" in headers:
            cdn = "Cloudflare"
        elif "x-amz-cf-id" in headers or "x-amz-cf-pop" in headers:
            cdn = "AWS CloudFront"
        elif "x-vercel-id" in headers:
            cdn = "Vercel"
        elif "server" in headers and "nginx" in headers["server"].lower():
            cdn = "Nginx direct (no CDN?)"
        tls = r.get("tls", {})
        issuer = tls.get("issuer", {})
        issuer_org = issuer.get("organizationName", "") if isinstance(issuer, dict) else ""
        if "Let's Encrypt" in issuer_org or "Let's Encrypt" in str(issuer):
            cdn = "Let's Encrypt cert (likely direct origin)"

        ips = r.get("dns", {}).get("ips", [])
        print(f"  {host:30} CDN: {cdn:25}  Issuer: {issuer_org}  IPs: {ips[:2]}")

if __name__ == "__main__":
    main()
