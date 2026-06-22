#!/usr/bin/env python3
import requests, json
from pathlib import Path
OUT = Path(r"c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\03_OUTPUTS\server_probe\http_headers.json")

URLS = [
    ("https://s13.iremovalpro.com/", "GET", None),
    ("https://s13.iremovalpro.com/version33.txt", "GET", None),
    ("https://s13.iremovalpro.com/iremovalActivation/auth3.php", "POST", {}),
    ("https://s13.iremovalpro.com/iremovalActivation/iact8.php", "POST", {}),
    ("https://s13.iremovalpro.com/iremovalActivation/checkm8.php", "POST", {}),
    ("https://s13.iremovalpro.com/iremovalActivation/ars2.php", "POST", {}),
    ("https://s13.iremovalpro.com/iremovalActivation/mf5.php", "POST", {}),
    ("https://s13.iremovalpro.com/iremovalActivation/mf6.php", "POST", {}),
    ("https://s13.iremovalpro.com/iremovalActivation/mf7.php", "POST", {}),
    ("https://s13.iremovalpro.com/pub.php", "GET", None),
]

results = []
for url, method, body in URLS:
    try:
        if method == "GET":
            r = requests.get(url, timeout=15, allow_redirects=False,
                             headers={"User-Agent": "curl/7.79 (research)"})
        else:
            r = requests.post(url, json=body, timeout=15, allow_redirects=False,
                              headers={"User-Agent": "curl/7.79 (research)",
                                       "Content-Type": "application/json",
                                       "Accept": "application/json"})
        results.append({
            "url": url, "method": method,
            "status": r.status_code,
            "headers": {k: v for k, v in r.headers.items()},
            "body_b64": r.content.hex() if r.content else "",
            "body_text": r.text,
            "body_size": len(r.content),
        })
    except Exception as e:
        results.append({"url": url, "method": method, "error": str(e)[:200]})

OUT.write_text(json.dumps(results, indent=2, ensure_ascii=False))
print(f"[+] Saved {len(results)} requests to {OUT}")
print("\n=== HEADER ANALYSIS ===")
for r in results:
    if "error" in r: continue
    print(f"\n{r['method']} {r['url']}  [{r['status']}]")
    interesting = {k: v for k, v in r["headers"].items()
                    if k.lower() in ("server", "via", "x-powered-by",
                                      "cf-ray", "cf-cache-status",
                                      "strict-transport-security",
                                      "content-type", "x-frame-options",
                                      "access-control-allow-origin",
                                      "x-served-by", "x-cache", "age",
                                      "x-amz-cf-id", "x-amz-cf-pop",
                                      "server-timing", "alt-svc")}
    for k, v in sorted(interesting.items()):
        vs = v[:200] if isinstance(v, str) else str(v)[:200]
        print(f"  {k:30} = {vs}")
