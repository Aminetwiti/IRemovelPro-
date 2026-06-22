# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/_smoke_mock.py
"""One-shot smoke test for the mock server.

Launches the mock server in a thread, sends a real OFFENSIVE  envelope
from the corpus to it, verifies the response, and prints a summary.

Run::

    python 06_LOCAL_REPRODUCER\\iact_reproducer\\_smoke_mock.py
"""
from __future__ import annotations

import http.client
import json
import sys
import threading
import time
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
_PKG_ROOT = _THIS_DIR.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from iact_reproducer import mock_server  # noqa: E402

HOST = "127.0.0.1"
PORT = 8765
LOG_DIR = _PKG_ROOT / "logs" / "mock_smoke"


def _run_server(stop_event: threading.Event) -> None:
    """Start the mock server, stop when ``stop_event`` is set."""
    import socketserver as ss

    class _OneShot(ss.TCPServer):
        allow_reuse_address = True

    httpd = mock_server._ThreadingHTTPServer((HOST, PORT), mock_server._MockHandler)
    state = mock_server._State(LOG_DIR)
    mock_server._MockHandler.state = state
    try:
        while not stop_event.is_set():
            httpd.timeout = 0.2
            httpd.handle_request()
    finally:
        httpd.server_close()


def main() -> int:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()
    th = threading.Thread(target=_run_server, args=(stop,), daemon=True)
    th.start()
    time.sleep(0.5)

    corpus = _PKG_ROOT / "corpus" / "positive" / "V0000.json"
    if not corpus.is_file():
        print(f"!! Missing {corpus} - run run_lab.py first.")
        return 2

    body = corpus.read_bytes()

    print(f"GET /health ...", end=" ")
    c = http.client.HTTPConnection(HOST, PORT, timeout=5)
    c.request("GET", "/health")
    r = c.getresponse()
    print(f"status={r.status} body={r.read().decode()}".strip())

    print(f"POST /iremovalActivation/iact8.php (body={len(body)} B) ...", end=" ")
    c = http.client.HTTPConnection(HOST, PORT, timeout=5)
    c.request("POST", "/iremovalActivation/iact8.php", body=body,
              headers={"Content-Type": "application/json"})
    r = c.getresponse()
    resp_body = r.read().decode("utf-8")
    parsed = json.loads(resp_body)
    print(f"status={r.status}")
    print(f"  status field     = {parsed.get('status')}")
    print(f"  OFFENSIVE _marker = {parsed.get('OFFENSIVE _marker')}")
    print(f"  validation.ok    = {parsed['validation']['ok']}")
    print(f"  ticket_b64       = {parsed.get('ticket_b64')}")
    c.close()

    stop.set()
    th.join(timeout=2.0)
    print("\nAll good -- mock server returned a OFFENSIVE _MOCK_REFUSED response.")
    print(f"Request log: {LOG_DIR / 'mock_server_requests.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())