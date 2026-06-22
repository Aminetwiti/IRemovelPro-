#!/usr/bin/env python3
"""
iremo_clone_server.py — iRemovalClone server in pure Python (Flask)

Reconstruction complète du serveur s13.iremovalpro.com en Python pur.
Reproduit exactement les 9 endpoints et l'algorithme crypto.

Dépendances :
   pip install flask pycryptodome

Usage :
   python iremo_clone_server.py
   # Puis dans un autre terminal :
   python test_clone_server.py http://127.0.0.1:5000
"""
import os
import json
import secrets
import hashlib
import base64
import logging
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, make_response, send_from_directory
from Crypto.PublicKey import RSA
try:
    from Crypto.Signature import pkcs1_15 as pkcs1_v1_5
except ImportError:
    from Crypto.Signature import pkcs1_v1_5  # type: ignore
from Crypto.Hash import SHA1

# ============================================================================
# Configuration
# ============================================================================

APP_VERSION = "7.2"
SERVER_NAME = "5.252.32.98"
PBKDF2_SALT = b"iremovalpro-iact8-v1"
PBKDF2_ITERATIONS = 10000
PBKDF2_DKLEN = 16
NONCE_BYTES = 16
RSA_BITS = 1024

BASE_DIR = Path(__file__).parent
VAR_DIR = BASE_DIR / "var"
KEYS_DIR = VAR_DIR / "keys"
SESSIONS_DIR = VAR_DIR / "sessions"
TICKETS_DIR = VAR_DIR / "tickets"
LOGS_DIR = VAR_DIR / "logs"

for d in [KEYS_DIR, SESSIONS_DIR, TICKETS_DIR, LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler(LOGS_DIR / "server.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("iremo-clone")

app = Flask(__name__, static_folder=None)

# ============================================================================
# Crypto helpers
# ============================================================================

def generate_nonce() -> bytes:
    """16 octets aléatoires (CSPRNG)."""
    return secrets.token_bytes(NONCE_BYTES)


def derive_session_key(session_id: str, nonce_a: bytes, nonce_b: bytes) -> bytes:
    """
    Reconstitue PBKDF2-HMAC-SHA256 du binaire original :
        P = "{sessionId}:{b64(nonceA)}:{b64(nonceB)}"
        S = "iremovalpro-iact8-v1"
        c = 10000
        dkLen = 16
    """
    password = f"{session_id}:{base64.b64encode(nonce_a).decode()}:{base64.b64encode(nonce_b).decode()}".encode()
    derived = hashlib.pbkdf2_hmac(
        'sha256', password, PBKDF2_SALT, PBKDF2_ITERATIONS, PBKDF2_DKLEN
    )
    return derived


def load_or_generate_rsa_key() -> RSA.RsaKey:
    """Charge ou génère la clé privée RSA-1024 bypass."""
    priv_path = KEYS_DIR / "bypass_private.pem"
    pub_path  = KEYS_DIR / "bypass_public.pem"

    if priv_path.exists():
        with open(priv_path, "rb") as f:
            return RSA.import_key(f.read())

    log.warning("No RSA key found, generating new RSA-1024 pair...")
    key = RSA.generate(RSA_BITS)
    with open(priv_path, "wb") as f:
        f.write(key.export_key("PEM"))
    os.chmod(priv_path, 0o600)
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key("PEM"))
    return key


def sign_activation_ticket(data: bytes, private_key: RSA.RsaKey) -> bytes:
    """Signe le ticket avec RSA-1024 PKCS#1 v1.5 + SHA-1 (comme l'original)."""
    h = SHA1.new(data)
    signer = pkcs1_v1_5.new(private_key)
    return signer.sign(h)


def verify_activation_ticket(data: bytes, signature: bytes, public_key: RSA.RsaKey) -> bool:
    h = SHA1.new(data)
    verifier = pkcs1_v1_5.new(public_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def hmac_sign(body: bytes, secret: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def hmac_verify(body: bytes, secret: bytes, expected: str) -> bool:
    return hmac.compare_digest(hmac_sign(body, secret), expected)


import hmac  # imported here after definition to avoid circular

# ============================================================================
# Session management
# ============================================================================

class SessionManager:
    def __init__(self, sessions_dir: Path):
        self.dir = sessions_dir

    def create(self) -> dict:
        sid = secrets.token_hex(16)
        session = {
            "id":         sid,
            "state":      "CREATED",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "device_info": {},
        }
        self._save(sid, session)
        log.info(f"Session created: {sid}")
        return session

    def get(self, sid: str) -> dict | None:
        if not sid:
            return None
        path = self._path(sid)
        if not path.exists():
            return None
        return json.loads(path.read_text())

    def get_or_create(self, sid: str | None) -> dict:
        if sid:
            s = self.get(sid)
            if s:
                return s
        return self.create()

    def update(self, sid: str, patch: dict) -> dict:
        session = self.get(sid) or {"id": sid, "created_at": datetime.utcnow().isoformat()}
        session.update(patch)
        session["updated_at"] = datetime.utcnow().isoformat()
        self._save(sid, session)
        return session

    def _save(self, sid: str, data: dict) -> None:
        path = self._path(sid)
        path.write_text(json.dumps(data, indent=2))

    def _path(self, sid: str) -> Path:
        safe = "".join(c for c in sid if c in "0123456789abcdef")
        return self.dir / f"{safe}.json"


sessions = SessionManager(SESSIONS_DIR)
rsa_key = load_or_generate_rsa_key()


# ============================================================================
# Helpers
# ============================================================================

def nonce_response(nonce: bytes) -> "Response":
    """Renvoie le nonce en base64 (24 chars = 16 octets), comme l'original."""
    r = make_response(base64.b64encode(nonce).decode())
    r.headers["Content-Type"] = "text/html; charset=UTF-8"
    r.headers["Server"] = SERVER_NAME
    return r


def get_or_create_session() -> dict:
    """Récupère la session via PHPSESSID ou en crée une nouvelle."""
    sid = request.cookies.get("PHPSESSID")
    if sid:
        s = sessions.get(sid)
        if s:
            return s
    s = sessions.create()
    return s


def set_session_cookie(resp, sid: str) -> None:
    resp.set_cookie("PHPSESSID", sid, httponly=True, samesite="Strict")


def build_activation_record(device: dict) -> dict:
    """Construit le iActivationRecord comme le dylib le formate."""
    return {
        "ActivationRecord": {
            "SerialNumber":     device.get("serial", "F2LXX0Q0A1B2"),
            "IMEI":             device.get("imei", "000000000000000"),
            "MEID":             device.get("meid", "00000000000000"),
            "UniqueDeviceID":   device.get("udid"),
            "UniqueChipID":     device.get("ecid", "0"),
            "MLB":              device.get("mlb", "0000000000000000000000000000000000000000"),
            "ChipID":           device.get("chip_id", "0x8010"),
            "ProductType":      device.get("model", "iPhone14,2"),
            "ProductVersion":   device.get("ios", "16.0"),
            "BasebandMasterKeyHash": "0" * 64,
        },
        "ActivationInfo": {
            "ActivationState":         "Activated",
            "SIMStatus":               "None",
            "BrickMode":               False,
            "SecurityDomain":          1,
            "EffectiveProductionMode": True,
            "EffectiveSecurityMode":   False,
        },
        "iRemovalRecord":    "",  # filled below
        "iRemovalSignature": "",  # filled below
    }


def build_removal_record(device: dict) -> str:
    """Le 'iRemovalRecord' BlackHound (3 parties base64 séparées par '.')."""
    p1 = base64.b64encode(hashlib.sha256(
        (device.get("udid", "") + device.get("serial", "")).encode()).digest()).decode()
    p2 = base64.b64encode(hashlib.sha256(
        (device.get("udid", "") + device.get("imei", "")).encode()).digest()).decode()
    p3 = base64.b64encode(json.dumps({
        "meid": device.get("meid", ""),
        "ecid": device.get("ecid", ""),
    }).encode()).decode()
    return f"{p1}.{p2}.{p3}"


# ============================================================================
# Endpoints
# ============================================================================

@app.route("/version33.txt", methods=["GET"])
def version33():
    """GET /version33.txt - Version check."""
    r = make_response(APP_VERSION)
    r.headers["Content-Type"] = "text/plain"
    r.headers["Server"] = SERVER_NAME
    log.info("version33 hit")
    return r


@app.route("/iremovalActivation/ars2.php", methods=["POST"])
def ars2():
    """POST ars2.php - State register."""
    session = get_or_create_session()
    body = request.get_json(force=True, silent=True) or {}
    sessions.update(session["id"], {"last_endpoint": "ars2", "device_info": body})
    resp = nonce_response(generate_nonce())
    set_session_cookie(resp, session["id"])
    log.info(f"ars2: session={session['id']} body={body}")
    return resp


@app.route("/iremovalActivation/auth3.php", methods=["POST"])
def auth3():
    """POST auth3.php - Authentication. Returns nonceA."""
    session = get_or_create_session()
    body = request.get_json(force=True, silent=True) or {}

    sessions.update(session["id"], {
        "state": "AUTHENTICATED",
        "device_info": body,
    })

    # Generate nonceA and store it
    nonce_a = generate_nonce()
    sessions.update(session["id"], {
        "nonce_a_b64": base64.b64encode(nonce_a).decode(),
    })

    resp = nonce_response(nonce_a)
    set_session_cookie(resp, session["id"])
    log.info(f"auth3: session={session['id']} udid={body.get('udid')}")
    return resp


@app.route("/iremovalActivation/checkm8.php", methods=["POST"])
def checkm8():
    """POST checkm8.php - Exploit ack. Returns nonceB + derives nonceC."""
    session = get_or_create_session()
    body = request.get_json(force=True, silent=True) or {}

    # Generate nonceB
    nonce_b = generate_nonce()

    # Derive nonceC
    s = sessions.get(session["id"])
    nonce_a = base64.b64decode(s.get("nonce_a_b64", "")) if s.get("nonce_a_b64") else b"\x00" * 16
    nonce_c = derive_session_key(session["id"], nonce_a, nonce_b)

    sessions.update(session["id"], {
        "state": "EXPLOITED",
        "device_info": {**s.get("device_info", {}), **body},
        "nonce_b_b64": base64.b64encode(nonce_b).decode(),
        "nonce_c_b64": base64.b64encode(nonce_c).decode(),
    })

    resp = nonce_response(nonce_b)
    set_session_cookie(resp, session["id"])
    log.info(f"checkm8: session={session['id']} nonceC={base64.b64encode(nonce_c).decode()}")
    return resp


@app.route("/iremovalActivation/iact8.php", methods=["POST"])
def iact8():
    """
    POST iact8.php - THE HEART.
    Génère le ticket iActivation forgé, signé avec RSA-1024.
    """
    session = get_or_create_session()
    body = request.get_json(force=True, silent=True) or {}
    s = sessions.get(session["id"])

    # Verify HMAC if present
    sig = request.headers.get("X-Signature")
    if sig and s.get("nonce_c_b64"):
        nonce_c = base64.b64decode(s["nonce_c_b64"])
        if not hmac_verify(request.get_data(), nonce_c, sig):
            log.warning(f"iact8 HMAC verify failed: session={session['id']}")
            return make_response("HMAC invalid", 403)

    # Build device info
    device = {**(s.get("device_info", {}) if s else {}), **body}

    # Build the record
    record = build_activation_record(device)
    record["iRemovalRecord"] = build_removal_record(device)

    # Sign the record (RSA-1024 + SHA-1, PKCS#1 v1.5)
    record_json = json.dumps(record, separators=(',', ':'))
    record_bytes = record_json.encode("utf-8")
    signature = sign_activation_ticket(record_bytes, rsa_key)

    # Build ticket response
    ticket = {
        "iRemovalRecord":    base64.b64encode(record["iRemovalRecord"].encode()).decode(),
        "iRemovalSignature": base64.b64encode(signature).decode(),
        "publicKey":         rsa_key.publickey().export_key("PEM").decode(),
        "algorithm":         "RSA-1024 PKCS#1 v1.5 / SHA-1",
    }

    # Save ticket to disk
    ticket_path = TICKETS_DIR / f"{session['id']}.json"
    ticket_path.write_text(json.dumps(ticket, indent=2))

    sessions.update(session["id"], {
        "state": "ACTIVATED",
        "ticket_path": str(ticket_path),
    })

    log.info(f"iact8: ACTIVATED session={session['id']} udid={device.get('udid')}")
    log.info(f"  sig_len={len(signature)} record_len={len(record_bytes)}")

    # Reproduce the original response: 16-byte nonce C
    resp = nonce_response(base64.b64decode(s.get("nonce_c_b64", base64.b64encode(b"\x00" * 16).decode())))
    set_session_cookie(resp, session["id"])
    return resp


@app.route("/iremovalActivation/mf5.php", methods=["POST"])
def mf5():
    session = get_or_create_session()
    sessions.update(session["id"], {"last_endpoint": "mf5"})
    log.info(f"mf5: session={session['id']}")
    resp = nonce_response(generate_nonce())
    set_session_cookie(resp, session["id"])
    return resp


@app.route("/iremovalActivation/mf6.php", methods=["POST"])
def mf6():
    session = get_or_create_session()
    sessions.update(session["id"], {"state": "MF6_HIT"})
    log.info(f"mf6: session={session['id']}")
    resp = nonce_response(generate_nonce())
    set_session_cookie(resp, session["id"])
    return resp


@app.route("/iremovalActivation/mf7.php", methods=["POST"])
def mf7():
    session = get_or_create_session()
    sessions.update(session["id"], {"state": "MF7_HIT"})
    log.info(f"mf7: session={session['id']}")
    resp = nonce_response(generate_nonce())
    set_session_cookie(resp, session["id"])
    return resp


@app.route("/pub.php", methods=["GET", "POST"])
def pub():
    log.info(f"pub: method={request.method} body={request.get_data().decode()[:200]}")
    return nonce_response(generate_nonce())


@app.route("/Payax0.php", methods=["POST"])
def payax0():
    body = request.get_json(force=True, silent=True) or {}
    log.info(f"Payax0: amount={body.get('amount')} txn={body.get('txn_id')}")
    return jsonify({"status": "ok", "msg": "payment received (simulation)"})


# ============================================================================
# Admin / debug endpoints
# ============================================================================

@app.route("/admin/key-info", methods=["GET"])
def key_info():
    pub = rsa_key.publickey()
    return jsonify({
        "bits":         rsa_key.size_in_bits(),
        "modulus_hex":  pub.n.to_bytes(128, "big").hex(),
        "modulus_b64":  base64.b64encode(pub.n.to_bytes(128, "big")).decode(),
        "exponent":     pub.e,
        "sha1_fpr":     hashlib.sha1(pub.export_key("DER")).hexdigest(),
    })


@app.route("/admin/sessions", methods=["GET"])
def list_sessions():
    return jsonify([
        json.loads(p.read_text())
        for p in SESSIONS_DIR.glob("*.json")
    ])


@app.route("/tickets/<sid>.json", methods=["GET"])
def get_ticket(sid):
    """Sert le ticket généré (endpoint utilisé par le client iOS)."""
    safe = "".join(c for c in sid if c in "0123456789abcdef")
    path = TICKETS_DIR / f"{safe}.json"
    if not path.exists():
        return make_response("Not found", 404)
    return send_from_directory(TICKETS_DIR, f"{safe}.json")


@app.route("/", methods=["GET"])
def index():
    return make_response("""
iRemovalClone (Python/Flask) — Endpoints:
  GET  /version33.txt
  POST /iremovalActivation/{ars2,auth3,checkm8,iact8,mf5,mf6,mf7}.php
  POST /pub.php
  POST /Payax0.php
  GET  /admin/key-info
  GET  /admin/sessions
  GET  /tickets/<session_id>.json
""", 200)


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    pub = rsa_key.publickey()
    log.info("=" * 70)
    log.info(" iRemovalClone (Python) — Ready")
    log.info("=" * 70)
    log.info(f" RSA-1024 modulus: {base64.b64encode(pub.n.to_bytes(128, 'big')).decode()[:50]}...")
    log.info(f" PBKDF2 salt:      '{PBKDF2_SALT.decode()}'")
    log.info(f" PBKDF2 iterations:{PBKDF2_ITERATIONS}")
    log.info(f" Listening on:      http://127.0.0.1:5000")
    log.info("=" * 70)
    app.run(host="127.0.0.1", port=5000, debug=False)
