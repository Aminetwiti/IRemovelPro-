"""Self-sign the RELEASE_MANIFEST.txt with a local RSA-2048 key.

Output:
  * `RELEASE_MANIFEST.sig`   — base64 PKCS#1 v1.5 signature
  * `RELEASE_MANIFEST.pub`   — PEM public key (for verification)
  * `RELEASE_MANIFEST.tsr`   — human-readable transcript: pubkey FP, manifest FP, signature

The key is local-only; for a production release, swap this for `cosign sign-blob` with
a Sigstore keyless signature or a KMS-backed key.
"""
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

OUT = Path("06_LOCAL_REPRODUCER")
MANIFEST = OUT / "RELEASE_MANIFEST.txt"
SIG = OUT / "RELEASE_MANIFEST.sig"
PUB = OUT / "RELEASE_MANIFEST.pub"
TSR = OUT / "RELEASE_MANIFEST.tsr"

# Reuse or generate the key.  We persist it so the same key can verify the
# signature later without rebuilding the lab.
PRIV_KEY_PATH = OUT / "RELEASE_MANIFEST.key"

if PRIV_KEY_PATH.exists():
    priv = serialization.load_pem_private_key(PRIV_KEY_PATH.read_bytes(), password=None)
else:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    PRIV_KEY_PATH.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

manifest_bytes = MANIFEST.read_bytes()
manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()

sig = priv.sign(
    manifest_bytes,
    padding.PKCS1v15(),
    hashes.SHA256(),
)

SIG.write_bytes(base64.b64encode(sig))

pub_pem = priv.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
PUB.write_bytes(pub_pem)

pub_sha = hashlib.sha256(pub_pem).hexdigest()
ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

TSR.write_text(
    f"""iAct8 Lab release signature — v5.2-LAB-0.2
Generated     : {ts}
Algorithm     : RSA-2048 + PKCS#1 v1.5 + SHA-256
Pubkey SHA-256: {pub_sha}
Pubkey SHA-1  : {hashlib.sha1(pub_pem).hexdigest()}
Pubkey SHA-256 (first 16): {pub_sha[:16]}

Manifest SHA-256: {manifest_sha}
Manifest size   : {len(manifest_bytes)} bytes
Manifest path   : {MANIFEST}

Signature (b64) : {base64.b64encode(sig).decode()}
Signature bytes : {len(sig)} bytes

Verification (Python):
    from cryptography.hazmat.primitives.asymmetric import padding, hashes
    from cryptography.hazmat.primitives import serialization
    pub = serialization.load_pem_public_key(open('RELEASE_MANIFEST.pub','rb').read())
    pub.verify(base64.b64decode(open('RELEASE_MANIFEST.sig').read()),
               open('RELEASE_MANIFEST.txt','rb').read(),
               padding.PKCS1v15(), hashes.SHA256())
    print('OK')

Verification (cosign):
    cosign verify-blob --key RELEASE_MANIFEST.pub \\
        --signature RELEASE_MANIFEST.sig RELEASE_MANIFEST.txt
""",
    encoding="utf-8",
)

print(f"signature   : {SIG} ({len(sig)} bytes)")
print(f"public key  : {PUB}")
print(f"transcript  : {TSR}")
print(f"manifest fp : {manifest_sha}")
print(f"pubkey fp   : {pub_sha}")
