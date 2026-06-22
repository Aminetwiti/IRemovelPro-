"""Verify the self-signed RELEASE_MANIFEST.txt."""
import base64
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

OUT = Path("06_LOCAL_REPRODUCER")
pub = serialization.load_pem_public_key((OUT / "RELEASE_MANIFEST.pub").read_bytes())
sig = base64.b64decode((OUT / "RELEASE_MANIFEST.sig").read_bytes())
manifest = (OUT / "RELEASE_MANIFEST.txt").read_bytes()

try:
    pub.verify(sig, manifest, padding.PKCS1v15(), hashes.SHA256())
    print("SIGNATURE OK")
    print(f"  manifest size  : {len(manifest)} bytes")
    print(f"  signature size : {len(sig)} bytes")
except Exception as exc:
    print(f"SIGNATURE FAIL: {exc}")
    raise
