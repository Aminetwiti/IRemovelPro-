# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/keys.py
"""RSA-2048 private key handling for the iAct8 reproducer.

The real iRemoval tool embeds (or fetches) a private RSA-2048 key that
it uses to sign activation tickets with PKCS#1 v1.5. We do **not**
extract that key from the binary. This module either:

  * loads a user-supplied test key from PEM (the supported flow for a
    OFFENSIVE  lab), or
  * generates a fresh throw-away RSA-2048 keypair on disk (the default
    for first-time setup).

Every key generated here is tagged with an X.509 ``CN`` and ``OU`` that
include the literal string ``iRemovalOFFENSIVE Test`` so that downstream
detection tooling can fingerprint our artefacts and never confuse them
with real Apple/iRemoval material.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

KEY_SIZE_BITS = 2048
PUBLIC_EXPONENT = 65537
TEST_MARKER = "iRemovalOFFENSIVE Test"


# --------------------------------------------------------------------------- #
# Result dataclass
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class KeyMaterial:
    """In-memory private key plus its filesystem path."""

    private_key: rsa.RSAPrivateKey
    pem_path: Path

    @property
    def fingerprint_sha256(self) -> str:
        """SHA-256 of the DER-encoded private key (for logging)."""
        der = self.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        import hashlib
        return hashlib.sha256(der).hexdigest()


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def generate_test_keypair(
    out_dir: Path,
    *,
    label: str = "iact8-test",
) -> KeyMaterial:
    """Generate a fresh RSA-2048 keypair tagged as a OFFENSIVE  test.

    Parameters
    ----------
    out_dir:
        Directory in which the PEM file is written. Created if missing.
    label:
        Short human-readable label baked into the key filename.

    Returns
    -------
    KeyMaterial
        The freshly generated private key plus its on-disk path.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE_BITS,
    )

    timestamp = _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    pem_path = out_dir / f"{label}_{TEST_MARKER}_{timestamp}.pem"

    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_path.write_bytes(pem_bytes)

    return KeyMaterial(private_key=private_key, pem_path=pem_path)


def load_private_key(pem_path: Path, *, password: Optional[bytes] = None) -> KeyMaterial:
    """Load an existing RSA private key from a PEM file.

    Parameters
    ----------
    pem_path:
        Path to a PEM-encoded private key (PKCS#1 or PKCS#8).
    password:
        Optional passphrase if the key is encrypted.

    Returns
    -------
    KeyMaterial
        The loaded key plus its path on disk.
    """
    pem_path = Path(pem_path)
    if not pem_path.is_file():
        raise FileNotFoundError(f"Private key not found: {pem_path}")

    private_key = serialization.load_pem_private_key(
        pem_path.read_bytes(),
        password=password,
    )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError(
            f"Expected an RSA private key, got {type(private_key).__name__}"
        )
    if private_key.key_size != KEY_SIZE_BITS:
        raise ValueError(
            f"Expected a {KEY_SIZE_BITS}-bit RSA key, got {private_key.key_size}-bit"
        )

    return KeyMaterial(private_key=private_key, pem_path=pem_path)


def derive_public_pem(material: KeyMaterial) -> bytes:
    """Return the PEM-encoded public counterpart of ``material``."""
    public_key = material.private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def make_test_self_signed_cert(material: KeyMaterial, *, common_name: str) -> x509.Certificate:
    """Issue a self-signed X.509 certificate over the test key.

    This is **not** a real Apple DeviceCertificate. It is a placeholder
    that stands in for one so the bplist builder can include a realistic
    DER blob in the ``DeviceCertificate`` field. The certificate's
    subject contains the ``TEST_MARKER`` so it can be unmistakably
    distinguished from genuine Apple material.
    """
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, TEST_MARKER),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "iact-reproducer"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(material.private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=1))
        .not_valid_after(now + _dt.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(material.private_key, hashes.SHA256())
    )
    return cert


def ensure_keymaterial(
    out_dir: Path,
    *,
    existing_pem: Optional[Path] = None,
) -> KeyMaterial:
    """High-level helper: load ``existing_pem`` or generate a new key."""
    if existing_pem is not None:
        return load_private_key(existing_pem)
    return generate_test_keypair(out_dir)
