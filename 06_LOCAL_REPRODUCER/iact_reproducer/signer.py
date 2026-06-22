# filepath: 06_LOCAL_REPRODUCER/iact_reproducer/signer.py
"""PKCS#1 v1.5 RSA-2048 signer for the iAct8 reproducer.

This module emulates the call that iRemoval PRO makes on the server
side of ``iact8.php``::

    openssl_sign(
        data = bplist00(activation_ticket),
        signature,
        private_key,
        OPENSSL_ALGO_SHA256,   # historically SHA-1 on older iOS
    );

Apple's iActivation tickets use **RSASSA-PKCS1-v1_5** with a SHA-1
digest on older iOS revisions and SHA-256 on newer ones. We default to
SHA-256 to match current Apple practice, but expose the choice so
researchers can reproduce historical samples.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.hashes import HashAlgorithm

from . import keys as _keys


# --------------------------------------------------------------------------- #
# Supported digests
# --------------------------------------------------------------------------- #

SUPPORTED_HASHES = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


def _resolve_hash(name: str) -> HashAlgorithm:
    try:
        return SUPPORTED_HASHES[name.lower()]()
    except KeyError as exc:
        raise ValueError(
            f"Unsupported hash {name!r}. Choose from {sorted(SUPPORTED_HASHES)}."
        ) from exc


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Signature:
    """A signed bundle ready to be embedded in the wire envelope."""

    data: bytes
    signature: bytes
    hash_name: str
    key_fingerprint_sha256: str

    @property
    def signature_hex(self) -> str:
        return self.signature.hex()


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def sign_bytes(
    data: bytes,
    private_key: Union[rsa.RSAPrivateKey, _keys.KeyMaterial, PrivateKeyTypes],
    *,
    hash_name: str = "sha256",
) -> Signature:
    """Sign ``data`` with PKCS#1 v1.5 + RSA-2048.

    Parameters
    ----------
    data:
        The plaintext bytes to sign (e.g. the bplist00 ticket).
    private_key:
        Either an :class:`RSAPrivateKey`, a :class:`KeyMaterial`
        wrapper, or any private key object accepted by ``cryptography``.
    hash_name:
        Name of the hash algorithm. Defaults to ``"sha256"``.

    Returns
    -------
    Signature
        A dataclass with the data, the signature bytes, the hash name
        and the SHA-256 fingerprint of the signing key.
    """
    if isinstance(private_key, _keys.KeyMaterial):
        rsa_key = private_key.private_key
        fingerprint = private_key.fingerprint_sha256
    elif isinstance(private_key, rsa.RSAPrivateKey):
        rsa_key = private_key
        fingerprint = _fingerprint_of(private_key)
    else:
        # Generic private key object (rare path). Cast and continue.
        rsa_key = private_key  # type: ignore[assignment]
        fingerprint = "<unknown>"

    hash_algo = _resolve_hash(hash_name)

    signature_bytes = rsa_key.sign(
        data,
        padding.PKCS1v15(),
        hash_algo,
    )

    return Signature(
        data=data,
        signature=signature_bytes,
        hash_name=hash_name.lower(),
        key_fingerprint_sha256=fingerprint,
    )


def verify_bytes(
    data: bytes,
    signature: bytes,
    public_key,
    *,
    hash_name: str = "sha256",
) -> bool:
    """Verify a PKCS#1 v1.5 RSA-2048 signature. Used in tests."""
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    from cryptography.exceptions import InvalidSignature

    hash_algo = _resolve_hash(hash_name)
    try:
        public_key.verify(signature, data, _pad.PKCS1v15(), hash_algo)
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #

def _fingerprint_of(key: rsa.RSAPrivateKey) -> str:
    import hashlib
    der = key.private_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.DER,
        format=__import__("cryptography").hazmat.primitives.serialization.PrivateFormat.PKCS8,
        encryption_algorithm=__import__("cryptography").hazmat.primitives.serialization.NoEncryption(),
    )
    return hashlib.sha256(der).hexdigest()
