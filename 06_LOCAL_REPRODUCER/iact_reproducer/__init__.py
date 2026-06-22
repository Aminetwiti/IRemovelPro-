"""iAct8 local reproducer (OFFENSIVE  RESEARCH).

Recreates the LOCAL signing pipeline that iRemoval PRO's ``iact8.php``
endpoint triggers on the server side:

    1. Load (or generate) the iRemoval RSA-2048 private key.
    2. Build a binary plist (bplist00) carrying the activation artefacts
       (DeviceCertificate, SigningIdentity, FairPlayCertificate,
       WildcardTicket, ...).
    3. Sign the plist with PKCS#1 v1.5 RSA-2048 (Apple-style).
    4. Wrap the whole thing as the JSON+base64 envelope that
       ``iact8.php`` expects.

All artefacts produced here are **clearly marked as test fixtures**.
They are not functional activation tickets and will not unlock any
device. The purpose is to give blue teams, detection engineers and
Apple security a reproducible harness to study the wire format,
exercise YARA/SIGMA rules and train ML models.

See ``01_REPORTS/ENDPOINT_IACT8.md`` and
``01_REPORTS/CRYPTO_CRITICAL_ANALYSIS.md`` for the upstream analysis
that motivated this reproducer.
"""

__all__ = [
    "keys",
    "bplist_builder",
    "signer",
    "wire_format",
    "orchestrator",
    "corpus_generator",
    "multi_endpoint_corpus",
    "yara_runner",
    "mock_server",
    "pcap_writer",
    "dashboard",
    "run_lab",
]

__version__ = "1.1.0"
__classification__ = "OFFENSIVE _RESEARCH"
