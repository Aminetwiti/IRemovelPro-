/*
    YARA Rules — §23 ADVERSARIAL DETECTION for iRemoval PRO v5.2
    Author: Audit statique — 2026-06-22
    Purpose: Detection rules for the artifacts produced by the §22
             adversarial simulation (test_adversarial.py).
             These rules target the LOCAL-ONLY lab artifacts — they
             detect attempts to reuse the §21 pipeline, NOT the real
             iRemoval tool in production.
    Severity: MEDIUM (lab/forensic artefact reuse, not active bypass)
    Reference: 01_REPORTS/BYPASS_CORE.md §23

    Companion rules (in same family):
      05_IOC/YARA_RULES.yar         — iRemoval PRO binary SHA-256
      05_IOC/YARA_RULES_WIRE.yar    — iAct8 wire format markers
      05_IOC/YARA_RULES_ADVERSARIAL.yar — §22 artefacts (this file)

    Tested with: yara-python 4.5.4
    Sample fixtures: 06_LOCAL_REPRODUCER/adversarial_tests/<TS>/
*/


rule IActEnvelope_Offensive_Lab
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "JSON envelope matching the iAct8 wire format emitted by §21 local pipeline (test_adversarial.py case 1, 6, 8, 9, 10)"
        severity = "medium"
        category = "iCloud-bypass-forgery-infrastructure"
        tlp = "LEAKED"
        section23_case = "1, 6, 8, 9, 10"
        reference = "BYPASS_CORE.md §23.3"

    strings:
        // IActEnvelope JSON shape: udid + b64 + sig + alg + nonce + ts + key_fingerprint + lab_marker
        $alg = "\"alg\":\"RSA-PKCS1v1.5-SHA256\"" ascii
        $b64 = "\"b64\":\"" ascii
        $sig = "\"sig\":\"" ascii
        $nonce = "\"nonce\":\"" ascii
        $ts = "\"ts\":\"20" ascii
        $udid = "\"udid\":\"" ascii

    condition:
        // All six wire-format fields must be present in a single JSON object
        filesize < 16KB
        and $alg and $b64 and $sig and $nonce and $ts and $udid
        and #b64 == 1 and #sig == 1
}


rule AttackerKeypair_Offensive_Lab
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "Fresh attacker-controlled RSA-2048 PEM keypair generated during §22 case 2/3/7"
        severity = "high"
        category = "iCloud-bypass-forgery-infrastructure"
        tlp = "LEAKED"
        section23_case = "2, 3, 7"
        reference = "BYPASS_CORE.md §23.3"

    strings:
        $pem_header = "-----BEGIN " ascii
        $rsa_oid = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" ascii
        // The offensive-lab test names attacker keys with timestamp prefix
        $lab_naming = "attacker_" ascii

    condition:
        filesize < 4KB
        and $pem_header and $rsa_oid
        and $lab_naming
}


rule Offensive_Lab_Marker_In_Envelope
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "JSON envelope carrying the iRemovalOFFENSIVE Test lab marker (test_adversarial.py case 1, 3, 8, 9, 10)"
        severity = "high"
        category = "iCloud-bypass-forgery-infrastructure"
        tlp = "LEAKED"
        section23_case = "1, 3, 8, 9, 10"
        reference = "BYPASS_CORE.md §23.3"

    strings:
        $lab_marker = "\"lab_marker\":\"iRemovalOFFENSIVE Test\"" ascii

    condition:
        filesize < 16KB
        and $lab_marker
}


rule Zeroed_Signature_Offensive_Lab
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "All-zero 256-byte RSA-2048 signature (test_adversarial.py case 5)"
        severity = "medium"
        category = "iCloud-bypass-forgery-infrastructure"
        tlp = "LEAKED"
        section23_case = "5"
        reference = "BYPASS_CORE.md §23.3"

    strings:
        // 32 bytes of 0x00 followed by 32 more — pattern is just a marker for
        // "this file is mostly zeros", not the actual sig (YARA can't easily
        // count runs of 0x00 across the whole file). The real check is in
        // test_detection.py which uses Python to detect the exact 256-zero sig.
        $marker = "ZEROED_SIG_OFFENSIVE_LAB" ascii

    condition:
        // Marker file dropped by test_detection.py for case 5
        $marker
}


rule Unknown_Pubkey_Offensive_Lab
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "Alien RSA-2048 public key generated during §22 case 7 cross-verify test"
        severity = "medium"
        category = "iCloud-bypass-forgery-infrastructure"
        tlp = "LEAKED"
        section23_case = "7"
        reference = "BYPASS_CORE.md §23.3"

    strings:
        $pem_header = "-----BEGIN PUBLIC KEY-----" ascii
        $rsa_oid = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" ascii
        $lab_naming = "alien_" ascii

    condition:
        filesize < 2KB
        and $pem_header and $rsa_oid
        and $lab_naming
}


rule Bplist00_Payload_Offensive_Lab
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "Apple binary plist (bplist00) carrying an iActivation ticket dict"
        severity = "medium"
        category = "iCloud-bypass-forgery-infrastructure"
        tlp = "LEAKED"
        section23_case = "1, 6"
        reference = "BYPASS_CORE.md §23.3"

    strings:
        // Apple bplist00 magic
        $bplist_magic = { 62 70 6C 69 73 74 30 30 }  // "bplist00"
        // iActivation ticket dict keys (extracted from bplist_builder output)
        $key_activation = "Activation" ascii
        $key_imei = "IMEI" ascii
        $key_serial = "SerialNumber" ascii
        $key_udid = "UDID" ascii

    condition:
        $bplist_magic at 0
        and filesize > 100 and filesize < 64KB
        and 2 of ($key_imei, $key_serial, $key_udid, $key_activation)
}
