/*
    YARA Rules — iRemoval PRO wire-format detection
    Author: iact8 reproducer — 2026-06-22
    Purpose: OFFENSIVE  detection of the iRemoval iact8.php envelope
             (network artefacts, JSON bodies, bplist00 tickets).
    Severity: HIGH (iCloud Activation Lock bypass tool)
    TLP: LEAKED

    References:
      - 01_REPORTS/ENDPOINT_IACT8.md
      - 01_REPORTS/CRYPTO_CRITICAL_ANALYSIS.md
      - 06_LOCAL_REPRODUCER/iact_reproducer/wire_format.py
      - 06_LOCAL_REPRODUCER/iact_reproducer/bplist_builder.py

    These rules target the **wire format** used by the iRemoval PRO
    client when it talks to `https://s13.iremovalpro.com/iremovalActivation/iact8.php`.
    They are designed to be matched on:
      * raw HTTP request bodies (JSON envelopes)
      * extracted JSON files
      * bplist00 activation ticket binaries
      * PCAP-extracted HTTP payloads

    NOTE: The OFFENSIVE  corpus emitted by the iAct8 reproducer carries
    the marker `iRemovalOFFENSIVE Test` everywhere — these rules
    intentionally do NOT match that marker (so lab traffic does not
    trip detections in production). They DO match the real iRemoval
    field marker `iDevice Activated Successfully` and the original
    server / tweak identifiers.
*/

import "hash"


rule iRemovalPro_WireEnvelope_Fields
{
    meta:
        author = "iact8-reproducer"
        date = "2026-06-22"
        description = "iRemoval PRO iact8.php envelope field shape (JSON)"
        severity = "high"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"
        reference1 = "01_REPORTS/ENDPOINT_IACT8.md"

    strings:
        $alg = "RSA-PKCS1v1.5-SHA256" ascii wide
        $sig = "\"sig\":" ascii
        $b64 = "\"b64\":" ascii
        $nonce = "\"nonce\":" ascii
        $udid = "\"udid\":" ascii
        $ts = "\"ts\":" ascii
        $def = "\"OFFENSIVE _marker\":" ascii   // catches real variant if present

    condition:
        // JSON envelope shape: 5+ of the iAct8 field names
        5 of ($alg, $sig, $b64, $nonce, $udid, $ts, $def)
        and filesize < 64KB
}


rule iRemovalPro_Bplist00Ticket_Marker
{
    meta:
        author = "iact8-reproducer"
        date = "2026-06-22"
        description = "bplist00 activation ticket carrying iRemoval PRO artefact keys"
        severity = "high"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"
        reference1 = "01_REPORTS/ENDPOINT_IACT8.md"

    strings:
        $magic = "bplist00" ascii
        $dcert = "DeviceCertificate" ascii
        $sident = "SigningIdentity" ascii
        $fpcert = "FairPlayCertificate" ascii
        $wtick = "WildcardTicket" ascii
        $activationrecord = "ActivationRecord" ascii
        $hooktarget1 = "MobileActivationDaemon" ascii
        $hooktarget2 = "SecKeyRawVerify" ascii
        $hooktarget3 = "SecKeyVerifySignature" ascii
        $hooktarget4 = "SecTrustEvaluateWithError" ascii
        $blackhound = "blackhound" ascii
        $panyolsoft = "panyolsoft" ascii

    condition:
        $magic at 0
        and filesize < 64KB
        // require multiple artefacts that the real iRemoval bundle emits
        and 2 of ($dcert, $sident, $fpcert, $wtick, $activationrecord)
        and 2 of ($hooktarget1, $hooktarget2, $hooktarget3, $hooktarget4, $blackhound, $panyolsoft)
}


rule iRemovalPro_HTTP_Request_Iact8
{
    meta:
        author = "iact8-reproducer"
        date = "2026-06-22"
        description = "HTTP request to iRemoval iact8.php endpoint"
        severity = "medium"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"

    strings:
        $method = "POST /iremovalActivation/iact8.php" ascii wide
        $host1 = "s13.iremovalpro.com" ascii wide
        $host2 = "iremovalpro.com" ascii wide
        $ver = "X-iRemovalPRO-Version" ascii wide
        $agent = "User-Agent: iRemovalPro" ascii wide

    condition:
        $method and (any of ($host1, $host2))
        and (any of ($ver, $agent))
        and filesize < 64KB
}


rule iRemovalPro_DefensiveLab_Marker
{
    meta:
        author = "iact8-reproducer"
        date = "2026-06-22"
        description = "Marks artefacts produced by the iAct8 OFFENSIVE  reproducer (NOT malicious)"
        severity = "informational"
        category = "iCloud-bypass-tool-lab"
        tlp = "LEAKED"
        lab_only = "true"

    strings:
        $marker1 = "iRemovalOFFENSIVE Test" ascii wide
        $marker2 = "OFFENSIVE -CORPUS-" ascii
        $marker3 = "OFFENSIVE -TEST-" ascii
        $marker4 = "iRemovalOFFENSIVE Test-" ascii

    condition:
        1 of ($marker1, $marker2, $marker3, $marker4)
}


rule iRemovalPro_Generic_Endpoint_Mix
{
    meta:
        author = "iact8-reproducer"
        date = "2026-06-22"
        description = "Generic iRemoval server endpoint strings (URL fragments in bodies)"
        severity = "high"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"

    strings:
        $e1 = "/iremovalActivation/iact8.php" ascii wide
        $e2 = "/iremovalActivation/auth3.php" ascii wide
        $e3 = "/iremovalActivation/checkm8.php" ascii wide
        $e4 = "/iremovalActivation/ars2.php" ascii wide
        $e5 = "/iremovalActivation/mf5.php" ascii wide
        $e6 = "/iremovalActivation/mf6.php" ascii wide
        $e7 = "/iremovalActivation/mf7.php" ascii wide
        $e8 = "/Payax0.php" ascii wide
        $e9 = "/version33.txt" ascii wide
        $b64helper = "iRemovalRecord" ascii wide
        $b64helper2 = "iRemovalSignature" ascii wide

    condition:
        filesize < 256KB
        and (3 of ($e1, $e2, $e3, $e4, $e5, $e6, $e7, $e8, $e9)
             or (any of ($b64helper, $b64helper2) and any of ($e1, $e2, $e3, $e4)))
}
