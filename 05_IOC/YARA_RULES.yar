/*
    YARA Rules — iRemoval PRO Premium Edition v5.2 Detection
    Author: Audit statique — 2026-06-22
    Purpose: OFFENSIVE  detection only — for AV/EDR/scanners
    Severity: HIGH (iCloud Activation Lock bypass tool)
    
    References:
      - iRemoval PRO.exe  SHA-256: 07452A1E12FE3A36519611B3932AE43CD2C64093981C047A788FA1939E424DB7
      - iremovalpro.dll   SHA-256: 08D283CC16C92582594A277C23625AF9D0F0109FAC5415F75D20D55B92BA8141
*/

import "hash"


rule iRemovalPro_Executable_5_2
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "iRemoval PRO Premium Edition v5.2 executable (WPF .NET Framework 4.x)"
        severity = "high"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"
        reference1 = "https://bypassfrpfiles.com"
        sha256 = "07452A1E12FE3A36519611B3932AE43CD2C64093981C047A788FA1939E424DB7"
        imphash = "N/A (managed assembly)"
        
    condition:
        uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and filesize < 5MB
        and filesize > 1MB
        and hash.sha256(0, filesize) == "07452A1E12FE3A36519611B3932AE43CD2C64093981C047A788FA1939E424DB7"
}


rule iRemovalPro_Library_5_2
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "iRemoval PRO Premium Edition v5.2 main library (.NET 8 NativeAOT)"
        severity = "high"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"
        reference1 = "https://bypassfrpfiles.com"
        sha256 = "08D283CC16C92582594A277C23625AF9D0F0109FAC5415F75D20D55B92BA8141"
        
    condition:
        uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and filesize > 25MB
        and filesize < 35MB
        and hash.sha256(0, filesize) == "08D283CC16C92582594A277C23625AF9D0F0109FAC5415F75D20D55B92BA8141"
}


rule iRemovalPro_Generic_Indicators
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "Generic detection of iRemoval PRO via assembly strings + version marker"
        severity = "high"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"
        
    strings:
        $asm_name = "iRemovalProWPF" ascii wide
        $build_marker = "Blackhound iRemovalPro Public build 0.7.1" ascii wide
        $server1 = "s13.iremovalpro.com" ascii wide
        $server2 = "iremovalActivation" ascii wide
        $server3 = "iRemovalRecord" ascii wide
        $server4 = "iRemovalSignature" ascii wide
        $tweak_bundle = "com.panyolsoft.blackhound" ascii wide
        $helper_bundle = "com.iremovalpro.bypass" ascii wide
        
    condition:
        uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and filesize > 1MB
        and 3 of ($asm_name, $build_marker, $server1, $server2, $server3, $server4, $tweak_bundle, $helper_bundle)
}


rule iRemovalPro_iOS_Tweak_Blackhound
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "iRemoval PRO iOS tweak blackhound.dylib (Cydia Substrate)"
        severity = "high"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"
        platform = "iOS"
        
    strings:
        $bundle = "com.panyolsoft.blackhound" ascii wide
        $hook1 = "validateActivationDataSignature" ascii wide
        $hook2 = "handleActivationInfo" ascii wide
        $hook3 = "MobileActivationDaemon" ascii wide
        $logos1 = "__logos_method$" ascii
        $logos2 = "_MSHookFunction" ascii
        $subtitle = "/Library/MobileSubstrate/DynamicLibraries" ascii wide
        
    condition:
        uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE
        and filesize < 10MB
        and 4 of ($bundle, $hook1, $hook2, $hook3, $logos1, $logos2, $subtitle)
}


rule iRemovalPro_ServerConfig_Endpoints
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "Detection of iRemoval PRO server endpoint URLs (in binaries or configs)"
        severity = "medium"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"
        
    strings:
        $ep1 = "s13.iremovalpro.com/iremovalActivation/auth3.ph" ascii wide
        $ep2 = "s13.iremovalpro.com/iremovalActivation/checkm8.ph" ascii wide
        $ep3 = "s13.iremovalpro.com/iremovalActivation/iact8.ph" ascii wide
        $ep4 = "s13.iremovalpro.com/iremovalActivation/ars2.ph" ascii wide
        $ep5 = "s13.iremovalpro.com/version33.tx" ascii wide
        $ep6 = "s13.iremovalpro.com/pub.ph" ascii wide
        $ep7 = "iremovalpro.com/Payax0.ph" ascii wide
        $apple_ep = "albert.apple.com/deviceservices/drmHandshak" ascii wide
        
    condition:
        any of ($ep1, $ep2, $ep3, $ep4, $ep5, $ep6, $ep7, $apple_ep)
}


rule iRemovalPro_iOS_Artifacts_Path
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "Detection of iRemoval PRO iOS artifacts in filesystem"
        severity = "high"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"
        platform = "iOS"
        
    strings:
        $path1 = "/Library/MobileSubstrate/DynamicLibraries/blackhound.dylib" ascii wide
        $path2 = "com.panyolsoft.blackhound.plist" ascii wide
        $path3 = "/var/mobile/Library/activation_records/activation_record.plist" ascii wide
        $path4 = "com.iremovalpro.bypass" ascii wide
        
    condition:
        any of them
}


rule iRemovalPro_AntiDebug_Strings
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "Detection of anti-debug techniques specific to iRemoval PRO"
        severity = "low"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"
        
    strings:
        $antidebug1 = "BypassMeidSignal" ascii wide
        $antidebug2 = "Firewall_iDeviceProxy" ascii wide
        $antidebug3 = "SecureClearAndCollect" ascii wide
        $antidebug4 = "ExecuteAsAdmin" ascii wide
        $antidebug5 = "MibTcpRowOwnerPid" ascii wide
        $aot = "hydrated" ascii
        $rdtsc_pe = { 0F 31 }
        $cpuid_pe = { 0F A2 }
        $peb_pe = { 65 48 8B 04 25 30 00 00 00 }
        
    condition:
        uint16(0) == 0x5A4D
        and 2 of ($antidebug1, $antidebug2, $antidebug3, $antidebug4, $antidebug5, $aot)
        and 1 of ($rdtsc_pe, $cpuid_pe, $peb_pe)
}


rule iRemovalPro_BuildMarker_Generic
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "Generic detection via build marker string (multi-version)"
        severity = "high"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"
        
    strings:
        $build = "Blackhound iRemovalPro Public build" ascii wide
        $jailbreak = "checkrain" ascii wide
        $lib1 = "libimobiledevice" ascii wide
        $lib2 = "libusbmuxd" ascii wide
        $patch = "A12Eraser" ascii wide
        $meid = "BypassMeidSignal" ascii wide
        $server = "s13.iremovalpro.com" ascii wide
        $tweak = "com.panyolsoft.blackhound" ascii wide
        $maint = "iRemoval PRO Servers are currently under MAINTENANCE" ascii wide
        
    condition:
        uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and filesize > 1MB
        and 5 of them
}


rule iRemovalPro_Driver_StateMachines
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "Detection of iRemoval PRO Driver state machines (async .NET)"
        severity = "medium"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"
        
    strings:
        $sm1 = "Driver.<BypassMeidSignal>" ascii wide
        $sm2 = "Driver.<CommonConnectDevice>" ascii wide
        $sm3 = "Driver.<CheckIOS>" ascii wide
        $sm4 = "Driver.<Install>" ascii wide
        $sm5 = "Driver.<RestoreBackup>" ascii wide
        $cls = "iremovalpro.Driver" ascii wide
        
    condition:
        uint16(0) == 0x5A4D
        and 2 of ($sm1, $sm2, $sm3, $sm4, $sm5, $cls)
}


/*
    Compound rule — high confidence detection
    
    Fires when multiple independent indicators are present in the same file.
    This is the recommended rule for production use to minimize false positives.
*/
rule iRemovalPro_Compound_HighConfidence
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "High-confidence compound detection of iRemoval PRO (multiple indicators)"
        severity = "high"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"
        
    strings:
        // Server-side indicators
        $srv1 = "s13.iremovalpro.com" ascii wide
        $srv2 = "iremovalActivation" ascii wide
        $srv3 = "Blackhound iRemovalPro" ascii wide
        
        // iOS payload bundle IDs
        $ios1 = "com.panyolsoft.blackhound" ascii wide
        $ios2 = "com.iremovalpro.bypass" ascii wide
        
        // Library function references
        $lib1 = "iDevice_Activate" ascii wide
        $lib2 = "iDevice_Tnl" ascii wide
        $lib3 = "iDevice_Pair" ascii wide
        $lib4 = "Erase_V2" ascii wide
        
        // AOT sections
        $aot1 = "hydrated" ascii
        $aot2 = ".managed" ascii
        $aot3 = "NativeAOT" ascii
        
    condition:
        uint16(0) == 0x5A4D
        and filesize > 1MB
        and (
            (3 of ($srv1, $srv2, $srv3) and 2 of ($ios1, $ios2))
            or
            (2 of ($srv1, $srv2, $srv3) and 2 of ($lib1, $lib2, $lib3, $lib4))
            or
            (1 of ($srv1, $srv2, $srv3) and 2 of ($aot1, $aot2, $aot3) and 2 of ($ios1, $ios2))
        )
}


/*
    Rule: iRemovalPro_ForgedRSASignature
    Purpose: Detect PKCS#1 v1.5 RSA signatures WITHOUT SHA-256 OID
             (used by iRemoval PRO bypass — see OFFENSIVE _PLAYBOOK.md §3)
    Source: blackhound_rsa_pubkey.pem (RSA-1024 embedded in dylib)
*/
rule iRemovalPro_ForgedRSASignature
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "PKCS#1 v1.5 RSA signature without SHA-256 DigestInfo (iRemoval PRO pattern)"
        severity = "high"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"
        reference = "01_REPORTS/OFFENSIVE _PLAYBOOK.md"

    strings:
        // Hash 32 octets SANS OID SHA-256 qui suit le separator 00
        // 32 wildcards = "any 32 bytes" (hash brute)
        $no_sha_oid = { 00 01 FF FF FF [3-240] FF 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }

        // Hash 32 octets AVEC OID SHA-256 = signature Apple conforme (à exclure)
        $has_sha_oid = {
            00 01 FF FF FF [3-240] FF 00
            30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
        }

    condition:
        $no_sha_oid and not $has_sha_oid
}


/*
    Rule: iRemovalPro_BypassRSAPublicKey
    Purpose: Detect the embedded RSA-1024 bypass public key (modulus hash)
    SHA-256 modulus: 2c8c67d4066a5b1f8848ab9284aae4f9f37a6e6edfebb27bde26ac99e2615d27
    Source: 04_EXTRACTED/blackhound_rsa_pubkey.pem
*/
rule iRemovalPro_BypassRSAPublicKey
{
    meta:
        author = "audit-statique"
        date = "2026-06-22"
        description = "RSA-1024 public key used by blackhound.dylib bypass (modulus SHA-256 fingerprint)"
        severity = "critical"
        category = "iCloud-bypass-tool"
        tlp = "LEAKED"
        modulus_sha256 = "2c8c67d4066a5b1f8848ab9284aae4f9f37a6e6edfebb27bde26ac99e2615d27"
        modulus_md5 = "bfdad9bab7b8ed47f4f941e1e1ae3949"
        reference = "01_REPORTS/OFFENSIVE _PLAYBOOK.md#1-clé-bypass-exposée--ioc"

    strings:
        // Modulus en hex (string ASCII)
        $mod_hex = "B83B6E2F23ADE61C4A324FA7B92233066D9A588D961EA8CCFE3C7224AE2545FE62FD9CD30C947A454B05250F49AC3404AFD38614164F21105DC0F7AB85022BC2A7F868A83FC4AC461D2991139B1926953A9FEABDD9F3901613ACFE6D59D94B2006F450B1C4A61F06EB43D688CF41F1899C821ED0C61428C4B6C276F6C6CC8581" ascii wide
        // Modulus en DER binaire (128 octets)
        $mod_der = { B8 3B 6E 2F 23 AD E6 1C 4A 32 4F A7 B9 22 33 06 6D 9A 58 8D 96 1E A8 CC FE 3C 72 24 AE 25 45 FE 62 FD 9C D3 0C 94 7A 45 4B 05 25 0F 49 AC 34 04 AF D3 86 14 16 4F 21 10 5D C0 F7 AB 85 02 2B C2 A7 F8 68 A8 3F C4 AC 46 1D 29 91 13 9B 19 26 95 3A 9F EA BD D9 F3 90 16 13 AC FE 6D 59 D9 4B 20 06 F4 50 B1 C4 A6 1F 06 EB 43 D6 88 CF 41 F1 89 9C 82 1E D0 C6 14 28 C4 B6 C2 76 F6 C6 CC 85 81 }

    condition:
        any of them
}

