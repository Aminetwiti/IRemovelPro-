/*
   YARA Rule: iRemoval PRO Setup Bypass Detection
   Description: Détecte les plists forgés et les artefacts d'injection Setup Assistant
   Author: Defensive Analysis v5.2-LAB-0.3
   Date: 2026-06-23
   Reference: RAPPORT_FINAL_5_AXES.md, AXE5_DECOMPILATION_FINDINGS.md
*/

rule iRemoval_Forged_PurpleBuddy_Plist {
    meta:
        description = "Détecte com.apple.purplebuddy.plist forgé avec SetupDone=True"
        severity = "high"
        category = "iOS Activation Lock Bypass"
        reference = "Setup Assistant state manipulation"

    strings:
        // Clés critiques du bypass Setup Assistant
        $key1 = "SetupDone" ascii wide
        $key2 = "SetupState" ascii wide
        $key3 = "SetupLastExit" ascii wide
        $key4 = "ConfigurationFinished" ascii wide

        // Valeurs typiques du bypass
        $val1 = "GestureNav" ascii wide  // dernière étape franchie
        $val2 = "<integer>5</integer>" ascii  // SetupState = 5 (complete)

        // Signature de forge
        $forge1 = "_ForgedBy" ascii wide
        $forge2 = "plist_patcher" ascii wide

    condition:
        uint32(0) == 0x696c7062 and  // bplist magic
        (
            (all of ($key*) and any of ($val*)) or  // bypass complet
            any of ($forge*)  // signature explicite
        )
}

rule iRemoval_Forged_PreBoard_Plist {
    meta:
        description = "Détecte com.apple.PreBoard.plist modifié (ActivationState=Activated)"
        severity = "high"
        category = "iOS Activation Lock Bypass"

    strings:
        $key1 = "ActivationState" ascii wide
        $key2 = "BrickState" ascii wide
        $key3 = "ShowSetupUI" ascii wide

        $val1 = "Activated" ascii wide
        $val2 = "<false/>" ascii  // BrickState=false, ShowSetupUI=false

        $forge = "_ForgedBy" ascii wide

    condition:
        uint32(0) == 0x696c7062 and
        (
            (all of ($key*) and $val1) or
            $forge
        )
}

rule iRemoval_Forged_ActivationRecord_Plist {
    meta:
        description = "Détecte activation_record.plist avec données nulles (FairPlayKeyData/ActivationRandomness)"
        severity = "critical"
        category = "iOS Activation Lock Bypass"
        reference = "MobileActivationDaemon record forgery"

    strings:
        $key1 = "ActivationState" ascii wide
        $key2 = "ActivationRandomness" ascii wide
        $key3 = "FairPlayKeyData" ascii wide
        $key4 = "AccountTokenCertificate" ascii wide

        // FairPlayKeyData forgé = 165 bytes de nulls (en base64 dans plist XML)
        $null_fairplay = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii

        // ActivationRandomness forgé = 20 bytes nulls
        $null_randomness = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii

        $forge = "_ForgedBy" ascii wide

    condition:
        uint32(0) == 0x696c7062 and
        (
            ($key1 and ($null_fairplay or $null_randomness)) or
            ($forge and any of ($key*))
        )
}

rule iRemoval_SSH_Injection_Script {
    meta:
        description = "Détecte le script Python d'injection plist via SSH"
        severity = "high"
        category = "iOS Bypass Toolkit"

    strings:
        $py1 = "import paramiko" ascii
        $py2 = "inject_plists_ssh" ascii
        $py3 = "com.apple.purplebuddy.plist" ascii
        $py4 = "mobileactivationd" ascii
        $py5 = "killall -9 mobileactivationd" ascii

        $path1 = "/var/mobile/Library/Preferences/com.apple.purplebuddy.plist" ascii
        $path2 = "/var/mobile/Library/Preferences/com.apple.PreBoard.plist" ascii
        $path3 = "systemgroup.com.apple.mobileactivationd/activation_records" ascii

    condition:
        filesize < 50KB and
        (
            (3 of ($py*) and any of ($path*)) or
            all of ($path*)
        )
}

rule iRemoval_Backup_Plists_Pattern {
    meta:
        description = "Détecte les backups de plists originaux créés lors de l'injection"
        severity = "medium"
        category = "iOS Bypass Forensics"

    strings:
        // Pattern de backup: *.plist.bak
        $backup1 = "com.apple.purplebuddy.plist.bak" ascii wide
        $backup2 = "com.apple.PreBoard.plist.bak" ascii wide
        $backup3 = "activation_record.plist.bak" ascii wide

    condition:
        any of them
}

rule iRemoval_iOS_Tweak_Hooks {
    meta:
        description = "Détecte les hooks Theos/Logos dans le tweak iOS (couche 4)"
        severity = "critical"
        category = "iOS Runtime Hooking"
        reference = "AXE5_DECOMPILATION_FINDINGS.md section 6"

    strings:
        // Logos framework symbols
        $hook1 = "MSHookMessageEx" ascii
        $hook2 = "MSHookFunction" ascii
        $hook3 = "_logos_method" ascii
        $hook4 = "_logos_orig" ascii

        // Target daemon
        $target1 = "MobileActivationDaemon" ascii
        $target2 = "com.apple.mobileactivationd" ascii

        // Hooked methods
        $method1 = "isActivated" ascii
        $method2 = "handleActivationInfo" ascii
        $method3 = "copyActivationRecord" ascii

    condition:
        (2 of ($hook*) and any of ($target*)) or
        (any of ($hook*) and 2 of ($method*))
}

rule iRemoval_Combined_Bypass_Indicators {
    meta:
        description = "Règle composite: détecte présence simultanée de plists forgés + scripts d'injection"
        severity = "critical"
        category = "iOS Activation Lock Bypass - Full Kit"

    strings:
        // Plists
        $p1 = "SetupDone" ascii wide
        $p2 = "ActivationState" ascii wide
        $p3 = "FairPlayKeyData" ascii wide

        // Scripts
        $s1 = "paramiko" ascii
        $s2 = "plist_patcher" ascii
        $s3 = "forge_plists" ascii

        // Forge signature
        $f1 = "_ForgedBy" ascii wide
        $f2 = "_ForgedAt" ascii wide

    condition:
        (
            (2 of ($p*) and any of ($f*)) or  // plists forgés
            (2 of ($s*))  // toolkit d'injection
        )
}
