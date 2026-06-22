# Phase 4+ — Driver Class Deep Analysis (from strings)

> Analyse basée sur `03_OUTPUTS/strings_all_long.txt`
> (Binaires absents du projet — analyse statique des chaînes)

**Date** : 2026-06-22
**Méthode** : Grep patterns sur 75 000+ chaînes

---

## A. Méthodes iDevice_* identifiées

Total : 8 méthodes uniques

| # | Méthode | Contexte |
|---|---|---|
| 1 | `iDevice_Activate` | iDevice_LnchV2 iDevice_Activate iDevice_GetState*iDevice_EnableDevMode*Firewall_ |
| 2 | `iDevice_Deactivate` | ExecuteAsAdmin*SecureClearAndCollect$iDevice_Deactivate |
| 3 | `iDevice_EnableDevMode` | iDevice_LnchV2 iDevice_Activate iDevice_GetState*iDevice_EnableDevMode*Firewall_ |
| 4 | `iDevice_GetState` | iDevice_LnchV2 iDevice_Activate iDevice_GetState*iDevice_EnableDevMode*Firewall_ |
| 5 | `iDevice_LnchV2` | iDevice_LnchV2 iDevice_Activate iDevice_GetState*iDevice_EnableDevMode*Firewall_ |
| 6 | `iDevice_RemoveProfiles` | ,<Button_Click_5>d__121,<Imei_MouseDown>d__114(<Sn_MouseDown>d__113:<iDevice_Rem |
| 7 | `iDevice_Restart` | iDevice_Restart,iDevice_RemoveProfiles |
| 8 | `iDevice_Tnl` | "<iDevice_Tnl>b__0 |

## B. Identifiants Driver class

Total : 1 occurrences

```
  L1520: Driver.<BypassMeidSignal>d__516<CommonConnectDevice>d__107"MibTcpRowOwnerPid*<>c__DisplayClass73_0
```

## C. State machines async

Total : 7 occurrences

| # | Pattern | Contexte |
|---|---|---|
| 1 | `<BypassMeidSignal>` | Driver.<BypassMeidSignal>d__516<CommonConnectDevice>d__107"M |
| 2 | `<Imei_MouseDown>` | ,<Button_Click_5>d__121,<Imei_MouseDown>d__114(<Sn_MouseDown |
| 3 | `<Install>` | <Install>d__8,<InstallFromLocal>d__60<WatchForCompletion>d__ |
| 4 | `<WatchForCompletion>` | <Browse>d__9 <Uninstall>d__110<WatchForCompletion>d__8 |
| 5 | `<VersionExchange>` | <SendPath>d__64&<SendPrefixed>d__65.<SendStatusReport>d__66, |
| 6 | `<CheckIOS>` | "<CheckIOS>b__15_0@ |
| 7 | `<CheckIOS>` | "<CheckIOS>b__15_1@ |

## D. Bypass-related strings

Total : 46 occurrences

| Mot-clé | Ligne | Contexte |
|---|---|---|
| `MobileActivation` | L1107 | .MobileActivationService2Mobilebackup2ServiceIFPDZ |
| `BypassMeidSignal` | L1520 | Driver.<BypassMeidSignal>d__516<CommonConnectDevice>d__107"MibTcpRowOwnerPid*<>c |
| `BypassMeidSignal` | L1523 | A12Eraser BypassMeidSignalg |
| `BypassCache` | L6412 | 2GetRuntimeTypeBypassCache |
| `Erase_V2` | L7656 | Erase_V2$get_UniqueDeviceIDPget_InternationalMobileEquipmentIdentityRget_Interna |
| `SecureClearAndCollect` | L7660 | ExecuteAsAdmin*SecureClearAndCollect$iDevice_Deactivate |
| `Firewall_iDeviceProxy` | L7661 | iDevice_LnchV2 iDevice_Activate iDevice_GetState*iDevice_EnableDevMode*Firewall_ |
| `blackhound` | L9153 | /Library/MobileSubstrate/DynamicLibraries/blackhound.dylib |
| `blackhound` | L9162 | com.panyolsoft.blackhound |
| `MobileActivation` | L9163 | MobileActivationDaemon |
| `iRemovalSignature` | L9168 | iRemovalSignature |
| `MobileActivation` | L9269 | __logos_method$_ungrouped$MobileActivationDaemon$validateActivationDataSignature |
| `MobileActivation` | L9273 | __logos_orig$_ungrouped$MobileActivationDaemon$validateActivationDataSignature$a |
| `blackhound` | L9276 | /Users/josuealonsorodriguez/Documents/Pro/TweakDevelopment/blackhound/.theos/obj |
| `blackhound` | L9278 | blackhound.dylib.8b1348c6.unsigned |
| `blackhound` | L9279 | "blackhound.dylib.8b1348c6.unsigned |
| `minaeraser` | L9313 | /Users/minacriss/Documents/Minasoftware/minaeraser12/minaeraser/ |
| `mobileactivationd` | L9359 | <key>com.apple.mobileactivationd.spi</key> |
| `MobileActivation` | L9364 | <key>com.apple.private.MobileActivation</key> |
| `MobileActivation` | L9541 | /System/Library/PrivateFrameworks/MobileActivation.framework/MobileActivation |
| `mobileactivationd` | L9553 | <key>com.apple.mobileactivationd.device-identifiers</key> |
| `mobileactivationd` | L9586 | <string>/private/var/logs/mobileactivationd_restore/</string> |
| `mobileactivationd` | L9588 | <string>/Library/Logs/mobileactivationd/</string> |
| `mobileactivationd` | L9590 | <string>com.apple.mobileactivationd</string> |
| `mobileactivationd` | L9595 | <string>systemgroup.com.apple.mobileactivationd</string> |
| `mobileactivationd` | L9600 | <string>mobileactivationd</string> |
| `albert.apple.com` | L14203 | https://albert.apple.com/deviceservices/drmHandshak |
| `s13.iremovalpro.com` | L14206 | https://s13.iremovalpro.com/iremovalActivation/ars2.ph |
| `s13.iremovalpro.com` | L14213 | https://s13.iremovalpro.com/pub.ph |
| `s13.iremovalpro.com` | L14214 | https://s13.iremovalpro.com/version33.tx |
| `MobileActivation` | L14218 | iOS Device Activator (MobileActivation-20 built on Jan 15 2012 at 19:07:28 |
| `MobileActivation` | L14219 | iOS Device Activator (MobileActivation-592.103.2 |

## E. Endpoints serveur

Total : 12 occurrences

```
  L12840: Please contact the administrator at support@iremovalpro.com for further assistance
  L14203: https://albert.apple.com/deviceservices/drmHandshak
  L14205: https://iremovalpro.com/Payax0.ph
  L14206: https://s13.iremovalpro.com/iremovalActivation/ars2.ph
  L14207: https://s13.iremovalpro.com/iremovalActivation/auth3.ph
  L14208: https://s13.iremovalpro.com/iremovalActivation/checkm8.ph
  L14209: https://s13.iremovalpro.com/iremovalActivation/iact8.ph
  L14210: https://s13.iremovalpro.com/iremovalActivation/mf5.ph
  L14211: https://s13.iremovalpro.com/iremovalActivation/mf6.ph
  L14212: https://s13.iremovalpro.com/iremovalActivation/mf7.ph
  L14213: https://s13.iremovalpro.com/pub.ph
  L14214: https://s13.iremovalpro.com/version33.tx
```

## F. Anti-debug APIs

Total : 13 occurrences

| API | Ligne | Contexte |
|---|---|---|
| `MibTcpRowOwnerPid` | L1520 | Driver.<BypassMeidSignal>d__516<CommonConnectDevice>d__107"MibTcpRowOwnerPid*<>c |
| `NtQueryInformationProcess` | L4482 | 2NtQueryInformationProcess |
| `NtQuerySystemInformation` | L4483 | 0NtQuerySystemInformation |
| `NtQueryInformationProcess` | L4484 | V<NtQueryInformationProcess>g____PInvoke|0_0 |
| `EnumWindows` | L4525 | IsMainWindow&EnumWindowsCallback |
| `QueryPerformanceCounter` | L6491 | .QueryPerformanceCounter |
| `NtQueryInformationFile` | L6507 | ,NtQueryInformationFile |
| `NtQueryInformationFile` | L6508 | R<NtQueryInformationFile>g____PInvoke|17_0 |
| `Firewall_iDeviceProxy` | L7661 | iDevice_LnchV2 iDevice_Activate iDevice_GetState*iDevice_EnableDevMode*Firewall_ |
| `NtQueryInformationFile` | L10231 | NtQueryInformationFile |
| `NtQueryInformationProcess` | L10232 | NtQueryInformationProcess |
| `NtQuerySystemInformation` | L10233 | NtQuerySystemInformation |
| `IsDebuggerPresent` | L11212 | IsDebuggerPresent |

## G. Synthèse

- **Méthodes iDevice_*** : 8 uniques
- **Driver identifiers** : 1 occurrences
- **State machines** : 7 occurrences
- **Bypass strings** : 46 occurrences
- **Endpoints** : 12 occurrences
- **Anti-debug APIs** : 13 occurrences

**Note** : Cette analyse est limitée par l'absence du binaire.
Pour une analyse complète, restaurer `iremovalpro.dll` (30 MB).
