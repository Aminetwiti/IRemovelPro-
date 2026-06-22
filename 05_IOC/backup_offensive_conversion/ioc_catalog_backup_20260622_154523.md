# Catalogue IoC — iRemoval PRO Premium Edition v5.2

> Catalogue dérivé des 5 rapports d'audit. Mis à jour : 2026-06-22

---

## 🔑 Hashes de fichiers

| Fichier | SHA-256 |
|---|---|
| `iRemoval PRO.exe` | `07452A1E12FE3A36519611B3932AE43CD2C64093981C047A788FA1939E424DB7` |
| `iremovalpro.dll` | `08D283CC16C92582594A277C23625AF9D0F0109FAC5415F75D20D55B92BA8141` |
| `blackhound_rsa_pubkey.pem` (RSA-1024 bypass pubkey) | `2777656e2aa326f7f02b215cc6cac1da8d2550c978bb745b9ac7aaed45434b4f` |
| `Modulus RSA-1024 (nu, 128 octets)` | `2c8c67d4066a5b1f8848ab9284aae4f9f37a6e6edfebb27bde26ac99e2615d27` |
| `Modulus RSA-1024 (SHA-1)` | `d488c22c7300b7355c04959d77bcd7f5b2dc844c` |

## 🌐 Domaines

| Domaine | Usage |
|---|---|
| `s13.iremovalpro.com` | Serveur principal d'activation (9 endpoints) |
| `iremovalpro.co` | Site vitrine |
| `iremovalpro.com` | Site principal + paiement (Payax0) |
| `t.me/iremovalpro` | Support Telegram |
| `albert.apple.com` | **Apple officiel** — endpoint DRM handshake |

## 🔌 Endpoints serveur iRemovalPRO

| URL | Méthode | Rôle |
|---|---|---|
| `https://s13.iremovalpro.com/version33.tx` | GET | Version check |
| `https://s13.iremovalpro.com/pub.ph` | GET/POST | Public info / config |
| `https://s13.iremovalpro.com/iremovalActivation/auth3.ph` | POST | Authentification client |
| `https://s13.iremovalpro.com/iremovalActivation/ars2.ph` | POST | Activation Record Service |
| `https://s13.iremovalpro.com/iremovalActivation/checkm8.ph` | POST | Status checkm8 |
| `https://s13.iremovalpro.com/iremovalActivation/iact8.ph` | POST | iCloud Activation ticket |
| `https://s13.iremovalpro.com/iremovalActivation/mf5.ph` | POST | Bypass MEID v5 |
| `https://s13.iremovalpro.com/iremovalActivation/mf6.ph` | POST | Bypass MEID v6 |
| `https://s13.iremovalpro.com/iremovalActivation/mf7.ph` | POST | Bypass MEID v7 |
| `https://iremovalpro.com/Payax0.ph` | POST | Payment |
| `https://www.trustpilot.com/review/iremovalpro.co` | GET | Reputation |

## 🍎 Endpoints Apple (utilisés par le bypass)

| URL | Usage |
|---|---|
| `http://crl.apple.com/root.crl` | Validation certificat |
| `https://www.apple.com/appleca/` | Apple CA |
| `http://ocsp.apple.com/ocsp03-wwdr190` | OCSP |
| `http://www.apple.com/certificateauthority/` | Cert authority |
| `https://albert.apple.com/deviceservices/drmHandshake` | **DRM handshake (cible Apple)** |

## 📱 Bundles iOS déployés

| Bundle ID | Type | Rôle |
|---|---|---|
| `com.iremovalpro.bypass` | App iOS helper | Génère faux DeviceCertificate |
| `com.panyolsoft.blackhound` | Tweak Cydia Substrate | Hook `MobileActivationDaemon` |
| `com.apple.mobileactivationd` | Daemon iOS | **Cible des hooks** |
| `com.apple.springboard` | Daemon iOS | Notification UI |

## 📂 Chemins iOS

```
/private/var/logs/mobileactivationd_restore/
/var/mobile/Library/activation_records/activation_record.plist
/Library/MobileSubstrate/DynamicLibraries/blackhound.dylib
/Library/MobileSubstrate/DynamicLibraries/blackhound.dylib.plist
/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate
/System/Library/PrivateFrameworks/MobileActivation.framework/MobileActivation
```

## 🎯 Méthodes iOS hookées (Logos/Cydia Substrate)

```objc
- (BOOL)validateActivationDataSignature:(NSData *)activationSignature
                          activationData:(NSDictionary *)activationData
                              withError:(NSError **)error;

- (void)handleActivationInfo:(NSDictionary *)activationInfo
         withCompletionBlock:(void (^)(NSDictionary *response, NSError *error))completionBlock;

- (void)handleActivationInfoWithSession:(id)session
                    activationSignature:(NSData *)signature
                        completionBlock:(void (^)(NSDictionary *response, NSError *error))completionBlock;
```

## 📦 Payloads iOS identifiés

| Payload | Auteur | Build path | Rôle |
|---|---|---|---|
| `blackhound.dylib` | josuealonsorodriguez | `~/Documents/Pro/TweakDevelopment/blackhound/.theos/` | Hook Cydia Substrate |
| `minaeraser` | minacriss | `~/Documents/Minasoftware/minaeraser/` | A11 et antérieur |
| `minaeraser12` | minacriss | `~/Documents/Minasoftware/minaeraser12/` | A12+ NAND eraser |
| `rc` | minacriss | `~/DerivedData/rc-.../Build/` | Recovery Creator |

## 🪪 Certificats Apple intégrés

| Cert | Rôle |
|---|---|
| `Apple Development: weidong li (PBNGZQ8G6L)` | Cert dev Apple réutilisé pour signer tweak |

## 🛡️ Strings de service (marketing)

```
"Remember, this is an exclusive A12+ Full Bypass service with OTA feature,
 you can update but cannot restore!"
"iRemoval PRO Servers are currently under MAINTENANCE"
"iDevice Activated Succesfully"
"please allow 24 hours for the order to be completed"
"please contact the administrator at support@iremovalpro.com"
"please uninstall WireShark or Flexihub application and try again"
```

## 🔐 Anti-débogage (5+ techniques)

| Technique | Détecté |
|---|---|
| `IsDebuggerPresent` (KERNEL32 import) | ✅ |
| `NtQueryInformationProcess` P/Invoke | ✅ |
| `NtQueryInformationFile` P/Invoke | ✅ |
| `RDTSC` opcode (timing) | ✅ (1 occurrence) |
| `CPUID` opcode (hypervisor detect) | ✅ (16 occurrences) |
| `mov rax, gs:[0x30]` (PEB access) | ✅ (5 occurrences) |
| `EnumWindows` (window scan) | ✅ |
| `RegOpenKey` / `RegQueryValueEx` (VM detect) | ✅ |

## 🧬 API Windows utilisées

| Catégorie | APIs |
|---|---|
| **Anti-debug** | `IsDebuggerPresent`, `NtQueryInformationProcess`, `NtQueryInformationFile` |
| **Crypto CNG** | `BCryptOpenAlgorithmProvider`, `BCryptCreateHash`, `BCryptHashData`, `BCryptEncrypt`, `BCryptGenerateKeyPair`, `BCryptImportKeyPair` |
| **Crypto NCrypt** | `NCryptSignHash`, `NCryptVerifySignature`, `NCryptOpenKey` |
| **X.509** | `CertOpenStore`, `CertVerifyCertificateChainPolicy`, `PFXImportCertStore` |
| **Registry** | `RegOpenKeyExW`, `RegQueryValueExW` |
| **Network** | `HttpClient`, `SslStream`, `Tls12`, `Tls13`, `RemoteCertificateValidationCallback` |
| **iOS** | libimobiledevice, libusbmuxd, libplist, libssl/crypto (OpenSSL 3) |

## 🔌 Ports réseau

| Port | Service |
|---|---|
| 22 (SSH) | Tunnel Renci.SshNet vers iDevice jailbreaké |
| 62078 (iOS lockdown) | Via `ideviceproxy` tunnelé localhost |
| 443 (HTTPS) | API REST vers `s13.iremovalpro.com` |

## 🪪 Classes / méthodes .NET (Driver, iDevice)

### Méthodes iDevice (12)
- `iDevice_Pair`
- `iDevice_Tnl`
- `iDevice_Activate`
- `iDevice_Deactivate`
- `iDevice_LnchV2`
- `iDevice_GetState`
- `iDevice_EnableDevMode`
- `iDevice_Restart`
- `iDevice_RemoveProfiles`
- `Erase_V2`
- `ExecuteAsAdmin`
- `SecureClearAndCollect`
- `Firewall_iDeviceProxy`

### State machines async (5)
- `<BypassMeidSignal>d__516`
- `<CommonConnectDevice>d__107`
- `<CheckIOS>d__15`
- `<Install>d__8`
- `<RestoreBackup>d__9`

## 📚 Bibliothèques identifiées

| Lib | Version |
|---|---|
| RestSharp | 106.11.4 |
| Renci.SshNet | 2021.10.10 |
| QRCoder | 1.4.3 |
| SshNet.Security.Cryptography | 1.3.0 |
| libimobiledevice | 1.0+ |
| libplist | 2.0 |
| libusbmuxd | 2.0 |
| OpenSSL | 3.x |
| .NET Runtime | 8.0.10 |

## 🏷️ Catégorie

- **Type** : Outil commercial de bypass iCloud Activation Lock
- **Catégorie MITRE ATT&CK** : T1553 (Subvert Trust Controls) — bypass activation lock
- **TLP** : LEAKED (à distribuer avec restrictions)
- **CWE** : CWE-863 (Incorrect Authorization), CWE-489 (Active Debug Code)
