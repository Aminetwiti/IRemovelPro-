# GLOSSARY — Termes techniques

> Définitions des termes utilisés dans le projet d'audit

## A

**A12 Eraser** (`minaeraser12`)
Outil iOS développé par `minacriss` pour effacer la mémoire NAND sur les appareils A12+ (iPhone XS et plus récents). Déployé via SSH pendant le bypass.

**Activation Lock**
Mécanisme de sécurité d'Apple qui lie un iPhone à un identifiant Apple ID. Empêche l'utilisation de l'appareil après un effacement tant que l'identifiant n'est pas entré. **Cible du bypass iRemoval PRO.**

**Anti-debug**
Techniques utilisées par un binaire pour détecter ou empêcher l'analyse dynamique (débogueurs attachés, breakpoints, VM). Voir `01_REPORTS/EXPERT_REPORT.md` §3.

**Anti-VM**
Techniques pour détecter les machines virtuelles (VMware, VirtualBox, Hyper-V). Utilise CPUID, RDTSC, checks registre.

**APK** (Android Package Kit)
Format d'application Android — non applicable ici (le projet est iOS).

**Apple Mobile File Integrity (AMFI)**
Service iOS qui vérifie la signature des binaires. `AmfiLockdownService` est l'interface libimobiledevice.

**Apple File Conduit (AFC)**
Protocole iOS pour le transfert de fichiers via USB. Voir `01_REPORTS/EXPERT_REPORT.md` §5.3.

**AOT** (Ahead-of-Time)
Compilation native complète à la compilation, par opposition à JIT. .NET 8 NativeAOT produit du code machine natif.

## B

**Bash Bunny**
Outil d'injection HID USB pour pentest — non utilisé dans ce projet.

**Blackhound iRemovalPro**
Version originale de l'outil iRemoval (v0.7.1, 2022), développé par `josuealonsorodriguez`. Forked en "iRemoval PRO Premium Edition".

**Bypass**
Contournement d'un mécanisme de protection. Ici : bypass de l'Activation Lock iCloud.

## C

**CAPI** (Cryptographic API)
Ancienne API crypto Windows. Présente dans iremovalpro.dll via `SafeCapiKeyHandle`.

**CEH** (Certified Ethical Hacker)
Certification sécurité. Non requise pour ce projet (recherche autorisée).

**CFB** (CryptoAPI Binary)
Format de conteneur PKCS#12 (.pfx). Voir `PFXImportCertStore`.

**CFR** (Code of Federal Regulations)
Lois américaines. Le **Computer Fraud and Abuse Act** (18 U.S.C. § 1030) criminalise le bypass non autorisé.

**checkm8**
Exploit bootrom publié en 2019 par `axi0mX`. Cible A5-A11. Permet l'exécution de code non signé. Utilisé par iRemoval PRO pour A11 et antérieurs.

**checkra1n**
Outil de jailbreak iOS basé sur checkm8, pour A5-A11.

**Cydia Substrate**
Framework de hooking iOS. Utilisé par `blackhound.dylib` pour intercepter `MobileActivationDaemon`.

**CNG** (Cryptography API: Next Generation)
API crypto moderne de Windows. Utilisée dans iremovalpro.dll (BCrypt*, NCrypt*).

## D

**DYLIB** (Dynamic Library)
Équivalent macOS/iOS d'une DLL Windows. `blackhound.dylib` est un tweak jailbreak.

## E

**ECB** (Electronic Codebook)
Mode de chiffrement par bloc — moins sécurisé que CBC/GCM.

**ECDSA** (Elliptic Curve Digital Signature Algorithm)
Algorithme de signature basé sur les courbes elliptiques. Présent dans iremovalpro.dll.

**Entitlement**
Permission spéciale iOS (ex: `com.apple.security.attestation.access`). Voir `01_REPORTS/EXPERT_REPORT.md` §6.5.

**EXE** (Executable)
Fichier exécutable Windows. `iRemoval PRO.exe` est un PE32 x86 WPF.

**Extraction** (de plist)
Lecture d'un fichier binaire plist (Apple Property List). Formats : XML ou binaire.

## F

**FairPlay**
Système de DRM d'Apple. `fairplay-client` est un entitlement sensible.

**FCB (File Control Block)**
Structure NTFS — non utilisé ici.

**FormDFU / DFU Mode**
Mode Device Firmware Upgrade d'iOS, permet le flash bas niveau. Cible des exploits checkm8.

**Frida**
Outil d'instrumentation dynamique multiplateforme. **Hors scope** pour ce projet statique.

## G

**Ghidra**
Outil RE open-source de la NSA. Pour décompiler le binaire AOT (5-7 jours estimés).

**Gibraltar** (Border)
---

## H

**Hash**
Empreinte cryptographique (SHA-256 ici). Voir `05_IOC/ioc_catalog.md` §hashes.

**HTTPS** (Hypertext Transfer Protocol Secure)
HTTP + TLS. Tous les endpoints iRemovalPRO utilisent HTTPS.

## I

**iCloud**
Service cloud d'Apple. **Activation Lock** lie l'iPhone à l'Apple ID.

**ICLR** (.NET)
Common Language Runtime. Voir [MSDN](https://learn.microsoft.com/dotnet/standard/clr).

**idevicepair**
Outil de libimobiledevice pour le pairing USB iPhone.

**ideviceproxy**
Outil de libimobiledevice pour tunnel localhost ↔ iPhone.

**ImageBase**
Adresse de base en mémoire où Windows charge un PE. iRemovalPro.dll : 0x180000000.

**IOC** (Indicator of Compromise)
Marqueur technique d'une compromission. Voir `05_IOC/ioc_catalog.md`.

**iOS**
Système d'exploitation mobile d'Apple. Le bypass cible iOS 12+.

**iPhone6,2**
Identifiant matériel iPhone 5s. Visible dans l'UI de l'app.

## J

**JIT** (Just-in-Time)
Compilation à l'exécution. .NET classique utilise JIT ; .NET NativeAOT utilise AOT.

**JSON** (JavaScript Object Notation)
Format d'échange. Utilisé par l'API iRemovalPRO.

## L

**libimobiledevice**
Stack open-source de communication USB iOS. Présente dans `ref/toolkits/`.

**libplist**
Bibliothèque de manipulation plist. Utilisée par iremovalpro.dll.

**libusbmuxd**
Wrapper pour `usbmuxd` (multiplexeur USB Apple).

**LLB** (Low Level Bootloader)
Première étape du boot iOS. Mentionné dans iremovalpro.dll.

**logOS**
Service iOS pour la journalisation système.

## M

**Mach-O**
Format binaire natif macOS/iOS. Voir `04_EXTRACTED/*.bin` pour les payloads iOS extraits.

**MDM** (Mobile Device Management)
Gestion d'appareils mobiles en entreprise. iRemoval PRO peut supprimer les profils MDM.

**MEID** (Mobile Equipment Identifier)
Identifiant unique 56 bits d'un appareil cellulaire. Bypassé par `BypassMeidSignal`.

**Metadata Token**
Token dans la table des métadonnées .NET. Format : 0x06000000 + RID.

**MitM** (Man-in-the-Middle)
Attaque réseau par interception. mitmproxy est l'outil utilisé.

**MobileActivationDaemon**
Service iOS responsable de l'activation. **Hooké** par blackhound.dylib.

**MVC** (Model-View-Controller)
Pattern de design — non utilisé ici.

## N

**NativeAOT**
Compilation AOT native de .NET 8+. Produit du binaire compilé complet.

**NetworkCredential**
Identifiants réseau (.NET). Présent dans iremovalpro.dll.

**Non-AOT** (.NET)
Mode de compilation .NET classique (JIT).

## O

**OCSP** (Online Certificate Status Protocol)
Protocole de vérification de révocation de certificats. Endpoints Apple intégrés.

**OpenSSL**
Bibliothèque crypto open-source. OpenSSL 3 utilisée (libssl-3-x64.dll).

## P

**Pairing**
Processus d'authentification iPhone ↔ PC. `iDevice_Pair` réalise cette étape.

**PCAP** (Packet Capture)
Format de capture réseau. Wireshark produit des PCAP.

**PE** (Portable Executable)
Format des exécutables Windows. iRemoval PRO.exe et iremovalpro.dll.

**PE32** / **PE32+**
PE 32-bit / 64-bit. EXE = PE32 x86, DLL = PE32+ x64.

**PFX** (Personal Information Exchange)
Format PKCS#12 pour clés privées. `PFXImportCertStore` importe.

**plist** (Property List)
Format de sérialisation Apple. Binaire ou XML.

**PKCS#7**
Format de signature cryptographique. Présent dans iremovalpro.dll.

**PMU** (Performance Monitor Unit)
Matériel CPU pour mesurer les performances. Pas utilisé ici.

## Q

**QRCoder**
Bibliothèque .NET pour générer des QR codes. Présente dans iremovalpro.dll.

## R

**R2R** (ReadyToRun)
Format de pré-compilation .NET. Présent dans iremovalpro.dll (AOT).

**RBAC** (Role-Based Access Control)
Contrôle d'accès basé sur les rôles. Non utilisé ici.

**RCE** (Remote Code Execution)
Exécution de code à distance. Pas de RCE dans iRemoval.

**RestSharp**
Client REST .NET populaire. Utilisé par iremovalpro.dll.

**RVA** (Relative Virtual Address)
Offset relatif à l'ImageBase.

## S

**SAML** (Security Assertion Markup Language)
Pas utilisé.

**SAN** (Subject Alternative Name)
Extension de certificat X.509.

**SHA** (Secure Hash Algorithm)
SHA-1, SHA-256, SHA-384, SHA-512 sont présents.

**SshNet** (Renci.SshNet)
Client SSH .NET. Utilisé pour tunneler vers l'iPhone jailbreaké.

**SUS** (Single User Signature)
Pas utilisé.

## T

**TCP** (Transmission Control Protocol)
Protocole de transport. Tous les flux utilisent TCP (port 443 pour HTTPS).

**TLP** (Traffic Light Protocol)
TLP:LEAKED = diffusion restreinte, TLP:GREEN = diffusion libre.

**TMS** (Threat Management System)
Pas utilisé ici.

**TPM** (Trusted Platform Module)
Pas utilisé.

**Tweak**
Extension iOS jailbreakée. `blackhound.dylib` est un tweak Cydia Substrate.

**TypeRef** (.NET)
Table de métadonnées .NET — référence à un type externe.

## U

**UEFI** (Unified Extensible Firmware Interface)
Firmware moderne. iPhone utilise un équivalent (iBoot).

**UAC** (User Account Control)
Mécanisme Windows d'élévation. `ExecuteAsAdmin` le contourne.

**UEM** (Unified Endpoint Management)
Synonyme MDM.

**Unified Logging**
Système de logs centralisé d'iOS. Pas intercepté ici.

**USB** (Universal Serial Bus)
Transport utilisé pour iPhone ↔ PC.

**USBPcap**
Outil pour capturer le trafic USB. Wireshark peut lire les PCAP.

**usbmuxd**
Daemon macOS/Windows pour multiplexer les connexions iOS sur USB.

## V

**VB.NET** (Visual Basic .NET)
Pas utilisé ici. Le projet est en C#.

**VI** (Version Information)
Métadonnées de version d'un PE. Timestamp + VersionInfo.

**Visual Studio**
IDE Microsoft. Linker 48.0 (VS 2005) dans iRemoval PRO.exe.

## W

**WAF** (Web Application Firewall)
Pas utilisé.

**WPF** (Windows Presentation Foundation)
Framework UI .NET. `iRemovalProWPF` est l'assembly EXE.

## X

**XAML** (eXtensible Application Markup Language)
Format de markup pour WPF. `MainWindow.xaml` est l'UI.

**X.509**
Standard de certificat numérique. Validation via `CertVerifyCertificateChainPolicy`.

**XOR** (Exclusive OR)
Opération binaire. Utilisé dans certains chiffrement simples.

## Y

**YARA**
Outil d'identification de malwares basé sur des règles. Voir `05_IOC/YARA_RULES.yar`.

## Z

**ZIP** (compression)
Format de compression. Pas de ZIP protégé dans le projet.

---

**Total termes** : 100+
**Dernière mise à jour** : 2026-06-22
