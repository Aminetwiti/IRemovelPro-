#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deep RE pass 3: iOS protocol layers, lockdown plist, AFC, MobileBackup2."""
import sys, struct, re, io
from collections import Counter
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DLL = r'c:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\iremovalpro.dll'
with open(DLL, 'rb') as f:
    data = f.read()

# ==== A) iOS lockdown plist keys (very comprehensive) ====
print("="*80)
print("[1] LOCKDOWN PROTOCOL - PLIST KEYS")
print("="*80)
lockdown_keys = [
    b'DeviceName', b'BoardID', b'ChipID', b'ProductType', b'SerialNumber',
    b'IMEI', b'IMSI', b'ICCID', b'FirmwareVersion', b'HardwarePlatform',
    b'HostName', b'UniqueDeviceID', b'ProductVersion', b'ProductBuildVersion',
    b'ModelNumber', b'ActivationState', b'BrickState',
    b'BasebandVersion', b'BasebandStatus', b'BasebandCertId', b'BasebandSerialNumber',
    b'BasebandChipId', b'BasebandClass', b'BasebandFirmwareVersion',
    b'BluetoothAddress', b'WifiAddress',
    b'TimeZone', b'TimeIntervalSince1970',
    b'RegionInfo', b'RegionCode',
    b'SIMStatus', b'SIMTrayStatus', b'SIMCarrier', b'SIMPhoneNumber',
    b'PhoneNumber', b'MCC', b'MNC',
    b'CertificateProduction', b'CertificateDevelopment',
    b'ChipSerialNo', b'UniqueChipID',
    b'ECID', b'IMei', b'Imei', b'MobileSubscriberInfo', b'InternationalMobileEquipmentIdentity',
    b'IntegratedCircuitCardIdentity', b'InternationalMobileSubscriberIdentity',
    b'GetValue', b'SetValue', b'RemoveValue', b'GetRecord', b'SetRecord',
    b'Remove', b'Get', b'Set', b'Delete', b'List',
    b'Sync', b'SyncDataClass', b'WaitForSync',
    b'GetCapabilities', b'SetCapabilities', b'GetUsageData', b'GetDiagnosticsData',
    b'UserName', b'Password', b'PasswordType', b'Domain',
    b'VerifyMessage', b'VerifyReceipt', b'VerifyPhone',
    b'Requested', b'Request', b'Response', b'Status', b'Error', b'ErrorCode', b'ErrorDescription',
    b'PairingOptions', b'PairingRequestId', b'PairingStatus', b'PairingData',
    b'PairingSessionId', b'PairingError', b'PairingErrorCode',
    b'BUID', b'PROG', b'GID', b'UID', b'AK', b'GIDKey', b'DKey',
    b'X509', b'X509Issuer', b'X509Subject', b'X509Serial', b'X509NotBefore', b'X509NotAfter',
    b'BeginSession', b'EndSession', b'CommitChanges', b'RevertChanges',
    b'UnlockDevice', b'Activation', b'ActivationStateAcknowledged', b'WaitForDeviceUnlock',
    b'LockDevice', b'Notifications', b'PostNotification', b'ObserveNotification',
    b'Screenshot', b'ScreenSize', b'ScreenWidth', b'ScreenHeight',
    b'SetDeviceName', b'SetHostName', b'SetTimeZone', b'SetLanguage',
    b'RestoreOSRequest', b'RestoreOSStatus', b'BackupMessage', b'BackupDomain',
    b'Snapshot', b'SnapshotMessage', b'WillSync', b'DidSync', b'WillRestore', b'DidRestore',
    b'Notification', b'NotificationsStart', b'NotificationsStop',
    b'Connected', b'Disconnected',
    b'RecoveryMode', b'DFUMode', b'RestoreMode', b'NormalMode', b'UnknownMode',
    b'NonVolatileRAM', b'NOR', b'NAND', b'NORData', b'NANDData',
    b'iBoot', b'IBoot', b'iBoot-', b'iBEC', b'IBEC', b'iBSS', b'IBSS',
    b'LLB', b'BootChain', b'kernelcache', b'deviceTree', b'ramdisk',
    b'BasebandBootloaderVersion', b'BasebandFirmwareUpdateVersion',
    b'SigningServer', b'SigningCert', b'SignRequest', b'FDR', b'fdr',
    b'HashTable', b'HashInfo', b'Nonce', b'nonce',
    b'iTunesAccount', b'iTunesVersion', b'iCloudAccount', b'AppleID',
    b'ActivationPolicy', b'ActivationTicket', b'ActivationInfo', b'ActivationRecord',
    b'AccountToken', b'AccountInfo', b'AccountLogin', b'AccountLogout',
    b'AccountState', b'AccountPhoneNumber', b'AccountEmail', b'AccountValidated',
    b'AccountCredential', b'AccountSession', b'AccountNonce', b'AccountAnonymousRequest',
    b'FairPlayKey', b'FairPlayCertificate', b'FairPlayRequest',
    b'FMiPSign', b'FMiPRequest', b'FMiP',
    b'iPhoneActivate', b'RequestActivation', b'ActivationRequest',
    b'ProvisioningProfile', b'MCProfile', b'ProfileList', b'Profile',
    b'InstalledApp', b'InstalledApps', b'ApplicationListing',
    b'VerifyProfile', b'RemoveProfile', b'InstallProfile',
    b'OSEnvironment', b'OSVersion', b'BuildVersion',
    b'SkylockBackup', b'Skylock', b'RestoreData', b'BackupData',
    b'BootedFromSnapshot', b'WillEncrypt', b'HasEncrypted', b'EncryptedData',
    b'BackupPassword', b'BackupPasswordSet', b'RestoreWillTruncate',
    b'BootedSnapshotUUID', b'EncryptionKey', b'SnapshotUUID',
    b'Cleanup', b'BackupFinished', b'BackupCompleted',
    b'MessageType', b'Payload', b'PayloadSize', b'PayloadDescriptor',
    b'BESOperation', b'BESRequest', b'BESResponse', b'BESError',
    b'BBTicket', b'BBTicketRequest', b'BBTicketResponse', b'BBTicketData',
    b'BBI', b'BBIRequest', b'BBIResponse', b'BBIData',
    b'BLS', b'BLSRequest', b'BLSResponse', b'BLSData',
    b'BasebandTicket', b'BasebandSigningRequest', b'BasebandSigningResponse',
    b'WildcardTicket', b'WildcardRequest', b'WildcardResponse',
    b'IMG4', b'IM4M', b'IM4P', b'IM4R', b'Manifest', b'APTicket',
    b'RestorationOS', b'RestorationFirmware', b'RestoreKernelCache',
    b'NORImage', b'NANDImage', b'FirmwareDirectory', b'FirmwareFiles',
    b'PersonalizationData', b'PersonalizationPayload', b'ChipID',
    b'ProductionMode', b'DevelopmentMode', b'OnenessMode',
    b'BoardID', b'BoardRevision', b'BoardName', b'ChipRevision',
    b'BootDelay', b'BootNumber', b'BootSessionUUID', b'BootTimestamp',
    b'UUID', b'EFI', b'ESP', b'IDevice', b'iDevice',
    b'SIMService', b'SIMStatus', b'IMessageSecurity',
    b'BatteryLevel', b'BatteryState', b'BatteryHealth',
    b'ChargingState', b'ExternalChargingState', b'HasBattery', b'HasInternalBattery',
    b'Fusing', b'ChipManufacturingDate', b'ChipFusingInfo',
    b'DeviceClass', b'DeviceColor', b'DeviceEnclosureColor',
    b'ActivationLockAllowed', b'ActivationLockState',
    b'MCXProfile', b'PasscodeStatus', b'IsPasscodeRequired',
    b'iTunesAccountHash', b'iTunesAccountIdentifier', b'iCloudAccountHash',
    b'FindMyPhone', b'FindMy', b'FMIP', b'FMiP',
    b'CallVoicemail', b'Voicemail', b'LiveVoicemail',
    b'ContentSync', b'BackupStorage',
    b'PkiBag', b'PkiCert', b'PkiToken', b'PkiTrustObject', b'PkiTrustResult',
    b'Identity', b'IdentityCertificate', b'IdentityPrivateKey', b'IdentityPublicKey',
    b'UnsignedCertificate', b'RootCertificate', b'IntermediateCertificate',
    b'SystemEnroll', b'Personalize', b'RollDer',
    b'PowerAssertion', b'PowerOn', b'PowerOff', b'Reset',
    b'WIFI', b'CellularNetwork', b'CellularTechnology',
    b'CarrierInstall', b'CarrierBundle', b'CarrierList',
    b'OSEnvironment', b'FileSystem', b'MountImage', b'UnmountImage',
    b'RestoreDevice', b'FactoryReset', b'NVram', b'NVRAM',
    b'Provisioning', b'ProvisioningKey', b'ProvisioningServer',
    b'Vortex', b'VortexStatus', b'VortexInfo', b'VortexError',
    b'Success', b'Failure', b'Progress', b'Cancelled',
    b'SyncBackup', b'SyncBackupEncrypted', b'BackupEncryptionKey',
    b'MobileMailService', b'MobileSafariService', b'MobileNotesService',
    b'SSH', b'SSHPublicKey', b'SSHPrivateKey', b'SSHPort',
    b'com.apple.mobile.lockdown',
    b'com.apple.mobile.notification_proxy',
    b'com.apple.mobile.installation_proxy',
    b'com.apple.mobile.backup',
    b'com.apple.mobile.MobileBackup2',
    b'com.apple.mobile.afc',
    b'com.apple.mobile.SBService',
    b'com.apple.mobile.diagnostics_relay',
    b'com.apple.mobile.crashreporter',
    b'com.apple.mobile.house_arrest',
    b'com.apple.syslog',
    b'com.apple.mobile.file_relay',
    b'com.apple.mobile.screenshotr',
    b'com.apple.mobileactivation',
    b'com.apple.purplebuddy',
    b'com.apple.iosdiagnostics',
    b'com.apple.mobile.iTunes',
    b'com.apple.mobile.restoration',
]
hits = []
for k in lockdown_keys:
    if k in data:
        # Find positions
        positions = []
        p = 0
        while True:
            p = data.find(k, p+1)
            if p < 0: break
            positions.append(p)
            if len(positions) > 5: break
        hits.append((k.decode('latin1','replace'), len(positions), positions[:3]))

# Sort by hit count
hits.sort(key=lambda x: -x[1])
for k, c, pos in hits[:80]:
    print(f"    {k:50}  count={c:3}  first3={[hex(p) for p in pos]}")

# ==== B) AFC (Apple File Conduit) specific ====
print("\n" + "="*80)
print("[2] AFC PROTOCOL COMMANDS")
print("="*80)
afc_cmds = [
    b'AFCGetDeviceInfo', b'AFCGetConnectionInfo', b'AFCGetFileInfo',
    b'AFCOpenFile', b'AFCCloseFile', b'AFCReadFile', b'AFCWriteFile',
    b'AFCOpenDirectory', b'AFCReadDirectory', b'AFCRemovePath', b'AFCRenamePath',
    b'AFCMakeDirectory', b'AFCGetFileHash', b'AFCSetFileModTime', b'AFCSetFileSize',
    b'AFCFileRefOpen', b'AFCFileRefClose', b'AFCFileRefRead', b'AFCFileRefWrite',
    b'AFCProcessExit', b'AFCSendRawCommand', b'AFCReceiveRawCommand',
    b'AFCGetAFCMounts', b'AFCGetAFCStats', b'AFCProcessOp', b'AFCProcessResponse',
    b'AFCHeaderMagic', b'AFCHeaderLength',
    b'AFC_OP_GET_DEVINFO', b'AFC_OP_GET_CONINFO', b'AFC_OP_GET_FILEINFO',
    b'AFC_OP_OPEN_FILE', b'AFC_OP_CLOSE_FILE', b'AFC_OP_READ_FILE', b'AFC_OP_WRITE_FILE',
    b'AFC_OP_OPEN_DIR', b'AFC_OP_READ_DIR', b'AFC_OP_REMOVE_PATH', b'AFC_OP_RENAME_PATH',
    b'AFC_OP_MAKE_DIR', b'AFC_OP_GET_FILEHASH',
    b'/var/containers', b'/var/mobile', b'/var/root', b'/private/var',
    b'/var/Keychains', b'/var/MobileDevice', b'/var/Managed Preferences',
    b'/var/ManagedPreferences', b'/var/mobile/Library', b'/var/mobile/Media',
    b'/private/var/mobile', b'/private/var/root', b'/private/var/Keychains',
    b'/private/var/lib', b'/private/var/db',
    b'SystemKeyBag', b'SystemKeybag', b'UserKeyBag', b'UserKeybag',
    b'keybag-2.db', b'keybag-2-backup.db',
]
for k in afc_cmds:
    pos = data.find(k)
    if pos >= 0:
        # show context
        ctx = data[max(0,pos-20):pos+60]
        print(f"    {k.decode('latin1','replace'):40}  @ 0x{pos:08x}  ctx: {ctx[:60]!r}")

# ==== C) MobileBackup2 protocol ====
print("\n" + "="*80)
print("[3] MOBILEBACKUP2 PROTOCOL")
print("="*80)
mb2_msgs = [
    b'Hello', b'HelloResponse', b'Ready', b'ReadyResponse',
    b'SendFile', b'SendFileResponse', b'ReceiveFile', b'ReceiveFileResponse',
    b'BackupDomainAttach', b'BackupDomainDetach', b'BackupDomainRequest',
    b'BackupDomainBegin', b'BackupDomainEnd', b'BackupDomainCancel',
    b'BackupMessage', b'BackupResponse',
    b'BackupFileReceived', b'BackupFileSent', b'BackupFileSkipped',
    b'BackupFileCorrupted', b'BackupFileEncrypted',
    b'BackupItem', b'BackupItemKey', b'BackupItemValue', b'BackupItemType',
    b'BackupManifestVersion', b'BackupVersion', b'BackupWasEncrypted',
    b'BackupError', b'BackupErrorCode', b'BackupErrorDescription',
    b'BackupProgress', b'BackupProgressBytes', b'BackupProgressTotal',
    b'BackupProgressFile', b'BackupProgressFiles',
    b'BackupTarget', b'BackupTargetIdentifier', b'BackupTargetUUID',
    b'BackupRestore', b'BackupRestoreInfo', b'BackupRestoreDataClass',
    b'BackupRestoreFileReceived', b'BackupRestoreFileSent',
    b'BackupItemLinkTarget', b'BackupItemLinkTargetKey',
    b'BackupItemEncryptionKey', b'BackupItemIsEncrypted',
    b'BackupItemsToCopy', b'BackupItemsToDelete', b'BackupItemsToMove',
    b'BackupPathPrefix', b'BackupPath',
    b'BackupPermissions', b'BackupPermissionsUID', b'BackupPermissionsGID',
    b'BackupPermissionsMode', b'BackupPermissionsMTime',
    b'BackupFileMode', b'BackupFileGroup', b'BackupFileOwner',
    b'BackupFlags', b'BackupFlagsEncrypted', b'BackupFlagsUserFile',
    b'BackupItemTypeFile', b'BackupItemTypeDirectory', b'BackupItemTypeSymlink',
    b'BackupItemTypeHardlink', b'BackupItemTypeFifo', b'BackupItemTypeSocket',
    b'BackupSnapshotUUID', b'BackupSnapshotVersion', b'BackupSnapshotSerial',
    b'BackupSnapshotLastModified', b'BackupSnapshotBackupState',
    b'BackupSnapshotICloud', b'BackupSnapshotICloudVersion',
    b'BackupSnapshotFinished', b'BackupSnapshotStarted', b'BackupSnapshotCancelled',
    b'BackupBackupStateNew', b'BackupBackupStateRunning', b'BackupBackupStateFinished',
    b'BackupBackupStateFailed', b'BackupBackupStateCancelled',
    b'EncryptionKey', b'EncryptionKeyUUID', b'EncryptionKeyWrapping',
    b'EncryptionKeyWrappingType', b'EncryptionKeyEncryption',
    b'DataClassKey', b'DataClassValue', b'DataClassName',
    b'SystemFiles', b'ApplicationFiles', b'MediaFiles',
    b'AddressBook', b'Calendar', b'CallHistory', b'EmailAccounts',
    b'Keychain', b'Notes', b'Voicemail', b'Photos',
    b'SMS', b'MMS', b'WhatsApp', b'Telegram', b'Signal',
    b'ApplicationIdentifier', b'BundleIdentifier', b'Version', b'ShortVersion',
    b'Container', b'Bundle', b'Sandbox', b'Documents',
    b'/RootDomain', b'/HomeDomain', b'/AppDomain', b'/KeychainDomain',
    b'/CameraRollDomain', b'/BackupDomain',
    b'ManifestKey', b'Manifest.plist', b'Info.plist', b'Status.plist',
]
found_mb2 = []
for k in mb2_msgs:
    if k in data:
        p = data.find(k)
        found_mb2.append((k.decode('latin1','replace'), p))
for k, p in found_mb2[:40]:
    print(f"    {k:50}  @ 0x{p:08x}")

# ==== D) Installation Proxy protocol ====
print("\n" + "="*80)
print("[4] INSTALLATION PROXY PROTOCOL")
print("="*80)
ip_msgs = [
    b'Lookup', b'LookupResult', b'LookupResultKey', b'LookupResultValue',
    b'Install', b'InstallResponse', b'InstallMessage', b'InstallMessageType',
    b'Uninstall', b'Upgrade', b'UpgradeResponse', b'UpgradeMessage',
    b'Browse', b'BrowseResult', b'BrowseResultKey', b'BrowseResultValue',
    b'Archive', b'Bundle', b'BundleContainer', b'BundleExecutable',
    b'BundleIdentifier', b'BundlePath', b'BundleVersion',
    b'ApplicationDSID', b'ApplicationSINF', b'ApplicationApplicationIdentifier',
    b'ApplicationDynamicDiskUsage', b'ApplicationStaticDiskUsage',
    b'ApplicationSize', b'ApplicationDate', b'ApplicationTime', b'ApplicationState',
    b'SignerIdentity', b'SignerIdentityCert', b'ApplicationShortVersionString',
    b'ApplicationMinimumOSVersion', b'ApplicationInfoPlist',
    b'iTunesMetadata', b'iTunesMetadata.plist', b'iTunesMetadataVersion',
    b'iTunesMetadataData', b'iTunesMetadataDataUUID',
    b'InstallMode', b'InstallModeAll', b'InstallModeUser', b'InstallModeSystem',
    b'InstallOption', b'InstallOptionUpgrade', b'InstallOptionSkip',
    b'SyncMode', b'SyncModeFast', b'SyncModeSlow',
    b'ReturnStatus', b'ReturnCode', b'ReturnMessage',
    b'ErrorUnknown', b'ErrorBundleNotFound', b'ErrorBundleInvalid',
    b'ErrorBundleVersionMismatch', b'ErrorBundleSignature',
    b'ErrorBundleNotSigned', b'ErrorBundleInvalidUUID',
    b'ErrorBundleMissingExecutable', b'ErrorBundleMissingInfoPlist',
    b'ErrorBundleMinimumOSVersion', b'ErrorBundleMaximumOSVersion',
    b'ErrorBundleArchitectureMismatch', b'ErrorBundleSandbox',
    b'ErrorBundleForbidden',
    b'.app/', b'.app\\', b'Payload/', b'Payload\\', b'IPSW',
    b'SignedManifest.plist', b'AssetManifest.plist',
    b'BuildManifest.plist', b'Restore.plist', b'RestoreKernel',
    b'RestoreRamdisk', b'RestoreDeviceTree', b'RestoreSEP',
    b'iBSS', b'iBEC', b'LLB', b'iBoot', b'kernelcache', b'deviceTree',
    b'ramdisk', b'recovery', b'BatteryPlugin', b'BatteryLow',
    b'BasebandFirmware', b'BasebandBoot', b'BasebandUpdate',
    b'NOR', b'NAND', b'PersistentPartition', b'Volume',
]
found_ip = []
for k in ip_msgs:
    if k in data:
        p = data.find(k)
        found_ip.append((k.decode('latin1','replace'), p))
for k, p in found_ip[:40]:
    print(f"    {k:50}  @ 0x{p:08x}")
print(f"    ... total found: {len(found_ip)}")
