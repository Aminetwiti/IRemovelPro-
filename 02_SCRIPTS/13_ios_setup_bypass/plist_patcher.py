#!/usr/bin/env python3
"""
plist_patcher.py - iOS Setup Assistant Bypass via plist injection
Forge les fichiers plist critiques pour contourner l'Assistant de configuration iOS

Usage:
    python plist_patcher.py --mode forge --output ./patched_plists
    python plist_patcher.py --mode inject --host 192.168.1.100
"""

import argparse
import sys
import plistlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

# === 1. PLIST TARGETS ===
# Ces chemins correspondent aux fichiers critiques identifiés dans l'architecture
PLIST_TARGETS = {
    "purplebuddy": {
        "path": "/var/mobile/Library/Preferences/com.apple.purplebuddy.plist",
        "description": "Setup Assistant state tracker",
        "forge_keys": {
            "SetupDone": True,
            "SetupState": 5,              # 5 = Setup complete
            "SetupLastExit": "GestureNav", # dernière étape franchie
            "ProductVersion": "16.7.5",
            "ConfigurationFinished": True
        }
    },
    "preboard": {
        "path": "/var/mobile/Library/Preferences/com.apple.PreBoard.plist",
        "description": "Pre-boot activation state",
        "forge_keys": {
            "ActivationState": "Activated",
            "BrickState": False,
            "ShowSetupUI": False
        }
    },
    "activation_record": {
        "path": "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobileactivationd/activation_records/activation_record.plist",
        "description": "MAD activation record",
        "forge_keys": {
            "ActivationState": "Activated",
            "ActivationRandomness": b"\x00" * 20,  # 20 bytes nuls
            "FairPlayKeyData": b"\x00" * 165,      # 165 bytes nuls
            "AccountTokenCertificate": None,
            "DeviceCertificate": None
        }
    }
}


def forge_plists(output_dir: Path) -> None:
    """
    Crée les plists forgés avec les valeurs bypass
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"[+] Forge des plists dans {output_dir}")
    
    for name, config in PLIST_TARGETS.items():
        plist_data = config["forge_keys"].copy()
        plist_data["_ForgedBy"] = "plist_patcher.py"
        plist_data["_ForgedAt"] = datetime.utcnow().isoformat() + "Z"
        
        output_file = output_dir / f"{name}.plist"
        with open(output_file, "wb") as f:
            plistlib.dump(plist_data, f)
        
        print(f"  ✓ {name}.plist ({len(plist_data)} clés) → {config['description']}")
    
    print(f"\n[✓] {len(PLIST_TARGETS)} plists forgés avec succès")


def inject_plists_ssh(host: str, port: int = 22, user: str = "root", password: str = "alpine") -> None:
    """
    Injecte les plists via SSH sur un iPhone jailbreaké
    Requiert: paramiko (pip install paramiko)
    """
    try:
        import paramiko
    except ImportError:
        print("[!] Erreur: paramiko non installé. Utilisez: pip install paramiko")
        sys.exit(1)
    
    print(f"[+] Connexion SSH à {user}@{host}:{port}")
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(host, port=port, username=user, password=password, timeout=10)
        print("  ✓ Connecté")
        
        sftp = ssh.open_sftp()
        
        for name, config in PLIST_TARGETS.items():
            local_file = Path("./patched_plists") / f"{name}.plist"
            remote_path = config["path"]
            
            if not local_file.exists():
                print(f"  [!] Fichier local manquant: {local_file}")
                continue
            
            # Backup de l'original si existant
            backup_cmd = f"[ -f {remote_path} ] && cp {remote_path} {remote_path}.bak"
            stdin, stdout, stderr = ssh.exec_command(backup_cmd)
            stdout.channel.recv_exit_status()
            
            # Injection
            sftp.put(str(local_file), remote_path)
            
            # Permissions
            ssh.exec_command(f"chmod 644 {remote_path}")
            ssh.exec_command(f"chown mobile:mobile {remote_path}")
            
            print(f"  ✓ {name}.plist injecté à {remote_path}")
        
        sftp.close()
        
        # Redémarrage du daemon activation
        print("\n[+] Redémarrage de mobileactivationd...")
        stdin, stdout, stderr = ssh.exec_command("killall -9 mobileactivationd; sleep 2")
        stdout.channel.recv_exit_status()
        print("  ✓ Daemon redémarré")
        
        print("\n[✓] Injection complète. Redémarrez l'iPhone (reboot) pour appliquer.")
        
    except paramiko.AuthenticationException:
        print(f"[!] Authentification échouée (user={user}, pass={password})")
        sys.exit(1)
    except paramiko.SSHException as e:
        print(f"[!] Erreur SSH: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Erreur: {e}")
        sys.exit(1)
    finally:
        ssh.close()


def verify_bypass(host: str, port: int = 22, user: str = "root", password: str = "alpine") -> None:
    """
    Vérifie si le bypass a réussi en lisant les plists sur l'iPhone
    """
    try:
        import paramiko
    except ImportError:
        print("[!] paramiko requis pour verify")
        sys.exit(1)
    
    print(f"[+] Vérification du bypass sur {host}")
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(host, port=port, username=user, password=password, timeout=10)
        
        for name, config in PLIST_TARGETS.items():
            remote_path = config["path"]
            stdin, stdout, stderr = ssh.exec_command(f"cat {remote_path}")
            exit_code = stdout.channel.recv_exit_status()
            
            if exit_code == 0:
                data = stdout.read()
                try:
                    plist = plistlib.loads(data)
                    print(f"\n  ✓ {name}.plist:")
                    for key in config["forge_keys"]:
                        actual = plist.get(key, "MISSING")
                        expected = config["forge_keys"][key]
                        match = "✓" if actual == expected else "✗"
                        print(f"    {match} {key}: {actual}")
                except Exception as e:
                    print(f"  [!] Erreur parsing {name}: {e}")
            else:
                print(f"  [!] {name}.plist non trouvé à {remote_path}")
        
    finally:
        ssh.close()


def main():
    parser = argparse.ArgumentParser(
        description="iOS Setup Assistant Bypass - plist injector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # 1. Forger les plists localement
  python plist_patcher.py --mode forge --output ./patched_plists
  
  # 2. Injecter sur iPhone via SSH (jailbreak requis)
  python plist_patcher.py --mode inject --host 192.168.1.100 --user root --pass alpine
  
  # 3. Vérifier le bypass
  python plist_patcher.py --mode verify --host 192.168.1.100

Note: L'iPhone doit être jailbreaké avec accès SSH (OpenSSH installé via Cydia/Sileo)
        """
    )
    
    parser.add_argument("--mode", choices=["forge", "inject", "verify"], required=True,
                        help="Mode: forge (créer plists), inject (envoyer via SSH), verify (vérifier)")
    parser.add_argument("--output", type=Path, default=Path("./patched_plists"),
                        help="Dossier de sortie pour mode forge (défaut: ./patched_plists)")
    parser.add_argument("--host", help="Adresse IP de l'iPhone (requis pour inject/verify)")
    parser.add_argument("--port", type=int, default=22, help="Port SSH (défaut: 22)")
    parser.add_argument("--user", default="root", help="User SSH (défaut: root)")
    parser.add_argument("--pass", dest="password", default="alpine", help="Mot de passe SSH (défaut: alpine)")
    
    args = parser.parse_args()
    
    if args.mode == "forge":
        forge_plists(args.output)
    
    elif args.mode == "inject":
        if not args.host:
            print("[!] --host requis pour mode inject")
            sys.exit(1)
        inject_plists_ssh(args.host, args.port, args.user, args.password)
    
    elif args.mode == "verify":
        if not args.host:
            print("[!] --host requis pour mode verify")
            sys.exit(1)
        verify_bypass(args.host, args.port, args.user, args.password)


if __name__ == "__main__":
    main()
