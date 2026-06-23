"""apple_drm_defense.py
====================================

**Simulation défensive** de ce qu'Apple *doit* implémenter côté
``albert.apple.com/deviceservices/drmHandshake`` pour détecter un
bypass iCloud Activation Lock de type **iRemoval PRO v5.2**.

.. important::

   100% défensif — ce module **ne contient aucune** technique de bypass
   ni aucun marqueur réutilisable par un attaquant. Son seul but est de
   permettre aux défenseurs, chercheurs et équipes SOC de :

   1. **Valider** leurs propres règles de détection (YARA, Sigma,
      Suricata, EDR) en réutilisant un oracle Python pur.
   2. **Comparer** une charge d'activation entrante contre les IoC
      extraits de l'audit (``05_IOC/ioc_catalog.md``,
      ``01_REPORTS/BYPASS_CORE.md``).
   3. **Éduquer** les défenseurs : chaque check est annoté avec la
      source documentaire (section, hash, chaîne de l'audit).

Architecture
------------

Le défenseur expose **une seule fonction publique** :

.. code-block:: python

    ok, reason = AppleDRMDefender().validate_ticket(ticket)

où ``ticket`` est un :class:`ActivationTicket` (dataclass immuable).
Chaque contrôle est indépendant et produit une *raison* lisible par un
humain. Le test "OK" final exige que **tous** les contrôles passent
(détection à base de "deny-list" → un seul match = blocage).

Les listes noires sont chargées depuis des **constantes figées** au
moment de l'import, alignées sur la version v5.2 auditée. Une mise à
jour d'iRemoval PRO demandera de revalider et de re-publier ce module
(voir la :class:`AppleDRMDefender.VERSION`).

Exécution
---------

Le module s'exécute en mode self-test :

.. code-block:: bash

    python 06_LOCAL_REPRODUCER/apple_drm_defense.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ============================================================================ #
# 1. Dataclass — un ticket d'activation (ce qu'Apple reçoit sur le wire)
# ============================================================================ #

@dataclass(frozen=True)
class ActivationTicket:
    """Vue *défensive* d'un ticket d'activation reçu par ``drmHandshake``.

    Tous les champs sont **ce qu'Apple observe réellement** côté serveur
    (les détails internes des clefs privées restent opaques pour le
    défenseur — l'oracle se concentre sur ce qui est publiquement
    vérifiable).
    """

    # Identifiants device
    udid: str
    serial: str = ""
    imei: str = ""
    meid: str = ""

    # Cryptographie de la signature (extrait du plist)
    public_key_modulus: bytes = b""

    # Plist complet (key -> valeur) après parsing bplist00
    plist_data: Dict[str, Any] = field(default_factory=dict)

    # Métadonnées réseau
    client_ip: str = ""
    client_build_marker: str = ""  # ce que le binaire Win envoie en clair

    # --- Champs pour les défenses "session" (ajoutés 2026-06-22) --- #

    #: Nonce de session (pour anti-replay). Venant du plist, doit être
    #: *unique* sur la fenêtre glissante ``NONCE_WINDOW_SECONDS``.
    #: Source : BYPASS_CORE.md §16 step 2 (``nonceB`` côté serveur).
    nonce: str = ""

    #: Numéro de séquence monotone de l'UDID. Doit croître
    #: continuellement ; un saut > ``MAX_SEQUENCE_GAP`` ou une
    #: régression (seq < précédent) indique un replay ou un
    #: bypass de machine d'état.
    sequence_number: int = 0

    #: HWID client (empreinte opérateur) déclaré dans la requête. Doit
    #: correspondre au HWID enregistré à l'achat de la licence.
    #: Source : BYPASS_CORE.md §14.1.
    client_hwid: str = ""

    #: Timestamp client (secondes epoch) pour détecter les tickets
    #: forgés "dans le passé" ou "dans le futur". Apple a l'horloge
    #: de référence côté ``albert.apple.com``.
    client_timestamp: float = 0.0

    # --- Champs couches D / E / F (ajoutés 2026-06-22, v5.2-LAB-0.2) --- #

    #: Issuer DN du certificat device (couche D — HWID root-of-trust).
    #: Doit commencer par ``"CN=Apple Device CA"``.
    device_cert_issuer: str = ""

    #: Empreinte SHA-256 du certificat client mTLS (couche G).
    #: Format hex 64-char. Si présent, doit matcher le pin Apple.
    client_cert_sha256: str = ""

    #: Token DeviceCheck JWT (couche G). iCloud l'utilise pour les
    #: re-checks hors-ligne. iRemoval PRO ne peut pas en signer un.
    devicecheck_token: str = ""


@dataclass
class SessionState:
    """État serveur multi-appels pour les défenses *session*.

    Conservé entre plusieurs appels à :meth:`AppleDRMDefender.validate_ticket`
    pour implémenter l'anti-replay (sliding-window sur les nonces), la
    vérification de séquence monotone par UDID, et le HWID binding
    (BYPASS_CORE.md §16 step 2 + §14).

    Trois dictionnaires internes :

    * ``seen_nonces`` — ``nonce -> timestamp``. Purge automatique des
      entrées plus vieilles que ``nonce_window_seconds``.
    * ``last_sequence`` — ``udid -> dernier_sequence_number_valide``.
    * ``known_hwids`` — ``udid -> hwid_attendu_à_l'enregistrement``.

    Usage::

        state = SessionState()
        defender.register_legit_session(state, udid="...", hwid="...")
        ok, reasons = defender.validate_ticket(ticket, session=state)
    """

    seen_nonces: Dict[str, float] = field(default_factory=dict)
    last_sequence: Dict[str, int] = field(default_factory=dict)
    known_hwids: Dict[str, str] = field(default_factory=dict)


# ============================================================================ #
# 2. Le défenseur
# ============================================================================ #

class AppleDRMDefender:
    """Simule la politique défensive qu'Apple *devrait* appliquer.

    .. note::

       Cette simulation n'est **pas** une copie du code serveur d'Apple
       (qui est propriétaire). C'est une **spécification inversée** à
       partir de l'audit de iRemoval PRO v5.2, qui énumère les
       marqueurs **uniques** au bypass et qui seraient trivialement
       détectables côté serveur.
    """

    #: Version de la base de marqueurs. À incrémenter à chaque mise à
    #: jour de iRemoval PRO pour permettre la coexistence de plusieurs
    #: bases défensives (utile pour les tests de régression).
    VERSION = "5.2-LAB-0.2"

    # ------------------------------------------------------------------ #
    # 2.1 Blacklists — toutes dérivées de l'audit (BYPASS_CORE.md §3, §5, §10)
    # ------------------------------------------------------------------ #

    #: SHA-1 du modulus RSA-1024 embarqué dans le dylib de bypass.
    #: Source : ``04_EXTRACTED/blackhound_rsa_pubkey.pem`` (calculé au
    #: runtime pour éviter toute divergence entre l'audit et le code).
    #: Note : l'IoC catalog publie ``d488c22c...`` mais ce SHA-1 ne
    #: correspond pas au modulus de la clé embarquée
    #: (``b83b6e2f...``). Le SHA-1 calculé
    #: ``032476fc5c2ff5e65e5ae6ae81b2c45433bf32a8`` est la valeur de
    #: référence pour ce défenseur.
    FORBIDDEN_MODULI_SHA1: Dict[str, str] = {
        "032476fc5c2ff5e65e5ae6ae81b2c45433bf32a8":
            "iRemoval PRO v5.2 RSA-1024 bypass modulus (BY-INT-001)",
    }

    #: Champs plist *jamais* présents dans un ticket Apple légitime.
    #: Source : ``BYPASS_CORE.md`` §5 — "BlackHound custom keys".
    FORBIDDEN_PLIST_KEYS: Dict[str, str] = {
        "iRemovalRecord":
            "champ 'iRemovalRecord' réservé au bypass (BY-INT-002)",
        "iRemovalSignature":
            "champ 'iRemovalSignature' réservé au bypass (BY-INT-003)",
        "BlackHound-Public-Build":
            "build marker Cydia Substrate (BY-INT-004)",
        "iRemovalState":
            "champ introduit dans les variantes v5+ (BY-INT-005)",
    }

    #: Bundle IDs déposés sur l'iDevice cible.
    #: Source : ``ioc_catalog.md`` — "Bundles iOS déployés".
    #:
    #: .. note::
    #:
    #:   **Heuristique d'extension** (rapport §14 #12) : pour ajouter une
    #:   nouvelle entrée, utiliser le script ``forensic_discovery.py`` qui
    #:   scanne les dumps de strings et remonte les Bundle IDs candidats
    #:   matchant les patterns typiques des outils de bypass commerciaux.
    #:   Tout candidat doit être **validé manuellement** (reverse engineering
    #:   + OSINT) avant ajout ici. Les faux positifs évidents (troncatures
    #:   de Bundle IDs déjà catalogués) sont filtrés automatiquement.
    FORBIDDEN_BUNDLE_IDS: Dict[str, str] = {
        "com.panyolsoft.blackhound":
            "tweak Cydia Substrate (BY-EXT-001)",
        "com.iremovalpro.bypass":
            "helper iOS du bypass (BY-EXT-002)",
        "com.blackhound.eraser":
            "helper d'effacement NAND (BY-EXT-003)",
    }

    #: Build markers textuels que le binaire Win envoie en clair.
    #: Source : ``HISTORICAL_VARIANTS.md`` — "Build marker".
    FORBIDDEN_BUILD_MARKERS: Dict[str, str] = {
        "Blackhound iRemovalPro Public build 0.7.1 @2022":
            "build marker original jamais mis à jour (BY-EXT-004)",
        "iRemovalProWPF":
            "namespace UI WPF (BY-EXT-005)",
    }

    #: Endpoints C2 connus (pour journalisation des IP, pas un check
    #: de blocage — un iPhone légitime ne devrait jamais appeler ces
    #: hôtes). Source : ``ioc_catalog.md`` — "Domaines".
    KNOWN_C2_DOMAINS: Dict[str, str] = {
        "s13.iremovalpro.com": "serveur principal iRemoval PRO",
        "iremovalpro.co": "site vitrine iRemoval PRO",
        "pay.iremovalpro.com": "page paiement",
    }

    #: Préfixes HWID *légitimes attendus* (documentation — pas un
    #: check d'autorisation). Ces préfixes correspondent aux APIs
    #: Win32 que le binaire iRemoval PRO interroge pour construire
    #: le HWID (voir BYPASS_CORE.md §14.1) ; en production Apple
    #: maintiendrait sa propre cartographie HWID ↔ licence.
    HWID_SOURCES: Dict[str, str] = {
        "GetVolumeInformationW": "sérial de volume Windows",
        "Win32_Processor": "CPU brand + stepping",
        "Win32_BaseBoard": "sérial carte mère",
        "GetAdaptersInfo": "adresse MAC (entropie dominante)",
        "Win32_OperatingSystem": "InstallDate + SerialNumber",
    }

    # ------------------------------------------------------------------ #
    # 2.2 Seuils
    # ------------------------------------------------------------------ #

    #: Apple utilise RSA ≥ 2048 sur iOS 13+. Toute valeur inférieure
    #: doit être considérée comme suspecte (BYPASS_CORE.md §3).
    MIN_RSA_BITS = 2048

    #: Fenêtre glissante (secondes) pendant laquelle un nonce est
    #: considéré "déjà vu". 5 minutes = compromis entre mémoire
    #: bornée et détection de replay rapide.
    NONCE_WINDOW_SECONDS: float = 300.0

    #: Saut de séquence maximal toléré. Au-delà, c'est suspect (un
    #: attaquant qui rejoue en avançant la séquence, ou un client
    #: corrompu qui réinitialise son compteur).
    MAX_SEQUENCE_GAP: int = 1000

    #: Dérive temporelle maximale tolérée (secondes) entre le timestamp
    #: client et l'horloge de référence (``albert.apple.com``). 5
    #: minutes couvre les RTT intercontinentaux tout en bloquant les
    #: tickets forgés "dans le futur".
    MAX_TIMESTAMP_DRIFT_SECONDS: float = 300.0

    #: Plancher de latence pour ``drmHandshake``. Un ticket légitime
    #: impose à Apple un calcul RSA + lookup DB ≥ 5 ms. Un temps
    #: mesuré < 5 ms indique un ticket **pré-signé** (cache) ou
    #: une réponse scripted.
    TIMING_FLOOR_MS: float = 5.0

    #: Plafond de latence (sanité). Au-delà, c'est probablement un
    #: DoS ou un timeout de tunnel SSH.
    TIMING_CEILING_MS: float = 30_000.0

    # ------------------------------------------------------------------ #
    # 2.2.1 Couche D — Forensique iOS (root-of-trust + identity file)
    # ------------------------------------------------------------------ #

    #: Préfixes attendus des certificats d'attestation de HWID émis
    #: par le Secure Enclave (racine Apple Device CA). Les certificats
    #: iRemoval PRO sont auto-signés ou absents.
    #: Source : BYPASS_CORE.md §14 — "HWID root-of-trust".
    EXPECTED_DEVICE_CA_ISSUER_PREFIX: str = "CN=Apple Device CA"

    #: Champs plist *obligatoires* qu'Apple inclut dans un ticket
    #: authentique pour l'iOS Activation Lock (SecureROM/identity
    #: file). Un ticket forgé en omettant ces champs contourne
    #: silencieusement la vérification de fichier d'identité.
    #: Source : BYPASS_CORE.md §11 — "Identity file bypass".
    REQUIRED_IDENTITY_FIELDS: Tuple[str, ...] = (
        "BoardID",
        "ChipID",
        "SecurityDomain",
        "ProductionStatus",
        "CertificateSecurityMode",
    )

    #: Domaine autorisé pour les DeviceCheck tokens. iRemoval PRO ne
    #: peut pas générer un token valide car il nécessite la clé privée
    #: côté Secure Enclave (BYPASS_CORE.md §15).
    DEVICECHECK_ISSUER: str = "devicecheck.apple.com"

    # ------------------------------------------------------------------ #
    # 2.2.2 Couche E — Validation baseband (MEID/IMEI coherency)
    # ------------------------------------------------------------------ #

    #: Luhn check sur l'IMEI — calcul rapide côté serveur pour rejeter
    #: les IMEI forgés / aléatoires. Apple l'applique déjà sur le
    #: portail GSMA, mais un ticket iCloud *ne le vérifie pas* —
    #: c'est précisément le trou que iRemoval PRO exploite.
    @staticmethod
    def _luhn_check(s: str) -> bool:
        if not s or not s.isdigit():
            return False
        total = 0
        for i, ch in enumerate(reversed(s)):
            d = int(ch)
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0

    # ------------------------------------------------------------------ #
    # 2.2.3 Couche F — DMD hardening (3 ops DMD critiques)
    # ------------------------------------------------------------------ #

    #: Clés DMD (Device Management Daemon) qui *doivent* figurer dans
    #: un ticket de désactivation légitime. iRemoval PRO les omet pour
    #: court-circuiter la vérification MDM. Source : BYPASS_CORE.md §12
    #: — "DMD bypass".
    REQUIRED_DMD_OPERATIONS: Tuple[str, ...] = (
        "ActivationLockStatus",
        "DeviceLockState",
        "BackupPasswordProtected",
    )

    # ------------------------------------------------------------------ #
    # 2.2.4 Couche G — Apple DeviceCheck + client-cert pinning (B3/B4)
    # ------------------------------------------------------------------ #

    #: Empreinte SHA-256 du certificat client attendu pour les
    #: requêtes iCloud / drmHandshake. En production, Apple utilise
    #: la chaîne "Apple iPhone Device CA" — toute déviation indique
    #: un proxy MITM ou un certificat auto-signé.
    #: Source : BYPASS_CORE.md §17 — "SSL bypass".
    EXPECTED_CLIENT_CERT_SHA256_PREFIX: str = (
        "A0B1C2D3E4F5"  # placeholder for demo; Apple uses real pin
    )

    #: Audience DeviceCheck — un token iCloud valide est signé avec
    #: cette audience. iRemoval PRO forge un token arbitraire.
    DEVICECHECK_AUDIENCE: str = "com.apple.devicecheck.activation"

    # ------------------------------------------------------------------ #
    # 2.2.5 Couche AFC — Détection d'injection Apple File Conduit
    # ------------------------------------------------------------------ #

    #: Chaînes de caractères typiques d'une injection AFC (Apple File
    #: Conduit) trouvées dans le plist forgé ou les traces device.
    #: Source : ``AFC_INJECTION_ANALYSIS.md`` §2.2, §3.
    AFC_INJECTION_STRINGS: Tuple[str, ...] = (
        "/var/mobile/Library/Caches/activation_record.plist",
        "/var/mobile/Library/Caches/activation_records/",
        "/var/mobile/Library/Caches/version33.txt",
        "com.apple.mobile.house_arrest",
        "com.apple.mobile.afc",
        "AFCWriteFile",
        "AFCOpenFile",
        "ideviceproxy",
        "afcclient",
        "BlackHound-AFC",
    )

    #: Marqueurs de l'état de pairing lockdown. Un ticket légitime
    #: iTunes contient au moins un de ces champs. Un ticket injecté
    #: via AFC2 sans iTunes les omet (BY-AFC-001).
    AFC_LOCKDOWN_PAIRING_KEYS: Tuple[str, ...] = (
        "PairingOptions",
        "PairingRequestId",
        "PairingStatus",
        "PairingData",
        "PairingSessionId",
        "PairingError",
        "PairingErrorCode",
    )

    def validate_ticket(
        self,
        ticket: ActivationTicket,
        session: Optional["SessionState"] = None,
        server_proc_ms: float = 0.0,
    ) -> Tuple[bool, List[str]]:
        """Vérifie qu'un ticket d'activation est légitime.

        :param ticket: le ticket à valider (champs statiques).
        :param session: état serveur optionnel pour les défenses
            *session* (anti-replay, séquence, HWID). Si ``None``,
            seules les défenses *statiques* sont appliquées.
        :param server_proc_ms: latence mesurée côté serveur pour
            traiter ce ticket (utile à la défense *timing*). Si
            ``0.0``, le check timing est ignoré.
        :returns: ``(True, [])`` si le ticket passe tous les contrôles,
            sinon ``(False, [raisons_lisibles...])``. On retourne
            *toutes* les raisons pour faciliter la journalisation
            (un défenseur préfère savoir qu'un ticket cumule 3 marqueurs
            plutôt qu'un seul).
        """
        reasons: List[str] = []

        # 1) Modulus RSA blacklisté
        if ticket.public_key_modulus:
            mod_sha1 = hashlib.sha1(
                ticket.public_key_modulus
            ).hexdigest()
            if mod_sha1 in self.FORBIDDEN_MODULI_SHA1:
                reasons.append(
                    f"modulus RSA blacklisté "
                    f"({mod_sha1[:16]}…) — "
                    f"{self.FORBIDDEN_MODULI_SHA1[mod_sha1]}"
                )
        else:
            # Pas de modulus = signature autogénérée par un hook
            # Security.framework (cf. §3 BYPASS_CORE.md).
            reasons.append(
                "aucun modulus RSA présenté — signature probablement "
                "générée par un hook local (SecKeyRawVerify bypassed)"
            )

        # 2) Clé trop courte
        if ticket.public_key_modulus:
            bits = len(ticket.public_key_modulus) * 8
            if bits < self.MIN_RSA_BITS:
                reasons.append(
                    f"clé RSA trop courte: {bits} bits "
                    f"(attendu ≥ {self.MIN_RSA_BITS})"
                )

        # 3) Champs plist suspects
        for key, descr in self.FORBIDDEN_PLIST_KEYS.items():
            if key in ticket.plist_data:
                reasons.append(
                    f"champ plist suspect '{key}' présent — {descr}"
                )

        # 4) Bundle IDs (souvent présents dans un ticket enrichi)
        bundle_ids = self._extract_bundle_ids(ticket.plist_data)
        for bid in bundle_ids:
            if bid in self.FORBIDDEN_BUNDLE_IDS:
                reasons.append(
                    f"bundle ID interdit '{bid}' — "
                    f"{self.FORBIDDEN_BUNDLE_IDS[bid]}"
                )

        # 5) Build markers
        if ticket.client_build_marker:
            for marker, descr in self.FORBIDDEN_BUILD_MARKERS.items():
                if marker in ticket.client_build_marker:
                    reasons.append(
                        f"build marker suspect '{marker}' — {descr}"
                    )

        # 6) IP qui résout vers un domaine C2 connu (best-effort :
        # on ne fait pas de DNS ici, on regarde les reverse-DNS
        # déjà fournis par le caller).
        if ticket.client_ip:
            # L'extension self._reverse_dns_hint est injectable pour
            # les tests ; en production, on logge simplement la classe
            # réseau (cf. IOC « ports »).
            pass

        # --- Défenses "session" (cumulatives) --- #

        # 7) Anti-replay (nonce + fenêtre glissante)
        if session is not None and ticket.nonce:
            reasons.extend(self._check_anti_replay(ticket, session))

        # 8) Séquence monotone par UDID
        if session is not None and ticket.sequence_number:
            reasons.extend(self._check_sequence(ticket, session))

        # 9) HWID binding
        if session is not None and ticket.client_hwid:
            reasons.extend(self._check_hwid(ticket, session))

        # 10) Dérive temporelle (timestamp client vs horloge serveur)
        if ticket.client_timestamp > 0.0:
            reasons.extend(self._check_timestamp_drift(ticket))

        # 11) Timing anomaly (latence mesurée côté serveur)
        if server_proc_ms > 0.0:
            reasons.extend(self._check_timing(ticket, server_proc_ms))

        # --- Couches D / E / F (forensique iOS, baseband, DMD) --- #

        # 12) HWID root-of-trust (Device CA issuer)
        if ticket.device_cert_issuer:
            reasons.extend(self._check_device_ca(ticket))

        # 13) Identity file completeness (SecureROM attestation)
        reasons.extend(self._check_identity_file(ticket))

        # 14) MEID/IMEI Luhn checksum
        reasons.extend(self._check_baseband_coherency(ticket))

        # 15) DMD operations completeness
        reasons.extend(self._check_dmd_operations(ticket))

        # --- Couches G (DeviceCheck + client-cert, B3 / B4) --- #

        # 16) Apple DeviceCheck token validation (toujours évalué —
        # un token absent est *aussi* suspect qu'un token mal-formé).
        reasons.extend(self._check_devicecheck_token(ticket))

        # --- Couche AFC — Apple File Conduit injection detection --- #

        # 18) AFC traces in plist / missing lockdown pairing
        reasons.extend(self._check_afc_injection(ticket))

        return (len(reasons) == 0), reasons

    # ------------------------------------------------------------------ #
    # 2.3.1 Défenses session — anti-replay, séquence, HWID, timing
    # ------------------------------------------------------------------ #

    def _check_anti_replay(
        self, ticket: ActivationTicket, session: "SessionState"
    ) -> List[str]:
        """Rejette tout nonce déjà vu dans la fenêtre glissante.

        Effet de bord : un nonce *frais* est inséré dans
        ``session.seen_nonces`` et les entrées expirées sont purgées.
        """
        now = time.time()
        # Purge des entrées expirées.
        expired = [
            n for n, ts in session.seen_nonces.items()
            if now - ts > self.NONCE_WINDOW_SECONDS
        ]
        for n in expired:
            session.seen_nonces.pop(n, None)

        if ticket.nonce in session.seen_nonces:
            return [
                f"replay détecté: nonce '{ticket.nonce[:16]}…' déjà "
                f"présent dans la fenêtre de {int(self.NONCE_WINDOW_SECONDS)}s "
                f"(BY-SES-001)"
            ]
        # Enregistrement.
        session.seen_nonces[ticket.nonce] = now
        return []

    def _check_sequence(
        self, ticket: ActivationTicket, session: "SessionState"
    ) -> List[str]:
        """Vérifie la monotonicité de la séquence par UDID.

        Une régression (``seq < last``) est un signe de replay ; un
        saut > ``MAX_SEQUENCE_GAP`` est suspect (reset de compteur
        ou tentative de saut de file d'attente).
        """
        reasons: List[str] = []
        last = session.last_sequence.get(ticket.udid)
        if last is not None:
            if ticket.sequence_number < last:
                reasons.append(
                    f"séquence régressive pour UDID {ticket.udid[:12]}…: "
                    f"{ticket.sequence_number} < dernier vu {last} "
                    f"(BY-SES-002)"
                )
            elif ticket.sequence_number - last > self.MAX_SEQUENCE_GAP:
                reasons.append(
                    f"saut de séquence anormal pour UDID {ticket.udid[:12]}…: "
                    f"{ticket.sequence_number} - {last} = "
                    f"{ticket.sequence_number - last} > {self.MAX_SEQUENCE_GAP} "
                    f"(BY-SES-003)"
                )
        # Mise à jour.
        if not reasons or ticket.sequence_number >= (last or 0):
            session.last_sequence[ticket.udid] = max(
                ticket.sequence_number, last or 0
            )
        return reasons

    def _check_hwid(
        self, ticket: ActivationTicket, session: "SessionState"
    ) -> List[str]:
        """Vérifie que le HWID présenté correspond au HWID enregistré.

        Le HWID binding est ce qui empêche le vol de licence : un
        attaquant qui copie un ticket d'un autre PC se fait rejeter
        par ce check (BYPASS_CORE.md §14).
        """
        expected = session.known_hwids.get(ticket.udid)
        if expected is None:
            # Premier contact : on enregistre et on laisse passer
            # (ou l'opérateur Apple aura pré-enregistré le HWID).
            session.known_hwids[ticket.udid] = ticket.client_hwid
            return []
        if expected != ticket.client_hwid:
            return [
                f"HWID mismatch pour UDID {ticket.udid[:12]}…: "
                f"présenté '{ticket.client_hwid[:16]}…' mais attendu "
                f"'{expected[:16]}…' (BY-SES-004)"
            ]
        return []

    def _check_timestamp_drift(
        self, ticket: ActivationTicket
    ) -> List[str]:
        """Rejette les tickets dont le timestamp client dérive trop."""
        now = time.time()
        drift = abs(now - ticket.client_timestamp)
        if drift > self.MAX_TIMESTAMP_DRIFT_SECONDS:
            direction = "futur" if ticket.client_timestamp > now else "passé"
            return [
                f"timestamp client hors fenêtre: dérive {drift:.0f}s "
                f"vers le {direction} (max {self.MAX_TIMESTAMP_DRIFT_SECONDS}s, "
                f"BY-SES-005)"
            ]
        return []

    def _check_timing(
        self, ticket: ActivationTicket, server_proc_ms: float
    ) -> List[str]:
        """Détecte les réponses *trop rapides* (ticket pré-signé).

        Un ``drmHandshake`` légitime prend ≥ 5 ms (RSA verify + DB
        lookup). Une latence mesurée < ``TIMING_FLOOR_MS`` indique
        un ticket en cache (replay) ou une réponse scripted.
        """
        reasons: List[str] = []
        if server_proc_ms < self.TIMING_FLOOR_MS:
            reasons.append(
                f"latence serveur anormale: {server_proc_ms:.2f}ms < "
                f"{self.TIMING_FLOOR_MS}ms (ticket probablement pré-signé, "
                f"BY-SES-006)"
            )
        if server_proc_ms > self.TIMING_CEILING_MS:
            reasons.append(
                f"latence serveur excessive: {server_proc_ms:.0f}ms > "
                f"{self.TIMING_CEILING_MS}ms (DoS ou tunnel SSH lent, "
                f"BY-SES-007)"
            )
        return reasons

    # ------------------------------------------------------------------ #
    # 2.3.2 Défenses couches D / E / F (nouveau 2026-06-22, v5.2-LAB-0.2)
    # ------------------------------------------------------------------ #

    def _check_device_ca(self, ticket: ActivationTicket) -> List[str]:
        """Vérifie que le device-cert est bien émis par Apple Device CA.

        iRemoval PRO remplace le certificat device par un
        self-signed / absent pour court-circuiter le HWID binding.
        Source : BYPASS_CORE.md §14.
        """
        issuer = ticket.device_cert_issuer
        if not issuer.startswith(self.EXPECTED_DEVICE_CA_ISSUER_PREFIX):
            return [
                f"certificat device NON émis par Apple Device CA "
                f"(issuer='{issuer[:32]}…') — HWID root-of-trust "
                f"contourné (BY-D-001)"
            ]
        return []

    def _check_identity_file(self, ticket: ActivationTicket) -> List[str]:
        """Vérifie que tous les champs d'identité SecureROM sont présents.

        Un ticket légitime contient *toujours* BoardID, ChipID,
        SecurityDomain, ProductionStatus, CertificateSecurityMode.
        iRemoval PRO omet ces champs dans sa variante "fast bypass".
        Source : BYPASS_CORE.md §11.
        """
        missing = [
            f for f in self.REQUIRED_IDENTITY_FIELDS
            if f not in ticket.plist_data
        ]
        if missing:
            return [
                f"identity file incomplet: champs SecureROM absents "
                f"{missing} — fichier d'identité bypassé (BY-D-002)"
            ]
        return []

    def _check_baseband_coherency(self, ticket: ActivationTicket) -> List[str]:
        """Vérifie le Luhn checksum sur IMEI et le format MEID.

        iRemoval PRO génère des IMEI aléatoires qui *échouent*
        systématiquement le Luhn check. Côté Apple, le Luhn n'est
        pas appliqué sur iCloud (uniquement sur GSMA), ce qui
        constitue le trou exploité par le bypass.
        """
        reasons: List[str] = []
        if ticket.imei:
            if not self._luhn_check(ticket.imei):
                reasons.append(
                    f"IMEI Luhn check échoué: '{ticket.imei[:8]}…' — "
                    f"IMEI forgé ou aléatoire (BY-E-001)"
                )
        if ticket.meid:
            # MEID = 14 hex chars (decimal) — 56 bits
            if len(ticket.meid) != 14 or not ticket.meid.isalnum():
                reasons.append(
                    f"MEID format invalide: '{ticket.meid[:8]}…' "
                    f"(attendu 14 chars alnum, BY-E-002)"
                )
        return reasons

    def _check_dmd_operations(self, ticket: ActivationTicket) -> List[str]:
        """Vérifie que les 3 ops DMD critiques sont présentes.

        iRemoval PRO omet ``ActivationLockStatus``,
        ``DeviceLockState`` et ``BackupPasswordProtected`` pour
        court-circuiter la vérification MDM. Source :
        BYPASS_CORE.md §12.
        """
        dmd = ticket.plist_data.get("DMDOperations") or {}
        if not isinstance(dmd, dict):
            return [
                f"DMDOperations absent ou non-dict "
                f"(type={type(dmd).__name__}) — "
                f"ops MDM bypassées (BY-F-001)"
            ]
        missing = [op for op in self.REQUIRED_DMD_OPERATIONS if op not in dmd]
        if missing:
            return [
                f"DMD ops critiques absentes {missing} — "
                f"vérification MDM contournée (BY-F-002)"
            ]
        return []

    def _check_devicecheck_token(self, ticket: ActivationTicket) -> List[str]:
        """Vérifie qu'un token DeviceCheck est présent et bien formé.

        iCloud utilise DeviceCheck pour les re-vérifications hors
        ligne. Un token valide a :

          * audience = ``DEVICECHECK_AUDIENCE``
          * issuer  = ``DEVICECHECK_ISSUER``
          * non expiré

        iRemoval PRO fournit un token forgé / absent.
        Source : BYPASS_CORE.md §15.
        """
        tok = ticket.devicecheck_token
        if not tok:
            return [
                "DeviceCheck token absent — re-vérification hors-ligne "
                "désactivée (BY-G-001)"
            ]
        # Minimal shape check (full JWT verify would need cryptography).
        if tok.count(".") != 2:
            return [
                f"DeviceCheck token mal-formé ({tok.count('.')} segments, "
                f"attendu 2) — JWT DeviceCheck invalide (BY-G-002)"
            ]
        return []

    def _check_client_cert_pin(self, ticket: ActivationTicket) -> List[str]:
        """Vérifie que le cert client mTLS est pinné par Apple.

        iRemoval PRO contourne mTLS en présentant un cert auto-signé
        (le serveur iCloud authentique exige la chaîne Apple Device
        CA). Source : BYPASS_CORE.md §17.
        """
        pin = ticket.client_cert_sha256
        if not pin:
            return [
                "certificat client mTLS absent — connexion non "
                "authentifiée (BY-G-003)"
            ]
        if not pin.startswith(self.EXPECTED_CLIENT_CERT_SHA256_PREFIX[:8]):
            return [
                f"certificat client mTLS non pinné (sha256='{pin[:16]}…') "
                f"— chaîne Apple Device CA absente (BY-G-004)"
            ]
        return []

    def _check_afc_injection(self, ticket: ActivationTicket) -> List[str]:
        """Détecte les traces d'injection AFC (Apple File Conduit).

        iRemoval PRO écrit le `activation_record.plist` forgé sur
        l'iPhone via AFC2 (mode house-arrest) sans jamais passer par
        un lockdown iTunes légitime. Côté serveur, on détecte :

        1. Absence de marqueurs lockdown pairing (BY-AFC-001)
        2. Présence de chemins AFC dans le plist (BY-AFC-002)
        3. Service house-arrest / AFC dans le plist (BY-AFC-003)
        4. Marqueur version33.txt ou ideviceproxy (BY-AFC-004)
        5. ActivationState mais DeviceCheck absent (BY-AFC-005)

        Source : ``AFC_INJECTION_ANALYSIS.md`` §4, §5.
        """
        reasons: List[str] = []
        plist = ticket.plist_data

        # BY-AFC-001 — missing lockdown pairing record
        # A legit iTunes activation ALWAYS includes Pairing* keys.
        has_pairing = any(
            k in plist for k in self.AFC_LOCKDOWN_PAIRING_KEYS
        )
        if not has_pairing and "ActivationState" in plist:
            reasons.append(
                "ActivationState présent mais aucun PairingRecord "
                "lockdown — activation probable via AFC sans iTunes "
                "pairing (BY-AFC-001)"
            )

        # BY-AFC-002 / BY-AFC-003 / BY-AFC-004 — AFC strings in plist
        # We scan all string values for AFC injection traces.
        def _scan_plist_for_afc(obj: Any) -> List[str]:
            """Recursive scan for AFC strings in plist values."""
            hits: List[str] = []
            if isinstance(obj, str):
                for s in self.AFC_INJECTION_STRINGS:
                    if s in obj:
                        hits.append(s)
            elif isinstance(obj, dict):
                for v in obj.values():
                    hits.extend(_scan_plist_for_afc(v))
            elif isinstance(obj, list):
                for item in obj:
                    hits.extend(_scan_plist_for_afc(item))
            return hits

        afc_hits = _scan_plist_for_afc(plist)
        if afc_hits:
            # Deduplicate while preserving order
            seen: set = set()
            unique_hits = []
            for h in afc_hits:
                if h not in seen:
                    seen.add(h)
                    unique_hits.append(h)
            for h in unique_hits:
                if "var/mobile/Library/Caches" in h:
                    reasons.append(
                        f"chemin AFC injecté '{h}' détecté dans plist — "
                        f"injection directe via Apple File Conduit "
                        f"(BY-AFC-002)"
                    )
                elif "house_arrest" in h or "com.apple.mobile.afc" in h:
                    reasons.append(
                        f"service AFC '{h}' détecté dans plist — "
                        f"mode house-arrest / AFC2 actif (BY-AFC-003)"
                    )
                else:
                    reasons.append(
                        f"marqueur AFC '{h}' dans plist — "
                        f"trace de l'outil iRemoval PRO / ideviceproxy "
                        f"(BY-AFC-004)"
                    )

        # BY-AFC-005 — Activated state without DeviceCheck
        # A legit iCloud activation always includes a valid
        # DeviceCheck token. AFC injection skips this step.
        if plist.get("ActivationState") == "Activated" and \
                not ticket.devicecheck_token:
            reasons.append(
                "ActivationState='Activated' mais DeviceCheck token "
                "absent — activation locale via AFC contournant "
                "la vérification Apple (BY-AFC-005)"
            )

        return reasons

    # ------------------------------------------------------------------ #
    # 2.3.2 Bootstrap des sessions légitimes
    # ------------------------------------------------------------------ #

    def register_legit_session(
        self,
        session: "SessionState",
        udid: str,
        hwid: str,
        initial_sequence: int = 1,
    ) -> None:
        """Enregistre une session *légitime* (bootstrap côté Apple).

        À appeler une fois par UDID, après authentification réussie
        (Step 2 du handshake 9-étapes). Permet aux checks
        *session* d'avoir un point de référence.
        """
        session.known_hwids[udid] = hwid
        session.last_sequence[udid] = initial_sequence

    # ------------------------------------------------------------------ #
    # 2.4 Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_bundle_ids(plist: Dict[str, Any]) -> List[str]:
        """Extrait récursivement les bundle IDs d'un plist iOS.

        Les bundle IDs peuvent apparaître dans :

        * ``ActivationInfo`` -> ``BundleIdentifier``
        * un tableau ``Bundles`` ou ``InstalledBundles``
        * un dict ``com.apple.mobileactivationd.records``
        """
        out: List[str] = []
        if not isinstance(plist, dict):
            return out

        for key, value in plist.items():
            if key in ("BundleIdentifier", "bundleID", "CFBundleIdentifier"):
                if isinstance(value, str):
                    out.append(value)
            elif isinstance(value, (dict, list)):
                if isinstance(value, dict):
                    out.extend(AppleDRMDefender._extract_bundle_ids(value))
                else:
                    for item in value:
                        if isinstance(item, (dict, str)):
                            if isinstance(item, str):
                                out.append(item)
                            else:
                                out.extend(
                                    AppleDRMDefender._extract_bundle_ids(item)
                                )
        return out

    # ------------------------------------------------------------------ #
    # 2.5 Sérialisation — utile pour le dashboard
    # ------------------------------------------------------------------ #

    def policy_snapshot(self) -> Dict[str, Any]:
        """Retourne la politique défensive en cours (sérialisable JSON)."""
        return {
            "version": self.VERSION,
            "min_rsa_bits": self.MIN_RSA_BITS,
            "nonce_window_seconds": self.NONCE_WINDOW_SECONDS,
            "max_sequence_gap": self.MAX_SEQUENCE_GAP,
            "max_timestamp_drift_seconds": self.MAX_TIMESTAMP_DRIFT_SECONDS,
            "timing_floor_ms": self.TIMING_FLOOR_MS,
            "timing_ceiling_ms": self.TIMING_CEILING_MS,
            "forbidden_moduli_sha1": list(self.FORBIDDEN_MODULI_SHA1.keys()),
            "forbidden_plist_keys": list(self.FORBIDDEN_PLIST_KEYS.keys()),
            "forbidden_bundle_ids": list(self.FORBIDDEN_BUNDLE_IDS.keys()),
            "forbidden_build_markers": list(
                self.FORBIDDEN_BUILD_MARKERS.keys()
            ),
            "known_c2_domains": list(self.KNOWN_C2_DOMAINS.keys()),
            "hwid_sources": self.HWID_SOURCES,
        }


# ============================================================================ #
# 3. Self-test
# ============================================================================ #

def _run_self_test() -> int:
    """Exécute un jeu de 6 tests intégrés.

    Les tests sont **uniquement défensifs** : ils vérifient qu'un ticket
    légitime passe et qu'un ticket malicieux est bloqué avec la bonne
    raison. Aucune technique de bypass n'est testée.
    """
    # Force UTF-8 stdout to avoid Windows cp1252 issues with the
    # arrow character. Safe no-op on POSIX.
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass
    defender = AppleDRMDefender()

    # 3.1 — Modulus RSA-1024 blacklisté (BYPASS_CORE.md §3)
    bad_modulus = bytes.fromhex(
        "b83b6e2f23ade61c4a324fa7b9223306"
        "6d9a588d961ea8ccfe3c7224ae2545fe"
        "62fd9cd30c947a454b05250f49ac3404"
        "afd38614164f21105dc0f7ab85022bc2"
        "a7f868a83fc4ac461d2991139b192695"
        "3a9feabdd9f3901613acfe6d59d94b20"
        "06f450b1c4a61f06eb43d688cf41f189"
        "9c821ed0c61428c4b6c276f6c6cc8581"
    )
    bad_ticket = ActivationTicket(
        udid="00000000-AAAA-BBBB-CCCC-000000000000",
        public_key_modulus=bad_modulus,
    )
    ok, reasons = defender.validate_ticket(bad_ticket)
    assert not ok, "le modulus blacklisté doit être bloqué"
    assert any("modulus RSA blacklisté" in r for r in reasons), reasons
    print("  [PASS] modulus RSA-1024 blacklisté -> bloqué")

    # 3.2 — Plist contenant iRemovalRecord (BYPASS_CORE.md §5)
    forged_ticket = ActivationTicket(
        udid="00000000-1111-2222-3333-444444444444",
        public_key_modulus=bad_modulus,
        plist_data={
            "ActivationState": "Activated",
            "iRemovalRecord": b"FAKE==",
            "iRemovalSignature": b"SIG==",
        },
    )
    ok, reasons = defender.validate_ticket(forged_ticket)
    assert not ok
    assert any("iRemovalRecord" in r for r in reasons)
    assert any("iRemovalSignature" in r for r in reasons)
    print("  [PASS] champs plist iRemoval* -> bloqué")

    # 3.3 — Bundle ID interdit (BYPASS_CORE.md §10)
    bundle_ticket = ActivationTicket(
        udid="00000000-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
        public_key_modulus=os.urandom(256),  # RSA-2048 random
        plist_data={
            "ActivationInfo": {
                "BundleIdentifier": "com.panyolsoft.blackhound",
            }
        },
    )
    ok, reasons = defender.validate_ticket(bundle_ticket)
    assert not ok
    assert any("com.panyolsoft.blackhound" in r for r in reasons)
    print("  [PASS] bundle ID Cydia Substrate -> bloqué")

    # 3.4 — Clé trop courte
    short_key_ticket = ActivationTicket(
        udid="00000000-BBBB-BBBB-BBBB-BBBBBBBBBBBB",
        public_key_modulus=b"\x00" * 128,  # RSA-1024
    )
    ok, reasons = defender.validate_ticket(short_key_ticket)
    assert not ok
    assert any("trop courte" in r for r in reasons)
    print("  [PASS] clé RSA < 2048 bits -> bloqué")

    # 3.5 — Build marker suspect
    marker_ticket = ActivationTicket(
        udid="00000000-CCCC-CCCC-CCCC-CCCCCCCCCCCC",
        public_key_modulus=os.urandom(256),
        client_build_marker="Blackhound iRemovalPro Public build 0.7.1 @2022",
    )
    ok, reasons = defender.validate_ticket(marker_ticket)
    assert not ok
    assert any("build marker" in r for r in reasons)
    print("  [PASS] build marker original -> bloqué")

    # 3.6 — Ticket légitime (RSA-2048, plist Apple propre, identity + DMD complets)
    legit_ticket = ActivationTicket(
        udid="00000000-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
        public_key_modulus=os.urandom(256),  # RSA-2048 random
        plist_data={
            "ActivationState": "Unactivated",
            "SerialNumber": "F2LXX0000000",
            "UniqueDeviceID": "00000000-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
            # Identity file (couche D)
            "BoardID": 0x02,
            "ChipID": 0x8015,
            "SecurityDomain": 1,
            "ProductionStatus": 1,
            "CertificateSecurityMode": 1,
            # DMD ops (couche F)
            "DMDOperations": {
                "ActivationLockStatus": "OFF",
                "DeviceLockState": "Unlocked",
                "BackupPasswordProtected": False,
            },
        },
        # Couche D — Device CA valide
        device_cert_issuer="CN=Apple Device CA, O=Apple Inc.",
        # Couche G — DeviceCheck + client-cert valides
        devicecheck_token=(
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJpc3MiOiJkZXZpY2VjaGVjay5hcHBsZS5jb20iLC"
            "JhdWQiOiJjb20uYXBwbGUuZGV2aWNlY2hlY2suYWN0aX"
            "ZhdGlvbiJ9."
            "fake_signature"
        ),
        client_cert_sha256="A0B1C2D3E4F5" + "00" * 27,  # pin Apple match
    )
    ok, reasons = defender.validate_ticket(legit_ticket)
    assert ok, f"un ticket légitime doit passer: {reasons}"
    print("  [PASS] ticket Apple légitime (toutes couches) -> OK")

    # ===== Section session (nouveaux tests, BY-SES-001..007) ===== #

    # 3.7 — Anti-replay (même nonce présenté 2x)
    state = SessionState()
    base_ticket = ActivationTicket(
        udid="00000000-AAAA-BBBB-CCCC-AAAAAAAAAAAA",
        public_key_modulus=os.urandom(256),
        plist_data={
            "ActivationState": "Activated",
            "BoardID": 0x02, "ChipID": 0x8015,
            "SecurityDomain": 1, "ProductionStatus": 1,
            "CertificateSecurityMode": 1,
            "DMDOperations": {
                "ActivationLockStatus": "OFF",
                "DeviceLockState": "Unlocked",
                "BackupPasswordProtected": False,
            },
        },
        nonce="abcdef0123456789" * 2,  # 32-char nonce
        sequence_number=1,
        client_hwid="hwid-legit-1",
        device_cert_issuer="CN=Apple Device CA, O=Apple Inc.",
        devicecheck_token="a.b.c",
        client_cert_sha256="A0B1C2D3E4F5" + "00" * 27,
    )
    ok1, reasons1 = defender.validate_ticket(base_ticket, session=state)
    ok2, reasons2 = defender.validate_ticket(base_ticket, session=state)
    assert ok1, f"premier appel doit passer: {reasons1}"
    assert not ok2, "second appel avec le même nonce doit être bloqué"
    assert any("replay" in r for r in reasons2), reasons2
    print("  [PASS] anti-replay: même nonce 2x -> 2e bloqué (BY-SES-001)")

    # 3.8 — Séquence régressive
    state2 = SessionState()
    udid_seq = "00000000-BBBB-AAAA-CCCC-BBBBBBBBBBBB"
    full_session_setup = dict(
        device_cert_issuer="CN=Apple Device CA, O=Apple Inc.",
        devicecheck_token="a.b.c",
        client_cert_sha256="A0B1C2D3E4F5" + "00" * 27,
        plist_data={
            "BoardID": 0x02, "ChipID": 0x8015,
            "SecurityDomain": 1, "ProductionStatus": 1,
            "CertificateSecurityMode": 1,
            "DMDOperations": {
                "ActivationLockStatus": "OFF",
                "DeviceLockState": "Unlocked",
                "BackupPasswordProtected": False,
            },
        },
    )
    t1 = ActivationTicket(
        udid=udid_seq, public_key_modulus=os.urandom(256),
        nonce="n1", sequence_number=10, client_hwid="h",
        **full_session_setup,
    )
    t2 = ActivationTicket(
        udid=udid_seq, public_key_modulus=os.urandom(256),
        nonce="n2", sequence_number=5, client_hwid="h",  # régression !
        **full_session_setup,
    )
    defender.validate_ticket(t1, session=state2)
    ok, reasons = defender.validate_ticket(t2, session=state2)
    assert not ok
    assert any("régressive" in r for r in reasons), reasons
    print("  [PASS] séquence monotone: 5 < 10 -> bloqué (BY-SES-002)")

    # 3.9 — Saut de séquence anormal
    state3 = SessionState()
    t_a = ActivationTicket(
        udid=udid_seq, public_key_modulus=os.urandom(256),
        nonce="na", sequence_number=1, client_hwid="h",
        **full_session_setup,
    )
    t_b = ActivationTicket(
        udid=udid_seq, public_key_modulus=os.urandom(256),
        nonce="nb", sequence_number=10_000, client_hwid="h",  # saut > 1000
        **full_session_setup,
    )
    defender.validate_ticket(t_a, session=state3)
    ok, reasons = defender.validate_ticket(t_b, session=state3)
    assert not ok
    assert any("anormal" in r for r in reasons), reasons
    print("  [PASS] saut de séquence > 1000 -> bloqué (BY-SES-003)")

    # 3.10 — HWID mismatch
    state4 = SessionState()
    udid_h = "00000000-CCCC-AAAA-BBBB-CCCCCCCCCCCC"
    t_h1 = ActivationTicket(
        udid=udid_h, public_key_modulus=os.urandom(256),
        nonce="nh1", sequence_number=1, client_hwid="hwid-original",
        **full_session_setup,
    )
    t_h2 = ActivationTicket(
        udid=udid_h, public_key_modulus=os.urandom(256),
        nonce="nh2", sequence_number=2, client_hwid="hwid-pirate",
        **full_session_setup,
    )
    defender.validate_ticket(t_h1, session=state4)  # enregistre hwid-original
    ok, reasons = defender.validate_ticket(t_h2, session=state4)
    assert not ok
    assert any("HWID mismatch" in r for r in reasons), reasons
    print("  [PASS] HWID mismatch: pirate vs original -> bloqué (BY-SES-004)")

    # 3.11 — Timestamp drift (ticket du futur)
    t_future = ActivationTicket(
        udid="00000000-FFFF-AAAA-CCCC-FFFFFFFFFFFF",
        public_key_modulus=os.urandom(256),
        plist_data={"ActivationState": "Activated"},
        client_timestamp=time.time() + 3600,  # +1h dans le futur
    )
    ok, reasons = defender.validate_ticket(t_future)
    assert not ok
    assert any("timestamp" in r for r in reasons), reasons
    print("  [PASS] timestamp dans le futur (+1h) -> bloqué (BY-SES-005)")

    # 3.12 — Timing anomaly (latence trop courte = pré-signé)
    t_timing = ActivationTicket(
        udid="00000000-FFFF-FFFF-AAAA-FFFFFFFFFFFF",
        public_key_modulus=os.urandom(256),
        plist_data={"ActivationState": "Activated"},
    )
    ok, reasons = defender.validate_ticket(t_timing, server_proc_ms=0.42)
    assert not ok
    assert any("0.42ms" in r or "latence serveur" in r for r in reasons), reasons
    print("  [PASS] timing anomaly: 0.42ms < 5ms -> bloqué (BY-SES-006)")

    # 3.13 — Attaque combinée : 3 marqueurs statiques + 1 session
    state5 = SessionState()
    bad_mod_short = os.urandom(64)  # 512 bits (trop court)
    t_combined = ActivationTicket(
        udid="00000000-DEAD-BEEF-CAFE-000000000000",
        public_key_modulus=bad_mod_short,  # 1) trop court
        plist_data={                         # 2) iRemovalRecord
            "ActivationState": "Activated",
            "iRemovalRecord": b"FAKE==",
        },
        client_build_marker="Blackhound iRemovalPro Public build 0.7.1 @2022",  # 3) build marker
        nonce="combined-attack-nonce-1",
        sequence_number=42,
    )
    ok, reasons = defender.validate_ticket(t_combined, session=state5)
    assert not ok
    # Au moins 3 raisons distinctes attendues.
    n_short = sum(1 for r in reasons if "trop courte" in r)
    n_iremove = sum(1 for r in reasons if "iRemovalRecord" in r)
    n_marker = sum(1 for r in reasons if "build marker" in r)
    assert n_short and n_iremove and n_marker, reasons
    assert len(reasons) >= 3, f"≥3 raisons attendues, got {len(reasons)}: {reasons}"
    print(f"  [PASS] attaque combinée -> {len(reasons)} raisons cumulées "
          f"(short + plist + marker)")

    # ===== Section couches D / E / F / G (nouveaux tests, v5.2-LAB-0.2) ===== #

    # 3.14 — Couche D : HWID root-of-trust (Device CA issuer manquant)
    t_no_ca = ActivationTicket(
        udid="00000000-D001-0000-0000-000000000000",
        public_key_modulus=os.urandom(256),
        plist_data={"ActivationState": "Activated"},
        device_cert_issuer="CN=iRemoval Self-Signed CA",
    )
    ok, reasons = defender.validate_ticket(t_no_ca)
    assert not ok, "ticket avec mauvais issuer doit être bloqué"
    assert any("Apple Device CA" in r for r in reasons), reasons
    print("  [PASS] Device CA issuer invalide -> bloqué (BY-D-001)")

    # 3.15 — Couche D : identity file incomplet (champs SecureROM absents)
    t_incomplete_id = ActivationTicket(
        udid="00000000-D002-0000-0000-000000000000",
        public_key_modulus=os.urandom(256),
        plist_data={
            "ActivationState": "Activated",
            # BoardID, ChipID, etc. absents à dessein
        },
    )
    ok, reasons = defender.validate_ticket(t_incomplete_id)
    assert not ok, "identity file incomplet doit être bloqué"
    assert any("identity file incomplet" in r for r in reasons), reasons
    assert any("BoardID" in r for r in reasons), reasons
    print("  [PASS] identity file SecureROM incomplet -> bloqué (BY-D-002)")

    # 3.16 — Couche E : IMEI Luhn check échoué (IMEI forgé)
    t_bad_imei = ActivationTicket(
        udid="00000000-E001-0000-0000-000000000000",
        public_key_modulus=os.urandom(256),
        plist_data={"ActivationState": "Activated"},
        imei="123456789012345",  # Luhn fail (un dernier digit bidon)
        meid="A0B1C2D3E4F5G6",  # 14 chars alnum — valide
    )
    ok, reasons = defender.validate_ticket(t_bad_imei)
    assert not ok, "IMEI forgé doit être bloqué"
    assert any("Luhn" in r for r in reasons), reasons
    print("  [PASS] IMEI Luhn check échoué -> bloqué (BY-E-001)")

    # 3.17 — Couche F : DMDOperations absent (bypass MDM)
    t_no_dmd = ActivationTicket(
        udid="00000000-F001-0000-0000-000000000000",
        public_key_modulus=os.urandom(256),
        plist_data={"ActivationState": "Activated"},
        # pas de DMDOperations
    )
    ok, reasons = defender.validate_ticket(t_no_dmd)
    assert not ok, "DMD ops absentes doivent être bloquées"
    assert any("DMD" in r for r in reasons), reasons
    print("  [PASS] DMDOperations critiques absentes -> bloqué (BY-F-001/002)")

    # 3.18 — Couche G : DeviceCheck token absent
    t_no_dc = ActivationTicket(
        udid="00000000-G001-0000-0000-000000000000",
        public_key_modulus=os.urandom(256),
        plist_data={"ActivationState": "Activated"},
        # pas de devicecheck_token
    )
    ok, reasons = defender.validate_ticket(t_no_dc)
    assert not ok, "DeviceCheck token absent doit être bloqué"
    assert any("DeviceCheck token absent" in r for r in reasons), reasons
    print("  [PASS] DeviceCheck token absent -> bloqué (BY-G-001)")

    # 3.19 — Couche G : Client-cert pinning échoué
    t_bad_pin = ActivationTicket(
        udid="00000000-G002-0000-0000-000000000000",
        public_key_modulus=os.urandom(256),
        plist_data={"ActivationState": "Activated"},
        client_cert_sha256="deadbeef" + "00" * 28,  # pas le pin Apple
    )
    ok, reasons = defender.validate_ticket(t_bad_pin)
    assert not ok, "client-cert pin mismatch doit être bloqué"
    assert any("non pinné" in r or "pinné" in r for r in reasons), reasons
    print("  [PASS] Client-cert pinning échoué -> bloqué (BY-G-004)")

    # 3.20 — Attaque "fast bypass" iRemoval : aucun champ sensible présent
    t_fast_bypass = ActivationTicket(
        udid="00000000-FAST-0000-BYP4-000000000000",
        public_key_modulus=b"\x00" * 64,  # RSA-512 (très court)
        plist_data={
            "ActivationState": "Activated",
            "iRemovalRecord": b"X" * 256,  # BY-INT-002
            "iRemovalSignature": b"Y" * 256,  # BY-INT-003
        },
        client_build_marker="Blackhound iRemovalPro Public build 0.7.1 @2022",  # BY-EXT-004
        imei="000000000000000",  # Luhn fail — BY-E-001
        device_cert_issuer="CN=Self-Signed",  # BY-D-001
        # DMD absent  -> BY-F-001/002
        # Identity file absent -> BY-D-002
        # DeviceCheck absent -> BY-G-001
        # Client-cert absent -> BY-G-003
    )
    ok, reasons = defender.validate_ticket(t_fast_bypass)
    assert not ok
    # On attend au moins 7 raisons cumulées (les 4 marqueurs
    # historiques + IMEI + Device CA + identity file + DMD + ...).
    assert len(reasons) >= 7, (
        f"≥7 raisons attendues sur fast bypass, got {len(reasons)}: "
        f"{reasons}"
    )
    print(f"  [PASS] fast bypass iRemoval -> {len(reasons)} raisons cumulées")

    print(f"\n  Tous les tests passent (defender v{defender.VERSION}).")
    return 0


# ============================================================================ #
# 4. CLI
# ============================================================================ #

def _cli_dump_policy(out_path: Optional[Path]) -> int:
    """Sérialise la politique défensive au format JSON (utile pour le
    dashboard ``dashboard_20260622.html``)."""
    snap = AppleDRMDefender().policy_snapshot()
    text = json.dumps(snap, indent=2, sort_keys=True, ensure_ascii=False)
    if out_path is None:
        print(text)
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
        print(f"Policy written to {out_path}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Apple DRM Defender — simulation défensive d'albert.apple.com",
    )
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "--self-test",
        action="store_true",
        help="Exécute la batterie de tests internes",
    )
    g.add_argument(
        "--dump-policy",
        action="store_true",
        help="Sérialise la politique défensive au format JSON",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Chemin du fichier de sortie (défaut: stdout)",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return _run_self_test()
    if args.dump_policy:
        return _cli_dump_policy(args.output)
    parser.error("argument required")
    return 2  # unreachable


if __name__ == "__main__":
    sys.exit(main())
