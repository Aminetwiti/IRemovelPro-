"""forensic_discovery.py
====================================

**Heuristique défensive** pour étendre la liste
``FORBIDDEN_BUNDLE_IDS`` du défenseur ``apple_drm_defense.py``.

.. important::

   100% défensif — ce script **ne contient aucune** technique de
   contournement iCloud, ne génère aucun payload malveillant. Son seul
   rôle est de **repérer des Bundle IDs candidats** qui matchent les
   *patterns de nommage* typiques des outils de bypass commerciaux
   (BlackHound / iRemoval PRO et leur descendance), pour faciliter la
   mise à jour de la liste noire au gré des découvertes forensiques.

   Tout Bundle ID remonté par ce script **doit être validé
   manuellement** avant d'être ajouté à ``FORBIDDEN_BUNDLE_IDS`` —
   l'outil ne produit que des *candidats*, jamais des certitudes.

Contexte
--------

La recommandation **#12** du rapport §14 (moyen terme) demande
d'étendre ``FORBIDDEN_BUNDLE_IDS`` au gré des découvertes forensiques.
Cette tâche est :

* **Coûteuse en revue manuelle** : un Bundle ID ressemble à un autre
  et seuls ~5-10 dans tout iOS sont *vraiment* malveillants.
* **Soumise à faux positifs** : `com.panyolsoft.blackhound` est
  malveillant, mais `com.apple.mobileactivationd` est un daemon
  *légitime* d'Apple — on ne peut pas le blacklister.

L'heuristique suivante propose un compromis :

1. **Scanner** un ou plusieurs fichiers (strings dump, binaire extrait,
   plist) à la recherche de chaînes de la forme ``com.X.Y``.
2. **Filtrer** via une liste de patterns typiques des outils de bypass
   (constante ``BYPASS_NAME_PATTERNS`` ci-dessous).
3. **Exclure** les Bundle IDs Apple légitimes (constante
   ``APPLE_KNOWN_BUNDLE_PREFIXES``).
4. **Émettre** une sortie JSON + Markdown de candidats à valider.

Usage
-----

.. code-block:: bash

    # Scanner un dump de strings (sortie par défaut : stdout JSON)
    python 06_LOCAL_REPRODUCER/forensic_discovery.py \\
        --input 03_OUTPUTS/strings_all_long.txt \\
        --out-json 05_IOC/candidate_bundle_ids.json \\
        --out-md   05_IOC/candidate_bundle_ids.md

    # Scanner plusieurs fichiers d'un coup
    python 06_LOCAL_REPRODUCER/forensic_discovery.py \\
        --input 03_OUTPUTS/strings_all_long.txt \\
        --input 03_OUTPUTS/nativeaot/nativeaot_20260622_022333.all.json \\
        --out-md /tmp/candidates.md

    # Mode "self-test" — valide que le scanner fonctionne
    python 06_LOCAL_REPRODUCER/forensic_discovery.py --selftest

Code de retour : 0 si OK, 1 si erreur d'I/O ou d'argument.

Limites connues
---------------

* Le scanner **ne comprend pas le format Mach-O** — il travaille sur
  des dumps de strings (sortie de ``strings`` GNU / BSD).
* La liste ``BYPASS_NAME_PATTERNS`` est *opinionated* : basée sur les
  variantes connues de la famille BlackHound + autres outils du marché
  gris (iRemoval, Checkm8.info, Sliver, etc.).
* ``com.panyolsoft.blackhound`` et les 2 autres entrées actuelles de
  ``FORBIDDEN_BUNDLE_IDS`` sont **dans** la whitelist de détection —
  attendues et confirmées — donc marquées ``already_known``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable, List, Set


# ============================================================================ #
# 1. Constantes — patterns et whitelist
# ============================================================================ #

# Patterns typiques des outils de bypass iCloud commerciaux connus.
# Chaque entrée est une regex *substring* appliquée au Bundle ID complet.
# La liste est volontairement保守 (conservative) : trop de faux positifs
# ruineraient la confiance de l'analyste SOC qui revoit la sortie.
BYPASS_NAME_PATTERNS: List[str] = [
    r"blackhound",         # iRemoval PRO v5.2 / BlackHound 0.7.1 (référence)
    r"iRemoval",           # nom commercial
    r"iremovalpro",        # variante lowercase
    r"iosbypass",          # famille générique
    r"icloudbypass",       # famille générique
    r"icloud-unlock",      # tiret
    r"unlocktool",         # autre famille
    r"checkm8",            # checkm8.info (lockdownd pairing bypass)
    r"sliver",             # Sliver / checkm8 variants
    r"palera1n",           # palera1n jailbreak (souvent packagé avec bypass)
    r"unc0ver",            # unc0ver jailbreak
    r"panyolsoft",         # éditeur du tweak BlackHound (auteur leak)
    r"minacriss",          # second auteur observé dans strings
    r"bypassios",          # autre famille
    r"iosunlock",          # autre famille
    r"abypass",            # autre famille
    r"activationbypass",   # explicite
    r"activation-bypass",  # tiret
]

# Préfixes Apple légitimes — JAMAIS blacklistables (sinon DoS)
APPLE_KNOWN_BUNDLE_PREFIXES: Set[str] = {
    "com.apple.",
    "systemgroup.com.apple.",
    "com.apple.",
}

# Bundle IDs déjà connus dans ``FORBIDDEN_BUNDLE_IDS`` (cf. apple_drm_defense.py).
# Marqueur ``already_known`` dans la sortie — sert d'auto-test que le scanner
# retrouve bien les références cataloguées.
KNOWN_FORBIDDEN_BUNDLE_IDS: Set[str] = {
    "com.panyolsoft.blackhound",
    "com.iremovalpro.bypass",
    "com.blackhound.eraser",
}

# Faux positifs connus : troncatures détectées par le scanner mais qui
# sont en fait des sous-chaînes d'un Bundle ID *plus long* déjà connu.
# Ce set est consulté *après* la classification pour éviter le bruit.
KNOWN_FALSE_POSITIVES: Set[str] = {
    # Troncature de com.iremovalpro.bypass (le `s` final est coupé par un
    # séparateur de mot dans les dumps de strings).
    "com.iremovalpro.bypas",
}

# Pattern d'extraction des Bundle IDs (regex stricte).
# Format standard Apple : segments alphanumériques séparés par des points.
BUNDLE_ID_RE = re.compile(
    r"\bcom\.[a-z][a-z0-9_]{1,30}(?:\.[a-z][a-z0-9_-]{1,40}){0,4}\b",
    flags=re.IGNORECASE,
)


# ============================================================================ #
# 2. Coeur du scanner
# ============================================================================ #

def extract_bundle_ids(text: str) -> Set[str]:
    """Extrait tous les Bundle IDs candidats d'un texte (strings dump)."""
    return {m.group(0).lower() for m in BUNDLE_ID_RE.finditer(text)}


def is_apple_legit(bid: str) -> bool:
    """True si le Bundle ID appartient clairement à un composant Apple légitime."""
    return any(bid.startswith(p) for p in APPLE_KNOWN_BUNDLE_PREFIXES)


def matches_bypass_pattern(bid: str) -> List[str]:
    """Retourne la liste des patterns BYPASS qui matchent ce Bundle ID."""
    return [p for p in BYPASS_NAME_PATTERNS if re.search(p, bid, re.IGNORECASE)]


def looks_truncated(bid: str) -> bool:
    """True si le dernier segment du Bundle ID ressemble à une troncature.

    Heuristique conservatrice : un segment final de 2-4 chars est suspect
    s'il *préfixe* exactement un Bundle ID connu. Cas typique :
    ``com.iremovalpro.bypas`` est détecté comme troncature de
    ``com.iremovalpro.bypass`` car ``bypas`` est préfixe de ``bypass``.
    """
    if "." not in bid:
        return False
    last = bid.rsplit(".", 1)[-1]
    if not (2 <= len(last) <= 4):
        return False
    for known in KNOWN_FORBIDDEN_BUNDLE_IDS:
        if known.startswith(bid):
            return True
    return False


def classify(bundle_ids: Iterable[str]) -> List[dict]:
    """Classe chaque Bundle ID en : ``apple_legit``, ``candidate``,
    ``already_known`` ou ``false_positive`` (troncature détectée)."""
    results: List[dict] = []
    for bid in sorted(set(bundle_ids)):
        if bid in KNOWN_FALSE_POSITIVES:
            results.append({
                "bundle_id": bid,
                "status": "false_positive",
                "patterns": [],
                "reason": "troncature connue d'un Bundle ID déjà catalogué",
            })
            continue
        if bid in KNOWN_FORBIDDEN_BUNDLE_IDS:
            results.append({
                "bundle_id": bid,
                "status": "already_known",
                "patterns": [],
                "reason": "présent dans FORBIDDEN_BUNDLE_IDS",
            })
            continue
        if is_apple_legit(bid):
            # Pas un candidat — composant système Apple
            continue
        pats = matches_bypass_pattern(bid)
        if not pats:
            continue
        if looks_truncated(bid):
            results.append({
                "bundle_id": bid,
                "status": "false_positive",
                "patterns": pats,
                "reason": "troncature probable (préfixe d'un Bundle ID connu)",
            })
            continue
        results.append({
            "bundle_id": bid,
            "status": "candidate",
            "patterns": pats,
            "reason": f"match {len(pats)} pattern(s) bypass: {', '.join(pats)}",
        })
    return results


# ============================================================================ #
# 3. I/O et sortie
# ============================================================================ #

def scan_files(paths: List[Path]) -> Set[str]:
    """Lit plusieurs fichiers et retourne l'union des Bundle IDs trouvés."""
    all_ids: Set[str] = set()
    for p in paths:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"[WARN] cannot read {p}: {exc}", file=sys.stderr)
            continue
        all_ids.update(extract_bundle_ids(text))
    return all_ids


def render_md(results: List[dict], sources: List[Path]) -> str:
    """Génère un rapport Markdown des candidats à valider."""
    candidates = [r for r in results if r["status"] == "candidate"]
    already = [r for r in results if r["status"] == "already_known"]
    false_positives = [r for r in results if r["status"] == "false_positive"]
    lines: List[str] = []
    lines.append("# Candidate Bundle IDs — forensic discovery")
    lines.append("")
    lines.append("> **Artefact défensif** — recommandation **#12** du rapport §14.")
    lines.append("> Sortie de `06_LOCAL_REPRODUCER/forensic_discovery.py`.")
    lines.append("> Chaque candidat **doit être validé manuellement** avant ajout")
    lines.append("> à `FORBIDDEN_BUNDLE_IDS` dans `apple_drm_defense.py`.")
    lines.append("")
    lines.append(f"## Sources scannées ({len(sources)})")
    for p in sources:
        lines.append(f"- `{p}`")
    lines.append("")
    lines.append(f"## Résultats")
    lines.append(f"- **Candidats à valider** : {len(candidates)}")
    lines.append(f"- **Déjà catalogués** : {len(already)}")
    lines.append(f"- **Faux positifs** (troncatures) : {len(false_positives)}")
    lines.append("")
    if candidates:
        lines.append("## 🔍 Candidats")
        lines.append("")
        lines.append("| Bundle ID | Patterns matchés | Raison |")
        lines.append("|---|---|---|")
        for r in candidates:
            pats = ", ".join(f"`{p}`" for p in r["patterns"])
            lines.append(f"| `{r['bundle_id']}` | {pats} | {r['reason']} |")
        lines.append("")
    if false_positives:
        lines.append("## ⚠️ Faux positifs détectés (troncatures)")
        lines.append("")
        for r in false_positives:
            lines.append(f"- `{r['bundle_id']}` — {r['reason']}")
        lines.append("")
    if already:
        lines.append("## ✅ Déjà catalogués (auto-test OK)")
        lines.append("")
        for r in already:
            lines.append(f"- `{r['bundle_id']}` — {r['reason']}")
        lines.append("")
    lines.append("## 📋 Prochaine étape")
    lines.append("")
    lines.append("1. Pour chaque **candidat**, confirmer via :")
    lines.append("   - Reverse engineering (Ghidra dump, NativeAOT strings)")
    lines.append("   - Recherche OSINT (Twitter/X, GitHub, Telegram channels)")
    lines.append("   - Corrélation avec `ioc_catalog.md` et `MITRE_MAPPING.md`")
    lines.append("2. Si confirmé → ajouter à `FORBIDDEN_BUNDLE_IDS` dans")
    lines.append("   `06_LOCAL_REPRODUCER/apple_drm_defense.py` avec description.")
    lines.append("3. Si faux positif → ajouter au set `KNOWN_FALSE_POSITIVES`")
    lines.append("   dans ce script pour éviter récurrence.")
    lines.append("")
    return "\n".join(lines)


def write_output(
    results: List[dict], sources: List[Path],
    out_json: Path | None, out_md: Path | None,
) -> None:
    """Sérialise la sortie (JSON et/ou Markdown)."""
    payload = {
        "scanner_version": "1.0",
        "scanner_purpose": "forensic discovery for FORBIDDEN_BUNDLE_IDS extension",
        "recommendation_ref": "01_REPORTS/NOUVELLES_DECOUVERTES.md §14 #12",
        "sources": [str(p) for p in sources],
        "patterns_count": len(BYPASS_NAME_PATTERNS),
        "results": results,
        "stats": {
            "candidates": sum(1 for r in results if r["status"] == "candidate"),
            "already_known": sum(1 for r in results if r["status"] == "already_known"),
            "false_positives": sum(1 for r in results if r["status"] == "false_positive"),
        },
    }
    if out_json:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"[OK] JSON written → {out_json}")
    if out_md:
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(render_md(results, sources), encoding="utf-8")
        print(f"[OK] Markdown written → {out_md}")


# ============================================================================ #
# 4. Self-test
# ============================================================================ #

def selftest() -> int:
    """Vérifie que les patterns + known IDs fonctionnent sur un texte type."""
    sample = """
        com.apple.mobileactivationd.spi
        systemgroup.com.apple.mobileactivationd
        com.panyolsoft.blackhound
        com.iremovalpro.bypass
        com.blackhound.eraser
        com.unknown.developer.app
        com.example.foobar
        com.icloudbypass.tool
        com.checkm8.info.helper
        com.iremovalpro.bypas
    """
    ids = extract_bundle_ids(sample)
    classified = classify(ids)
    # 3 known + 2 candidats attendus (icloudbypass, checkm8) + 1 FP (troncature)
    candidates = [r for r in classified if r["status"] == "candidate"]
    already = [r for r in classified if r["status"] == "already_known"]
    fp = [r for r in classified if r["status"] == "false_positive"]
    ok = (
        len(candidates) == 2
        and len(already) == 3
        and len(fp) == 1
        # auto-tests : chaque ID connu doit être retrouvé
        and {r["bundle_id"] for r in already} == KNOWN_FORBIDDEN_BUNDLE_IDS
        # auto-tests : la troncature doit être filtrée
        and any(r["bundle_id"] == "com.iremovalpro.bypas" for r in fp)
    )
    print(
        f"[SELFTEST] candidates={len(candidates)} "
        f"already_known={len(already)} "
        f"false_positives={len(fp)} "
        f"→ {'OK' if ok else 'FAIL'}"
    )
    for r in classified:
        print(f"  - {r['bundle_id']:<40} {r['status']:<14} {r['reason']}")
    return 0 if ok else 1


# ============================================================================ #
# 5. CLI
# ============================================================================ #

def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Heuristique défensive pour étendre FORBIDDEN_BUNDLE_IDS "
            "(recommandation #12 du rapport §14)."
        ),
    )
    parser.add_argument(
        "--input", type=Path, action="append", default=[],
        help="Fichier(s) à scanner (strings dump, JSON, plist).",
    )
    parser.add_argument(
        "--out-json", type=Path, default=None,
        help="Chemin du JSON de sortie (candidats structurés).",
    )
    parser.add_argument(
        "--out-md", type=Path, default=None,
        help="Chemin du Markdown de sortie (rapport lisible).",
    )
    parser.add_argument(
        "--selftest", action="store_true",
        help="Valide le scanner sur un échantillon de test.",
    )
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()

    if not args.input:
        print("[ERROR] --input required (or use --selftest)", file=sys.stderr)
        return 1

    sources = [p.resolve() for p in args.input]
    all_ids = scan_files(sources)
    classified = classify(all_ids)
    write_output(classified, sources, args.out_json, args.out_md)

    candidates = [r for r in classified if r["status"] == "candidate"]
    already = [r for r in classified if r["status"] == "already_known"]
    print(f"[INFO] {len(candidates)} candidats, {len(already)} déjà catalogués")
    if candidates:
        print("[INFO] Prochaine étape : valider manuellement chaque candidat")
    return 0


if __name__ == "__main__":
    sys.exit(main())