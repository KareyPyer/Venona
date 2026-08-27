# Venona v6.1 — Patch d'amélioration

## Fichiers modifiés / nouveaux

### Nouveaux collecteurs (à copier dans `collectors/`)
- `collectors/threat_intel/alienvault_otx.py` — AlienVault OTX (gratuit, riche en IOCs)
- `collectors/threat_intel/greynoise.py` — GreyNoise (IPs de scan, clé API optionnelle)
- `collectors/threat_intel/malwarebazaar.py` — MalwareBazaar (hashes de malware, gratuit)
- `collectors/threat_intel/urlscan.py` — URLScan.io (analyse d'URLs, clé API optionnelle)
- `collectors/breach_intel/hibp.py` — Have I Been Pwned (fuites email, clé API requise)
- `collectors/passive_feed/rss.py` — RSS Feeds (BleepingComputer, TheHackerNews, etc.)
- `collectors/surface_attack/shodan.py` — Shodan (hosts exposés, clé API requise)
- `collectors/surface_attack/censys.py` — Censys (hosts/certificats, clé API requise)

### Fichiers core modifiés
- `core/ioc_extractor.py` — 16 types d'IOCs, validation par entropie, filtrage TLD suspects
- `core/scoring.py` — Scoring v2 (Sévérité × Confiance × Fiabilité source)
- `core/dork_templates.py` — Templates de requêtes OSINT par type d'investigation

### Fichiers UI/Alerting corrigés
- `ui/search.py` — Session scraper corrigée, lien Recherche→Cas fonctionnel
- `ui/cases.py` — Bouton "Activer ce cas" ajouté
- `alerting/dispatcher.py` — Import asyncio corrigé

### Configuration
- `collectors_registry.json` — Registre complet avec les 12 collecteurs
- `.env.example` — Variables d'environnement mises à jour

## Installation rapide

1. **Copier les fichiers** dans ton repo Venona (écraser les existants)
2. **Créer les dossiers manquants** :
   ```bash
   mkdir -p collectors/threat_intel collectors/breach_intel collectors/passive_feed
   ```
3. **Renommer** `.env.example` en `.env` et remplir tes clés API
4. **Relancer** l'application :
   ```bash
   streamlit run app.py
   ```

## Clés API recommandées (par ordre de priorité)

| Service | Coût | Utilité |
|---------|------|---------|
| AlienVault OTX | Gratuit | ⭐⭐⭐⭐⭐ Threat intelligence communautaire |
| MalwareBazaar | Gratuit | ⭐⭐⭐⭐⭐ Hashes de malware |
| RSS Feeds | Gratuit | ⭐⭐⭐⭐ Veille continue |
| GreyNoise | Gratuit tier | ⭐⭐⭐⭐ Filtrage du bruit de scan |
| URLScan.io | Gratuit tier | ⭐⭐⭐⭐ Analyse d'URLs suspectes |
| HIBP | ~3€/mois | ⭐⭐⭐⭐ Fuites de credentials |
| Shodan | Gratuit tier | ⭐⭐⭐ Exposition Internet |
| Censys | Gratuit tier | ⭐⭐⭐ Exposition Internet |
