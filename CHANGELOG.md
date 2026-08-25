# Changelog - Dorker Pro OSINT Edition

## [6.0.0] - 2026-08-24
### Added
- **Architecture Modulaire** : Refactorisation complète du monolithe en modules `core`, `collectors`, `enrichment`, `storage`, `ui`.
- **Collecteurs Pluggables** : Système piloté par `collectors_registry.json`. Ajout de sources sans modifier le code source.
- **Case Management** : Gestion complète des dossiers d'enquête avec traçabilité (Chain of Custody via hash SHA-256 des résultats bruts).
- **Schéma DB Étendu** : Support natif des tables `cases`, `iocs` (déduplication globale), `leaks`, `watchlists`, `alerts`.
- **Avertissement Légal Renforcé** : Bannière obligatoire avec traçabilité de l'acceptation pour chaque session.

### Changed
- Le scoring des fuites est désormais basé sur un modèle pondéré (Sévérité × Confiance × Fraîcheur).
- Les clés API doivent être préférablement passées via `.env` pour supporter l'exécution headless (cron).

### Security / OPSEC
- Ajout du support natif des variables d'environnement pour les proxies (`HTTP_PROXY`).
- Implémentation d'un rate limiter avec backoff exponentiel dans `BaseCollector`.