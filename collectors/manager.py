# collectors/manager.py
import importlib
import json
import os
from typing import List, Dict, Any
from collectors.base import BaseCollector
from core.models import SearchResult

class CollectorManager:
    def __init__(self, registry_path: str = "collectors_registry.json"):
        self.registry_path = registry_path
        self.collectors: Dict[str, BaseCollector] = {}
        self._load_collectors()

    def _load_collectors(self):
        with open(self.registry_path, 'r', encoding='utf-8') as f:
            registry = json.load(f)
        
        for col_config in registry.get("collectors", []):
            if not col_config.get("enabled"):
                continue
            
            # Vérification des clés API via .env
            if col_config.get("requires_api_key"):
                env_var = col_config.get("env_var")
                if not os.getenv(env_var):
                    print(f"[WARN] Collecteur {col_config['name']} désactivé : {env_var} manquante.")
                    continue

            # Chargement dynamique du module
            try:
                module = importlib.import_module(col_config["module"])
                collector_class = getattr(module, col_config["class"])
                self.collectors[col_config["id"]] = collector_class(col_config)
            except Exception as e:
                print(f"[ERROR] Échec du chargement du collecteur {col_config['id']}: {e}")

    async def run_all(self, query: str, session: Any) -> List[SearchResult]:
        import asyncio
        tasks = []
        for col_id, collector in self.collectors.items():
            tasks.append(self._safe_collect(collector, query, session))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aplatissement et filtrage des exceptions
        final_results = []
        for res in results:
            if isinstance(res, list):
                final_results.extend(res)
            elif isinstance(res, Exception):
                print(f"[ERROR] Erreur dans un collecteur: {res}")
        return final_results

    async def _safe_collect(self, collector: BaseCollector, query: str, session: Any) -> List[SearchResult]:
        await collector._respect_rate_limit()
        return await collector.collect(query, session)