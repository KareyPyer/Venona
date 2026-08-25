# collectors/base.py
import abc
from typing import List, Dict, Any
from core.models import SearchResult

class BaseCollector(abc.ABC):
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = config.get("name", "Unknown")
        self.rate_limit = config.get("rate_limit", {})

    @abc.abstractmethod
    async def collect(self, query: str, session: Any) -> List[SearchResult]:
        """Méthode asynchrone à implémenter par chaque collecteur."""
        pass

    async def _respect_rate_limit(self):
        """Implémenter un backoff exponentiel ou un délai basé sur self.rate_limit."""
        import asyncio
        delay = 60.0 / self.rate_limit.get("requests_per_minute", 60)
        await asyncio.sleep(delay)