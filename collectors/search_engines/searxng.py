import aiohttp
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.searxng")

class SearXNGCollector(BaseCollector):
    async def collect(self, query: str, session: aiohttp.ClientSession) -> list[SearchResult]:
        # Utilisation d'une instance publique fiable (configurable via .env plus tard)
        base_url = self.config.get("instance_url", "https://searx.be")
        url = f"{base_url}/search"
        params = {
            "q": query,
            "format": "json",
            "language": "fr-FR"
        }
        
        try:
            async with session.get(url, params=params, timeout=10) as response:
                if response.status != 200:
                    return []
                data = await response.json()
                
                results = []
                for item in data.get("results", []):
                    results.append(SearchResult(
                        title=item.get("title", "No Title"),
                        url=item.get("url", ""),
                        snippet=item.get("content", ""),
                        source="SearXNG"
                    ))
                return results
        except Exception as e:
            logger.error(f"Erreur SearXNG: {e}")
            return []
