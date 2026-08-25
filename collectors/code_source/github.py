import aiohttp
import os
from collectors.base import BaseCollector
from core.models import SearchResult

class GitHubCollector(BaseCollector):
    async def collect(self, query: str, session: aiohttp.ClientSession) -> list[SearchResult]:
        token = os.getenv("GITHUB_TOKEN")
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"} if token else {}
        url = f"https://api.github.com/search/code?q={query}&per_page=10"
        
        await self._respect_rate_limit() # Utilise le RateLimiter de base.py
        
        try:
            async with session.get(url, headers=headers) as response:
                if response.status == 403:
                    raise Exception("Quota API GitHub dépassé ou token manquant.")
                response.raise_for_status()
                data = await response.json()
                
                results = []
                for item in data.get("items", []):
                    results.append(SearchResult(
                        title=item.get("name"),
                        url=item.get("html_url"),
                        snippet=f"Repo: {item.get('repository', {}).get('full_name')}",
                        source="GitHub API"
                    ))
                return results
        except Exception as e:
            print(f"[GitHub Collector Error] {e}")
            return []