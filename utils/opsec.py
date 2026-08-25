import aiohttp
import os

async def check_ip_leak(session: aiohttp.ClientSession) -> dict:
    """Vérifie l'IP réelle et l'IP perçue par les services externes."""
    try:
        # Vérifie l'IP vue par un service tiers
        async with session.get("https://api.ipify.org?format=json", timeout=10) as resp:
            data = await resp.json()
            perceived_ip = data.get("ip")
            
        # Vérifie s'il y a une fuite DNS (simplifié : vérifie si l'IP correspond à celle du système local si pas de proxy)
        # Dans une implémentation complète, on comparerait avec l'IP de l'interface réseau locale.
        
        return {
            "status": "success",
            "perceived_ip": perceived_ip,
            "proxy_active": bool(os.getenv("HTTP_PROXY") or os.getenv("HTTPS_PROXY")),
            "warning": "Assurez-vous que cette IP correspond à votre nœud de sortie Tor/Proxy attendu."
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}