def calculate_osint_score(iocs: list, leaks_count: int = 0) -> float:
    """Calcule un score de menace basé sur les IOC trouvés."""
    score = 0.0
    
    # Pondération par type
    weights = {
        "EMAIL": 1.0,
        "IPV4": 1.5,
        "DOMAIN": 1.2,
        "URL": 0.8,
        "HASH_MD5": 3.0,
        "HASH_SHA256": 3.0
    }
    
    for ioc in iocs:
        score += weights.get(ioc.type, 0.5)
        
    # Bonus fuites
    score += leaks_count * 5.0
    
    return round(score, 2)
