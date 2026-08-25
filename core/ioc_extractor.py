import re
from typing import List, Dict, Set
from core.models import IOC

class IOCExtractor:
    # Patterns Regex simplifiés mais efficaces
    PATTERNS = {
        "EMAIL": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
        "IPV4": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        "DOMAIN": r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b',
        "URL": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[^\s]*)?',
        "HASH_MD5": r'\b[a-fA-F0-9]{32}\b',
        "HASH_SHA256": r'\b[a-fA-F0-9]{64}\b'
    }

    @staticmethod
    def extract(text: str) -> List[IOC]:
        found_iocs = []
        seen = set()
        
        for ioc_type, pattern in IOCExtractor.PATTERNS.items():
            matches = re.findall(pattern, text)
            for match in matches:
                # Nettoyage basique
                clean_match = match.strip().rstrip('.')
                if clean_match not in seen:
                    seen.add(clean_match)
                    found_iocs.append(IOC(value=clean_match, type=ioc_type))
        return found_iocs
