"""
Extracteur d'IOC avec filtrage intelligent des domaines légitimes.

Améliorations :
- Détection de plus de patterns (hashes, clés API, etc.)
- Filtrage automatique des domaines whitelistés (vendors, CERT, médias)
- Scoring contextuel basé sur la source
"""

import re
from typing import List, Dict, Set, Tuple
from core.models import IOC
from core.domain_whitelist import DomainWhitelist

class IOCExtractor:
    # Patterns Regex pour différents types d'IOC
    PATTERNS = {
        # Emails (avec nettoyage)
        "EMAIL": r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        
        # IPv4 (éviter les versions, numéros, etc.)
        "IPV4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        
        # Domaines (filtrés par la whitelist ensuite)
        "DOMAIN": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        
        # URLs complètes
        "URL": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[^\s<>"\']*)?',
        
        # Hashes MD5 (32 hex)
        "HASH_MD5": r'\b[a-fA-F0-9]{32}\b',
        
        # Hashes SHA-1 (40 hex)
        "HASH_SHA1": r'\b[a-fA-F0-9]{40}\b',
        
        # Hashes SHA-256 (64 hex)
        "HASH_SHA256": r'\b[a-fA-F0-9]{64}\b',
        
        # Clés API AWS
        "API_KEY_AWS": r'AKIA[0-9A-Z]{16}',
        
        # Tokens GitHub
        "TOKEN_GITHUB": r'ghp_[a-zA-Z0-9]{36}',
        
        # Clés privées (début typique)
        "PRIVATE_KEY": r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
        
        # JWT tokens
        "JWT": r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
    }
    
    # Patterns qui génèrent trop de faux positifs dans certains contextes
    FALSE_POSITIVE_PATTERNS = {
        "IPV4": [
            r'^0\.0\.0\.0$',
            r'^127\.0\.0\.1$',  # Loopback
            r'^255\.255\.255\.',  # Broadcast
            r'^192\.168\.',  # Réseau privé (souvent exemple)
            r'^10\.',  # Réseau privé
            r'^172\.(?:1[6-9]|2[0-9]|3[0-1])\.',  # Réseau privé
        ],
        "HASH_MD5": [
            r'^0+$',  # Hash nul
            r'^d41d8cd98f00b204e9800998ecf8427e$',  # MD5 de chaîne vide
        ]
    }
    
    # Hashes vides connus (à exclure)
    EMPTY_HASHES = {
        'd41d8cd98f00b204e9800998ecf8427e',  # MD5 empty
        'da39a3ee5e6b4b0d3255bfef95601890afd80709',  # SHA1 empty
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  # SHA256 empty
    }
    
    @staticmethod
    def _is_false_positive(value: str, ioc_type: str) -> bool:
        """Vérifie si un IOC est un faux positif connu."""
        # Hashes vides
        if ioc_type.startswith("HASH_") and value.lower() in IOCExtractor.EMPTY_HASHES:
            return True
        
        # Patterns de faux positifs
        patterns = IOCExtractor.FALSE_POSITIVE_PATTERNS.get(ioc_type, [])
        for pattern in patterns:
            if re.match(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def extract(text: str, filter_legitimate: bool = True) -> Tuple[List[IOC], Dict]:
        """
        Extrait les IOC d'un texte.
        
        Args:
            text: Texte à analyser
            filter_legitimate: Si True, filtre les domaines whitelistés
        
        Returns:
            Tuple (liste d'IOC, statistiques)
        """
        found_iocs = []
        seen = set()
        stats = {
            'total_extracted': 0,
            'filtered_legitimate': 0,
            'filtered_false_positive': 0,
        }
        
        for ioc_type, pattern in IOCExtractor.PATTERNS.items():
            try:
                matches = re.findall(pattern, text)
            except re.error:
                continue
            
            for match in matches:
                clean_match = match.strip().rstrip('.,;:')
                
                # Ignorer les trop courts ou trop longs
                if len(clean_match) < 4 or len(clean_match) > 250:
                    continue
                
                # Éviter les doublons
                if clean_match in seen:
                    continue
                
                # Filtrer les faux positifs
                if IOCExtractor._is_false_positive(clean_match, ioc_type):
                    stats['filtered_false_positive'] += 1
                    continue
                
                # Filtrer les domaines légitimes
                if filter_legitimate and ioc_type == "DOMAIN":
                    if DomainWhitelist.is_legitimate(clean_match):
                        stats['filtered_legitimate'] += 1
                        continue
                
                seen.add(clean_match)
                stats['total_extracted'] += 1
                
                # Confiance basée sur le type
                confidence_map = {
                    "HASH_MD5": 0.95,
                    "HASH_SHA1": 0.95,
                    "HASH_SHA256": 0.98,
                    "IPV4": 0.85,
                    "EMAIL": 0.80,
                    "DOMAIN": 0.75,
                    "URL": 0.70,
                    "API_KEY_AWS": 0.99,
                    "TOKEN_GITHUB": 0.99,
                    "PRIVATE_KEY": 0.99,
                    "JWT": 0.90,
                }
                
                found_iocs.append(IOC(
                    value=clean_match,
                    type=ioc_type,
                    confidence=confidence_map.get(ioc_type, 0.7)
                ))
        
        return found_iocs, stats
    
    @staticmethod
    def extract_from_results(search_results: list, scraped_contents: list = None) -> Tuple[List[IOC], Dict]:
        """
        Extrait les IOC depuis les résultats de recherche ET les contenus scrapés.
        
        Combine intelligemment les deux sources pour maximiser la détection.
        """
        all_iocs = {}  # Dict pour dédupliquer par valeur
        stats = {
            'from_snippets': 0,
            'from_scraped_content': 0,
            'total_unique': 0,
            'filtered_legitimate': 0,
            'filtered_false_positive': 0,
        }
        
        # 1. Extraction depuis les snippets (titres + snippets des résultats)
        snippet_text = " ".join([
            f"{r.title} {r.snippet}" 
            for r in search_results
        ])
        snippet_iocs, snippet_stats = IOCExtractor.extract(snippet_text, filter_legitimate=True)
        stats['from_snippets'] = len(snippet_iocs)
        stats['filtered_legitimate'] += snippet_stats['filtered_legitimate']
        stats['filtered_false_positive'] += snippet_stats['filtered_false_positive']
        
        for ioc in snippet_iocs:
            all_iocs[ioc.value] = ioc
        
        # 2. Extraction depuis les contenus scrapés (texte complet des pages)
        if scraped_contents:
            content_text = " ".join([c.get('text', '') for c in scraped_contents])
            content_iocs, content_stats = IOCExtractor.extract(content_text, filter_legitimate=True)
            stats['from_scraped_content'] = len(content_iocs)
            stats['filtered_legitimate'] += content_stats['filtered_legitimate']
            stats['filtered_false_positive'] += content_stats['filtered_false_positive']
            
            for ioc in content_iocs:
                all_iocs[ioc.value] = ioc
        
        stats['total_unique'] = len(all_iocs)
        return list(all_iocs.values()), stats
