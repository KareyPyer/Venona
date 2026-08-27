"""
Extracteur d'IOC v2 — Détection enrichie, validation contextuelle, filtrage intelligent.

Améliorations par rapport à v1 :
- Patterns enrichis : CVE, C2 configs, YARA rules, TLPs, numéros de téléphone, IBAN
- Validation des hashes par entropie de Shannon
- Filtrage des TLD suspects (.tk, .ml, etc.)
- Détection des IoCs dans les chemins d'URL
- Scoring contextuel par type d'IOC
"""

import re
import math
from typing import List, Dict, Set, Tuple
from core.models import IOC
from core.domain_whitelist import DomainWhitelist


class IOCExtractor:
    # Patterns Regex enrichis pour différents types d'IOC
    PATTERNS = {
        # Emails
        "EMAIL": r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',

        # IPv4
        "IPV4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',

        # Domaines
        "DOMAIN": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',

        # URLs complètes
        "URL": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[^\s<>\"']*)?",

        # Hashes
        "HASH_MD5": r'\b[a-fA-F0-9]{32}\b',
        "HASH_SHA1": r'\b[a-fA-F0-9]{40}\b',
        "HASH_SHA256": r'\b[a-fA-F0-9]{64}\b',

        # CVE
        "CVE": r'\bCVE-\d{4}-\d{4,}\b',

        # Numéros de téléphone (US format principalement)
        "PHONE": r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',

        # IBAN
        "IBAN": r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b',

        # Clés API AWS
        "AWS_KEY": r'AKIA[0-9A-Z]{16}',

        # Tokens GitHub
        "GITHUB_TOKEN": r'ghp_[a-zA-Z0-9]{36}',

        # Clés privées
        "PRIVATE_KEY": r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',

        # JWT tokens
        "JWT": r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',

        # Configs C2 (patterns typiques)
        "C2_CONFIG": r"\b(?:c2_host|callback_url|gate|beacon|payload_url)\s*[:=]\s*[\"']?[^\s\"']+",

        # Règles YARA
        "YARA_RULE": r'rule\s+\w+\s*\{',

        # Marqueurs TLP
        "TLP_MARKER": r'\bTLP:[A-Z]+\b',
    }

    # TLD souvent utilisés par les infrastructures malveillantes
    SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'click', 'link',
        'work', 'date', 'party', 'racing', 'win', 'download', 'men',
        'stream', 'trade', 'accountant', 'science', 'ninja', 'space'
    }

    # Hashes vides / connus (à exclure)
    EMPTY_HASHES = {
        'd41d8cd98f00b204e9800998ecf8427e',
        'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    }

    @staticmethod
    def _entropy(s: str) -> float:
        """Calcule l'entropie de Shannon d'une chaîne."""
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
        return -sum(p * math.log2(p) for p in prob)

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Vérifie si une IP est privée ou loopback."""
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        try:
            first, second = int(parts[0]), int(parts[1])
        except ValueError:
            return True
        if first == 10 or first == 127:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        return False

    @staticmethod
    def _is_suspicious_domain(domain: str) -> bool:
        """Vérifie si un domaine utilise un TLD suspect."""
        tld = domain.split('.')[-1].lower()
        return tld in IOCExtractor.SUSPICIOUS_TLDS

    @classmethod
    def _is_valid_hash(cls, value: str, hash_type: str) -> bool:
        """Valide un hash par entropie et exclusion des valeurs nulles."""
        value = value.lower()
        if value in cls.EMPTY_HASHES:
            return False
        entropy = cls._entropy(value)
        # Seuils d'entropie minimale pour éviter les faux positifs (ex: 0000...)
        if hash_type == "HASH_MD5" and entropy < 2.5:
            return False
        if hash_type == "HASH_SHA1" and entropy < 3.0:
            return False
        if hash_type == "HASH_SHA256" and entropy < 3.5:
            return False
        return True

    @staticmethod
    def extract(text: str, filter_legitimate: bool = True) -> Tuple[List[IOC], Dict]:
        """
        Extrait les IOC d'un texte avec validation avancée.

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
            'suspicious_domains': 0,
        }

        for ioc_type, pattern in IOCExtractor.PATTERNS.items():
            try:
                flags = re.IGNORECASE if ioc_type in ("CVE", "C2_CONFIG") else 0
                matches = re.findall(pattern, text, flags)
            except re.error:
                continue

            for match in matches:
                clean_match = match.strip().rstrip('.,;:')

                if len(clean_match) < 4 or len(clean_match) > 250:
                    continue
                if clean_match in seen:
                    continue

                # Validation spécifique par type
                if ioc_type == "IPV4" and IOCExtractor._is_private_ip(clean_match):
                    stats['filtered_false_positive'] += 1
                    continue

                if ioc_type.startswith("HASH_") and not IOCExtractor._is_valid_hash(clean_match, ioc_type):
                    stats['filtered_false_positive'] += 1
                    continue

                if ioc_type == "DOMAIN":
                    if filter_legitimate and DomainWhitelist.is_legitimate(clean_match):
                        stats['filtered_legitimate'] += 1
                        continue
                    if IOCExtractor._is_suspicious_domain(clean_match):
                        stats['suspicious_domains'] += 1

                seen.add(clean_match)
                stats['total_extracted'] += 1

                confidence_map = {
                    "HASH_MD5": 0.95, "HASH_SHA1": 0.95, "HASH_SHA256": 0.98,
                    "IPV4": 0.90, "EMAIL": 0.85, "DOMAIN": 0.80, "URL": 0.75,
                    "CVE": 0.99, "PHONE": 0.70, "IBAN": 0.85,
                    "AWS_KEY": 0.99, "GITHUB_TOKEN": 0.99, "PRIVATE_KEY": 0.99,
                    "JWT": 0.90, "C2_CONFIG": 0.85, "YARA_RULE": 0.95,
                    "TLP_MARKER": 0.99
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
        """
        all_iocs = {}
        stats = {
            'from_snippets': 0,
            'from_scraped_content': 0,
            'total_unique': 0,
            'filtered_legitimate': 0,
            'filtered_false_positive': 0,
        }

        snippet_text = " ".join(f"{r.title} {r.snippet}" for r in search_results)
        snippet_iocs, snippet_stats = IOCExtractor.extract(snippet_text, filter_legitimate=True)
        stats['from_snippets'] = len(snippet_iocs)
        stats['filtered_legitimate'] += snippet_stats['filtered_legitimate']
        stats['filtered_false_positive'] += snippet_stats['filtered_false_positive']

        for ioc in snippet_iocs:
            all_iocs[ioc.value] = ioc

        if scraped_contents:
            content_text = " ".join(c.get('text', '') for c in scraped_contents)
            content_iocs, content_stats = IOCExtractor.extract(content_text, filter_legitimate=True)
            stats['from_scraped_content'] = len(content_iocs)
            stats['filtered_legitimate'] += content_stats['filtered_legitimate']
            stats['filtered_false_positive'] += content_stats['filtered_false_positive']

            for ioc in content_iocs:
                all_iocs[ioc.value] = ioc

        stats['total_unique'] = len(all_iocs)
        return list(all_iocs.values()), stats
