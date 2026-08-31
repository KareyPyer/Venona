"""
Templates de requêtes OSINT optimisées par type d'investigation.

Ces templates génèrent des requêtes pré-construites pour maximiser
la découverte d'IOCs selon le contexte de l'investigation.
"""

from typing import List


class DorkTemplates:
    """Générateur de requêtes OSINT contextuelles."""

    TEMPLATES = {
        "malware_hash": [
            '{hash} malware OR "malicious" OR "threat"',
            '{hash} "indicator of compromise" OR "IOC"',
            'site:virustotal.com {hash}',
            'site:bazaar.abuse.ch {hash}',
            '{hash} "file analysis" OR "sample"',
        ],
        "c2_infrastructure": [
            '"{domain}" OR "{ip}" C2 OR "command and control"',
            '"{domain}" malware OR trojan OR backdoor',
            'site:urlscan.io "{domain}"',
            'site:otx.alienvault.com "{domain}"',
            '"{domain}" "certificate transparency" OR crt.sh',
        ],
        "breach_email": [
            '"{email}" breach OR leaked OR paste OR dump',
            'site:haveibeenpwned.com "{email}"',
            'site:pastebin.com "{email}"',
            '"{email}" password OR credential',
        ],
        "threat_actor": [
            '"{actor}" malware OR APT OR campaign OR "threat group"',
            '"{actor}" "threat intelligence" OR "cyber attack" OR TTP',
            '"{actor}" "indicators of compromise" OR IOC',
        ],
        "vulnerability": [
            '{cve} exploit OR poc OR "proof of concept"',
            '{cve} "in the wild" OR "active exploitation"',
            '{cve} patch OR mitigation OR advisory',
            'site:cve.mitre.org {cve}',
        ],
        "domain_recon": [
            'site:*.{domain} -site:{domain}',
            '"{domain}" filetype:pdf OR filetype:doc OR filetype:xls',
            '"{domain}" "admin" OR "login" OR "portal"',
            'site:github.com "{domain}"',
        ],
        "ip_recon": [
            '"{ip}" port scan OR "open port"',
            '"{ip}" vulnerability OR exploit',
            'site:shodan.io "{ip}"',
            'site:greynoise.io "{ip}"',
        ],
        "topic_recall": [
            # {topic}   : le thème en une expression, ex. "aerospace technology"
            # {keywords}: alternation pré-construite des synonymes, ex.
            #             '"aerospace technology" OR "aeronautics" OR "space propulsion"'
            '{keywords} filetype:pdf',
            'site:*.gov {topic} ("export control" OR "technical report" OR "whitepaper")',
            'site:*.mil {topic}',
            'intitle:"{topic}" filetype:pdf (thesis OR whitepaper OR "technical report")',
            '{keywords} site:arxiv.org',
            '"{topic}" (supplier OR manufacturer OR directory OR listing)',
        ],
        "exposed_vcs_global": [
            # Aucune variable requise — recherche générique de VCS exposés,
            # à router en priorité vers github_code et leakix.
            '+plugin:GitConfigHttpPlugin',
            '+plugin:DotGitOpenPlugin',
            'filename:.git-credentials',
            'filename:.netrc password',
            'extension:git-config "[remote \"origin\"]"',
            'intitle:"index of" "/.git"',
        ],
        "exposed_vcs_scoped": [
            # {target}: domaine, organisation GitHub ou nom d'hôte à cibler
            'site:{target} filename:.git-credentials',
            'site:{target} inurl:"/.git/config"',
            '+plugin:GitConfigHttpPlugin +host:{target}',
            'org:{target} filename:.env DB_PASSWORD',
            'intitle:"index of" "/svn/" {target}',
        ],
    }

    @classmethod
    def generate(cls, template_name: str, **kwargs) -> List[str]:
        """
        Génère une liste de requêtes à partir d'un template.

        Args:
            template_name: Nom du template (clé de TEMPLATES)
            **kwargs: Variables à substituer dans le template

        Returns:
            Liste de requêtes formatées
        """
        templates = cls.TEMPLATES.get(template_name, [])
        return [t.format(**kwargs) for t in templates]

    @classmethod
    def list_templates(cls) -> List[str]:
        """Retourne la liste des templates disponibles."""
        return list(cls.TEMPLATES.keys())

    @classmethod
    def get_description(cls, template_name: str) -> str:
        """Retourne une description du template."""
        descriptions = {
            "malware_hash": "Recherche d'informations sur un hash de fichier malveillant",
            "c2_infrastructure": "Cartographie d'une infrastructure de command & control",
            "breach_email": "Recherche de fuites de données pour un email",
            "threat_actor": "Investigation sur un acteur de menace (APT, groupe criminel)",
            "vulnerability": "Recherche d'informations sur une CVE",
            "domain_recon": "Reconnaissance passive d'un domaine",
            "ip_recon": "Reconnaissance passive d'une adresse IP",
            "topic_recall": "Collecte large d'URLs sur un thème (synonymes + filetype/site)",
            "exposed_vcs_global": "Recherche générique de dépôts/VCS exposés (.git, .svn, secrets)",
            "exposed_vcs_scoped": "Recherche de VCS exposés ciblée sur un domaine/organisation",
        }
        return descriptions.get(template_name, "Template OSINT générique")
