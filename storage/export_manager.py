import json
import hashlib
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from stix2 import Indicator, Malware, Relationship, Bundle

class ExportManager:
    def __init__(self, db_path: str = "osint_searches.db"):
        self.db_path = db_path

    def export_stix21(self, iocs: list[dict], case_name: str) -> str:
        """Génère un bundle STIX 2.1 à partir des IOC."""
        stix_objects = []
        for ioc in iocs:
            # Exemple simplifié pour un domaine
            if ioc["type"] == "DOMAIN":
                indicator = Indicator(
                    pattern=f"[domain-name:value = '{ioc['value']}']",
                    pattern_type="stix",
                    labels=["malicious-activity"],
                    name=f"IOC: {ioc['value']}",
                    description=f"Extrait du cas: {case_name}"
                )
                stix_objects.append(indicator)
        
        bundle = Bundle(objects=stix_objects)
        filename = f"export_{case_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.json"
        with open(filename, "w") as f:
            f.write(bundle.serialize(pretty=True))
        return filename

    def export_pdf_report(self, case_data: dict, output_path: str):
        """Génère un rapport PDF synthétique du cas."""
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter
        
        # En-tête
        c.setFillColor(colors.darkred)
        c.setFont("Helvetica-Bold", 20)
        c.drawString(50, height - 50, f"RAPPORT D'INVESTIGATION OSINT")
        c.setFont("Helvetica", 12)
        c.setFillColor(colors.black)
        c.drawString(50, height - 80, f"Cas: {case_data.get('name')}")
        c.drawString(50, height - 100, f"Date: {datetime.now().strftime('%d/%m/%Y')}")
        c.drawString(50, height - 120, f"Hash d'intégrité (SHA-256): {case_data.get('integrity_hash', 'N/A')}")
        
        # Corps (Exemple simplifié)
        y_pos = height - 160
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y_pos, "1. Résumé Exécutif")
        c.setFont("Helvetica", 11)
        c.drawString(50, y_pos - 25, case_data.get('description', 'Aucune description fournie.'))
        
        c.save()
        return output_path