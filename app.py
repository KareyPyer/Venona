import streamlit as st
import asyncio
import os
from dotenv import load_dotenv

# Chargement des variables d'environnement
load_dotenv()
DB_PATH = os.getenv("OSINT_DB_PATH", "osint_searches.db")

# Importation des modules UI
from ui.legal_banner import render_legal_banner
from ui.cases import render_case_management
from ui.dashboard import render_dashboard
from ui.graph_view import render_entity_graph
from ui.watchlists import render_watchlists

# Configuration de la page
st.set_page_config(page_title="Dorker Pro v6.0", page_icon="🕵️‍♂️", layout="wide")

def check_db_connection():
    """Vérifie simplement que la DB est accessible."""
    import sqlite3
    if not os.path.exists(DB_PATH):
        st.error(f"Base de données introuvable à {DB_PATH}. Veuillez exécuter 'python init_db.py' d'abord.")
        st.stop()
    
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA integrity_check;")
        conn.close()
    except Exception as e:
        st.error(f"Erreur de connexion à la base de données : {e}")
        st.stop()

def main():
    # 1. Avertissement Légal Obligatoire
    render_legal_banner()

    st.title("🕵️‍♂️ Dorker Pro — OSINT Command Center v6.0")
    
    # 2. Sidebar pour la navigation
    with st.sidebar:
        st.header("Navigation")
        app_mode = st.selectbox(
            "Choisir un module",
            [
                "Centre de Commandement", 
                "Gestion des Cas", 
                "Recherche OSINT", 
                "Graphe d'Entités", 
                "Watchlists & Alertes", 
                "Configuration"
            ]
        )
        
        st.divider()
        st.subheader("Cas Actif")
        active_case = st.selectbox("Sélectionner un cas", ["Nouveau Cas...", "Cas Démo : Veille de Marque"])

    # 3. Routage vers les modules UI
    if app_mode == "Centre de Commandement":
        render_dashboard(None) # Passer le db_manager en production
    elif app_mode == "Gestion des Cas":
        render_case_management(None)
    elif app_mode == "Recherche OSINT":
        st.header("Nouvelle Investigation")
        query = st.text_input("Entrez votre requête (Dork, Email, Domaine, IP)")
        if st.button("Lancer la collecte"):
            if active_case == "Nouveau Cas...":
                st.warning("Veuillez d'abord sélectionner un cas.")
            else:
                st.info(f"Lancement de la collecte pour '{query}' sur le cas '{active_case}'...")
                # TODO: Intégrer l'appel au CollectorManager ici
    elif app_mode == "Graphe d'Entités":
        render_entity_graph(None, case_id="demo")
    elif app_mode == "Watchlists & Alertes":
        render_watchlists(None)
    elif app_mode == "Configuration":
        st.header("⚙️ Configuration")
        st.write("Gestion des clés API via `.env` et activation des collecteurs via `collectors_registry.json`.")
        st.code(f"DB_PATH actuel : {DB_PATH}", language="bash")

if __name__ == "__main__":
    check_db_connection()
    main()
