import streamlit as st
import os
from dotenv import load_dotenv

load_dotenv()
DB_PATH = os.getenv("OSINT_DB_PATH", "osint_searches.db")

from ui.legal_banner import render_legal_banner
from ui.search import render_search_interface
from ui.cases import render_case_management
from ui.dashboard import render_dashboard

st.set_page_config(page_title="Dorker Pro v6.0", page_icon="🕵️‍♂️", layout="wide")

def check_db():
    import sqlite3
    if not os.path.exists(DB_PATH):
        st.error(f"DB introuvable. Lancez 'python init_db.py'.")
        st.stop()

def main():
    render_legal_banner()
    st.title("🕵️‍♂️ Dorker Pro — OSINT Command Center")
    
    with st.sidebar:
        st.header("Navigation")
        app_mode = st.selectbox("Module", [
            "Recherche OSINT", 
            "Centre de Commandement", 
            "Gestion des Cas", 
            "Configuration"
        ])
        
        st.divider()
        st.caption(f"DB: {os.path.basename(DB_PATH)}")

    if app_mode == "Recherche OSINT":
        render_search_interface()
    elif app_mode == "Centre de Commandement":
        render_dashboard(None)
    elif app_mode == "Gestion des Cas":
        render_case_management(None)
    elif app_mode == "Configuration":
        st.header("⚙️ Configuration")
        st.write("Éditez `collectors_registry.json` et `.env` pour configurer les sources.")

if __name__ == "__main__":
    check_db()
    main()
