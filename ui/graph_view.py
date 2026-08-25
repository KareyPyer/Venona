import streamlit as st

def render_entity_graph(db_manager, case_id=None):
    st.header("🕸️ Graphe de Corrélation d'Entités")
    st.info("Le graphe interactif (NetworkX/PyVis) sera généré ici une fois les données d'enrichissement disponibles.")
