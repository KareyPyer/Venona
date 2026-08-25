import streamlit as st
import asyncio # <-- AJOUT CRUCIAL
import aiohttp
import json
import hashlib
from datetime import datetime

from collectors.manager import CollectorManager
from core.ioc_extractor import IOCExtractor
from core.scoring import calculate_osint_score
from storage.db_manager import DatabaseManager

async def run_osint_pipeline(query: str, selected_collectors: list, case_id: str):
    """Fonction asynchrone orchestrant la collecte, l'extraction et le stockage."""
    manager = CollectorManager()
    db = DatabaseManager()
    
    results = []
    iocs = []
    
    # 1. Collecte
    async with aiohttp.ClientSession() as session:
        results = await manager.run_all(query, session, selected_ids=selected_collectors)
    
    # 2. Extraction IOC
    raw_text = " ".join([f"{r.title} {r.snippet} {r.url}" for r in results])
    iocs = IOCExtractor.extract(raw_text)
    
    # 3. Scoring
    score = calculate_osint_score(iocs)
    
    # 4. Stockage DB (Chain of Custody)
    raw_json = json.dumps([r.dict() for r in results], default=str)
    search_id = await db.log_search(
        case_id=case_id, 
        query=query, 
        collector_type=",".join(selected_collectors), 
        raw_results=raw_json
    )
    
    return results, iocs, score, search_id

def render_search_interface():
    st.header("🔍 Recherche OSINT Multi-Sources")
    
    # Configuration de la recherche
    col1, col2 = st.columns([3, 1])
    with col1:
        query = st.text_input("Requête (Dork, Email, Domaine, IP...)", placeholder="ex: @target.com OR site:pastebin.com target")
    with col2:
        # Sélection dynamique des collecteurs disponibles
        manager = CollectorManager()
        available_collectors = list(manager.collectors.keys())
        selected_collectors = st.multiselect(
            "Moteurs actifs", 
            options=available_collectors, 
            default=available_collectors
        )

    # Simulation du Cas Actif
    case_id = "demo-case-id" 
    
    if st.button("🚀 Lancer l'Investigation", type="primary", use_container_width=True):
        if not query:
            st.warning("Veuillez entrer une requête.")
        elif not selected_collectors:
            st.warning("Veuillez sélectionner au moins un collecteur.")
        else:
            with st.spinner("Investigation en cours (Collecte -> Analyse -> Stockage)..."):
                try:
                    # Lancement de la boucle async
                    results, iocs, score, search_id = asyncio.run(
                        run_osint_pipeline(query, selected_collectors, case_id)
                    )
                    
                    st.success(f"✅ Investigation terminée. Score de menace: **{score}** | ID Recherche: `{search_id[:8]}...`")
                    
                    # Affichage des résultats
                    tab1, tab2, tab3 = st.tabs(["📄 Résultats Bruts", "🎯 IOC Extraits", "📊 Analyse"])
                    
                    with tab1:
                        if not results:
                            st.info("Aucun résultat trouvé pour cette requête.")
                        for r in results:
                            st.markdown(f"**[{r.source}] {r.title}**")
                            st.caption(r.url)
                            st.write(r.snippet)
                            st.divider()
                            
                    with tab2:
                        if iocs:
                            st.dataframe([{
                                "Type": i.type, 
                                "Value": i.value, 
                                "Confiance": f"{i.confidence*100:.0f}%"
                            } for i in iocs])
                        else:
                            st.info("Aucun IOC technique extrait.")
                            
                    with tab3:
                        st.metric("Score OSINT", score)
                        st.write(f"**Résumé** : {len(results)} résultats trouvés via {len(selected_collectors)} sources. {len(iocs)} indicateurs techniques extraits.")
                        
                except Exception as e:
                    st.error(f"Erreur lors de l'investigation : {e}")
                    import traceback
                    st.code(traceback.format_exc(), language="text")
