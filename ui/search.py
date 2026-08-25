import streamlit as st
import asyncio
import aiohttp
import json
import os
from datetime import datetime

from collectors.manager import CollectorManager
from core.ioc_extractor import IOCExtractor
from core.scoring import calculate_osint_score
from storage.db_manager import DatabaseManager
from enrichment.orchestrator import EnrichmentOrchestrator

async def run_osint_pipeline(query: str, selected_collectors: list, case_id: str, enrich: bool = False):
    """Pipeline complet : Collecte -> Extraction -> Enrichissement -> Stockage."""
    manager = CollectorManager()
    db = DatabaseManager()
    
    # 1. Collecte
    async with aiohttp.ClientSession() as session:
        results = await manager.run_all(query, session, selected_ids=selected_collectors)
    
    # 2. Extraction IOC
    raw_text = " ".join([f"{r.title} {r.snippet} {r.url}" for r in results])
    iocs = IOCExtractor.extract(raw_text)
    
    # 3. Enrichissement (optionnel)
    if enrich and iocs:
        orchestrator = EnrichmentOrchestrator()
        api_keys = {
            "VIRUSTOTAL": os.getenv("VIRUSTOTAL_API_KEY"),
            "ABUSEIPDB": os.getenv("ABUSEIPDB_API_KEY")
        }
        
        with st.spinner(f"Enrichissement de {len(iocs)} IOC..."):
            for ioc in iocs:
                enrichment_result = await orchestrator.enrich(ioc.value, ioc.type, api_keys)
                ioc.enrichment = enrichment_result.get("data", {})
    
    # 4. Scoring
    score = calculate_osint_score(iocs)
    
    # 5. Stockage
    raw_json = json.dumps([r.model_dump() for r in results], default=str)
    search_id = await db.log_search(case_id, query, ",".join(selected_collectors), raw_json)
    
    # Sauvegarde des IOC
    for ioc in iocs:
        await db.save_ioc(ioc, ioc.enrichment)
    
    return results, iocs, score, search_id

def render_search_interface():
    st.header("🔍 Recherche OSINT Multi-Sources")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        query = st.text_input("Requête", placeholder="ex: @target.com OR site:pastebin.com target")
    with col2:
        manager = CollectorManager()
        available_collectors = list(manager.collectors.keys())
        selected_collectors = st.multiselect("Moteurs", options=available_collectors, default=available_collectors[:2])
    
    enrich = st.checkbox("🔬 Activer l'enrichissement automatique (VT, AbuseIPDB, WHOIS)", value=False)
    
    case_id = st.session_state.get('active_case_id', 'demo-case-id')
    
    if st.button("🚀 Lancer l'Investigation", type="primary", use_container_width=True):
        if not query:
            st.warning("Entrez une requête.")
        elif not selected_collectors:
            st.warning("Sélectionnez au moins un collecteur.")
        else:
            with st.spinner("Investigation en cours..."):
                try:
                    results, iocs, score, search_id = asyncio.run(
                        run_osint_pipeline(query, selected_collectors, case_id, enrich)
                    )
                    
                    st.success(f"✅ Terminé. Score: **{score}** | IOC: {len(iocs)} | ID: `{search_id[:8]}...`")
                    
                    tab1, tab2, tab3 = st.tabs(["📄 Résultats", "🎯 IOC", "📊 Analyse"])
                    
                    with tab1:
                        if not results:
                            st.info("Aucun résultat.")
                        for r in results[:20]:
                            st.markdown(f"**[{r.source}] {r.title}**")
                            st.caption(r.url)
                            st.write(r.snippet)
                            st.divider()
                    
                    with tab2:
                        if iocs:
                            st.dataframe([{
                                "Type": i.type,
                                "Value": i.value,
                                "Confiance": f"{i.confidence*100:.0f}%",
                                "Enrichi": "✅" if i.enrichment else "❌"
                            } for i in iocs])
                        else:
                            st.info("Aucun IOC extrait.")
                    
                    with tab3:
                        st.metric("Score OSINT", score)
                        st.write(f"**Résumé** : {len(results)} résultats, {len(iocs)} IOC.")
                        
                except Exception as e:
                    st.error(f"Erreur : {e}")
                    import traceback
                    st.code(traceback.format_exc())
