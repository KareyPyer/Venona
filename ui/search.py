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
from core.dork_translator import DorkTranslator
from core.query_sanitizer import QuerySanitizer

async def run_osint_pipeline(
    query: str, 
    selected_collectors: list, 
    case_id: str, 
    enrich: bool = False,
    translated_queries: dict = None
):
    """Pipeline complet avec requêtes traduites par moteur."""
    manager = CollectorManager()
    db = DatabaseManager()
    
    # 1. Collecte avec requêtes traduites
    async with aiohttp.ClientSession() as session:
        results = await manager.run_all(
            query, 
            session, 
            selected_ids=selected_collectors,
            use_translated_queries=translated_queries
        )
    
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
    
    for ioc in iocs:
        await db.save_ioc(ioc, ioc.enrichment)
    
    return results, iocs, score, search_id

def render_search_interface():
    st.header("🔍 Recherche OSINT Multi-Sources")
    
    # === Zone de requête ===
    col1, col2 = st.columns([3, 1])
    with col1:
        query = st.text_input(
            "Requête (Google Dorks supportés)", 
            placeholder='ex: "EU DisinfoLab" OR "EUvsDisinfo" site:*.com OR site:*.ru',
            help="Utilisez la syntaxe Google Dorks. Les requêtes seront automatiquement adaptées à chaque moteur."
        )
    with col2:
        manager = CollectorManager()
        available_collectors = list(manager.collectors.keys())
        selected_collectors = st.multiselect(
            "Moteurs actifs", 
            options=available_collectors, 
            default=available_collectors[:2] if len(available_collectors) >= 2 else available_collectors
        )
    
    # === Recommandation de moteurs ===
    if query:
        is_complex = QuerySanitizer.is_complex_query(query)
        
        if is_complex:
            st.warning(
                "⚠️ **Requête complexe détectée** (parenthèses, OR/AND, site:, etc.)\n\n"
                "**Recommandation** : Utilisez uniquement **SearXNG** pour de meilleurs résultats.\n"
                "DuckDuckGo ne supporte pas ces opérateurs et retournera peu ou pas de résultats."
            )
            
            # Suggestion automatique
            if "duckduckgo_html" in selected_collectors and len(selected_collectors) > 1:
                if st.button("🎯 Utiliser uniquement SearXNG (recommandé)", type="secondary"):
                    selected_collectors = ["searxng_public"]
                    st.rerun()
    
    # === Affichage des traductions en temps réel ===
    if query and selected_collectors:
        with st.expander("🔧 Aperçu des requêtes traduites par moteur", expanded=False):
            st.caption("Dorker Pro adapte automatiquement votre requête à la syntaxe de chaque moteur.")
            
            translations = DorkTranslator.translate_for_multiple_engines(query, selected_collectors)
            
            for engine_id, translation in translations.items():
                st.markdown(f"**{engine_id}**")
                
                col_orig, col_trans = st.columns(2)
                with col_orig:
                    st.code(translation.original, language="text")
                    st.caption("Requête originale")
                with col_trans:
                    st.code(translation.translated, language="text")
                    st.caption("Requête traduite/nettoyée")
                
                if translation.was_sanitized:
                    st.info(f"🧹 Requête nettoyée pour {engine_id}")
                
                if translation.warnings:
                    for warning in translation.warnings:
                        st.warning(warning)
                
                if translation.lost_operators:
                    st.info(f"Opérateurs retirés : {', '.join(translation.lost_operators)}")
                
                st.divider()
    
    # === Options avancées ===
    with st.expander("⚙️ Options avancées", expanded=False):
        enrich = st.checkbox(
            "🔬 Activer l'enrichissement automatique (VT, AbuseIPDB, WHOIS)", 
            value=False,
            help="Consomme des quotas API. À utiliser uniquement pour les investigations ciblées."
        )
        
        st.markdown("#### 💡 Syntaxe supportée par moteur")
        
        if selected_collectors:
            cols = st.columns(len(selected_collectors))
            for idx, engine_id in enumerate(selected_collectors):
                with cols[idx]:
                    st.markdown(f"**{engine_id}**")
                    syntax = DorkTranslator.suggest_syntax(engine_id)
                    st.code(syntax, language="text")
    
    # === Bouton de lancement ===
    case_id = st.session_state.get('active_case_id', 'demo-case-id')
    
    if st.button("🚀 Lancer l'Investigation", type="primary", use_container_width=True):
        if not query:
            st.warning("Entrez une requête.")
        elif not selected_collectors:
            st.warning("Sélectionnez au moins un collecteur.")
        else:
            # Pré-calcul des traductions
            translations = DorkTranslator.translate_for_multiple_engines(query, selected_collectors)
            translated_queries = {
                engine_id: translation.translated
                for engine_id, translation in translations.items()
            }
            
            # Affichage des avertissements globaux
            all_warnings = []
            for translation in translations.values():
                all_warnings.extend(translation.warnings)
            
            if all_warnings:
                with st.expander("⚠️ Avertissements sur la traduction des requêtes", expanded=True):
                    for warning in set(all_warnings):
                        st.warning(warning)
            
            with st.spinner("Investigation en cours..."):
                try:
                    results, iocs, score, search_id = asyncio.run(
                        run_osint_pipeline(
                            query, 
                            selected_collectors, 
                            case_id, 
                            enrich,
                            translated_queries
                        )
                    )
                    
                    st.success(f"✅ Terminé. Score: **{score}** | IOC: {len(iocs)} | ID: `{search_id[:8]}...`")
                    
                    tab1, tab2, tab3, tab4 = st.tabs(["📄 Résultats", "🎯 IOC", "📊 Analyse", "🔧 Détails techniques"])
                    
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
                        
                        # Statistiques par source
                        source_counts = {}
                        for r in results:
                            source_counts[r.source] = source_counts.get(r.source, 0) + 1
                        
                        if source_counts:
                            st.markdown("**Résultats par source :**")
                            cols = st.columns(len(source_counts))
                            for idx, (source, count) in enumerate(source_counts.items()):
                                cols[idx].metric(source, count)
                    
                    with tab4:
                        st.markdown("#### Requêtes effectivement envoyées")
                        for engine_id, translated in translated_queries.items():
                            st.markdown(f"**{engine_id}**")
                            st.code(translated, language="text")
                        
                except Exception as e:
                    st.error(f"Erreur : {e}")
                    import traceback
                    st.code(traceback.format_exc())
