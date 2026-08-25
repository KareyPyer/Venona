import streamlit as st

def render_watchlists(db_manager):
    st.header("📡 Watchlists & Alertes")
    
    col1, col2 = st.columns([1, 2])
    with col1:
        st.subheader("Ajouter une cible")
        term = st.text_input("Terme à surveiller")
        w_type = st.selectbox("Type", ["EMAIL", "DOMAIN", "KEYWORD"])
        if st.button("Ajouter"):
            st.success(f"{term} ajouté.")
            
    with col2:
        st.subheader("Historique des alertes")
        st.dataframe({"Status": ["NEW"], "Term": ["admin@target.com"], "Severity": ["HIGH"]})
