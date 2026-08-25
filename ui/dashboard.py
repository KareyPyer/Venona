import streamlit as st

def render_dashboard(db_manager):
    st.header("📊 Centre de Commandement")
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Cas Ouverts", "3", "+1")
    col2.metric("IOC Trouvés", "142", "+12")
    col3.metric("Fuites Critiques", "4", "-1")
    col4.metric("Alertes Nouvelles", "7", "+3")
    
    st.divider()
    st.subheader("Dernières Découvertes")
    st.write("Timeline des événements récents...")
