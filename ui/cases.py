import streamlit as st

def render_case_management(db_manager):
    st.header("📁 Gestion des Cas d'Enquête")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.subheader("Nouveau Cas")
        case_name = st.text_input("Nom du cas")
        case_desc = st.text_area("Description")
        case_scope = st.text_input("Périmètre autorisé (Scope)")
        
        if st.button("Créer le cas"):
            if case_name and case_scope:
                st.success(f"Cas '{case_name}' créé avec succès.")
            else:
                st.error("Le nom et le périmètre sont obligatoires.")

    with col2:
        st.subheader("Cas Actifs")
        st.info("Liste des cas récupérés depuis la base de données.")
