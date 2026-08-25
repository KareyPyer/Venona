#!/usr/bin/env python3
"""
init_db.py - Script d'initialisation et de migration de la base de données Dorker Pro v6.0

Usage:
    python init_db.py

Ce script est idempotent : il peut être exécuté plusieurs fois sans risque 
de supprimer les données existantes (utilise CREATE TABLE IF NOT EXISTS).
"""

import os
import sqlite3
import hashlib
import uuid
from datetime import datetime
from dotenv import load_dotenv

# Charger les variables d'environnement (pour OSINT_DB_PATH)
load_dotenv()

DB_PATH = os.getenv("OSINT_DB_PATH", "osint_searches.db")

def get_db_connection():
    """Établit une connexion SQLite avec les optimisations recommandées."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Optimisations pour la performance et la sécurité
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;") # Write-Ahead Logging pour meilleure concurrence
    return conn

def create_schema(conn):
    """Crée les tables et les index si ils n'existent pas déjà."""
    print(f"[*] Initialisation de la base de données : {os.path.abspath(DB_PATH)}")
    
    schema = """
    -- Table des cas d'enquête
    CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        target_scope TEXT,
        status TEXT DEFAULT 'OPEN',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        closed_at TIMESTAMP,
        investigator TEXT
    );

    -- Table des recherches (liées à un cas)
    CREATE TABLE IF NOT EXISTS searches (
        id TEXT PRIMARY KEY,
        case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
        query TEXT NOT NULL,
        collector_type TEXT,
        raw_results_hash TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Table centralisée des IOC (déduplication globale)
    CREATE TABLE IF NOT EXISTS iocs (
        id TEXT PRIMARY KEY,
        value TEXT UNIQUE NOT NULL,
        type TEXT NOT NULL,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP,
        threat_score REAL DEFAULT 0.0,
        enrichment_data TEXT
    );

    -- Table des fuites (Leaks)
    CREATE TABLE IF NOT EXISTS leaks (
        id TEXT PRIMARY KEY,
        ioc_id TEXT REFERENCES iocs(id) ON DELETE CASCADE,
        case_id TEXT REFERENCES cases(id) ON DELETE SET NULL,
        signature_type TEXT,
        snippet TEXT,
        source_url TEXT,
        severity TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Table des watchlists
    CREATE TABLE IF NOT EXISTS watchlists (
        id TEXT PRIMARY KEY,
        term TEXT UNIQUE NOT NULL,
        type TEXT,
        is_active BOOLEAN DEFAULT 1
    );

    -- Table des alertes
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        watchlist_id TEXT REFERENCES watchlists(id) ON DELETE CASCADE,
        leak_id TEXT REFERENCES leaks(id) ON DELETE SET NULL,
        status TEXT DEFAULT 'NEW',
        triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    
    indexes = """
    -- Index pour accélérer les requêtes fréquentes
    CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
    CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
    CREATE INDEX IF NOT EXISTS idx_leaks_case_id ON leaks(case_id);
    CREATE INDEX IF NOT EXISTS idx_leaks_severity ON leaks(severity);
    CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
    CREATE INDEX IF NOT EXISTS idx_searches_case_id ON searches(case_id);
    """

    try:
        conn.executescript(schema)
        conn.executescript(indexes)
        conn.commit()
        print("[+] Schéma de base de données et index créés avec succès.")
    except sqlite3.Error as e:
        print(f"[!] Erreur lors de la création du schéma : {e}")
        raise

def seed_default_data(conn):
    """Insère des données de démonstration si la base est vide."""
    cursor = conn.cursor()
    
    # Vérifier si des cas existent déjà
    cursor.execute("SELECT COUNT(*) FROM cases")
    if cursor.fetchone()[0] == 0:
        print("[*] Insertion des données de démonstration...")
        
        # 1. Cas de démo
        case_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO cases (id, name, description, target_scope, status, investigator)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            case_id,
            "Cas Démo : Veille de Marque",
            "Investigation initiale pour tester le pipeline OSINT et la corrélation d'entités.",
            "*.exemple-cible.com, admin@exemple-cible.com",
            "OPEN",
            "Investigator_01"
        ))
        
        # 2. IOC de démo
        ioc_id = hashlib.sha256("admin@exemple-cible.com".encode()).hexdigest()
        cursor.execute("""
            INSERT INTO iocs (id, value, type, threat_score, enrichment_data)
            VALUES (?, ?, ?, ?, ?)
        """, (
            ioc_id,
            "admin@exemple-cible.com",
            "EMAIL",
            0.65,
            '{"mx_valid": true, "hibp_breaches": 1}'
        ))
        
        # 3. Recherche liée au cas
        search_id = str(uuid.uuid4())
        dummy_results = "mock html result for admin@exemple-cible.com"
        results_hash = hashlib.sha256(dummy_results.encode('utf-8')).hexdigest()
        
        cursor.execute("""
            INSERT INTO searches (id, case_id, query, collector_type, raw_results_hash)
            VALUES (?, ?, ?, ?, ?)
        """, (search_id, case_id, "admin@exemple-cible.com", "duckduckgo_html", results_hash))
        
        # 4. Watchlist de démo
        cursor.execute("""
            INSERT OR IGNORE INTO watchlists (id, term, type, is_active)
            VALUES (?, ?, ?, ?)
        """, (str(uuid.uuid4()), "exemple-cible.com", "DOMAIN", 1))
        
        conn.commit()
        print("[+] Données de démonstration insérées.")
    else:
        print("[*] La base de données contient déjà des données. Aucune insertion de démo effectuée.")

def verify_integrity(conn):
    """Vérifie l'intégrité de la base de données."""
    cursor = conn.cursor()
    cursor.execute("PRAGMA integrity_check;")
    result = cursor.fetchone()[0]
    if result == "ok":
        print("[+] Vérification d'intégrité SQLite : OK")
    else:
        print(f"[!] Erreur d'intégrité détectée : {result}")

def main():
    print("="*60)
    print(" DORKER PRO v6.0 - Initialisation de la Base de Données")
    print(" Usage légal : Uniquement pour des investigations autorisées.")
    print("="*60)
    
    # S'assurer que le répertoire parent du fichier DB existe
    db_dir = os.path.dirname(os.path.abspath(DB_PATH))
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
        print(f"[+] Répertoire créé : {db_dir}")

    conn = get_db_connection()
    try:
        create_schema(conn)
        seed_default_data(conn)
        verify_integrity(conn)
        print("="*60)
        print("[SUCCESS] Initialisation terminée avec succès !")
        print(f"Vous pouvez maintenant lancer l'application : streamlit run app.py")
        print("="*60)
    except Exception as e:
        print(f"[FATAL] Échec de l'initialisation : {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()