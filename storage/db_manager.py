import aiosqlite
import os
import hashlib
from datetime import datetime
from typing import Optional, List, Dict, Any

DB_PATH = os.getenv("OSINT_DB_PATH", "osint_searches.db")

class DatabaseManager:
    def __init__(self):
        self.db_path = DB_PATH

    async def init_db(self):
        """Initialisation idempotente de la base avec le schéma étendu."""
        async with aiosqlite.connect(self.db_path) as db:
            # Lecture du schéma SQL (à externaliser dans un fichier schema.sql en prod)
            schema = """
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT,
                target_scope TEXT, status TEXT DEFAULT 'OPEN',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS searches (
                id TEXT PRIMARY KEY, case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
                query TEXT NOT NULL, collector_type TEXT, raw_results_hash TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS iocs (
                id TEXT PRIMARY KEY, value TEXT UNIQUE NOT NULL, type TEXT NOT NULL,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_seen TIMESTAMP,
                threat_score REAL DEFAULT 0.0, enrichment_data TEXT
            );
            CREATE TABLE IF NOT EXISTS leaks (
                id TEXT PRIMARY KEY, ioc_id TEXT REFERENCES iocs(id), case_id TEXT REFERENCES cases(id),
                signature_type TEXT, snippet TEXT, source_url TEXT, severity TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS watchlists (
                id TEXT PRIMARY KEY, term TEXT UNIQUE NOT NULL, type TEXT, is_active BOOLEAN DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY, watchlist_id TEXT REFERENCES watchlists(id),
                leak_id TEXT REFERENCES leaks(id), status TEXT DEFAULT 'NEW',
                triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
            await db.executescript(schema)
            await db.commit()

    async def create_case(self, name: str, description: str, target_scope: str) -> str:
        import uuid
        case_id = str(uuid.uuid4())
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO cases (id, name, description, target_scope) VALUES (?, ?, ?, ?)",
                (case_id, name, description, target_scope)
            )
            await db.commit()
        return case_id

    async def log_search(self, case_id: str, query: str, collector_type: str, raw_results: str) -> str:
        import uuid
        search_id = str(uuid.uuid4())
        # Chain of custody : hash SHA-256 des résultats bruts
        results_hash = hashlib.sha256(raw_results.encode('utf-8')).hexdigest()
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO searches (id, case_id, query, collector_type, raw_results_hash) VALUES (?, ?, ?, ?, ?)",
                (search_id, case_id, query, collector_type, results_hash)
            )
            await db.commit()
        return search_id

# Instance globale pour Streamlit (à gérer avec st.cache_resource en pratique)
db = DatabaseManager()