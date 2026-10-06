import sqlite3
from pathlib import Path


DB_DIR = Path("database")
DB_PATH = DB_DIR / "securewatch.db"

def create_database():
    DB_DIR.mkdir(exist_ok=True)

    Connection = sqlite3.connect(DB_PATH)
    Cursor = Connection.cursor()

    Cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE NOT NULL,
            file_hash TEXT NOT NULL,
            last_checked TEXT NOT NULL
        )
    """)
    Cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            file_path TEXT NOT NULL,
            old_hash TEXT,
            new_hash TEXT,
            created_at TEXT NOT NULL
        )
    """)
    Connection.commit()
    Connection.close()