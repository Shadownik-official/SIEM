import sqlite3
from typing import List, Dict, Any, Optional
import json
import threading
from pathlib import Path

class Database:
    """SQLite database wrapper with thread safety."""
    
    def __init__(self, db_path: str):
        """Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._local = threading.local()
        self._ensure_tables()
    
    @property
    def conn(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn
        
    def _ensure_tables(self) -> None:
        """Create database tables if they don't exist."""
        with self.conn:
            self.conn.executescript('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    data TEXT NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT,
                    last_seen TEXT,
                    metadata TEXT
                );
                
                CREATE TABLE IF NOT EXISTS actors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    aliases TEXT,
                    description TEXT,
                    metadata TEXT
                );
            ''')
    
    def add_event(self, timestamp: str, source: str, event_type: str, data: Dict[str, Any]) -> None:
        """Add a new event to the database.
        
        Args:
            timestamp: Event timestamp
            source: Event source
            event_type: Type of event
            data: Event data
        """
        with self.conn:
            self.conn.execute(
                'INSERT INTO events (timestamp, source, event_type, data) VALUES (?, ?, ?, ?)',
                (timestamp, source, event_type, json.dumps(data))
            )
    
    def get_events(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get events from the database.
        
        Args:
            limit: Optional limit on number of events to return
        
        Returns:
            List of events
        """
        query = 'SELECT * FROM events ORDER BY timestamp DESC'
        if limit:
            query += f' LIMIT {limit}'
            
        with self.conn:
            cursor = self.conn.execute(query)
            events = []
            for row in cursor:
                event = dict(row)
                event['data'] = json.loads(event['data'])
                events.append(event)
            return events
            
    def close(self) -> None:
        """Close database connection."""
        if hasattr(self._local, "conn"):
            self._local.conn.close()
            del self._local.conn
