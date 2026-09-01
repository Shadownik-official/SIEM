import sqlite3
import os

class Data:
    def __init__(self, db_file):
        self.db_file = db_file
        self.create_database()

    def create_database(self):
        if not os.path.exists(self.db_file):
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        event_description TEXT NOT NULL,
                        event_time TIMESTAMP NOT NULL
                    )
                ''')
                conn.commit()

    def add_event(self, event_type, event_description, event_time):
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO events (event_type, event_description, event_time) VALUES (?, ?, ?)
            ''', (event_type, event_description, event_time))
            conn.commit()

    def get_events(self):
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM events ORDER BY event_time DESC')
            return cursor.fetchall()