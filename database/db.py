import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "incidents.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            event_type TEXT,
            raw_log TEXT,
            investigation_log TEXT,
            ai_verdict TEXT,
            ai_confidence INTEGER,
            remediation TEXT,
            status TEXT DEFAULT 'Pending'
        )
    ''')
    conn.commit()
    conn.close()

def insert_incident(parsed_data, raw_log, final_state):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    timestamp = parsed_data.get('timestamp') or datetime.now().isoformat()
    ip = parsed_data.get('ip') or 'Unknown'
    event = parsed_data.get('event') or 'Unknown'
    
    cursor.execute('''
        INSERT INTO incidents (
            timestamp, ip_address, event_type, raw_log, 
            investigation_log, ai_verdict, ai_confidence, remediation
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        timestamp, ip, event, raw_log, 
        final_state.get('osint_investigation_log', ''),
        final_state.get('verdict', 'Unknown'),
        final_state.get('confidence', 0),
        final_state.get('remediation', '')
    ))
    conn.commit()
    conn.close()

def get_all_incidents(status_filter=None):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    if status_filter:
        cursor.execute("SELECT * FROM incidents WHERE status = ? ORDER BY id DESC", (status_filter,))
    else:
        cursor.execute("SELECT * FROM incidents ORDER BY id DESC")
        
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def update_incident_status(incident_id, new_status):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE incidents SET status = ? WHERE id = ?", (new_status, incident_id))
    conn.commit()
    conn.close()

init_db()
