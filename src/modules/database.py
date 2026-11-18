import os, sys, time, sqlite3
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, src_ip TEXT, dst_ip TEXT, protocol TEXT, src_port INTEGER, dst_port INTEGER, length INTEGER, capture_file TEXT);
CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, rule_name TEXT, severity TEXT, src_ip TEXT, dst_ip TEXT, message TEXT, packet_count INTEGER, window_seconds INTEGER);
"""

class Database:
    def __init__(self, path=DB_PATH):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def insert_packets(self, records):
        rows = [(r["timestamp"], r["src_ip"], r["dst_ip"], r["protocol"], r.get("src_port"), r.get("dst_port"), r["length"], r.get("capture_file")) for r in records]
        self.conn.executemany("INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length, capture_file) VALUES (?,?,?,?,?,?,?,?)", rows)
        self.conn.commit()

    def insert_alert(self, alert):
        self.conn.execute("INSERT INTO alerts (timestamp, rule_name, severity, src_ip, dst_ip, message, packet_count, window_seconds) VALUES (?,?,?,?,?,?,?,?)",
            (alert["timestamp"], alert["rule_name"], alert["severity"], alert["src_ip"], alert["dst_ip"], alert["message"], alert.get("packet_count"), alert.get("window_seconds")))
        self.conn.commit()

    def fetch_packets_df(self):
        return pd.read_sql_query("SELECT * FROM packets", self.conn)

    def fetch_alerts_df(self):
        return pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp", self.conn)

    def close(self):
        self.conn.close()