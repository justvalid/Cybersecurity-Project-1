import time
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import PACKET_RATE_THRESHOLD, PACKET_RATE_WINDOW, PORT_SCAN_DISTINCT_PORTS, PORT_SCAN_WINDOW

class AlertEngine:
    def __init__(self, df): 
        self.df = df
        self.alerts = []

    def _add(self, rule, severity, src, dst, msg, count=None, window=None):
        self.alerts.append({
            "timestamp": time.time(), "rule_name": rule, "severity": severity,
            "src_ip": src, "dst_ip": dst, "message": msg, "packet_count": count, "window_seconds": window
        })

    def run_all(self):
        if not self.df.empty:
            df = self.df.copy()
            df["t_bin"] = (df["timestamp"] // PACKET_RATE_WINDOW) * PACKET_RATE_WINDOW
            counts = df.groupby(["src_ip", "t_bin"]).size().reset_index(name="c")
            for _, row in counts[counts["c"] > PACKET_RATE_THRESHOLD].iterrows():
                self._add("HIGH_PACKET_RATE", "High", row["src_ip"], "multiple", f"Sent {row['c']} pkts in {PACKET_RATE_WINDOW}s", int(row["c"]), PACKET_RATE_WINDOW)
            
            df_ports = self.df.dropna(subset=["dst_port"]).copy()
            df_ports["t_bin"] = (df_ports["timestamp"] // PORT_SCAN_WINDOW) * PORT_SCAN_WINDOW
            ports = df_ports.groupby(["src_ip", "t_bin"])["dst_port"].nunique().reset_index(name="d")
            for _, row in ports[ports["d"] > PORT_SCAN_DISTINCT_PORTS].iterrows():
                self._add("PORT_SCAN_SUSPECT", "High", row["src_ip"], "multiple", f"Hit {row['d']} ports in {PORT_SCAN_WINDOW}s", int(row["d"]), PORT_SCAN_WINDOW)
        return self.alerts