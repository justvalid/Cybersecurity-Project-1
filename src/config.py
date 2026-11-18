import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "traffic.db")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
CHARTS_DIR = os.path.join(REPORTS_DIR, "charts")

PACKET_RATE_THRESHOLD = 100       
PACKET_RATE_WINDOW = 10           
PORT_SCAN_DISTINCT_PORTS = 20     
PORT_SCAN_WINDOW = 60             
ALLOWED_PROTOCOLS = {"TCP", "UDP", "ICMP", "DNS"}