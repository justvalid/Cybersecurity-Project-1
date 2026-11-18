import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap

OUT_DIR = "data/sample_data"
os.makedirs(OUT_DIR, exist_ok=True)

def make_flood():
    pkts = []
    t = 2000.0
    for i in range(150): # 150 packets in less than 10 seconds
        t += 0.05
        p = IP(src="10.0.0.66", dst="10.0.0.10") / TCP(sport=60000, dport=80)
        p.time = t; pkts.append(p)
    return pkts

if __name__ == "__main__":
    pcap = os.path.join(OUT_DIR, "flood.pcap")
    wrpcap(pcap, make_flood())
    print(f"[+] Wrote {pcap} successfully!")