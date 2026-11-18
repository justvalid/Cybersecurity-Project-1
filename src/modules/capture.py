from scapy.all import rdpcap

def load_pcap(path):
    try:
        return list(rdpcap(path))
    except Exception as e:
        print(f"[!] Error reading PCAP: {e}")
        return []