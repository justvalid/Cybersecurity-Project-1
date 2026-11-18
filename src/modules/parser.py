from scapy.all import IP, TCP, UDP, ICMP, DNS

def detect_protocol(packet):
    if packet.haslayer(DNS): return "DNS"
    if packet.haslayer(TCP):
        if packet[TCP].dport in (80, 8080) or packet[TCP].sport in (80, 8080): return "HTTP"
        if packet[TCP].dport == 443 or packet[TCP].sport == 443: return "HTTPS"
        return "TCP"
    if packet.haslayer(UDP): return "UDP"
    if packet.haslayer(ICMP): return "ICMP"
    return "OTHER"

def parse_packets(packets, capture_file=None):
    records = []
    for pkt in packets:
        if pkt.haslayer(IP):
            sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else None)
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else None)
            
            records.append({
                "timestamp": float(pkt.time), 
                "src_ip": pkt[IP].src, 
                "dst_ip": pkt[IP].dst,
                "protocol": detect_protocol(pkt), 
                "src_port": sport, 
                "dst_port": dport,
                "length": len(pkt), 
                "capture_file": capture_file
            })
    return records