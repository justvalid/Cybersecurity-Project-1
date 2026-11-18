# Research Notes — Network Traffic Analyzer & IDS

## 1. Network Packets
A network packet is the fundamental unit of data in packet-switched networks. Each packet consists of a **header** (control data) and a **payload** (user data). When you browse the internet, your data is chopped up into thousands of these packets.

## 2. IP Header Fields (IPv4)
Every packet contains an IP header. The most important fields our tool extracts are:
Source IP Address:The sender's address.
Destination IP Address:The receiver's address.
Protocol:Tells the system how to process the payload (e.g., 6 = TCP, 17 = UDP, 1 = ICMP).
TTL (Time to Live):Prevents packets from looping forever.
Length:The total size of the packet in bytes.

## 3. TCP vs UDP
Aspect: TCP (Transmission Control Protocol) | UDP (User Datagram Protocol).
Connection:Connection-oriented (uses a 3-way handshake).Connectionless (just fires and forgets).
Reliability:Guaranteed delivery. Lost packets are re-sent.No guarantee. Lost packets are gone.
Ordering:Ensures packets arrive in the exact order they were sent. Packets may arrive out of order.
Speed:Slower due to error checking and ACKs.Very fast, minimal overhead.
Examples: HTTP, HTTPS, SSH, FTP, Emails. DNS, DHCP, VoIP, Video Streaming. 

## 4. Packet Sniffing vs. Packet Analysis
Sniffing: The act of capturing raw frames from the network interface card (NIC) in promiscuous mode. 
Analysis: The process of interpreting those captured packets—extracting metadata, identifying anomalies, and drawing conclusions. Our tool does both, but focuses heavily on analysis.

## 5. PCAP Files
PCAP (Packet Capture) files are standard binary files that store raw network traffic. They are incredibly useful for:
Reproducible testing (we used them to simulate a flood attack).
Preserving evidence during an investigation.
Offline analysis without needing to be connected to a live network.

## 6. Intrusion Detection Systems (IDS)
An IDS monitors network traffic for suspicious activity. 
NIDS (Network-based):Monitors traffic on a network segment (What we built).
HIDS (Host-based):Monitors system files and logs on a single computer.
Signature-based:Looks for known attack patterns (like antivirus).
Anomaly-based:Flags traffic that deviates from "normal" behavior (like a sudden flood).

## 7. How Traffic Analysis Detects Attacks
By analyzing packet metadata (IPs, ports, and volume), we can detect:
Port Scans:A single source IP trying to connect to dozens of different ports in a few seconds (looking for open doors).
Floods (DoS/DDoS):A single source IP sending hundreds of packets per second to overwhelm a target.
Unexpected Protocols:Seeing ICMP (ping) traffic when a network is supposed to only allow web traffic.

## 8. Limitations of Fixed Thresholds
Our tool uses fixed thresholds (e.g., alerting if an IP sends >100 packets in 10 seconds). The limitations are:
1. False Positives: A legitimate heavy download might trigger the alert.
2. Low-and-Slow Attacks: Attackers can bypass the alert by sending 99 packets every 10 seconds.
3. Tuning:Thresholds must be customized for every different network environment.