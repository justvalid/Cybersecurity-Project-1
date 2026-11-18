# Intelligent Network Traffic Analyzer and Intrusion Detection System

##  Project Overview
This project is a Python-based Network Intrusion Detection System (NIDS) that analyzes network traffic to identify unusual patterns, such as traffic floods and port scanning. It captures or imports network packets, extracts metadata, stores the data in a SQLite database, generates alerts based on configured thresholds, and produces visual reports.

##  Features
Packet Ingestion:Reads `.pcap` files for offline analysis.
Protocol Identification:** Classifies TCP, UDP, ICMP, and DNS traffic.
Traffic Analysis: Calculates packet counts, traffic volume, top talkers (source IPs), and protocol distributions using Pandas.
Alert Engine: Rule-based detection for High Packet Rate (floods) and Port Scans based on configurable time windows and thresholds.
Storage: Saves all packet metadata and generated alerts into a local SQLite database (`traffic.db`).
Reporting: Generates visual charts (PNG) and exports findings to JSON format.

##  Prerequisites
Before running this project, ensure you have:
Python 3.12** (or higher) installed.
`pip` package manager.
Python libraries installed (scapy, pandas, matplotlib)

## Installation
1. Clone or download this project folder to your local machine.
2. Open Command Prompt (CMD) and navigate to the project root folder:
   ```cmd
   cd C:\path\to\Cybersecurity-Project