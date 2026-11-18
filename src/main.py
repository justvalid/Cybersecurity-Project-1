import os, sys, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.capture import load_pcap
from modules.parser import parse_packets
from modules.database import Database
from modules.analyzer import TrafficAnalyzer
from modules.alert_engine import AlertEngine
from modules.reporter import generate_reports

def main():
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=["pcap"])
    p.add_argument("path")
    args = p.parse_args()

    if args.command == "pcap":
        print(f"[*] Loading {args.path}...")
        packets = load_pcap(args.path)
        records = parse_packets(packets, os.path.basename(args.path))
        
        db = Database()
        db.insert_packets(records)
        df = db.fetch_packets_df()
        
        analyzer = TrafficAnalyzer(df)
        summary = analyzer.summary()
        proto = analyzer.protocol_distribution()
        talkers = analyzer.top_talkers()
        
        print("\n========== SUMMARY ==========")
        for k, v in summary.items(): 
            print(f"  {k}: {v}")
        
        engine = AlertEngine(df)
        alerts = engine.run_all()
        for a in alerts: 
            db.insert_alert(a)
        print(f"\n[+] Generated {len(alerts)} alert(s).")
        
        alerts_df = db.fetch_alerts_df()
        generate_reports(summary, proto, talkers, alerts_df)
        print("[+] Charts and reports saved to the 'reports' folder!")
        db.close()

if __name__ == "__main__":
    main()