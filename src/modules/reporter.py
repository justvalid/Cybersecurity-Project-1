import os, sys, json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import CHARTS_DIR, REPORTS_DIR

def generate_reports(summary, proto_df, talkers_df, alerts_df):
    os.makedirs(CHARTS_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Protocol Chart
    plt.figure(figsize=(8, 5))
    plt.bar(proto_df["protocol"], proto_df["packets"], color="steelblue")
    plt.title("Packet Count by Protocol")
    plt.savefig(os.path.join(CHARTS_DIR, "protocol_distribution.png"))
    plt.close()

    # Top Talkers Chart
    plt.figure(figsize=(9, 5))
    plt.barh(talkers_df["src_ip"], talkers_df["packets"], color="darkorange")
    plt.title("Top Talkers")
    plt.savefig(os.path.join(CHARTS_DIR, "top_talkers.png"))
    plt.close()

    # JSON Export
    with open(os.path.join(REPORTS_DIR, "report.json"), "w") as f:
        json.dump({"summary": summary, "alerts": alerts_df.to_dict("records") if not alerts_df.empty else []}, f, indent=2, default=str)