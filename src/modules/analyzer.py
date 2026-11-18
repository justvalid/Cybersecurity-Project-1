class TrafficAnalyzer:
    def __init__(self, df): 
        self.df = df

    def summary(self):
        return {
            "total_packets": len(self.df), 
            "total_bytes": int(self.df["length"].sum()),
            "unique_src_ips": self.df["src_ip"].nunique(), 
            "unique_dst_ips": self.df["dst_ip"].nunique()
        }

    def protocol_distribution(self):
        return self.df.groupby("protocol").agg(packets=("id", "count"), bytes=("length", "sum")).reset_index()

    def top_talkers(self, n=10):
        return self.df.groupby("src_ip").agg(packets=("id", "count"), bytes=("length", "sum")).sort_values("packets", ascending=False).head(n).reset_index()