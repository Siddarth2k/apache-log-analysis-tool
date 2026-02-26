import json
import os
from dataclasses import asdict
from typing import List, Tuple
import pandas as pd
import matplotlib.pyplot as plt
from .detectors import Alert


def write_alerts_csv(alerts: List[Alert], out_csv: str):
    df = pd.DataFrame([asdict(a) for a in alerts])
    if df.empty:
        df = pd.DataFrame(columns=["ip", "alert_type", "count", "severity", "evidence"])
    df.to_csv(out_csv, index=False)


def write_summary_json(total_events: int, top_ips: List[Tuple[str, int]], alerts: List[Alert], out_json: str):
    summary = {
        "total_events": total_events,
        "top_ips": [{"ip": ip, "requests": c} for ip, c in top_ips],
        "total_alerts": len(alerts),
        "alerts_preview": [asdict(a) for a in alerts[:5]]
    }

    with open(out_json, "w") as f:
        json.dump(summary, f, indent=2)


def plot_top_ips(top_ips: List[Tuple[str, int]], out_png: str):
    if not top_ips:
        return

    ips = [ip for ip, _ in top_ips]
    counts = [c for _, c in top_ips]

    plt.figure()
    plt.bar(ips, counts)
    plt.xticks(rotation=45)
    plt.title("Top IPs by Request Volume")
    plt.ylabel("Request Count")
    plt.tight_layout()
    plt.savefig(out_png)
    plt.close()
