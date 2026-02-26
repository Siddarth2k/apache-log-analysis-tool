import os
import argparse
from .parser import parse_file
from .detectors import detect_bruteforce, detect_404_scanning, detect_sqli, top_talkers
from .report import write_alerts_csv, write_summary_json, plot_top_ips


def main():
    parser = argparse.ArgumentParser(description="Apache Log Security Analyzer")

    parser.add_argument("--log", required=True, help="Path to Apache log file")
    parser.add_argument("--outdir", default="output", help="Output directory")
    parser.add_argument("--bf-threshold", type=int, default=5, help="Brute force threshold")
    parser.add_argument("--scan404-threshold", type=int, default=3, help="404 scanning threshold")

    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    events = parse_file(args.log)

    alerts = []
    alerts += detect_bruteforce(events, threshold=args.bf_threshold)
    alerts += detect_404_scanning(events, threshold=args.scan404_threshold)
    alerts += detect_sqli(events)

    top_ips = top_talkers(events)

    write_alerts_csv(alerts, os.path.join(args.outdir, "alerts.csv"))
    write_summary_json(len(events), top_ips, alerts, os.path.join(args.outdir, "summary.json"))
    plot_top_ips(top_ips, os.path.join(args.outdir, "top_ips.png"))

    print(f"Parsed events: {len(events)}")
    print(f"Alerts found: {len(alerts)}")


if __name__ == "__main__":
    main()
