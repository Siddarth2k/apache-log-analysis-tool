import re
from dataclasses import dataclass
from typing import List, Dict, Tuple
from collections import Counter, defaultdict
from .parser import LogEvent

# --- Alert Structure ---
@dataclass
class Alert:
    ip: str
    alert_type: str
    count: int
    severity: str
    evidence: str


# --- 1️⃣ Brute Force Detection ---
def detect_bruteforce(events: List[LogEvent], threshold: int = 5) -> List[Alert]:
    failed = [e for e in events if e.status in (401, 403)]
    counts = Counter(e.ip for e in failed)

    alerts = []
    for ip, c in counts.items():
        if c >= threshold:
            sample_paths = [e.path for e in failed if e.ip == ip][:5]
            alerts.append(Alert(
                ip=ip,
                alert_type="Brute Force (401/403 spike)",
                count=c,
                severity="High",
                evidence=str(sample_paths)
            ))
    return alerts


# --- 2️⃣ 404 Scanning Detection ---
def detect_404_scanning(events: List[LogEvent], threshold: int = 3) -> List[Alert]:
    not_found = [e for e in events if e.status == 404]
    counts = Counter(e.ip for e in not_found)

    alerts = []
    for ip, c in counts.items():
        if c >= threshold:
            sample_paths = [e.path for e in not_found if e.ip == ip][:5]
            alerts.append(Alert(
                ip=ip,
                alert_type="Recon / Directory Scanning (404 spike)",
                count=c,
                severity="Medium",
                evidence=str(sample_paths)
            ))
    return alerts


# --- 3️⃣ SQL Injection Detection ---
SQLI_REGEX = re.compile(
    r"(union\s+select|or\s+1=1|sleep\(|drop\s+table|--)",
    re.IGNORECASE
)

def detect_sqli(events: List[LogEvent]) -> List[Alert]:
    hits: Dict[str, List[str]] = defaultdict(list)

    for e in events:
        if SQLI_REGEX.search(e.path):
            hits[e.ip].append(e.path)

    alerts = []
    for ip, paths in hits.items():
        alerts.append(Alert(
            ip=ip,
            alert_type="SQL Injection Pattern",
            count=len(paths),
            severity="High",
            evidence=str(paths[:5])
        ))

    return alerts


# --- Top Talkers (for statistics) ---
def top_talkers(events: List[LogEvent], n: int = 10) -> List[Tuple[str, int]]:
    counts = Counter(e.ip for e in events)
    return counts.most_common(n)
