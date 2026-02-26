import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

@dataclass
class LogEvent:
    ip: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status: int
    size: Optional[int]

def parse_apache_time(time_str: str) -> datetime:
    return datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")

def parse_line(line: str) -> Optional[LogEvent]:
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None

    size_raw = m.group("size")
    size = None if size_raw == "-" else int(size_raw)

    return LogEvent(
        ip=m.group("ip"),
        timestamp=parse_apache_time(m.group("time")),
        method=m.group("method"),
        path=m.group("path"),
        protocol=m.group("protocol"),
        status=int(m.group("status")),
        size=size,
    )

def parse_file(filepath: str) -> List[LogEvent]:
    events: List[LogEvent] = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            ev = parse_line(line)
            if ev:
                events.append(ev)
    return events
