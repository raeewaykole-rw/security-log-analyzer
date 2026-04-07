from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Dict, Iterable, List, Optional


AUTH_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+(?P<message>.*)$"
)
SYSLOG_TS_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)
IP_PATTERN = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
PORT_PATTERN = re.compile(r"(?:port|DPT=)\s*(\d{1,5})")
USER_PATTERN = re.compile(r"for (?:invalid user )?([^\s]+)")


@dataclass
class LogEvent:
    timestamp: datetime
    source_ip: str
    event_type: str
    raw: str
    username: Optional[str] = None
    destination_port: Optional[int] = None


def _parse_timestamp(month: str, day: str, time_part: str, year: Optional[int] = None) -> datetime:
    now = datetime.now()
    inferred_year = year or now.year
    return datetime.strptime(f"{inferred_year} {month} {day} {time_part}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: Optional[int] = None) -> Optional[Dict]:
    line = line.strip()
    if not line:
        return None

    auth_match = AUTH_PATTERN.search(line)
    generic_ts = SYSLOG_TS_PATTERN.search(line)
    timestamp = None
    message = line

    if auth_match:
        timestamp = _parse_timestamp(
            auth_match.group("month"),
            auth_match.group("day"),
            auth_match.group("time"),
            year,
        )
        message = auth_match.group("message")
    elif generic_ts:
        timestamp = _parse_timestamp(
            generic_ts.group("month"),
            generic_ts.group("day"),
            generic_ts.group("time"),
            year,
        )
    else:
        timestamp = datetime.now()

    ip_match = IP_PATTERN.search(line)
    if not ip_match:
        return None

    source_ip = ip_match.group(1)
    username_match = USER_PATTERN.search(message)
    username = username_match.group(1) if username_match else None

    event_type = "other"
    if "Failed password" in message:
        event_type = "failed_login"
    elif "Accepted password" in message:
        event_type = "successful_login"
    elif "Invalid user" in message:
        event_type = "invalid_user"
    elif "SRC=" in line and "DPT=" in line:
        event_type = "network_probe"

    destination_port = None
    port_match = PORT_PATTERN.search(line)
    if port_match:
        try:
            destination_port = int(port_match.group(1))
        except ValueError:
            destination_port = None

    event = LogEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        event_type=event_type,
        raw=line,
        username=username,
        destination_port=destination_port,
    )
    return event.__dict__


def parse_log(file_path: str, year: Optional[int] = None) -> List[Dict]:
    events: List[Dict] = []
    with open(file_path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            parsed = parse_line(line, year=year)
            if parsed:
                events.append(parsed)
    return events


def parse_lines(lines: Iterable[str], year: Optional[int] = None) -> List[Dict]:
    parsed_events: List[Dict] = []
    for line in lines:
        parsed = parse_line(line, year=year)
        if parsed:
            parsed_events.append(parsed)
    return parsed_events
