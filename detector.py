from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List

from utils.config import (
    BRUTE_FORCE_MIN_ATTEMPTS,
    BRUTE_FORCE_WINDOW_MINUTES,
    PORT_SCAN_MIN_PORTS,
    PORT_SCAN_WINDOW_MINUTES,
    SUCCESS_AFTER_FAIL_MIN_FAILS,
    SUCCESS_AFTER_FAIL_WINDOW_MINUTES,
)


def _normalize_timestamp(value):
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


def _bucket_by_ip(events: List[Dict], event_type: str) -> Dict[str, List[Dict]]:
    grouped = defaultdict(list)
    for event in events:
        if event.get("event_type") == event_type:
            grouped[event.get("source_ip")].append(event)

    for ip in grouped:
        grouped[ip] = sorted(grouped[ip], key=lambda e: _normalize_timestamp(e["timestamp"]))
    return grouped


def detect_bruteforce(events: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    failed_by_ip = _bucket_by_ip(events, "failed_login")
    window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)

    for ip, failed_events in failed_by_ip.items():
        left = 0
        peak = 0
        window_start = None
        window_end = None

        for right, event in enumerate(failed_events):
            current_time = _normalize_timestamp(event["timestamp"])
            while current_time - _normalize_timestamp(failed_events[left]["timestamp"]) > window:
                left += 1

            count = right - left + 1
            if count > peak:
                peak = count
                window_start = _normalize_timestamp(failed_events[left]["timestamp"])
                window_end = current_time

        if peak >= BRUTE_FORCE_MIN_ATTEMPTS:
            findings.append(
                {
                    "type": "bruteforce",
                    "source_ip": ip,
                    "count": peak,
                    "window_start": window_start.isoformat() if window_start else None,
                    "window_end": window_end.isoformat() if window_end else None,
                    "severity": "high" if peak >= BRUTE_FORCE_MIN_ATTEMPTS + 3 else "medium",
                    "description": f"{peak} failed logins within {BRUTE_FORCE_WINDOW_MINUTES} minutes.",
                }
            )

    return findings


def detect_success_after_failures(events: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    window = timedelta(minutes=SUCCESS_AFTER_FAIL_WINDOW_MINUTES)

    events_by_ip = defaultdict(list)
    for event in sorted(events, key=lambda e: _normalize_timestamp(e["timestamp"])):
        events_by_ip[event.get("source_ip")].append(event)

    for ip, ip_events in events_by_ip.items():
        fail_timestamps = []
        for event in ip_events:
            ts = _normalize_timestamp(event["timestamp"])
            if event.get("event_type") == "failed_login":
                fail_timestamps.append(ts)
                continue

            if event.get("event_type") == "successful_login":
                recent_fails = [f for f in fail_timestamps if ts - f <= window]
                if len(recent_fails) >= SUCCESS_AFTER_FAIL_MIN_FAILS:
                    findings.append(
                        {
                            "type": "success_after_failures",
                            "source_ip": ip,
                            "count": len(recent_fails),
                            "window_start": recent_fails[0].isoformat(),
                            "window_end": ts.isoformat(),
                            "severity": "critical",
                            "description": (
                                f"Successful login after {len(recent_fails)} failures "
                                f"within {SUCCESS_AFTER_FAIL_WINDOW_MINUTES} minutes."
                            ),
                        }
                    )

    return findings


def detect_port_scan_behavior(events: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    probes = [e for e in events if e.get("event_type") == "network_probe" and e.get("destination_port")]
    probes = sorted(probes, key=lambda e: _normalize_timestamp(e["timestamp"]))
    window = timedelta(minutes=PORT_SCAN_WINDOW_MINUTES)

    probes_by_ip = defaultdict(list)
    for event in probes:
        probes_by_ip[event.get("source_ip")].append(event)

    for ip, ip_probes in probes_by_ip.items():
        left = 0
        max_unique_ports = set()
        best_window = (None, None)

        for right, event in enumerate(ip_probes):
            right_ts = _normalize_timestamp(event["timestamp"])
            while right_ts - _normalize_timestamp(ip_probes[left]["timestamp"]) > window:
                left += 1

            window_slice = ip_probes[left : right + 1]
            unique_ports = {p.get("destination_port") for p in window_slice if p.get("destination_port")}
            if len(unique_ports) > len(max_unique_ports):
                max_unique_ports = unique_ports
                best_window = (
                    _normalize_timestamp(window_slice[0]["timestamp"]),
                    right_ts,
                )

        if len(max_unique_ports) >= PORT_SCAN_MIN_PORTS:
            findings.append(
                {
                    "type": "port_scan",
                    "source_ip": ip,
                    "count": len(max_unique_ports),
                    "ports": sorted(max_unique_ports),
                    "window_start": best_window[0].isoformat() if best_window[0] else None,
                    "window_end": best_window[1].isoformat() if best_window[1] else None,
                    "severity": "high",
                    "description": (
                        f"Connected to {len(max_unique_ports)} distinct ports "
                        f"within {PORT_SCAN_WINDOW_MINUTES} minutes."
                    ),
                }
            )

    return findings


def correlate_events(events: List[Dict]) -> Dict:
    findings = []
    findings.extend(detect_bruteforce(events))
    findings.extend(detect_success_after_failures(events))
    findings.extend(detect_port_scan_behavior(events))

    attack_counts = Counter(f["type"] for f in findings)
    return {
        "findings": findings,
        "attack_counts": dict(attack_counts),
        "total_events": len(events),
    }
