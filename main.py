from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List, Set, Tuple

from analyzer.alerts import export_alerts_json, generate_console_alerts
from analyzer.detector import correlate_events
from analyzer.geoip import get_ip_info
from analyzer.parser import parse_line, parse_log
from analyzer.realtime import follow
from analyzer.report_json import export_json
from analyzer.report_pdf import export_pdf
from analyzer.scorer import calculate_scores
from analyzer.virustotal import check_ip_virustotal


def _print_scoreboard(scores: Dict[str, Dict], top_n: int = 10) -> None:
    print("\n=== Threat Scoreboard ===")
    if not scores:
        print("No scored IPs.")
        return

    for idx, (ip, info) in enumerate(scores.items()):
        if idx >= top_n:
            break
        print(f"{ip:<16} score={info['score']}")


def _finding_signature(finding: Dict) -> Tuple:
    return (
        finding.get("type"),
        finding.get("source_ip"),
        finding.get("window_start"),
        finding.get("window_end"),
        finding.get("count"),
    )


def _collect_detection_counts(findings: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        ip = finding.get("source_ip")
        if not ip:
            continue
        counts[ip] = counts.get(ip, 0) + 1
    return counts


def build_intel_report(
    scores: Dict[str, Dict],
    findings: List[Dict],
    include_geoip: bool = False,
    include_virustotal: bool = False,
    virustotal_api_key: str | None = None,
) -> List[Dict]:
    detection_counts = _collect_detection_counts(findings)
    report_rows: List[Dict] = []

    for ip, score_data in scores.items():
        row = {
            "ip": ip,
            "score": score_data.get("score", 0),
            "detections": detection_counts.get(ip, 0),
            "country": "N/A",
            "city": "N/A",
            "isp": "N/A",
            "vt_malicious": "N/A",
            "vt_suspicious": "N/A",
        }

        if include_geoip:
            geo = get_ip_info(ip)
            row["country"] = geo.get("country", "Unknown")
            row["city"] = geo.get("city", "Unknown")
            row["isp"] = geo.get("isp", "Unknown")

        if include_virustotal:
            vt = check_ip_virustotal(ip, api_key=virustotal_api_key)
            if vt:
                row["vt_malicious"] = vt.get("malicious", 0)
                row["vt_suspicious"] = vt.get("suspicious", 0)

        report_rows.append(row)

    return report_rows


def _print_intel_report(report_rows: List[Dict], top_n: int = 10) -> None:
    if not report_rows:
        return

    print("\n=== Enriched Intelligence View ===")
    for row in report_rows[:top_n]:
        print(
            f"{row['ip']:<16} score={row['score']:<3} "
            f"country={row['country']:<12} isp={row['isp']} "
            f"vt_malicious={row['vt_malicious']}"
        )


def analyze_once(
    log_path: str,
    json_output: str | None = None,
    include_geoip: bool = False,
    include_virustotal: bool = False,
    virustotal_api_key: str | None = None,
    report_json_path: str | None = None,
    report_pdf_path: str | None = None,
) -> Dict:
    events = parse_log(log_path)
    result = correlate_events(events)
    scores = calculate_scores(events, result["findings"])

    generate_console_alerts(result["findings"])
    _print_scoreboard(scores)

    if json_output:
        exported = export_alerts_json(result["findings"], json_output)
        print(f"\n[INFO] Alerts exported to {exported}")

    report_rows = build_intel_report(
        scores=scores,
        findings=result["findings"],
        include_geoip=include_geoip,
        include_virustotal=include_virustotal,
        virustotal_api_key=virustotal_api_key,
    )

    if include_geoip or include_virustotal:
        _print_intel_report(report_rows)

    if report_json_path:
        written = export_json(report_rows, report_json_path)
        print(f"[INFO] Intelligence JSON report exported to {written}")

    if report_pdf_path:
        try:
            written = export_pdf(report_rows, report_pdf_path)
            print(f"[INFO] Intelligence PDF report exported to {written}")
        except RuntimeError as exc:
            print(f"[WARN] PDF export skipped: {exc}")

    return {"events": events, "findings": result["findings"], "scores": scores, "report": report_rows}


def monitor_realtime(
    log_path: str,
    poll_interval: float = 2.0,
    json_output: str | None = None,
) -> None:
    print(f"[INFO] Monitoring {log_path} in real-time. Press Ctrl+C to stop.")

    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    events = parse_log(log_path)
    seen_alerts: Set[Tuple] = set(_finding_signature(f) for f in correlate_events(events)["findings"])

    for line in follow(log_path, poll_interval=poll_interval):
        parsed = parse_line(line)
        if not parsed:
            continue

        events.append(parsed)
        correlated = correlate_events(events)

        new_findings = []
        for finding in correlated["findings"]:
            signature = _finding_signature(finding)
            if signature not in seen_alerts:
                seen_alerts.add(signature)
                new_findings.append(finding)

        if new_findings:
            generate_console_alerts(new_findings)
            scores = calculate_scores(events, correlated["findings"])
            _print_scoreboard(scores)

            if json_output:
                export_alerts_json(correlated["findings"], json_output)


def main() -> None:
    parser = argparse.ArgumentParser(description="Mini SIEM security log analyzer")
    parser.add_argument("--log", default="logs/sample.log", help="Path to log file")
    parser.add_argument("--follow", action="store_true", help="Enable real-time monitoring mode")
    parser.add_argument(
        "--json-output",
        default="logs/alerts.json",
        help="Where to write JSON alerts",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        help="Polling interval (seconds) for --follow mode",
    )

    parser.add_argument("--geoip", action="store_true", help="Enrich suspicious IPs with GeoIP data")
    parser.add_argument("--virustotal", action="store_true", help="Enrich suspicious IPs with VirusTotal")
    parser.add_argument("--vt-api-key", default=None, help="VirusTotal API key (or set VT_API_KEY env var)")
    parser.add_argument("--report-json", default="logs/report.json", help="Path to intelligence JSON report")
    parser.add_argument("--report-pdf", default=None, help="Path to intelligence PDF report")

    args = parser.parse_args()

    if args.follow:
        monitor_realtime(args.log, poll_interval=args.poll_interval, json_output=args.json_output)
    else:
        analyze_once(
            args.log,
            json_output=args.json_output,
            include_geoip=args.geoip,
            include_virustotal=args.virustotal,
            virustotal_api_key=args.vt_api_key,
            report_json_path=args.report_json,
            report_pdf_path=args.report_pdf,
        )


if __name__ == "__main__":
    main()
