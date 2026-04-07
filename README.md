# Security Log Analyzer (Mini SIEM Simulation)

This project simulates SOC-style detection workflows, not just basic parsing.

## Core Capabilities

- Parse and normalize auth/network events from log files
- Correlate events to detect brute force, success-after-failures, and port scans
- Threat scoring per source IP
- Alerting with console + JSON export
- Real-time monitoring mode (`--follow`)
- Flask dashboard for attack trends and top suspicious IPs

## Intelligence & Reporting Upgrades

- GeoIP enrichment (`ip-api`) for attacker country/city/ISP
- VirusTotal IP reputation enrichment
- Intelligence report export to JSON
- Intelligence report export to PDF

## Setup

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Run One-Time Analysis

```bash
python main.py --log logs/sample.log --json-output logs/alerts.json
```

## Run with GeoIP + VirusTotal Enrichment

```bash
python main.py --log logs/sample.log --geoip --virustotal
```

Set your VirusTotal key through environment variables instead of putting it directly in commands:

```bash
set VT_API_KEY=[insert ur api key]
python main.py --log logs/sample.log --geoip --virustotal
```

If you do not pass `--vt-api-key`, the app will try `VT_API_KEY` from environment variables.

## Export Intelligence Reports

```bash
python main.py --log logs/sample.log --geoip --report-json logs/report.json --report-pdf logs/report.pdf
```

## Real-Time Monitoring

```bash
python main.py --log logs/sample.log --follow --poll-interval 2
```

While running, append new lines to `logs/sample.log` to simulate live attacks.

## Run Dashboard

```bash
python dashboard/app.py
```

Open `http://127.0.0.1:5000`.

## Project Structure Highlights

- `analyzer/parser.py`: event parsing and normalization
- `analyzer/detector.py`: event correlation detectors
- `analyzer/scorer.py`: weighted threat scoring
- `analyzer/alerts.py`: alert formatting + JSON export
- `analyzer/realtime.py`: tail/follow streaming helper
- `analyzer/geoip.py`: GeoIP enrichment
- `analyzer/virustotal.py`: VirusTotal enrichment
- `analyzer/report_json.py`: JSON intelligence report export
- `analyzer/report_pdf.py`: PDF intelligence report export
- `main.py`: CLI orchestrator

## Interview Pitch

"Built a mini SIEM in Python with real-time monitoring, attack-pattern correlation, threat scoring, and threat-intelligence enrichment (GeoIP + VirusTotal). It generates SOC-style alerts and exports intelligence reports in JSON/PDF while providing a dashboard for analyst visibility."
