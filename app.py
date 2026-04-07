from __future__ import annotations

import sys
from pathlib import Path

from flask import Flask, render_template

# Allow running `python dashboard/app.py` from project root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from analyzer.detector import correlate_events
from analyzer.parser import parse_log
from analyzer.scorer import calculate_scores

app = Flask(__name__)


def _get_dashboard_data(log_path: str = "logs/sample.log"):
    events = parse_log(log_path)
    correlated = correlate_events(events)
    scores = calculate_scores(events, correlated["findings"])

    top_ips = [
        {"ip": ip, "score": data["score"], "reasons": data["reasons"][:3]}
        for ip, data in list(scores.items())[:10]
    ]

    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for finding in correlated["findings"]:
        sev = finding.get("severity", "low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "total_events": len(events),
        "total_alerts": len(correlated["findings"]),
        "attack_counts": correlated["attack_counts"],
        "severity_counts": severity_counts,
        "top_ips": top_ips,
        "recent_alerts": correlated["findings"][-10:][::-1],
    }


@app.route("/")
def home():
    data = _get_dashboard_data()
    return render_template("index.html", data=data)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
