from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import Dict, List


def format_alert(finding: Dict) -> str:
    return (
        f"[{finding.get('severity', 'low').upper()}] "
        f"{finding.get('type')} from {finding.get('source_ip')} | "
        f"{finding.get('description')}"
    )


def generate_console_alerts(findings: List[Dict]) -> None:
    if not findings:
        print("[INFO] No suspicious activity detected.")
        return

    print("\n=== Alerts ===")
    for finding in findings:
        print(format_alert(finding))


def export_alerts_json(findings: List[Dict], output_path: str) -> str:
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_alerts": len(findings),
        "alerts": findings,
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)
