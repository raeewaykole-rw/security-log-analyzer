from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def export_json(data: List[Dict[str, Any]], filename: str = "logs/report.json") -> str:
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return str(path)
