from __future__ import annotations

from typing import Dict

try:
    import requests
except Exception:  # pragma: no cover - optional dependency
    requests = None

from utils.config import GEOIP_TIMEOUT_SECONDS, IP_API_URL


def get_ip_info(ip: str) -> Dict:
    """Return lightweight IP geolocation and ISP details."""
    if not requests:
        return {"ip": ip, "country": "Unknown", "city": "Unknown", "isp": "Unknown"}

    try:
        response = requests.get(
            IP_API_URL.format(ip=ip),
            timeout=GEOIP_TIMEOUT_SECONDS,
        )
        if response.status_code != 200:
            return {"ip": ip, "country": "Unknown", "city": "Unknown", "isp": "Unknown"}

        payload = response.json()
        return {
            "ip": ip,
            "country": payload.get("country", "Unknown"),
            "city": payload.get("city", "Unknown"),
            "isp": payload.get("isp", "Unknown"),
        }
    except Exception:
        return {"ip": ip, "country": "Unknown", "city": "Unknown", "isp": "Unknown"}
