import json
from typing import Dict
from urllib.error import URLError
from urllib.request import urlopen


def _fetch_json(url: str) -> Dict:
    try:
        with urlopen(url, timeout=8) as res:
            return json.loads(res.read().decode("utf-8"))
    except (URLError, TimeoutError, ValueError):
        return {}


def lookup_ip(ip: str) -> Dict:
    info = _fetch_json(f"https://ipinfo.io/{ip}/json")
    api = _fetch_json(f"http://ip-api.com/json/{ip}")

    return {
        "ip": ip,
        "geolocation": info.get("loc") or f"{api.get('lat', '')},{api.get('lon', '')}".strip(","),
        "city": info.get("city") or api.get("city"),
        "region": info.get("region") or api.get("regionName"),
        "country": info.get("country") or api.get("country"),
        "isp": info.get("org") or api.get("isp"),
        "asn": info.get("asn", {}).get("asn") if isinstance(info.get("asn"), dict) else info.get("org"),
        "reverse_dns": info.get("hostname") or api.get("reverse"),
        "raw": {"ipinfo": info, "ip_api": api},
    }
