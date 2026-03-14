import csv
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SHERLOCK_DATA_URL = "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock/resources/data.json"
USER_AGENT = "YUSTUS-OSINT/2.0"

FALLBACK_PLATFORMS = {
    "Instagram": "https://www.instagram.com/{username}/",
    "Twitter/X": "https://x.com/{username}",
    "GitHub": "https://github.com/{username}",
    "Reddit": "https://www.reddit.com/user/{username}/",
    "TikTok": "https://www.tiktok.com/@{username}",
    "Facebook": "https://www.facebook.com/{username}",
    "Pinterest": "https://www.pinterest.com/{username}/",
    "Medium": "https://medium.com/@{username}",
    "StackOverflow": "https://stackoverflow.com/users/{username}",
}


@dataclass
class UsernameFinding:
    platform: str
    url: str
    exists: bool
    status_code: int
    detected: bool


def _http_status(url: str, timeout: int = 8) -> int:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=timeout) as response:
            return getattr(response, "status", 200)
    except HTTPError as e:
        return int(e.code)
    except (URLError, TimeoutError, ValueError):
        return 0


def _load_sherlock_sites(limit: int = 320) -> Dict[str, str]:
    req = Request(SHERLOCK_DATA_URL, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=15) as response:
        payload = json.loads(response.read().decode("utf-8"))

    websites: Dict[str, str] = {}
    for name, config in payload.items():
        url = config.get("url")
        if not isinstance(url, str) or "{}" not in url:
            continue
        websites[name] = url.replace("{}", "{username}")
        if len(websites) >= limit:
            break
    return websites


def get_platforms(limit: int = 320) -> Tuple[Dict[str, str], str]:
    try:
        sites = _load_sherlock_sites(limit=limit)
        if sites:
            return sites, "sherlock"
    except Exception:
        pass
    return FALLBACK_PLATFORMS, "fallback"


def _check_platform(platform: str, url: str, timeout: int = 8) -> UsernameFinding:
    status_code = _http_status(url, timeout=timeout)
    exists = status_code in {200, 301, 302}
    return UsernameFinding(platform=platform, url=url, exists=exists, status_code=status_code, detected=exists)


def scan_username(username: str, workers: int = 20, limit: int = 320) -> Dict:
    platform_map, source = get_platforms(limit=limit)
    findings: List[UsernameFinding] = []

    with ThreadPoolExecutor(max_workers=min(workers, len(platform_map))) as executor:
        futures = {
            executor.submit(_check_platform, platform, url_template.format(username=username)): platform
            for platform, url_template in platform_map.items()
        }
        for future in as_completed(futures):
            findings.append(future.result())

    findings.sort(key=lambda x: x.platform.lower())
    return {
        "username": username,
        "source": source,
        "platforms_scanned": len(platform_map),
        "accounts": [asdict(f) for f in findings if f.exists],
        "all_results": [asdict(f) for f in findings],
    }


def export_username_results(data: Dict, output_dir: str = "reports") -> Dict[str, str]:
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    json_path = target_dir / f"username_{data['username']}.json"
    csv_path = target_dir / f"username_{data['username']}.csv"

    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["platform", "url", "exists", "status_code", "detected"])
        writer.writeheader()
        writer.writerows(data["all_results"])

    return {"json": str(json_path), "csv": str(csv_path)}
