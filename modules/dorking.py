from dataclasses import dataclass, asdict
from typing import Dict, List
from urllib.parse import quote_plus


@dataclass
class DorkQuery:
    label: str
    query: str
    google_url: str


def build_dorks(target: str) -> Dict[str, List[Dict[str, str]]]:
    templates = [
        ("Exposed documents", f'site:{target} (ext:pdf OR ext:doc OR ext:xls)'),
        ("Open directories", f'site:{target} intitle:"index of"'),
        ("Login portals", f'site:{target} (inurl:login OR inurl:admin)'),
        ("Config leaks", f'site:{target} (ext:env OR ext:ini OR ext:conf OR ext:sql)'),
        ("Public backups", f'site:{target} (ext:bak OR ext:zip OR ext:tar OR ext:gz)'),
        ("Git exposure", f'site:{target} inurl:.git'),
        ("Email exposure", f'site:{target} "@{target}"'),
        ("API keys hints", f'site:{target} ("api_key" OR "secret" OR "token")'),
    ]
    dorks = []
    for label, query in templates:
        dorks.append(
            asdict(
                DorkQuery(
                    label=label,
                    query=query,
                    google_url=f"https://www.google.com/search?q={quote_plus(query)}",
                )
            )
        )
    return {"target": target, "dorks": dorks}
