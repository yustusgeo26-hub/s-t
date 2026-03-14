import re
from html.parser import HTMLParser
from typing import Dict, List
from urllib.error import URLError
from urllib.request import Request, urlopen

EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HREF_PATTERN = re.compile(r'href=["\']([^"\']+)["\']', flags=re.IGNORECASE)
SOCIAL_DOMAINS = [
    "twitter.com",
    "x.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "tiktok.com",
    "youtube.com",
    "github.com",
]


class _MetaParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.title = ""
        self.meta_description = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "meta" and attrs.get("name", "").lower() == "description":
            self.meta_description = attrs.get("content", "")

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data


def _detect_technologies(headers: Dict[str, str], html: str) -> List[str]:
    tech = []
    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    if server:
        tech.append(f"Server: {server}")
    if powered:
        tech.append(f"X-Powered-By: {powered}")

    signatures = {
        "WordPress": "wp-content",
        "React": "react",
        "Vue": "vue",
        "jQuery": "jquery",
        "Bootstrap": "bootstrap",
    }
    lower_html = html.lower()
    for name, marker in signatures.items():
        if marker in lower_html:
            tech.append(name)
    return sorted(set(tech))


def analyze_website(url: str) -> Dict:
    try:
        req = Request(url, headers={"User-Agent": "YUSTUS-OSINT/2.0"})
        with urlopen(req, timeout=12) as response:
            html = response.read().decode("utf-8", errors="replace")
            headers = dict(response.headers.items())
            status_code = getattr(response, "status", 200)
    except (URLError, TimeoutError, ValueError) as e:
        return {"url": url, "error": str(e)}

    parser = _MetaParser()
    parser.feed(html)

    emails = sorted(set(EMAIL_PATTERN.findall(html)))
    links = HREF_PATTERN.findall(html)
    social_links = sorted({link for link in links if any(domain in link for domain in SOCIAL_DOMAINS)})

    return {
        "url": url,
        "status_code": status_code,
        "title": parser.title.strip(),
        "meta_description": parser.meta_description.strip(),
        "emails": emails,
        "social_links": social_links,
        "technologies": _detect_technologies(headers, html),
    }
