import json
import socket
import ssl
from typing import Dict, List
from urllib.error import URLError
from urllib.request import Request, urlopen

try:
    import dns.resolver
except Exception:
    dns = None

try:
    import whois
except Exception:
    whois = None


COMMON_SUBDOMAINS = ["www", "mail", "api", "dev", "staging", "cdn", "blog", "m", "app", "portal"]
USER_AGENT = "YUSTUS-OSINT/2.0"


def _safe_dns_query(domain: str, record_type: str) -> List[str]:
    if dns is None:
        return []
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=5)
        return [str(rdata).strip() for rdata in answers]
    except Exception:
        return []


def _crtsh_subdomains(domain: str) -> List[str]:
    try:
        req = Request(f"https://crt.sh/?q=%25.{domain}&output=json", headers={"User-Agent": USER_AGENT})
        with urlopen(req, timeout=12) as res:
            data = json.loads(res.read().decode("utf-8"))
        names = set()
        for item in data:
            for name in item.get("name_value", "").split("\n"):
                cleaned = name.strip().lower()
                if cleaned.endswith(domain):
                    names.add(cleaned)
        return sorted(names)
    except Exception:
        return []


def _bruteforce_subdomains(domain: str) -> List[str]:
    found = []
    for sub in COMMON_SUBDOMAINS:
        candidate = f"{sub}.{domain}"
        try:
            socket.gethostbyname(candidate)
            found.append(candidate)
        except socket.gaierror:
            continue
    return found


def _hosting_provider(domain: str) -> str:
    try:
        ip = socket.gethostbyname(domain)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def _ssl_info(domain: str) -> Dict:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
        return {
            "subject": cert.get("subject", []),
            "issuer": cert.get("issuer", []),
            "notAfter": cert.get("notAfter"),
        }
    except Exception as e:
        return {"status": f"SSL lookup failed: {e}"}


def lookup_domain(domain: str) -> Dict:
    result: Dict = {
        "domain": domain,
        "whois": {},
        "dns": {},
        "subdomains": [],
        "hosting_provider": "Unknown",
        "ssl": {},
    }

    if whois is not None:
        try:
            w = whois.whois(domain)
            result["whois"] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "emails": w.emails,
            }
        except Exception as e:
            result["whois_error"] = str(e)
    else:
        result["whois_error"] = "python-whois dependency is not installed"

    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        result["dns"][rtype] = _safe_dns_query(domain, rtype)

    crt = _crtsh_subdomains(domain)
    brute = _bruteforce_subdomains(domain)
    result["subdomains"] = sorted(set(crt + brute))
    result["hosting_provider"] = _hosting_provider(domain)
    result["ssl"] = _ssl_info(domain)

    return result
