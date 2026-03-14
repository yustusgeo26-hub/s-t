import json
from typing import Dict, List
from urllib.error import URLError
from urllib.request import Request, urlopen

try:
    from email_validator import EmailNotValidError, validate_email
except Exception:  # optional dependency fallback
    EmailNotValidError = ValueError

    def validate_email(email: str, check_deliverability: bool = False):
        if "@" not in email or email.count("@") != 1:
            raise ValueError("Invalid email format")

        class _SimpleValidation:
            normalized = email.strip().lower()

        return _SimpleValidation()


USER_AGENT = "YUSTUS-OSINT/2.0"


def _emailrep_lookup(email: str) -> Dict:
    try:
        req = Request(f"https://emailrep.io/{email}", headers={"User-Agent": USER_AGENT})
        with urlopen(req, timeout=10) as res:
            return json.loads(res.read().decode("utf-8"))
    except (URLError, TimeoutError, ValueError):
        return {}


def _holehe_style_guess(domain: str) -> List[str]:
    common_services = {
        "gmail.com": ["Google", "YouTube", "Firebase"],
        "outlook.com": ["Microsoft", "Skype", "OneDrive"],
        "yahoo.com": ["Yahoo", "Flickr"],
        "icloud.com": ["Apple", "iCloud", "App Store"],
        "proton.me": ["ProtonMail", "Proton Pass"],
    }
    return common_services.get(domain.lower(), [])


def analyze_email(email: str) -> Dict:
    result: Dict = {
        "email": email,
        "valid": False,
        "normalized": None,
        "domain": None,
        "username_part": None,
        "reputation_score": "unknown",
        "breach_indicators": [],
        "associated_services": [],
    }

    try:
        v = validate_email(email, check_deliverability=False)
        normalized = v.normalized
        local, domain = normalized.split("@", 1)
    except Exception as e:
        result["error"] = str(e)
        return result

    result.update(
        {
            "valid": True,
            "normalized": normalized,
            "domain": domain,
            "username_part": local,
            "associated_services": _holehe_style_guess(domain),
        }
    )

    rep = _emailrep_lookup(normalized)
    if rep:
        result["reputation"] = {
            "reputation": rep.get("reputation", "unknown"),
            "suspicious": rep.get("suspicious", False),
            "references": rep.get("references", 0),
        }
        result["reputation_score"] = rep.get("reputation", "unknown")
        details = rep.get("details", {})
        for key in ["blacklisted", "malicious_activity", "credentials_leaked", "data_breach"]:
            if details.get(key):
                result["breach_indicators"].append(key)

    return result
