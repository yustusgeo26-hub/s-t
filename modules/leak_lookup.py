import hashlib
from typing import Dict
from urllib.error import URLError
from urllib.request import Request, urlopen


def password_pwned_count(password: str) -> Dict:
    if not password:
        return {"error": "Password cannot be empty"}

    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]

    try:
        req = Request(f"https://api.pwnedpasswords.com/range/{prefix}", headers={"User-Agent": "YUSTUS-OSINT/2.0"})
        with urlopen(req, timeout=10) as res:
            body = res.read().decode("utf-8")
        for line in body.splitlines():
            if ":" not in line:
                continue
            hash_suffix, count = line.split(":", 1)
            if hash_suffix.strip() == suffix:
                return {"pwned": True, "count": int(count.strip())}
        return {"pwned": False, "count": 0}
    except (URLError, TimeoutError, ValueError) as e:
        return {"error": str(e)}
