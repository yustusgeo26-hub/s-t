from typing import Dict

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone
except Exception:
    phonenumbers = None


def lookup_phone(phone: str, region: str = "US") -> Dict:
    result = {
        "input": phone,
        "valid": False,
        "possible": False,
        "country": None,
        "carrier": None,
        "timezone": [],
        "international": None,
    }

    if phonenumbers is None:
        result["error"] = "phonenumbers dependency is not installed"
        return result

    try:
        parsed = phonenumbers.parse(phone, region)
        result["possible"] = phonenumbers.is_possible_number(parsed)
        result["valid"] = phonenumbers.is_valid_number(parsed)
        result["country"] = geocoder.description_for_number(parsed, "en")
        result["carrier"] = carrier.name_for_number(parsed, "en")
        result["timezone"] = list(timezone.time_zones_for_number(parsed))
        result["international"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    except Exception as e:
        result["error"] = str(e)

    return result
