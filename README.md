# YUSTUS OSINT v2 — Elite Cyber Investigator Tool

YUSTUS is a modular OSINT toolkit for professional investigations, incident response, and cyber threat research.

## Key Features

- Sherlock-style **300+ website username scan** (auto-loads Sherlock site list when internet is available).
- Email intelligence (validation, reputation lookup, breach indicators).
- Domain intelligence (WHOIS, DNS records, SSL details, and subdomain finder).
- IP intelligence (geo/ISP/ASN/reverse DNS).
- Phone number intelligence.
- Website intelligence (title, meta, emails, social links, tech fingerprints).
- Image metadata analysis (EXIF/GPS).
- Google dork automation.
- Network scanning (Nmap if installed, otherwise built-in socket scanner).
- Password leak search (Have I Been Pwned k-anonymity API).
- Parallel intelligence scan and full investigation report generation (JSON/CSV/HTML).

## Project Structure

```text
yustus/
├── yustus.py
├── modules/
│   ├── username_scan.py
│   ├── email_lookup.py
│   ├── domain_lookup.py
│   ├── ip_lookup.py
│   ├── phone_lookup.py
│   ├── web_analyzer.py
│   ├── image_metadata.py
│   ├── dorking.py
│   ├── network_scan.py
│   └── leak_lookup.py
├── reports/
└── logs/
```

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python yustus.py
```

## Show me how it looks

You can run a non-interactive UI preview:

```bash
python yustus.py --preview
```

Example output:

```text
YUSTUS OSINT v2 — Elite Cyber Investigator Tool
1 Username Intelligence (Sherlock style, 300+ sites)
2 Email Intelligence
3 Domain Intelligence + Subdomain Finder
...
13 Exit

=== Preview: Username Intelligence ===
- platforms_scanned: 320
- found_accounts: 4
```

## How to Use (Quick)

1. Start the tool:
   ```bash
   python yustus.py
   ```
2. Choose an option from the menu:
   - `1` Username Intelligence (300+ platforms)
   - `8` Google Dork Automation
   - `9` Network Scanning
   - `10` Password Leak Search
   - `12` Generate Investigation Report
3. Reports are saved in `reports/`.
4. Logs are written to `logs/yustus.log`.

## Notes

- If optional packages are missing, YUSTUS continues running and returns structured error messages.
- For option `9`, install `nmap` on your OS for advanced service detection output.
