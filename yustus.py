import argparse
import csv
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table
except Exception:
    Console = None
    Progress = None
    SpinnerColumn = None
    TextColumn = None
    Table = None

from modules.domain_lookup import lookup_domain
from modules.dorking import build_dorks
from modules.email_lookup import analyze_email
from modules.image_metadata import analyze_image
from modules.ip_lookup import lookup_ip
from modules.leak_lookup import password_pwned_count
from modules.network_scan import run_network_scan
from modules.phone_lookup import lookup_phone
from modules.username_scan import export_username_results, scan_username
from modules.web_analyzer import analyze_website

REPORTS_DIR = Path("reports")
LOGS_DIR = Path("logs")
REPORTS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    filename=LOGS_DIR / "yustus.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


class _FallbackConsole:
    def print(self, *args, **kwargs):
        print(*args)

    def input(self, prompt: str) -> str:
        return input(prompt)


console = Console() if Console else _FallbackConsole()


class InvestigationSession:
    def __init__(self) -> None:
        self.data: Dict[str, Any] = {"started_at": datetime.utcnow().isoformat() + "Z"}

    def set_result(self, key: str, result: Dict[str, Any]) -> None:
        self.data[key] = result


def menu_lines() -> List[str]:
    return [
        "1 Username Intelligence (Sherlock style, 300+ sites)",
        "2 Email Intelligence",
        "3 Domain Intelligence + Subdomain Finder",
        "4 IP Intelligence",
        "5 Phone Intelligence",
        "6 Website Intelligence",
        "7 Image Metadata Analysis",
        "8 Google Dork Automation",
        "9 Network Scanning (Nmap/socket)",
        "10 Password Leak Search",
        "11 Parallel Intelligence Scan",
        "12 Generate Investigation Report",
        "13 Exit",
    ]


def run_with_progress(label: str, fn: Callable[..., Dict[str, Any]], *args: Any, **kwargs: Any) -> Dict[str, Any]:
    if Progress:
        with Progress(SpinnerColumn(), TextColumn("[bold cyan]{task.description}"), transient=True) as progress:
            progress.add_task(description=label, total=None)
            return fn(*args, **kwargs)
    console.print(label)
    return fn(*args, **kwargs)


def display_dict_table(title: str, data: Dict[str, Any]) -> None:
    if Table:
        table = Table(title=title)
        table.add_column("Field", style="bold green")
        table.add_column("Value", style="white")
        for key, value in data.items():
            table.add_row(str(key), json.dumps(value, default=str) if isinstance(value, (dict, list)) else str(value))
        console.print(table)
    else:
        console.print(f"\n=== {title} ===")
        for key, value in data.items():
            console.print(f"- {key}: {value}")


def preview_ui() -> None:
    console.print("\nYUSTUS OSINT v2 — Elite Cyber Investigator Tool")
    for line in menu_lines():
        console.print(line)
    display_dict_table(
        "Preview: Username Intelligence",
        {
            "platforms_scanned": 320,
            "found_accounts": 4,
            "sample_platforms": ["GitHub", "Reddit", "Instagram", "X"],
            "json_export": "reports/username_demo.json",
            "csv_export": "reports/username_demo.csv",
        },
    )


def generate_report(session: InvestigationSession) -> Dict[str, str]:
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_path = REPORTS_DIR / f"investigation_{timestamp}.json"
    csv_path = REPORTS_DIR / f"investigation_{timestamp}.csv"
    html_path = REPORTS_DIR / f"investigation_{timestamp}.html"

    json_path.write_text(json.dumps(session.data, indent=2, default=str), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["section", "content"])
        for section, content in session.data.items():
            writer.writerow([section, json.dumps(content, default=str)])

    html_parts = [
        "<html><head><title>YUSTUS Investigation Report</title></head><body>",
        "<h1>YUSTUS Investigation Report</h1>",
        f"<p>Generated: {datetime.utcnow().isoformat()}Z</p>",
    ]
    for section, content in session.data.items():
        html_parts.append(f"<h2>{section}</h2><pre>{json.dumps(content, indent=2, default=str)}</pre>")
    html_parts.append("</body></html>")
    html_path.write_text("\n".join(html_parts), encoding="utf-8")

    return {"json": str(json_path), "csv": str(csv_path), "html": str(html_path)}


def run_parallel_intelligence(targets: Dict[str, str], session: InvestigationSession) -> Dict[str, str]:
    jobs = {
        "username": (scan_username, (targets["username"],), {}),
        "email": (analyze_email, (targets["email"],), {}),
        "domain": (lookup_domain, (targets["domain"],), {}),
        "ip": (lookup_ip, (targets["ip"],), {}),
        "phone": (lookup_phone, (targets["phone"],), {}),
        "website": (analyze_website, (targets["website"],), {}),
    }
    status = {}
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        future_map = {pool.submit(fn, *args, **kwargs): key for key, (fn, args, kwargs) in jobs.items()}
        for future in as_completed(future_map):
            key = future_map[future]
            try:
                session.set_result(key, future.result())
                status[key] = "completed"
            except Exception as e:
                session.set_result(key, {"error": str(e)})
                status[key] = "failed"
    return status


def menu() -> None:
    session = InvestigationSession()

    while True:
        console.print("\n[bold magenta]YUSTUS OSINT v2 — Elite Cyber Investigator Tool[/bold magenta]" if Console else "\nYUSTUS OSINT v2")
        for line in menu_lines():
            console.print(line)

        choice = console.input("Select option: ").strip()

        try:
            if choice == "1":
                username = console.input("Username: ").strip()
                result = run_with_progress("Running Sherlock-style username scan...", scan_username, username)
                paths = export_username_results(result, REPORTS_DIR)
                session.set_result("username", result)
                display_dict_table("Username Intelligence", {"platforms_scanned": result.get("platforms_scanned"), "found_accounts": len(result.get("accounts", [])), **paths})
            elif choice == "2":
                email = console.input("Email: ").strip()
                result = run_with_progress("Analyzing email...", analyze_email, email)
                session.set_result("email", result)
                display_dict_table("Email Intelligence", result)
            elif choice == "3":
                domain = console.input("Domain: ").strip()
                result = run_with_progress("Gathering domain intelligence...", lookup_domain, domain)
                session.set_result("domain", result)
                display_dict_table("Domain Intelligence", {
                    "domain": domain,
                    "subdomains_found": len(result.get("subdomains", [])),
                    "hosting_provider": result.get("hosting_provider"),
                })
            elif choice == "4":
                ip = console.input("IP Address: ").strip()
                result = run_with_progress("Gathering IP intelligence...", lookup_ip, ip)
                session.set_result("ip", result)
                display_dict_table("IP Intelligence", result)
            elif choice == "5":
                phone = console.input("Phone Number: ").strip()
                result = run_with_progress("Analyzing phone...", lookup_phone, phone)
                session.set_result("phone", result)
                display_dict_table("Phone Intelligence", result)
            elif choice == "6":
                url = console.input("Website URL: ").strip()
                result = run_with_progress("Analyzing website...", analyze_website, url)
                session.set_result("website", result)
                display_dict_table("Website Intelligence", result)
            elif choice == "7":
                image_path = console.input("Image path: ").strip()
                result = run_with_progress("Extracting metadata...", analyze_image, image_path)
                session.set_result("image", result)
                display_dict_table("Image Metadata", result)
            elif choice == "8":
                target = console.input("Domain/keyword for dorks: ").strip()
                result = build_dorks(target)
                session.set_result("google_dorks", result)
                display_dict_table("Google Dorks", {"target": target, "dork_count": len(result["dorks"])})
            elif choice == "9":
                target = console.input("Host/IP for scan: ").strip()
                result = run_with_progress("Running network scan...", run_network_scan, target)
                session.set_result("network_scan", result)
                display_dict_table("Network Scan", {"target": target, "method": result.get("method"), "open_ports": result.get("open_ports", [])})
            elif choice == "10":
                password = console.input("Password to check (k-anon): ").strip()
                result = run_with_progress("Checking leaks with HIBP Pwned Passwords...", password_pwned_count, password)
                session.set_result("password_leaks", result)
                display_dict_table("Password Leak Search", result)
            elif choice == "11":
                targets = {
                    "username": console.input("Username: ").strip(),
                    "email": console.input("Email: ").strip(),
                    "domain": console.input("Domain: ").strip(),
                    "ip": console.input("IP: ").strip(),
                    "phone": console.input("Phone: ").strip(),
                    "website": console.input("Website URL: ").strip(),
                }
                status = run_with_progress("Running parallel intelligence tasks...", run_parallel_intelligence, targets, session)
                display_dict_table("Parallel Scan", status)
            elif choice == "12":
                paths = generate_report(session)
                display_dict_table("Report Generated", paths)
            elif choice == "13":
                console.print("Goodbye from YUSTUS OSINT v2")
                break
            else:
                console.print("Invalid choice.")
            logging.info("Action %s executed", choice)
        except KeyboardInterrupt:
            console.print("Operation interrupted.")
        except Exception as e:
            logging.exception("Unhandled error")
            console.print(f"Error: {e}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="YUSTUS OSINT v2")
    parser.add_argument("--preview", action="store_true", help="Show a non-interactive preview of the CLI UI")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.preview:
        preview_ui()
    else:
        menu()
