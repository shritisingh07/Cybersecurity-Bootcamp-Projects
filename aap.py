"""
Basic Web Security Header and CORS Checker
For educational use on websites you own or are authorized to assess.

Install dependency:
    python -m pip install -r requirements.txt

Run:
    python aap.py
"""

import ipaddress
import json
import socket
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests


SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps browsers use HTTPS for future connections.",
    "Content-Security-Policy": "Helps control which sources a browser may load content from.",
    "X-Content-Type-Options": "The nosniff value helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Can help control whether a page can be embedded in a frame.",
    "Referrer-Policy": "Controls how much referrer information browsers send.",
    "Permissions-Policy": "Controls access to supported browser features.",
}

TIMEOUT_SECONDS = 8
MAX_RESPONSE_BYTES = 1_000_000


def normalize_url(user_input):
    """Validate a URL and add HTTPS when no scheme is supplied."""
    value = user_input.strip()
    if not value:
        raise ValueError("Please enter a website address.")

    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise ValueError("The URL must include a valid hostname.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames or passwords are not allowed.")
    if parsed.port and not (1 <= parsed.port <= 65535):
        raise ValueError("The port number is invalid.")

    return value, parsed


def validate_public_host(hostname):
    """Reject localhost and hostnames resolving to non-public IP addresses."""
    if hostname.lower() in ("localhost", "localhost.localdomain"):
        raise ValueError("Localhost addresses are not allowed.")

    try:
        addresses = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Could not resolve this hostname. Check the URL and connection.") from exc

    if not addresses:
        raise ValueError("No IP address was found for this hostname.")

    for address in addresses:
        ip_text = address[4][0].split("%")[0]
        try:
            ip_obj = ipaddress.ip_address(ip_text)
        except ValueError as exc:
            raise ValueError("The hostname resolved to an invalid IP address.") from exc
        if not ip_obj.is_global:
            raise ValueError(
                "This hostname resolves to a private or restricted address. "
                "For safety, this scanner only checks public website addresses."
            )


def get_cors_findings(headers):
    """Summarize visible CORS response headers without claiming exploitability."""
    names = (
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Vary",
    )
    findings = {}
    for name in names:
        value = headers.get(name)
        findings[name] = value if value else "Not present in this response"

    origin = headers.get("Access-Control-Allow-Origin", "").strip()
    credentials = headers.get("Access-Control-Allow-Credentials", "").strip().lower()

    notes = []
    if not origin:
        notes.append(
            "No Access-Control-Allow-Origin header was observed. This is not automatically a vulnerability."
        )
    elif origin == "*":
        notes.append(
            "Wildcard origin was observed. Whether this is appropriate depends on the resource; "
            "wildcard origin cannot be used for credentialed browser access."
        )
    else:
        notes.append(
            "A specific or reflected origin was observed. Review whether it is intentionally allowed."
        )

    if credentials == "true":
        notes.append(
            "Access-Control-Allow-Credentials is true. Review together with the allowed origin; "
            "this alone does not prove a vulnerability."
        )

    notes.append(
        "This is a basic response-header check, not a complete browser-based CORS security test."
    )
    return findings, notes


def scan_website(url):
    """Make one non-intrusive GET request without following redirects."""
    _, parsed = normalize_url(url)
    validate_public_host(parsed.hostname)

    headers = {
        "User-Agent": "Basic-Web-Security-Checker/1.0 (educational use)",
        "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
        "Origin": "https://scanner.invalid",
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=TIMEOUT_SECONDS,
        allow_redirects=False,
        stream=True,
    )

    try:
        # Avoid downloading a large response body; only headers/status are needed.
        response.raw.read(MAX_RESPONSE_BYTES, decode_content=True)
        result = {
            "scan_timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "input_url": url,
            "final_url": response.url,
            "http_status": response.status_code,
            "https_used_in_input": parsed.scheme.lower() == "https",
            "redirect_not_followed": 300 <= response.status_code < 400,
            "location_header": response.headers.get("Location"),
            "security_headers": {},
            "cors_headers": {},
            "cors_notes": [],
            "errors": [],
            "limitations": [
                "Only one ordinary GET request was made; redirects were not followed.",
                "Missing headers do not automatically mean a website is vulnerable.",
                "This tool does not prove that a website is secure or detect all vulnerabilities.",
                "Use only on websites you own or are authorized to assess.",
            ],
        }

        for name, explanation in SECURITY_HEADERS.items():
            value = response.headers.get(name)
            result["security_headers"][name] = {
                "status": "Present" if value else "Missing",
                "value": value,
                "purpose": explanation,
                "note": (
                    "Review whether this header is appropriate for the application."
                    if value
                    else "Consider whether this header is appropriate for the application."
                ),
            }

        cors_findings, cors_notes = get_cors_findings(response.headers)
        result["cors_headers"] = cors_findings
        result["cors_notes"] = cors_notes
        return result
    finally:
        response.close()


def print_report(result):
    """Print findings in a readable format."""
    print("\n" + "=" * 58)
    print("BASIC WEB SECURITY SCAN REPORT")
    print("=" * 58)
    print(f"URL: {result['input_url']}")
    print(f"HTTP status: {result['http_status']}")
    print(f"HTTPS used in input: {'Yes' if result['https_used_in_input'] else 'No'}")

    if result["redirect_not_followed"]:
        print("Redirect: A redirect was returned and was not followed for safety.")
        if result.get("location_header"):
            print(f"Redirect destination: {result['location_header']}")

    print("\n1. SECURITY HEADERS")
    for name, item in result["security_headers"].items():
        print(f"\n{name}: {item['status']}")
        if item["value"]:
            print(f"  Value: {item['value']}")
        print(f"  Purpose: {item['purpose']}")
        print(f"  Note: {item['note']}")

    print("\n2. CORS RESPONSE HEADERS")
    for name, value in result["cors_headers"].items():
        print(f"{name}: {value}")

    print("\nCORS notes:")
    for note in result["cors_notes"]:
        print(f"- {note}")

    print("\nLIMITATIONS")
    for note in result["limitations"]:
        print(f"- {note}")


def save_json_report(result):
    """Save the report to a timestamped JSON file."""
    reports_dir = Path(__file__).resolve().parent / "reports"
    reports_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = reports_dir / f"scan_report_{timestamp}.json"

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=2, ensure_ascii=False)

    return output_path


def main():
    print("=" * 58)
    print("BASIC WEB SECURITY HEADER AND CORS CHECKER")
    print("=" * 58)
    print("Educational tool: checks basic response headers only.")
    print("Scan only websites you own or are authorized to assess.")
    print("This tool cannot prove that a website is completely secure.\n")

    user_input = input("Enter a website URL (example.com or https://example.com): ").strip()

    try:
        normalized_url, _ = normalize_url(user_input)
        print(f"\nTarget: {normalized_url}")
        print("Running basic checks. Please wait...")
        result = scan_website(normalized_url)
        print_report(result)

        choice = input("\nSave these results as a JSON report? (y/n): ").strip().lower()
        if choice in ("y", "yes"):
            try:
                output_path = save_json_report(result)
                print(f"Report saved to: {output_path}")
            except OSError as exc:
                print(f"Could not save the report: {exc}")

    except ValueError as exc:
        print(f"\nInput/validation problem: {exc}")
    except requests.exceptions.SSLError:
        print("\nConnection problem: TLS certificate verification failed. "
              "The scanner did not disable certificate verification.")
    except requests.exceptions.Timeout:
        print("\nConnection problem: the website took too long to respond.")
    except requests.exceptions.ConnectionError:
        print("\nConnection problem: could not connect to the website. "
              "Check the URL and your internet connection.")
    except requests.exceptions.RequestException as exc:
        print(f"\nHTTP request problem: {exc}")
    except KeyboardInterrupt:
        print("\nScan cancelled by user.")
    except Exception as exc:
        print(f"\nUnexpected error: {exc}")
        print("Please save this error message and ask for help debugging it.")


if __name__ == "__main__":
    main()
