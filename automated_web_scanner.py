"""
Automated Web Scanner
Checks common HTTP security headers and basic CORS configuration.
Use only on websites you own or have explicit permission to assess.
"""
import argparse
import json
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps enforce HTTPS connections.",
    "Content-Security-Policy": "Helps reduce cross-site scripting and content injection risks.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "X-Frame-Options": "Helps reduce clickjacking risk.",
    "Referrer-Policy": "Controls referrer information sent by the browser.",
    "Permissions-Policy": "Restricts access to browser features.",
}

def validate_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Enter a valid URL starting with http:// or https://")
    return url

def scan_website(url, timeout=10):
    """Make one ordinary GET request and report observable configuration."""
    validate_url(url)
    result = {
        "url": url,
        "final_url": None,
        "status_code": None,
        "https": urlparse(url).scheme == "https",
        "security_headers": {},
        "cors": {},
        "errors": [],
    }

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "Educational-Web-Security-Scanner/1.0"},
        )
        result["final_url"] = response.url
        result["status_code"] = response.status_code
        result["https"] = urlparse(response.url).scheme == "https"

        for header, purpose in SECURITY_HEADERS.items():
            value = response.headers.get(header)
            result["security_headers"][header] = {
                "present": value is not None,
                "value": value,
                "purpose": purpose,
            }

        acao = response.headers.get("Access-Control-Allow-Origin")
        acac = response.headers.get("Access-Control-Allow-Credentials")
        result["cors"] = {
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": acac,
            "wildcard_origin_with_credentials": acao == "*" and str(acac).lower() == "true",
            "note": (
                "Review this configuration. A wildcard origin with credentials is generally rejected by browsers, "
                "but broad CORS policies still deserve review."
                if acao == "*" else
                "No wildcard origin detected in this response; verify allowed origins against your intended policy."
            ),
        }
    except requests.RequestException as exc:
        result["errors"].append(f"Request failed: {exc}")

    return result

def print_report(report):
    print("\n=== Automated Web Scanner Report ===")
    print(f"URL: {report['url']}")
    print(f"Final URL: {report['final_url'] or 'Not available'}")
    print(f"HTTP status: {report['status_code'] or 'Not available'}")
    print(f"HTTPS: {'Yes' if report['https'] else 'No'}")

    print("\nSecurity headers:")
    for name, details in report["security_headers"].items():
        status = "PRESENT" if details["present"] else "MISSING"
        print(f"- {name}: {status}")
        if details["value"]:
            print(f"  Value: {details['value']}")

    print("\nCORS:")
    for key, value in report["cors"].items():
        print(f"- {key}: {value}")

    if report["errors"]:
        print("\nErrors:")
        for error in report["errors"]:
            print(f"- {error}")

def main():
    parser = argparse.ArgumentParser(description="Check common web security headers and basic CORS settings.")
    parser.add_argument("url", help="Website URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--json", dest="json_path", help="Optional path to save the raw report as JSON")
    args = parser.parse_args()

    try:
        report = scan_website(args.url, timeout=args.timeout)
    except ValueError as exc:
        parser.error(str(exc))
    print_report(report)

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2, ensure_ascii=False)
        print(f"\nJSON report saved to: {args.json_path}")

if __name__ == "__main__":
    main()
