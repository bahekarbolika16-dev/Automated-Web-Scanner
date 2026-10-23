# Automated Web Scanner

A beginner-friendly Python cyber security project that performs a **basic, passive check** of HTTP security headers and CORS-related response headers.

## Features
- Checks common security headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy.
- Displays HTTP status and whether the final URL uses HTTPS.
- Reports basic CORS response settings.
- Can save results to a JSON file.
- Uses one normal GET request; it does not exploit vulnerabilities or attempt authentication bypass.

## Requirements
- Python 3.9 or newer
- `requests` library

## Setup
```bash
python -m venv .venv
```
Activate the environment:
- Windows: `.venv\Scripts\activate`
- macOS/Linux: `source .venv/bin/activate`

Install dependencies:
```bash
pip install -r requirements.txt
```

## Run
Only scan websites you own or have explicit permission to assess.

```bash
python automated_web_scanner.py https://example.com
```

Save a JSON report:
```bash
python automated_web_scanner.py https://example.com --json report.json
```

## Jupyter Notebook
Open `YourName_AutomatedWebScanner.ipynb` in Jupyter Notebook or Google Colab and run the cells in order. Replace the example URL with a site you are authorized to test.

## Understanding the results
A missing header is a review item, not automatic proof that a site is vulnerable. CORS behavior depends on request context and browser enforcement. Review results with the website owner and the application's security requirements.

## Limitations
- This is an educational first-pass scanner, not a full penetration-testing tool.
- It does not crawl pages, test authenticated routes, or prove exploitability.
- Network errors, redirects, proxies, and server-specific behavior can affect results.

## Project files
- `automated_web_scanner.py` — command-line scanner
- `YourName_AutomatedWebScanner.ipynb` — notebook version
- `requirements.txt` — dependency list
- `YourName_ProjectReport.docx` — project report
