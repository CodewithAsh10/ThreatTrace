# VulnGuard — Smart Vulnerability Scanner System

Automated web vulnerability scanner for SQL Injection, XSS, missing security headers, and input validation issues. Runs entirely on `localhost:5000` with **no database**, **no Docker**, and **no npm** — just Python.

---

## Quick-Start Setup

1. **Clone / download** the project folder.

2. **Create a virtual environment**
   - **Windows:** `python -m venv venv` then `venv\Scripts\activate`
   - **macOS/Linux:** `python -m venv venv` then `source venv/bin/activate`

3. **Install dependencies:** `pip install -r requirements.txt`

4. **Run the app:** `python app.py`

5. **Open browser:** [http://localhost:5000](http://localhost:5000)

---

## Project Structure

```
vulnguard/
├── app.py                       # Flask application entry point
├── config.py                    # Configuration constants
├── requirements.txt             # Python dependencies
├── README.md                    # This file
│
├── scanner/                     # Vulnerability detection modules
│   ├── __init__.py
│   ├── crawler.py               # HTTP request & form extraction
│   ├── sql_injection_scanner.py # SQLi detection (error-based & blind)
│   ├── xss_scanner.py           # XSS detection (reflected)
│   ├── header_scanner.py        # Security header validation
│   ├── input_validation_scanner.py # Form input validation checks
│   └── payloads/                # Attack payload files
│       ├── sqli_payloads.txt
│       └── xss_payloads.txt
│
├── reports/                     # Report generation & analysis
│   ├── __init__.py
│   ├── severity_classifier.py   # Severity scoring & classification
│   ├── mitigation_kb.py         # Remediation guidance database
│   ├── report_generator.py      # Merge & structure findings
│   └── pdf_generator.py         # PDF export
│
├── storage/                     # Scan persistence layer
│   ├── __init__.py
│   └── scan_store.py            # JSON-based storage with thread safety
│
├── results/                     # Completed scan records (auto-created)
│   └── .gitkeep
│
├── static/                      # Frontend assets
│   ├── css/
│   │   └── style.css            # Custom CSS (Tailwind extensions)
│   └── js/
│       └── app.js               # Single-page app logic
│
└── templates/                   # Jinja2 templates
    ├── base.html                # Shared shell
    ├── index.html               # Home page
    ├── scan_progress.html       # Live progress with SSE
    ├── results.html             # Results dashboard
    └── history.html             # Scan history & management
```

---

## Usage Walkthrough

### 1. Home Page
Paste a target URL (e.g., `http://testphp.vulnweb.com`) and choose **Quick Scan** or **Full Scan**. Click **Start Scan**.

### 2. Scan Progress Page
You're redirected to a live progress dashboard showing:
- Overall progress bar (0–100%)
- Module checklist with real-time status icons (⏳ waiting, 🔄 running, ✅ complete)
- Live log of events with timestamps

Updates arrive via Server-Sent Events (SSE) every 1 second until completion or timeout.

### 3. Results Dashboard
When the scan completes, auto-redirects to the results page displaying:
- **Security Score Gauge** — circular SVG showing 0–100 score (green ≥70, yellow 40–69, red <40)
- **Severity Summary Cards** — counts of HIGH, MEDIUM, LOW, and INFO findings
- **Findings Table** — full details per vulnerability (type, parameter, evidence, mitigation)
- **Export Buttons** — Download PDF Report or JSON Report

### 4. Download Reports
- **PDF Report** — Professional security report with branding, score, summary, and findings
- **JSON Report** — Full structured data for integration with other tools

### 5. History Page
Navigate to **History** (top nav) to:
- View all past scans as a filterable/sortable table
- Re-open any scan's results
- Download PDF/JSON for any scan
- Delete completed scans

---

## Scan Modules

| Module | What it checks |
|---|---|
| **SQL Injection Scanner** | URL parameters & form fields via 20+ payloads; error-based detection (DB error texts) and blind detection (response timing/length) |
| **XSS Scanner** | URL parameters & form fields via 20+ payloads; unescaped reflection detection |
| **Header Analyzer** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Strict-Transport-Security, Referrer-Policy, Permissions-Policy |
| **Input Validation Scanner** | Missing HTML5 constraints: `required`, `maxlength`, `pattern`, `type`; hidden fields; HTTP (non-HTTPS) form actions |

---

## Scoring System

Score starts at **100** and deducts per finding:

| Severity | Deduction |
|---|---|
| HIGH | −25 |
| MEDIUM | −15 |
| LOW | −5 |
| INFO | −1 |

**Minimum score: 0**

**Gauge color:**
- 🟢 **Green:** ≥ 70 (Good)
- 🟡 **Yellow:** 40–69 (Needs Improvement)
- 🔴 **Red:** < 40 (Critical)

---

## Safety & Responsible Disclosure

⚠️ **VulnGuard performs passive, read-only testing only.** It does not:
- Exploit or modify the target
- Store sensitive data
- Persist credentials or session tokens
- Bypass authentication

**Always obtain written permission before scanning any website you do not own.**

---

## Results Persistence

Completed scans are saved automatically to `results/scan_<scan_id>.json`. On the next startup (`python app.py`), all prior scans are reloaded from disk into memory — **no database required**. Deleting a scan from the History page removes it from both memory and disk.

---

## Technology Stack

- **Backend:** Flask (Python 3.10+)
- **Frontend:** Jinja2 templates + Tailwind CSS + Vanilla JavaScript + SSE
- **PDF Generation:** ReportLab
- **HTTP Inspection:** requests + BeautifulSoup4
- **Threading:** Python `threading` module (daemon threads, RLock for sync)
- **Deployment:** None — runs locally with `python app.py`

---

## License

MIT License — See LICENSE file (if included) for details.
