# VulnGuard — Smart Vulnerability Scanner System

VulnGuard is a web vulnerability scanner built to automate practical security checks for modern web applications. It crawls targets, runs multi-module security analysis, streams live scan progress, and generates remediation-focused reports with severity scoring.

## Tech Stack

![Python](https://img.shields.io/badge/Python-3.8%2B-84cc16?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask&logoColor=white)
![Jinja2](https://img.shields.io/badge/Jinja2-Template%20Engine-b41717?style=flat-square)
![JavaScript](https://img.shields.io/badge/JavaScript-ES6-f7df1e?style=flat-square&logo=javascript&logoColor=black)
![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-Utility%20CSS-06b6d4?style=flat-square&logo=tailwindcss&logoColor=white)
![ReportLab](https://img.shields.io/badge/ReportLab-PDF%20Reports-6b7280?style=flat-square)
![BeautifulSoup4](https://img.shields.io/badge/BeautifulSoup4-HTML%20Parsing-10b981?style=flat-square)
![Requests](https://img.shields.io/badge/Requests-HTTP%20Client-3b82f6?style=flat-square)

## Key Features

- Automated vulnerability scanning for SQL Injection, XSS, security headers, and input-validation weaknesses.
- Live scan progress with module-level status, animated counters, and event logs.
- Results dashboard with narrative summary, score gauge, severity distribution donut, and module-wise bars.
- Severity classification with mitigation guidance for each finding.
- Exportable JSON and PDF reports for documentation and review.
- Scan history view with quick re-open, download, and delete actions.

## Quick-Start Setup

1. Clone or download the project.
2. Create a virtual environment:
     - Windows: `python -m venv venv` then `venv\Scripts\activate`
     - macOS/Linux: `python -m venv venv` then `source venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Run the application: `python app.py`
5. Open in browser: http://localhost:5000

## Usage Walkthrough 

1. Enter a target URL on the home page and start the scan.
2. Monitor real-time progress, module status, counters, and logs.
3. Review results: score, severity summary, findings table, and charts.
4. Export the report as PDF or JSON.
5. Use History to reopen, download, or delete past scans.

## Project Structure

```text
vulnguard/
├── app.py
├── config.py
├── requirements.txt
├── README.md
├── scanner/
│   ├── crawler.py
│   ├── scan_controller.py
│   ├── sql_injection_scanner.py
│   ├── xss_scanner.py
│   ├── header_scanner.py
│   ├── input_validation_scanner.py
│   └── payloads/
├── reports/
│   ├── severity_classifier.py
│   ├── mitigation_kb.py
│   ├── report_generator.py
│   └── pdf_generator.py
├── storage/
│   └── scan_store.py
├── results/
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       ├── app.js
│       └── matrix.js
└── templates/
        ├── base.html
        ├── index.html
        ├── scan_progress.html
        ├── results.html
        └── history.html
```
### Tech Stack

- Backend: Python, Flask
- Frontend: Jinja2 templates, Tailwind CSS, Vanilla JavaScript
- Networking and Parsing: Requests, BeautifulSoup4, urllib3
- Reporting: ReportLab (PDF)
- Runtime: Server-Sent Events (SSE), Python threading

## Scan Modules

- SQL Injection Scanner: Tests URL params and form fields using payload-based SQLi checks.
- XSS Scanner: Detects reflective script injection through payload reflection analysis.
- Header Analyzer: Validates critical security headers and highlights missing/misconfigured headers.
- Input Validation Scanner: Flags weak client-side input constraints and unsafe form behavior.

## Scoring System

- Score starts at 100.
- Deduction per finding:
    - HIGH: -25
    - MEDIUM: -15
    - LOW: -5
    - INFO: -0

Score bands:
- Green: 70 and above
- Yellow: 40 to 69
- Red: below 40

## Project Team

- Yash Tripathi : 24BCE10603
- Mohit Bankar : 24BCE11104
- Neel Pandey : 24BCE10303
- Arsh Bakshi : 24BCE10568
- Ayush Man Singh Bhadauria : 24BCE10404

## Supervisor

- Dr. Nilesh Kunhare

## Reviewer

- Dr.Gaurav Soni
- Dr.Ravi Verma

## License

This project is for educational purposes.
