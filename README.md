# AegisAI - Detection-Only Vulnerability Scanning Platform

AegisAI by **Provilance Technologies** is an advanced, non-destructive, detection-only Web Application Security & Vulnerability Scanning SaaS platform.

## Key Architecture & Features
- **15+ Specialized Security Audit Tools:**
  - **Nuclei:** 13,000+ detection-only vulnerability templates
  - **OWASP ZAP Baseline:** Passive security headers and cookie flags auditor
  - **Deep CSP Auditor:** Comprehensive Content Security Policy directive prober
  - **Retire.js:** Client-side JavaScript vulnerability detection (20+ frameworks, 50+ CVEs)
  - **Subdomain Takeover:** Dangling DNS CNAME resolution for 22+ cloud SaaS providers
  - **Sensitive Asset Prober:** 60+ critical file and secret exposure vectors (.env, keys, git, dumps)
  - **API Security:** OpenAPI 3.0, Swagger UI, GraphQL Introspection, and Postman collections
  - **TLS / SSL Auditor:** Certificate validity, deprecated protocols (TLS 1.0/1.1), and weak ciphers
  - **Technology Fingerprinter:** Server software (Nginx, Apache, hcdn), runtimes (Express, PHP), and frontend frameworks
  - **WPScan & CMS Auditor:** WordPress, Drupal, and Joomla exposure prober
  - **HTTP Methods & XST:** Cross-Site Tracing (TRACE method) and dangerous method detection
  - **Input Parameter Hygiene:** Safe canary reflection and verbose database error disclosures (T2 with consent)
- **Real-Time Threat Intelligence:**
  - Live CISA KEV (Known Exploited Vulnerabilities) sync
  - Real-time FIRST.org EPSS (Exploit Prediction Scoring System) probability scoring
- **Strict SSRF & Isolation Guardrails:**
  - Pre-flight DNS resolution blocking internal networks (`10/8`, `172.16/12`, `192.168/16`, `127/8`) and Cloud metadata (`169.254.169.254`)
  - Permanent prohibition of exploit-capable (T3) tools
- **Reports & Multi-Format Exports:**
  - Provilance Technologies branded executive PDF reports
  - SARIF 2.1 (GitHub code-scanning format)
  - Full JSON and CSV exports
- **Multi-Tenant SaaS Architecture:**
  - JWT authentication with tenant-scoped isolation
  - Append-only cryptographic audit logging

## Getting Started

### 1. Requirements
- Python 3.10+
- Dependencies in `aegisai/requirements.txt`

### 2. Run the Web Application
```bash
cd aegisai
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Open `http://localhost:8000/` in your browser. Default Admin: `admin@aegisai.com` / `admin123`.
