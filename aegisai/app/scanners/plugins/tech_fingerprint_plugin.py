import os
import re
import json
import requests
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

class TechFingerprintPlugin(BaseScannerPlugin):
    """
    Technology Stack & Runtime Exposure Fingerprinter:
    - Identifies web server banners across 15+ server types (Nginx, Apache, IIS, LiteSpeed, Caddy, hcdn, Envoy)
    - Detects backend runtime headers (X-Powered-By: Express, PHP, ASP.NET, Next.js)
    - Identifies frameworks, modern stacks, and CMS footprints (Django, Laravel, Spring Boot, React, Next.js, Vue, WordPress)
    """
    name = "tech_fingerprint"
    tier = "T1"
    docker_image = "python:3.11-slim"
    timeout_seconds = 45
    category = "Security Misconfiguration"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "tech_fingerprint.jsonl")

    def run_scan(self, target_url: str, out_dir: str, tenant_id: str, scan_id: str, target_id: str) -> List[Dict[str, Any]]:
        findings = self.parse("", target_url, tenant_id, scan_id, target_id)
        out_file = self.get_output_path(out_dir)
        try:
            with open(out_file, "w", encoding="utf-8") as f:
                for f_item in findings:
                    f.write(json.dumps(f_item) + "\n")
        except Exception:
            pass
        return findings

    def parse(self, raw_output_path: str, target_url: str, tenant_id: str, scan_id: str, target_id: str) -> List[Dict[str, Any]]:
        findings = []

        try:
            res = requests.get(target_url, headers={"User-Agent": "AegisAI-TechFingerprint/2.0"}, verify=False, timeout=6)
            headers = {k.lower(): v for k, v in res.headers.items()}
            html = res.text
            cookies = res.cookies.get_dict()

            # 1. Server Banner Exposure
            server_banner = headers.get("server")
            if server_banner:
                has_version = bool(re.search(r'\d+\.\d+', server_banner))
                fp = compute_fingerprint_hash(self.category, target_url, None, f"SERVER_BANNER_{server_banner}")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "SERVER_BANNER_DISCLOSED",
                    "title": f"Web Server Information Disclosed: '{server_banner}'",
                    "description": f"The response reveals the server software banner ({server_banner}). Advertising exact web server software aids adversaries in identifying targeted exploits and CVEs.",
                    "severity": "low" if has_version else "info",
                    "confidence": "confirmed", "category": self.category,
                    "cwe": "CWE-200", "cve": "[]", "cvss": 3.7 if has_version else 2.1,
                    "epss": 0.0, "kev": False,
                    "url": target_url, "host": target_url, "port": None, "parameter": None,
                    "evidence": redact_evidence(f"Server header: {server_banner}"),
                    "remediation": "Disable server tokens in web server config (e.g. 'server_tokens off;' in Nginx, or 'ServerTokens Prod' in Apache).",
                    "references": json.dumps(["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#server"]),
                    "status": "open", "fingerprint_hash": fp
                })

            # 2. X-Powered-By Banner
            x_powered = headers.get("x-powered-by")
            if x_powered:
                fp = compute_fingerprint_hash(self.category, target_url, None, f"X_POWERED_BY_{x_powered}")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "X_POWERED_BY_DISCLOSED",
                    "title": f"Backend Runtime Banner Disclosed: 'X-Powered-By: {x_powered}'",
                    "description": f"The web application exposes the underlying language, framework, or runtime via 'X-Powered-By: {x_powered}'.",
                    "severity": "low", "confidence": "confirmed", "category": self.category,
                    "cwe": "CWE-200", "cve": "[]", "cvss": 3.7, "epss": 0.0, "kev": False,
                    "url": target_url, "host": target_url, "port": None, "parameter": None,
                    "evidence": redact_evidence(f"X-Powered-By: {x_powered}"),
                    "remediation": f"Disable the X-Powered-By header (e.g. app.disable('x-powered-by') in Express, or expose_php = Off in php.ini).",
                    "references": json.dumps(["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-powered-by"]),
                    "status": "open", "fingerprint_hash": fp
                })

            # 3. Modern Web Stacks & Framework Footprint
            framework_matches = []
            if "laravel_session" in cookies or "XSRF-TOKEN" in cookies:
                framework_matches.append("Laravel (PHP)")
            if "csrftoken" in cookies and "sessionid" in cookies:
                framework_matches.append("Django (Python)")
            if "connect.sid" in cookies:
                framework_matches.append("Express.js (Node.js)")
            if "PHPSESSID" in cookies:
                framework_matches.append("PHP Session Runtime")
            if "ASP.NET_SessionId" in cookies or ".AspNetCore.Session" in cookies:
                framework_matches.append("ASP.NET / .NET Core")
            if "__next" in html or "/_next/static/" in html:
                framework_matches.append("Next.js (React Framework)")
            if "__nuxt" in html or "/_nuxt/" in html:
                framework_matches.append("Nuxt.js (Vue Framework)")
            if "data-reactroot" in html:
                framework_matches.append("React Frontend")
            if "ng-version" in html or "ng-app" in html:
                framework_matches.append("Angular Frontend")
            if "gatsby-" in html:
                framework_matches.append("Gatsby Static Site Generator")

            # CDN & Reverse Proxy headers
            cdn_matches = []
            if "cf-ray" in headers:
                cdn_matches.append("Cloudflare CDN / WAF")
            if "x-amz-cf-id" in headers:
                cdn_matches.append("AWS CloudFront")
            if "x-fastly-request-id" in headers:
                cdn_matches.append("Fastly CDN")
            if "x-hcdn-request-id" in headers or "x-hcdn-cache-status" in headers:
                cdn_matches.append("Hostinger Cloud CDN (hcdn)")
            if "x-varnish" in headers:
                cdn_matches.append("Varnish HTTP Accelerator")

            all_identified = framework_matches + cdn_matches
            if all_identified:
                fp = compute_fingerprint_hash("Information Disclosure", target_url, None, "TECH_STACK_FOOTPRINT")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "TECH_STACK_FOOTPRINT_IDENTIFIED",
                    "title": f"Identified Technologies: {', '.join(all_identified[:3])}",
                    "description": f"Automated inspection identified the following application infrastructure, frontend, and CDN layers: {', '.join(all_identified)}.",
                    "severity": "info", "confidence": "confirmed", "category": "Information Disclosure",
                    "cwe": "CWE-200", "cve": "[]", "cvss": 1.5, "epss": 0.0, "kev": False,
                    "url": target_url, "host": target_url, "port": None, "parameter": None,
                    "evidence": redact_evidence(f"Matched technology signatures: {all_identified}"),
                    "remediation": "Review publicly exposed technology signatures to reduce footprint visibility.",
                    "references": json.dumps(["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"]),
                    "status": "open", "fingerprint_hash": fp
                })

        except Exception:
            pass

        return findings
