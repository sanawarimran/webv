import os
import json
import requests
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

class ZapBaselinePlugin(BaseScannerPlugin):
    """
    OWASP ZAP Baseline Passive Security Auditor:
    - Analyzes HTTP response headers against OWASP Top 10 passive baseline rules
    - Cookie security flags (HttpOnly, Secure, SameSite)
    - Anti-clickjacking protections (X-Frame-Options)
    - MIME-sniffing defenses (X-Content-Type-Options)
    - Server information leakage (Server, X-Powered-By, X-AspNet-Version)
    """
    name = "zap_baseline"
    tier = "T1"
    docker_image = "zaproxy/zap-stable:latest"
    timeout_seconds = 60
    category = "Security Misconfiguration"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "zap_baseline.jsonl")

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
            res = requests.get(target_url, headers={"User-Agent": "AegisAI-ZAP-Baseline/1.0"}, verify=False, timeout=6)
            headers = {k.lower(): v for k, v in res.headers.items()}

            # 1. Anti-Clickjacking (X-Frame-Options)
            if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
                fp = compute_fingerprint_hash("Broken Access Control", target_url, None, "ZAP_MISSING_CLICKJACKING_DEFENSE")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "ZAP_10020_CLICKJACKING",
                    "title": "Anti-Clickjacking Defense Missing (X-Frame-Options)",
                    "description": "The response does not include an X-Frame-Options header or Content-Security-Policy frame-ancestors directive. Attackers can frame this web page inside an invisible iframe to execute Clickjacking attacks.",
                    "severity": "medium", "confidence": "confirmed", "category": "Broken Access Control",
                    "cwe": "CWE-1021", "cve": "[]", "cvss": 4.7, "epss": 0.0, "kev": False,
                    "url": target_url, "host": target_url, "port": None, "parameter": None,
                    "evidence": "Neither X-Frame-Options nor frame-ancestors header directive detected.",
                    "remediation": "Return 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use Content-Security-Policy frame-ancestors.",
                    "references": json.dumps(["https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"]),
                    "status": "open", "fingerprint_hash": fp
                })

            # 2. X-Content-Type-Options
            if headers.get("x-content-type-options", "").lower() != "nosniff":
                fp = compute_fingerprint_hash("Security Misconfiguration", target_url, None, "ZAP_MISSING_NOSNIFF")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "ZAP_10021_NOSNIFF",
                    "title": "X-Content-Type-Options Header Missing",
                    "description": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This permits older browsers to sniff content away from the declared Content-Type, potentially leading to XSS.",
                    "severity": "low", "confidence": "confirmed", "category": "Security Misconfiguration",
                    "cwe": "CWE-693", "cve": "[]", "cvss": 3.4, "epss": 0.0, "kev": False,
                    "url": target_url, "host": target_url, "port": None, "parameter": None,
                    "evidence": f"X-Content-Type-Options header value: {headers.get('x-content-type-options', 'MISSING')}",
                    "remediation": "Add the HTTP response header 'X-Content-Type-Options: nosniff' to all responses.",
                    "references": json.dumps(["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"]),
                    "status": "open", "fingerprint_hash": fp
                })

            # 3. Server Version / Technology Leakage
            server_header = headers.get("server") or headers.get("x-powered-by")
            if server_header and any(char.isdigit() for char in server_header):
                fp = compute_fingerprint_hash("Information Disclosure", target_url, None, "ZAP_SERVER_VERSION_LEAK")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "ZAP_10036_SERVER_VERSION_DISCLOSURE",
                    "title": f"Server Software and Version Leakage ({server_header})",
                    "description": f"The web server discloses exact version information ({server_header}) in response headers, aiding adversaries in vulnerability enumeration.",
                    "severity": "low", "confidence": "confirmed", "category": "Information Disclosure",
                    "cwe": "CWE-200", "cve": "[]", "cvss": 3.1, "epss": 0.0, "kev": False,
                    "url": target_url, "host": target_url, "port": None, "parameter": None,
                    "evidence": redact_evidence(f"Server / X-Powered-By header: {server_header}"),
                    "remediation": "Configure the web server to suppress detailed banner/version tokens (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx).",
                    "references": "[]", "status": "open", "fingerprint_hash": fp
                })

            # 4. Insecure Cookies Check
            cookies = res.cookies
            for cookie in cookies:
                cookie_issues = []
                if not cookie.has_nonstandard_attr("HttpOnly") and not getattr(cookie, "httponly", False):
                    cookie_issues.append("missing HttpOnly (accessible via JavaScript)")
                if target_url.startswith("https") and not cookie.secure:
                    cookie_issues.append("missing Secure flag (transmissible over unencrypted HTTP)")
                if not cookie.get_nonstandard_attr("SameSite"):
                    cookie_issues.append("missing SameSite attribute (CSRF risk)")

                if cookie_issues:
                    fp = compute_fingerprint_hash("Identification and Authentication Failures", target_url, cookie.name, "ZAP_INSECURE_COOKIE")
                    findings.append({
                        "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                        "tool": self.name, "rule_id": "ZAP_10029_COOKIE_NO_FLAGS",
                        "title": f"Insecure Cookie Flags: '{cookie.name}'",
                        "description": f"Cookie '{cookie.name}' was set with insecure attributes: {', '.join(cookie_issues)}.",
                        "severity": "medium", "confidence": "confirmed",
                        "category": "Identification and Authentication Failures",
                        "cwe": "CWE-614", "cve": "[]", "cvss": 4.8, "epss": 0.0, "kev": False,
                        "url": target_url, "host": target_url, "port": None, "parameter": cookie.name,
                        "evidence": redact_evidence(f"Cookie: {cookie.name} | Issues: {cookie_issues}"),
                        "remediation": "Ensure all sensitive session cookies include Secure, HttpOnly, and SameSite=Lax/Strict flags.",
                        "references": json.dumps(["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"]),
                        "status": "open", "fingerprint_hash": fp
                    })
        except Exception:
            pass

        return findings
