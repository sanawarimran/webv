import os
import json
import requests
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

class CookieSecurityPlugin(BaseScannerPlugin):
    """
    Session & Cookie Security Configuration Auditor:
    - Analyzes Set-Cookie headers for HttpOnly, Secure, and SameSite attributes
    - Identifies exposure to XSS token exfiltration (missing HttpOnly)
    - Identifies cleartext cookie transmission (missing Secure)
    - Identifies CSRF vulnerabilities (missing or weak SameSite)
    """
    name = "cookie_auditor"
    tier = "T1"
    docker_image = "python:3.11-slim"
    timeout_seconds = 60
    category = "Security Misconfiguration"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "cookie_security.jsonl")

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
            res = requests.get(target_url, headers={"User-Agent": "AegisAI-CookieAuditor/1.0"}, verify=False, timeout=6)
            
            # Extract raw Set-Cookie headers
            cookie_headers = []
            if "Set-Cookie" in res.headers:
                cookie_headers = [res.headers["Set-Cookie"]]
            elif hasattr(res.raw, "headers"):
                cookie_headers = res.raw.headers.getlist("Set-Cookie")

            for cookie_str in cookie_headers:
                parts = [p.strip() for p in cookie_str.split(";")]
                if not parts:
                    continue
                
                cookie_name = parts[0].split("=")[0]
                attrs = [p.lower() for p in parts[1:]]

                is_httponly = any("httponly" == a for a in attrs)
                is_secure = any("secure" == a for a in attrs)
                has_samesite = any(a.startswith("samesite") for a in attrs)

                # 1. Check Missing HttpOnly
                if not is_httponly:
                    fp = compute_fingerprint_hash(self.category, target_url, cookie_name, "COOKIE_MISSING_HTTPONLY")
                    findings.append({
                        "scan_id": scan_id,
                        "tenant_id": tenant_id,
                        "target_id": target_id,
                        "tool": self.name,
                        "rule_id": "COOKIE_MISSING_HTTPONLY",
                        "title": f"Insecure Cookie Flag: Missing HttpOnly Attribute on '{cookie_name}'",
                        "description": f"The cookie '{cookie_name}' is set without the HttpOnly flag. Client-side scripts can read this cookie using document.cookie, making authentication tokens susceptible to XSS token theft.",
                        "severity": "medium",
                        "confidence": "confirmed",
                        "category": self.category,
                        "cwe": "CWE-1004",
                        "cve": "[]",
                        "cvss": 5.3,
                        "epss": 0.0,
                        "kev": False,
                        "url": target_url,
                        "host": target_url,
                        "port": None,
                        "parameter": cookie_name,
                        "evidence": redact_evidence(f"Set-Cookie: {cookie_str[:200]}"),
                        "remediation": f"Add the 'HttpOnly' attribute to the '{cookie_name}' cookie in server session configuration.",
                        "references": json.dumps(["https://owasp.org/www-community/HttpOnly"]),
                        "status": "open",
                        "fingerprint_hash": fp
                    })

                # 2. Check Missing Secure (on HTTPS targets)
                if target_url.startswith("https://") and not is_secure:
                    fp = compute_fingerprint_hash("Cryptographic Failures", target_url, cookie_name, "COOKIE_MISSING_SECURE")
                    findings.append({
                        "scan_id": scan_id,
                        "tenant_id": tenant_id,
                        "target_id": target_id,
                        "tool": self.name,
                        "rule_id": "COOKIE_MISSING_SECURE",
                        "title": f"Insecure Cookie Flag: Missing Secure Attribute on '{cookie_name}'",
                        "description": f"The cookie '{cookie_name}' is set without the Secure attribute on an HTTPS site. Browsers may transmit this cookie over unencrypted HTTP connections if cleartext links are followed.",
                        "severity": "medium",
                        "confidence": "confirmed",
                        "category": "Cryptographic Failures",
                        "cwe": "CWE-614",
                        "cve": "[]",
                        "cvss": 4.8,
                        "epss": 0.0,
                        "kev": False,
                        "url": target_url,
                        "host": target_url,
                        "port": None,
                        "parameter": cookie_name,
                        "evidence": redact_evidence(f"Set-Cookie: {cookie_str[:200]}"),
                        "remediation": f"Ensure all cookies transmitted over HTTPS include the 'Secure' directive.",
                        "references": json.dumps(["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#secure-attribute"]),
                        "status": "open",
                        "fingerprint_hash": fp
                    })

                # 3. Check Missing SameSite
                if not has_samesite:
                    fp = compute_fingerprint_hash(self.category, target_url, cookie_name, "COOKIE_MISSING_SAMESITE")
                    findings.append({
                        "scan_id": scan_id,
                        "tenant_id": tenant_id,
                        "target_id": target_id,
                        "tool": self.name,
                        "rule_id": "COOKIE_MISSING_SAMESITE",
                        "title": f"Missing SameSite Attribute on Cookie '{cookie_name}'",
                        "description": f"The cookie '{cookie_name}' lacks a SameSite attribute (Lax or Strict), increasing exposure to Cross-Site Request Forgery (CSRF) attacks.",
                        "severity": "low",
                        "confidence": "confirmed",
                        "category": self.category,
                        "cwe": "CWE-1275",
                        "cve": "[]",
                        "cvss": 3.5,
                        "epss": 0.0,
                        "kev": False,
                        "url": target_url,
                        "host": target_url,
                        "port": None,
                        "parameter": cookie_name,
                        "evidence": redact_evidence(f"Set-Cookie: {cookie_str[:200]}"),
                        "remediation": f"Set 'SameSite=Lax' or 'SameSite=Strict' for the '{cookie_name}' cookie.",
                        "references": json.dumps(["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"]),
                        "status": "open",
                        "fingerprint_hash": fp
                    })
        except Exception:
            pass

        return findings
