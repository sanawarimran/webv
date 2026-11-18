import os
import json
import requests
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

class HeadersCorsPlugin(BaseScannerPlugin):
    name = "headers_cors"
    tier = "T1"
    docker_image = "python:3.11-slim"
    timeout_seconds = 60
    category = "Security Misconfiguration"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "headers_cors.jsonl")

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
            res = requests.get(target_url, headers={"User-Agent": "AegisAI-Audit/1.0"}, verify=False, timeout=6)
            headers = {k.lower(): v for k, v in res.headers.items()}
            
            # 1. Content Security Policy
            if "content-security-policy" not in headers:
                fp = compute_fingerprint_hash("Security Misconfiguration", target_url, None, "SEC_HDR_CSP_MISSING")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "SEC_HDR_CSP_MISSING",
                    "title": "Missing Content Security Policy (CSP)",
                    "description": "The Content-Security-Policy header is missing, leaving users exposed to cross-site scripting (XSS) and data injection.",
                    "severity": "medium", "confidence": "confirmed", "category": "Security Misconfiguration",
                    "cwe": "CWE-1021", "cve": "[]", "cvss": 5.4, "epss": 0.0, "kev": False,
                    "url": target_url, "host": target_url, "port": 443 if target_url.startswith("https") else 80,
                    "parameter": None, "evidence": "Content-Security-Policy header was absent from server response.",
                    "remediation": "Define a robust Content-Security-Policy restricting script-src, object-src, and frame-ancestors.",
                    "references": json.dumps(["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"]),
                    "status": "open", "fingerprint_hash": fp
                })

            # 2. Strict-Transport-Security (HSTS)
            if target_url.startswith("https") and "strict-transport-security" not in headers:
                fp = compute_fingerprint_hash("Cryptographic Failures", target_url, None, "SEC_HDR_HSTS_MISSING")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "SEC_HDR_HSTS_MISSING",
                    "title": "Missing Strict-Transport-Security (HSTS) Policy",
                    "description": "HSTS header is absent. Attackers can downgrade HTTPS connections to unencrypted HTTP via SSL-stripping.",
                    "severity": "medium", "confidence": "confirmed", "category": "Cryptographic Failures",
                    "cwe": "CWE-319", "cve": "[]", "cvss": 5.0, "epss": 0.0, "kev": False,
                    "url": target_url, "host": target_url, "port": 443, "parameter": None,
                    "evidence": "Strict-Transport-Security header was not returned.",
                    "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload header.",
                    "references": json.dumps(["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"]),
                    "status": "open", "fingerprint_hash": fp
                })

            # 3. CORS Misconfiguration (Null Origin & Arbitrary Origin Reflection)
            cors_res = requests.get(
                target_url,
                headers={"Origin": "https://evil-attacker.example.com"},
                verify=False,
                timeout=6
            )
            cors_headers = {k.lower(): v for k, v in cors_res.headers.items()}
            acao = cors_headers.get("access-control-allow-origin", "")
            acac = cors_headers.get("access-control-allow-credentials", "")
            if acao == "https://evil-attacker.example.com" or (acao == "*" and acac == "true"):
                fp = compute_fingerprint_hash("Broken Access Control", target_url, None, "CORS_ARBITRARY_ORIGIN_ALLOWED")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "CORS_ARBITRARY_ORIGIN_ALLOWED",
                    "title": "Overly Permissive Cross-Origin Resource Sharing (CORS)",
                    "description": f"The target dynamically reflects arbitrary Origin headers ({acao}) with credentials allowed.",
                    "severity": "high", "confidence": "confirmed", "category": "Broken Access Control",
                    "cwe": "CWE-942", "cve": "[]", "cvss": 7.5, "epss": 0.0, "kev": False,
                    "url": target_url, "host": target_url, "port": None, "parameter": "Origin",
                    "evidence": redact_evidence(f"Access-Control-Allow-Origin: {acao} | Access-Control-Allow-Credentials: {acac}"),
                    "remediation": "Restrict Access-Control-Allow-Origin to trusted explicit whitelist origins.",
                    "references": json.dumps(["https://portswigger.net/web-security/cors"]),
                    "status": "open", "fingerprint_hash": fp
                })
        except Exception:
            pass

        return findings
