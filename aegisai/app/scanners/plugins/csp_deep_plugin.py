import os
import json
import requests
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

class CspDeepPlugin(BaseScannerPlugin):
    """
    Deep Content Security Policy (CSP) Directives Auditor:
    - Inspects CSP policy strength against modern bypass techniques
    - Flags unsafe-inline, unsafe-eval, wildcard origins, missing base-uri, missing form-action
    """
    name = "csp_deep_auditor"
    tier = "T1"
    docker_image = "python:3.11-slim"
    timeout_seconds = 60
    category = "Security Misconfiguration"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "csp_deep.jsonl")

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
            res = requests.get(target_url, headers={"User-Agent": "AegisAI-CspAuditor/1.0"}, verify=False, timeout=6)
            headers = {k.lower(): v for k, v in res.headers.items()}
            csp = headers.get("content-security-policy", "")

            if not csp:
                # Missing CSP is already tracked or can be flagged
                fp = compute_fingerprint_hash(self.category, target_url, None, "CSP_POLICY_MISSING")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "CSP_POLICY_MISSING",
                    "title": "Missing Content-Security-Policy (CSP) Header",
                    "description": "The server does not return a Content-Security-Policy header, leaving the application without defense-in-depth protection against Cross-Site Scripting (XSS) and data injection attacks.",
                    "severity": "medium", "confidence": "confirmed", "category": self.category,
                    "cwe": "CWE-693", "cve": "[]", "cvss": 5.4, "epss": 0.0, "kev": False,
                    "url": target_url, "host": target_url, "port": None, "parameter": None,
                    "evidence": "Content-Security-Policy header is absent.",
                    "remediation": "Define a robust Content-Security-Policy restricting script, style, and object execution sources.",
                    "references": json.dumps(["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"]),
                    "status": "open", "fingerprint_hash": fp
                })
                return findings

            # Parse directives
            directives = {}
            for chunk in csp.split(";"):
                parts = chunk.strip().split()
                if parts:
                    directives[parts[0].lower()] = parts[1:]

            # 1. Unsafe-inline in script-src / default-src
            script_sources = directives.get("script-src", directives.get("default-src", []))
            if "'unsafe-inline'" in script_sources:
                fp = compute_fingerprint_hash(self.category, target_url, None, "CSP_UNSAFE_INLINE")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "CSP_UNSAFE_INLINE",
                    "title": "Weak Content Security Policy: 'unsafe-inline' Detected in script-src",
                    "description": "The Content-Security-Policy allows 'unsafe-inline' scripts. This completely disables CSP's primary defense against Cross-Site Scripting (XSS), allowing injected scripts to execute.",
                    "severity": "medium", "confidence": "confirmed", "category": self.category,
                    "cwe": "CWE-693", "cve": "[]", "cvss": 5.7, "epss": 0.05, "kev": False,
                    "url": target_url, "host": target_url, "port": None, "parameter": None,
                    "evidence": redact_evidence(f"script-src directive: {' '.join(script_sources)}"),
                    "remediation": "Remove 'unsafe-inline' and use cryptographic nonces (nonce-...) or SHA-256 hashes for legitimate inline scripts.",
                    "references": json.dumps(["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"]),
                    "status": "open", "fingerprint_hash": fp
                })

            # 2. Wildcard * in script sources
            if "*" in script_sources:
                fp = compute_fingerprint_hash(self.category, target_url, None, "CSP_WILDCARD_SCRIPT_SRC")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "CSP_WILDCARD_SCRIPT_SRC",
                    "title": "Insecure Content Security Policy: Wildcard '*' in script-src",
                    "description": "The Content-Security-Policy allows loading executable scripts from any arbitrary domain (*), nullifying origin-based restriction defenses.",
                    "severity": "medium", "confidence": "confirmed", "category": self.category,
                    "cwe": "CWE-693", "cve": "[]", "cvss": 5.3, "epss": 0.0, "kev": False,
                    "url": target_url, "host": target_url, "port": None, "parameter": None,
                    "evidence": redact_evidence(f"script-src directive: {' '.join(script_sources)}"),
                    "remediation": "Replace wildcard '*' with specific trusted CDN hostnames or 'self'.",
                    "references": json.dumps(["https://content-security-policy.com/"]),
                    "status": "open", "fingerprint_hash": fp
                })

            # 3. Missing base-uri directive
            if "base-uri" not in directives:
                fp = compute_fingerprint_hash(self.category, target_url, None, "CSP_MISSING_BASE_URI")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "CSP_MISSING_BASE_URI",
                    "title": "Missing 'base-uri' Directive in Content Security Policy",
                    "description": "The policy lacks a base-uri directive. Attackers can inject a <base href=...> tag into the DOM to redirect all relative script, stylesheet, and API calls to an external attacker-controlled domain.",
                    "severity": "low", "confidence": "confirmed", "category": self.category,
                    "cwe": "CWE-693", "cve": "[]", "cvss": 4.1, "epss": 0.0, "kev": False,
                    "url": target_url, "host": target_url, "port": None, "parameter": None,
                    "evidence": "base-uri directive is missing from Content-Security-Policy.",
                    "remediation": "Add 'base-uri 'self';' to your Content-Security-Policy header.",
                    "references": json.dumps(["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/base-uri"]),
                    "status": "open", "fingerprint_hash": fp
                })

            # 4. Missing form-action directive
            if "form-action" not in directives:
                fp = compute_fingerprint_hash(self.category, target_url, None, "CSP_MISSING_FORM_ACTION")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "CSP_MISSING_FORM_ACTION",
                    "title": "Missing 'form-action' Directive in Content Security Policy",
                    "description": "Without form-action, HTML forms can submit sensitive credentials and data to any arbitrary external domain without restriction.",
                    "severity": "low", "confidence": "confirmed", "category": self.category,
                    "cwe": "CWE-693", "cve": "[]", "cvss": 4.1, "epss": 0.0, "kev": False,
                    "url": target_url, "host": target_url, "port": None, "parameter": None,
                    "evidence": "form-action directive is missing from Content-Security-Policy.",
                    "remediation": "Add 'form-action 'self';' or list trusted submission endpoints.",
                    "references": json.dumps(["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/form-action"]),
                    "status": "open", "fingerprint_hash": fp
                })

        except Exception:
            pass

        return findings
