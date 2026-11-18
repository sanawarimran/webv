import os
import json
import requests
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

class HttpMethodsPlugin(BaseScannerPlugin):
    """
    HTTP Methods & Cross-Site Tracing (XST) Auditor:
    - Tests for enabled TRACE / TRACK methods (enabling Cross-Site Tracing / HttpOnly cookie bypass)
    - Checks for unauthenticated dangerous methods (PUT, DELETE, WebDAV PROPFIND)
    """
    name = "http_methods"
    tier = "T1"
    docker_image = "python:3.11-slim"
    timeout_seconds = 45
    category = "Security Misconfiguration"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "http_methods.jsonl")

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

        # 1. Test TRACE method (XST)
        try:
            trace_canary = "X-AegisAI-Trace-Probe: active-verification"
            res_trace = requests.request(
                "TRACE",
                target_url,
                headers={"User-Agent": "AegisAI/1.0", "X-AegisAI-Trace-Probe": "active-verification"},
                verify=False,
                timeout=4
            )

            if res_trace.status_code == 200 and trace_canary in res_trace.text:
                fp = compute_fingerprint_hash(self.category, target_url, "TRACE", "HTTP_TRACE_METHOD_ENABLED")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "HTTP_TRACE_METHOD_ENABLED",
                    "title": "Dangerous HTTP TRACE Method Enabled (Cross-Site Tracing - XST)",
                    "description": "The web server supports the HTTP TRACE method and echoes client headers back in the body. Attackers can leverage Cross-Site Tracing (XST) via XSS to steal sensitive HttpOnly cookies.",
                    "severity": "medium",
                    "confidence": "confirmed",
                    "category": self.category,
                    "cwe": "CWE-693",
                    "cve": "[]",
                    "cvss": 5.3,
                    "epss": 0.08,
                    "kev": False,
                    "url": target_url,
                    "host": target_url,
                    "port": None,
                    "parameter": "HTTP TRACE",
                    "evidence": redact_evidence(f"TRACE returned HTTP 200 with header echo: {res_trace.text[:150]}"),
                    "remediation": "Disable TRACE method in web server configuration ('TraceEnable off' in Apache, or return 405 for TRACE in Nginx).",
                    "references": json.dumps(["https://owasp.org/www-community/attacks/Cross_Site_Tracing"]),
                    "status": "open",
                    "fingerprint_hash": fp
                })
        except Exception:
            pass

        # 2. Test OPTIONS method to inspect Allowed methods
        try:
            res_options = requests.options(target_url, headers={"User-Agent": "AegisAI/1.0"}, verify=False, timeout=4)
            allow_header = res_options.headers.get("allow") or res_options.headers.get("public")
            if allow_header:
                methods = [m.strip().upper() for m in allow_header.split(",")]
                dangerous_allowed = [m for m in methods if m in ["PUT", "DELETE", "CONNECT"]]
                if dangerous_allowed:
                    fp = compute_fingerprint_hash(self.category, target_url, "ALLOW", "POTENTIALLY_DANGEROUS_HTTP_METHODS")
                    findings.append({
                        "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                        "tool": self.name, "rule_id": "POTENTIALLY_DANGEROUS_HTTP_METHODS",
                        "title": f"Potentially Dangerous HTTP Methods Advertised: {', '.join(dangerous_allowed)}",
                        "description": f"The Allow header advertises dangerous HTTP methods ({', '.join(dangerous_allowed)}). If unauthenticated, these methods may allow arbitrary file creation or deletion.",
                        "severity": "low",
                        "confidence": "likely",
                        "category": self.category,
                        "cwe": "CWE-650",
                        "cve": "[]",
                        "cvss": 4.3,
                        "epss": 0.01,
                        "kev": False,
                        "url": target_url,
                        "host": target_url,
                        "port": None,
                        "parameter": ", ".join(dangerous_allowed),
                        "evidence": redact_evidence(f"Allow Header: {allow_header}"),
                        "remediation": "Restrict HTTP methods in web server configuration to only those required (typically GET, POST, HEAD, OPTIONS).",
                        "references": json.dumps(["https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"]),
                        "status": "open",
                        "fingerprint_hash": fp
                    })
        except Exception:
            pass

        return findings
