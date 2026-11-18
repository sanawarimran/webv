import os
import json
import requests
from urllib.parse import urljoin
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

COMMON_REDIRECT_PARAMS = [
    "redirect", "next", "url", "dest", "return", "return_url", "target", "goto", "out"
]

CANARY_DOMAIN = "https://example.com/aegisai-redirect-test"

class OpenRedirectPlugin(BaseScannerPlugin):
    """
    Open Redirect & Unvalidated Navigation Parameter Prober:
    - TIER: T2 (Requires verified ownership AND explicit user consent)
    - Tests for unvalidated redirection to external domains using safe canary targets
    - Strictly detection-only; never exploits or steals session tokens
    """
    name = "open_redirect"
    tier = "T2"
    docker_image = "python:3.11-slim"
    timeout_seconds = 90
    category = "Broken Access Control"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "open_redirect.jsonl")

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

        base_clean = target_url.split("?")[0].rstrip("/")

        for param in COMMON_REDIRECT_PARAMS:
            probe_url = f"{base_clean}/?{param}={CANARY_DOMAIN}"
            try:
                res = requests.get(
                    probe_url,
                    headers={"User-Agent": "AegisAI-Redirect-Prober/1.0"},
                    allow_redirects=False,
                    verify=False,
                    timeout=4
                )

                location = res.headers.get("location", "")
                
                # Check if Location header reflects the external canary
                if res.status_code in [301, 302, 303, 307, 308] and CANARY_DOMAIN in location:
                    fp = compute_fingerprint_hash(self.category, base_clean, param, "OPEN_REDIRECT_PARAMETER")
                    findings.append({
                        "scan_id": scan_id,
                        "tenant_id": tenant_id,
                        "target_id": target_id,
                        "tool": self.name,
                        "rule_id": f"OPEN_REDIRECT_{param.upper()}",
                        "title": f"Unvalidated Open Redirect via Parameter: '{param}'",
                        "description": f"The parameter '{param}' redirects users to arbitrary external domains without validation. Attackers can leverage this to conduct phishing campaigns and credential harvesting under your trusted domain reputation.",
                        "severity": "medium",
                        "confidence": "confirmed",
                        "category": self.category,
                        "cwe": "CWE-601",
                        "cve": "[]",
                        "cvss": 6.1,
                        "epss": 0.10,
                        "kev": False,
                        "url": probe_url,
                        "host": base_clean,
                        "port": None,
                        "parameter": param,
                        "evidence": redact_evidence(f"HTTP Status: {res.status_code} | Location Header: {location}"),
                        "remediation": f"Implement strict allow-listing for the '{param}' parameter, or validate that the destination starts with a relative path (e.g. '/') and not double slashes ('//').",
                        "references": json.dumps(["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"]),
                        "status": "open",
                        "fingerprint_hash": fp
                    })
            except Exception:
                pass

        return findings
