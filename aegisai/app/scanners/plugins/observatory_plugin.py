import os
import json
import requests
import urllib.parse
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

class ObservatoryPlugin(BaseScannerPlugin):
    """
    Mozilla HTTP Observatory API integration:
    Queries MDN HTTP Observatory v2 API: POST https://observatory-api.mdn.mozilla.net/api/v2/scan?host=<domain>
    Evaluates security grade (A+ to F), test score, and detailed header compliance.
    """
    name = "observatory"
    tier = "T1"
    docker_image = "python:3.11-slim"
    timeout_seconds = 60
    category = "Security Misconfiguration"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "observatory.jsonl")

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
        parsed = urllib.parse.urlparse(target_url)
        host = parsed.hostname or target_url.replace("https://", "").replace("http://", "").split("/")[0]

        api_url = f"https://observatory-api.mdn.mozilla.net/api/v2/scan?host={host}"
        try:
            res = requests.post(
                api_url,
                headers={"User-Agent": "AegisAI-Scanner/1.0 (+https://provilance.com/aegisai)"},
                timeout=10
            )
            if res.status_code in [200, 201]:
                data = res.json()
                grade = data.get("grade")
                score = data.get("score")
                tests_failed = data.get("tests_failed", 0)

                # Report poor security grade as finding
                if grade in ["D", "D-", "D+", "F"]:
                    fp = compute_fingerprint_hash("Security Misconfiguration", host, None, "OBSERVATORY_GRADE_FAIL")
                    findings.append({
                        "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                        "tool": self.name, "rule_id": "OBSERVATORY_POOR_SECURITY_GRADE",
                        "title": f"Poor Web Security Posture: Mozilla Observatory Grade '{grade}' (Score {score}/100)",
                        "description": f"Target host {host} achieved a failing security grade '{grade}' with score {score}/100 on Mozilla HTTP Observatory. Multiple key defense-in-depth headers are missing or improperly configured.",
                        "severity": "high" if grade.startswith("F") else "medium",
                        "confidence": "confirmed",
                        "category": "Security Misconfiguration",
                        "cwe": "CWE-693", "cve": "[]",
                        "cvss": 7.1 if grade.startswith("F") else 5.5,
                        "epss": 0.0, "kev": False,
                        "url": target_url, "host": host, "port": 443, "parameter": None,
                        "evidence": redact_evidence(f"Grade: {grade} | Score: {score}/100 | Tests Failed: {tests_failed} | Details: {data.get('details_url', '')}"),
                        "remediation": "Review Mozilla Observatory guidelines and configure Content-Security-Policy, HSTS, X-Content-Type-Options, and secure cookie attributes.",
                        "references": json.dumps(["https://observatory.mozilla.org/", "https://infosec.mozilla.org/guidelines/web_security"]),
                        "status": "open", "fingerprint_hash": fp
                    })
        except Exception:
            pass

        return findings
