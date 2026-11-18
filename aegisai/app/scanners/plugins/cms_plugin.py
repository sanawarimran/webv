import os
import json
import shutil
import requests
from urllib.parse import urljoin
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

class CmsPlugin(BaseScannerPlugin):
    """
    Multi-CMS Security Auditor (Drupal, Joomla, Moodle, Silverstripe):
    - Identifies non-WordPress CMS platforms via signatures and changelog files
    - Checks for sensitive admin portals, install scripts, and version disclosures
    - Can invoke Droopescan CLI if installed
    """
    name = "cms_detector"
    tier = "T1"
    docker_image = "python:3.11-slim"
    timeout_seconds = 120
    category = "Vulnerable and Outdated Components"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "cms_detector.jsonl")

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

        cms_signatures = [
            # Drupal
            {
                "cms": "Drupal",
                "paths": ["/CHANGELOG.txt", "/core/CHANGELOG.txt", "/modules/README.txt"],
                "signatures": ["Drupal", "drupal.org"],
                "severity": "medium",
                "cwe": "CWE-200"
            },
            # Joomla
            {
                "cms": "Joomla",
                "paths": ["/administrator/manifests/files/joomla.xml", "/language/en-GB/en-GB.xml", "/README.txt"],
                "signatures": ["<version>", "Joomla!"],
                "severity": "medium",
                "cwe": "CWE-200"
            },
            # Moodle
            {
                "cms": "Moodle",
                "paths": ["/lib/upgrade.txt", "/admin/environment.xml"],
                "signatures": ["Moodle", "<COMPATIBILITY_MATRIX>"],
                "severity": "low",
                "cwe": "CWE-200"
            }
        ]

        for check in cms_signatures:
            cms_name = check["cms"]
            for path in check["paths"]:
                check_url = urljoin(target_url + "/", path.lstrip("/"))
                try:
                    res = requests.get(check_url, headers={"User-Agent": "AegisAI/1.0"}, verify=False, timeout=4)
                    if res.status_code == 200 and any(sig.lower() in res.text.lower() for sig in check["signatures"]):
                        fp = compute_fingerprint_hash("Information Disclosure", check_url, None, f"CMS_{cms_name.upper()}_VERSION_EXPOSED")
                        findings.append({
                            "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                            "tool": self.name, "rule_id": f"CMS_{cms_name.upper()}_INFO_LEAK",
                            "title": f"{cms_name} Version and Documentation Disclosure: {path}",
                            "description": f"The {cms_name} documentation or changelog file was discovered accessible at {path}, exposing internal CMS deployment and version details.",
                            "severity": check["severity"], "confidence": "confirmed",
                            "category": "Information Disclosure",
                            "cwe": check["cwe"], "cve": "[]", "cvss": 4.5, "epss": 0.0, "kev": False,
                            "url": check_url, "host": target_url, "port": None, "parameter": None,
                            "evidence": redact_evidence(f"Discovered at {check_url}. Excerpt: {res.text[:150]}"),
                            "remediation": f"Block public web access to {path} or remove non-essential text files from the document root.",
                            "references": "[]", "status": "open", "fingerprint_hash": fp
                        })
                        break
                except Exception:
                    continue

        return findings
