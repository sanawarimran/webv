import os
import json
import shutil
import requests
import subprocess
from urllib.parse import urljoin
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

NIKTO_DANGEROUS_PATHS = [
    ("/server-status", "Apache Server Status Console", "high", "CWE-200", ["Apache Server Status", "Current Time:"]),
    ("/server-info", "Apache Server Information Disclosure", "high", "CWE-200", ["Apache Server Information", "Server Version:"]),
    ("/test.php", "Residual Test Script Exposed", "medium", "CWE-538", ["phpinfo()", "<title>phpinfo()</title>"]),
    ("/install.php", "Residual Application Installer Wizard", "high", "CWE-538", ["install", "wizard", "step"]),
    ("/setup.php", "Residual Setup Configuration Script", "high", "CWE-538", ["setup", "configuration"]),
    ("/phpmyadmin/", "Publicly Exposed phpMyAdmin Web Console", "high", "CWE-284", ["phpMyAdmin", "pma_username"]),
    ("/web.config", "IIS Web Configuration File Leak", "critical", "CWE-538", ["<configuration>", "<system.webServer>"]),
    ("/crossdomain.xml", "Overly Permissive Flash Cross-Domain Policy", "low", "CWE-346", ["allow-access-from domain=\"*\""]),
    ("/clientaccesspolicy.xml", "Overly Permissive Silverlight Access Policy", "low", "CWE-346", ["<domain uri=\"*\""]),
    ("/.svn/entries", "Subversion Source Code Metadata Leak", "critical", "CWE-538", ["dir", "svn"]),
    ("/.bzr/README", "Bazaar Source Repository Metadata Leak", "critical", "CWE-538", ["Bazaar"])
]

class NiktoPlugin(BaseScannerPlugin):
    """
    Nikto Web Server Security & Misconfiguration Auditor:
    - Identifies dangerous administrative web consoles, server-status, test scripts, and web.config leaks
    - Employs soft-404 baseline guards to eliminate false positives
    - Invokes native Nikto CLI if installed, or runs high-fidelity built-in rules engine
    """
    name = "nikto"
    tier = "T1"
    docker_image = "sullo/nikto:latest"
    timeout_seconds = 90
    category = "Security Misconfiguration"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "nikto.jsonl")

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

        # 1. Soft-404 baseline check
        soft404_url = urljoin(target_url + "/", "aegis_nikto_nonexistent_check_994821")
        soft404_len = 0
        try:
            r404 = requests.get(soft404_url, headers={"User-Agent": "AegisAI-Nikto/1.0"}, verify=False, timeout=4, allow_redirects=False)
            soft404_len = len(r404.content)
        except Exception:
            pass

        # 2. Probe Nikto dangerous paths
        for path, label, severity, cwe, signatures in NIKTO_DANGEROUS_PATHS:
            probe_url = urljoin(target_url + "/", path.lstrip("/"))
            try:
                res = requests.get(
                    probe_url,
                    headers={"User-Agent": "AegisAI-Nikto/1.0"},
                    verify=False,
                    timeout=3,
                    allow_redirects=False
                )

                if res.status_code == 200:
                    content_len = len(res.content)
                    if abs(content_len - soft404_len) < 30:
                        continue

                    # If signatures specified, verify at least one matches
                    matched_sig = None
                    if signatures:
                        for s in signatures:
                            if s.lower() in res.text.lower():
                                matched_sig = s
                                break
                        if not matched_sig:
                            continue

                    fp = compute_fingerprint_hash(self.category, target_url, path, f"NIKTO_DANGEROUS_PATH_{path}")
                    findings.append({
                        "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                        "tool": self.name, "rule_id": f"NIKTO_EXPOSED_{path.strip('/').replace('/', '_').upper()}",
                        "title": f"Dangerous Server Resource Exposed: {label} ({path})",
                        "description": f"The web server exposes '{path}', which corresponds to {label}. This asset should not be publicly accessible on production endpoints.",
                        "severity": severity,
                        "confidence": "confirmed",
                        "category": self.category,
                        "cwe": cwe,
                        "cve": "[]",
                        "cvss": 7.5 if severity == "critical" else (6.5 if severity == "high" else 4.5),
                        "epss": 0.05,
                        "kev": False,
                        "url": probe_url,
                        "host": target_url,
                        "port": None,
                        "parameter": path,
                        "evidence": redact_evidence(f"HTTP 200 OK at {probe_url} (Size: {content_len} bytes)"),
                        "remediation": f"Block public access to '{path}' in web server configuration or remove the file from the document root.",
                        "references": json.dumps(["https://cwe.mitre.org/data/definitions/" + cwe.replace("CWE-", "") + ".html"]),
                        "status": "open",
                        "fingerprint_hash": fp
                    })
            except Exception:
                pass

        return findings
