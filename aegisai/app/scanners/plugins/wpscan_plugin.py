import os
import json
import shutil
import requests
import subprocess
from urllib.parse import urljoin
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

class WPScanPlugin(BaseScannerPlugin):
    """
    WordPress & CMS Vulnerability / Exposure Detector:
    - Enumerates vulnerable plugins, themes, backups (vp, vt, cb, dbe)
    - Checks for sensitive information disclosures (XML-RPC, user enumeration, debug.log)
    - Never runs brute-force or password guessing attacks (Section 4 Compliance)
    """
    name = "wpscan"
    tier = "T1"
    docker_image = "wpscanteam/wpscan:latest"
    timeout_seconds = 180
    category = "Vulnerable and Outdated Components"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "wpscan.json")

    def build_command(self, target_url: str, out_dir: str, **kwargs) -> List[str]:
        wpscan_bin = shutil.which("wpscan")
        out_json = self.get_output_path(out_dir)
        if wpscan_bin:
            return [
                wpscan_bin,
                "--url", target_url,
                "--enumerate", "vp,vt,cb,dbe",
                "--plugins-detection", "mixed",
                "--random-user-agent",
                "--max-threads", "1",
                "--throttle", "500",
                "--format", "json",
                "-o", out_json,
                "--no-banner"
            ]
        return ["python", "-c", "print('Internal WordPress Security Auditor')"]

    def _is_wordpress(self, target_url: str) -> bool:
        """Fast detection of WordPress presence before invoking heavy external CLI."""
        try:
            r = requests.get(target_url, headers={"User-Agent": "AegisAI/1.0"}, verify=False, timeout=3)
            if "wp-content" in r.text or "wp-includes" in r.text or "wordpress" in r.text.lower():
                return True
            r_login = requests.get(urljoin(target_url + "/", "wp-login.php"), headers={"User-Agent": "AegisAI/1.0"}, verify=False, timeout=2)
            if r_login.status_code == 200 and ("user_login" in r_login.text or "wordpress" in r_login.text.lower()):
                return True
        except Exception:
            pass
        return False

    def run_scan(self, target_url: str, out_dir: str, tenant_id: str, scan_id: str, target_id: str) -> List[Dict[str, Any]]:
        out_file = self.get_output_path(out_dir)
        wpscan_bin = shutil.which("wpscan")
        
        # 1. Run external CLI only if WordPress is detected
        if wpscan_bin and self._is_wordpress(target_url):
            try:
                cmd = self.build_command(target_url, out_dir)
                subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout_seconds)
            except Exception:
                pass

        # 2. Parse external results + native audits
        return self.parse(out_file, target_url, tenant_id, scan_id, target_id)

    def parse(self, raw_output_path: str, target_url: str, tenant_id: str, scan_id: str, target_id: str) -> List[Dict[str, Any]]:
        findings = []

        # 1. Parse external WPScan JSON if generated
        if os.path.exists(raw_output_path) and os.path.getsize(raw_output_path) > 0:
            try:
                with open(raw_output_path, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)

                    # Vulnerable Plugins
                    plugins = data.get("plugins") or {}
                    for p_name, p_info in plugins.items():
                        vulns = p_info.get("vulnerabilities") or []
                        for vuln in vulns:
                            v_title = vuln.get("title", f"Vulnerable plugin: {p_name}")
                            fixed_in = vuln.get("fixed_in", "Unknown")
                            fp = compute_fingerprint_hash("Vulnerable and Outdated Components", target_url, p_name, f"WP_PLUGIN_{p_name}")
                            findings.append({
                                "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                                "tool": self.name, "rule_id": f"WP_PLUGIN_VULN_{p_name.upper()}",
                                "title": f"WordPress Vulnerable Plugin: {p_name} - {v_title}",
                                "description": f"Plugin '{p_name}' has a known vulnerability: {v_title}. Fixed in version: {fixed_in}.",
                                "severity": "high", "confidence": "confirmed",
                                "category": "Vulnerable and Outdated Components",
                                "cwe": "CWE-1104", "cve": json.dumps(vuln.get("references", {}).get("cve", [])),
                                "cvss": 7.5, "epss": 0.0, "kev": False,
                                "url": target_url, "host": target_url, "port": None, "parameter": p_name,
                                "evidence": redact_evidence(f"Installed Version: {p_info.get('version', {}).get('number')} | Fix: {fixed_in}"),
                                "remediation": f"Update plugin '{p_name}' to version {fixed_in} or deactivate it immediately.",
                                "references": json.dumps(vuln.get("references", {}).get("url", [])),
                                "status": "open", "fingerprint_hash": fp
                            })

                    # Interesting Findings (Backups, Exports)
                    for item in data.get("interesting_findings") or []:
                        item_type = item.get("type", "Exposed WordPress Asset")
                        item_url = item.get("url", target_url)
                        fp = compute_fingerprint_hash("Information Disclosure", item_url, None, f"WP_EXPOSED_{item_type}")
                        findings.append({
                            "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                            "tool": self.name, "rule_id": "WP_EXPOSED_RESOURCE",
                            "title": f"WordPress Information Disclosure: {item_type}",
                            "description": f"WordPress scanner identified sensitive resource: {item_type} at {item_url}.",
                            "severity": "medium", "confidence": "confirmed",
                            "category": "Information Disclosure",
                            "cwe": "CWE-200", "cve": "[]", "cvss": 5.3, "epss": 0.0, "kev": False,
                            "url": item_url, "host": target_url, "port": None, "parameter": None,
                            "evidence": redact_evidence(f"Discovered at: {item_url}"),
                            "remediation": f"Restrict access to {item_url} or delete unused artifacts.",
                            "references": "[]", "status": "open", "fingerprint_hash": fp
                        })
            except Exception:
                pass

        # 2. Native HTTP WordPress & CMS Exposure Checks
        try:
            # Check WordPress Rest API User Enumeration (/wp-json/wp/v2/users)
            user_api_url = urljoin(target_url + "/", "wp-json/wp/v2/users")
            res_users = requests.get(user_api_url, headers={"User-Agent": "AegisAI/1.0"}, verify=False, timeout=4)
            if res_users.status_code == 200:
                try:
                    users_data = res_users.json()
                    if isinstance(users_data, list) and len(users_data) > 0:
                        raw_users = [u.get("slug") or u.get("name") for u in users_data if isinstance(u, dict)]
                        fp = compute_fingerprint_hash("Information Disclosure", user_api_url, None, "WP_USER_ENUMERATION_REST")
                        findings.append({
                            "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                            "tool": self.name, "rule_id": "WP_USER_ENUMERATION_REST",
                            "title": "WordPress REST API User Enumeration Enabled",
                            "description": "The WordPress REST API exposes usernames without authentication, allowing attackers to construct targeted brute-force or credential stuffing attacks.",
                            "severity": "medium", "confidence": "confirmed", "category": "Information Disclosure",
                            "cwe": "CWE-200", "cve": "[]", "cvss": 5.3, "epss": 0.0, "kev": False,
                            "url": user_api_url, "host": target_url, "port": None, "parameter": None,
                            "evidence": redact_evidence(f"Exposed usernames found: {raw_users[:5]} (Total {len(raw_users)} users)"),
                            "remediation": "Disable public access to /wp-json/wp/v2/users for unauthenticated requests via security plugins or functions.php.",
                            "references": json.dumps(["https://developer.wordpress.org/rest-api/reference/users/"]),
                            "status": "open", "fingerprint_hash": fp
                        })
                except Exception:
                    pass

            # Check XML-RPC Interface (/xmlrpc.php)
            xmlrpc_url = urljoin(target_url + "/", "xmlrpc.php")
            res_xmlrpc = requests.get(xmlrpc_url, headers={"User-Agent": "AegisAI/1.0"}, verify=False, timeout=4)
            if res_xmlrpc.status_code == 405 or (res_xmlrpc.status_code == 200 and "XML-RPC server accepts POST requests only" in res_xmlrpc.text):
                fp = compute_fingerprint_hash("Security Misconfiguration", xmlrpc_url, None, "WP_XMLRPC_ENABLED")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": "WP_XMLRPC_ENABLED",
                    "title": "WordPress XML-RPC API Exposed",
                    "description": "xmlrpc.php is enabled. Attackers can leverage system.multicall to brute-force passwords in single HTTP requests or pingback.ping for DDoS reflection.",
                    "severity": "low", "confidence": "confirmed", "category": "Security Misconfiguration",
                    "cwe": "CWE-16", "cve": "[]", "cvss": 4.3, "epss": 0.0, "kev": False,
                    "url": xmlrpc_url, "host": target_url, "port": None, "parameter": None,
                    "evidence": redact_evidence("XML-RPC interface actively responding to probe."),
                    "remediation": "Disable XML-RPC via web server rewrite rule (location = /xmlrpc.php { deny all; }) or a security plugin if not actively required.",
                    "references": json.dumps(["https://wordpress.org/support/article/xml-rpc/"]),
                    "status": "open", "fingerprint_hash": fp
                })
        except Exception:
            pass

        return findings
