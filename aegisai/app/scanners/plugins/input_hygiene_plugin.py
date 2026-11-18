import os
import json
import secrets
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

DB_ERROR_SIGNATURES = [
    ("You have an error in your SQL syntax", "MySQL / MariaDB"),
    ("check the manual that corresponds to your MySQL server version", "MySQL"),
    ("mysql_fetch_array()", "MySQL PHP Driver"),
    ("ORA-01756", "Oracle Database"),
    ("ORA-00933", "Oracle Database"),
    ("PostgreSQL query failed", "PostgreSQL"),
    ("pg_query(): Query failed", "PostgreSQL"),
    ("syntax error at or near", "PostgreSQL"),
    ("SQLite3::SQLException", "SQLite"),
    ("sqlite3.OperationalError", "SQLite"),
    ("Unclosed quotation mark after the character string", "Microsoft SQL Server"),
    ("Microsoft OLE DB Provider for SQL Server", "MSSQL OLE DB"),
    ("Driver][SQL Server]", "MSSQL ODBC Driver")
]

class InputHygienePlugin(BaseScannerPlugin):
    """
    Input Parameter Hygiene & Error Disclosure Auditor:
    - TIER: T2 (Active non-destructive parameter testing with explicit consent)
    - Probes query parameters for unescaped HTML reflection (Reflected XSS Indicator)
    - Checks for verbose database syntax error disclosure (SQL Injection Indicator)
    - Strictly detection-only; never exploits or exfiltrates database records
    """
    name = "input_hygiene"
    tier = "T2"
    docker_image = "python:3.11-slim"
    timeout_seconds = 90
    category = "Injection"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "input_hygiene.jsonl")

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

        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)

        # Baseline response
        baseline_text = ""
        try:
            r_base = requests.get(target_url, headers={"User-Agent": "AegisAI-Hygiene/1.0"}, verify=False, timeout=5)
            baseline_text = r_base.text
        except Exception:
            return findings

        # Test common parameter set if URL has no query string
        test_params = params.copy() if params else {"q": [""], "search": [""], "id": ["1"]}

        # 1. Parameter Reflection Check with harmless unique canary
        canary_id = secrets.token_hex(4)
        canary_probe = f"aegisCanary{canary_id}<\"'test>"

        for p_name in list(test_params.keys())[:3]:
            mutated = test_params.copy()
            mutated[p_name] = [canary_probe]
            probe_qs = urlencode(mutated, doseq=True)
            probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", probe_qs, ""))

            try:
                res_xss = requests.get(
                    probe_url,
                    headers={"User-Agent": "AegisAI-Hygiene/1.0"},
                    verify=False,
                    timeout=5
                )

                # Check if exact canary with raw < " ' was reflected unescaped
                if canary_probe in res_xss.text and canary_probe not in baseline_text:
                    fp = compute_fingerprint_hash(self.category, target_url, p_name, "REFLECTED_XSS_INDICATOR")
                    findings.append({
                        "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                        "tool": self.name, "rule_id": "REFLECTED_XSS_INDICATOR",
                        "title": f"Reflected HTML/XSS Indicator in Parameter: '{p_name}'",
                        "description": f"User-supplied special HTML characters ('<' and '>') passed in parameter '{p_name}' were reflected verbatim in the HTTP response without context-aware HTML entity encoding.",
                        "severity": "high",
                        "confidence": "likely",
                        "category": "Injection",
                        "cwe": "CWE-79",
                        "cve": "[]",
                        "cvss": 7.1,
                        "epss": 0.20,
                        "kev": False,
                        "url": probe_url,
                        "host": target_url,
                        "port": None,
                        "parameter": p_name,
                        "evidence": redact_evidence(f"Reflected unescaped canary probe in response to {probe_url}"),
                        "remediation": "Apply context-aware HTML entity encoding (e.g. htmlspecialchars() or template auto-escaping) before displaying user input in browser context.",
                        "references": json.dumps(["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"]),
                        "status": "open",
                        "fingerprint_hash": fp
                    })
            except Exception:
                pass

        # 2. Database Error Disclosure Probe (Non-destructive test)
        for p_name in list(test_params.keys())[:3]:
            mutated = test_params.copy()
            mutated[p_name] = ["'"]
            probe_qs = urlencode(mutated, doseq=True)
            probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", probe_qs, ""))

            try:
                res_db = requests.get(
                    probe_url,
                    headers={"User-Agent": "AegisAI-Hygiene/1.0"},
                    verify=False,
                    timeout=5
                )

                for err_sig, db_vendor in DB_ERROR_SIGNATURES:
                    if err_sig.lower() in res_db.text.lower() and err_sig.lower() not in baseline_text.lower():
                        fp = compute_fingerprint_hash(self.category, target_url, p_name, f"SQL_ERROR_DISCLOSURE_{db_vendor}")
                        findings.append({
                            "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                            "tool": self.name, "rule_id": "VERBOSE_SQL_ERROR_DISCLOSURE",
                            "title": f"Verbose Database Error Disclosed ({db_vendor}) in Parameter: '{p_name}'",
                            "description": f"Input manipulation in parameter '{p_name}' triggered a detailed {db_vendor} syntax error message. This indicates potential vulnerability to SQL Injection and assists attackers in database profiling.",
                            "severity": "high",
                            "confidence": "likely",
                            "category": "Injection",
                            "cwe": "CWE-89",
                            "cve": "[]",
                            "cvss": 7.5,
                            "epss": 0.25,
                            "kev": False,
                            "url": probe_url,
                            "host": target_url,
                            "port": None,
                            "parameter": p_name,
                            "evidence": redact_evidence(f"Matched {db_vendor} syntax error '{err_sig}' at {probe_url}"),
                            "remediation": "Use parameterized queries / prepared statements (ORM) and disable verbose error message display in production.",
                            "references": json.dumps(["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"]),
                            "status": "open",
                            "fingerprint_hash": fp
                        })
                        break
            except Exception:
                pass

        return findings
