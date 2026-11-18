import os
import ssl
import json
import socket
import datetime
import urllib.parse
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

class TlsPlugin(BaseScannerPlugin):
    name = "tls_ssl"
    tier = "T1"
    docker_image = "python:3.11-slim"
    timeout_seconds = 60
    category = "Cryptographic Failures"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "tls_ssl.jsonl")

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
        port = parsed.port or 443

        # 1. Certificate Details & Expiration Check
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

                    # Check Certificate Expiration
                    not_after_str = cert.get("notAfter")
                    if not_after_str:
                        not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        now = datetime.datetime.utcnow()
                        if now > not_after:
                            fp = compute_fingerprint_hash("Cryptographic Failures", host, None, "TLS_CERT_EXPIRED")
                            findings.append({
                                "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                                "tool": self.name, "rule_id": "TLS_CERT_EXPIRED",
                                "title": "Expired SSL/TLS Certificate",
                                "description": f"The SSL/TLS certificate for {host} expired on {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}.",
                                "severity": "high", "confidence": "confirmed", "category": "Cryptographic Failures",
                                "cwe": "CWE-295", "cve": "[]", "cvss": 7.5, "epss": 0.0, "kev": False,
                                "url": f"https://{host}:{port}", "host": host, "port": port, "parameter": None,
                                "evidence": redact_evidence(f"Certificate expired at {not_after_str}. Subject: {cert.get('subject')}"),
                                "remediation": "Renew and install a valid trusted SSL/TLS certificate immediately.",
                                "references": "[]", "status": "open", "fingerprint_hash": fp
                            })
                        elif (not_after - now).days < 15:
                            days_left = (not_after - now).days
                            fp = compute_fingerprint_hash("Cryptographic Failures", host, None, "TLS_CERT_EXPIRING_SOON")
                            findings.append({
                                "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                                "tool": self.name, "rule_id": "TLS_CERT_EXPIRING_SOON",
                                "title": f"SSL/TLS Certificate Expiring Soon ({days_left} days remaining)",
                                "description": f"The SSL/TLS certificate will expire on {not_after.strftime('%Y-%m-%d')}.",
                                "severity": "low", "confidence": "confirmed", "category": "Cryptographic Failures",
                                "cwe": "CWE-295", "cve": "[]", "cvss": 3.7, "epss": 0.0, "kev": False,
                                "url": f"https://{host}:{port}", "host": host, "port": port, "parameter": None,
                                "evidence": redact_evidence(f"Expires in {days_left} days: {not_after_str}"),
                                "remediation": "Automate certificate renewal before expiration (e.g., via Let's Encrypt certbot).",
                                "references": "[]", "status": "open", "fingerprint_hash": fp
                            })
        except ssl.SSLCertVerificationError as e:
            fp = compute_fingerprint_hash("Cryptographic Failures", host, None, "TLS_CERT_VERIFICATION_FAILED")
            findings.append({
                "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                "tool": self.name, "rule_id": "TLS_CERT_VERIFICATION_FAILED",
                "title": "Untrusted or Self-Signed SSL/TLS Certificate",
                "description": f"Certificate verification failed for {host}: {str(e)}",
                "severity": "high", "confidence": "confirmed", "category": "Cryptographic Failures",
                "cwe": "CWE-295", "cve": "[]", "cvss": 7.4, "epss": 0.0, "kev": False,
                "url": f"https://{host}:{port}", "host": host, "port": port, "parameter": None,
                "evidence": redact_evidence(f"SSL verification error: {str(e)}"),
                "remediation": "Replace self-signed or invalid certificates with a trusted CA-signed certificate.",
                "references": "[]", "status": "open", "fingerprint_hash": fp
            })
        except Exception:
            pass

        return findings
