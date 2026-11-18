import os
import json
import socket
import urllib.parse
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

DANGEROUS_PORTS = {
    3306: ("MySQL Database Server", "CRITICAL", "CWE-284"),
    5432: ("PostgreSQL Database Server", "CRITICAL", "CWE-284"),
    27017: ("MongoDB NoSQL Database", "CRITICAL", "CWE-284"),
    6379: ("Redis Cache / Key-Value Store", "CRITICAL", "CWE-284"),
    9200: ("Elasticsearch Cluster Endpoint", "CRITICAL", "CWE-284"),
    22: ("SSH Remote Shell Access", "MEDIUM", "CWE-200"),
    21: ("FTP Unencrypted File Transfer", "HIGH", "CWE-319"),
    23: ("Telnet Insecure Remote Shell", "CRITICAL", "CWE-319")
}

class NmapPortPlugin(BaseScannerPlugin):
    name = "nmap_ports"
    tier = "T1"
    docker_image = "instrumentisto/nmap:latest"
    timeout_seconds = 60
    category = "Security Misconfiguration"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "nmap_ports.jsonl")

    def run_scan(self, target_url: str, out_dir: str, tenant_id: str, scan_id: str, target_id: str) -> List[Dict[str, Any]]:
        findings = self.parse("", target_url, tenant_id, scan_id, target_id)
        # Write raw output
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

        for port, (service_label, severity, cwe) in DANGEROUS_PORTS.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                fp = compute_fingerprint_hash("Security Misconfiguration", host, str(port), f"PORT_EXPOSED_{port}")
                findings.append({
                    "scan_id": scan_id, "tenant_id": tenant_id, "target_id": target_id,
                    "tool": self.name, "rule_id": f"PORT_EXPOSED_{port}",
                    "title": f"Dangerous Open Database/Management Port: {port} ({service_label})",
                    "description": f"Port {port} is publicly open on {host}, exposing {service_label} directly to the public internet.",
                    "severity": severity.lower(),
                    "confidence": "confirmed",
                    "category": "Security Misconfiguration",
                    "cwe": cwe, "cve": "[]", "cvss": 9.1 if severity == "CRITICAL" else 7.2,
                    "epss": 0.0, "kev": False,
                    "url": f"{host}:{port}", "host": host, "port": port, "parameter": None,
                    "evidence": redact_evidence(f"Direct TCP socket handshake succeeded on {host}:{port}"),
                    "remediation": f"Block public inbound traffic to port {port} via firewall (AWS Security Groups, iptables, ufw).",
                    "references": "[]", "status": "open", "fingerprint_hash": fp
                })

        return findings
