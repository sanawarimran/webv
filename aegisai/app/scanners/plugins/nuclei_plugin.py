import os
import json
import shutil
import subprocess
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

class NucleiPlugin(BaseScannerPlugin):
    name = "nuclei"
    tier = "T1"
    docker_image = "projectdiscovery/nuclei:v3.11.1"
    timeout_seconds = 300
    category = "Vulnerable and Outdated Components"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "nuclei.jsonl")

    def _resolve_paths(self):
        # Look for local workspace binary & templates
        workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
        local_bin = os.path.join(workspace_root, "web vulnerability scanner", "bin", "nuclei.exe")
        if not os.path.exists(local_bin):
            local_bin = os.path.join(workspace_root, "web vuln", "bin", "nuclei.exe")

        local_templates = os.path.join(workspace_root, "web vulnerability scanner", "nuclei-templates")
        if not os.path.exists(local_templates):
            local_templates = os.path.join(workspace_root, "web vuln", "nuclei-templates")

        bin_path = local_bin if os.path.exists(local_bin) else shutil.which("nuclei") or "nuclei"
        templates_path = local_templates if os.path.exists(local_templates) else None
        return bin_path, templates_path

    def build_command(self, target_url: str, out_dir: str, **kwargs) -> List[str]:
        out_file = self.get_output_path(out_dir)
        bin_path, templates_path = self._resolve_paths()

        cmd = [
            bin_path,
            "-u", target_url,
            "-severity", "low,medium,high,critical",
            "-tags", "cve,exposure,misconfig,takeover",
            "-etags", "dos,fuzz,intrusive,bruteforce",
            "-rl", "75",
            "-c", "25",
            "-timeout", "6",
            "-duc",
            "-silent",
            "-jsonl",
            "-o", out_file
        ]
        if templates_path:
            cmd.extend(["-t", templates_path])

        return cmd

    def run_scan(self, target_url: str, out_dir: str, tenant_id: str, scan_id: str, target_id: str) -> List[Dict[str, Any]]:
        out_file = self.get_output_path(out_dir)
        bin_path, templates_path = self._resolve_paths()

        if not os.path.exists(bin_path) and not shutil.which("nuclei"):
            return []

        cmd = self.build_command(target_url, out_dir)
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout_seconds)
        except Exception:
            pass

        return self.parse(out_file, target_url, tenant_id, scan_id, target_id)

    def parse(self, raw_output_path: str, target_url: str, tenant_id: str, scan_id: str, target_id: str) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(raw_output_path):
            return findings

        with open(raw_output_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    template_id = data.get("template-id", "nuclei_detection")
                    raw_sev = (info.get("severity") or "info").lower()
                    title = info.get("name") or template_id
                    desc = info.get("description") or f"Vulnerability detected by Nuclei template {template_id}."
                    matched_at = data.get("matched-at") or target_url
                    
                    classification = info.get("classification", {})
                    cwe_raw = classification.get("cwe-id", ["CWE-693"])
                    cwe = cwe_raw[0] if isinstance(cwe_raw, list) and cwe_raw else str(cwe_raw or "CWE-693")
                    cve = classification.get("cve-id", [])
                    if isinstance(cve, str):
                        cve = [cve]

                    cvss = float(classification.get("cvss-score", 0.0) or 0.0)
                    remediation = info.get("remediation") or "Update components and verify endpoint access restrictions."
                    raw_evidence = f"Matched: {matched_at} | Extracted: {data.get('extracted-results', '')}"

                    category = classification.get("category") or "Security Misconfiguration"
                    fp_hash = compute_fingerprint_hash(category, matched_at, None, template_id)

                    findings.append({
                        "scan_id": scan_id,
                        "tenant_id": tenant_id,
                        "target_id": target_id,
                        "tool": self.name,
                        "rule_id": f"NUCLEI_{template_id.upper()}",
                        "title": f"Nuclei: {title}",
                        "description": desc,
                        "severity": raw_sev,
                        "confidence": "confirmed" if raw_sev in ["critical", "high"] else "likely",
                        "category": category,
                        "cwe": cwe,
                        "cve": json.dumps(cve or []),
                        "cvss": cvss,
                        "epss": 0.0,
                        "kev": False,
                        "url": matched_at,
                        "host": data.get("host") or target_url,
                        "port": None,
                        "parameter": None,
                        "evidence": redact_evidence(raw_evidence),
                        "remediation": remediation,
                        "references": json.dumps(info.get("reference", []) if isinstance(info.get("reference"), list) else []),
                        "status": "open",
                        "fingerprint_hash": fp_hash
                    })
                except Exception:
                    continue

        return findings
