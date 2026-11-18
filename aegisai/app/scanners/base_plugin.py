import os
import re
import hashlib
import json
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime

# Regex for sensitive token / secret redaction in finding evidence
SECRET_PATTERNS = [
    re.compile(r'(AKIA[0-9A-Z]{16})'),                                # AWS Access Key
    re.compile(r'([a-zA-Z0-9_-]{20,}secret[a-zA-Z0-9_-]*)', re.I),   # Generic secrets
    re.compile(r'(ghp_[a-zA-Z0-9]{36})'),                             # GitHub Token
    re.compile(r'(sk_live_[0-9a-zA-Z]{24})'),                         # Stripe Live Key
    re.compile(r'(Bearer\s+[a-zA-Z0-9_\-\.]{20,})', re.I),           # Bearer Tokens
    re.compile(r'(password\s*[:=]\s*["\']?[^"\'\s,]+["\']?)', re.I)   # Passwords
]

def redact_evidence(evidence_text: str, max_chars: int = 2048) -> str:
    """Masks credentials and caps evidence output at 2KB."""
    if not evidence_text:
        return "Observed during scan execution."
    text = str(evidence_text)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED_SECRET]", text)
    if len(text) > max_chars:
        text = text[:max_chars] + "... [TRUNCATED_AT_2KB]"
    return text

def compute_fingerprint_hash(category: str, url_or_host: str, parameter: Optional[str], rule_or_cve: str) -> str:
    """
    Computes Section 5 canonical fingerprint hash for deduplication:
    hash(category + normalised url/host + parameter + cve/rule id)
    """
    norm_url = (url_or_host or "").lower().split("?")[0].rstrip("/")
    norm_param = (parameter or "none").lower()
    norm_rule = (rule_or_cve or "general").upper()
    norm_cat = (category or "misc").lower()
    raw = f"{norm_cat}|{norm_url}|{norm_param}|{norm_rule}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

class BaseScannerPlugin(ABC):
    """
    Section 4 Plugin Interface:
    Every security tool is defined as a plugin with isolation attributes:
    - name: Tool identifier
    - tier: T1 (Default/Safe) or T2 (Consent Required)
    - docker_image: Associated container image
    - timeout_seconds: Hard execution kill cap
    - get_output_path(out_dir): Path to raw output file in /scans/<job_id>/
    - run_scan(target_url, out_dir, tenant_id, scan_id, target_id): Executes scan and returns normalized findings
    """
    name: str = "base_tool"
    tier: str = "T1"  # "T1" or "T2"
    docker_image: str = "alpine:latest"
    timeout_seconds: int = 300
    category: str = "Security Misconfiguration"

    def __init__(self, log_callback=None):
        self.log = log_callback or (lambda msg: None)

    def get_output_path(self, out_dir: str) -> str:
        """Returns standard raw output destination inside /scans/<job_id>/."""
        return os.path.join(out_dir, f"{self.name}.jsonl")

    def build_command(self, target_url: str, out_dir: str, **kwargs) -> List[str]:
        """Optional CLI command builder for external container/binary execution."""
        return ["python", "-c", f"print('{self.name}')"]

    def parse(self, raw_output_path: str, target_url: str, tenant_id: str, scan_id: str, target_id: str) -> List[Dict[str, Any]]:
        """Parses output file into Section 5 normalized finding dictionaries."""
        return []

    @abstractmethod
    def run_scan(self, target_url: str, out_dir: str, tenant_id: str, scan_id: str, target_id: str) -> List[Dict[str, Any]]:
        """
        Executes the detection audit.
        Handles subprocess CLI execution if tool binary is available,
        or performs robust native inspection, writing raw output and returning findings.
        """
        pass
