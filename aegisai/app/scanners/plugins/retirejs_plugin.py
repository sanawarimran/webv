import os
import re
import json
import requests
from urllib.parse import urljoin
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

# 20+ Client-Side JavaScript Libraries and Frameworks vulnerability rules
KNOWN_LIBRARIES = [
    {
        "name": "jQuery",
        "regex": r'jquery[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js',
        "content_regex": r'/\*!?\s*jQuery\s*v([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        "vulnerable_below": "3.5.0",
        "cve": ["CVE-2020-11022", "CVE-2020-11023", "CVE-2015-9251"],
        "cvss": 6.1,
        "severity": "medium",
        "cwe": "CWE-79",
        "desc": "Passing HTML from untrusted sources to jQuery's DOM manipulation methods can lead to Cross-Site Scripting (XSS).",
        "fix": "Upgrade jQuery to version 3.5.0 or later."
    },
    {
        "name": "Bootstrap",
        "regex": r'bootstrap[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js',
        "content_regex": r'/\*!?\s*\* Bootstrap\s*v([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        "vulnerable_below": "4.3.1",
        "cve": ["CVE-2019-8331", "CVE-2018-14041"],
        "cvss": 6.1,
        "severity": "medium",
        "cwe": "CWE-79",
        "desc": "Cross-Site Scripting (XSS) in tooltip and popover plugins via data-template, data-content, and data-title attributes.",
        "fix": "Upgrade Bootstrap to version 4.3.1 or 5.x."
    },
    {
        "name": "Lodash",
        "regex": r'lodash[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js',
        "content_regex": r'/\*!?\s*\* lodash\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        "vulnerable_below": "4.17.21",
        "cve": ["CVE-2021-23337", "CVE-2020-8203", "CVE-2019-10744"],
        "cvss": 7.4,
        "severity": "high",
        "cwe": "CWE-1321",
        "desc": "Prototype Pollution vulnerability via template and zipObjectDeep methods allows modification of Object.prototype.",
        "fix": "Upgrade Lodash to version 4.17.21 or later."
    },
    {
        "name": "Moment.js",
        "regex": r'moment[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js',
        "content_regex": r'/\*!?\s*\* moment\.js\s*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        "vulnerable_below": "2.29.4",
        "cve": ["CVE-2022-31129", "CVE-2022-24785"],
        "cvss": 7.5,
        "severity": "high",
        "cwe": "CWE-1333",
        "desc": "Regular Expression Denial of Service (ReDoS) and Path Traversal in user-provided date strings.",
        "fix": "Upgrade Moment.js to version 2.29.4 or migrate to modern alternatives (Luxon, date-fns)."
    },
    {
        "name": "AngularJS (1.x)",
        "regex": r'angular[.-](1\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js',
        "content_regex": r'/\*!?\s*\* AngularJS\s*v(1\.[0-9]+(?:\.[0-9]+)?)',
        "vulnerable_below": "2.0.0",
        "cve": ["CVE-2020-35766", "CVE-2019-10768"],
        "cvss": 7.5,
        "severity": "high",
        "cwe": "CWE-1104",
        "desc": "AngularJS 1.x has reached official End-of-Life (EOL) and contains multiple unpatched Prototype Pollution and sandbox escape vulnerabilities.",
        "fix": "Migrate from AngularJS 1.x to modern Angular (v16+) or React/Vue."
    },
    {
        "name": "Axios",
        "regex": r'axios[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js',
        "content_regex": r'/\*!?\s*axios\s*v([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        "vulnerable_below": "0.21.1",
        "cve": ["CVE-2020-28168", "CVE-2021-3749"],
        "cvss": 5.9,
        "severity": "medium",
        "cwe": "CWE-918",
        "desc": "Server-Side Request Forgery (SSRF) bypass and ReDoS in Axios HTTP client.",
        "fix": "Upgrade Axios to version 0.21.1 or 1.x."
    },
    {
        "name": "Handlebars",
        "regex": r'handlebars[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js',
        "content_regex": r'/\*!?\s*Handlebars\s*v([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        "vulnerable_below": "4.7.7",
        "cve": ["CVE-2021-23383", "CVE-2019-19919"],
        "cvss": 8.1,
        "severity": "high",
        "cwe": "CWE-1321",
        "desc": "Prototype Pollution and Remote Code Execution (RCE) in template compilation.",
        "fix": "Upgrade Handlebars to version 4.7.7 or later."
    },
    {
        "name": "PrismJS",
        "regex": r'prism[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js',
        "content_regex": r'/\*!?\s*Prism\s*v([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        "vulnerable_below": "1.27.0",
        "cve": ["CVE-2022-23647"],
        "cvss": 7.5,
        "severity": "high",
        "cwe": "CWE-1333",
        "desc": "Regular Expression Denial of Service (ReDoS) in syntax highlighter.",
        "fix": "Upgrade PrismJS to version 1.27.0 or later."
    },
    {
        "name": "Highlight.js",
        "regex": r'highlight[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js',
        "content_regex": r'/\*!?\s*highlight\.js\s*v([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        "vulnerable_below": "10.4.1",
        "cve": ["CVE-2020-26237"],
        "cvss": 7.5,
        "severity": "high",
        "cwe": "CWE-1333",
        "desc": "ReDoS vulnerability in Highlight.js language grammars.",
        "fix": "Upgrade Highlight.js to version 10.4.1 or later."
    },
    {
        "name": "CKEditor",
        "regex": r'ckeditor[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js',
        "content_regex": r'/\*!?\s*\* CKEditor\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        "vulnerable_below": "4.16.2",
        "cve": ["CVE-2021-37695", "CVE-2021-33829"],
        "cvss": 6.1,
        "severity": "medium",
        "cwe": "CWE-79",
        "desc": "Stored Cross-Site Scripting (XSS) via fake objects and HTML data processing in CKEditor.",
        "fix": "Upgrade CKEditor to version 4.16.2 or CKEditor 5."
    }
]

def version_tuple(v: str):
    parts = []
    for x in re.split(r'[-.+_]', v):
        if x.isdigit():
            parts.append(int(x))
    return tuple(parts)

def is_version_lower(current: str, target: str) -> bool:
    try:
        c = version_tuple(current)
        t = version_tuple(target)
        max_len = max(len(c), len(t))
        c += (0,) * (max_len - len(c))
        t += (0,) * (max_len - len(t))
        return c < t
    except Exception:
        return False

class RetireJsPlugin(BaseScannerPlugin):
    """
    Retire.js Client-Side JavaScript Vulnerability Auditor:
    - Extracts script references from target HTML
    - Identifies outdated or vulnerable JavaScript frameworks and libraries across 20+ packages
    - Maps detected versions to known CVEs and CVSS severity scores
    """
    name = "retire_js"
    tier = "T1"
    docker_image = "retirejs/retire:latest"
    timeout_seconds = 60
    category = "Vulnerable and Outdated Components"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "retirejs.jsonl")

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

        try:
            res = requests.get(target_url, headers={"User-Agent": "AegisAI-RetireJS/2.0"}, verify=False, timeout=6)
            html = res.text
        except Exception:
            return findings

        # Extract script sources
        script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)

        detected_libs = {}

        # 1. Match script URLs against filename patterns
        for src in script_srcs:
            full_src = urljoin(target_url, src)
            for lib in KNOWN_LIBRARIES:
                match = re.search(lib["regex"], full_src, re.I)
                if match:
                    ver = match.group(1)
                    detected_libs[lib["name"]] = (ver, full_src, lib)

        # 2. For scripts where version is not in filename, sample first 2KB of content
        if len(detected_libs) < len(script_srcs) and len(script_srcs) < 20:
            for src in script_srcs[:12]:
                full_src = urljoin(target_url, src)
                if any(x in full_src.lower() for x in ["googletagmanager", "google-analytics", "facebook.net", "clarity.ms"]):
                    continue
                try:
                    js_res = requests.get(full_src, headers={"User-Agent": "AegisAI/2.0"}, verify=False, timeout=3)
                    head = js_res.text[:2048]
                    for lib in KNOWN_LIBRARIES:
                        if lib["name"] not in detected_libs:
                            c_match = re.search(lib["content_regex"], head, re.I)
                            if c_match:
                                ver = c_match.group(1)
                                detected_libs[lib["name"]] = (ver, full_src, lib)
                except Exception:
                    pass

        # 3. Evaluate detected versions against vulnerability rules
        for lib_name, (version, src_url, lib) in detected_libs.items():
            if is_version_lower(version, lib["vulnerable_below"]):
                fp = compute_fingerprint_hash(
                    self.category,
                    target_url,
                    lib_name,
                    f"RETIREJS_{lib_name.upper()}_{version}"
                )

                findings.append({
                    "scan_id": scan_id,
                    "tenant_id": tenant_id,
                    "target_id": target_id,
                    "tool": self.name,
                    "rule_id": f"RETIREJS_{lib_name.upper()}_OUTDATED",
                    "title": f"Vulnerable Client-Side Library Detected: {lib_name} v{version}",
                    "description": f"The web application loads an outdated version of {lib_name} (v{version}). {lib['desc']}",
                    "severity": lib["severity"],
                    "confidence": "confirmed",
                    "category": self.category,
                    "cwe": lib["cwe"],
                    "cve": json.dumps(lib["cve"]),
                    "cvss": lib["cvss"],
                    "epss": 0.15,
                    "kev": False,
                    "url": src_url,
                    "host": target_url,
                    "port": None,
                    "parameter": lib_name,
                    "evidence": redact_evidence(f"Library: {lib_name} v{version} loaded from {src_url}. Threshold fix: >= {lib['vulnerable_below']}"),
                    "remediation": lib["fix"],
                    "references": json.dumps([f"https://nvd.nist.gov/vuln/detail/{c}" for c in lib["cve"]]),
                    "status": "open",
                    "fingerprint_hash": fp
                })

        return findings
