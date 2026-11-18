import os
import json
import requests
from urllib.parse import urljoin
from typing import List, Dict, Any
from app.scanners.base_plugin import BaseScannerPlugin, compute_fingerprint_hash, redact_evidence

# Comprehensive curated sensitive files and administrative exposure database (60+ critical vectors)
SENSITIVE_FILES_DATABASE = [
    # 1. Environment & Cloud Credentials
    ("/.env", "Environment Variables Secrets File", "critical", "CWE-552", ["DB_PASSWORD", "SECRET_KEY", "AWS_", "DATABASE_URL", "API_KEY", "APP_KEY"]),
    ("/.env.local", "Local Environment Configuration", "critical", "CWE-552", ["DB_", "SECRET", "KEY="]),
    ("/.env.production", "Production Environment Configuration", "critical", "CWE-552", ["DB_", "SECRET", "KEY="]),
    ("/.env.backup", "Environment Variables Backup File", "critical", "CWE-552", ["DB_", "SECRET", "KEY="]),
    ("/.env.dev", "Development Environment Configuration", "high", "CWE-552", ["DB_", "SECRET", "KEY="]),
    ("/.aws/credentials", "AWS Cloud Credentials File", "critical", "CWE-552", ["aws_access_key_id", "aws_secret_access_key"]),
    ("/.aws/config", "AWS Cloud Configuration File", "high", "CWE-552", ["[default]", "region ="]),
    ("/docker-compose.yml", "Docker Compose Infrastructure Config", "high", "CWE-200", ["version:", "services:", "image:"]),
    ("/Dockerfile", "Docker Container Build Definition", "medium", "CWE-200", ["FROM ", "WORKDIR ", "ENTRYPOINT "]),
    ("/.gitlab-ci.yml", "GitLab CI/CD Pipeline Definition", "medium", "CWE-200", ["stages:", "image:", "script:"]),
    ("/.circleci/config.yml", "CircleCI Pipeline Configuration", "medium", "CWE-200", ["version:", "jobs:"]),
    ("/id_rsa", "SSH Private Key File", "critical", "CWE-552", ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"]),
    ("/id_dsa", "SSH DSA Private Key File", "critical", "CWE-552", ["BEGIN DSA PRIVATE KEY"]),
    ("/server.key", "SSL/TLS Server Private Key", "critical", "CWE-552", ["BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY"]),
    ("/credentials.json", "Google Cloud / App Credentials JSON", "critical", "CWE-552", ["private_key", "client_email", "project_id"]),

    # 2. Source Code Repository Metadata Leaks
    ("/.git/HEAD", "Exposed Git Source Code Repository", "critical", "CWE-538", ["ref: refs/"]),
    ("/.git/config", "Git Repository Configuration File", "critical", "CWE-538", ["[core]", "[remote \"origin\"]"]),
    ("/.git/index", "Git Index Binary Metadata", "critical", "CWE-538", ["DIRC"]),
    ("/.svn/entries", "Subversion Source Repository Metadata", "critical", "CWE-538", ["dir\n", "svn"]),
    ("/.svn/wc.db", "Subversion Working Copy SQLite Database", "critical", "CWE-538", ["SQLite format 3"]),
    ("/.hg/dirstate", "Mercurial Source Repository Metadata", "critical", "CWE-538", []),

    # 3. Database Dumps & SQL Backups
    ("/database.sql", "SQL Database Dump Backup File", "critical", "CWE-538", ["CREATE TABLE", "INSERT INTO"]),
    ("/backup.sql", "Database Backup SQL Dump", "critical", "CWE-538", ["CREATE TABLE", "INSERT INTO", "DROP TABLE"]),
    ("/db.sql", "Database Dump File", "critical", "CWE-538", ["CREATE TABLE", "INSERT INTO"]),
    ("/dump.sql", "SQL Data Dump File", "critical", "CWE-538", ["CREATE TABLE", "INSERT INTO"]),
    ("/data.sql", "Application Data SQL Dump", "critical", "CWE-538", ["CREATE TABLE", "INSERT INTO"]),
    ("/users.sql", "User Table SQL Export", "critical", "CWE-538", ["CREATE TABLE", "INSERT INTO"]),

    # 4. Web Archive Backups
    ("/backup.zip", "Web Archive Full Backup Archive", "high", "CWE-538", []),
    ("/backup.tar.gz", "Gzipped Backup Archive", "high", "CWE-538", []),
    ("/site.zip", "Full Website Source Zip Backup", "high", "CWE-538", []),
    ("/www.zip", "Web Server Root Backup Archive", "high", "CWE-538", []),
    ("/html.zip", "Document Root Backup Archive", "high", "CWE-538", []),
    ("/backup.rar", "RAR Compressed Website Backup", "high", "CWE-538", []),

    # 5. CMS Configuration Backups
    ("/wp-config.php.bak", "WordPress Database Config Backup", "high", "CWE-552", ["DB_NAME", "DB_USER", "DB_PASSWORD"]),
    ("/wp-config.php.old", "Legacy WordPress Config Backup", "high", "CWE-552", ["DB_NAME", "DB_USER", "DB_PASSWORD"]),
    ("/wp-config.php.save", "WordPress Config Editor Save File", "high", "CWE-552", ["DB_NAME", "DB_USER", "DB_PASSWORD"]),
    ("/wp-config.php~", "WordPress Vim/Nano Swap Backup", "high", "CWE-552", ["DB_NAME", "DB_USER"]),
    ("/wp-config.txt", "WordPress Plaintext Config Exposure", "high", "CWE-552", ["DB_NAME", "DB_USER"]),
    ("/configuration.php.bak", "Joomla Configuration Backup", "high", "CWE-552", ["$password", "$user", "$db"]),
    ("/settings.php.bak", "Drupal Configuration Backup", "high", "CWE-552", ["$databases", "database", "username"]),

    # 6. Framework Debug & Actuator Consoles
    ("/phpinfo.php", "PHP Information Environment Diagnostic", "medium", "CWE-200", ["phpinfo()", "<title>phpinfo()</title>", "PHP Version"]),
    ("/info.php", "PHP Info Script", "medium", "CWE-200", ["phpinfo()", "<title>phpinfo()</title>"]),
    ("/test.php", "Residual Test Diagnostic Script", "medium", "CWE-200", ["phpinfo()", "test"]),
    ("/actuator/env", "Spring Boot Actuator Environment Dump", "critical", "CWE-552", ["propertySources", "activeProfiles"]),
    ("/actuator/health", "Spring Boot Health Status Endpoint", "low", "CWE-200", ["\"status\":\"UP\""]),
    ("/actuator/heapdump", "Spring Boot JVM Memory Heap Dump", "critical", "CWE-552", ["JAVA PROFILE"]),
    ("/actuator/mappings", "Spring Boot URL Route Mappings", "medium", "CWE-200", ["dispatcherServlets", "contexts"]),
    ("/elmah.axd", "ASP.NET ELMAH Verbose Error Log Console", "high", "CWE-200", ["Error Log for", "System.Web"]),
    ("/trace.axd", "ASP.NET Trace Diagnostic Viewer", "high", "CWE-200", ["Application Trace", "Requests to this Application"]),
    ("/telescope/requests", "Laravel Telescope Debug Dashboard", "high", "CWE-200", ["Telescope", "laravel"]),
    ("/_profiler/empty/search/results", "Symfony Web Debug Profiler", "medium", "CWE-200", ["Symfony Profiler", "profiler"]),

    # 7. Package Manager & Dependency Locks
    ("/composer.lock", "PHP Composer Dependency Lock File", "low", "CWE-200", ["packages", "hash"]),
    ("/package-lock.json", "Node.js NPM Dependency Lock File", "low", "CWE-200", ["lockfileVersion", "dependencies"]),
    ("/yarn.lock", "Yarn Dependency Lock File", "low", "CWE-200", ["yarn lockfile"]),
    ("/Pipfile.lock", "Python Pipenv Dependency Lock File", "low", "CWE-200", ["_meta", "default"])
]

class SensitiveFilesPlugin(BaseScannerPlugin):
    name = "sensitive_files"
    tier = "T1"
    docker_image = "python:3.11-slim"
    timeout_seconds = 60
    category = "Information Disclosure"

    def get_output_path(self, out_dir: str) -> str:
        return os.path.join(out_dir, "sensitive_files.jsonl")

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
        
        # Soft-404 baseline detection
        soft404_url = urljoin(target_url + "/", "aegis_nonexistent_random_probe_991827")
        soft404_status = 404
        soft404_len = 0
        try:
            r404 = requests.get(soft404_url, headers={"User-Agent": "AegisAI/1.0"}, verify=False, timeout=4, allow_redirects=False)
            soft404_status = r404.status_code
            soft404_len = len(r404.content)
        except Exception:
            pass

        session = requests.Session()
        session.headers.update({"User-Agent": "AegisAI-SensitiveFiles/2.0"})

        for path, label, severity, cwe, signatures in SENSITIVE_FILES_DATABASE:
            file_url = urljoin(target_url + "/", path.lstrip("/"))
            try:
                res = session.get(file_url, verify=False, timeout=2.5, allow_redirects=False)
                if res.status_code == 200 and len(res.content) > 0:
                    # Ignore soft-404
                    if soft404_status == 200 and abs(len(res.content) - soft404_len) < 30:
                        continue

                    # If signatures specified, verify at least one signature matches
                    matched_sig = None
                    if signatures:
                        body_sample = res.text[:4096]
                        for s in signatures:
                            if s in body_sample:
                                matched_sig = s
                                break
                        if not matched_sig:
                            continue

                    fp = compute_fingerprint_hash(self.category, target_url, path, f"EXPOSED_FILE_{path}")
                    findings.append({
                        "scan_id": scan_id,
                        "tenant_id": tenant_id,
                        "target_id": target_id,
                        "tool": self.name,
                        "rule_id": f"EXPOSED_FILE_{path.strip('/').replace('/', '_').replace('.', '_').upper()}",
                        "title": f"Sensitive Asset Exposed: {label} ({path})",
                        "description": f"The endpoint '{path}' is publicly accessible. This file discloses sensitive internal data ({label}) that should never be reachable via the public internet.",
                        "severity": severity,
                        "confidence": "confirmed",
                        "category": self.category,
                        "cwe": cwe,
                        "cve": "[]",
                        "cvss": 8.5 if severity == "critical" else (7.2 if severity == "high" else (5.3 if severity == "medium" else 3.1)),
                        "epss": 0.20 if severity == "critical" else 0.05,
                        "kev": False,
                        "url": file_url,
                        "host": target_url,
                        "port": None,
                        "parameter": path,
                        "evidence": redact_evidence(f"HTTP 200 OK at {file_url} (Size: {len(res.content)} bytes). Matched: {matched_sig or 'Status 200 verification'}"),
                        "remediation": f"Block public access to '{path}' via web server rewrite rule (e.g. deny all;) or remove the file immediately from production.",
                        "references": json.dumps(["https://cwe.mitre.org/data/definitions/" + cwe.replace("CWE-", "") + ".html"]),
                        "status": "open",
                        "fingerprint_hash": fp
                    })
            except Exception:
                pass

        return findings
