import os
import json
import time
import base64
import requests
import subprocess
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.ssrf_guard import SSRFGuard, SSRFSecurityException
from app.services.target_verifier import TargetVerifier
from app.services.deduplicator import FindingDeduplicator
from app.services.email_notifier import EmailNotifier
from app.models.scan import Scan
from app.models.target import Target
from app.models.finding import Finding
from app.models.user import User
from app.models.audit_log import AuditLog

# Import all tool plugins
from app.scanners.plugins.nuclei_plugin import NucleiPlugin
from app.scanners.plugins.nuclei_dast_plugin import NucleiDastPlugin
from app.scanners.plugins.observatory_plugin import ObservatoryPlugin
from app.scanners.plugins.tls_plugin import TlsPlugin
from app.scanners.plugins.headers_cors_plugin import HeadersCorsPlugin
from app.scanners.plugins.nmap_plugin import NmapPortPlugin
from app.scanners.plugins.sensitive_files_plugin import SensitiveFilesPlugin
from app.scanners.plugins.api_security_plugin import ApiSecurityPlugin
from app.scanners.plugins.wpscan_plugin import WPScanPlugin
from app.scanners.plugins.cms_plugin import CmsPlugin
from app.scanners.plugins.zap_baseline_plugin import ZapBaselinePlugin
from app.scanners.plugins.retirejs_plugin import RetireJsPlugin
from app.scanners.plugins.takeover_plugin import SubdomainTakeoverPlugin
from app.scanners.plugins.cookie_security_plugin import CookieSecurityPlugin
from app.scanners.plugins.csp_deep_plugin import CspDeepPlugin
from app.scanners.plugins.open_redirect_plugin import OpenRedirectPlugin
from app.scanners.plugins.tech_fingerprint_plugin import TechFingerprintPlugin
from app.scanners.plugins.nikto_plugin import NiktoPlugin
from app.scanners.plugins.http_methods_plugin import HttpMethodsPlugin
from app.scanners.plugins.input_hygiene_plugin import InputHygienePlugin

ES_HOST = "https://localhost:9200"
ES_USER = "elastic"
ES_PASS = "admin1"

def push_findings_to_elasticsearch(scan_report: dict) -> bool:
    """Index scan report into local Elasticsearch cluster if active."""
    try:
        url = f"{ES_HOST}/vuln-scans/_doc"
        auth = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode("ascii")
        headers = {"Content-Type": "application/json", "Authorization": f"Basic {auth}"}
        res = requests.post(url, json=scan_report, headers=headers, verify=False, timeout=3)
        return res.status_code in [200, 201]
    except Exception:
        return False

class ScanEngine:
    """
    Core Pipeline Executor:
    - Enforces SSRF and 90-day ownership guardrails
    - Dispatches isolated tool plugins with timeout protection
    - Supports 'quick', 'standard', and 'deep' profiles
    - Recovers gracefully from tool failures (never aborts entire scan)
    - Deduplicates findings, enriches with CISA KEV/EPSS, and notifies via Email
    """

    @classmethod
    def get_plugins_for_profile(cls, profile: str, consent_t2: bool = False) -> list:
        profile_lower = (profile or "standard").lower()

        # Base passive checks included in all profiles
        base_plugins = [
            HeadersCorsPlugin(),
            TlsPlugin(),
            ObservatoryPlugin(),
            SensitiveFilesPlugin(),
            ApiSecurityPlugin(),
            NmapPortPlugin(),
            CmsPlugin(),
            CookieSecurityPlugin(),
            CspDeepPlugin(),
            SubdomainTakeoverPlugin(),
            TechFingerprintPlugin(),
            HttpMethodsPlugin()
        ]

        if profile_lower == "quick":
            return base_plugins

        # Standard includes Nuclei T1, RetireJS, Nikto, WPScan, and ZAP baseline
        standard_plugins = base_plugins + [
            RetireJsPlugin(),
            NiktoPlugin(),
            WPScanPlugin(),
            ZapBaselinePlugin(),
            NucleiPlugin()
        ]

        if profile_lower == "deep":
            # Deep includes Nuclei DAST, OpenRedirect, and InputHygiene if T2 consent is present
            if consent_t2:
                standard_plugins.extend([
                    NucleiDastPlugin(),
                    OpenRedirectPlugin(),
                    InputHygienePlugin()
                ])
            return standard_plugins

        return standard_plugins

    @classmethod
    def execute_scan(cls, scan_id: str):
        db: Session = SessionLocal()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            db.close()
            return

        target = db.query(Target).filter(Target.id == scan.target_id).first()
        if not target:
            scan.status = "failed"
            scan.error_message = "Target not found."
            db.commit()
            db.close()
            return

        # 1. Ownership & Expiration Guard (Enforced for regular users; admin is pre-authorized)
        is_admin_scan = False
        if target.verification_method == "admin_authorized":
            is_admin_scan = True
        elif scan.consent_user_id:
            user = db.query(User).filter(User.id == scan.consent_user_id).first()
            if user and user.role == "admin":
                is_admin_scan = True
        else:
            admin_user = db.query(User).filter(User.tenant_id == scan.tenant_id, User.role == "admin").first()
            if admin_user:
                is_admin_scan = True

        if not is_admin_scan:
            if not target.is_verified or TargetVerifier.is_verification_expired(target):
                scan.status = "failed"
                scan.error_message = "Scan Rejected: Target domain ownership is unverified or verification expired (>90 days)."
                db.commit()
                db.close()
                return

        # 2. SSRF Guard (Resolve DNS & block private/cloud IPs)
        try:
            target_url, host, ips = SSRFGuard.validate_target_url(target.url, expected_domain=target.domain)
        except SSRFSecurityException as e:
            scan.status = "failed"
            scan.error_message = f"Scan Blocked by SSRF Guard: {str(e)}"
            db.commit()
            db.close()
            return

        # Setup output folder (/scans/<job_id>/)
        out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scans", scan.id)
        os.makedirs(out_dir, exist_ok=True)

        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()

        start_time = time.monotonic()
        raw_findings: List[Dict[str, Any]] = []

        # Select plugins based on profile and consent
        plugins = cls.get_plugins_for_profile(scan.profile, consent_t2=scan.consent_t2)

        tool_logs = []

        for plugin in plugins:
            # Check T2 consent safeguard
            if plugin.tier == "T2" and not scan.consent_t2:
                continue

            tool_name = plugin.name
            
            # Execute plugin run_scan
            try:
                tool_start = time.monotonic()
                plugin_findings = plugin.run_scan(target.url, out_dir, scan.tenant_id, scan.id, target.id)
                tool_duration = round(time.monotonic() - tool_start, 2)

                raw_findings.extend(plugin_findings)
                tool_logs.append({
                    "tool": tool_name,
                    "tier": plugin.tier,
                    "status": "success",
                    "duration": tool_duration,
                    "findings": len(plugin_findings)
                })
            except subprocess.TimeoutExpired:
                tool_logs.append({
                    "tool": tool_name,
                    "tier": plugin.tier,
                    "status": "timeout_killed",
                    "error": f"Killed after {plugin.timeout_seconds}s limit"
                })
            except Exception as e:
                # Per spec: Failed tool must not abort the scan
                tool_logs.append({
                    "tool": tool_name,
                    "tier": plugin.tier,
                    "status": "failed",
                    "error": str(e)
                })

        # Deduplicate & Prioritize Findings (with real-time CISA KEV & EPSS enrichment)
        deduped = FindingDeduplicator.deduplicate_and_prioritize(raw_findings)

        # Save to Database
        for item in deduped:
            finding_obj = Finding(
                scan_id=scan.id,
                tenant_id=scan.tenant_id,
                target_id=target.id,
                tool=item["tool"],
                rule_id=item["rule_id"],
                title=item["title"],
                description=item["description"],
                severity=item["severity"],
                confidence=item["confidence"],
                category=item["category"],
                cwe=item["cwe"],
                cve=item.get("cve", "[]"),
                cvss=item.get("cvss", 0.0),
                epss=item.get("epss", 0.0),
                kev=item.get("kev", False),
                url=item["url"],
                host=item["host"],
                port=item.get("port"),
                parameter=item.get("parameter"),
                evidence=item["evidence"],
                remediation=item["remediation"],
                references=item.get("references", "[]"),
                status="open",
                fingerprint_hash=item["fingerprint_hash"]
            )
            db.add(finding_obj)

        scan.finished_at = datetime.utcnow()
        scan.duration = round(time.monotonic() - start_time, 2)
        scan.status = "completed"

        # Append-only Audit Log
        audit = AuditLog(
            tenant_id=scan.tenant_id,
            user_id=scan.consent_user_id,
            action="SCAN_COMPLETED",
            resource_type="Scan",
            resource_id=scan.id,
            details=json.dumps({
                "target": target.domain,
                "profile": scan.profile,
                "duration": scan.duration,
                "tools": tool_logs,
                "findings_count": len(deduped)
            })
        )
        db.add(audit)
        db.commit()

        # Email Notification Alert
        try:
            admin_user = db.query(User).filter(User.tenant_id == scan.tenant_id).first()
            if admin_user and admin_user.email:
                EmailNotifier.send_scan_completion_alert(admin_user.email, scan, target, deduped)
        except Exception:
            pass

        # Ship to Elasticsearch (non-blocking)
        es_payload = {
            "scan_id": scan.id,
            "tenant_id": scan.tenant_id,
            "target_url": target.url,
            "domain": target.domain,
            "status": "completed",
            "duration": scan.duration,
            "findings_count": len(deduped),
            "findings": deduped,
            "timestamp": datetime.utcnow().isoformat()
        }
        push_findings_to_elasticsearch(es_payload)

        db.close()
