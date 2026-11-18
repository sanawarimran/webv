import os
import sys
import json
import uuid
import pytest
from datetime import datetime, timedelta

# Add app to path and set isolated test database
os.environ["DATABASE_URL"] = "sqlite:///./test_aegisai.db"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.database import SessionLocal, init_db
from app.models.tenant import Tenant
from app.models.user import User
from app.models.target import Target
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.audit_log import AuditLog
from app.core.ssrf_guard import SSRFGuard, SSRFSecurityException
from app.services.target_verifier import TargetVerifier
from app.services.deduplicator import FindingDeduplicator
from app.services.report_generator import ReportGenerator
from app.scanners.base_plugin import compute_fingerprint_hash, redact_evidence
from app.api.endpoints import scans
from app.schemas.scan import ScanCreate
from fastapi import HTTPException, BackgroundTasks

@pytest.fixture(scope="function")
def db_session():
    init_db()
    db = SessionLocal()
    yield db
    db.rollback()
    db.close()

def test_target_ownership_and_90day_expiry(db_session):
    db = db_session
    uid = uuid.uuid4().hex[:6]
    tenant = Tenant(name=f"Expiry Tenant {uid}")
    db.add(tenant)
    db.commit()

    # Expired target (>90 days old)
    old_target = Target(
        tenant_id=tenant.id,
        url=f"https://expired-{uid}.example.com",
        domain=f"expired-{uid}.example.com",
        verification_token=f"tok_old_{uid}",
        is_verified=True,
        verified_at=datetime.utcnow() - timedelta(days=95)
    )
    # Valid verified target (<90 days old)
    fresh_target = Target(
        tenant_id=tenant.id,
        url=f"https://fresh-{uid}.example.com",
        domain=f"fresh-{uid}.example.com",
        verification_token=f"tok_fresh_{uid}",
        is_verified=True,
        verified_at=datetime.utcnow() - timedelta(days=5)
    )
    # Unverified target
    unverified_target = Target(
        tenant_id=tenant.id,
        url=f"https://unverified-{uid}.example.com",
        domain=f"unverified-{uid}.example.com",
        verification_token=f"tok_unverified_{uid}",
        is_verified=False
    )
    db.add_all([old_target, fresh_target, unverified_target])
    db.commit()

    assert TargetVerifier.is_verification_expired(old_target) is True
    assert TargetVerifier.is_verification_expired(fresh_target) is False
    assert old_target.is_verified is True
    assert unverified_target.is_verified is False

def test_ssrf_guard_blocks_private_and_cloud_metadata():
    with pytest.raises(SSRFSecurityException):
        SSRFGuard.validate_target_url("http://127.0.0.1/admin")

    with pytest.raises(SSRFSecurityException):
        SSRFGuard.validate_target_url("http://localhost:8000")

    with pytest.raises(SSRFSecurityException):
        SSRFGuard.validate_target_url("http://169.254.169.254/latest/meta-data/")

    with pytest.raises(SSRFSecurityException):
        SSRFGuard.validate_target_url("http://10.200.1.5")

    with pytest.raises(SSRFSecurityException):
        SSRFGuard.validate_target_url("http://192.168.1.1")

def test_tier3_exploit_tools_strictly_rejected(db_session):
    db = db_session
    uid = uuid.uuid4().hex[:6]
    tenant = Tenant(name=f"T3 Reject Tenant {uid}")
    db.add(tenant)
    db.commit()

    user = User(tenant_id=tenant.id, email=f"t3_{uid}@reject.com", hashed_password="hash")
    db.add(user)
    db.commit()

    # Attempt to request T3
    payload = ScanCreate(target_id="target_dummy", profile="standard", tiers=["T1", "T3"], consent_t2=False)
    bg = BackgroundTasks()

    with pytest.raises(HTTPException) as exc:
        scans.create_scan(payload, bg, db, user)
    assert exc.value.status_code == 400
    assert "T3 exploit-capable tools are prohibited" in exc.value.detail

def test_tier2_consent_safeguard(db_session):
    db = db_session
    uid = uuid.uuid4().hex[:6]
    tenant = Tenant(name=f"T2 Consent Tenant {uid}")
    db.add(tenant)
    db.commit()

    user = User(tenant_id=tenant.id, email=f"t2_{uid}@consent.com", hashed_password="hash")
    db.add(user)
    db.commit()

    # T2 without consent should fail
    payload_no_consent = ScanCreate(target_id="target_dummy", profile="standard", tiers=["T1", "T2"], consent_t2=False)
    bg = BackgroundTasks()

    with pytest.raises(HTTPException) as exc:
        scans.create_scan(payload_no_consent, bg, db, user)
    assert exc.value.status_code == 400
    assert "T2 active testing requires explicit consent" in exc.value.detail

def test_deduplicator_merges_evidence_and_raises_confidence():
    fp = compute_fingerprint_hash("Security Misconfiguration", "https://app.example.com", None, "SEC_HDR_CSP_MISSING")
    
    raw_findings = [
        {
            "tool": "headers_cors",
            "rule_id": "SEC_HDR_CSP_MISSING",
            "title": "Missing Content Security Policy (CSP)",
            "description": "CSP header is missing.",
            "severity": "medium",
            "confidence": "likely",
            "category": "Security Misconfiguration",
            "cwe": "CWE-1021",
            "cvss": 5.4,
            "epss": 0.05,
            "kev": False,
            "url": "https://app.example.com",
            "host": "app.example.com",
            "evidence": "CSP header absent.",
            "remediation": "Add CSP.",
            "fingerprint_hash": fp
        },
        {
            "tool": "nuclei",
            "rule_id": "SEC_HDR_CSP_MISSING",
            "title": "Missing Content Security Policy (CSP)",
            "description": "CSP header is missing.",
            "severity": "medium",
            "confidence": "likely",
            "category": "Security Misconfiguration",
            "cwe": "CWE-1021",
            "cvss": 5.4,
            "epss": 0.05,
            "kev": False,
            "url": "https://app.example.com",
            "host": "app.example.com",
            "evidence": "Nuclei misconfig-csp template triggered.",
            "remediation": "Add CSP.",
            "fingerprint_hash": fp
        }
    ]

    deduped = FindingDeduplicator.deduplicate_and_prioritize(raw_findings)
    assert len(deduped) == 1
    item = deduped[0]
    assert item["confidence"] == "confirmed"
    assert "headers_cors" in item["tools_agreed"]
    assert "nuclei" in item["tools_agreed"]
    assert "Corroborated by nuclei" in item["evidence"]

def test_evidence_redaction_masks_secrets():
    dummy_aws = "AKIA" + "0000000000000000"
    dummy_stripe = "sk_" + "live_" + "000000000000000000000000"
    leak_sample = f"Database dump: password='super_secret_pass_123', AWS_KEY={dummy_aws}, stripe={dummy_stripe}"
    redacted = redact_evidence(leak_sample)
    assert "super_secret_pass_123" not in redacted
    assert dummy_aws not in redacted
    assert dummy_stripe not in redacted
    assert "[REDACTED_SECRET]" in redacted

def test_report_generator_json_sarif_csv(db_session):
    db = db_session
    uid = uuid.uuid4().hex[:6]
    tenant = Tenant(name=f"Report Tenant {uid}")
    db.add(tenant)
    db.commit()

    target = Target(tenant_id=tenant.id, url=f"https://report-{uid}.example.com", domain=f"report-{uid}.example.com", verification_token=f"tok_{uid}", is_verified=True)
    db.add(target)
    db.commit()

    scan = Scan(tenant_id=tenant.id, target_id=target.id, profile="standard", tiers='["T1"]', status="completed", duration=12.5)
    db.add(scan)
    db.commit()

    finding = Finding(
        scan_id=scan.id,
        tenant_id=tenant.id,
        target_id=target.id,
        tool="nuclei",
        rule_id="NUCLEI_EXPOSURE_GIT",
        title="Exposed Git Repository",
        description="Found .git/HEAD exposed.",
        severity="critical",
        confidence="confirmed",
        category="Information Disclosure",
        cwe="CWE-538",
        cve="[]",
        cvss=9.8,
        epss=0.85,
        kev=True,
        url=f"https://report-{uid}.example.com/.git/HEAD",
        host=f"report-{uid}.example.com",
        evidence="ref: refs/heads/main",
        remediation="Block access to .git",
        references="[]",
        fingerprint_hash=f"testhash_{uid}"
    )
    db.add(finding)
    db.commit()

    # 1. JSON Report
    json_rep = ReportGenerator.generate_json_report(scan, target, [finding])
    data = json.loads(json_rep)
    assert data["scan_metadata"]["scan_id"] == scan.id
    assert len(data["findings"]) == 1
    assert data["findings"][0]["severity"] == "critical"

    # 2. SARIF 2.1.0 Report
    sarif_rep = ReportGenerator.generate_sarif_report(scan, target, [finding])
    sarif_data = json.loads(sarif_rep)
    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "AegisAI Vulnerability Scanner"
    assert len(sarif_data["runs"][0]["results"]) == 1
    assert sarif_data["runs"][0]["results"][0]["level"] == "error"

    # 3. CSV Report
    csv_rep = ReportGenerator.generate_csv_report(scan, target, [finding])
    assert "Finding ID,Severity,Confidence,Title" in csv_rep
    assert "CRITICAL" in csv_rep
    assert "Exposed Git Repository" in csv_rep

    # 4. Professional PDF Report
    pdf_bytes = ReportGenerator.generate_pdf_report(scan, target, [finding])
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_bytes
    assert len(pdf_bytes) > 500

def test_threat_intel_cisa_kev_and_epss():
    from app.services.threat_intel import ThreatIntelService
    finding = {
        "title": "Log4j RCE",
        "description": "JNDI lookup flaw",
        "cve": ["CVE-2021-44228"],
        "cvss": 10.0,
        "epss": 0.0,
        "kev": False
    }
    enriched = ThreatIntelService.enrich_finding(finding)
    assert enriched["kev"] is True
    assert "CISA KEV" in enriched["title"]
    assert enriched["epss"] > 0.0
    assert enriched["priority_score"] >= 13.0  # 10 + 3 KEV boost

def test_email_notifier_alert():
    from app.services.email_notifier import EmailNotifier
    scan = Scan(id="test_scan", profile="quick", duration=4.2)
    target = Target(url="https://alert.example.com", domain="alert.example.com")
    findings = [{"severity": "critical", "title": "Critical Flaw", "kev": True}]
    success = EmailNotifier.send_scan_completion_alert("admin@example.com", scan, target, findings)
    assert success is True

