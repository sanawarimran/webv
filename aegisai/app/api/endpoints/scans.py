import json
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user
from app.core.ssrf_guard import SSRFGuard, SSRFSecurityException
from app.services.target_verifier import TargetVerifier
from app.services.scan_engine import ScanEngine
from app.services.report_generator import ReportGenerator
from app.models.user import User
from app.models.target import Target
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.audit_log import AuditLog
from app.schemas.scan import ScanCreate, ScanRead, FindingRead

router = APIRouter(prefix="/scans", tags=["Scans"])

@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Launch a Vulnerability Detection Scan:
    - Enforces safety controls: verified domain, 90-day expiry, SSRF protection
    - Strictly rejects T3 requests (exploit-capable tools)
    - Enforces explicit consent for T2
    """
    # 1. HARD RULE: T3 is strictly prohibited
    requested_tiers = [t.upper() for t in payload.tiers]
    if "T3" in requested_tiers:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="T3 exploit-capable tools are prohibited in AegisAI detection platform."
        )

    # 2. HARD RULE: T2 requires explicit consent
    if "T2" in requested_tiers and not payload.consent_t2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="T2 active testing requires explicit consent. Set consent_t2=true."
        )

    # 3. Target Ownership & Tenant Verification
    target = db.query(Target).filter(
        Target.id == payload.target_id,
        Target.tenant_id == current_user.tenant_id
    ).first()

    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")

    is_admin = (current_user.role == "admin")

    if not is_admin:
        if not target.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target domain ownership is not verified. Complete DNS TXT or HTTP verification first."
            )

        if TargetVerifier.is_verification_expired(target):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target verification expired (>90 days old). Re-verification is required before scanning."
            )
    else:
        # Admin privilege: auto-verify if not already verified
        if not target.is_verified:
            target.is_verified = True
            target.verified_at = datetime.utcnow()
            target.verification_method = "admin_authorized"
            db.commit()

    # 4. Pre-flight SSRF Validation
    try:
        SSRFGuard.validate_target_url(target.url, expected_domain=target.domain)
    except SSRFSecurityException as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target URL blocked by SSRF Guard: {str(e)}"
        )

    # 5. Create Scan Record
    scan = Scan(
        tenant_id=current_user.tenant_id,
        target_id=target.id,
        profile=payload.profile.lower(),
        tiers=json.dumps(requested_tiers),
        consent_t2=payload.consent_t2,
        consent_user_id=current_user.id if payload.consent_t2 else None,
        consent_timestamp=datetime.utcnow() if payload.consent_t2 else None,
        status="queued"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # 6. Append-only Audit Log
    audit = AuditLog(
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
        action="SCAN_CREATED",
        resource_type="Scan",
        resource_id=scan.id,
        details=json.dumps({
            "target": target.domain,
            "profile": payload.profile,
            "tiers": requested_tiers,
            "consent_t2": payload.consent_t2
        })
    )
    db.add(audit)
    db.commit()

    # 7. Dispatch background execution
    background_tasks.add_task(ScanEngine.execute_scan, scan.id)

    return scan

@router.get("", response_model=List[ScanRead])
def list_scans(
    target_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Scan).filter(Scan.tenant_id == current_user.tenant_id)
    if target_id:
        query = query.filter(Scan.target_id == target_id)
    return query.order_by(Scan.created_at.desc()).all()

@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == current_user.tenant_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan

@router.get("/{scan_id}/findings", response_model=List[FindingRead])
def get_scan_findings(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == current_user.tenant_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    findings = db.query(Finding).filter(
        Finding.scan_id == scan_id,
        Finding.tenant_id == current_user.tenant_id
    ).all()
    return findings

@router.get("/{scan_id}/report")
def export_scan_report(
    scan_id: str,
    format: str = "json",
    token: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == current_user.tenant_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    target = db.query(Target).filter(Target.id == scan.target_id, Target.tenant_id == current_user.tenant_id).first()
    findings = db.query(Finding).filter(Finding.scan_id == scan.id, Finding.tenant_id == current_user.tenant_id).all()

    fmt = format.lower()
    if fmt == "pdf":
        pdf_bytes = ReportGenerator.generate_pdf_report(scan, target, findings)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=aegisai_report_{scan.id}.pdf"}
        )
    elif fmt == "sarif":
        sarif_content = ReportGenerator.generate_sarif_report(scan, target, findings)
        return Response(content=sarif_content, media_type="application/sarif+json")
    elif fmt == "csv":
        csv_content = ReportGenerator.generate_csv_report(scan, target, findings)
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=aegisai_report_{scan.id}.csv"}
        )
    else:
        json_content = ReportGenerator.generate_json_report(scan, target, findings)
        return Response(content=json_content, media_type="application/json")

@router.post("/{scan_id}/cancel")
def cancel_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == current_user.tenant_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    if scan.status in ["queued", "running"]:
        scan.status = "cancelled"
        db.commit()
    return {"status": scan.status, "message": "Scan cancelled."}
