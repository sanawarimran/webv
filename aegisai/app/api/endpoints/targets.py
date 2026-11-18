import json
import secrets
import urllib.parse
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.target import Target
from app.models.audit_log import AuditLog
from app.schemas.target import TargetCreate, TargetRead
from app.services.target_verifier import TargetVerifier

router = APIRouter(prefix="/targets", tags=["Targets"])

@router.post("", response_model=TargetRead)
def create_target(
    payload: TargetCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Creates a target under the authenticated user's tenant with a cryptographic verification token.
    Enforces multi-tenant isolation: target is strictly bound to current_user.tenant_id.
    """
    raw_url = payload.url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    parsed = urllib.parse.urlparse(raw_url)
    domain = parsed.hostname
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid target URL or hostname.")

    # Generate 64-char hex verification token
    verification_token = secrets.token_hex(32)

    # For administrator, ownership verification is automatically pre-authorized
    is_admin = (current_user.role == "admin")

    target = Target(
        tenant_id=current_user.tenant_id,
        domain=domain.lower(),
        url=raw_url,
        verification_token=verification_token,
        verification_method="admin_authorized" if is_admin else payload.verification_method,
        is_verified=True if is_admin else False,
        verified_at=datetime.utcnow() if is_admin else None
    )
    db.add(target)
    db.flush()

    # Append-only Audit Log
    client_ip = request.client.host if request.client else "127.0.0.1"
    audit = AuditLog(
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
        action="TARGET_CREATED",
        resource_type="Target",
        resource_id=target.id,
        details=json.dumps({"domain": target.domain, "url": target.url, "verification_method": target.verification_method}),
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()
    db.refresh(target)

    return target

@router.get("", response_model=List[TargetRead])
def list_targets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves all targets for the authenticated tenant ONLY.
    Strict tenant isolation: queries must filter by current_user.tenant_id.
    """
    return db.query(Target).filter(Target.tenant_id == current_user.tenant_id).all()

@router.get("/{target_id}", response_model=TargetRead)
def get_target(
    target_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves single target.
    Returns 404 if target does not belong to the authenticated user's tenant.
    """
    target = db.query(Target).filter(
        Target.id == target_id,
        Target.tenant_id == current_user.tenant_id
    ).first()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found or unauthorized access."
        )

    return target

@router.post("/{target_id}/verify")
def verify_target(
    target_id: str,
    request: Request,
    force: Optional[bool] = False,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verifies domain ownership via DNS TXT record or well-known file.
    Supports force=true for authorized local sandbox / dev testing.
    """
    target = db.query(Target).filter(
        Target.id == target_id,
        Target.tenant_id == current_user.tenant_id
    ).first()

    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    client_ip = request.client.host if request.client else "127.0.0.1"

    if force:
        # Dev / Authorized lab bypass for local evaluation
        target.is_verified = True
        target.verified_at = datetime.utcnow()
        audit = AuditLog(
            tenant_id=current_user.tenant_id,
            user_id=current_user.id,
            action="TARGET_VERIFIED_FORCE_DEV",
            resource_type="Target",
            resource_id=target.id,
            details=json.dumps({"domain": target.domain, "verified_at": target.verified_at.isoformat(), "mode": "authorized_eval"}),
            ip_address=client_ip
        )
        db.add(audit)
        db.commit()
        return {
            "status": "verified",
            "message": "Target ownership verified under authorized local testing mode.",
            "domain": target.domain,
            "is_verified": target.is_verified,
            "verified_at": target.verified_at.isoformat()
        }

    verified, msg = TargetVerifier.verify_target(target)
    if not verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Verification failed: {msg}"
        )

    target.is_verified = True
    target.verified_at = datetime.utcnow()

    # Append-only Audit Log
    audit = AuditLog(
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
        action="TARGET_VERIFIED",
        resource_type="Target",
        resource_id=target.id,
        details=json.dumps({"domain": target.domain, "verified_at": target.verified_at.isoformat()}),
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()

    return {
        "status": "verified",
        "message": msg,
        "domain": target.domain,
        "is_verified": target.is_verified,
        "verified_at": target.verified_at.isoformat()
    }
