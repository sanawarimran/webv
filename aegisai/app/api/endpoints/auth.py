import json
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import hash_password, verify_password, create_access_token
from app.models.tenant import Tenant
from app.models.user import User
from app.models.audit_log import AuditLog
from app.schemas.auth import UserRegisterRequest, UserLoginRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=TokenResponse)
def register(payload: UserRegisterRequest, request: Request, db: Session = Depends(get_db)):
    """Registers a new Organization/Tenant and root administrator."""
    existing_user = db.query(User).filter(User.email == payload.email.lower()).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    # 1. Create Tenant
    tenant = Tenant(name=payload.tenant_name.strip())
    db.add(tenant)
    db.flush()

    # 2. Create User
    user = User(
        tenant_id=tenant.id,
        email=payload.email.lower(),
        hashed_password=hash_password(payload.password),
        role=payload.role
    )
    db.add(user)
    db.flush()

    # 3. Append-only Audit Log
    client_ip = request.client.host if request.client else "127.0.0.1"
    audit = AuditLog(
        tenant_id=tenant.id,
        user_id=user.id,
        action="USER_REGISTERED",
        resource_type="User",
        resource_id=user.id,
        details=json.dumps({"tenant_name": tenant.name, "email": user.email, "role": user.role}),
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()

    token_data = {
        "sub": user.id,
        "tenant_id": tenant.id,
        "role": user.role,
        "email": user.email
    }
    access_token = create_access_token(token_data)

    return TokenResponse(
        access_token=access_token,
        user_id=user.id,
        tenant_id=tenant.id,
        tenant_name=tenant.name,
        role=user.role
    )

@router.post("/login", response_model=TokenResponse)
def login(payload: UserLoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticates user credentials and issues scoped multi-tenant JWT."""
    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive. Contact Provilance administrator."
        )

    tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Append-only Audit Log
    audit = AuditLog(
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="USER_LOGIN",
        resource_type="User",
        resource_id=user.id,
        details=json.dumps({"email": user.email}),
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()

    token_data = {
        "sub": user.id,
        "tenant_id": user.tenant_id,
        "role": user.role,
        "email": user.email
    }
    access_token = create_access_token(token_data)

    return TokenResponse(
        access_token=access_token,
        user_id=user.id,
        tenant_id=user.tenant_id,
        tenant_name=tenant.name if tenant else "Default",
        role=user.role
    )
