import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi import HTTPException

from app.core.database import Base
from app.models.tenant import Tenant
from app.models.user import User
from app.models.target import Target
from app.models.audit_log import AuditLog
from app.schemas.auth import UserRegisterRequest, UserLoginRequest
from app.schemas.target import TargetCreate
from app.api.endpoints import auth, targets
from app.core.security import decode_token

# In-memory SQLite engine for testing
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)

class MockClient:
    host = "127.0.0.1"

class MockRequest:
    client = MockClient()

def test_user_registration_and_jwt_payload():
    """Verify tenant registration, password hashing, and multi-tenant JWT payload."""
    db = TestingSessionLocal()
    req = MockRequest()
    payload = UserRegisterRequest(
        tenant_name="Provilance Technologies",
        email="admin@provilance.com",
        password="SuperPassword123!",
        role="admin"
    )

    res = auth.register(payload=payload, request=req, db=db)
    assert res.access_token is not None
    assert res.tenant_name == "Provilance Technologies"
    assert res.role == "admin"

    # Decode and verify token claims
    token_claims = decode_token(res.access_token)
    assert token_claims["sub"] == res.user_id
    assert token_claims["tenant_id"] == res.tenant_id
    assert token_claims["role"] == "admin"

    # Verify user exists in database with bcrypt hash
    user = db.query(User).filter(User.id == res.user_id).first()
    assert user is not None
    assert user.hashed_password.startswith("$2b$")
    assert user.tenant_id == res.tenant_id

    db.close()

def test_login_success_and_invalid_credentials():
    """Verify login authentication and rejection of bad credentials."""
    db = TestingSessionLocal()
    req = MockRequest()

    # 1. Register
    reg_payload = UserRegisterRequest(
        tenant_name="Provilance Security Lab",
        email="auditor@provilance.com",
        password="CorrectPassword123!",
        role="auditor"
    )
    auth.register(payload=reg_payload, request=req, db=db)

    # 2. Login Success
    login_payload = UserLoginRequest(
        email="auditor@provilance.com",
        password="CorrectPassword123!"
    )
    login_res = auth.login(payload=login_payload, request=req, db=db)
    assert login_res.access_token is not None

    # 3. Invalid Password -> 401
    bad_payload = UserLoginRequest(
        email="auditor@provilance.com",
        password="WrongPassword123!"
    )
    with pytest.raises(HTTPException) as exc_info:
        auth.login(payload=bad_payload, request=req, db=db)
    assert exc_info.value.status_code == 401

    db.close()

def test_multi_tenant_isolation_targets():
    """
    CORE ACCEPTANCE TEST:
    Strictly proves Tenant A CANNOT list, read, or access Tenant B's targets.
    """
    db = TestingSessionLocal()
    req = MockRequest()

    # 1. Register Tenant Alpha
    reg_a = auth.register(
        payload=UserRegisterRequest(
            tenant_name="Alpha Corp",
            email="admin@alpha.com",
            password="AlphaPassword123!",
            role="admin"
        ),
        request=req,
        db=db
    )
    user_a = db.query(User).filter(User.id == reg_a.user_id).first()

    # 2. Register Tenant Beta
    reg_b = auth.register(
        payload=UserRegisterRequest(
            tenant_name="Beta Inc",
            email="admin@beta.com",
            password="BetaPassword123!",
            role="admin"
        ),
        request=req,
        db=db
    )
    user_b = db.query(User).filter(User.id == reg_b.user_id).first()

    # 3. Tenant Alpha creates target alpha.com
    target_a = targets.create_target(
        payload=TargetCreate(url="https://alpha-portal.internal", verification_method="dns_txt"),
        request=req,
        current_user=user_a,
        db=db
    )
    assert target_a.domain == "alpha-portal.internal"
    assert target_a.tenant_id == user_a.tenant_id

    # 4. Tenant Beta creates target beta.com
    target_b = targets.create_target(
        payload=TargetCreate(url="https://beta-cloud.internal", verification_method="file"),
        request=req,
        current_user=user_b,
        db=db
    )
    assert target_b.domain == "beta-cloud.internal"
    assert target_b.tenant_id == user_b.tenant_id

    # 5. Isolation Check: Tenant Alpha lists targets
    list_a = targets.list_targets(current_user=user_a, db=db)
    assert len(list_a) == 1
    assert list_a[0].id == target_a.id
    assert list_a[0].domain == "alpha-portal.internal"
    # Ensure Tenant Beta's target is NOT visible to Alpha
    assert target_b.id not in [t.id for t in list_a]

    # 6. Isolation Check: Tenant Beta lists targets
    list_b = targets.list_targets(current_user=user_b, db=db)
    assert len(list_b) == 1
    assert list_b[0].id == target_b.id
    assert list_b[0].domain == "beta-cloud.internal"
    # Ensure Tenant Alpha's target is NOT visible to Beta
    assert target_a.id not in [t.id for t in list_b]

    # 7. Cross-Tenant Direct Access Attempt: Tenant Alpha requests Tenant Beta's target ID
    with pytest.raises(HTTPException) as exc_alpha:
        targets.get_target(target_id=target_b.id, current_user=user_a, db=db)
    assert exc_alpha.value.status_code == 404  # Strictly 404 Not Found

    # 8. Cross-Tenant Direct Access Attempt: Tenant Beta requests Tenant Alpha's target ID
    with pytest.raises(HTTPException) as exc_beta:
        targets.get_target(target_id=target_a.id, current_user=user_b, db=db)
    assert exc_beta.value.status_code == 404  # Strictly 404 Not Found

    db.close()

def test_append_only_audit_log_records_tenant_actions():
    """Verify append-only compliance audit trail."""
    db = TestingSessionLocal()
    req = MockRequest()

    # Register user
    reg = auth.register(
        payload=UserRegisterRequest(
            tenant_name="Audit Test Corp",
            email="auditor@audit.com",
            password="AuditPassword123!",
            role="admin"
        ),
        request=req,
        db=db
    )
    user = db.query(User).filter(User.id == reg.user_id).first()

    # Create target
    targets.create_target(
        payload=TargetCreate(url="https://audited-site.org", verification_method="dns_txt"),
        request=req,
        current_user=user,
        db=db
    )

    # Check Audit Logs
    logs = db.query(AuditLog).filter(AuditLog.tenant_id == user.tenant_id).all()
    assert len(logs) == 2
    actions = [l.action for l in logs]
    assert "USER_REGISTERED" in actions
    assert "TARGET_CREATED" in actions

    db.close()
