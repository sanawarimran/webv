import os
import sys
import json
import uuid
import socket
import pytest
from datetime import datetime
from unittest.mock import patch

# Add app to path and set isolated test database
os.environ["DATABASE_URL"] = "sqlite:///./test_aegisai.db"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.database import SessionLocal, init_db
from app.models.tenant import Tenant
from app.models.user import User
from app.models.target import Target
from app.models.scan import Scan
from app.models.finding import Finding
from app.services.scan_engine import ScanEngine

def test_scan_engine_execution_flow(monkeypatch):
    init_db()
    db = SessionLocal()

    # Mock DNS resolution to public IP for sandbox environment
    def mock_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    uid = uuid.uuid4().hex[:6]

    # 1. Setup Tenant and Verified Target
    tenant = Tenant(name=f"E2E Tenant {uid}")
    db.add(tenant)
    db.commit()

    user = User(tenant_id=tenant.id, email=f"e2e_{uid}@test.com", hashed_password="pw")
    db.add(user)
    db.commit()

    target = Target(
        tenant_id=tenant.id,
        url=f"https://target-{uid}.example.com",
        domain=f"target-{uid}.example.com",
        verification_token=f"token_{uid}",
        is_verified=True,
        verified_at=datetime.utcnow()
    )
    db.add(target)
    db.commit()

    # 2. Setup Scan Job
    scan = Scan(
        tenant_id=tenant.id,
        target_id=target.id,
        profile="quick",
        tiers='["T1"]',
        consent_t2=False,
        status="queued"
    )
    db.add(scan)
    db.commit()

    # 3. Execute Scan Engine
    ScanEngine.execute_scan(scan.id)

    # 4. Assert Results
    db.refresh(scan)
    assert scan.status == "completed"
    assert scan.duration is not None
    assert scan.duration >= 0

    # Verify scan finished without uncaught errors
    assert scan.finished_at is not None

    db.close()
