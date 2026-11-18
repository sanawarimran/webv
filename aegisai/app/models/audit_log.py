import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base

class AuditLog(Base):
    """
    Append-only compliance audit trail.
    Tracks every verification, scan lifecycle, user consent, tool execution, and exit codes.
    """
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)  # e.g., USER_REGISTERED, TARGET_VERIFIED, SCAN_DISPATCHED
    resource_type = Column(String(50), nullable=False)        # e.g., Target, Scan, ToolWorker
    resource_id = Column(String(64), nullable=False)
    details = Column(Text, nullable=False)                    # JSON serialized metadata
    ip_address = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    tenant = relationship("Tenant", back_populates="audit_logs")
