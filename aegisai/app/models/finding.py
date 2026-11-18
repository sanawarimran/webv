import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Float, Integer, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    
    tool = Column(String(64), nullable=False)
    rule_id = Column(String(128), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(32), nullable=False)  # critical, high, medium, low, info
    confidence = Column(String(32), default="confirmed", nullable=False)  # confirmed, likely, suspected
    category = Column(String(128), default="Security Misconfiguration", nullable=False)
    cwe = Column(String(64), default="CWE-693", nullable=False)
    cve = Column(Text, default="[]", nullable=False)  # JSON list
    cvss = Column(Float, default=0.0, nullable=False)
    epss = Column(Float, default=0.0, nullable=False)
    kev = Column(Boolean, default=False, nullable=False)
    url = Column(String(2048), nullable=False)
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=True)
    parameter = Column(String(255), nullable=True)
    evidence = Column(Text, nullable=False)  # Trimmed & secrets redacted (capped at 2KB)
    remediation = Column(Text, nullable=False)
    references = Column(Text, default="[]", nullable=False)  # JSON list
    
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String(32), default="open", nullable=False)  # open, fixed, accepted_risk, false_positive
    fingerprint_hash = Column(String(64), nullable=False, index=True)

    @property
    def created_at(self):
        return self.first_seen

    tenant = relationship("Tenant", back_populates="findings")
    target = relationship("Target", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")
