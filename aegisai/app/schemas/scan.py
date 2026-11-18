from typing import List, Optional, Any
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

class ScanCreate(BaseModel):
    target_id: str
    profile: str = Field(default="standard", description="quick, standard, or deep")
    tiers: List[str] = Field(default=["T1"], description="T1 (safe/passive) or T2 (active DAST with consent). T3 is prohibited.")
    consent_t2: bool = Field(default=False, description="Explicit user consent required if T2 is selected")

class ScanRead(BaseModel):
    id: str
    tenant_id: str
    target_id: str
    profile: str
    tiers: Any
    consent_t2: bool
    status: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration: Optional[float] = None
    error_message: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class FindingRead(BaseModel):
    id: str
    scan_id: str
    target_id: str
    tool: str
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    category: str
    cwe: str
    cve: Any
    cvss: float
    epss: float
    kev: bool
    url: str
    host: str
    port: Optional[int] = None
    parameter: Optional[str] = None
    evidence: str
    remediation: str
    references: Any
    status: str
    fingerprint_hash: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
