from typing import Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

class TargetCreate(BaseModel):
    url: str = Field(..., description="Target website URL e.g. https://example.com")
    verification_method: str = Field(default="dns_txt", description="dns_txt, file, or meta")

class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    domain: str
    url: str
    verification_token: str
    verification_method: str
    is_verified: bool
    verified_at: Optional[datetime] = None
    created_at: datetime
