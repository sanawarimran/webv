from typing import Optional
from pydantic import BaseModel, Field

class UserRegisterRequest(BaseModel):
    tenant_name: str = Field(..., min_length=2, max_length=100, description="Organization or Tenant Name")
    email: str = Field(..., min_length=3, max_length=255, description="Administrator email address")
    password: str = Field(..., min_length=8, description="Strong account password")
    role: str = Field(default="admin", description="Initial role: admin")

class UserLoginRequest(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    tenant_id: str
    tenant_name: str
    role: str
