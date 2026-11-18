import os
from typing import List
from pydantic import BaseModel, Field

class Settings(BaseModel):
    PROJECT_NAME: str = "AegisAI Vulnerability Detection Platform"
    ORGANIZATION: str = "Provilance Technologies"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Environment & Security Keys
    SECRET_KEY: str = Field(default_factory=lambda: os.getenv("SECRET_KEY", "aegisai-enterprise-secret-key-32chars-minimum"))
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day

    # Database & Cache (Defaults to SQLite for local development & automated unit tests)
    DATABASE_URL: str = Field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./aegisai.db"))
    REDIS_URL: str = Field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))

    # Section 3 Safety Controls
    VERIFICATION_MAX_AGE_DAYS: int = 90  # Hard rule: Reject verification older than 90 days
    T1_RATE_LIMIT_RPS: int = 10
    T2_RATE_LIMIT_RPS: int = 20
    CONTAINER_TIMEOUT_SECONDS: int = 600  # 10 min hard kill per tool container

    # SSRF & Private IP Denylist
    BLOCKED_IP_NETWORKS: List[str] = [
        "127.0.0.0/8",       # Loopback
        "10.0.0.0/8",        # Private Class A
        "172.16.0.0/12",     # Private Class B
        "192.168.0.0/16",    # Private Class C
        "169.254.0.0/16",    # Link-Local / Cloud Metadata (169.254.169.254)
        "100.64.0.0/10",     # Carrier-grade NAT
        "0.0.0.0/8",         # Broadcast
        "::1/128",           # IPv6 loopback
        "fc00::/7",          # IPv6 Unique Local Address
        "fe80::/10"          # IPv6 Link-Local
    ]

settings = Settings()
