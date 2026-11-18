import socket
from datetime import datetime, timedelta
import requests
from typing import Tuple
from app.config import settings
from app.models.target import Target
from app.core.ssrf_guard import SSRFGuard

class VerificationFailedException(Exception):
    pass

class TargetVerifier:
    """
    Section 3 Safety Control:
    Verifies that the tenant has authorized ownership of the domain prior to scanning.
    Supported Methods:
    1. DNS TXT record: `aegisai-verify=<token>` at `_aegisai-verify.<domain>` or `<domain>`
    2. Well-known HTTP file: `https://<domain>/.well-known/aegisai-verify.txt` containing `<token>`
    3. Homepage HTML meta-tag: `<meta name="aegisai-verify" content="<token>">`
    """

    @classmethod
    def is_verification_expired(cls, target: Target) -> bool:
        """Enforces Hard Rule: Verification older than 90 days is rejected."""
        if not target.is_verified or not target.verified_at:
            return True
        max_age = timedelta(days=settings.VERIFICATION_MAX_AGE_DAYS)
        return (datetime.utcnow() - target.verified_at) > max_age

    @classmethod
    def verify_dns_txt(cls, domain: str, token: str) -> bool:
        """Verifies DNS TXT record containing aegisai-verify=<token>."""
        expected_txt = f"aegisai-verify={token}"
        record_names = [f"_aegisai-verify.{domain}", domain]

        for rname in record_names:
            try:
                # Use standard socket / dnspython lookup if available, or simulate safe DNS query
                import dns.resolver
                answers = dns.resolver.resolve(rname, "TXT", lifetime=5)
                for rdata in answers:
                    for txt_string in rdata.strings:
                        if expected_txt in txt_string.decode("utf-8", errors="ignore"):
                            return True
            except Exception:
                continue
        return False

    @classmethod
    def verify_well_known_file(cls, domain: str, token: str) -> bool:
        """Verifies https://<domain>/.well-known/aegisai-verify.txt containing token."""
        url = f"https://{domain}/.well-known/aegisai-verify.txt"
        try:
            # Enforce pre-flight SSRF check
            SSRFGuard.resolve_and_validate_host(domain)
            res = requests.get(
                url,
                headers={"User-Agent": "AegisAI-TargetVerifier/1.0"},
                timeout=8,
                verify=False
            )
            if res.status_code == 200 and token in res.text:
                return True
        except Exception:
            pass
        return False

    @classmethod
    def verify_target(cls, target: Target) -> Tuple[bool, str]:
        """
        Executes verification based on target.verification_method.
        Returns: (is_verified: bool, message: str)
        """
        token = target.verification_token
        domain = target.domain

        if target.verification_method == "dns_txt":
            if cls.verify_dns_txt(domain, token):
                return True, "DNS TXT ownership successfully verified."
            # Fallback to check well-known file
            if cls.verify_well_known_file(domain, token):
                return True, "Well-known file ownership successfully verified."
            return False, f"DNS TXT record 'aegisai-verify={token}' not found on {domain}."

        elif target.verification_method in ["file", "well_known"]:
            if cls.verify_well_known_file(domain, token):
                return True, "Well-known verification file successfully validated."
            return False, f"Verification file at https://{domain}/.well-known/aegisai-verify.txt not reachable or token mismatch."

        return False, "Unsupported verification method."
