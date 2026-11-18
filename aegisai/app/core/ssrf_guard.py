import socket
import ipaddress
import urllib.parse
from typing import List, Tuple
from app.config import settings

class SSRFSecurityException(Exception):
    """Raised when a target or redirect attempts to resolve to an internal/private network."""
    pass

class ScopeViolationException(Exception):
    """Raised when a target host or redirect attempts to probe outside the authorized domain scope."""
    pass

class SSRFGuard:
    """
    Section 3 Safety Control:
    - Pre-flight DNS resolution before scans and after redirects
    - Blocks RFC 1918, loopback, link-local, carrier NAT, and cloud metadata (169.254.169.254)
    - Enforces scope to ensure only authorized domain hosts are audited.
    """
    BLOCKED_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
        ipaddress.ip_network(cidr) for cidr in settings.BLOCKED_IP_NETWORKS
    ]

    @classmethod
    def is_ip_blocked(cls, ip_str: str) -> bool:
        """Evaluates whether an IP address belongs to a prohibited or private CIDR."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in cls.BLOCKED_NETWORKS)
        except ValueError:
            return True  # Block unparseable IP representations

    @classmethod
    def resolve_and_validate_host(cls, host: str, expected_domain: str = None) -> List[str]:
        """
        Resolves domain to A/AAAA IP addresses and validates against SSRF denylist and scope.
        """
        clean_host = host.split(":")[0].strip().lower()

        # Scope enforcement (if expected_domain is provided)
        if expected_domain:
            exp_clean = expected_domain.split(":")[0].strip().lower()
            if clean_host != exp_clean and not clean_host.endswith("." + exp_clean):
                raise ScopeViolationException(
                    f"Host '{clean_host}' is outside verified domain scope '{exp_clean}'."
                )

        # DNS resolution
        try:
            addr_info = socket.getaddrinfo(clean_host, None)
        except socket.gaierror as e:
            raise SSRFSecurityException(f"Failed to resolve hostname '{clean_host}': {str(e)}")

        resolved_ips = list(set([item[4][0] for item in addr_info]))
        if not resolved_ips:
            raise SSRFSecurityException(f"No IP records found for host '{clean_host}'.")

        for ip in resolved_ips:
            if cls.is_ip_blocked(ip):
                raise SSRFSecurityException(
                    f"Security Block: Host '{clean_host}' resolves to prohibited/private IP '{ip}' (SSRF Guard)."
                )

        return resolved_ips

    @classmethod
    def validate_target_url(cls, target_url: str, expected_domain: str = None) -> Tuple[str, str, List[str]]:
        """
        Validates target URL scheme, extracts host, and verifies against SSRF and scope rules.
        Returns: (normalized_url, hostname, resolved_ips)
        """
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        parsed = urllib.parse.urlparse(target_url)
        hostname = parsed.hostname
        if not hostname:
            raise SSRFSecurityException("Invalid URL: missing hostname.")

        resolved_ips = cls.resolve_and_validate_host(hostname, expected_domain=expected_domain)
        return (target_url, hostname, resolved_ips)
