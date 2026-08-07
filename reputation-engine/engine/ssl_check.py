"""
ssl_check.py
------------
Validates SSL certificates by opening a direct socket connection.
No external API — connects to port 443 on the domain itself.
"""

import ssl
import socket
import ipaddress


def check_ssl_valid(domain: str) -> bool:
    """
    Returns True if the domain has a valid, non-expired SSL certificate.
    Skips check and returns False immediately for raw IP addresses
    (IPs cannot have domain-validated certificates).
    """
    # Raw IPs cannot have SSL certs — skip and flag as invalid
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass  # Not an IP, proceed normally

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert is not None
    except Exception:
        return False