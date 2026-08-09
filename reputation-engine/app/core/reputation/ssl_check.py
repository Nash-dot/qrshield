"""
SSL Certificate Validation Check
--------------------------------
Connects directly to target hostname over TLS to verify certificate presence.
"""

import socket
import ssl
import ipaddress


def check_ssl_valid(domain: str) -> bool:
    """
    Returns True if the domain has a valid TLS/SSL certificate on port 443.
    Returns False for IP addresses or unreachable hosts.
    """
    # IP addresses do not have standard domain SSL certs in this context
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert is not None
    except Exception:
        return False
