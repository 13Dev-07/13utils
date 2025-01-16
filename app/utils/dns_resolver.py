"""
DNS Resolver Module
Performs DNS lookups and retrieves MX records.
"""

import dns.resolver
from app.utils.exceptions import ValidationError

def resolve_domain(domain: str) -> bool:
    """
    Checks if the domain has valid DNS records.
    
    Args:
        domain (str): The domain to verify.
    
    Returns:
        bool: True if DNS records are found, False otherwise.
    """
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return False
    except Exception as e:
        return False

def get_mx_records(domain: str) -> bool:
    """
    Retrieves MX records for the domain.
    
    Args:
        domain (str): The domain to query.
    
    Returns:
        bool: True if MX records are found, False otherwise.
    """
    try:
        records = dns.resolver.resolve(domain, 'MX')
        return len(records) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False
    except Exception:
        return False