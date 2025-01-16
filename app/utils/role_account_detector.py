"""
Role Account Detector Module
Identifies role-based email addresses that are often targets for abuse.
"""

ROLE_BASED_PREFIXES = [
    "admin", "support", "info", "contact", "sales", "help",
    "service", "billing", "noreply", "no-reply", "webmaster"
]

def is_role_account(email: str) -> bool:
    """
    Determines if the email address is a role-based account.
    
    Args:
        email (str): The email address to evaluate.
    
    Returns:
        bool: True if it's a role account, False otherwise.
    """
    local_part = email.split('@')[0].lower()
    return any(local_part.startswith(prefix) for prefix in ROLE_BASED_PREFIXES)