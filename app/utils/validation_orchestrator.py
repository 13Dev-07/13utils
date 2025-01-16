"""
Validation Orchestrator Module
Coordinates various email validation processes.
"""

from app.utils.syntax_validator import validate_syntax
from app.utils.dns_resolver import resolve_domain, get_mx_records
from app.utils.smtp_verifier import verify_smtp
from app.utils.disposable_email_detector import is_disposable_email
from app.utils.role_account_detector import is_role_account
from app.utils.typo_detector import detect_typo
from app.utils.domain_reputation import get_domain_reputation
from app.utils.spam_trap_detector import SpamTrapDetector
from app.utils.catch_all_detector import CatchAllDetector
from app.utils.exceptions import ValidationError
from typing import Dict

# Initialize detectors
spam_trap_detector = SpamTrapDetector()
catch_all_detector = CatchAllDetector()

def validate_email(email: str) -> dict:
    """
    Validates the provided email through multiple validation steps.
    
    Args:
        email (str): The email address to validate.
    
    Returns:
        dict: Validation results and risk score.
    
    Raises:
        ValidationError: If validation fails.
    """
    result = {
        "email": email,
        "syntax_valid": False,
        "domain_exists": False,
        "mx_records_valid": False,
        "smtp_verified": False,
        "disposable": False,
        "role_account": False,
        "typo_detected": False,
        "typo_suggestion": None,
        "domain_reputation": 0,
        "spam_trap": False,
        "catch_all": False,
        "risk_score": 0,
        "status": "Invalid"
    }
    
    domain = extract_domain(email)
    if not domain:
        raise ValidationError("Invalid email format: Missing domain.")
    
    # Syntax Validation
    if not validate_syntax(email):
        raise ValidationError("Invalid email syntax.")
    result["syntax_valid"] = True
    
    # Domain Resolution
    if not resolve_domain(domain):
        raise ValidationError("Domain does not exist.")
    result["domain_exists"] = True
    
    # MX Records Verification
    if not get_mx_records(domain):
        raise ValidationError("No valid MX records found for domain.")
    result["mx_records_valid"] = True
    
    # SMTP Verification
    if verify_smtp(email):
        result["smtp_verified"] = True
    else:
        result["smtp_verified"] = False
    
    # Disposable Email Detection
    result["disposable"] = is_disposable_email(email)
    
    # Role Account Detection
    result["role_account"] = is_role_account(email)
    
    # Typo Detection
    typo_suggestion = detect_typo(email)
    if typo_suggestion:
        result["typo_detected"] = True
        result["typo_suggestion"] = typo_suggestion
    
    # Domain Reputation
    result["domain_reputation"] = get_domain_reputation(domain)
    
    # Spam Trap Detection
    result["spam_trap"] = spam_trap_detector.is_spam_trap(email)
    
    # Catch-All Detection
    result["catch_all"] = catch_all_detector.is_catch_all(domain)
    
    # Risk Scoring
    result["risk_score"] = calculate_risk_score(result)
    
    # Final Status
    result["status"] = "Valid" if result["risk_score"] < 50 else "Risky"
    
    return result

def extract_domain(email: str) -> str:
    """
    Extracts the domain part from the email address.
    
    Args:
        email (str): The email address.
    
    Returns:
        str: The domain if extraction is successful, else an empty string.
    """
    try:
        return email.split('@')[1].lower()
    except IndexError:
        return ""

def calculate_risk_score(validation_result: Dict) -> int:
    """
    Calculates a risk score based on various validation factors.
    
    Args:
        validation_result (dict): Results from validation steps.
    
    Returns:
        int: Calculated risk score.
    """
    score = 0
    if validation_result.get("disposable", False):
        score += 30
    if validation_result.get("role_account", False):
        score += 20
    if validation_result.get("spam_trap", False):
        score += 50
    if validation_result.get("typo_detected", False):
        score += 10
    if validation_result.get("catch_all", False):
        score += 15
    domain_reputation = validation_result.get("domain_reputation", 0)
    # Invert domain reputation: higher reputation reduces risk
    score += max(0, 100 - domain_reputation) * 0.5
    return int(score)