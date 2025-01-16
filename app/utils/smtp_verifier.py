"""
SMTP Verifier Module
Verifies the existence of an email's mailbox via SMTP.
"""

import smtplib
import dns.resolver
from app.utils.exceptions import SMTPVerificationError
from app.utils.logger import setup_logger

logger = setup_logger('SMTPVerifier')

def verify_smtp(email: str) -> bool:
    """
    Verifies the existence of the mailbox by communicating with the SMTP server.
    
    Args:
        email (str): The email address to verify.
    
    Returns:
        bool: True if the mailbox exists, False otherwise.
    
    Raises:
        SMTPVerificationError: If SMTP verification fails.
    """
    domain = email.split('@')[-1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
    except dns.resolver.NoAnswer:
        logger.error(f"No MX records found for domain: {domain}")
        raise SMTPVerificationError("No MX records found for domain.")
    except dns.resolver.NXDOMAIN:
        logger.error(f"Domain does not exist: {domain}")
        raise SMTPVerificationError("Domain does not exist.")
    except Exception as e:
        logger.exception(f"DNS resolution failed for domain {domain}: {e}")
        raise SMTPVerificationError(f"DNS resolution failed: {e}")
    
    try:
        server = smtplib.SMTP(timeout=10)
        server.connect(mx_record)
        server.helo(server.local_hostname)  # Can be customized based on requirements
        server.mail('noreply@example.com')    # Sender email can be customized
        code, message = server.rcpt(email)
        server.quit()
        
        if code == 250:
            logger.info(f"SMTP verification successful for email: {email}")
            return True
        elif code == 550:
            logger.warning(f"SMTP verification failed for email: {email} - Mailbox does not exist.")
            return False
        else:
            logger.warning(f"SMTP verification returned unexpected code {code} for email: {email}")
            return False
    except smtplib.SMTPServerDisconnected:
        logger.error("SMTP server unexpectedly disconnected.")
        raise SMTPVerificationError("SMTP server unexpectedly disconnected.")
    except smtplib.SMTPConnectError:
        logger.error("Failed to connect to SMTP server.")
        raise SMTPVerificationError("Failed to connect to SMTP server.")
    except smtplib.SMTPException as e:
        logger.exception(f"SMTP verification error: {e}")
        raise SMTPVerificationError(f"SMTP verification error: {e}")
    except Exception as e:
        logger.exception(f"Unexpected error during SMTP verification: {e}")
        raise SMTPVerificationError(f"Unexpected error: {e}")