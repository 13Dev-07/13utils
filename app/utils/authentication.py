"""
Authentication Module
Handles API Key generation and validation.
"""

import secrets
from typing import Optional
from app.utils.logger import setup_logger

logger = setup_logger('Authentication')

# In-memory storage for API keys. In production, use a persistent database.
VALID_API_KEYS = {
    "your-generated-api-key-1",
    "your-generated-api-key-2",
    # Add more API keys as needed
}

def generate_api_key() -> str:
    """
    Generates a new secure API key.

    Returns:
        str: A new API key.
    """
    new_key = secrets.token_urlsafe(32)
    VALID_API_KEYS.add(new_key)
    logger.info(f"Generated new API key: {new_key}")
    return new_key

def validate_api_key(api_key: str) -> bool:
    """
    Validates the provided API key.

    Args:
        api_key (str): The API key to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    if api_key in VALID_API_KEYS:
        logger.debug(f"Valid API key: {api_key}")
        return True
    logger.warning(f"Invalid API key attempted: {api_key}")
    return False