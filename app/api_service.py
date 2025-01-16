"""
API Service Module
Handles API interactions for email validation.
"""

from flask import Flask, request, jsonify
from app.utils.logger import setup_logger
from app.utils.validation_orchestrator import validate_email
from app.utils.rate_limiter import RateLimiter
from app.utils.exceptions import ValidationError, RateLimitError
from app.utils.authentication import validate_api_key
from functools import wraps
from app.tasks import validate_email_task
from app.utils.results_handler import log_results, save_results_to_file, save_results_to_db

logger = setup_logger('APIServer')
app = Flask(__name__)

rate_limiter = RateLimiter(max_requests=100, window_seconds=60)

def require_api_key(f):
    """
    Decorator to require API key authentication for endpoints.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-KEY')
        if not api_key:
            logger.warning("API key missing in request headers.")
            return jsonify({"error": "API key missing."}), 401
        if not validate_api_key(api_key):
            logger.warning("Invalid API key provided.")
            return jsonify({"error": "Invalid API key."}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/validate', methods=['POST'])
@require_api_key
def validate():
    client_ip = request.remote_addr
    if not rate_limiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        raise RateLimitError("Rate limit exceeded. Please try again later.")
    
    data = request.get_json()
    email = data.get('email', '').strip()
    
    if not email:
        logger.warning("No email provided in the request.")
        return jsonify({"error": "Email is required."}), 400
    
    try:
        validation_result = validate_email(email)
        log_results(validation_result)
        save_results_to_file([validation_result])
        save_results_to_db([validation_result])
        return jsonify(validation_result), 200
    except ValidationError as ve:
        logger.error(f"Validation error: {ve.message}")
        return jsonify({"error": ve.message}), 400
    except RateLimitError as rle:
        logger.warning(f"Rate limit error: {rle.message}")
        return jsonify({"error": rle.message}), 429
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/validate_async', methods=['POST'])
@require_api_key
def validate_async():
    """
    Endpoint for asynchronous email validation.
    Accepts a list of emails and enqueues validation tasks.
    """
    client_ip = request.remote_addr
    if not rate_limiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        raise RateLimitError("Rate limit exceeded. Please try again later.")
    
    data = request.get_json()
    emails = data.get('emails', [])
    save = data.get('save', False)
    output = data.get('output', 'results/validation_results.json')
    
    if not emails:
        logger.warning("No emails provided in the asynchronous request.")
        return jsonify({"error": "At least one email is required."}), 400
    
    if not isinstance(emails, list):
        logger.warning("Emails should be provided as a list.")
        return jsonify({"error": "Emails should be a list."}), 400
    
    task_ids = []
    for email in emails:
        email = email.strip()
        if email:
            task = validate_email_task.delay(email, save, output)
            task_ids.append(task.id)
            logger.info(f"Enqueued validation task for email: {email} with Task ID: {task.id}")
    
    return jsonify({"message": "Validation tasks enqueued.", "task_ids": task_ids}), 202

def run():
    logger.info("Starting API Service with Authentication and Asynchronous Processing")
    app.run(host='0.0.0.0', port=5000, debug=False)