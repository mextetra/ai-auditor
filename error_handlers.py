class GovernorFailureException(Exception):
    """Raised when the Governor Agent fails to provide a valid verdict."""
    pass

class WorkerTimeoutException(Exception):
    """Raised when the Worker Agent takes too long to respond."""
    pass

class SanitizerRejectionException(ValueError):
    """Raised when the Input Sanitizer rejects the input."""
    pass

def handle_error(e: Exception) -> dict:
    """
    Global error handler to ensure fail-secure behavior.
    Returns a 'Blocked' verdict structure.
    """
    error_type = type(e).__name__
    return {
        "is_safe": False,
        "violation_type": "SystemError",
        "reasoning": f"Request blocked due to system error: {error_type}. Please try again later.",
        "confidence_score": 1.0,
        "flagged_content": None,
        "timestamp": None, # Will be filled by caller or current time
        "governor_version": "System"
    }
