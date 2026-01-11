import re
import logging
from schemas import GovernanceVerdict, ViolationType

logger = logging.getLogger(__name__)

class FallbackGovernor:
    """
    Emergency fallback governor using regex-based rules.
    Only used if the main AI Governor fails repeatedly.
    """
    
    # Regex patterns for common PII and security risks
    SSN_PATTERN = r'\b\d{3}-\d{2}-\d{4}\b'
    CREDIT_CARD_PATTERN = r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
    SQL_INJECTION_PATTERN = r'(?i)(DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+.+SET|UNION\s+SELECT)'
    PROMPT_INJECTION_PATTERN = r'(?i)(ignore\s+(previous|all)\s+(instructions|rules)|disregard\s+.+instructions)'
    
    @staticmethod
    def quick_audit(user_query: str, draft_response: str) -> GovernanceVerdict:
        """
        Performs a basic regex-based safety check.
        This is a fail-secure fallback - it may have false positives but won't miss obvious violations.
        """
        logger.warning("Using fallback Governor - AI Governor unavailable")
        
        combined_text = f"{user_query} {draft_response}"
        
        # Check for SSN
        if re.search(FallbackGovernor.SSN_PATTERN, combined_text):
            return GovernanceVerdict(
                is_safe=False,
                violation_type=ViolationType.PII,
                reasoning="Detected pattern matching Social Security Number format",
                confidence_score=0.9,
                flagged_content="SSN pattern detected",
                governor_version="Fallback-Regex-v1"
            )
        
        # Check for Credit Card
        if re.search(FallbackGovernor.CREDIT_CARD_PATTERN, combined_text):
            return GovernanceVerdict(
                is_safe=False,
                violation_type=ViolationType.PII,
                reasoning="Detected pattern matching credit card number format",
                confidence_score=0.85,
                flagged_content="Credit card pattern detected",
                governor_version="Fallback-Regex-v1"
            )
        
        # Check for SQL Injection
        if re.search(FallbackGovernor.SQL_INJECTION_PATTERN, combined_text):
            return GovernanceVerdict(
                is_safe=False,
                violation_type=ViolationType.SQLI,
                reasoning="Detected SQL command patterns that could be malicious",
                confidence_score=0.8,
                flagged_content="SQL pattern detected",
                governor_version="Fallback-Regex-v1"
            )
        
        # Check for Prompt Injection
        if re.search(FallbackGovernor.PROMPT_INJECTION_PATTERN, combined_text):
            return GovernanceVerdict(
                is_safe=False,
                violation_type=ViolationType.PROMPT_INJECTION,
                reasoning="Detected potential prompt injection attempt",
                confidence_score=0.75,
                flagged_content="Injection attempt detected",
                governor_version="Fallback-Regex-v1"
            )
        
        # If no obvious violations, allow but with low confidence
        return GovernanceVerdict(
            is_safe=True,
            violation_type=ViolationType.NONE,
            reasoning="No obvious violations detected by fallback checker (AI Governor unavailable - reduced confidence)",
            confidence_score=0.5,  # Lower confidence since this is just regex
            flagged_content=None,
            governor_version="Fallback-Regex-v1"
        )