import os
import logging
import sys
import time
from typing import List, Dict
from dotenv import load_dotenv

# Load env before importing other modules that might use os.getenv at module level
load_dotenv(override=True)

from agents import WorkerAgent, GovernorAgent
from schemas import GovernanceVerdict, ConversationContext
from sanitizer import InputSanitizer
from rate_limiter import RateLimiter
from audit_log import AuditLogger
from error_handlers import handle_error, SanitizerRejectionException, GovernorFailureException
from fallback_governor import FallbackGovernor

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Orchestrator")

def main():
    print("Initializing NIST-Compliant AI Governance System...")
    
    # Initialize Components
    try:
        worker = WorkerAgent()
        governor = GovernorAgent()
        sanitizer = InputSanitizer()
        rate_limiter = RateLimiter()
        audit_logger = AuditLogger()
    except Exception as e:
        logger.critical(f"Failed to initialize components: {e}")
        sys.exit(1)

    # Simple REPL for demonstration
    user_id = "demo_user_01"  # In a real app, this comes from auth
    history: List[Dict[str, str]] = []

    print(f"System Ready. Strictness: {os.getenv('GOVERNOR_STRICTNESS')}")
    print("Type 'exit' to quit.\n")

    while True:
        try:
            user_input = input("User: ")
            if user_input.lower() in ["exit", "quit"]:
                break

            start_time = time.time()

            # 1. Rate Limiting
            if not rate_limiter.is_allowed(user_id):
                print("System: Rate limit exceeded. Please wait.")
                continue

            # 2. Input Sanitization
            clean_input = sanitizer.sanitize(user_input)
            
            # Update history temporarily for worker context
            current_context = history + [{"role": "user", "content": clean_input}]

            # 3. Worker Generation
            print("... Worker generating response ...")
            draft_response = worker.generate_response(current_context)

            # 4. Governor Audit
            print("... Governor auditing response ...")
            try:
                verdict = governor.audit_response(clean_input, draft_response)
            except GovernorFailureException as gfe:
                logger.warning(f"AI Governor failed, using fallback: {gfe}")
                print("... Using fallback safety checker ...")
                verdict = FallbackGovernor.quick_audit(clean_input, draft_response)

            # Calculate latency
            latency_ms = (time.time() - start_time) * 1000

            # 5. Enforcement & Logging
            # Convert verdict to dict for logging - ensure it's fully serializable
            try:
                verdict_dict = verdict.model_dump(mode='json')
            except AttributeError:
                # Fallback for Pydantic v1
                verdict_dict = verdict.dict()
            
            audit_logger.log_event(user_id, clean_input, verdict_dict, latency_ms=latency_ms)

            if verdict.is_safe:
                print(f"\nAssistant: {draft_response}\n")
                # Commit to history
                history.append({"role": "user", "content": clean_input})
                history.append({"role": "assistant", "content": draft_response})
            else:
                print(f"\n🔒 Security Alert: Response blocked.")
                print(f"   Reason: {verdict.reasoning}")
                print(f"   Violation Type: {verdict.violation_type.value}")
                print(f"   Confidence: {verdict.confidence_score:.2f}\n")
                # Do not commit blocked interactions to history to prevent context poisoning

        except SanitizerRejectionException as s:
            print(f"\n⚠️  Input Rejected: {s}\n")
            # Log sanitizer rejection
            try:
                verdict_dict = {
                    "is_safe": False,
                    "violation_type": "InputSanitization",
                    "reasoning": str(s),
                    "confidence_score": 1.0,
                    "flagged_content": None,
                    "timestamp": None,
                    "governor_version": "Sanitizer"
                }
                audit_logger.log_event(user_id, user_input if 'user_input' in locals() else "", verdict_dict)
            except Exception as log_err:
                logger.error(f"Failed to log sanitizer rejection: {log_err}")
                
        except Exception as e:
            # Global Fail-Secure
            logger.error(f"Unexpected error in main loop: {e}", exc_info=True)
            verdict_dict = handle_error(e)
            print(f"\n❌ System Error: {verdict_dict['reasoning']}\n")
            # Log the error verdict
            try:
                audit_logger.log_event(
                    user_id, 
                    user_input if 'user_input' in locals() else "Unknown", 
                    verdict_dict
                )
            except Exception as log_err:
                logger.error(f"Failed to log error: {log_err}")

if __name__ == "__main__":
    main()