import json
import os
import time
from datetime import datetime
from typing import Any, Dict

class AuditLogger:
    def __init__(self, log_file: str = "audit_log.jsonl"):
        self.log_file = log_file
        self.max_size_mb = int(os.getenv("AUDIT_LOG_MAX_SIZE_MB", 500))

    def log_event(self, 
                  user_id: str, 
                  prompt: str, 
                  verdict: Dict[str, Any], 
                  latency_ms: float = 0.0):
        """
        Logs an event to the JSONL file.
        """
        self._rotate_if_needed()
        
        # Convert verdict dict to ensure all values are JSON serializable
        serializable_verdict = self._make_json_serializable(verdict)
        
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "prompt_snippet": prompt[:100] if len(prompt) > 100 else prompt,
            "prompt_full_hash": str(hash(prompt)),  # Integrity check
            "verdict": serializable_verdict,  # GovernanceVerdict dict
            "latency_ms": latency_ms
        }
        
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            # Fallback: Print to stderr to ensure it's not lost silently
            print(f"CRITICAL: Failed to write to audit log: {e}")

    def _make_json_serializable(self, obj: Any) -> Any:
        """
        Recursively convert objects to JSON-serializable format.
        Handles datetime objects, enums, Pydantic models, and nested structures.
        """
        if isinstance(obj, dict):
            return {key: self._make_json_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_serializable(item) for item in obj]
        elif isinstance(obj, tuple):
            return [self._make_json_serializable(item) for item in obj]
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, 'model_dump'):
            # Handle Pydantic v2 models
            return self._make_json_serializable(obj.model_dump())
        elif hasattr(obj, 'dict'):
            # Handle Pydantic v1 models
            return self._make_json_serializable(obj.dict())
        elif hasattr(obj, '__dict__') and not isinstance(obj, type):
            # Handle other objects with __dict__, but skip classes themselves
            return self._make_json_serializable(obj.__dict__)
        elif hasattr(obj, 'value'):
            # Handle Enums
            return obj.value
        elif isinstance(obj, (str, int, float, bool, type(None))):
            # Already JSON serializable
            return obj
        else:
            # For any other type, convert to string as fallback
            try:
                return str(obj)
            except:
                return repr(obj)

    def _rotate_if_needed(self):
        """
        Simple rotation: if file exceeds size, rename with timestamp.
        """
        if not os.path.exists(self.log_file):
            return
            
        size_mb = os.path.getsize(self.log_file) / (1024 * 1024)
        if size_mb >= self.max_size_mb:
            timestamp = int(time.time())
            new_name = f"{self.log_file}.{timestamp}.bak"
            os.rename(self.log_file, new_name)