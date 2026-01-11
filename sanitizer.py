import re
import base64
import binascii

class InputSanitizer:
    
    BASE64_PATTERN = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
    HEX_PATTERN = r'^[0-9a-fA-F]+$'

    @staticmethod
    def sanitize(input_text: str) -> str:
        """
        Basic sanitization and risk detection.
        Raises ValueError if input looks suspiciously encoded or malformed.
        """
        if not input_text or not input_text.strip():
            raise ValueError("Input cannot be empty")
        
        if len(input_text) > 10000: # Hardcap to prevent DOS
            raise ValueError("Input exceeds maximum length")

        # Heuristic check for Base64 bombs
        if len(input_text) > 20 and re.match(InputSanitizer.BASE64_PATTERN, input_text.strip()):
             # Try decoding to see if it's just random or actual content (simplified check)
             try:
                 decoded = base64.b64decode(input_text).decode('utf-8', errors='ignore')
                 if "system" in decoded.lower() or "ignore" in decoded.lower():
                     raise ValueError("Potential encoded injection detected (Base64)")
             except (binascii.Error, UnicodeDecodeError):
                 pass

        return input_text.strip()
