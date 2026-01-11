import time
from collections import defaultdict, deque
from typing import Dict, Tuple
import os

class RateLimiter:
    def __init__(self):
        # Default limits, can be overridden by env vars
        self.hourly_limit = int(os.getenv("RATE_LIMIT_HOURLY", 100))
        self.burst_limit = int(os.getenv("RATE_LIMIT_BURST", 10))
        
        # Storage: user_id -> list of timestamps
        self.requests: Dict[str, deque] = defaultdict(deque)

    def is_allowed(self, user_id: str) -> bool:
        """
        Checks if the request is allowed for the given user_id.
        Implements a sliding window strategy.
        """
        now = time.time()
        user_requests = self.requests[user_id]
        
        # Cleanup old requests (older than 1 hour)
        while user_requests and user_requests[0] < now - 3600:
            user_requests.popleft()
            
        # Check hourly limit
        if len(user_requests) >= self.hourly_limit:
            return False
            
        # Check burst limit (last minute)
        # Count requests in the last 60 seconds
        burst_count = sum(1 for t in user_requests if t > now - 60)
        if burst_count >= self.burst_limit:
            return False
            
        # Log this request
        user_requests.append(now)
        return True
