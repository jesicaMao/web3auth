from datetime import datetime, timedelta
from collections import defaultdict


class RateLimiter:
    def __init__(self, max_requests=100, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)

    def is_allowed(self, key):
        """
        Check if request is allowed based on rate limits

        Args:
            key (str): Identifier for the client (e.g., IP address)

        Returns:
            bool: True if request is allowed, False otherwise
        """
        now = datetime.now()
        window_start = now - timedelta(seconds=self.window_seconds)

        # Remove old requests
        self.requests[key] = [
            req_time for req_time in self.requests[key] if req_time > window_start
        ]

        # Check if under limit
        if len(self.requests[key]) >= self.max_requests:
            return False

        # Add new request
        self.requests[key].append(now)
        return True
