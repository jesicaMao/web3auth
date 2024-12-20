import os
from dataclasses import dataclass


@dataclass
class Config:
    """Configuration settings for web3auth"""

    DEFAULT_TTL: int = 3600  # 1 hour
    MIN_TTL: int = 300  # 5 minutes
    MAX_TTL: int = 86400  # 24 hours

    @classmethod
    def from_env(cls):
        """Load configuration from environment variables"""
        return cls(
            DEFAULT_TTL=int(os.getenv("WEB3AUTH_DEFAULT_TTL", cls.DEFAULT_TTL)),
            MIN_TTL=int(os.getenv("WEB3AUTH_MIN_TTL", cls.MIN_TTL)),
            MAX_TTL=int(os.getenv("WEB3AUTH_MAX_TTL", cls.MAX_TTL)),
        )
