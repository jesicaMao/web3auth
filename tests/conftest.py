import pytest
from eth_account import Account
import secrets

@pytest.fixture
def random_private_key():
    """Generate a random private key for testing"""
    return "0x" + secrets.token_hex(32)

@pytest.fixture
def random_address():
    """Generate a random Ethereum address for testing"""
    account = Account.create()
    return account.address

@pytest.fixture
def sample_message():
    """Create a sample message for testing"""
    return {
        'address': '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
        'init': {
            'challenge': 'sample_challenge',
            'signature': '0x1234567890'
        },
        'signature': '0x9876543210'
    } 