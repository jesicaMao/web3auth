import pytest
from verifier import Verifier, new_verifier
import base64
import time


def test_verifier_initialization(random_private_key):
    verifier = new_verifier(bytes.fromhex(random_private_key[2:]))
    assert verifier.pk is not None


def test_token_validation(random_private_key):
    verifier = new_verifier(bytes.fromhex(random_private_key[2:]))
    # Create a mock token
    mock_token = base64.b64encode(b"addr=0x123;expire=9999999999;sign=0x456").decode()
    with pytest.raises(Exception):
        verifier.validate(mock_token)
