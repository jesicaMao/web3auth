import pytest
from issuer import Issuer, new_issuer
import time


def test_issuer_initialization(random_private_key):
    ttl = 3600  # 1 hour
    issuer = new_issuer(bytes.fromhex(random_private_key[2:]), ttl)
    assert issuer.ttl == ttl
    assert issuer.err is None


def test_challenge_generation(random_private_key, random_address):
    issuer = new_issuer(bytes.fromhex(random_private_key[2:]), 3600)
    message = {"address": random_address}
    response = issuer.challenge(message)
    assert "challenge" in response
    assert "signature" in response
    assert response["signature"].startswith("0x")
