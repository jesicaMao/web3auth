import pytest
from datetime import datetime, timedelta
from rate_limiter import RateLimiter
from unittest.mock import patch


@pytest.fixture
def rate_limiter():
    return RateLimiter(max_requests=2, window_seconds=1)


def test_init():
    limiter = RateLimiter(max_requests=100, window_seconds=60)
    assert limiter.max_requests == 100
    assert limiter.window_seconds == 60
    assert len(limiter.requests) == 0


def test_allow_requests_within_limit(rate_limiter):
    assert rate_limiter.is_allowed("test_client") is True
    assert rate_limiter.is_allowed("test_client") is True
    assert rate_limiter.is_allowed("test_client") is False


def test_different_clients(rate_limiter):
    assert rate_limiter.is_allowed("client1") is True
    assert rate_limiter.is_allowed("client2") is True
    assert rate_limiter.is_allowed("client1") is True
    assert rate_limiter.is_allowed("client2") is True
    assert rate_limiter.is_allowed("client1") is False
    assert rate_limiter.is_allowed("client2") is False


@patch("rate_limiter.datetime")
def test_window_expiration(mock_datetime, rate_limiter):
    # Set up mock times
    start_time = datetime(2024, 1, 1, 12, 0, 0)
    mock_datetime.now.return_value = start_time

    # First two requests should be allowed
    assert rate_limiter.is_allowed("test_client") is True
    assert rate_limiter.is_allowed("test_client") is True
    assert rate_limiter.is_allowed("test_client") is False

    # Move time forward past window
    mock_datetime.now.return_value = start_time + timedelta(seconds=2)

    # Should be allowed again as window has expired
    assert rate_limiter.is_allowed("test_client") is True


def test_cleanup_old_requests(rate_limiter):
    # Make initial requests
    assert rate_limiter.is_allowed("test_client") is True
    assert rate_limiter.is_allowed("test_client") is True

    # Manually modify request times to be old
    old_time = datetime.now() - timedelta(seconds=2)
    rate_limiter.requests["test_client"] = [old_time, old_time]

    # Should be allowed as old requests are cleaned up
    assert rate_limiter.is_allowed("test_client") is True


def test_empty_key(rate_limiter):
    assert rate_limiter.is_allowed("") is True
    assert rate_limiter.is_allowed("") is True
    assert rate_limiter.is_allowed("") is False


def test_none_key():
    with pytest.raises(TypeError):
        rate_limiter = RateLimiter()
        rate_limiter.is_allowed(None)
