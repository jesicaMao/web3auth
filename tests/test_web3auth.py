import pytest
import json
from web3auth import Response, InitReply, marshaled_reply_error, marshaled_init_reply_error

def test_response_initialization():
    """Test Response class initialization"""
    # Test with error
    response = Response(error="test error")
    assert response.error == "test error"
    
    # Test without error
    response = Response()
    assert response.error is None

def test_response_marshal_json():
    """Test Response JSON marshaling"""
    # Test with error
    response = Response(error="test error")
    marshaled = response.marshal_json()
    assert isinstance(marshaled, bytes)
    decoded = json.loads(marshaled.decode('utf-8'))
    assert decoded['error'] == "test error"
    
    # Test without error
    response = Response()
    marshaled = response.marshal_json()
    decoded = json.loads(marshaled.decode('utf-8'))
    assert decoded['error'] is None

def test_init_reply_initialization():
    """Test InitReply class initialization"""
    # Test with error
    reply = InitReply(error="test error")
    assert reply.error == "test error"
    
    # Test without error
    reply = InitReply()
    assert reply.error is None

def test_init_reply_marshal_json():
    """Test InitReply JSON marshaling"""
    # Test with error
    reply = InitReply(error="test error")
    marshaled = reply.marshal_json()
    assert isinstance(marshaled, bytes)
    decoded = json.loads(marshaled.decode('utf-8'))
    assert decoded['error'] == "test error"
    
    # Test without error
    reply = InitReply()
    marshaled = reply.marshal_json()
    decoded = json.loads(marshaled.decode('utf-8'))
    assert decoded['error'] is None

def test_marshaled_reply_error():
    """Test marshaled_reply_error function"""
    error = Exception("test error")
    marshaled = marshaled_reply_error(error)
    assert isinstance(marshaled, bytes)
    decoded = json.loads(marshaled.decode('utf-8'))
    assert decoded['error'] == "test error"

def test_marshaled_init_reply_error():
    """Test marshaled_init_reply_error function"""
    error = Exception("test error")
    marshaled = marshaled_init_reply_error(error)
    assert isinstance(marshaled, bytes)
    decoded = json.loads(marshaled.decode('utf-8'))
    assert decoded['error'] == "test error" 