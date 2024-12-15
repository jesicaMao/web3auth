import json

class Response:
    def __init__(self, error=None):
        """
        Initialize Response object
        
        Args:
            error (str, optional): Error message
        """
        self.error = error

    def marshal_json(self):
        """
        Convert Response object to JSON bytes
        
        Returns:
            bytes: JSON encoded response
        """
        return json.dumps({
            'error': self.error if self.error else None
        }).encode('utf-8')

class InitReply:
    def __init__(self, error=None):
        """
        Initialize InitReply object
        
        Args:
            error (str, optional): Error message
        """
        self.error = error

    def marshal_json(self):
        """
        Convert InitReply object to JSON bytes
        
        Returns:
            bytes: JSON encoded response
        """
        return json.dumps({
            'error': self.error if self.error else None
        }).encode('utf-8')

def marshaled_reply_error(err):
    """
    Create a marshaled error response
    
    Args:
        err (Exception): Error to marshal
        
    Returns:
        bytes: JSON encoded error response
    """
    res = Response(error=str(err))
    return res.marshal_json()

def marshaled_init_reply_error(err):
    """
    Create a marshaled init error response
    
    Args:
        err (Exception): Error to marshal
        
    Returns:
        bytes: JSON encoded init error response
    """
    res = InitReply(error=str(err))
    return res.marshal_json() 