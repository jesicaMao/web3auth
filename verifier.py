import base64
import time
from eth_account.messages import encode_defunct
from web3 import Web3
from eth_keys import keys

class Verifier:
    def __init__(self, pk):
        """
        Initialize verifier with a public key
        
        Args:
            pk (bytes): Public key in bytes
        """
        self.pk = pk

    def validate(self, token):
        """
        Validate a token
        
        Args:
            token (str): Base64 encoded token
            
        Returns:
            None if valid, raises Exception if invalid
        """
        try:
            # Decode base64 token
            bytes_token = base64.b64decode(token)
            token_str = bytes_token.decode('utf-8')
            
            # Parse token elements
            token_elms = {}
            for elm in token_str.split(';'):
                if '=' not in elm:
                    continue
                attr, value = elm.split('=', 1)
                token_elms[attr] = value
            
            # Create message to verify
            token_info = f"addr={token_elms['addr']};expire={token_elms['expire']}"
            message = f"\x19Ethereum Signed Message:\n{len(token_info)}{token_info}"
            
            # Parse signature
            signature = self._parse_signature(token_elms['sign'])
            
            # Verify signature
            w3 = Web3()
            message_hash = encode_defunct(text=message)
            recovered_address = w3.eth.account.recover_message(
                message_hash,
                signature=signature
            )
            
            # Verify recovered address matches public key
            pk = keys.PublicKey(self.pk)
            if recovered_address.lower() != pk.to_address().lower():
                raise Exception("Invalid signature")
            
            # Check expiration
            expire = int(token_elms['expire'])
            if expire < int(time.time()):
                raise Exception("Token expired")
            
            return None
            
        except Exception as e:
            raise Exception(f"Validation error: {str(e)}")
    
    def _parse_signature(self, sig):
        """
        Parse signature from hex string
        
        Args:
            sig (str): Hex string signature
            
        Returns:
            bytes: Signature bytes
        """
        if sig.startswith('0x'):
            sig = sig[2:]
        return bytes.fromhex(sig)

def new_verifier(pk):
    """
    Create a new verifier instance
    
    Args:
        pk (bytes): Public key in bytes
        
    Returns:
        Verifier: New verifier instance
    """
    return Verifier(pk) 