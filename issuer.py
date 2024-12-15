import time
import base64
import secrets
import hashlib
from eth_account.messages import encode_defunct
from web3 import Web3
from eth_keys import keys

class Issuer:
    def __init__(self, sk, ttl):
        """
        Initialize issuer with a secret key and TTL
        
        Args:
            sk (bytes): Secret key in bytes
            ttl (int): Time to live in seconds
        """
        try:
            self.sk = sk
            self.pk = keys.PrivateKey(sk).public_key
            self.ttl = ttl
            self.err = None
        except Exception as e:
            self.err = str(e)

    def challenge(self, message):
        """
        Create a challenge for the given init message
        
        Args:
            message (dict): Init message containing address
            
        Returns:
            dict: Challenge response
        """
        if self.err:
            return {'error': self.err}

        try:
            # Generate random nonce
            nonce = secrets.randbelow(2**64)
            
            # Create challenge hash
            challenge = hashlib.sha256(
                f"{message['address']}{nonce}".encode()
            ).hexdigest()

            # Sign the challenge
            w3 = Web3()
            message_hash = encode_defunct(text=challenge)
            signed = w3.eth.account.sign_message(
                message_hash,
                private_key=self.sk
            )
            
            # Adjust v value as in Go code
            signature = signed.signature
            signature = signature[:-1] + bytes([signature[-1] + 27])

            return {
                'challenge': challenge,
                'signature': '0x' + signature.hex()
            }

        except Exception as e:
            return {'error': str(e)}

    def issue(self, message):
        """
        Issue a token for the given message
        
        Args:
            message (dict): Message containing init data and signatures
            
        Returns:
            dict: Response containing token or error
        """
        if self.err:
            return {'error': self.err}

        try:
            # Verify issuer's signature
            err = self._verify_challenge_issuer_signature(message)
            if err:
                return {'error': str(err)}

            # Verify wallet signature
            err = self._verify_challenge_wallet_signature(message)
            if err:
                return {'error': str(err)}

            # Issue token
            token = self._issue_token(message)
            return {'token': token}

        except Exception as e:
            return {'error': str(e)}

    def _verify_challenge_issuer_signature(self, message):
        """Verify the issuer's signature on the challenge"""
        try:
            w3 = Web3()
            init_sig = bytes.fromhex(message['init']['signature'][2:])
            message_hash = encode_defunct(text=message['init']['challenge'])
            recovered_address = w3.eth.account.recover_message(
                message_hash,
                signature=init_sig
            )
            
            if recovered_address.lower() != self.pk.to_address().lower():
                return Exception("Invalid issuer signature")
            
            return None
        except Exception as e:
            return e

    def _verify_challenge_wallet_signature(self, message):
        """Verify the wallet's signature on the challenge"""
        try:
            w3 = Web3()
            challenge = f"\x19Ethereum Signed Message:\n{len(message['init']['challenge'])}{message['init']['challenge']}"
            wallet_sig = bytes.fromhex(message['signature'][2:])
            message_hash = encode_defunct(text=challenge)
            recovered_address = w3.eth.account.recover_message(
                message_hash,
                signature=wallet_sig
            )
            
            if recovered_address.lower() != message['address'].lower():
                return Exception(f"Wallet signature does not match address: {recovered_address}!={message['address']}")
            
            return None
        except Exception as e:
            return e

    def _issue_token(self, message):
        """Issue a new token"""
        try:
            w3 = Web3()
            waddr = message['address'].lower()
            expire = int(time.time()) + self.ttl
            token_info = f"addr={waddr};expire={expire}"
            
            message_hash = encode_defunct(
                text=f"\x19Ethereum Signed Message:\n{len(token_info)}{token_info}"
            )
            signed = w3.eth.account.sign_message(
                message_hash,
                private_key=self.sk
            )
            
            # Adjust v value as in Go code
            signature = signed.signature
            signature = signature[:-1] + bytes([signature[-1] + 27])
            
            token = f"{token_info};sign=0x{signature.hex()}"
            return base64.b64encode(token.encode()).decode()
            
        except Exception as e:
            return str(e)

def new_issuer(sk, ttl):
    """
    Create a new issuer instance
    
    Args:
        sk (bytes): Secret key in bytes
        ttl (int): Time to live in seconds
        
    Returns:
        Issuer: New issuer instance
    """
    return Issuer(sk, ttl) 