from eth_hash.auto import keccak

def parse_signature(signature):
    """
    Parse and normalize an Ethereum signature
    
    Args:
        signature (str): Hex string signature
        
    Returns:
        bytes: Normalized signature bytes
        
    Raises:
        ValueError: If signature is invalid
    """
    try:
        # Remove '0x' prefix if present
        if signature.startswith(('0x', '0X')):
            signature = signature[2:]
            
        # Convert hex to bytes
        sign = bytes.fromhex(signature)
        
        # Adjust v value (equivalent to sign[64] -= 27 in Go)
        return sign[:-1] + bytes([sign[-1] - 27])
    
    except Exception as e:
        raise ValueError(f"Invalid signature format: {str(e)}")

def wallet_addr_from_pubkey(pkey):
    """
    Derive Ethereum address from public key
    
    Args:
        pkey (bytes): Public key bytes
        
    Returns:
        str: Ethereum address with '0x' prefix
    """
    # Remove EC prefix (04) if present
    key_bytes = pkey[1:] if pkey[0] == 4 else pkey
    
    # Compute Keccak-256 hash
    k = keccak()
    k.update(key_bytes)
    addr = k.digest()[-20:]  # Take last 20 bytes
    
    return f"0x{addr.hex()}" 