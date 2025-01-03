from eth_hash.auto import keccak
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from eth_typing import ChecksumAddress
from web3 import Web3
from eth_utils import to_checksum_address, is_address


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
        if signature.startswith(("0x", "0X")):
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


def validate_ethereum_address(address: str) -> bool:
    """
    Validate if a string is a valid Ethereum address.

    Args:
        address (str): The address to validate

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        return is_address(address)
    except Exception:
        return False


def to_wei(amount: Union[int, float, str], unit: str = "ether") -> int:
    """
    Convert amount to wei from a given unit.

    Args:
        amount: Amount to convert
        unit: Unit to convert from (ether, gwei, etc.)

    Returns:
        int: Amount in wei
    """
    return Web3.to_wei(amount, unit)


def from_wei(wei_amount: int, unit: str = "ether") -> float:
    """
    Convert wei amount to another unit.

    Args:
        wei_amount: Amount in wei
        unit: Unit to convert to (ether, gwei, etc.)

    Returns:
        float: Converted amount
    """
    return Web3.from_wei(wei_amount, unit)


def retry_with_backoff(
    func: callable,
    max_retries: int = 3,
    initial_delay: float = 1,
    max_delay: float = 10,
    backoff_factor: float = 2,
    exceptions: tuple = (Exception,),
) -> Any:
    """
    Retry a function with exponential backoff.

    Args:
        func: Function to retry
        max_retries: Maximum number of retries
        initial_delay: Initial delay between retries in seconds
        max_delay: Maximum delay between retries in seconds
        backoff_factor: Factor to multiply delay by after each retry
        exceptions: Tuple of exceptions to catch

    Returns:
        Any: Result of the function
    """
    delay = initial_delay
    last_exception = None

    for retry in range(max_retries):
        try:
            return func()
        except exceptions as e:
            last_exception = e
            if retry == max_retries - 1:
                raise

            time.sleep(delay)
            delay = min(delay * backoff_factor, max_delay)

    raise last_exception


def load_abi(path: str) -> List[Dict]:
    """
    Load ABI from JSON file.

    Args:
        path: Path to ABI JSON file

    Returns:
        List[Dict]: The loaded ABI
    """
    with open(path, "r") as f:
        return json.load(f)


def get_contract_instance(web3: Web3, contract_address: str, abi: List[Dict]) -> Any:
    """
    Get contract instance from address and ABI.

    Args:
        web3: Web3 instance
        contract_address: Contract address
        abi: Contract ABI

    Returns:
        Contract instance
    """
    return web3.eth.contract(address=to_checksum_address(contract_address), abi=abi)


def format_timestamp(timestamp: int, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Format Unix timestamp to human readable string.

    Args:
        timestamp: Unix timestamp
        format_str: DateTime format string

    Returns:
        str: Formatted datetime string
    """
    return datetime.fromtimestamp(timestamp).strftime(format_str)


def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """
    Split a list into chunks of specified size.

    Args:
        lst: List to chunk
        chunk_size: Size of each chunk

    Returns:
        List[List]: List of chunks
    """
    return [lst[i : i + chunk_size] for i in range(0, len(lst), chunk_size)]


def safe_transaction_params(
    web3: Web3,
    from_address: ChecksumAddress,
    to_address: ChecksumAddress,
    value: int = 0,
    gas_buffer: float = 1.1,
) -> Dict[str, Any]:
    """
    Generate safe transaction parameters with gas estimation.

    Args:
        web3: Web3 instance
        from_address: Sender address
        to_address: Recipient address
        value: Transaction value in wei
        gas_buffer: Multiplier for gas estimate (safety margin)

    Returns:
        Dict: Transaction parameters
    """
    gas_price = web3.eth.gas_price
    gas_estimate = web3.eth.estimate_gas(
        {"from": from_address, "to": to_address, "value": value}
    )

    return {
        "from": from_address,
        "to": to_address,
        "value": value,
        "gas": int(gas_estimate * gas_buffer),
        "gasPrice": gas_price,
        "nonce": web3.eth.get_transaction_count(from_address),
    }


def decode_transaction_input(
    web3: Web3, transaction_input: str, abi: List[Dict]
) -> Optional[Dict[str, Any]]:
    """
    Decode transaction input data using contract ABI.

    Args:
        web3: Web3 instance
        transaction_input: Transaction input data
        abi: Contract ABI

    Returns:
        Optional[Dict]: Decoded transaction input or None if decoding fails
    """
    try:
        contract = web3.eth.contract(abi=abi)
        return contract.decode_function_input(transaction_input)
    except Exception:
        return None


def is_contract(web3: Web3, address: str) -> bool:
    """
    Check if an address is a contract.

    Args:
        web3: Web3 instance
        address: Address to check

    Returns:
        bool: True if address is a contract, False otherwise
    """
    code = web3.eth.get_code(to_checksum_address(address))
    return code != b""


def get_event_logs(
    web3: Web3,
    contract: Any,
    event_name: str,
    from_block: int,
    to_block: Union[int, str] = "latest",
    batch_size: int = 2000,
) -> List[Dict]:
    """
    Get event logs with automatic pagination.

    Args:
        web3: Web3 instance
        contract: Contract instance
        event_name: Name of the event
        from_block: Starting block
        to_block: Ending block
        batch_size: Number of blocks per batch

    Returns:
        List[Dict]: List of event logs
    """
    if to_block == "latest":
        to_block = web3.eth.block_number

    events = []
    current_block = from_block

    while current_block <= to_block:
        end_block = min(current_block + batch_size, to_block)
        event_filter = getattr(contract.events, event_name).create_filter(
            fromBlock=current_block, toBlock=end_block
        )
        events.extend(event_filter.get_all_entries())
        current_block = end_block + 1

    return events
