"""
Server-side cryptographic utilities for CAPSTONE SecAgg Forward Privacy Audit.
Mirrors the ESP32-C3 client crypto operations for verification and back-decryption testing.
"""

import hashlib
import hmac
import secrets
from typing import List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class SecAggMethod(Enum):
    SIMPLE_SECAGG = "Simple_SecAgg"
    PQC_RATCHETING = "PQC_Ratcheting"


@dataclass
class ClientState:
    method: SecAggMethod
    client_id: bytes
    static_secret: Optional[bytes] = None
    current_seed: Optional[bytes] = None
    round_keys: List[bytes] = None
    seed_history: List[bytes] = None
    current_round: int = 0

    def __post_init__(self):
        if self.round_keys is None:
            self.round_keys = []
        if self.seed_history is None:
            self.seed_history = []


SEED_SIZE = 32
KEY_SIZE = 32
ROUND_NUM_SIZE = 4
MODEL_UPDATE_SIZE = 64
CLIENT_ID_SIZE = 8
SHA256_DIGEST_SIZE = 32
MAX_ROUNDS = 10


def sha256(data: bytes) -> bytes:
    """Compute SHA-256 hash."""
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison."""
    return hmac.compare_digest(a, b)


def derive_key_simple(static_secret: bytes, round_num: int) -> bytes:
    """
    Method A: Simple SecAgg key derivation.
    key_round = SHA256(static_secret || round_num)
    """
    round_bytes = round_num.to_bytes(ROUND_NUM_SIZE, 'big')
    buffer = static_secret + round_bytes
    return sha256(buffer)


def derive_key_ratchet(seed: bytes, round_num: int) -> Tuple[bytes, bytes]:
    """
    Method B: PQC Hash-Chain Ratcheting key derivation.
    ephemeral_key = SHA256(seed_t || round_num)
    seed_{t+1} = SHA256(seed_t || ephemeral_key)
    Returns: (ephemeral_key, next_seed)
    """
    round_bytes = round_num.to_bytes(ROUND_NUM_SIZE, 'big')
    
    # ephemeral_key = SHA256(seed || round_num)
    buffer1 = seed + round_bytes
    ephemeral_key = sha256(buffer1)
    
    # next_seed = SHA256(seed || ephemeral_key)
    buffer2 = seed + ephemeral_key
    next_seed = sha256(buffer2)
    
    return ephemeral_key, next_seed


def generate_random_seed() -> bytes:
    """Generate cryptographically secure random seed."""
    return secrets.token_bytes(SEED_SIZE)


def simulate_model_update(round_num: int) -> bytes:
    """Generate deterministic model update for testing."""
    return bytes((round_num * 31 + i * 17 + 0x5A) % 256 for i in range(MODEL_UPDATE_SIZE))


def create_payload_mac(key: bytes, round_num: int, model_update: bytes, client_id: bytes) -> bytes:
    """Create MAC for payload authentication."""
    round_bytes = round_num.to_bytes(ROUND_NUM_SIZE, 'big')
    mac_input = model_update + client_id + round_bytes
    return hmac_sha256(key, mac_input)


def verify_payload_mac(key: bytes, round_num: int, model_update: bytes, client_id: bytes, mac: bytes) -> bool:
    """Verify payload MAC."""
    expected_mac = create_payload_mac(key, round_num, model_update, client_id)
    return constant_time_compare(expected_mac, mac)


def initialize_client_a() -> ClientState:
    """Initialize Client A with Simple SecAgg method."""
    static_secret = generate_random_seed()
    return ClientState(
        method=SecAggMethod.SIMPLE_SECAGG,
        client_id=bytes.fromhex("0102030405060708"),
        static_secret=static_secret,
        round_keys=[b'\x00' * KEY_SIZE for _ in range(MAX_ROUNDS)],
        seed_history=[b'\x00' * SEED_SIZE for _ in range(MAX_ROUNDS + 1)]
    )


def initialize_client_b() -> ClientState:
    """Initialize Client B with PQC Ratcheting method."""
    initial_seed = generate_random_seed()
    return ClientState(
        method=SecAggMethod.PQC_RATCHETING,
        client_id=bytes.fromhex("1122334455667788"),
        current_seed=initial_seed,
        seed_history=[initial_seed] + [b'\x00' * SEED_SIZE for _ in range(MAX_ROUNDS)],
        round_keys=[b'\x00' * KEY_SIZE for _ in range(MAX_ROUNDS)]
    )


def run_round_simple(client: ClientState, round_num: int) -> Tuple[bytes, bytes]:
    """Run a single round for Simple SecAgg client."""
    key = derive_key_simple(client.static_secret, round_num)
    client.round_keys[round_num] = key
    model_update = simulate_model_update(round_num)
    mac = create_payload_mac(key, round_num, model_update, client.client_id)
    return key, mac


def run_round_ratcheting(client: ClientState, round_num: int) -> Tuple[bytes, bytes, bytes]:
    """Run a single round for PQC Ratcheting client."""
    if round_num == 0:
        seed = client.seed_history[0]
    else:
        seed = client.seed_history[round_num]
    
    key, next_seed = derive_key_ratchet(seed, round_num)
    client.round_keys[round_num] = key
    client.seed_history[round_num + 1] = next_seed
    
    model_update = simulate_model_update(round_num)
    mac = create_payload_mac(key, round_num, model_update, client.client_id)
    return key, next_seed, mac


def simulate_compromise_simple(client: ClientState, compromise_round: int) -> bytes:
    """
    Simulate compromise of Simple SecAgg client at given round.
    Returns the static secret (which allows computing all keys).
    """
    return client.static_secret


def simulate_compromise_ratcheting(client: ClientState, compromise_round: int) -> bytes:
    """
    Simulate compromise of PQC Ratcheting client at given round.
    Returns the seed at that round (cannot derive past seeds).
    """
    return client.seed_history[compromise_round]


def backtrack_key_simple(static_secret: bytes, target_round: int) -> bytes:
    """Backtrack key for Simple SecAgg using compromised static secret."""
    return derive_key_simple(static_secret, target_round)


def backtrack_key_ratcheting(compromised_seed: bytes, compromise_round: int, target_round: int) -> Optional[bytes]:
    """
    Attempt to backtrack key for PQC Ratcheting using compromised seed.
    This should FAIL for target_round < compromise_round due to one-way hash chain.
    """
    if target_round > compromise_round:
        # Forward derivation is possible
        seed = compromised_seed
        for r in range(compromise_round, target_round + 1):
            key, seed = derive_key_ratchet(seed, r)
        return key
    elif target_round == compromise_round:
        key, _ = derive_key_ratchet(compromised_seed, target_round)
        return key
    else:
        # Backward derivation - IMPOSSIBLE with one-way hash
        # The adversary would need to reverse SHA256, which is computationally infeasible
        return None


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


def print_key_trace(client: ClientState, label: str) -> None:
    """Print key trace for a client."""
    print(f"\n=== {label} Key Trace ===")
    print(f"Method: {client.method.value}")
    print(f"Client ID: {bytes_to_hex(client.client_id)}")
    
    if client.method == SecAggMethod.SIMPLE_SECAGG:
        print(f"Static Secret: {bytes_to_hex(client.static_secret)}")
    else:
        print(f"Initial Seed: {bytes_to_hex(client.seed_history[0])}")
    
    print("\nRound Keys:")
    for r in range(MAX_ROUNDS):
        print(f"  Round {r}: {bytes_to_hex(client.round_keys[r])}")
    
    if client.method == SecAggMethod.PQC_RATCHETING:
        print("\nSeed Chain:")
        for r in range(MAX_ROUNDS + 1):
            print(f"  Seed[{r}]: {bytes_to_hex(client.seed_history[r])}")
    
    print("========================\n")


def print_backtrack_result(target_round: int, original_key: bytes, backtracked_key: Optional[bytes], method_name: str) -> None:
    """Print backtrack test result."""
    print(f"\n--- Backtrack Test: {method_name} ---")
    print(f"Target Round: {target_round}")
    print(f"Original Key:   {bytes_to_hex(original_key)}")
    
    if backtracked_key is None:
        print(f"Backtracked Key: DERIVATION FAILED (One-way hash prevents backtracking)")
        print(f"Keys Match: NO")
        print(f"Forward Privacy: PRESERVED")
    else:
        match = constant_time_compare(original_key, backtracked_key)
        print(f"Backtracked Key: {bytes_to_hex(backtracked_key)}")
        print(f"Keys Match: {'YES' if match else 'NO'}")
        print(f"Forward Privacy: {'BROKEN' if match else 'PRESERVED'}")