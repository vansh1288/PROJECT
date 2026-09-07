"""
Security Audit & Back-decryption Test Runner for CAPSTONE SecAgg Forward Privacy.
Orchestrates the complete audit: key trace, compromise simulation, backtracking test.
"""

from typing import Dict, Any, Optional
import json
from pqc_handler import (
    ClientState, SecAggMethod, MAX_ROUNDS, KEY_SIZE,
    initialize_client_a, initialize_client_b,
    run_round_simple, run_round_ratcheting,
    simulate_compromise_simple, simulate_compromise_ratcheting,
    backtrack_key_simple, backtrack_key_ratcheting,
    print_key_trace, print_backtrack_result,
    bytes_to_hex, constant_time_compare
)


class SecurityAuditor:
    """Main security auditor for SecAgg forward privacy analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.max_rounds = config.get('simulation', {}).get('max_rounds', MAX_ROUNDS)
        self.compromise_round = config.get('simulation', {}).get('compromise_round', 5)
        self.target_round = config.get('simulation', {}).get('target_backtrack_round', 2)
        self.verbose = config.get('output', {}).get('verbose', True)
        self.results = {}
    
    def log(self, message: str) -> None:
        """Log message if verbose."""
        if self.verbose:
            print(message)
    
    def run_simple_secagg_audit(self) -> Dict[str, Any]:
        """Run complete audit for Simple SecAgg (Method A)."""
        self.log("\n" + "=" * 60)
        self.log("AUDIT: Simple SecAgg (Method A - Static Key Derivation)")
        self.log("=" * 60)
        
        client = initialize_client_a()
        
        # Phase 1: 10-Round Key Trace
        self.log("\n[Phase 1] 10-Round Key Trace Generation")
        for round_num in range(self.max_rounds):
            key, mac = run_round_simple(client, round_num)
            self.log(f"  Round {round_num}: Key={bytes_to_hex(key)[:16]}... MAC={bytes_to_hex(mac)[:16]}...")
        
        print_key_trace(client, "Simple SecAgg")
        
        # Phase 2: Round 5 Compromise Simulation
        self.log(f"\n[Phase 2] Compromise Simulation at Round {self.compromise_round}")
        compromised_secret = simulate_compromise_simple(client, self.compromise_round)
        self.log(f"  Adversary captures: Static Secret = {bytes_to_hex(compromised_secret)}")
        
        # Phase 3: Backtracking & Back-Decryption Test
        self.log(f"\n[Phase 3] Backtracking to Round {self.target_round}")
        backtracked_key = backtrack_key_simple(compromised_secret, self.target_round)
        original_key = client.round_keys[self.target_round]
        
        match = constant_time_compare(original_key, backtracked_key)
        self.log(f"  Original Round {self.target_round} Key:   {bytes_to_hex(original_key)}")
        self.log(f"  Backtracked Round {self.target_round} Key: {bytes_to_hex(backtracked_key)}")
        self.log(f"  Keys Match: {'YES' if match else 'NO'}")
        
        # Phase 4: Result
        forward_privacy = "BROKEN" if match else "PRESERVED"
        self.log(f"\n[Phase 4] RESULT: Forward Privacy = {forward_privacy}")
        
        result = {
            "method": "Simple_SecAgg",
            "compromise_round": self.compromise_round,
            "target_round": self.target_round,
            "original_key": bytes_to_hex(original_key),
            "backtracked_key": bytes_to_hex(backtracked_key),
            "keys_match": match,
            "forward_privacy": forward_privacy,
            "all_round_keys": [bytes_to_hex(k) for k in client.round_keys],
            "static_secret": bytes_to_hex(client.static_secret)
        }
        
        print_backtrack_result(self.target_round, original_key, backtracked_key, "Simple SecAgg")
        
        return result
    
    def run_pqc_ratcheting_audit(self) -> Dict[str, Any]:
        """Run complete audit for PQC Hash-Chain Ratcheting (Method B)."""
        self.log("\n" + "=" * 60)
        self.log("AUDIT: PQC Hash-Chain Ratcheting (Method B - Forward Privacy)")
        self.log("=" * 60)
        
        client = initialize_client_b()
        
        # Phase 1: 10-Round Key Trace
        self.log("\n[Phase 1] 10-Round Key Trace Generation")
        for round_num in range(self.max_rounds):
            key, next_seed, mac = run_round_ratcheting(client, round_num)
            self.log(f"  Round {round_num}: Key={bytes_to_hex(key)[:16]}... Seed_{round_num+1}={bytes_to_hex(next_seed)[:16]}...")
        
        print_key_trace(client, "PQC Hash-Chain Ratcheting")
        
        # Phase 2: Round 5 Compromise Simulation
        self.log(f"\n[Phase 2] Compromise Simulation at Round {self.compromise_round}")
        compromised_seed = simulate_compromise_ratcheting(client, self.compromise_round)
        self.log(f"  Adversary captures: Seed_{self.compromise_round} = {bytes_to_hex(compromised_seed)}")
        self.log(f"  Note: Adversary CANNOT derive Seed_{self.compromise_round - 1}, Seed_{self.compromise_round - 2}, ... Seed_0")
        self.log(f"  Reason: SHA-256 is a one-way function (preimage resistance)")
        
        # Phase 3: Backtracking & Back-Decryption Test
        self.log(f"\n[Phase 3] Backtracking to Round {self.target_round}")
        backtracked_key = backtrack_key_ratcheting(
            compromised_seed, self.compromise_round, self.target_round
        )
        original_key = client.round_keys[self.target_round]
        
        if backtracked_key is None:
            match = False
            self.log(f"  Original Round {self.target_round} Key:   {bytes_to_hex(original_key)}")
            self.log(f"  Backtracked Round {self.target_round} Key: DERIVATION FAILED")
            self.log(f"  Keys Match: NO")
        else:
            match = constant_time_compare(original_key, backtracked_key)
            self.log(f"  Original Round {self.target_round} Key:   {bytes_to_hex(original_key)}")
            self.log(f"  Backtracked Round {self.target_round} Key: {bytes_to_hex(backtracked_key)}")
            self.log(f"  Keys Match: {'YES' if match else 'NO'}")
        
        # Phase 4: Result
        forward_privacy = "BROKEN" if match else "PRESERVED"
        self.log(f"\n[Phase 4] RESULT: Forward Privacy = {forward_privacy}")
        
        result = {
            "method": "PQC_Ratcheting",
            "compromise_round": self.compromise_round,
            "target_round": self.target_round,
            "original_key": bytes_to_hex(original_key),
            "backtracked_key": bytes_to_hex(backtracked_key) if backtracked_key else None,
            "keys_match": match,
            "forward_privacy": forward_privacy,
            "all_round_keys": [bytes_to_hex(k) for k in client.round_keys],
            "seed_chain": [bytes_to_hex(s) for s in client.seed_history],
            "compromised_seed": bytes_to_hex(compromised_seed)
        }
        
        print_backtrack_result(self.target_round, original_key, backtracked_key, "PQC Ratcheting")
        
        return result
    
    def run_full_audit(self) -> Dict[str, Any]:
        """Run complete audit for both methods."""
        self.log("\n" + "#" * 60)
        self.log("# CAPSTONE SecAgg Forward Privacy Security Audit")
        self.log("#" * 60)
        
        # Audit Method A
        result_a = self.run_simple_secagg_audit()
        
        # Audit Method B
        result_b = self.run_pqc_ratcheting_audit()
        
        # Final Comparison
        self.log("\n" + "=" * 60)
        self.log("FINAL COMPARISON PROOF")
        self.log("=" * 60)
        self.log("")
        self.log("Method A (Simple SecAgg):")
        self.log("  - Key derivation: key_round = SHA256(static_secret || round_num)")
        self.log("  - Compromise at Round 5 reveals static_secret")
        self.log("  - Adversary computes ANY past/future round key")
        self.log(f"  - Round {self.target_round} Key Recovery: {'SUCCESS' if result_a['keys_match'] else 'FAILED'}")
        self.log(f"  - Forward Privacy: {result_a['forward_privacy']}")
        self.log("")
        self.log("Method B (PQC Hash-Chain Ratcheting):")
        self.log("  - Key derivation: ephemeral_key = SHA256(seed_t || round_num)")
        self.log("  - Seed evolution: seed_{t+1} = SHA256(seed_t || ephemeral_key)")
        self.log("  - Compromise at Round 5 reveals seed_5 ONLY")
        self.log("  - Cannot reverse SHA-256 to get seed_4, seed_3, ... seed_0")
        self.log(f"  - Round {self.target_round} Key Recovery: {'SUCCESS' if result_b['keys_match'] else 'FAILED (One-way hash)'}")
        self.log(f"  - Forward Privacy: {result_b['forward_privacy']}")
        self.log("")
        self.log("CORE RESULT:")
        self.log("  Hash-chain ratcheting PROVIDES forward privacy.")
        self.log("  Static key derivation DOES NOT provide forward privacy.")
        self.log("=" * 60)
        
        return {
            "simple_secagg": result_a,
            "pqc_ratcheting": result_b,
            "summary": {
                "simple_secagg_forward_privacy": result_a['forward_privacy'],
                "pqc_ratcheting_forward_privacy": result_b['forward_privacy'],
                "conclusion": "Forward privacy achieved only with hash-chain ratcheting"
            }
        }
    
    def export_results(self, results: Dict[str, Any], filepath: str) -> None:
        """Export audit results to JSON file."""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        self.log(f"\nResults exported to: {filepath.replace(chr(0xbc14), '').replace(chr(0xd0d5), '').replace(chr(0xd654), '').replace(chr(0xba74), '')}")


def create_auditor(config: Dict[str, Any]) -> SecurityAuditor:
    """Factory function to create SecurityAuditor."""
    return SecurityAuditor(config)