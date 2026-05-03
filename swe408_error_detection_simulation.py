"""
Error Detection Simulation Tool.
Simulates Parity Check and Hamming Block Coding against single-bit and burst errors.

Usage:
    python swe408_error_detection_simulation.py [--dataword BINARY] [--burst_len LEN] [--hamming_r R]
"""

import argparse
import hashlib
import random

# ============================================================================
# 1. UTILITIES & DATA INPUT HANDLING
# ============================================================================


def validate_binary_string(s: str) -> None:
    """Validate that the binary string is non-empty and contains only 0 and 1."""
    s = s.strip()
    if not s:
        raise ValueError("Binary dataword must not be empty.")
    if any(ch not in "01" for ch in s):
        raise ValueError("Binary dataword must contain only '0' and '1'.")


def to_bit_list(binary_string: str) -> list[int]:
    """Convert a binary string into a list of integer bits (0/1)."""
    return [int(ch) for ch in binary_string.strip()]


def bits_to_string(bits: list[int]) -> str:
    """Convert a list of integer bits (0/1) into its binary string representation."""
    return "".join(str(b) for b in bits)


def stable_seed(*parts: str) -> int:
    """Create a deterministic integer seed from scenario parameters for reproducible error injection."""
    raw = "|".join(parts).encode("utf-8")
    digest = hashlib.sha256(raw).digest()
    return int.from_bytes(digest[:4], "big")


def redundancy_ratio(redundant_bits: int, data_bits: int) -> float:
    """Compute the redundancy ratio (redundant/data)."""
    if data_bits <= 0:
        return 0.0
    return redundant_bits / data_bits


def format_redundancy(redundant_bits: int, data_bits: int) -> str:
    """Format redundancy ratio for display."""
    ratio = redundancy_ratio(redundant_bits, data_bits)
    return f"{redundant_bits}/{data_bits} = {ratio:.6f} ({ratio * 100:.2f}%)"


def final_result_text(error_detected: bool) -> str:
    """Return the final status string based on detection state."""
    return "Corrupted (Error is detected)" if error_detected else "Successful (No error detected)"


# ============================================================================
# 2. PARITY CHECK SYSTEM
# ============================================================================


def encode_parity(data_bits: list[int], parity_mode: str) -> list[int]:
    """Encode data bits with an even or odd parity bit."""
    if parity_mode not in ("even", "odd"):
        raise ValueError("parity_mode must be 'even' or 'odd'.")
    data_ones = sum(data_bits) % 2
    desired_total_parity = 0 if parity_mode == "even" else 1
    parity_bit = desired_total_parity ^ data_ones
    return data_bits + [parity_bit]


def detect_parity(received_bits: list[int], parity_mode: str) -> bool:
    """Verify parity of the received codeword and return True if an error is detected."""
    if parity_mode not in ("even", "odd"):
        raise ValueError("parity_mode must be 'even' or 'odd'.")
    total_parity = sum(received_bits) % 2
    expected_total_parity = 0 if parity_mode == "even" else 1
    return total_parity != expected_total_parity


# ============================================================================
# 3. HAMMING(7,4) BLOCK CODE SYSTEM
# ============================================================================


def chunk_bits(bits: list[int], size: int) -> list[list[int]]:
    """Split a bit stream into fixed-size blocks for k->n block code processing."""
    return [bits[i : i + size] for i in range(0, len(bits), size)]


def encode_hamming_dynamic(data_bits: list[int], r: int = 3) -> tuple[list[int], int]:
    """Encode data into Hamming(n, k) block code where n=2^r-1 and k=n-r."""
    n = 2**r - 1
    k = n - r
    
    # Pad data to align with block size k
    padded = data_bits[:]
    if len(padded) % k != 0:
        padded.extend([0] * (k - (len(padded) % k)))

    encoded: list[int] = []
    
    # Process blocks of k-bits
    for block in chunk_bits(padded, k):
        # Use 1-based indexing for standard Hamming code positions
        codeword = [0] * (n + 1)
        
        # Place data bits at non-power-of-2 positions
        data_idx = 0
        for i in range(1, n + 1):
            if (i & (i - 1)) != 0:  # Bitwise trick: i is not a power of 2
                codeword[i] = block[data_idx]
                data_idx += 1
        
        # Calculate parity bits at power-of-2 positions
        for i in range(r):
            p_pos = 2**i
            parity_val = 0
            for j in range(1, n + 1):
                # Check if position j is covered by parity p_pos
                if j & p_pos:
                    parity_val ^= codeword[j]
            codeword[p_pos] = parity_val
            
        encoded.extend(codeword[1:])
        
    return encoded, len(padded)


def detect_hamming_dynamic(received_bits: list[int], r: int = 3) -> bool:
    """Calculate the syndrome for received Hamming(n, k) blocks to detect errors."""
    n = 2**r - 1
    if len(received_bits) % n != 0:
        raise ValueError(f"Received codeword length must be a multiple of {n}.")

    error_detected = False
    for block in chunk_bits(received_bits, n):
        # 1-based indexing alignment
        indexed_block = [0] + block
        syndrome = 0

        # Check each parity position; accumulate its power-of-2 index on failure
        for i in range(r):
            parity_pos = 2**i
            syndrome_bit = 0
            for j in range(1, n + 1):
                # Check if position j is covered by parity parity_pos
                if j & parity_pos:
                    syndrome_bit ^= indexed_block[j]
            if syndrome_bit != 0:
                syndrome += parity_pos

        if syndrome != 0:
            error_detected = True

    return error_detected


# ============================================================================
# 4. TRANSMISSION SIMULATION & ERROR INJECTION
# ============================================================================


def inject_error(code_bits: list[int], scenario: str, burst_len: int, seed: int) -> list[int]:
    """Inject specific error patterns into the bitstream for testing."""
    if scenario not in ("no_error", "single_bit", "burst"):
        raise ValueError("scenario must be one of: 'no_error', 'single_bit', 'burst'.")

    received = code_bits[:]  # Create a shallow copy to prevent aliasing issues
    if scenario == "no_error":
        return received

    rng = random.Random(seed)
    if scenario == "single_bit":
        i = rng.randrange(0, len(received))
        received[i] ^= 1  # Flip bit via XOR
        return received

    burst_len_eff = min(burst_len, len(received))
    if burst_len_eff < 2:
        i = rng.randrange(0, len(received))
        received[i] ^= 1  # Flip bit via XOR
        return received

    start = rng.randrange(0, len(received) - burst_len_eff + 1)
    for idx in range(start, start + burst_len_eff):
        received[idx] ^= 1  # Flip bit via XOR
    return received


# ============================================================================
# 5. SIMULATION RUNNERS & ANALYSIS REPORTING
# ============================================================================


def run_parity_scenario(
    original_dataword: str, data_bits: list[int], parity_mode: str, scenario: str, burst_len: int
) -> dict:
    """Execute a parity check simulation scenario and return metrics."""
    generated = encode_parity(data_bits, parity_mode)
    seed = stable_seed("parity", parity_mode, scenario, str(len(generated)), original_dataword)
    received = inject_error(generated, scenario, burst_len, seed)
    error_detected = detect_parity(received, parity_mode)
    redundant = 1
    data_len = len(data_bits)
    return {
        "method": f"Parity Check ({parity_mode} parity)",
        "scenario": scenario,
        "original_dataword": original_dataword,
        "generated_codeword": bits_to_string(generated),
        "received_codeword": bits_to_string(received),
        "error_detected": error_detected,
        "ground_truth_error_present": scenario != "no_error",
        "redundant_bits": redundant,
        "data_bits_count": data_len,
    }


def run_block_scenario(
    original_dataword: str, data_bits: list[int], scenario: str, burst_len: int, hamming_r: int
) -> dict:
    """Execute a Hamming block coding simulation scenario and return metrics."""
    # n = 2^r - 1 (Total codeword length), k = n - r (Data bits length)
    generated, padded_len = encode_hamming_dynamic(data_bits, r=hamming_r)
    
    n_val = 2**hamming_r - 1
    k_val = n_val - hamming_r
    
    seed = stable_seed(
        f"block_hamming_{n_val}_{k_val}", 
        scenario, 
        str(len(generated)), 
        original_dataword, 
        str(padded_len)
    )
    
    received = inject_error(generated, scenario, burst_len, seed)
    error_detected = detect_hamming_dynamic(received, r=hamming_r)
    
    redundant = len(generated) - padded_len
    
    return {
        "method": f"Block Coding (Hamming {n_val},{k_val})",
        "scenario": scenario,
        "original_dataword": original_dataword,
        "generated_codeword": bits_to_string(generated),
        "received_codeword": bits_to_string(received),
        "error_detected": error_detected,
        "ground_truth_error_present": scenario != "no_error",
        "redundant_bits": redundant,
        "data_bits_count": padded_len,
    }


def print_run_metrics(record: dict) -> None:
    """Print the execution log metrics for a given scenario run."""
    scenario_titles = {
        "no_error": "No error introduced",
        "single_bit": "A single-bit error was introduced",
        "burst": "A multiple-bit (burst) error was introduced",
    }
    print(f"Method: {record['method']}")
    print(f"Scenario: {scenario_titles[record['scenario']]}")
    print(f"Original dataword: {record['original_dataword']}")
    print(f"Generated codeword: {record['generated_codeword']}")
    print(f"Received codeword: {record['received_codeword']}")
    print(
        "Redundancy Ratio (redundant/data): "
        f"{format_redundancy(record['redundant_bits'], record['data_bits_count'])}"
    )
    print(f"Final error detection result: {final_result_text(record['error_detected'])}")
    print("-" * 70)


def print_analysis_report(results: list[dict]) -> None:
    """Print an analysis report summarizing the simulation results."""
    scenario_order = ["no_error", "single_bit", "burst"]
    scenario_titles = {
        "no_error": "No error introduced",
        "single_bit": "A single-bit error was introduced",
        "burst": "A multiple-bit (burst) error was introduced",
    }
    methods = sorted({r["method"] for r in results})

    print()
    print("# Analysis Report")
    print()

    print("## Engineering Metrics")
    for method in methods:
        r = next(x for x in results if x["method"] == method and x["scenario"] == "no_error")
        print(
            f"- {method}: Redundancy Ratio (redundant/data) = "
            f"{format_redundancy(r['redundant_bits'], r['data_bits_count'])}"
        )
    print()

    print("## Scenario Testing")
    for scenario in scenario_order:
        print(f"### {scenario_titles[scenario]}")
        for method in methods:
            r = next(x for x in results if x["method"] == method and x["scenario"] == scenario)
            status = final_result_text(r["error_detected"])
            gt = "error present" if r["ground_truth_error_present"] else "no error present"
            print(f"- {method}: {status} (ground truth: {gt})")
        print()

    print("## Comparative Analysis")
    no_error_parity_ok = all(
        (not r["error_detected"])
        for r in results
        if r["scenario"] == "no_error" and "Parity Check" in r["method"]
    )
    block_no_error_ok = all(
        (not r["error_detected"]) for r in results if r["scenario"] == "no_error" and "Block Coding" in r["method"]
    )
    print()
    print("- In the `no_error` scenario, both techniques behave as expected: no error is detected.")
    print(f"- Parity Check correctness on `no_error`: {no_error_parity_ok}.")
    print(f"- Block Coding correctness on `no_error`: {block_no_error_ok}.")
    print()

    for scenario in ["single_bit", "burst"]:
        parity_methods = [m for m in methods if m.startswith("Parity Check")]
        block_method = [m for m in methods if m.startswith("Block Coding")][0]
        parity_detected = all(
            next(x for x in results if x["method"] == m and x["scenario"] == scenario)["error_detected"]
            for m in parity_methods
        )
        block_detected = next(x for x in results if x["method"] == block_method and x["scenario"] == scenario)[
            "error_detected"
        ]
        print(f"- On `{scenario}`, parity methods detect error: {parity_detected}; block coding detects error: {block_detected}.")


def main() -> None:
    """Run the main simulation pipeline."""
    default_dataword = "101011001"
    parser = argparse.ArgumentParser(description="SWE408 error detection simulation")
    parser.add_argument("--dataword", default=default_dataword, help="Binary dataword (e.g., 101011001).")
    parser.add_argument('--burst_len', type=int, default=3, help='Length of the burst error (default: 3)')
    parser.add_argument('--hamming_r', type=int, default=3, help='Number of redundant bits for Hamming (default: 3 for Hamming 7,4)')
    args = parser.parse_args()
    dataword = args.dataword.strip()
    burst_len = args.burst_len
    hamming_r = args.hamming_r

    validate_binary_string(dataword)

    data_bits = to_bit_list(dataword)
    

    scenarios = ["no_error", "single_bit", "burst"]
    results: list[dict] = []

    for scenario in scenarios:
        parity_even = run_parity_scenario(dataword, data_bits, "even", scenario, burst_len)
        parity_odd = run_parity_scenario(dataword, data_bits, "odd", scenario, burst_len)
        block = run_block_scenario(dataword, data_bits, scenario, burst_len, hamming_r)

        print_run_metrics(parity_even)
        print_run_metrics(parity_odd)
        print_run_metrics(block)

        results.extend([parity_even, parity_odd, block])

    print_analysis_report(results)


if __name__ == "__main__":
    main()

