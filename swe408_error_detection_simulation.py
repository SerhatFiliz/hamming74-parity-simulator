"""
--------------------------------------------------------------------------
Sakarya University
Faculty of Computer and Information Sciences
Department of Software Engineering
Course: SWE408 - DATA COMMUNICATION AND COMPUTER NETWORKS
Instructor: ELTAHIR IDRIS ELTAHIR MOHAMED MOHAMED
Assignment: #1 - Simulation and Analysis of Error Detection
Student: Serhat Filiz
Student ID: B211202031
--------------------------------------------------------------------------

USAGE INSTRUCTIONS:
Run with the default dataword (101011001):
  python swe408_error_detection_simulation.py
Run with a custom variable-length dataword (e.g., 4-bit, 8-bit, etc.):
  python swe408_error_detection_simulation.py --dataword 1011
  python swe408_error_detection_simulation.py --dataword 11110000
"""

import argparse
import hashlib
import random

# Data Input Handling & Validation
def validate_binary_string(s: str) -> None:
    s = s.strip()
    if not s:
        raise ValueError("Binary dataword must not be empty.")
    if any(ch not in "01" for ch in s):
        raise ValueError("Binary dataword must contain only '0' and '1'.")


def to_bit_list(binary_string: str) -> list[int]:
    return [1 if ch == "1" else 0 for ch in binary_string.strip()]


def bits_to_string(bits: list[int]) -> str:
    return "".join("1" if b else "0" for b in bits)


def stable_seed(*parts: str) -> int:
    payload = "|".join(parts).encode("utf-8")
    digest = hashlib.sha256(payload).digest()
    return int.from_bytes(digest[:4], "big", signed=False)


# Parity Check Encoding (Even/Odd)
def encode_parity(data_bits: list[int], parity_mode: str) -> list[int]:
    if parity_mode not in ("even", "odd"):
        raise ValueError("parity_mode must be 'even' or 'odd'.")
    data_ones = sum(data_bits) % 2
    desired_total_parity = 0 if parity_mode == "even" else 1
    parity_bit = desired_total_parity ^ data_ones
    return data_bits + [parity_bit]


# Receiving Process & Error Detection Logic
def detect_parity(received_bits: list[int], parity_mode: str) -> bool:
    if parity_mode not in ("even", "odd"):
        raise ValueError("parity_mode must be 'even' or 'odd'.")
    total_parity = sum(received_bits) % 2
    expected_total_parity = 0 if parity_mode == "even" else 1
    return total_parity != expected_total_parity


def chunk_bits(bits: list[int], size: int) -> list[list[int]]:
    return [bits[i : i + size] for i in range(0, len(bits), size)]


# Block Coding (Hamming 7,4 Implementation)
def encode_hamming74(data_bits: list[int]) -> tuple[list[int], int]:
    k = 4
    n = 7
    padded = data_bits[:]
    if len(padded) % k != 0:
        padded.extend([0] * (k - (len(padded) % k)))

    encoded: list[int] = []
    for block in chunk_bits(padded, k):
        d0, d1, d2, d3 = block
        # Codeword positions (1-indexed): 1=p1, 2=p2, 3=d0, 4=p4, 5=d1, 6=d2, 7=d3
        p1 = d0 ^ d1 ^ d3
        p2 = d0 ^ d2 ^ d3
        p4 = d1 ^ d2 ^ d3

        codeword = [p1, p2, d0, p4, d1, d2, d3]
        if len(codeword) != n:
            raise RuntimeError("Unexpected Hamming(7,4) codeword length.")
        encoded.extend(codeword)
    return encoded, len(padded)


# Receiving Process & Error Detection Logic
def detect_hamming74(received_bits: list[int]) -> bool:
    if len(received_bits) % 7 != 0:
        raise ValueError("Received Hamming(7,4) codeword length must be a multiple of 7.")

    error_detected = False
    for block in chunk_bits(received_bits, 7):
        # Syndrome bits computed from even parity checks on the received block.
        # Parity-check sets:
        # s1: positions {1,3,5,7}
        # s2: positions {2,3,6,7}
        # s4: positions {4,5,6,7}
        r1, r2, r3, r4, r5, r6, r7 = block
        s1 = r1 ^ r3 ^ r5 ^ r7
        s2 = r2 ^ r3 ^ r6 ^ r7
        s4 = r4 ^ r5 ^ r6 ^ r7
        if (s1 | s2 | s4) != 0:
            error_detected = True
    return error_detected


# Transmission Simulation & Error Injection
def inject_error(code_bits: list[int], scenario: str, burst_len: int, seed: int) -> list[int]:
    if scenario not in ("no_error", "single_bit", "burst"):
        raise ValueError("scenario must be one of: 'no_error', 'single_bit', 'burst'.")

    received = code_bits[:]
    if scenario == "no_error":
        return received

    rng = random.Random(seed)
    if scenario == "single_bit":
        i = rng.randrange(0, len(received))
        received[i] ^= 1
        return received

    burst_len_eff = min(burst_len, len(received))
    if burst_len_eff < 2:
        i = rng.randrange(0, len(received))
        received[i] ^= 1
        return received

    start = rng.randrange(0, len(received) - burst_len_eff + 1)
    for idx in range(start, start + burst_len_eff):
        received[idx] ^= 1
    return received


def final_result_text(error_detected: bool) -> str:
    return "Corrupted (Error is detected)" if error_detected else "Successful (No error detected)"


def redundancy_ratio(redundant_bits: int, data_bits: int) -> float:
    if data_bits <= 0:
        return 0.0
    return redundant_bits / data_bits


def format_redundancy(redundant_bits: int, data_bits: int) -> str:
    ratio = redundancy_ratio(redundant_bits, data_bits)
    return f"{redundant_bits}/{data_bits} = {ratio:.6f} ({ratio * 100:.2f}%)"


def run_parity_scenario(
    original_dataword: str, data_bits: list[int], parity_mode: str, scenario: str, burst_len: int
) -> dict:
    # Parity Check Encoding (Even/Odd)
    generated = encode_parity(data_bits, parity_mode)
    seed = stable_seed("parity", parity_mode, scenario, str(len(generated)), original_dataword)
    # Transmission Simulation & Error Injection
    received = inject_error(generated, scenario, burst_len, seed)
    # Receiving Process & Error Detection Logic
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


def run_block_scenario(original_dataword: str, data_bits: list[int], scenario: str, burst_len: int) -> dict:
    # Block Coding (Hamming 7,4 Implementation)
    generated, padded_len = encode_hamming74(data_bits)
    seed = stable_seed("block_hamming74", scenario, str(len(generated)), original_dataword, str(padded_len))
    # Transmission Simulation & Error Injection
    received = inject_error(generated, scenario, burst_len, seed)
    # Receiving Process & Error Detection Logic
    error_detected = detect_hamming74(received)
    redundant = len(generated) - padded_len
    return {
        "method": "Block Coding (Hamming(7,4))",
        "scenario": scenario,
        "original_dataword": original_dataword,
        "generated_codeword": bits_to_string(generated),
        "received_codeword": bits_to_string(received),
        "error_detected": error_detected,
        "ground_truth_error_present": scenario != "no_error",
        "redundant_bits": redundant,
        "data_bits_count": padded_len,
    }


# System Metrics Display
def print_run_metrics(record: dict) -> None:
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


# Markdown Analysis Report Generation
def print_analysis_report(results: list[dict]) -> None:
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

    # Detection behavior insight for this specific run.
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
    default_dataword = "101011001"
    parser = argparse.ArgumentParser(description="SWE408 error detection simulation")
    parser.add_argument("--dataword", default=default_dataword, help="Binary dataword (e.g., 101011001).")
    args = parser.parse_args()
    dataword = args.dataword.strip()

    # Data Input Handling & Validation
    validate_binary_string(dataword)

    data_bits = to_bit_list(dataword)
    burst_len = 3

    # Automated Scenario Testing
    scenarios = ["no_error", "single_bit", "burst"]
    results: list[dict] = []

    for scenario in scenarios:
        parity_even = run_parity_scenario(dataword, data_bits, "even", scenario, burst_len)
        parity_odd = run_parity_scenario(dataword, data_bits, "odd", scenario, burst_len)
        block = run_block_scenario(dataword, data_bits, scenario, burst_len)

        # System Metrics Display
        print_run_metrics(parity_even)
        print_run_metrics(parity_odd)
        print_run_metrics(block)

        results.extend([parity_even, parity_odd, block])

    # Markdown Analysis Report Generation
    print_analysis_report(results)


if __name__ == "__main__":
    main()

