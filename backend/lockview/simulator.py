"""
LockView — Circuit Evaluator & Corruptibility Measurement
==============================================================
Pure Python gate-level simulator for bench-format circuits.
No external dependencies — traces 0s and 1s through gates directly.

Used when both original and locked netlists are available to compute
real corruptibility via Monte Carlo simulation, as done in published
logic locking research (Rajendran et al., Yasin et al., Karmakar et al.)

Algorithm:
  For each of N random input patterns:
    1. Evaluate original netlist → correct output vector
    2. For each sampled wrong key:
       a. Evaluate locked netlist with that wrong key → corrupted output vector
       b. Compute Hamming distance between correct and corrupted outputs
  Average HD across all (input, wrong_key) pairs = real corruptibility

I used the standard Monte Carlo corruptibility estimation used in papers
when exhaustive simulation over all 2^n inputs is infeasible.
"""

import random
from dataclasses import dataclass, field
from .parser import NetlistInfo, Gate


# ─── Gate evaluation functions ─────────────────────────────────────────────────

def _eval_gate(gate_type: str, input_vals: list[int]) -> int:
    """Evaluate a single gate given its input values. Returns 0 or 1."""
    t = gate_type.upper()

    if t == "AND":
        return 1 if all(v == 1 for v in input_vals) else 0
    elif t == "NAND":
        return 0 if all(v == 1 for v in input_vals) else 1
    elif t == "OR":
        return 1 if any(v == 1 for v in input_vals) else 0
    elif t == "NOR":
        return 0 if any(v == 1 for v in input_vals) else 1
    elif t == "XOR":
        result = 0
        for v in input_vals:
            result ^= v
        return result
    elif t == "XNOR":
        result = 0
        for v in input_vals:
            result ^= v
        return 1 - result  # invert XOR
    elif t in ("NOT", "INV"):
        return 1 - input_vals[0]
    elif t in ("BUF", "BUFF"):
        return input_vals[0]
    elif t == "MUX":
        # MUX(sel, in0, in1) — sel=0 → in0, sel=1 → in1
        if len(input_vals) >= 3:
            return input_vals[1] if input_vals[0] == 0 else input_vals[2]
        return input_vals[0]
    else:
        # Unknown gate type — pass through first input
        return input_vals[0] if input_vals else 0


# ─── Netlist evaluator ─────────────────────────────────────────────────────────
def get_evaluation_order(gates: list[Gate]) -> list[Gate]:
    """
    Compute topological evaluation order once — reuse across all evaluations.
    Returns gates sorted so every gate's inputs are resolved before it runs.
    """
    resolved: set[str] = set()
    ordered: list[Gate] = []
    remaining = gates[:]
    max_iterations = len(gates) + 10

    iteration = 0
    while remaining and iteration < max_iterations:
        iteration += 1
        still_pending = []
        for gate in remaining:
            if all(inp in resolved for inp in gate.inputs):
                ordered.append(gate)
                resolved.add(gate.output)
            else:
                still_pending.append(gate)
        remaining = still_pending

    # Any unresolvable gates (loops) — append at end
    ordered.extend(remaining)
    return ordered


def evaluate_ordered(
    ordered_gates: list[Gate],
    input_assignment: dict[str, int]
) -> dict[str, int]:
    """
    Evaluate circuit given pre-ordered gates. Much faster than evaluate()
    since topological order is already resolved.
    """
    wire_values: dict[str, int] = dict(input_assignment)

    for gate in ordered_gates:
        input_vals = [wire_values.get(inp, 0) for inp in gate.inputs]
        wire_values[gate.output] = _eval_gate(gate.gate_type, input_vals)

    return wire_values


def get_output_vector(wire_values: dict[str, int], output_nets: list[str]) -> list[int]:
    """Extract output bit vector in order of output_nets."""
    return [wire_values.get(net, 0) for net in output_nets]


def hamming_distance(vec_a: list[int], vec_b: list[int]) -> int:
    """Bit-level Hamming distance between two output vectors."""
    return sum(a != b for a, b in zip(vec_a, vec_b))


# ─── Real corruptibility measurement ──────────────────────────────────────────

@dataclass
class RealCorruptibilityReport:
    # Core metrics
    mean_hamming_distance: float        # avg HD per output bit [0.0 – 1.0]
    corruptibility_pct: float           # mean_HD × 100
    output_corruption_coverage: float   # % of outputs corrupted at least once
    per_output_corruption: dict[str, float]  # output net → avg corruption prob

    # Simulation parameters
    n_input_samples: int
    n_wrong_key_samples: int
    total_evaluations: int              # n_input_samples × n_wrong_key_samples
    key_bits: int
    correct_key: dict[str, int]

    # Risk
    risk_level: str                     # "low" | "medium" | "balanced" | "high"
    risk_flags: list[str]

    # Metadata
    method: str = "monte-carlo-simulation"
    confidence: str = "measured"        # not an estimate


def measure_corruptibility(
    original: NetlistInfo,
    locked: NetlistInfo,
    correct_key: dict[str, int],
    n_input_samples: int = 10_000,
    n_wrong_key_samples: int = 50,
    seed: int = 42,
) -> RealCorruptibilityReport:
    """
    Measures real corruptibility via Monte Carlo simulation.

    Args:
        original:           Parsed original (unlocked) netlist
        locked:             Parsed locked netlist
        correct_key:        Dict of {keyinput_name: correct_bit_value}
        n_input_samples:    Number of random primary input patterns to test
        n_wrong_key_samples: Number of random wrong keys to test per input
        seed:               Random seed for reproducibility
    """
    rng = random.Random(seed)

    primary_inputs = original.inputs        # non-key primary inputs
    output_nets = original.outputs
    key_input_names = locked.key_inputs
    # Computes gate evaluation order once — reuse across all evaluations
    orig_ordered = get_evaluation_order(original.gates)
    locked_ordered = get_evaluation_order(locked.gates)

    n_outputs = len(output_nets)
    if n_outputs == 0:
        raise ValueError("No primary outputs found in netlist")

    # Accumulators: per output bit, how often was it corrupted?
    per_output_corrupted: dict[str, int] = {net: 0 for net in output_nets}
    total_hd_bits = 0           # total differing output bits across all evaluations
    total_evaluations = 0

    prev_corruptibility_pct = 0.0
    check_interval = 50

    for sample_idx in range(n_input_samples):
        # Random primary input assignment (same for both original and locked)
        input_vals = {inp: rng.randint(0, 1) for inp in primary_inputs}

        # Evaluate original netlist → correct output
        orig_wires = evaluate_ordered(orig_ordered, input_vals)
        correct_output = get_output_vector(orig_wires, output_nets)

        # Test multiple wrong keys
        for _ in range(n_wrong_key_samples):
            # Generate a wrong key — at least one bit different from correct key
            wrong_key = _sample_wrong_key(correct_key, key_input_names, rng)

            # Builds full input assignment for locked netlist
            locked_input = {**input_vals, **wrong_key}
            locked_wires = evaluate_ordered(locked_ordered, locked_input)
            wrong_output = get_output_vector(locked_wires, output_nets)

            # Compute Hamming distance
            for i, net in enumerate(output_nets):
                if correct_output[i] != wrong_output[i]:
                    per_output_corrupted[net] += 1
                    total_hd_bits += 1

            total_evaluations += 1

        # Early stopping check — only after 500 input patterns minimum
        if sample_idx > 500 and sample_idx % check_interval == 0:
            current_corruptibility_pct = round(total_hd_bits / (total_evaluations * n_outputs) * 100, 2)
            if abs(current_corruptibility_pct - prev_corruptibility_pct) < 0.05:
                print(f"  Early stopping at {total_evaluations:,} evaluations — result stabilized at {current_corruptibility_pct}%")
                break
            prev_corruptibility_pct = current_corruptibility_pct

    # Compute final metrics
    per_output_corruption = {
        net: round(per_output_corrupted[net] / total_evaluations, 4)
        for net in output_nets
    }

    mean_hd = total_hd_bits / (total_evaluations * n_outputs) if total_evaluations > 0 else 0.0
    corruptibility_pct = round(mean_hd * 100, 2)

    # Output corruption coverage — % of outputs corrupted at least once
    corrupted_outputs = sum(1 for v in per_output_corrupted.values() if v > 0)
    occ = round(corrupted_outputs / n_outputs * 100, 2) if n_outputs > 0 else 0.0

    # Risk assessment
    risk_level, risk_flags = _assess_risk(corruptibility_pct, per_output_corruption, output_nets)

    return RealCorruptibilityReport(
        mean_hamming_distance=round(mean_hd, 4),
        corruptibility_pct=corruptibility_pct,
        output_corruption_coverage=occ,
        per_output_corruption=per_output_corruption,
        n_input_samples=n_input_samples,
        n_wrong_key_samples=n_wrong_key_samples,
        total_evaluations=total_evaluations,
        key_bits=len(key_input_names),
        correct_key=correct_key,
        risk_level=risk_level,
        risk_flags=risk_flags,
    )


def _sample_wrong_key(
    correct_key: dict[str, int],
    key_input_names: list[str],
    rng: random.Random,
) -> dict[str, int]:
    """
    Sample a random wrong key — guaranteed to differ from correct key
    in at least one bit position.
    """
    while True:
        wrong_key = {k: rng.randint(0, 1) for k in key_input_names}
        # Ensure it's actually wrong
        if any(wrong_key.get(k, 0) != v for k, v in correct_key.items()):
            return wrong_key


def _assess_risk(
    corruptibility_pct: float,
    per_output: dict[str, float],
    output_nets: list[str],
) -> tuple[str, list[str]]:
    """Risk assessment based on measured corruptibility."""
    flags: list[str] = []
    risk = "balanced"

    if corruptibility_pct < 10:
        flags.append(
            f"Very low corruptibility ({corruptibility_pct}%) — high AppSAT risk. "
            "AppSAT terminates early when wrong keys rarely produce wrong outputs."
        )
        risk = "high"
    elif corruptibility_pct < 25:
        flags.append(
            f"Low corruptibility ({corruptibility_pct}%) — consider adding more "
            "XOR/XNOR locked gates to approach the 50% target."
        )
        risk = "medium"
    elif corruptibility_pct < 45:
        flags.append(
            f"Corruptibility ({corruptibility_pct}%) is below the 45-55% target range — "
            "more locked gates needed in output cones."
        )
        risk = "medium"
    elif corruptibility_pct <= 55:
        flags.append(
            f"Corruptibility ({corruptibility_pct}%) is within the 45-55% target range — "
            "good corruptibility profile."
        )
        risk = "balanced"
    elif corruptibility_pct <= 75:
        flags.append(
            f"Corruptibility ({corruptibility_pct}%) is above the 45-55% target range — "
            "verify SAT resistance separately."
        )
        risk = "medium"
    else:
        flags.append(
            f"Very high corruptibility ({corruptibility_pct}%) — without SAT-resistant structure "
            "this circuit is likely vulnerable to the standard SAT attack."
        )
        risk = "high"

    # Flag zero-corruption outputs
    zero_outputs = [net for net, v in per_output.items() if v == 0.0]
    if zero_outputs:
        flags.append(
            f"Outputs {zero_outputs} were never corrupted across all simulations — "
            "these outputs are fully observable without the correct key."
        )
        if risk == "balanced":
            risk = "medium"

    return risk, flags
