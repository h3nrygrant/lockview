"""
LockView — Locking Coverage Metrics
Computes coverage stats and key analysis from parsed netlist.
"""

from dataclasses import dataclass, field
from .parser import NetlistInfo, Gate


@dataclass
class ModuleCoverage:
    total_gates: int
    locked_gates: int
    coverage_pct: float
    key_bits: int
    key_inputs: list[str]
    locked_gate_names: list[str]
    unlocked_gate_names: list[str]
    gate_type_distribution: dict[str, int]
    key_gate_type_distribution: dict[str, int]
    avg_key_fanin: float          # avg number of key bits feeding a locked gate
    output_cone_coverage: float   # % of gates in output cones that are locked


@dataclass
class CoverageReport:
    module_name: str
    total_gates: int
    locked_gates: int
    coverage_pct: float
    key_bits: int
    key_inputs: list[str]
    gate_type_distribution: dict[str, int]
    key_gate_type_distribution: dict[str, int]
    avg_key_fanin: float
    output_cone_coverage: float
    per_output_coverage: dict[str, float]   # output net → % locked gates in its cone
    warnings: list[str] = field(default_factory=list)


def compute_coverage(netlist: NetlistInfo) -> CoverageReport:
    gates = netlist.gates
    total = len(gates)
    locked = [g for g in gates if g.is_key_gate]
    unlocked = [g for g in gates if not g.is_key_gate]

    coverage_pct = (len(locked) / total * 100) if total else 0.0

    # Gate type distributions
    gate_type_dist: dict[str, int] = {}
    key_gate_type_dist: dict[str, int] = {}
    for g in gates:
        gate_type_dist[g.gate_type] = gate_type_dist.get(g.gate_type, 0) + 1
    for g in locked:
        key_gate_type_dist[g.gate_type] = key_gate_type_dist.get(g.gate_type, 0) + 1

    # Average key fanin (how many key inputs connect per locked gate)
    total_key_inputs_used = sum(
        sum(1 for inp in g.inputs if any(k in inp for k in netlist.key_inputs))
        for g in locked
    )
    avg_key_fanin = (total_key_inputs_used / len(locked)) if locked else 0.0

    # Output cone coverage — backward reachability from each output
    # Build a map: net → gate that drives it
    net_to_gate: dict[str, Gate] = {g.output: g for g in gates}

    def cone_gates(output_net: str) -> set[str]:
        """Return set of gate names in the transitive fanin cone of output_net."""
        visited: set[str] = set()
        stack = [output_net]
        while stack:
            net = stack.pop()
            g = net_to_gate.get(net)
            if g and g.name not in visited:
                visited.add(g.name)
                stack.extend(g.inputs)
        return visited

    per_output: dict[str, float] = {}
    locked_names = {g.name for g in locked}
    all_cone_gate_names: set[str] = set()

    for out_net in netlist.outputs:
        cone = cone_gates(out_net)
        all_cone_gate_names |= cone
        if cone:
            pct = len(cone & locked_names) / len(cone) * 100
        else:
            pct = 0.0
        per_output[out_net] = round(pct, 1)

    output_cone_coverage = (
        len(all_cone_gate_names & locked_names) / len(all_cone_gate_names) * 100
        if all_cone_gate_names else 0.0
    )

    # Warnings
    warnings: list[str] = []
    if coverage_pct < 5:
        warnings.append(f"Very low locking coverage ({coverage_pct:.1f}%) — circuit may offer minimal IP protection.")
    if len(netlist.key_inputs) < 32:
        warnings.append(f"Only {len(netlist.key_inputs)} key bits — consider ≥64 bits to resist brute-force attacks.")
    if avg_key_fanin < 1.05:
        warnings.append("Most locked gates connect to only one key bit — key reuse may reduce effective key entropy.")

    return CoverageReport(
        module_name=netlist.module_name,
        total_gates=total,
        locked_gates=len(locked),
        coverage_pct=round(coverage_pct, 2),
        key_bits=len(netlist.key_inputs),
        key_inputs=netlist.key_inputs,
        gate_type_distribution=gate_type_dist,
        key_gate_type_distribution=key_gate_type_dist,
        avg_key_fanin=round(avg_key_fanin, 2),
        output_cone_coverage=round(output_cone_coverage, 2),
        per_output_coverage=per_output,
        warnings=warnings,
    )
