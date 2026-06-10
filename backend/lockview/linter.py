"""
LockView — Attack Surface Linter
Flags known vulnerabilities in logic locking schemes based on published attacks.

References:
  - SAT attack (Subramanyan et al., 2015)
  - ATPG-based attack (El Massad et al., 2015)
  - Structural analysis (Yasin et al., 2016 — SARLock / Anti-SAT awareness)
  - CAS-Lock / SFLL structural patterns (Shakya et al., 2020)
  - Sensitization attack on XOR/XNOR chains
"""

from dataclasses import dataclass, field
from enum import Enum
from .parser import NetlistInfo, Gate


class Severity(str, Enum):
    ERROR = "error"       # high-confidence vulnerability
    WARNING = "warning"   # potential weakness
    INFO = "info"         # informational / best-practice


@dataclass
class Diagnostic:
    severity: Severity
    message: str
    line_number: int        # 1-based, 0 = file-level
    gate_name: str
    rule_id: str
    detail: str = ""        # longer explanation for hover tooltip


@dataclass
class LintReport:
    diagnostics: list[Diagnostic]
    summary: dict[str, int]   # severity → count


# ─── Individual rules ──────────────────────────────────────────────────────────

def _rule_xor_chain(gates: list[Gate], key_inputs: list[str]) -> list[Diagnostic]:
    """
    Sensitization attack: long chains of XOR/XNOR gates all driven by key bits
    can be broken individually via sensitization without needing the full key.
    Flag chains of 3+ consecutive XOR/XNOR key gates.
    """
    diags: list[Diagnostic] = []
    xor_key_gates = {g.name for g in gates if g.gate_type in ("XOR", "XNOR") and g.is_key_gate}
    net_to_gate = {g.output: g for g in gates}

    visited: set[str] = set()
    for g in gates:
        if g.name in visited or g.gate_type not in ("XOR", "XNOR") or not g.is_key_gate:
            continue
        # Walk the chain
        chain = [g]
        cur = g
        while True:
            # Find a successor gate that is also an XOR/XNOR key gate fed by cur's output
            next_g = next(
                (ng for ng in gates
                 if ng.gate_type in ("XOR", "XNOR")
                 and ng.is_key_gate
                 and cur.output in ng.inputs),
                None
            )
            if next_g is None:
                break
            chain.append(next_g)
            cur = next_g

        if len(chain) >= 3:
            for cg in chain:
                visited.add(cg.name)
            diags.append(Diagnostic(
                severity=Severity.WARNING,
                message=f"XOR/XNOR key-gate chain of length {len(chain)} detected — vulnerable to sensitization attack.",
                line_number=chain[0].line_number,
                gate_name=chain[0].name,
                rule_id="LV001",
                detail=(
                    f"Gates: {', '.join(c.name for c in chain)}. "
                    "Long XOR chains allow attackers to determine key bits one by one "
                    "via input sensitization without solving the full SAT instance. "
                    "Consider interleaving with non-XOR locked gates or using SFLL-flex."
                )
            ))
    return diags


def _rule_low_key_entropy(gates: list[Gate], key_inputs: list[str]) -> list[Diagnostic]:
    """
    Flag when the same key bit is reused across many gates — reduces effective entropy.
    """
    diags: list[Diagnostic] = []
    key_usage: dict[str, list[str]] = {}
    for g in gates:
        if g.key_input:
            key_usage.setdefault(g.key_input, []).append(g.name)

    for ki, gate_names in key_usage.items():
        if len(gate_names) >= 4:
            # find line number of first gate using this key
            first_line = next(
                (g.line_number for g in gates if g.key_input == ki), 0
            )
            diags.append(Diagnostic(
                severity=Severity.WARNING,
                message=f"Key bit '{ki}' reused across {len(gate_names)} gates — reduces effective key entropy.",
                line_number=first_line,
                gate_name=gate_names[0],
                rule_id="LV002",
                detail=(
                    f"Reused in: {', '.join(gate_names[:6])}{'...' if len(gate_names) > 6 else ''}. "
                    "High key reuse means breaking one gate's key bit reveals information about others. "
                    "Each key bit should ideally control exactly one locked gate (1:1 mapping)."
                )
            ))
    return diags


def _rule_output_cone_gap(gates: list[Gate], outputs: list[str]) -> list[Diagnostic]:
    """
    Flag outputs whose transitive fanin cone contains zero locked gates —
    those outputs are fully observable regardless of key, enabling partial ATPG.
    """
    diags: list[Diagnostic] = []
    net_to_gate = {g.output: g for g in gates}
    locked_names = {g.name for g in gates if g.is_key_gate}

    def cone_names(net: str) -> set[str]:
        visited: set[str] = set()
        stack = [net]
        while stack:
            n = stack.pop()
            g = net_to_gate.get(n)
            if g and g.name not in visited:
                visited.add(g.name)
                stack.extend(g.inputs)
        return visited

    for out in outputs:
        cone = cone_names(out)
        if cone and not (cone & locked_names):
            diags.append(Diagnostic(
                severity=Severity.ERROR,
                message=f"Output '{out}' has no locked gates in its fanin cone — fully observable without key.",
                line_number=0,
                gate_name=out,
                rule_id="LV003",
                detail=(
                    f"The entire combinational cone driving '{out}' contains no key-gated logic. "
                    "An attacker can use ATPG to generate distinguishing input patterns on this output "
                    "without needing the key. Every primary output should have at least one locked gate "
                    "in its transitive fanin."
                )
            ))
    return diags


def _rule_single_key_gate_output(gates: list[Gate], outputs: list[str]) -> list[Diagnostic]:
    """
    Outputs controlled by exactly one key gate may be vulnerable to key-bit isolation.
    """
    diags: list[Diagnostic] = []
    net_to_gate = {g.output: g for g in gates}
    locked_names_set = {g.name for g in gates if g.is_key_gate}

    def cone_names(net: str) -> set[str]:
        visited: set[str] = set()
        stack = [net]
        while stack:
            n = stack.pop()
            g = net_to_gate.get(n)
            if g and g.name not in visited:
                visited.add(g.name)
                stack.extend(g.inputs)
        return visited

    for out in outputs:
        cone = cone_names(out)
        locked_in_cone = cone & locked_names_set
        if len(locked_in_cone) == 1:
            diags.append(Diagnostic(
                severity=Severity.INFO,
                message=f"Output '{out}' has only 1 locked gate in its cone — consider adding more locking depth.",
                line_number=0,
                gate_name=out,
                rule_id="LV004",
                detail=(
                    "With only one locked gate per output cone, the SAT attack resolves this output "
                    "in very few iterations. Adding 2–3 locked gates per output cone significantly "
                    "increases SAT attack complexity."
                )
            ))
    return diags


def _rule_non_xor_locked(gates: list[Gate]) -> list[Diagnostic]:
    """
    Non-XOR locked gates (AND, OR, MUX with key) can leak key value
    through logic-0 or logic-1 forcing — flag them as lower-security.
    """
    diags: list[Diagnostic] = []
    risky_types = {"AND", "NAND", "OR", "NOR"}
    for g in gates:
        if g.is_key_gate and g.gate_type in risky_types:
            diags.append(Diagnostic(
                severity=Severity.INFO,
                message=f"Gate '{g.name}' ({g.gate_type}) locked with key — AND/OR locking leaks key via stuck-at forcing.",
                line_number=g.line_number,
                gate_name=g.name,
                rule_id="LV005",
                detail=(
                    f"AND/OR/NAND/NOR gates locked with a key bit can be attacked by forcing inputs to "
                    "the controlling value (0 for AND, 1 for OR), making the output independent of the key. "
                    "XOR/XNOR locking is preferred as both values keep the output key-dependent."
                )
            ))
    return diags


# ─── Main linter entry point ───────────────────────────────────────────────────

def lint(netlist: NetlistInfo, sensitivity: str = "medium") -> LintReport:
    """
    Run all linting rules. sensitivity: "low" | "medium" | "high"
    Low → errors only. Medium → errors + warnings. High → all.
    """
    all_diags: list[Diagnostic] = []

    all_diags += _rule_output_cone_gap(netlist.gates, netlist.outputs)
    all_diags += _rule_xor_chain(netlist.gates, netlist.key_inputs)
    all_diags += _rule_low_key_entropy(netlist.gates, netlist.key_inputs)

    if sensitivity in ("medium", "high"):
        all_diags += _rule_single_key_gate_output(netlist.gates, netlist.outputs)

    if sensitivity == "high":
        all_diags += _rule_non_xor_locked(netlist.gates)

    summary = {
        "error": sum(1 for d in all_diags if d.severity == Severity.ERROR),
        "warning": sum(1 for d in all_diags if d.severity == Severity.WARNING),
        "info": sum(1 for d in all_diags if d.severity == Severity.INFO),
    }

    return LintReport(diagnostics=all_diags, summary=summary)
