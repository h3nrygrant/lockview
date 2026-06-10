"""
LockView — Netlist Parser
Supports: Verilog gate-level netlists (.v / .sv) and Bench format (.bench)
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Gate:
    name: str
    gate_type: str          # AND, OR, XOR, XNOR, NOT, BUF, MUX, etc.
    inputs: list[str]
    output: str
    line_number: int
    is_key_gate: bool = False
    key_input: Optional[str] = None  # e.g. "keyinput0"


@dataclass
class NetlistInfo:
    format: str              # "verilog" or "bench"
    module_name: str
    inputs: list[str]
    outputs: list[str]
    wires: list[str]
    gates: list[Gate]
    key_inputs: list[str]    # ports/inputs named key* or keyinput*
    errors: list[str] = field(default_factory=list)


# ─── Bench Parser ──────────────────────────────────────────────────────────────

def parse_bench(content: str) -> NetlistInfo:
    inputs, outputs, wires, gates, key_inputs, errors = [], [], [], [], [], []
    module_name = "circuit"

    KEY_RE = re.compile(r'\b(key\w*|keyinput\d*)\b', re.IGNORECASE)
    GATE_RE = re.compile(
        r'^(\w+)\s*=\s*(\w+)\(([^)]*)\)', re.IGNORECASE
    )

    for lineno, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue

        if line.upper().startswith('INPUT('):
            net = re.search(r'\((\w+)\)', line)
            if net:
                name = net.group(1)
                if KEY_RE.search(name):
                    key_inputs.append(name)
                else:
                    inputs.append(name)

        elif line.upper().startswith('OUTPUT('):
            net = re.search(r'\((\w+)\)', line)
            if net:
                outputs.append(net.group(1))

        else:
            m = GATE_RE.match(line)
            if m:
                out_net, gtype, args = m.group(1), m.group(2).upper(), m.group(3)
                in_nets = [a.strip() for a in args.split(',') if a.strip()]
                key_in = next((n for n in in_nets if KEY_RE.search(n)), None)
                g = Gate(
                    name=out_net,
                    gate_type=gtype,
                    inputs=in_nets,
                    output=out_net,
                    line_number=lineno,
                    is_key_gate=key_in is not None,
                    key_input=key_in,
                )
                gates.append(g)
                wires.append(out_net)
            elif '=' in line:
                errors.append(f"Line {lineno}: unrecognised gate syntax — {line[:60]}")

    return NetlistInfo(
        format="bench",
        module_name=module_name,
        inputs=inputs,
        outputs=outputs,
        wires=wires,
        gates=gates,
        key_inputs=key_inputs,
        errors=errors,
    )


# ─── Verilog Gate-Level Parser ─────────────────────────────────────────────────

def parse_verilog(content: str) -> NetlistInfo:
    inputs, outputs, wires, gates, key_inputs, errors = [], [], [], [], [], []
    module_name = "unknown"

    KEY_RE = re.compile(r'\b(key\w*|keyinput\d*)\b', re.IGNORECASE)

    # Strip line and block comments
    content = re.sub(r'//.*', '', content)
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)

    # Module name
    mod = re.search(r'\bmodule\s+(\w+)', content)
    if mod:
        module_name = mod.group(1)

    # Port declarations — input/output/wire
    for lineno, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()

        inp = re.match(r'\binput\b\s*(?:\[\d+:\d+\])?\s*([\w,\s]+);', line)
        if inp:
            names = [n.strip() for n in inp.group(1).split(',') if n.strip()]
            for n in names:
                (key_inputs if KEY_RE.search(n) else inputs).append(n)
            continue

        out = re.match(r'\boutput\b\s*(?:\[\d+:\d+\])?\s*([\w,\s]+);', line)
        if out:
            outputs += [n.strip() for n in out.group(1).split(',') if n.strip()]
            continue

        wr = re.match(r'\bwire\b\s*(?:\[\d+:\d+\])?\s*([\w,\s]+);', line)
        if wr:
            wires += [n.strip() for n in wr.group(1).split(',') if n.strip()]
            continue

        # Gate instantiations: and g1 (.Y(out), .A(a), .B(b));
        # or primitives:       and g1 (out, a, b);
        gate_inst = re.match(
            r'\b(and|or|xor|xnor|nand|nor|not|buf|mux|xor2|and2|or2)\b'
            r'\s+(\w+)\s*\(([^;]+)\);',
            line, re.IGNORECASE
        )
        if gate_inst:
            gtype = gate_inst.group(1).upper()
            gname = gate_inst.group(2)
            port_str = gate_inst.group(3)

            # Named ports (.Y(sig)) or positional
            named = re.findall(r'\.(\w+)\s*\(\s*(\w+)\s*\)', port_str)
            if named:
                port_map = {p: s for p, s in named}
                out_net = port_map.get('Y') or port_map.get('Z') or port_map.get('Q') or list(port_map.values())[0]
                in_nets = [s for p, s in named if s != out_net]
            else:
                sigs = [s.strip() for s in port_str.split(',') if s.strip()]
                out_net = sigs[0] if sigs else gname
                in_nets = sigs[1:]

            key_in = next((n for n in in_nets if KEY_RE.search(n)), None)
            gates.append(Gate(
                name=gname,
                gate_type=gtype,
                inputs=in_nets,
                output=out_net,
                line_number=lineno,
                is_key_gate=key_in is not None,
                key_input=key_in,
            ))

    return NetlistInfo(
        format="verilog",
        module_name=module_name,
        inputs=inputs,
        outputs=outputs,
        wires=wires,
        gates=gates,
        key_inputs=key_inputs,
        errors=errors,
    )


def parse(content: str, filename: str = "") -> NetlistInfo:
    if filename.endswith(".bench"):
        return parse_bench(content)
    return parse_verilog(content)
