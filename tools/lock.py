"""
Random XOR/XNOR Logic Locking
==============================
Implements the baseline random XOR/XNOR locking scheme from:
  Rajendran et al., "Security Analysis of Logic Obfuscation" (DAC 2012)

Usage:
  python3 lock.py <input.bench> <output_locked.bench> --key-bits 32 --seed 42

What it does:
  1. Parses the bench file
  2. Randomly selects N internal wires to lock
  3. Inserts an XOR or XNOR gate on each selected wire
     - XOR:  output = wire XOR key_bit  (correct key bit = 0)
     - XNOR: output = wire XNOR key_bit (correct key bit = 1)
  4. Writes the locked bench file with key inputs added
"""

import re
import random
import argparse
from pathlib import Path


def parse_bench(content: str):
    inputs, outputs, gates, lines_raw = [], [], [], []

    for lineno, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        lines_raw.append(raw)

        if not line or line.startswith('#'):
            continue

        if line.upper().startswith('INPUT('):
            m = re.search(r'\((\w+)\)', line)
            if m:
                inputs.append(m.group(1))

        elif line.upper().startswith('OUTPUT('):
            m = re.search(r'\((\w+)\)', line)
            if m:
                outputs.append(m.group(1))

        else:
            m = re.match(r'(\w+)\s*=\s*(\w+)\(([^)]*)\)', line)
            if m:
                out = m.group(1)
                gtype = m.group(2).upper()
                ins = [a.strip() for a in m.group(3).split(',') if a.strip()]
                gates.append({'out': out, 'type': gtype, 'ins': ins})

    return inputs, outputs, gates, lines_raw


def lock(input_path: str, output_path: str, key_bits: int, seed: int):
    content = Path(input_path).read_text(encoding='utf-8')
    inputs, outputs, gates, lines_raw = parse_bench(content)

    if not gates:
        print("No gates found — is this a valid bench file?")
        return

    rng = random.Random(seed)

    # Collect all internal wire names (gate outputs that aren't primary outputs)
    primary_outputs = set(outputs)
    internal_wires = [g['out'] for g in gates if g['out'] not in primary_outputs]

    # Also allow locking on gate inputs that are primary inputs
    # (connect key gate between primary input and first gate)
    lockable = internal_wires if internal_wires else [g['out'] for g in gates]

    # Pick N random wires to lock — cap at available wires
    n = min(key_bits, len(lockable))
    if n < key_bits:
        print(f"Warning: only {len(lockable)} lockable wires available, using {n} key bits")

    chosen = rng.sample(lockable, n)
    chosen_set = set(chosen)

    # For each chosen wire, randomly pick XOR or XNOR
    # XOR  → correct key bit is 0 (wire passes through unchanged when key=0)
    # XNOR → correct key bit is 1 (wire passes through unchanged when key=1)
    scheme = {wire: rng.choice(['XOR', 'XNOR']) for wire in chosen}
    correct_key = {
        f'keyinput{i}': (0 if scheme[wire] == 'XOR' else 1)
        for i, wire in enumerate(chosen)
    }

    # Build a map: original wire → locked wire name
    # The locked gate takes the original wire as input and outputs a new name
    # All downstream gates that used the original wire now use the locked wire
    wire_remap = {}
    key_gates = []
    for i, wire in enumerate(chosen):
        key_name = f'keyinput{i}'
        locked_wire = f'{wire}_locked'
        gate_type = scheme[wire]
        wire_remap[wire] = locked_wire
        key_gates.append({
            'out': locked_wire,
            'type': gate_type,
            'ins': [wire, key_name],
        })

    # Rebuild the bench file
    out_lines = []

    # Primary inputs (original)
    for inp in inputs:
        out_lines.append(f'INPUT({inp})')

    # Key inputs
    for i in range(n):
        out_lines.append(f'INPUT(keyinput{i})')

    out_lines.append('')  # blank line

    # Primary outputs (unchanged)
    for outp in outputs:
        out_lines.append(f'OUTPUT({outp})')

    out_lines.append('')

    # Original gates — remap inputs that now come from a locked wire
    for g in gates:
        remapped_ins = [wire_remap.get(inp, inp) for inp in g['ins']]
        # If this gate's output was chosen for locking, keep original output name
        # (the key gate sits after it and produces the locked version)
        out_lines.append(f"{g['out']} = {g['type']}({', '.join(remapped_ins)})")

    out_lines.append('')
    out_lines.append('# --- Key gates inserted by LockView random XOR/XNOR locking ---')

    # Key gates
    for kg in key_gates:
        out_lines.append(f"{kg['out']} = {kg['type']}({', '.join(kg['ins'])})")

    # Write output
    Path(output_path).write_text('\n'.join(out_lines) + '\n', encoding='utf-8')

    # Print summary
    print(f"\n✓ Locked netlist written to: {output_path}")
    print(f"\n  Original gates : {len(gates)}")
    print(f"  Key bits       : {n}")
    print(f"  Locked wires   : {', '.join(chosen[:8])}{'...' if len(chosen) > 8 else ''}")
    print(f"\n  Correct key (for verification):")
    for k, v in correct_key.items():
        gate_idx = int(k.replace('keyinput', ''))
        wire = chosen[gate_idx]
        print(f"    {k} = {v}  ({scheme[wire]} on wire {wire})")
    print(f"\n  Now run: python3 -m lockview.main analyze {output_path} --sensitivity high")


def main():
    parser = argparse.ArgumentParser(description='Random XOR/XNOR Logic Locking')
    parser.add_argument('input', help='Input bench file (unlocked)')
    parser.add_argument('output', help='Output bench file (locked)')
    parser.add_argument('--key-bits', type=int, default=32, help='Number of key bits (default: 32)')
    parser.add_argument('--seed', type=int, default=42, help='Random seed for reproducibility (default: 42)')
    args = parser.parse_args()

    lock(args.input, args.output, args.key_bits, args.seed)


if __name__ == '__main__':
    main()
